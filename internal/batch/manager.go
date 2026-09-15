package batch

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yohnark/tadori/internal/model"
	"github.com/yohnark/tadori/internal/orchestrate"
	"github.com/yohnark/tadori/internal/report"
)

const (
	// DefaultConcurrency bounds active diagnostic processes in one batch.
	DefaultConcurrency = 4
	// DefaultItemTimeout is the per-endpoint budget. The batch itself has no
	// unbounded lifetime because every item gets this independent deadline.
	DefaultItemTimeout = 30 * time.Second
	// DefaultMaxConcurrentBatches prevents repeated clicks from multiplying
	// active diagnostic work while retaining completed in-memory reports.
	DefaultMaxConcurrentBatches = 1
)

var (
	ErrNotFound                  = errors.New("validation batch not found")
	ErrBusy                      = errors.New("validation batch capacity is full")
	ErrClosed                    = errors.New("validation batch manager is closed")
	ErrEndpointReportUnavailable = errors.New("endpoint report is not available")
)

// Runner is the existing canonical diagnostic orchestration boundary. Batch
// validation does not define or duplicate probe behavior.
type Runner func(context.Context, model.Target) model.DiagnosticReport

// Options configures a bounded in-memory batch manager.
type Options struct {
	Run                  Runner
	MaxConcurrency       int
	MaxConcurrentBatches int
	ItemTimeout          time.Duration
	Now                  func() time.Time
	NewID                func() string
}

// State is the lifecycle of one validation batch.
type State string

const (
	StateStarting   State = "starting"
	StateRunning    State = "running"
	StateCancelling State = "cancelling"
	StateCompleted  State = "completed"
	StateCancelled  State = "cancelled"
	StateFailed     State = "failed"
)

// EntryState is the lifecycle of one plan entry.
type EntryState string

const (
	EntryQueued      EntryState = "queued"
	EntryRunning     EntryState = "running"
	EntryCompleted   EntryState = "completed"
	EntryCancelled   EntryState = "cancelled"
	EntryUnsupported EntryState = "unsupported"
)

// ValidationOutcome is independent from capture outcome. A later active
// result never overwrites the capture observation retained on the entry.
type ValidationOutcome string

const (
	ValidationPassed      ValidationOutcome = "passed"
	ValidationFailed      ValidationOutcome = "failed"
	ValidationPartial     ValidationOutcome = "partial"
	ValidationUnsupported ValidationOutcome = "unsupported"
	ValidationCancelled   ValidationOutcome = "cancelled"
	ValidationNotRun      ValidationOutcome = "not_run"
)

// FailureBoundary is the normalized active-validation failure boundary. The
// detail and references are derived from the canonical report projection.
type FailureBoundary struct {
	Reason      model.FailureReason `json:"reason"`
	Layer       model.Layer         `json:"layer"`
	FaultDomain model.FaultDomain   `json:"fault_domain"`
	Detail      string              `json:"detail,omitempty"`
	ProbeNames  []string            `json:"probe_names,omitempty"`
	EvidenceIDs []string            `json:"evidence_ids,omitempty"`
}

// Result is the dense endpoint-oriented projection used by the batch UI and
// export. Report remains the canonical per-endpoint document; these fields are
// references/normalized projections for table rendering and filtering.
type Result struct {
	ID                      string                           `json:"id"`
	RequestedHostname       string                           `json:"requested_hostname"`
	RequestedIdentity       string                           `json:"requested_identity"`
	Port                    uint16                           `json:"port"`
	Service                 model.ServiceProfile             `json:"service"`
	CaptureMechanism        model.BrowserCaptureMechanism    `json:"capture_mechanism"`
	CaptureOutcome          model.BrowserCaptureOutcome      `json:"capture_outcome"`
	CaptureFailed           bool                             `json:"capture_failed"`
	CaptureObservationCount uint64                           `json:"capture_observation_count"`
	CaptureConnectionCount  uint64                           `json:"capture_connection_count"`
	CaptureSuccessCount     uint64                           `json:"capture_success_count"`
	CaptureFailureCount     uint64                           `json:"capture_failure_count"`
	Capture                 CaptureProvenance                `json:"capture"`
	State                   EntryState                       `json:"state"`
	Outcome                 ValidationOutcome                `json:"validation_outcome"`
	ReportStatus            model.ReportStatus               `json:"report_status,omitempty"`
	Destination             report.DestinationStatus         `json:"destination"`
	FailureBoundary         FailureBoundary                  `json:"failure_boundary"`
	DNS                     *model.NameResolutionObservation `json:"dns,omitempty"`
	TCP                     *model.TransportObservation      `json:"tcp,omitempty"`
	TLS                     *model.SecurityObservation       `json:"tls,omitempty"`
	Application             *model.ApplicationObservation    `json:"application,omitempty"`
	Report                  *model.DiagnosticReport          `json:"report,omitempty"`
	Error                   string                           `json:"error,omitempty"`
	StartedAt               *time.Time                       `json:"started_at,omitempty"`
	CompletedAt             *time.Time                       `json:"completed_at,omitempty"`
}

// Summary aggregates batch execution while keeping failed endpoint identities
// readily exportable.
type Summary struct {
	Total                  int      `json:"total"`
	Queued                 int      `json:"queued"`
	Running                int      `json:"running"`
	Completed              int      `json:"completed"`
	Passed                 int      `json:"passed"`
	Failed                 int      `json:"failed"`
	Partial                int      `json:"partial"`
	Unsupported            int      `json:"unsupported"`
	Cancelled              int      `json:"cancelled"`
	CapturedFailureCount   int      `json:"captured_failure_count"`
	ValidationFailureCount int      `json:"validation_failure_count"`
	FailedEndpointIDs      []string `json:"failed_endpoint_ids,omitempty"`
	FailedIdentities       []string `json:"failed_identities,omitempty"`
}

// Report is the batch summary plus one canonical report per active-validated
// endpoint. It is valid both during execution and after completion.
type Report struct {
	SchemaVersion    string        `json:"schema_version"`
	ID               string        `json:"id"`
	CaptureSessionID string        `json:"capture_session_id"`
	CaptureBrowser   string        `json:"capture_browser,omitempty"`
	Selection        SelectionMode `json:"selection"`
	State            State         `json:"state"`
	StartedAt        *time.Time    `json:"started_at,omitempty"`
	CompletedAt      *time.Time    `json:"completed_at,omitempty"`
	Plan             Plan          `json:"plan"`
	Results          []Result      `json:"results"`
	Summary          Summary       `json:"summary"`
	Error            string        `json:"error,omitempty"`
}

const ReportSchemaVersion = "1"

// Snapshot is the JSON-safe live view. It has the same contract as Report so
// clients can use the final polling response without a shape change.
type Snapshot = Report

type Manager struct {
	mu             sync.Mutex
	batches        map[string]*managedBatch
	capacity       chan struct{}
	closed         bool
	run            Runner
	maxConcurrency int
	itemTimeout    time.Duration
	now            func() time.Time
	newID          func() string
	idSequence     atomic.Uint64
}

type managedBatch struct {
	mu              sync.Mutex
	id              string
	plan            Plan
	state           State
	startedAt       *time.Time
	completedAt     *time.Time
	results         []Result
	summary         Summary
	error           string
	ctx             context.Context
	cancel          context.CancelFunc
	done            chan struct{}
	cancelRequested bool
}

// NewManager creates a bounded in-memory validation batch manager.
func NewManager(opts Options) *Manager {
	maxConcurrency := opts.MaxConcurrency
	if maxConcurrency <= 0 {
		maxConcurrency = DefaultConcurrency
	}
	maxBatches := opts.MaxConcurrentBatches
	if maxBatches <= 0 {
		maxBatches = DefaultMaxConcurrentBatches
	}
	itemTimeout := opts.ItemTimeout
	if itemTimeout <= 0 {
		itemTimeout = DefaultItemTimeout
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	run := opts.Run
	if run == nil {
		run = func(ctx context.Context, target model.Target) model.DiagnosticReport {
			return orchestrate.Run(ctx, target, orchestrate.Options{})
		}
	}
	newID := opts.NewID
	if newID == nil {
		newID = func() string {
			var random [8]byte
			if _, err := rand.Read(random[:]); err == nil {
				return "validation-" + hex.EncodeToString(random[:])
			}
			return fmt.Sprintf("validation-%d", time.Now().UnixNano())
		}
	}
	return &Manager{
		batches:        make(map[string]*managedBatch),
		capacity:       make(chan struct{}, maxBatches),
		run:            run,
		maxConcurrency: maxConcurrency,
		itemTimeout:    itemTimeout,
		now:            now,
		newID:          newID,
	}
}

// Start schedules one deterministic plan. The caller owns plan construction;
// the manager takes a detached copy before asynchronous execution begins.
func (m *Manager) Start(ctx context.Context, plan Plan) (Snapshot, error) {
	if len(plan.Entries) == 0 {
		return Snapshot{}, ErrEmptyValidationPlan
	}
	select {
	case m.capacity <- struct{}{}:
	default:
		return Snapshot{}, ErrBusy
	}
	if ctx == nil {
		ctx = context.Background()
	}
	plan = normalizePlan(plan, m.maxConcurrency)
	baseCtx, cancel := context.WithCancel(ctx)
	started := m.now().UTC()
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		cancel()
		<-m.capacity
		return Snapshot{}, ErrClosed
	}
	id := m.uniqueIDLocked()
	batch := &managedBatch{
		id:        id,
		plan:      plan,
		state:     StateStarting,
		startedAt: &started,
		results:   initialResults(plan),
		done:      make(chan struct{}),
		ctx:       baseCtx,
		cancel:    cancel,
	}
	batch.summary = summarize(batch.results)
	m.batches[id] = batch
	m.mu.Unlock()
	go m.execute(batch)
	return batch.snapshot(), nil
}

// Get returns a detached point-in-time batch snapshot.
func (m *Manager) Get(id string) (Snapshot, error) {
	batch, err := m.lookup(id)
	if err != nil {
		return Snapshot{}, err
	}
	return batch.snapshot(), nil
}

// Report returns the batch's canonical machine-readable projection.
func (m *Manager) Report(id string) (Report, error) {
	batch, err := m.lookup(id)
	if err != nil {
		return Report{}, err
	}
	return batch.snapshot(), nil
}

// EndpointReport returns one canonical diagnostic report for a completed
// endpoint. Unsupported/cancelled entries have no active report.
func (m *Manager) EndpointReport(batchID, entryID string) (model.DiagnosticReport, error) {
	batch, err := m.lookup(batchID)
	if err != nil {
		return model.DiagnosticReport{}, err
	}
	snapshot := batch.snapshot()
	for _, result := range snapshot.Results {
		if result.ID != entryID {
			continue
		}
		if result.Report == nil {
			return model.DiagnosticReport{}, fmt.Errorf("%w for %s", ErrEndpointReportUnavailable, entryID)
		}
		return *result.Report, nil
	}
	return model.DiagnosticReport{}, ErrNotFound
}

// FailedIdentities returns canonical service identities for failed active
// validations. The result is stable and suitable for copy/export.
func (m *Manager) FailedIdentities(id string) ([]string, error) {
	snapshot, err := m.Get(id)
	if err != nil {
		return nil, err
	}
	return append([]string(nil), snapshot.Summary.FailedIdentities...), nil
}

// Cancel requests cancellation. In-flight canonical runners receive the same
// context cancellation and queued entries become explicit cancelled results.
func (m *Manager) Cancel(id string) (Snapshot, error) {
	batch, err := m.lookup(id)
	if err != nil {
		return Snapshot{}, err
	}
	batch.mu.Lock()
	if terminal(batch.state) {
		snapshot := batch.snapshotLocked()
		batch.mu.Unlock()
		return snapshot, nil
	}
	batch.cancelRequested = true
	if batch.state == StateStarting || batch.state == StateRunning {
		batch.state = StateCancelling
	}
	snapshot := batch.snapshotLocked()
	cancel := batch.cancel
	batch.mu.Unlock()
	cancel()
	return snapshot, nil
}

// Wait waits until one batch reaches a terminal state.
func (m *Manager) Wait(ctx context.Context, id string) (Snapshot, error) {
	batch, err := m.lookup(id)
	if err != nil {
		return Snapshot{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-batch.done:
		return batch.snapshot(), nil
	case <-ctx.Done():
		return Snapshot{}, ctx.Err()
	}
}

// Close cancels active batches and rejects new work. Completed snapshots remain
// available until the manager is released by its owning process.
func (m *Manager) Close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	batches := make([]*managedBatch, 0, len(m.batches))
	for _, batch := range m.batches {
		batches = append(batches, batch)
	}
	m.mu.Unlock()
	for _, batch := range batches {
		batch.mu.Lock()
		if terminal(batch.state) {
			batch.mu.Unlock()
			continue
		}
		batch.cancelRequested = true
		batch.state = StateCancelling
		cancel := batch.cancel
		batch.mu.Unlock()
		cancel()
	}
}

func (m *Manager) execute(batch *managedBatch) {
	defer func() { <-m.capacity }()
	defer batch.cancel()
	batch.mu.Lock()
	if batch.state == StateStarting {
		batch.state = StateRunning
	}
	batch.mu.Unlock()

	concurrency := batch.plan.Concurrency
	if concurrency <= 0 || concurrency > m.maxConcurrency {
		concurrency = m.maxConcurrency
	}
	if concurrency > len(batch.plan.Entries) {
		concurrency = len(batch.plan.Entries)
	}
	jobs := make(chan int, len(batch.plan.Entries))
	for index := range batch.plan.Entries {
		jobs <- index
	}
	close(jobs)
	var workers sync.WaitGroup
	workers.Add(concurrency)
	for worker := 0; worker < concurrency; worker++ {
		go func() {
			defer workers.Done()
			for index := range jobs {
				entry := batch.plan.Entries[index]
				if entry.Unsupported {
					batch.finish(index, unsupportedResult(entry, m.now))
					continue
				}
				if batch.contextCancelled() {
					batch.finish(index, cancelledResult(entry, m.now))
					continue
				}
				batch.markRunning(index, m.now)
				result := m.runEntry(batch, entry)
				batch.finish(index, result)
			}
		}()
	}
	workers.Wait()

	batch.mu.Lock()
	completed := m.now().UTC()
	batch.completedAt = &completed
	if batch.cancelRequested || batch.ctx.Err() != nil {
		batch.state = StateCancelled
	} else {
		batch.state = StateCompleted
	}
	batch.summary = summarize(batch.results)
	close(batch.done)
	batch.mu.Unlock()
}

func (m *Manager) runEntry(batch *managedBatch, entry PlanEntry) Result {
	started := m.now().UTC()
	result := resultForEntry(entry)
	itemCtx, cancel := context.WithTimeout(batch.ctx, m.itemTimeout)
	defer cancel()
	var diagnostic model.DiagnosticReport
	panicked := false
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				panicked = true
				diagnostic = errorReport(*entry.Target, m.now, fmt.Sprintf("diagnostic runner panic: %v", recovered))
			}
		}()
		diagnostic = m.run(itemCtx, *entry.Target)
	}()
	completed := m.now().UTC()
	result.StartedAt = &started
	result.CompletedAt = &completed
	result.Report = &diagnostic
	result.ReportStatus = diagnostic.Status
	result.Destination = report.DestinationStatusForReport(diagnostic)
	result.FailureBoundary = failureBoundary(diagnostic, result.Destination)
	result.DNS, result.TCP, result.TLS, result.Application = observationPointers(diagnostic, entry)
	if errors.Is(itemCtx.Err(), context.Canceled) && !panicked {
		result.State = EntryCancelled
		result.Outcome = ValidationCancelled
		result.Error = "validation cancelled"
		return result
	}
	if errors.Is(itemCtx.Err(), context.DeadlineExceeded) && diagnostic.Status == model.ReportStatusComplete {
		result.ReportStatus = model.ReportStatusIncomplete
		result.Outcome = ValidationPartial
		result.Error = "validation timed out"
		return result
	}
	result.State = EntryCompleted
	result.Outcome = classifyOutcome(diagnostic, result.Destination)
	if panicked {
		result.Error = "diagnostic runner panicked"
	}
	return result
}

func (b *managedBatch) markRunning(index int, now func() time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if index < 0 || index >= len(b.results) || terminalEntry(b.results[index].State) {
		return
	}
	b.results[index].State = EntryRunning
	started := now().UTC()
	b.results[index].StartedAt = &started
	b.summary = summarize(b.results)
}

func (b *managedBatch) finish(index int, result Result) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if index < 0 || index >= len(b.results) {
		return
	}
	b.results[index] = result
	b.summary = summarize(b.results)
}

func (b *managedBatch) contextCancelled() bool {
	b.mu.Lock()
	cancelled := b.cancelRequested || b.ctx.Err() != nil
	b.mu.Unlock()
	return cancelled
}

func (b *managedBatch) snapshot() Snapshot {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.snapshotLocked()
}

func (b *managedBatch) snapshotLocked() Snapshot {
	return cloneReport(Report{
		SchemaVersion:    ReportSchemaVersion,
		ID:               b.id,
		CaptureSessionID: b.plan.CaptureSessionID,
		CaptureBrowser:   b.plan.CaptureBrowser,
		Selection:        b.plan.Selection,
		State:            b.state,
		StartedAt:        cloneTime(b.startedAt),
		CompletedAt:      cloneTime(b.completedAt),
		Plan:             b.plan,
		Results:          b.results,
		Summary:          b.summary,
		Error:            b.error,
	})
}

func initialResults(plan Plan) []Result {
	results := make([]Result, len(plan.Entries))
	for index, entry := range plan.Entries {
		results[index] = resultForEntry(entry)
	}
	return results
}

func resultForEntry(entry PlanEntry) Result {
	return Result{
		ID:                      entry.ID,
		RequestedHostname:       entry.RequestedHostname,
		RequestedIdentity:       entry.RequestedIdentity,
		Port:                    entry.Port,
		Service:                 entry.Service,
		CaptureMechanism:        entry.CaptureMechanism,
		CaptureOutcome:          entry.CaptureOutcome,
		CaptureFailed:           entry.CaptureFailed,
		CaptureObservationCount: entry.CaptureObservationCount,
		CaptureConnectionCount:  entry.CaptureConnectionCount,
		CaptureSuccessCount:     entry.CaptureSuccessCount,
		CaptureFailureCount:     entry.CaptureFailureCount,
		Capture:                 entry.Capture,
		State:                   EntryQueued,
		Outcome:                 ValidationNotRun,
		Destination:             report.DestinationStatus{},
	}
}

func unsupportedResult(entry PlanEntry, now func() time.Time) Result {
	result := resultForEntry(entry)
	result.State = EntryUnsupported
	result.Outcome = ValidationUnsupported
	result.Error = entry.UnsupportedReason
	completed := now().UTC()
	result.CompletedAt = &completed
	return result
}

func cancelledResult(entry PlanEntry, now func() time.Time) Result {
	result := resultForEntry(entry)
	result.State = EntryCancelled
	result.Outcome = ValidationCancelled
	result.Error = "validation cancelled"
	completed := now().UTC()
	result.CompletedAt = &completed
	return result
}

func classifyOutcome(diagnostic model.DiagnosticReport, destination report.DestinationStatus) ValidationOutcome {
	if diagnostic.Status == model.ReportStatusError || diagnostic.Status == model.ReportStatusUnknown {
		if destination.Status == report.DestinationStatusUnreachable || destination.Status == report.DestinationStatusDegraded {
			return ValidationFailed
		}
		return ValidationPartial
	}
	if diagnostic.Status == model.ReportStatusIncomplete {
		return ValidationPartial
	}
	switch destination.Status {
	case report.DestinationStatusReachable:
		return ValidationPassed
	case report.DestinationStatusUnreachable, report.DestinationStatusDegraded:
		return ValidationFailed
	default:
		if destination.FailureReason == model.FailureReasonUnsupported {
			return ValidationUnsupported
		}
		if destination.FailureReason != "" && destination.FailureReason != model.FailureReasonNone && destination.FailureReason != model.FailureReasonUnknown {
			return ValidationFailed
		}
		return ValidationPartial
	}
}

func observationPointers(diagnostic model.DiagnosticReport, entry PlanEntry) (*model.NameResolutionObservation, *model.TransportObservation, *model.SecurityObservation, *model.ApplicationObservation) {
	observations := model.NormalizeObservations(diagnostic.Observations)
	dns := &observations.NameResolution
	tcp := &observations.Transport
	var tls *model.SecurityObservation
	if entry.Service.ID == model.ServiceProfileHTTPS || entry.Service.ID == model.ServiceProfileCustomTLS || observations.Security.Attempted || observations.Security.HandshakeComplete {
		value := observations.Security
		tls = &value
	}
	var application *model.ApplicationObservation
	if entry.Service.ID != model.ServiceProfileCustomTCP || observations.Application.RequestAttempted || observations.Application.ResponseReceived || observations.Application.Protocol != "" {
		value := observations.Application
		application = &value
	}
	return dns, tcp, tls, application
}

func failureBoundary(diagnostic model.DiagnosticReport, destination report.DestinationStatus) FailureBoundary {
	boundary := FailureBoundary{
		Reason:      destination.FailureReason,
		Detail:      destination.Detail,
		ProbeNames:  append([]string(nil), destination.ProbeNames...),
		EvidenceIDs: append([]string(nil), destination.EvidenceIDs...),
	}
	for _, finding := range diagnostic.Findings {
		if destination.FailureReason != "" && finding.FailureReason != destination.FailureReason {
			continue
		}
		boundary.Layer = finding.Layer
		boundary.FaultDomain = finding.FaultDomain
		if len(boundary.ProbeNames) == 0 {
			boundary.ProbeNames = append([]string(nil), finding.ProbeNames...)
		}
		if len(boundary.EvidenceIDs) == 0 {
			boundary.EvidenceIDs = append([]string(nil), finding.EvidenceIDs...)
		}
		return boundary
	}
	for _, candidate := range []struct {
		reason      model.FailureReason
		layer       model.Layer
		faultDomain model.FaultDomain
		provenance  []string
		evidenceIDs []string
	}{
		{diagnostic.Observations.Application.FailureReason, model.LayerHTTP, diagnostic.Observations.Application.FaultDomain, diagnostic.Observations.Application.ProbeNames, diagnostic.Observations.Application.EvidenceIDs},
		{diagnostic.Observations.Security.FailureReason, model.LayerTLS, diagnostic.Observations.Security.FaultDomain, diagnostic.Observations.Security.ProbeNames, diagnostic.Observations.Security.EvidenceIDs},
		{diagnostic.Observations.Transport.FailureReason, model.LayerTCP, diagnostic.Observations.Transport.FaultDomain, diagnostic.Observations.Transport.ProbeNames, diagnostic.Observations.Transport.EvidenceIDs},
		{diagnostic.Observations.NameResolution.FailureReason, model.LayerDNS, diagnostic.Observations.NameResolution.FaultDomain, diagnostic.Observations.NameResolution.ProbeNames, diagnostic.Observations.NameResolution.EvidenceIDs},
	} {
		if candidate.reason == "" || candidate.reason == model.FailureReasonNone || (destination.FailureReason != "" && candidate.reason != destination.FailureReason) {
			continue
		}
		boundary.Layer = candidate.layer
		boundary.FaultDomain = candidate.faultDomain
		boundary.ProbeNames = appendUnique(boundary.ProbeNames, candidate.provenance...)
		boundary.EvidenceIDs = appendUnique(boundary.EvidenceIDs, candidate.evidenceIDs...)
		return boundary
	}
	return boundary
}

func summarize(results []Result) Summary {
	summary := Summary{Total: len(results)}
	for _, result := range results {
		switch result.State {
		case EntryQueued:
			summary.Queued++
		case EntryRunning:
			summary.Running++
		case EntryCompleted, EntryUnsupported, EntryCancelled:
			summary.Completed++
		}
		if result.CaptureFailed {
			summary.CapturedFailureCount++
		}
		switch result.Outcome {
		case ValidationPassed:
			summary.Passed++
		case ValidationFailed:
			summary.Failed++
			summary.ValidationFailureCount++
			summary.FailedEndpointIDs = append(summary.FailedEndpointIDs, result.ID)
			summary.FailedIdentities = append(summary.FailedIdentities, TargetIdentity(PlanEntry{Target: targetForResult(result), RequestedHostname: result.RequestedHostname, RequestedIdentity: result.RequestedIdentity, Port: result.Port, Service: result.Service}))
		case ValidationPartial:
			summary.Partial++
		case ValidationUnsupported:
			summary.Unsupported++
		case ValidationCancelled:
			summary.Cancelled++
		}
	}
	return summary
}

func targetForResult(result Result) *model.Target {
	if result.Report != nil {
		value := result.Report.Target
		return &value
	}
	return nil
}

func normalizePlan(plan Plan, maxConcurrency int) Plan {
	plan = clonePlan(plan)
	plan.PlanSchemaNormalize()
	if plan.Concurrency <= 0 || plan.Concurrency > maxConcurrency {
		plan.Concurrency = maxConcurrency
	}
	plan.Entries = append([]PlanEntry(nil), plan.Entries...)
	return plan
}

func clonePlan(value Plan) Plan {
	encoded, err := json.Marshal(value)
	if err != nil {
		return value
	}
	var copy Plan
	if err := json.Unmarshal(encoded, &copy); err != nil {
		return value
	}
	return copy
}

func (p *Plan) PlanSchemaNormalize() {
	if p.SchemaVersion == "" {
		p.SchemaVersion = PlanSchemaVersion
	}
	if p.Selection == "" {
		p.Selection = SelectionAll
	}
	for index := range p.Entries {
		if p.Entries[index].ID == "" {
			p.Entries[index].ID = fmt.Sprintf("endpoint-%03d", index+1)
		}
	}
}

func terminal(value State) bool {
	return value == StateCompleted || value == StateCancelled || value == StateFailed
}

func terminalEntry(value EntryState) bool {
	return value == EntryCompleted || value == EntryCancelled || value == EntryUnsupported
}

func cloneReport(value Report) Report {
	encoded, err := json.Marshal(value)
	if err != nil {
		return value
	}
	var copy Report
	if err := json.Unmarshal(encoded, &copy); err != nil {
		return value
	}
	return copy
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := value.UTC()
	return &copy
}

func appendUnique(values []string, additions ...string) []string {
	for _, addition := range additions {
		if addition == "" {
			continue
		}
		seen := false
		for _, value := range values {
			if value == addition {
				seen = true
				break
			}
		}
		if !seen {
			values = append(values, addition)
		}
	}
	return values
}

func (m *Manager) lookup(id string) (*managedBatch, error) {
	m.mu.Lock()
	batch, ok := m.batches[id]
	m.mu.Unlock()
	if !ok {
		return nil, ErrNotFound
	}
	return batch, nil
}

func (m *Manager) uniqueIDLocked() string {
	for {
		id := m.newID()
		if id == "" {
			id = fmt.Sprintf("validation-%d", m.idSequence.Add(1))
		}
		if _, exists := m.batches[id]; !exists {
			return id
		}
		id = fmt.Sprintf("%s-%d", id, m.idSequence.Add(1))
		if _, exists := m.batches[id]; !exists {
			return id
		}
	}
}

func errorReport(target model.Target, now func() time.Time, message string) model.DiagnosticReport {
	started := now().UTC()
	completed := now().UTC()
	return model.DiagnosticReport{
		SchemaVersion: model.DiagnosticSchemaVersion,
		Target:        model.TargetIntentOnly(target),
		Status:        model.ReportStatusError,
		StartedAt:     &started,
		CompletedAt:   &completed,
		Probes:        []model.ProbeResult{},
		Observations:  model.Observations{Endpoint: model.EndpointObservation{OriginalInput: target.OriginalInput, RequestedIdentity: target.RequestedIdentity, Service: target.Service, ApplicationProtocol: target.ApplicationProtocol, TransportProtocol: target.TransportProtocol, Port: target.Port}},
		Findings:      []model.DiagnosticFinding{{FailureReason: model.FailureReasonProbeExecution, Layer: model.LayerUnknown, FaultDomain: model.FaultDomainUnknown, ProbeNames: []string{message}}},
	}
}
