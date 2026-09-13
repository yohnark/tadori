// Package session owns the ephemeral lifecycle of local diagnostic runs.
// It deliberately contains no HTTP or presentation logic: callers receive
// structured events and the canonical report produced by their runner.
package session

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
)

const (
	// DefaultOverallTimeout bounds one local diagnostic execution.
	DefaultOverallTimeout = 30 * time.Second
	// DefaultMaxConcurrentSessions prevents an accidental or repeated local
	// request from creating an unbounded number of active diagnostic runs.
	DefaultMaxConcurrentSessions = 2
	// maxEventHistory is deliberately finite. A diagnostic has a small fixed
	// probe set today, while the bound keeps future incremental observations
	// from turning one session into an unbounded in-memory log.
	maxEventHistory  = 4096
	subscriberBuffer = 256
)

var (
	ErrNotFound = errors.New("diagnosis session not found")
	ErrBusy     = errors.New("diagnostic session capacity is full")
	ErrClosed   = errors.New("diagnostic session manager is closed")
)

// State is the machine-readable lifecycle of a session.
type State string

const (
	StateRunning    State = "running"
	StateCancelling State = "cancelling"
	StateCompleted  State = "completed"
	StateCancelled  State = "cancelled"
	StateFailed     State = "failed"
)

// EventType names the structured progress events emitted by a session.
type EventType string

const (
	EventDiagnosisStarted   EventType = "diagnosis_started"
	EventProbeStarted       EventType = "probe_started"
	EventProbeCompleted     EventType = "probe_completed"
	EventResultUpdated      EventType = "result_updated"
	EventFindingUpdated     EventType = "finding_updated"
	EventDiagnosisCompleted EventType = "diagnosis_completed"
	EventDiagnosisCancelled EventType = "diagnosis_cancelled"
)

// Event is the versioned progress contract. Optional fields carry structured
// model values; Data is reserved for future typed extensions such as path or
// hop observations. Human-readable presentation text is intentionally absent.
type Event struct {
	SchemaVersion string                   `json:"schema_version"`
	Sequence      uint64                   `json:"sequence"`
	Type          EventType                `json:"type"`
	SessionID     string                   `json:"session_id"`
	Timestamp     time.Time                `json:"timestamp"`
	Target        *model.Target            `json:"target,omitempty"`
	ProbeName     string                   `json:"probe_name,omitempty"`
	Result        *model.ProbeResult       `json:"result,omitempty"`
	Finding       *model.DiagnosticFinding `json:"finding,omitempty"`
	Report        *model.DiagnosticReport  `json:"report,omitempty"`
	Data          json.RawMessage          `json:"data,omitempty"`
}

// EventSchemaVersion is independent from the canonical report schema so the
// progress stream can evolve without changing DiagnosticReport JSON.
const EventSchemaVersion = "1"

// Snapshot is the JSON-safe view of a session. Report is nil until execution
// reaches a terminal state; once present it is the canonical final report.
type Snapshot struct {
	ID              string                  `json:"id"`
	Target          model.Target            `json:"target"`
	State           State                   `json:"state"`
	StartedAt       *time.Time              `json:"started_at,omitempty"`
	CompletedAt     *time.Time              `json:"completed_at,omitempty"`
	CancelRequested bool                    `json:"cancel_requested,omitempty"`
	Report          *model.DiagnosticReport `json:"report,omitempty"`
}

// Progress contains notifications supplied to a diagnostic runner. The
// production adapter passes these callbacks into orchestrate.Run; test or
// future runners can use the same contract without depending on HTTP.
type Progress struct {
	// SessionID is the manager-owned identity that packet evidence and other
	// scoped orchestration lanes may use for deterministic correlation.
	SessionID      string
	ProbeStarted   func(name string)
	ProbeCompleted func(result model.ProbeResult)
	// Emit lets a future orchestration lane publish a typed extension event,
	// such as a path or hop observation, without changing the session store or
	// HTTP transport. Session-owned sequence and identity fields are applied
	// when the event is recorded.
	Emit func(event Event)
}

// Runner is the direct in-process diagnostic orchestration contract.
type Runner func(context.Context, model.Target, Progress) model.DiagnosticReport

// Options configures a Manager. All zero values select bounded local
// defaults, except Run, for which a structured error report is used if no
// runner is supplied.
type Options struct {
	Run                   Runner
	OverallTimeout        time.Duration
	MaxConcurrentSessions int
	Now                   func() time.Time
	NewID                 func() string
}

// Manager stores active and completed sessions in memory for the lifetime of
// the process. It is safe for concurrent HTTP requests and never persists
// session history.
type Manager struct {
	mu       sync.Mutex
	sessions map[string]*managedSession
	capacity chan struct{}
	closed   bool
	run      Runner
	timeout  time.Duration
	now      func() time.Time
	newID    func() string
}

type managedSession struct {
	mu              sync.Mutex
	id              string
	target          model.Target
	state           State
	startedAt       *time.Time
	completedAt     *time.Time
	cancelRequested bool
	report          *model.DiagnosticReport
	ctx             context.Context
	cancel          context.CancelFunc
	done            chan struct{}
	events          []Event
	nextSequence    uint64
	subscribers     map[chan Event]struct{}
	now             func() time.Time
}

// NewManager creates an in-memory bounded session manager.
func NewManager(opts Options) *Manager {
	maxConcurrent := opts.MaxConcurrentSessions
	if maxConcurrent <= 0 {
		maxConcurrent = DefaultMaxConcurrentSessions
	}
	timeout := opts.OverallTimeout
	if timeout <= 0 {
		timeout = DefaultOverallTimeout
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	run := opts.Run
	if run == nil {
		run = func(_ context.Context, target model.Target, _ Progress) model.DiagnosticReport {
			return model.DiagnosticReport{
				SchemaVersion: model.DiagnosticSchemaVersion,
				Target:        target,
				Status:        model.ReportStatusError,
				Probes:        []model.ProbeResult{},
			}
		}
	}
	newID := opts.NewID
	if newID == nil {
		newID = defaultID
	}
	return &Manager{
		sessions: make(map[string]*managedSession),
		capacity: make(chan struct{}, maxConcurrent),
		run:      run,
		timeout:  timeout,
		now:      now,
		newID:    newID,
	}
}

// Create validates no semantics itself; callers should pass the normalized
// model.Target returned by model.ParseTarget. NormalizeTarget is also
// applied here as a defensive boundary for non-HTTP callers.
func (m *Manager) Create(target model.Target) (Snapshot, error) {
	target = model.NormalizeTarget(target)
	select {
	case m.capacity <- struct{}{}:
	default:
		return Snapshot{}, ErrBusy
	}

	ctx, cancel := context.WithCancel(context.Background())
	started := m.currentTime()

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		cancel()
		<-m.capacity
		return Snapshot{}, ErrClosed
	}
	id := m.uniqueIDLocked()
	s := &managedSession{
		id:          id,
		target:      target,
		state:       StateRunning,
		startedAt:   &started,
		ctx:         ctx,
		cancel:      cancel,
		done:        make(chan struct{}),
		subscribers: make(map[chan Event]struct{}),
		now:         m.now,
	}
	m.sessions[id] = s
	m.mu.Unlock()

	go m.execute(s)
	return s.snapshot(), nil
}

// Get returns a point-in-time snapshot of a session.
func (m *Manager) Get(id string) (Snapshot, error) {
	s, err := m.lookup(id)
	if err != nil {
		return Snapshot{}, err
	}
	return s.snapshot(), nil
}

// Cancel requests cancellation and propagates it to the runner's context.
// The state is cancelling until the runner has returned and the final report
// has been recorded, at which point it becomes cancelled.
func (m *Manager) Cancel(id string) (Snapshot, error) {
	s, err := m.lookup(id)
	if err != nil {
		return Snapshot{}, err
	}
	s.mu.Lock()
	if !terminal(s.state) {
		s.cancelRequested = true
		if s.state == StateRunning {
			s.state = StateCancelling
		}
		cancel := s.cancel
		snapshot := s.snapshotLocked()
		s.mu.Unlock()
		cancel()
		return snapshot, nil
	}
	snapshot := s.snapshotLocked()
	s.mu.Unlock()
	return snapshot, nil
}

// Events returns all retained events with a sequence greater than after.
// Sequence numbers are scoped to one session and start at one.
func (m *Manager) Events(id string, after uint64) ([]Event, error) {
	s, err := m.lookup(id)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	events := make([]Event, 0, len(s.events))
	for _, event := range s.events {
		if event.Sequence > after {
			events = append(events, event)
		}
	}
	return events, nil
}

// Subscribe replays retained events after after and then delivers future
// events. The returned channel is closed when the session reaches a terminal
// state or when unsubscribe is called. Delivery is buffered and non-blocking
// so a slow browser cannot stall diagnostic execution.
func (m *Manager) Subscribe(id string, after uint64) (<-chan Event, func(), error) {
	s, err := m.lookup(id)
	if err != nil {
		return nil, nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	bufferSize := subscriberBuffer
	if len(s.events)+1 > bufferSize {
		bufferSize = len(s.events) + 1
	}
	ch := make(chan Event, bufferSize)
	for _, event := range s.events {
		if event.Sequence > after {
			ch <- event
		}
	}
	if terminal(s.state) {
		close(ch)
		return ch, func() {}, nil
	}
	s.subscribers[ch] = struct{}{}
	var once sync.Once
	unsubscribe := func() {
		once.Do(func() {
			s.mu.Lock()
			if _, ok := s.subscribers[ch]; ok {
				delete(s.subscribers, ch)
				close(ch)
			}
			s.mu.Unlock()
		})
	}
	return ch, unsubscribe, nil
}

// Wait waits for a terminal state and is useful to non-HTTP callers and
// deterministic tests.
func (m *Manager) Wait(ctx context.Context, id string) (Snapshot, error) {
	s, err := m.lookup(id)
	if err != nil {
		return Snapshot{}, err
	}
	select {
	case <-s.done:
		return s.snapshot(), nil
	case <-ctx.Done():
		return Snapshot{}, ctx.Err()
	}
}

// Close cancels every non-terminal session and rejects new sessions. It does
// not delete completed in-memory snapshots; the process lifetime is their
// retention boundary.
func (m *Manager) Close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	sessions := make([]*managedSession, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	m.mu.Unlock()
	for _, s := range sessions {
		s.mu.Lock()
		if !terminal(s.state) {
			s.cancelRequested = true
			if s.state == StateRunning {
				s.state = StateCancelling
			}
			cancel := s.cancel
			s.mu.Unlock()
			cancel()
			continue
		}
		s.mu.Unlock()
	}
}

func (m *Manager) execute(s *managedSession) {
	defer func() { <-m.capacity }()
	defer s.cancel()

	s.emit(Event{Type: EventDiagnosisStarted, Target: targetPointer(s.target)})

	ctx, cancel := context.WithTimeout(s.ctx, m.timeout)
	defer cancel()
	progress := Progress{
		SessionID: s.id,
		ProbeStarted: func(name string) {
			s.emit(Event{Type: EventProbeStarted, ProbeName: name})
		},
		ProbeCompleted: func(result model.ProbeResult) {
			resultCopy := result
			s.emit(Event{Type: EventProbeCompleted, ProbeName: result.Name, Result: &resultCopy})
		},
		Emit: func(event Event) {
			s.emit(event)
		},
	}

	report, panicked := runSafely(m.run, ctx, s.target, progress, m.currentTime)

	s.mu.Lock()
	completed := m.currentTime()
	s.completedAt = &completed
	s.report = &report
	if s.cancelRequested {
		s.state = StateCancelled
	} else if panicked {
		s.state = StateFailed
	} else {
		s.state = StateCompleted
	}
	for _, finding := range report.Findings {
		findingCopy := finding
		s.emitLocked(Event{Type: EventFindingUpdated, Finding: &findingCopy})
	}
	if s.state == StateCancelled {
		reportCopy := report
		s.emitLocked(Event{Type: EventDiagnosisCancelled, Report: &reportCopy})
	} else {
		reportCopy := report
		s.emitLocked(Event{Type: EventDiagnosisCompleted, Report: &reportCopy})
	}
	for subscriber := range s.subscribers {
		delete(s.subscribers, subscriber)
		close(subscriber)
	}
	close(s.done)
	s.mu.Unlock()
}

func runSafely(run Runner, ctx context.Context, target model.Target, progress Progress, now func() time.Time) (report model.DiagnosticReport, panicked bool) {
	defer func() {
		if recovered := recover(); recovered != nil {
			started := now()
			completed := now()
			report = model.DiagnosticReport{
				SchemaVersion: model.DiagnosticSchemaVersion,
				Target:        target,
				Status:        model.ReportStatusError,
				StartedAt:     &started,
				CompletedAt:   &completed,
				Probes:        []model.ProbeResult{},
			}
			panicked = true
		}
	}()
	return run(ctx, target, progress), false
}

func (s *managedSession) emit(event Event) {
	s.mu.Lock()
	s.emitLocked(event)
	s.mu.Unlock()
}

func (s *managedSession) emitLocked(event Event) {
	s.nextSequence++
	event.SchemaVersion = EventSchemaVersion
	event.Sequence = s.nextSequence
	event.SessionID = s.id
	event.Timestamp = eventTimestamp(event.Timestamp, s.now)
	if len(s.events) == maxEventHistory {
		copy(s.events, s.events[1:])
		s.events[len(s.events)-1] = event
	} else {
		s.events = append(s.events, event)
	}
	for subscriber := range s.subscribers {
		select {
		case subscriber <- event:
		default:
			// A subscriber that cannot accept a bounded event buffer is no
			// longer a reliable SSE consumer. Drop it without blocking the
			// diagnostic runner.
			delete(s.subscribers, subscriber)
			close(subscriber)
		}
	}
}

// eventTimestamp keeps Event construction compact while ensuring every
// emitted timestamp is canonical UTC. Session-specific clocks are applied
// when callers leave Timestamp empty.
func eventTimestamp(timestamp time.Time, now func() time.Time) time.Time {
	if timestamp.IsZero() {
		return now().UTC()
	}
	return timestamp.UTC()
}

func (s *managedSession) snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshotLocked()
}

func (s *managedSession) snapshotLocked() Snapshot {
	return Snapshot{
		ID:              s.id,
		Target:          s.target,
		State:           s.state,
		StartedAt:       cloneTime(s.startedAt),
		CompletedAt:     cloneTime(s.completedAt),
		CancelRequested: s.cancelRequested,
		Report:          s.report,
	}
}

func (m *Manager) lookup(id string) (*managedSession, error) {
	m.mu.Lock()
	s, ok := m.sessions[id]
	m.mu.Unlock()
	if !ok {
		return nil, ErrNotFound
	}
	return s, nil
}

func (m *Manager) uniqueIDLocked() string {
	for attempts := 0; attempts < 16; attempts++ {
		id := m.newID()
		if id == "" {
			id = defaultID()
		}
		if _, exists := m.sessions[id]; !exists {
			return id
		}
	}
	for {
		id := defaultID()
		if _, exists := m.sessions[id]; !exists {
			return id
		}
	}
}

func (m *Manager) currentTime() time.Time {
	return m.now().UTC()
}

func targetPointer(target model.Target) *model.Target {
	copy := target
	return &copy
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := value.UTC()
	return &copy
}

func terminal(state State) bool {
	return state == StateCompleted || state == StateCancelled || state == StateFailed
}

var fallbackID atomic.Uint64

func defaultID() string {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err == nil {
		return hex.EncodeToString(bytes[:])
	}
	return fmt.Sprintf("session-%d", fallbackID.Add(1))
}
