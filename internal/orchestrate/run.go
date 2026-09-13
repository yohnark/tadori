package orchestrate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yohnark/tadori/internal/diagnosis"
	"github.com/yohnark/tadori/internal/model"
	"github.com/yohnark/tadori/internal/observations"
	"github.com/yohnark/tadori/internal/packet"
	"github.com/yohnark/tadori/internal/probe"
	"github.com/yohnark/tadori/internal/probe/dns"
	"github.com/yohnark/tadori/internal/probe/enterprise"
	"github.com/yohnark/tadori/internal/probe/http"
	"github.com/yohnark/tadori/internal/probe/interfacecfg"
	pathprobe "github.com/yohnark/tadori/internal/probe/path"
	"github.com/yohnark/tadori/internal/probe/proxy"
	"github.com/yohnark/tadori/internal/probe/rdp"
	"github.com/yohnark/tadori/internal/probe/route"
	"github.com/yohnark/tadori/internal/probe/smb"
	"github.com/yohnark/tadori/internal/probe/ssh"
	"github.com/yohnark/tadori/internal/probe/tcp"
	"github.com/yohnark/tadori/internal/probe/tls"
)

// DefaultProbeTimeout bounds one probe invocation when Options.ProbeTimeout
// is not set. Each probe package already enforces its own internal bound;
// this timeout is the orchestration-level backstop shared by every probe.
const DefaultProbeTimeout = 15 * time.Second

// DefaultProbeConcurrency bounds the number of probes executing in one
// diagnostic run. The value is intentionally small for the local runtime:
// it keeps resource use predictable while preserving useful parallelism.
const DefaultProbeConcurrency = 4

// ProbeStartedFunc and ProbeCompletedFunc are optional progress hooks. Hooks
// are notifications only; they do not alter the report or probe scheduling.
// A hook may be called from a worker goroutine.
type ProbeStartedFunc func(name string)
type ProbeCompletedFunc func(result model.ProbeResult)

// Options controls one diagnostic run.
type Options struct {
	// ProbeTimeout bounds each individual probe invocation. A non-positive
	// value selects DefaultProbeTimeout.
	ProbeTimeout time.Duration
	// Now supplies the clock used for report timestamps. It defaults to
	// time.Now and exists for deterministic tests.
	Now func() time.Time
	// ProbeConcurrency bounds concurrently executing probes. A non-positive
	// value selects DefaultProbeConcurrency.
	ProbeConcurrency int
	// OnProbeStarted is called immediately before a probe is invoked.
	OnProbeStarted ProbeStartedFunc
	// OnProbeCompleted is called after a probe returns a result (including an
	// execution error or timeout result).
	OnProbeCompleted ProbeCompletedFunc
	// SessionID scopes packet observations to one diagnostic session. When
	// empty, Run creates an ephemeral process-local run identity.
	SessionID string
	// PacketBackend supplies the bounded packet acquisition adapter. Nil uses
	// the platform default; an unavailable default is reported as evidence and
	// does not fail TCP/path or unrelated probes.
	PacketBackend packet.Backend
}

var runSequence atomic.Uint64

// Run resolves target, invokes every wired probe concurrently under bounded
// per-probe timeouts, and returns a diagnosed report. A probe that fails or
// errors does not prevent the other probes' results from being collected:
// every probe result reaching the report is preserved even when other probes
// fail. Report status is then aggregated from the canonical probe results;
// diagnosis remains a separate interpretation of those results.
func Run(ctx context.Context, target model.Target, opts Options) model.DiagnosticReport {
	target = model.NormalizeTarget(target)
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	timeout := opts.ProbeTimeout
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}
	probeConcurrency := opts.ProbeConcurrency
	if probeConcurrency <= 0 {
		probeConcurrency = DefaultProbeConcurrency
	}

	started := now().UTC()
	sessionID := opts.SessionID
	if sessionID == "" {
		sessionID = fmt.Sprintf("run-%d-%d", started.UnixNano(), runSequence.Add(1))
	}
	backend := opts.PacketBackend
	if backend == nil {
		backend = packet.DefaultBackend()
	}

	results := runProbes(ctx, target, timeout, probeConcurrency, sessionID, backend, opts.OnProbeStarted, opts.OnProbeCompleted)
	target = enrichTargetEndpoints(target, results)
	if networkContext, ok := route.NetworkContextFromProbeResults(target, results); ok {
		target.NetworkContext = &networkContext
	}
	for index := range results {
		results[index].Target = target
	}

	sort.Slice(results, func(i, j int) bool { return results[i].Name < results[j].Name })

	completed := now().UTC()
	report := model.DiagnosticReport{
		SchemaVersion: model.DiagnosticSchemaVersion,
		// Target is the user/request intent in the report contract. Runtime
		// endpoint, resolver, and route facts are projected into Observations;
		// probe-local execution targets retain compatibility for existing probe
		// and diagnosis consumers during the migration window.
		Target:       model.TargetIntentOnly(target),
		SessionID:    sessionID,
		Status:       reportStatus(results),
		StartedAt:    &started,
		CompletedAt:  &completed,
		Probes:       results,
		Observations: observations.Build(target, results),
	}
	report = diagnosis.DiagnoseReport(report)
	return report
}

// runProbes executes every wired probe concurrently, including DNS. The
// route, default-route, and gateway probes benefit from the address DNS resolves, so they
// wait only on a small channel carrying that one result (with the shared
// deadline still enforced) rather than the batch waiting on DNS in serial.
// A probe that panics, errors, or times out still yields a result for its
// slot, so a single failing probe cannot drop the others.
func runProbes(ctx context.Context, target model.Target, timeout time.Duration, concurrency int, sessionID string, backend packet.Backend, onStarted ProbeStartedFunc, onCompleted ProbeCompletedFunc) []model.ProbeResult {
	if concurrency <= 0 {
		concurrency = DefaultProbeConcurrency
	}
	selection := &endpointSelectionState{}
	resolvedReady := make(chan struct{})
	transportReady := make(chan struct{})

	type job struct {
		name       string
		packetType packet.ProbeType
		run        func(runCtx context.Context, execution probe.ExecutionContext) model.ProbeResult
	}

	jobs := []job{
		{name: "dns", run: func(runCtx context.Context, execution probe.ExecutionContext) model.ProbeResult {
			defer close(resolvedReady)
			result := dns.New().Run(runCtx, execution)
			selection.setCandidates(endpointCandidatesFromDNS(target, result))
			return result
		}},
		{name: "interface_state", run: func(runCtx context.Context, execution probe.ExecutionContext) model.ProbeResult {
			return interfacecfg.NewInterfaceProbe().Run(runCtx, execution)
		}},
		{name: "dns_configuration", run: func(runCtx context.Context, execution probe.ExecutionContext) model.ProbeResult {
			return interfacecfg.NewDNSProbe().Run(runCtx, execution)
		}},
		{name: "tcp", packetType: packet.ProbeTypeTCP, run: func(runCtx context.Context, execution probe.ExecutionContext) model.ProbeResult {
			defer close(transportReady)
			result := tcp.New(timeout).Run(runCtx, execution)
			selection.setTested(result.Target.TestedEndpoint)
			return result
		}},
		{name: route.DefaultRouteProbeName, run: func(runCtx context.Context, execution probe.ExecutionContext) model.ProbeResult {
			p := route.NewDefaultRouteProbe()
			if targetIP := targetAddressForProbe(execution.Target); targetIP.IsValid() {
				return p.RunForAddress(runCtx, execution, targetIP)
			}
			return p.Run(runCtx, execution)
		}},
		{name: route.TargetRouteProbeName, run: func(runCtx context.Context, execution probe.ExecutionContext) model.ProbeResult {
			p := route.NewTargetRouteProbe()
			if targetIP := targetAddressForProbe(execution.Target); targetIP.IsValid() {
				return p.RunForAddress(runCtx, execution, targetIP)
			}
			return p.Run(runCtx, execution)
		}},
		{name: route.GatewayProbeName, run: func(runCtx context.Context, execution probe.ExecutionContext) model.ProbeResult {
			p := route.NewGatewayProbe()
			if targetIP := targetAddressForProbe(execution.Target); targetIP.IsValid() {
				return p.RunForAddress(runCtx, execution, targetIP)
			}
			return p.Run(runCtx, execution)
		}},
		{name: proxy.Name, run: func(runCtx context.Context, execution probe.ExecutionContext) model.ProbeResult {
			return proxy.NewProbe().Run(runCtx, execution)
		}},
		{name: enterprise.Name, run: func(runCtx context.Context, execution probe.ExecutionContext) model.ProbeResult {
			return enterprise.New().Run(runCtx, execution)
		}},
		{name: pathprobe.PathProbeName, packetType: packet.ProbeTypePath, run: func(runCtx context.Context, execution probe.ExecutionContext) model.ProbeResult {
			return pathprobe.New(pathprobe.Config{Timeout: timeout}).Run(runCtx, execution)
		}},
	}
	if target.ApplicationProtocol == model.ApplicationProtocolHTTPS {
		jobs = append(jobs,
			job{name: "tls", run: func(runCtx context.Context, execution probe.ExecutionContext) model.ProbeResult {
				return tls.New(tls.Config{}).Run(runCtx, execution)
			}},
			job{name: "http", run: func(runCtx context.Context, execution probe.ExecutionContext) model.ProbeResult {
				return http.New().Run(runCtx, execution)
			}},
		)
	} else if target.ApplicationProtocol == model.ApplicationProtocolTLS {
		jobs = append(jobs,
			job{name: "tls", run: func(runCtx context.Context, execution probe.ExecutionContext) model.ProbeResult {
				return tls.New(tls.Config{}).Run(runCtx, execution)
			}},
			job{name: "http", run: func(runCtx context.Context, execution probe.ExecutionContext) model.ProbeResult {
				return skippedURLProbe(runCtx, target, "http", model.LayerHTTP, model.FaultDomainHTTP)
			}},
		)
	} else if target.ApplicationProtocol == model.ApplicationProtocolHTTP {
		jobs = append(jobs,
			job{name: "tls", run: func(runCtx context.Context, execution probe.ExecutionContext) model.ProbeResult {
				return skippedURLProbe(runCtx, target, "tls", model.LayerTLS, model.FaultDomainTLS)
			}},
			job{name: "http", run: func(runCtx context.Context, execution probe.ExecutionContext) model.ProbeResult {
				return http.New().Run(runCtx, execution)
			}},
		)
	} else if target.ApplicationProtocol == model.ApplicationProtocolSSH {
		jobs = append(jobs,
			job{name: "ssh", run: func(runCtx context.Context, execution probe.ExecutionContext) model.ProbeResult {
				return ssh.New(timeout).Run(runCtx, execution)
			}},
			job{name: "tls", run: func(runCtx context.Context, execution probe.ExecutionContext) model.ProbeResult {
				return skippedURLProbe(runCtx, target, "tls", model.LayerTLS, model.FaultDomainTLS)
			}},
			job{name: "http", run: func(runCtx context.Context, execution probe.ExecutionContext) model.ProbeResult {
				return skippedURLProbe(runCtx, target, "http", model.LayerHTTP, model.FaultDomainHTTP)
			}},
		)
	} else if target.ApplicationProtocol == model.ApplicationProtocolRDP {
		jobs = append(jobs,
			job{name: "rdp", run: func(runCtx context.Context, execution probe.ExecutionContext) model.ProbeResult {
				return rdp.New(rdp.Config{Timeout: timeout}).Run(runCtx, execution)
			}},
			job{name: "tls", run: func(runCtx context.Context, execution probe.ExecutionContext) model.ProbeResult {
				return skippedURLProbe(runCtx, target, "tls", model.LayerTLS, model.FaultDomainTLS)
			}},
			job{name: "http", run: func(runCtx context.Context, execution probe.ExecutionContext) model.ProbeResult {
				return skippedURLProbe(runCtx, target, "http", model.LayerHTTP, model.FaultDomainHTTP)
			}},
		)
	} else {
		if target.ApplicationProtocol == model.ApplicationProtocolSMB {
			jobs = append(jobs, job{name: smb.Name, run: func(runCtx context.Context, execution probe.ExecutionContext) model.ProbeResult {
				return smb.New(smb.Config{Timeout: timeout}).Run(runCtx, execution)
			}})
		}
		// Non-HTTP profiles retain lower-layer diagnostics and expose explicit
		// skipped URL lanes rather than guessing an application probe.
		jobs = append(jobs,
			job{name: "tls", run: func(runCtx context.Context, execution probe.ExecutionContext) model.ProbeResult {
				return skippedURLProbe(runCtx, target, "tls", model.LayerTLS, model.FaultDomainTLS)
			}},
			job{name: "http", run: func(runCtx context.Context, execution probe.ExecutionContext) model.ProbeResult {
				return skippedURLProbe(runCtx, target, "http", model.LayerHTTP, model.FaultDomainHTTP)
			}},
		)
	}
	if target.Service.ID == model.ServiceProfileDNS || target.ApplicationProtocol == model.ApplicationProtocolDNS {
		jobs = append(jobs, job{name: dns.ServiceProbeName, run: func(runCtx context.Context, execution probe.ExecutionContext) model.ProbeResult {
			return dns.NewDNSServiceProbe(dns.WithServiceTimeout(timeout)).Run(runCtx, execution)
		}})
	}

	results := make([]model.ProbeResult, len(jobs))

	if concurrency > len(jobs) {
		concurrency = len(jobs)
	}

	// The jobs channel is finite and the worker count is explicit. Every job
	// is drained even after cancellation so the report retains one result slot
	// per wired probe and progress consumers see terminal probe events.
	jobsCh := make(chan struct {
		index int
		job   job
	}, len(jobs))
	for i, j := range jobs {
		jobsCh <- struct {
			index int
			job   job
		}{index: i, job: j}
	}
	close(jobsCh)

	var wg sync.WaitGroup
	wg.Add(concurrency)
	for worker := 0; worker < concurrency; worker++ {
		go func() {
			defer wg.Done()
			for item := range jobsCh {
				notifyProbeStarted(onStarted, item.job.name)
				identity := model.ProbeIdentity{
					SessionID:     sessionID,
					ProbeID:       item.job.name,
					CorrelationID: sessionID + "/" + item.job.name,
				}
				probeTarget := target
				result := runBounded(ctx, timeout, item.job.name, func(runCtx context.Context) model.ProbeResult {
					if item.job.name != "dns" && item.job.name != "interface_state" && item.job.name != "dns_configuration" {
						probeTarget = targetWithResolvedCandidates(runCtx, resolvedReady, selection, target)
						if waitsForTransportEndpoint(item.job.name) {
							probeTarget = targetWithTransportEndpoint(runCtx, transportReady, selection, probeTarget)
						}
					}
					execution := probe.ExecutionContext{Target: probeTarget, SessionID: identity.SessionID, ProbeID: identity.ProbeID, CorrelationID: identity.CorrelationID}
					if item.job.packetType == "" {
						return item.job.run(runCtx, execution)
					}
					return runWithPacketEvidence(runCtx, item.job.run, execution, item.job.packetType, backend)
				})
				if result.Name == "" {
					result.Name = item.job.name
				}
				if result.Target.OriginalInput == "" && result.Target.RequestedIdentity == "" && result.Target.Port == 0 {
					result.Target = probeTarget
				}
				result.SessionID = identity.SessionID
				result.ProbeID = identity.ProbeID
				result.CorrelationID = identity.CorrelationID
				results[item.index] = result
				notifyProbeCompleted(onCompleted, result)
			}
		}()
	}
	wg.Wait()

	return results
}

func runWithPacketEvidence(ctx context.Context, run func(context.Context, probe.ExecutionContext) model.ProbeResult, execution probe.ExecutionContext, probeType packet.ProbeType, backend packet.Backend) model.ProbeResult {
	windowStarted := time.Now().UTC()
	scope := packet.Scope{
		Identity:      model.ProbeIdentity{SessionID: execution.SessionID, ProbeID: execution.ProbeID, CorrelationID: execution.CorrelationID},
		Target:        execution.Target,
		ProbeType:     probeType,
		ProcessID:     uint32(os.Getpid()),
		WindowStarted: windowStarted,
	}
	if deadline, ok := ctx.Deadline(); ok {
		scope.Deadline = deadline.UTC()
	}

	var capture packet.Capture
	var startErr error
	if backend == nil {
		startErr = packet.ErrUnsupported
	} else {
		capture, startErr = backend.Start(ctx, scope)
		if startErr == nil && capture == nil {
			startErr = fmt.Errorf("%w: backend returned a nil capture", packet.ErrUnsupported)
		}
	}

	result := run(ctx, execution)
	var captureResult packet.CaptureResult
	var stopErr error
	if capture != nil {
		captureResult, stopErr = capture.Stop()
	}
	flow := packet.Correlate(packet.CorrelationInput{
		Scope:        scope,
		Result:       result,
		ProbeStarted: true,
		Capture:      captureResult,
		StartError:   startErr,
		StopError:    stopErr,
		Cancelled:    errors.Is(ctx.Err(), context.Canceled),
	})
	if evidence, err := model.PacketFlowEvidenceFor(flow); err == nil {
		result.Evidence = append(result.Evidence, evidence)
	}
	return result
}

func notifyProbeStarted(callback ProbeStartedFunc, name string) {
	if callback == nil {
		return
	}
	defer func() { _ = recover() }()
	callback(name)
}

func notifyProbeCompleted(callback ProbeCompletedFunc, result model.ProbeResult) {
	if callback == nil {
		return
	}
	defer func() { _ = recover() }()
	callback(result)
}

// endpointSelectionState is the small orchestration hand-off between DNS,
// transport, and the dependent route/path/application lanes. The mutex makes
// publication and snapshots race-safe while the channels provide the explicit
// ordering edges between probe phases.
type endpointSelectionState struct {
	mu         sync.RWMutex
	candidates []model.EndpointCandidate
	tested     *model.Endpoint
}

func (s *endpointSelectionState) setCandidates(candidates []model.EndpointCandidate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.candidates = append([]model.EndpointCandidate(nil), candidates...)
}

func (s *endpointSelectionState) candidatesSnapshot() []model.EndpointCandidate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]model.EndpointCandidate(nil), s.candidates...)
}

func (s *endpointSelectionState) setTested(endpoint *model.Endpoint) {
	if endpoint == nil || endpoint.Address == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	copy := *endpoint
	s.tested = &copy
}

func (s *endpointSelectionState) testedSnapshot() *model.Endpoint {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.tested == nil {
		return nil
	}
	copy := *s.tested
	return &copy
}

func endpointCandidatesFromDNS(target model.Target, result model.ProbeResult) []model.EndpointCandidate {
	if target.LiteralIP != "" {
		return target.ProbeEndpointCandidates()
	}
	if result.NameResolution != nil {
		return model.EndpointCandidatesFromAnswers(result.NameResolution.A, result.NameResolution.AAAA)
	}
	for _, evidence := range result.Evidence {
		if evidence.Kind != model.EvidenceKindDNSResolution {
			continue
		}
		var resolution dns.DNSResolutionEvidence
		if err := json.Unmarshal(evidence.Raw, &resolution); err == nil {
			return model.EndpointCandidatesFromAnswers(resolution.A, resolution.AAAA)
		}
	}
	return nil
}

func endpointForCandidate(candidate model.EndpointCandidate, port uint16, reason model.EndpointSelectionReason) *model.Endpoint {
	return &model.Endpoint{
		Address: candidate.Address, Port: port, Family: candidate.Family,
		SelectionReason: reason,
		Provenance:      "tadori bounded deterministic candidate selection",
	}
}

func targetWithResolvedCandidates(ctx context.Context, ready <-chan struct{}, state *endpointSelectionState, target model.Target) model.Target {
	target = model.NormalizeTarget(target)
	if target.LiteralIP != "" {
		candidates := target.ProbeEndpointCandidates()
		if len(candidates) > 0 {
			applyCandidates(&target, candidates)
		}
		return target
	}
	select {
	case <-ready:
	case <-ctx.Done():
		return target
	}
	candidates := state.candidatesSnapshot()
	if len(candidates) == 0 {
		candidates = target.ProbeEndpointCandidates()
	}
	if len(candidates) > 0 {
		applyCandidates(&target, candidates)
	}
	return target
}

func targetWithTransportEndpoint(ctx context.Context, ready <-chan struct{}, state *endpointSelectionState, target model.Target) model.Target {
	select {
	case <-ready:
		if tested := state.testedSnapshot(); tested != nil {
			target.TestedEndpoint = tested
			selected := *tested
			target.SelectedEndpoint = &selected
		}
	case <-ctx.Done():
	}
	return target
}

func applyCandidates(target *model.Target, candidates []model.EndpointCandidate) {
	if target == nil || len(candidates) == 0 {
		return
	}
	target.ResolvedCandidates = append([]model.EndpointCandidate(nil), candidates...)
	target.ProbeCandidates = model.LimitEndpointCandidates(candidates, model.MaxEndpointCandidates)
	if len(target.ProbeCandidates) == 0 {
		return
	}
	target.ResolvedAddresses = make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		target.ResolvedAddresses = append(target.ResolvedAddresses, candidate.Address)
	}
	selected := endpointForCandidate(target.ProbeCandidates[0], target.Port, model.EndpointSelectionDeterministic)
	target.SelectedEndpoint = selected
}

func waitsForTransportEndpoint(name string) bool {
	switch name {
	case "path", "tls", "http", "ssh", "rdp", smb.Name, route.DefaultRouteProbeName, route.TargetRouteProbeName, route.GatewayProbeName:
		return true
	default:
		return false
	}
}

func targetAddressForProbe(target model.Target) netip.Addr {
	target = model.NormalizeTarget(target)
	values := make([]string, 0, 4)
	if target.SelectedEndpoint != nil {
		values = append(values, target.SelectedEndpoint.Address)
	}
	if target.TestedEndpoint != nil {
		values = append(values, target.TestedEndpoint.Address)
	}
	for _, candidate := range target.ProbeCandidates {
		values = append(values, candidate.Address)
	}
	values = append(values, target.LiteralIP, target.RequestedIdentity)
	for _, value := range values {
		if address, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(value), "[]")); err == nil {
			return model.NormalizeAddr(address)
		}
	}
	return netip.Addr{}
}

func applyLegacyResolvedAddress(target *model.Target, address netip.Addr) {
	if target == nil || !address.IsValid() {
		return
	}
	candidate := model.EndpointCandidate{Address: model.NormalizeAddr(address).String(), Order: 1}
	if address.Is4() {
		candidate.Family = model.EndpointFamilyIPv4
	} else {
		candidate.Family = model.EndpointFamilyIPv6
	}
	applyCandidates(target, []model.EndpointCandidate{candidate})
}

// waitForAddress blocks until the DNS probe publishes its resolved address by
// closing ready, or until runCtx's own deadline expires (including when the
// DNS job never publishes because it panicked or was itself canceled). addr
// must not be read until ready is closed, which the happens-before edge from
// close(ready) in the DNS job guarantees.
func waitForAddress(runCtx context.Context, ready <-chan struct{}, addr *netip.Addr) netip.Addr {
	select {
	case <-ready:
		return *addr
	case <-runCtx.Done():
		return netip.Addr{}
	}
}

func targetWithResolvedAddress(ctx context.Context, ready <-chan struct{}, addr *netip.Addr, target model.Target) model.Target {
	if target.LiteralIP != "" {
		if target.SelectedEndpoint == nil {
			if parsed, err := netip.ParseAddr(target.LiteralIP); err == nil {
				applyLegacyResolvedAddress(&target, parsed)
			}
		}
		return target
	}
	selected := waitForAddress(ctx, ready, addr)
	if selected.IsValid() {
		applyLegacyResolvedAddress(&target, selected)
	}
	return target
}

// runBounded applies a per-probe deadline on top of ctx and recovers a panic
// from a probe implementation so it cannot take down the whole diagnostic
// run; a recovered panic is reported as an execution error result.
func runBounded(ctx context.Context, timeout time.Duration, name string, fn func(context.Context) model.ProbeResult) (result model.ProbeResult) {
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	defer func() {
		if r := recover(); r != nil {
			result = model.ProbeResult{
				Name:   name,
				Status: model.ProbeStatusError,
				Interpretation: model.ProbeInterpretation{
					FailureReason: model.FailureReasonProbeExecution,
					Layer:         model.LayerUnknown,
					FaultDomain:   model.FaultDomainUnknown,
				},
			}
		}
	}()
	return fn(runCtx)
}

// resolvedAddress extracts the first usable address observed by the DNS
// probe so the route and gateway probes can select a route toward the same
// address the HTTP/TCP/TLS lanes will use, rather than re-resolving.
func resolvedAddress(result model.ProbeResult) netip.Addr {
	if result.Status != model.ProbeStatusPassed {
		return netip.Addr{}
	}
	if result.NameResolution != nil {
		if address, err := netip.ParseAddr(result.NameResolution.SelectedAddress); err == nil {
			return model.NormalizeAddr(address)
		}
	}
	for _, evidence := range result.Evidence {
		if evidence.Kind != model.EvidenceKindDNSResolution {
			continue
		}
		var decoded dns.DNSResolutionEvidence
		if err := json.Unmarshal(evidence.Raw, &decoded); err != nil {
			continue
		}
		for _, candidates := range [][]string{decoded.A, decoded.AAAA} {
			for _, candidate := range candidates {
				if addr, err := netip.ParseAddr(candidate); err == nil {
					return addr
				}
			}
		}
	}
	return netip.Addr{}
}

func enrichTargetEndpoints(target model.Target, results []model.ProbeResult) model.Target {
	target = model.NormalizeTarget(target)
	var a, aaaa []string
	for _, result := range results {
		for _, evidence := range result.Evidence {
			if evidence.Kind != model.EvidenceKindDNSResolution {
				continue
			}
			var value dns.DNSResolutionEvidence
			if err := json.Unmarshal(evidence.Raw, &value); err != nil {
				continue
			}
			a = append(a, value.A...)
			aaaa = append(aaaa, value.AAAA...)
		}
	}
	candidates := model.EndpointCandidatesFromAnswers(a, aaaa)
	if len(candidates) == 0 {
		candidates = append([]model.EndpointCandidate(nil), target.ResolvedCandidates...)
	}
	if len(candidates) > 0 {
		applyCandidates(&target, candidates)
	} else if target.LiteralIP != "" {
		if address, err := netip.ParseAddr(target.LiteralIP); err == nil {
			applyLegacyResolvedAddress(&target, address)
		}
	}

	for _, result := range results {
		if result.Name != "tcp" && result.Name != dns.ServiceProbeName {
			continue
		}
		if result.Target.CandidateAttempts != nil {
			target.CandidateAttempts = append([]model.EndpointAttempt(nil), result.Target.CandidateAttempts...)
		}
		if result.Target.TestedEndpoint != nil && result.Target.TestedEndpoint.Address != "" {
			endpoint := *result.Target.TestedEndpoint
			target.TestedEndpoint = &endpoint
		}
		for _, evidence := range result.Evidence {
			if evidence.Kind != model.EvidenceKindTCPConnection {
				continue
			}
			var value struct {
				RemoteEndpoint    string                  `json:"remote_endpoint"`
				TestedEndpoint    string                  `json:"tested_endpoint"`
				CandidateAttempts []model.EndpointAttempt `json:"candidate_attempts"`
			}
			if err := json.Unmarshal(evidence.Raw, &value); err != nil {
				continue
			}
			if len(value.CandidateAttempts) > 0 && len(target.CandidateAttempts) == 0 {
				target.CandidateAttempts = append([]model.EndpointAttempt(nil), value.CandidateAttempts...)
			}
			if value.TestedEndpoint != "" {
				if concrete, ok := concreteEndpoint(value.TestedEndpoint, target.Port); ok {
					concrete.SelectionReason = model.EndpointSelectionTransport
					concrete.Provenance = "transport conn.RemoteAddr observation"
					target.TestedEndpoint = &concrete
				}
			}
			if target.TestedEndpoint == nil && result.Status == model.ProbeStatusPassed && value.RemoteEndpoint != "" {
				if concrete, ok := concreteEndpoint(value.RemoteEndpoint, target.Port); ok {
					concrete.SelectionReason = model.EndpointSelectionTransport
					concrete.Provenance = "transport conn.RemoteAddr observation"
					target.TestedEndpoint = &concrete
				}
			}
		}
	}
	return target
}

func concreteEndpoint(raw string, defaultPort uint16) (model.Endpoint, bool) {
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		host = strings.Trim(raw, "[]")
		port = fmt.Sprintf("%d", defaultPort)
	}
	if host == "" {
		return model.Endpoint{}, false
	}
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsedPort == 0 {
		return model.Endpoint{}, false
	}
	if address, err := netip.ParseAddr(host); err == nil {
		host = model.NormalizeAddr(address).String()
	}
	return model.Endpoint{Address: host, Port: uint16(parsedPort)}, true
}

func reportStatus(results []model.ProbeResult) model.ReportStatus {
	if len(results) == 0 {
		return model.ReportStatusUnknown
	}

	// A successful HTTP, SMB, or TCP observation establishes the requested endpoint
	// boundary. TCP is included because host:port targets intentionally have no
	// HTTP semantics, and a destination TCP success proves reachability even
	// when path hops are unobservable. Only a canonical successful
	// interpretation has this early-dominance rule; an actual failure still
	// participates in the incomplete-evidence check below.
	for _, result := range results {
		if (result.Interpretation.Layer == model.LayerHTTP || result.Interpretation.Layer == model.LayerSMB || result.Interpretation.Layer == model.LayerTCP || result.Interpretation.Layer == model.LayerSSH || result.Interpretation.Layer == model.LayerRDP) &&
			result.Status == model.ProbeStatusPassed &&
			result.Interpretation.FailureReason == model.FailureReasonNone {
			return model.ReportStatusComplete
		}
	}

	for _, result := range results {
		if (result.Status == model.ProbeStatusError || result.Status == model.ProbeStatusSkipped) && !nonFatalUnavailable(result) {
			return model.ReportStatusIncomplete
		}
	}
	return model.ReportStatusComplete
}

// nonFatalUnavailable identifies probes whose absence is expected on some
// platforms and does not, by itself, make the collected connectivity evidence
// inconclusive. The classification is derived from the structured
// interpretation, never from probe names or raw evidence.
func nonFatalUnavailable(result model.ProbeResult) bool {
	if result.Interpretation.FailureReason != model.FailureReasonUnsupported {
		return false
	}
	switch result.Interpretation.Layer {
	case model.LayerGateway, model.LayerICMP, model.LayerNetwork, model.LayerProxy:
		return true
	case model.LayerTLS, model.LayerHTTP:
		return result.Status == model.ProbeStatusSkipped
	default:
		return false
	}
}

func skippedURLProbe(ctx context.Context, target model.Target, name string, layer model.Layer, domain model.FaultDomain) model.ProbeResult {
	started := time.Now().UTC()
	completed := started
	if ctx != nil && ctx.Err() != nil {
		completed = time.Now().UTC()
	}
	return model.ProbeResult{
		Name:   name,
		Target: target,
		Status: model.ProbeStatusSkipped,
		Timing: model.Timing{StartedAt: &started, CompletedAt: &completed, DurationMS: completed.Sub(started).Milliseconds()},
		Interpretation: model.ProbeInterpretation{
			FailureReason: model.FailureReasonUnsupported,
			Layer:         layer,
			FaultDomain:   domain,
		},
	}
}
