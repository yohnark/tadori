package orchestrate

import (
	"context"
	"encoding/json"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/yohnark/tadori/internal/diagnosis"
	"github.com/yohnark/tadori/internal/model"
	"github.com/yohnark/tadori/internal/probe"
	"github.com/yohnark/tadori/internal/probe/dns"
	"github.com/yohnark/tadori/internal/probe/enterprise"
	"github.com/yohnark/tadori/internal/probe/http"
	"github.com/yohnark/tadori/internal/probe/interfacecfg"
	pathprobe "github.com/yohnark/tadori/internal/probe/path"
	"github.com/yohnark/tadori/internal/probe/proxy"
	"github.com/yohnark/tadori/internal/probe/route"
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
}

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

	results := runProbes(ctx, target, timeout, probeConcurrency, opts.OnProbeStarted, opts.OnProbeCompleted)

	sort.Slice(results, func(i, j int) bool { return results[i].Name < results[j].Name })

	completed := now().UTC()
	report := model.DiagnosticReport{
		SchemaVersion: model.DiagnosticSchemaVersion,
		Target:        target,
		Status:        reportStatus(results),
		StartedAt:     &started,
		CompletedAt:   &completed,
		Probes:        results,
	}
	report.Findings = diagnosis.Diagnose(report.Probes)
	return report
}

// runProbes executes every wired probe concurrently, including DNS. The
// route and gateway probes benefit from the address DNS resolves, so they
// wait only on a small channel carrying that one result (with the shared
// deadline still enforced) rather than the batch waiting on DNS in serial.
// A probe that panics, errors, or times out still yields a result for its
// slot, so a single failing probe cannot drop the others.
func runProbes(ctx context.Context, target model.Target, timeout time.Duration, concurrency int, onStarted ProbeStartedFunc, onCompleted ProbeCompletedFunc) []model.ProbeResult {
	if concurrency <= 0 {
		concurrency = DefaultProbeConcurrency
	}
	execution := probe.ExecutionContext{Target: target}

	var resolvedAddr netip.Addr
	resolvedReady := make(chan struct{})

	type job struct {
		name string
		run  func(runCtx context.Context) model.ProbeResult
	}

	jobs := []job{
		{name: "dns", run: func(runCtx context.Context) model.ProbeResult {
			defer close(resolvedReady)
			result := dns.New().Run(runCtx, execution)
			resolvedAddr = resolvedAddress(result)
			return result
		}},
		{name: "interface_state", run: func(runCtx context.Context) model.ProbeResult {
			return interfacecfg.NewInterfaceProbe().Run(runCtx, execution)
		}},
		{name: "dns_configuration", run: func(runCtx context.Context) model.ProbeResult {
			return interfacecfg.NewDNSProbe().Run(runCtx, execution)
		}},
		{name: route.DefaultRouteProbeName, run: func(runCtx context.Context) model.ProbeResult {
			return route.NewDefaultRouteProbe().Run(runCtx, execution)
		}},
		{name: route.TargetRouteProbeName, run: func(runCtx context.Context) model.ProbeResult {
			p := route.NewTargetRouteProbe()
			if targetIP := waitForAddress(runCtx, resolvedReady, &resolvedAddr); targetIP.IsValid() {
				return p.RunForAddress(runCtx, execution, targetIP)
			}
			return p.Run(runCtx, execution)
		}},
		{name: route.GatewayProbeName, run: func(runCtx context.Context) model.ProbeResult {
			p := route.NewGatewayProbe()
			if targetIP := waitForAddress(runCtx, resolvedReady, &resolvedAddr); targetIP.IsValid() {
				return p.RunForAddress(runCtx, execution, targetIP)
			}
			return p.Run(runCtx, execution)
		}},
		{name: proxy.Name, run: func(runCtx context.Context) model.ProbeResult {
			return proxy.NewProbe().Run(runCtx, execution)
		}},
		{name: enterprise.Name, run: func(runCtx context.Context) model.ProbeResult {
			return enterprise.New().Run(runCtx, execution)
		}},
		{name: "tcp", run: func(runCtx context.Context) model.ProbeResult {
			return tcp.New(timeout).Run(runCtx, execution)
		}},
		{name: pathprobe.PathProbeName, run: func(runCtx context.Context) model.ProbeResult {
			return pathprobe.New(pathprobe.Config{Timeout: timeout}).Run(runCtx, execution)
		}},
	}
	if target.URL == "" {
		// A host:port target has no URL semantics. Preserve explicit skipped
		// lanes in the report so consumers can distinguish them from an
		// attempted TLS/HTTP failure.
		jobs = append(jobs,
			job{name: "tls", run: func(runCtx context.Context) model.ProbeResult {
				return skippedURLProbe(runCtx, target, "tls", model.LayerTLS, model.FaultDomainTLS)
			}},
			job{name: "http", run: func(runCtx context.Context) model.ProbeResult {
				return skippedURLProbe(runCtx, target, "http", model.LayerHTTP, model.FaultDomainHTTP)
			}},
		)
	} else {
		jobs = append(jobs,
			job{name: "tls", run: func(runCtx context.Context) model.ProbeResult {
				return tls.New(tls.Config{}).Run(runCtx, execution)
			}},
			job{name: "http", run: func(runCtx context.Context) model.ProbeResult {
				return http.New().Run(runCtx, execution)
			}},
		)
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
				result := runBounded(ctx, timeout, item.job.name, item.job.run)
				if result.Name == "" {
					result.Name = item.job.name
				}
				if result.Target == (model.Target{}) {
					result.Target = target
				}
				results[item.index] = result
				notifyProbeCompleted(onCompleted, result)
			}
		}()
	}
	wg.Wait()

	return results
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

func reportStatus(results []model.ProbeResult) model.ReportStatus {
	if len(results) == 0 {
		return model.ReportStatusUnknown
	}

	// A successful HTTP or TCP observation establishes the requested endpoint
	// boundary. TCP is included because host:port targets intentionally have no
	// HTTP semantics, and a destination TCP success proves reachability even
	// when path hops are unobservable. Only a canonical successful
	// interpretation has this early-dominance rule; an actual failure still
	// participates in the incomplete-evidence check below.
	for _, result := range results {
		if (result.Interpretation.Layer == model.LayerHTTP || result.Interpretation.Layer == model.LayerTCP) &&
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
