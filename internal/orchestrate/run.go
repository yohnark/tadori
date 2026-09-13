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
	"github.com/yohnark/tadori/internal/probe/http"
	"github.com/yohnark/tadori/internal/probe/interfacecfg"
	"github.com/yohnark/tadori/internal/probe/proxy"
	"github.com/yohnark/tadori/internal/probe/route"
	"github.com/yohnark/tadori/internal/probe/tcp"
	"github.com/yohnark/tadori/internal/probe/tls"
)

// DefaultProbeTimeout bounds one probe invocation when Options.ProbeTimeout
// is not set. Each probe package already enforces its own internal bound;
// this timeout is the orchestration-level backstop shared by every probe.
const DefaultProbeTimeout = 15 * time.Second

// Options controls one diagnostic run.
type Options struct {
	// ProbeTimeout bounds each individual probe invocation. A non-positive
	// value selects DefaultProbeTimeout.
	ProbeTimeout time.Duration
	// Now supplies the clock used for report timestamps. It defaults to
	// time.Now and exists for deterministic tests.
	Now func() time.Time
}

// Run resolves target, invokes every wired probe concurrently under bounded
// per-probe timeouts, and returns a diagnosed report. A probe that fails or
// errors does not prevent the other probes' results from being collected:
// every probe result reaching the report is preserved even when other probes
// fail. Report status is then aggregated from the canonical probe results;
// diagnosis remains a separate interpretation of those results.
func Run(ctx context.Context, target model.Target, opts Options) model.DiagnosticReport {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	timeout := opts.ProbeTimeout
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}

	started := now().UTC()

	results := runProbes(ctx, target, timeout)

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
func runProbes(ctx context.Context, target model.Target, timeout time.Duration) []model.ProbeResult {
	execution := probe.ExecutionContext{Target: target}

	var resolvedAddr netip.Addr
	resolvedReady := make(chan struct{})

	type job struct {
		name string
		run  func(runCtx context.Context) model.ProbeResult
	}

	jobs := []job{
		{name: "dns", run: func(runCtx context.Context) model.ProbeResult {
			result := dns.New().Run(runCtx, execution)
			resolvedAddr = resolvedAddress(result)
			close(resolvedReady)
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
		{name: "tcp", run: func(runCtx context.Context) model.ProbeResult {
			return tcp.New(timeout).Run(runCtx, execution)
		}},
		{name: "tls", run: func(runCtx context.Context) model.ProbeResult {
			return tls.New(tls.Config{}).Run(runCtx, execution)
		}},
		{name: "http", run: func(runCtx context.Context) model.ProbeResult {
			return http.New().Run(runCtx, execution)
		}},
	}

	results := make([]model.ProbeResult, len(jobs))

	var wg sync.WaitGroup
	wg.Add(len(jobs))
	for i, j := range jobs {
		i, j := i, j
		go func() {
			defer wg.Done()
			results[i] = runBounded(ctx, timeout, j.run)
		}()
	}
	wg.Wait()

	return results
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
func runBounded(ctx context.Context, timeout time.Duration, fn func(context.Context) model.ProbeResult) (result model.ProbeResult) {
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	defer func() {
		if r := recover(); r != nil {
			result = model.ProbeResult{
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

	// A successful HTTP observation establishes the end-to-end result. In
	// particular, a successful response must not be downgraded because a
	// weaker supporting probe could not run. Only a canonical successful
	// interpretation has this early-dominance rule; an actual failure still
	// participates in the incomplete-evidence check below.
	for _, result := range results {
		if result.Interpretation.Layer == model.LayerHTTP &&
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
	case model.LayerGateway, model.LayerICMP, model.LayerProxy:
		return true
	default:
		return false
	}
}
