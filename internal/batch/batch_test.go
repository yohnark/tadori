package batch

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yohnark/tadori/internal/model"
)

func TestBuildPlanDeduplicatesSemanticServiceAndPort(t *testing.T) {
	capture := captureReport(
		captureDestination("API.Example.", 443, model.BrowserCaptureMechanismCONNECT, model.BrowserCaptureOutcomeConnected, 2, 2, 2, 0),
		captureDestination("api.example", 443, model.BrowserCaptureMechanismCONNECT, model.BrowserCaptureOutcomeFailed, 1, 1, 0, 1),
		captureDestination("api.example", 80, model.BrowserCaptureMechanismHTTP, model.BrowserCaptureOutcomeConnected, 1, 1, 1, 0),
		captureDestination("api.example", 443, model.BrowserCaptureMechanismHTTP, model.BrowserCaptureOutcomeConnected, 1, 1, 1, 0),
	)

	plan, err := BuildPlan(capture, Request{Selection: SelectionAll})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Entries) != 3 {
		t.Fatalf("entries = %d, want 3: %#v", len(plan.Entries), plan.Entries)
	}
	var https443, http443 PlanEntry
	for _, entry := range plan.Entries {
		if entry.Port == 443 && entry.Service.ID == model.ServiceProfileHTTPS {
			https443 = entry
		}
		if entry.Port == 443 && entry.Service.ID == model.ServiceProfileHTTP {
			http443 = entry
		}
	}
	if https443.RequestedIdentity != "api.example" || https443.CaptureObservationCount != 3 || https443.CaptureFailureCount != 1 || !https443.CaptureFailed || https443.CaptureOutcome != model.BrowserCaptureOutcomeMixed {
		t.Fatalf("HTTPS aggregate = %#v", https443)
	}
	if len(https443.CaptureObservations) != 2 {
		t.Fatalf("HTTPS provenance count = %d, want 2", len(https443.CaptureObservations))
	}
	if TargetIdentity(https443) != "https://api.example:443" {
		t.Fatalf("HTTPS identity = %q", TargetIdentity(https443))
	}
	if http443.CaptureFailed || TargetIdentity(http443) != "http://api.example:443" {
		t.Fatalf("HTTP aggregate = %#v", http443)
	}
}

func TestBuildPlanFailedOnlyAndManualSelection(t *testing.T) {
	capture := captureReport(
		captureDestination("ok.example", 443, model.BrowserCaptureMechanismCONNECT, model.BrowserCaptureOutcomeConnected, 1, 1, 1, 0),
		captureDestination("failed.example", 443, model.BrowserCaptureMechanismCONNECT, model.BrowserCaptureOutcomeFailed, 1, 1, 0, 1),
		captureDestination("failed.example", 80, model.BrowserCaptureMechanismHTTP, model.BrowserCaptureOutcomeConnected, 1, 1, 1, 0),
	)
	failed, err := BuildPlan(capture, Request{Selection: SelectionFailedOnly})
	if err != nil {
		t.Fatal(err)
	}
	if len(failed.Entries) != 1 || failed.Entries[0].RequestedIdentity != "failed.example" {
		t.Fatalf("failed-only plan = %#v", failed.Entries)
	}
	manual, err := BuildPlan(capture, Request{Selection: SelectionSelected, Selected: []string{"ok.example"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(manual.Entries) != 1 || manual.Entries[0].RequestedIdentity != "ok.example" {
		t.Fatalf("manual plan = %#v", manual.Entries)
	}
}

func TestBuildPlanRetainsUnsupportedCaptureResult(t *testing.T) {
	plan, err := BuildPlan(captureReport(captureDestination("unsupported.example", 1234, model.BrowserCaptureMechanism("quic"), model.BrowserCaptureOutcomeUnsupported, 1, 0, 0, 1)), Request{})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Entries) != 1 || !plan.Entries[0].Unsupported || plan.Entries[0].UnsupportedReason == "" {
		t.Fatalf("unsupported plan entry = %#v", plan.Entries)
	}
	manager := NewManager(Options{NewID: func() string { return "batch-unsupported" }})
	snapshot, err := manager.Start(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	final, err := manager.Wait(context.Background(), snapshot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if final.Summary.Unsupported != 1 || final.Results[0].Outcome != ValidationUnsupported {
		t.Fatalf("unsupported result = %#v", final)
	}
}

func TestManagerBoundsConcurrencyAndPreservesCaptureProvenance(t *testing.T) {
	plan, err := BuildPlan(captureReport(
		captureDestination("pass.example", 443, model.BrowserCaptureMechanismCONNECT, model.BrowserCaptureOutcomeFailed, 1, 1, 0, 1),
		captureDestination("fail.example", 443, model.BrowserCaptureMechanismCONNECT, model.BrowserCaptureOutcomeConnected, 1, 1, 1, 0),
		captureDestination("third.example", 443, model.BrowserCaptureMechanismCONNECT, model.BrowserCaptureOutcomeConnected, 1, 1, 1, 0),
		captureDestination("fourth.example", 443, model.BrowserCaptureMechanismCONNECT, model.BrowserCaptureOutcomeConnected, 1, 1, 1, 0),
	), Request{Concurrency: 4})
	if err != nil {
		t.Fatal(err)
	}
	var active, maxActive atomic.Int32
	var mu sync.Mutex
	seen := make([]string, 0, len(plan.Entries))
	runner := func(ctx context.Context, target model.Target) model.DiagnosticReport {
		current := active.Add(1)
		for {
			old := maxActive.Load()
			if current <= old || maxActive.CompareAndSwap(old, current) {
				break
			}
		}
		defer active.Add(-1)
		mu.Lock()
		seen = append(seen, target.RequestedIdentity)
		mu.Unlock()
		select {
		case <-time.After(5 * time.Millisecond):
		case <-ctx.Done():
		}
		if target.RequestedIdentity == "fail.example" {
			return diagnosticReport(target, false)
		}
		return diagnosticReport(target, true)
	}
	manager := NewManager(Options{Run: runner, MaxConcurrency: 2, ItemTimeout: time.Second, NewID: func() string { return "batch-bounded" }})
	started, err := manager.Start(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	final, err := manager.Wait(context.Background(), started.ID)
	if err != nil {
		t.Fatal(err)
	}
	if final.State != StateCompleted || maxActive.Load() > 2 || len(seen) != 4 {
		t.Fatalf("batch state/concurrency/seen = %s/%d/%d", final.State, maxActive.Load(), len(seen))
	}
	if final.Summary.Passed != 3 || final.Summary.Failed != 1 || len(final.Summary.FailedIdentities) != 1 || final.Summary.FailedIdentities[0] != "https://fail.example:443" {
		t.Fatalf("summary = %#v", final.Summary)
	}
	for _, result := range final.Results {
		if result.RequestedIdentity == "pass.example" && (!result.CaptureFailed || result.Outcome != ValidationPassed || result.CaptureOutcome != model.BrowserCaptureOutcomeFailed) {
			t.Fatalf("capture/probe provenance was conflated: %#v", result)
		}
	}
}

func TestManagerPreservesPartialValidationOutcome(t *testing.T) {
	plan, err := BuildPlan(captureReport(captureDestination("partial.example", 443, model.BrowserCaptureMechanismCONNECT, model.BrowserCaptureOutcomeConnected, 1, 1, 1, 0)), Request{})
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager(Options{
		Run: func(_ context.Context, target model.Target) model.DiagnosticReport {
			report := diagnosticReport(target, true)
			report.Status = model.ReportStatusIncomplete
			return report
		},
		NewID: func() string { return "batch-partial" },
	})
	started, err := manager.Start(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	final, err := manager.Wait(context.Background(), started.ID)
	if err != nil {
		t.Fatal(err)
	}
	if final.Results[0].Outcome != ValidationPartial || final.Summary.Partial != 1 {
		t.Fatalf("partial result = %#v", final.Results[0])
	}
}

func TestManagerCancellationCompletesEveryEntry(t *testing.T) {
	plan, err := BuildPlan(captureReport(
		captureDestination("one.example", 443, model.BrowserCaptureMechanismCONNECT, model.BrowserCaptureOutcomeConnected, 1, 1, 1, 0),
		captureDestination("two.example", 443, model.BrowserCaptureMechanismCONNECT, model.BrowserCaptureOutcomeConnected, 1, 1, 1, 0),
		captureDestination("three.example", 443, model.BrowserCaptureMechanismCONNECT, model.BrowserCaptureOutcomeConnected, 1, 1, 1, 0),
	), Request{Concurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	startedRunner := make(chan struct{})
	runner := func(ctx context.Context, target model.Target) model.DiagnosticReport {
		closeOnce := false
		if !closeOnce {
			close(startedRunner)
			closeOnce = true
		}
		<-ctx.Done()
		return diagnosticReport(target, true)
	}
	manager := NewManager(Options{Run: runner, MaxConcurrency: 1, ItemTimeout: time.Second, NewID: func() string { return "batch-cancel" }})
	snapshot, err := manager.Start(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-startedRunner:
	case <-time.After(time.Second):
		t.Fatal("runner did not start")
	}
	if _, err := manager.Cancel(snapshot.ID); err != nil {
		t.Fatal(err)
	}
	final, err := manager.Wait(context.Background(), snapshot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if final.State != StateCancelled || final.Summary.Cancelled != len(plan.Entries) {
		t.Fatalf("cancelled batch = %#v", final)
	}
}

func captureReport(destinations ...model.BrowserCaptureDestination) model.BrowserCaptureReport {
	return model.BrowserCaptureReport{
		SchemaVersion: model.BrowserCaptureSchemaVersion,
		SessionID:     "capture-test",
		Browser:       "edge",
		State:         model.BrowserCaptureStateCompleted,
		Observations: model.Observations{BrowserCapture: &model.BrowserCaptureObservation{
			SessionID: "capture-test", Browser: "edge", State: model.BrowserCaptureStateCompleted, Destinations: destinations,
		}},
	}
}

func captureDestination(host string, port uint16, mechanism model.BrowserCaptureMechanism, outcome model.BrowserCaptureOutcome, observations, connections, successes, failures uint64) model.BrowserCaptureDestination {
	return model.BrowserCaptureDestination{
		RequestedHostname: host, RequestedAuthority: host, Port: port, Mechanism: mechanism, Outcome: outcome,
		ObservationCount: observations, ConnectionCount: connections, SuccessCount: successes, FailureCount: failures,
		FailureReason: func() string {
			if failures > 0 {
				return "connect_failed"
			}
			return ""
		}(),
	}
}

func diagnosticReport(target model.Target, reachable bool) model.DiagnosticReport {
	transportOutcome := model.TransportConnectionOutcomeRefused
	transportFailure := model.FailureReasonTCPConnectionRefused
	if reachable {
		transportOutcome = model.TransportConnectionOutcomeConnected
		transportFailure = model.FailureReasonNone
	}
	return model.DiagnosticReport{
		SchemaVersion: model.DiagnosticSchemaVersion, Target: target, Status: model.ReportStatusComplete,
		Probes: []model.ProbeResult{}, Observations: model.Observations{
			Endpoint:       model.EndpointObservation{OriginalInput: target.OriginalInput, RequestedIdentity: target.RequestedIdentity, Service: target.Service, ApplicationProtocol: target.ApplicationProtocol, TransportProtocol: target.TransportProtocol, Port: target.Port},
			NameResolution: model.NameResolutionObservation{RequestedName: target.RequestedIdentity, A: []string{"192.0.2.1"}, Certainty: model.ObservationCertaintyObserved, FailureReason: model.FailureReasonNone},
			Transport:      model.TransportObservation{Applicability: model.ObservationApplicabilityApplicable, RequestedEndpoint: target.RequestedIdentity, ConnectionOutcome: transportOutcome, Connected: reachable, FailureReason: transportFailure, FaultDomain: model.FaultDomainTransport},
			Security: model.SecurityObservation{Applicability: model.ObservationApplicabilityApplicable, Attempted: true, HandshakeComplete: reachable, FailureReason: func() model.FailureReason {
				if reachable {
					return model.FailureReasonNone
				}
				return model.FailureReasonTLSHandshakeFailure
			}(), FaultDomain: model.FaultDomainTLS},
			Application: model.ApplicationObservation{Applicability: model.ObservationApplicabilityApplicable, Protocol: target.ApplicationProtocol, RequestAttempted: true, ResponseReceived: reachable, Result: func() model.ApplicationResult {
				if reachable {
					return model.HTTPResultSuccess
				}
				return model.HTTPResultRequestFailure
			}(), FailureReason: func() model.FailureReason {
				if reachable {
					return model.FailureReasonNone
				}
				return model.FailureReasonHTTPFailure
			}(), FaultDomain: model.FaultDomainHTTP},
		},
	}
}
