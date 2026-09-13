package session

import (
	"context"
	"fmt"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yohnark/tadori/internal/model"
)

func TestManagerLifecycleProgressAndCanonicalReport(t *testing.T) {
	clock := func() time.Time { return time.Date(2026, 9, 13, 1, 2, 3, 0, time.FixedZone("JST", 9*60*60)) }
	target, err := model.ParseTarget(model.TargetIntent{Input: "https://example.com"})
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}
	wantReport := model.DiagnosticReport{
		SchemaVersion: model.DiagnosticSchemaVersion,
		Target:        target,
		Status:        model.ReportStatusComplete,
		StartedAt:     sessionTestTimePointer(clock()),
		CompletedAt:   sessionTestTimePointer(clock().Add(time.Second)),
		Probes: []model.ProbeResult{{
			Name:   "fake",
			Target: target,
			Status: model.ProbeStatusPassed,
			Interpretation: model.ProbeInterpretation{
				FailureReason: model.FailureReasonNone,
				Layer:         model.LayerHTTP,
				FaultDomain:   model.FaultDomainHTTP,
			},
		}},
	}
	var idNumber atomic.Int32
	m := NewManager(Options{
		Run: func(_ context.Context, target model.Target, progress Progress) model.DiagnosticReport {
			progress.ProbeStarted("fake")
			progress.ProbeCompleted(wantReport.Probes[0])
			return wantReport
		},
		Now: clock,
		NewID: func() string {
			return fmt.Sprintf("session-%d", idNumber.Add(1))
		},
	})

	created, err := m.Create(target)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ID != "session-1" || created.State != StateRunning {
		t.Fatalf("created snapshot = %#v", created)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	completed, err := m.Wait(ctx, created.ID)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if completed.State != StateCompleted {
		t.Fatalf("state = %q, want completed", completed.State)
	}
	if completed.StartedAt == nil || completed.CompletedAt == nil {
		t.Fatalf("lifecycle timestamps missing: %#v", completed)
	}
	if !reflect.DeepEqual(completed.Report, &wantReport) {
		t.Fatalf("final report changed\n got: %#v\nwant: %#v", completed.Report, &wantReport)
	}

	events, err := m.Events(created.ID, 0)
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	wantTypes := []EventType{
		EventDiagnosisStarted,
		EventProbeStarted,
		EventProbeCompleted,
		EventDiagnosisCompleted,
	}
	if len(events) != len(wantTypes) {
		t.Fatalf("event count = %d, want %d: %#v", len(events), len(wantTypes), events)
	}
	for index, event := range events {
		if event.Sequence != uint64(index+1) || event.Type != wantTypes[index] {
			t.Errorf("event[%d] = %#v", index, event)
		}
		if event.SessionID != created.ID || event.Timestamp.Location() != time.UTC {
			t.Errorf("event[%d] identity/timestamp = %#v", index, event)
		}
	}
	if events[1].ProbeName != "fake" || events[2].Result == nil || events[3].Report == nil {
		t.Fatalf("structured progress fields missing: %#v", events)
	}

	replayed, unsubscribe, err := m.Subscribe(created.ID, 2)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer unsubscribe()
	var replayedEvents []Event
	for event := range replayed {
		replayedEvents = append(replayedEvents, event)
	}
	if len(replayedEvents) != 2 || replayedEvents[0].Sequence != 3 || replayedEvents[1].Sequence != 4 {
		t.Fatalf("replayed events = %#v", replayedEvents)
	}
}

func TestManagerCancellationPropagatesOnlyToOneSession(t *testing.T) {
	started := make(chan string, 2)
	cancelled := make(chan string, 2)
	var idNumber atomic.Int32
	m := NewManager(Options{
		MaxConcurrentSessions: 2,
		NewID: func() string {
			return fmt.Sprintf("cancel-%d", idNumber.Add(1))
		},
		Run: func(ctx context.Context, target model.Target, _ Progress) model.DiagnosticReport {
			started <- target.RequestedIdentity
			<-ctx.Done()
			cancelled <- target.RequestedIdentity
			return sessionTestErrorReport(target)
		},
	})

	first, err := m.Create(model.NewTarget("first", 443))
	if err != nil {
		t.Fatalf("Create first: %v", err)
	}
	second, err := m.Create(model.NewTarget("second", 443))
	if err != nil {
		t.Fatalf("Create second: %v", err)
	}
	for range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("sessions did not start")
		}
	}

	if _, err := m.Cancel(first.ID); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	firstDone, err := m.Wait(ctx, first.ID)
	if err != nil {
		t.Fatalf("Wait first: %v", err)
	}
	if firstDone.State != StateCancelled || !firstDone.CancelRequested {
		t.Fatalf("first cancellation snapshot = %#v", firstDone)
	}
	secondSnapshot, err := m.Get(second.ID)
	if err != nil {
		t.Fatalf("Get second: %v", err)
	}
	if secondSnapshot.State != StateRunning || secondSnapshot.CancelRequested {
		t.Fatalf("second session was affected by first cancellation: %#v", secondSnapshot)
	}
	if got := <-cancelled; got != "first" {
		t.Fatalf("cancelled target = %q, want first", got)
	}
	m.Close()
	if _, err := m.Wait(ctx, second.ID); err != nil {
		t.Fatalf("Wait second after Close: %v", err)
	}
}

func TestManagerBoundsConcurrentExecution(t *testing.T) {
	var active atomic.Int32
	var maximum atomic.Int32
	release := make(chan struct{})
	var idNumber atomic.Int32
	m := NewManager(Options{
		MaxConcurrentSessions: 2,
		NewID: func() string {
			return fmt.Sprintf("bounded-%d", idNumber.Add(1))
		},
		Run: func(ctx context.Context, target model.Target, _ Progress) model.DiagnosticReport {
			current := active.Add(1)
			for {
				old := maximum.Load()
				if current <= old || maximum.CompareAndSwap(old, current) {
					break
				}
			}
			select {
			case <-release:
			case <-ctx.Done():
			}
			active.Add(-1)
			return sessionTestErrorReport(target)
		},
	})

	first, err := m.Create(model.NewTarget("one", 80))
	if err != nil {
		t.Fatalf("Create first: %v", err)
	}
	second, err := m.Create(model.NewTarget("two", 80))
	if err != nil {
		t.Fatalf("Create second: %v", err)
	}
	if _, err := m.Create(model.NewTarget("three", 80)); err != ErrBusy {
		t.Fatalf("third Create error = %v, want ErrBusy", err)
	}

	deadline := time.After(time.Second)
	for maximum.Load() < 2 {
		select {
		case <-deadline:
			t.Fatalf("two sessions did not run concurrently; maximum = %d", maximum.Load())
		default:
			time.Sleep(time.Millisecond)
		}
	}
	close(release)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := m.Wait(ctx, first.ID); err != nil {
		t.Fatalf("Wait first: %v", err)
	}
	if _, err := m.Wait(ctx, second.ID); err != nil {
		t.Fatalf("Wait second: %v", err)
	}
	if maximum.Load() > 2 {
		t.Fatalf("maximum concurrent sessions = %d, want <= 2", maximum.Load())
	}
}

func TestManagerOverallTimeoutFailsAndRetainsCanonicalReport(t *testing.T) {
	target := model.NewTarget("overall-timeout.example", 443)
	wantReport := model.DiagnosticReport{
		SchemaVersion: model.DiagnosticSchemaVersion,
		Target:        target,
		Status:        model.ReportStatusComplete,
		Probes: []model.ProbeResult{{
			Name:   "tcp",
			Status: model.ProbeStatusPassed,
			Interpretation: model.ProbeInterpretation{
				FailureReason: model.FailureReasonNone,
				Layer:         model.LayerTCP,
				FaultDomain:   model.FaultDomainTransport,
			},
		}},
	}
	m := NewManager(Options{
		OverallTimeout: 20 * time.Millisecond,
		NewID:          func() string { return "overall-timeout-1" },
		Run: func(ctx context.Context, _ model.Target, _ Progress) model.DiagnosticReport {
			<-ctx.Done()
			return wantReport
		},
	})

	created, err := m.Create(target)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	completed, err := m.Wait(ctx, created.ID)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if completed.State != StateFailed {
		t.Fatalf("state = %q, want failed after overall timeout", completed.State)
	}
	if completed.Report == nil {
		t.Fatal("overall timeout discarded the canonical report")
	}
	if completed.Report.Status == model.ReportStatusComplete {
		t.Fatalf("timed-out report status = %q, want non-complete", completed.Report.Status)
	}
	if len(completed.Report.Probes) != len(wantReport.Probes) || completed.Report.Probes[0].Name != "tcp" {
		t.Fatalf("canonical report was not retained: %#v", completed.Report)
	}
}

func sessionTestErrorReport(target model.Target) model.DiagnosticReport {
	return model.DiagnosticReport{
		SchemaVersion: model.DiagnosticSchemaVersion,
		Target:        target,
		Status:        model.ReportStatusIncomplete,
		Probes:        []model.ProbeResult{},
	}
}

func sessionTestTimePointer(value time.Time) *time.Time {
	return &value
}
