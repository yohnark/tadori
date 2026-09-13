package packet

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yohnark/tadori/internal/model"
)

func testScope(probeType ProbeType) Scope {
	return Scope{
		Identity: model.ProbeIdentity{
			SessionID:     "session-1",
			ProbeID:       string(probeType),
			CorrelationID: "session-1/" + string(probeType),
		},
		Target:        model.NewTarget("203.0.113.10", 443),
		ProbeType:     probeType,
		ProcessID:     42,
		WindowStarted: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Deadline:      time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC),
	}
}

func TestUnsupportedBackendRequiresScopeAndIsExplicit(t *testing.T) {
	backend := NewUnsupportedBackend("test platform")
	if _, err := backend.Start(context.Background(), Scope{}); !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("invalid scope error = %v, want ErrInvalidScope", err)
	}
	if _, err := backend.Start(context.Background(), testScope(ProbeTypeTCP)); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported backend error = %v, want ErrUnsupported", err)
	}
	flow := Correlate(CorrelationInput{
		Scope:        testScope(ProbeTypeTCP),
		ProbeStarted: true,
		StartError:   ErrUnsupported,
		Result:       model.ProbeResult{Target: testScope(ProbeTypeTCP).Target},
	})
	if flow.CaptureStatus != model.PacketCaptureStatusUnsupported || flow.Outcome != model.PacketFlowOutcomeCaptureUnavailable {
		t.Fatalf("unsupported flow = %#v", flow)
	}
}

func TestPartialOrBackendErrorDoesNotBecomeNoResponse(t *testing.T) {
	scope := testScope(ProbeTypeTCP)
	result := Correlate(CorrelationInput{
		Scope: scope, ProbeStarted: true,
		Capture: CaptureResult{Source: "fixture", Complete: false, EventsLost: 1},
	})
	if result.CaptureStatus != model.PacketCaptureStatusPartial || result.Outcome != model.PacketFlowOutcomeCaptureUnavailable || result.ProbeEmission != model.PacketEmissionUnknown {
		t.Fatalf("partial capture = %#v", result)
	}

	result = Correlate(CorrelationInput{
		Scope: scope, ProbeStarted: true,
		Capture: CaptureResult{Source: "fixture", Complete: true, Error: "decoder stopped"},
	})
	if result.CaptureStatus != model.PacketCaptureStatusError || result.CaptureError != "decoder stopped" || result.Outcome != model.PacketFlowOutcomeCaptureUnavailable {
		t.Fatalf("backend error = %#v", result)
	}
}

func TestInsufficientPrivilegeIsExplicitAndScoped(t *testing.T) {
	scope := testScope(ProbeTypeTCP)
	flow := Correlate(CorrelationInput{
		Scope: scope, ProbeStarted: true,
		StartError: errors.Join(ErrInsufficientPrivilege, errors.New("ETW session denied")),
	})
	if flow.CaptureStatus != model.PacketCaptureStatusInsufficientPrivilege || flow.Outcome != model.PacketFlowOutcomeCaptureUnavailable {
		t.Fatalf("privilege-limited flow = %#v", flow)
	}
	if flow.CaptureError == "" {
		t.Fatal("privilege error was not retained as explicit capture evidence")
	}
}
