package probe

import (
	"context"
	"reflect"
	"testing"

	"github.com/yohnark/tadori/internal/model"
)

type fixtureProbe struct{}

func (fixtureProbe) Name() string { return "fixture" }

func (fixtureProbe) Run(_ context.Context, execution ExecutionContext) model.ProbeResult {
	return model.ProbeResult{
		Name:   "fixture",
		Target: execution.Target,
		Status: model.ProbeStatusPassed,
		Timing: model.Timing{DurationMS: 1},
		Interpretation: model.ProbeInterpretation{
			FailureReason: model.FailureReasonNone,
			Layer:         model.LayerUnknown,
			FaultDomain:   model.FaultDomainUnknown,
		},
	}
}

func TestProbeContractPassesExecutionTargetToResult(t *testing.T) {
	var p Probe = fixtureProbe{}
	wantTarget, err := model.ParseTarget(model.TargetIntent{Input: "https://example.com"})
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}
	got := p.Run(context.Background(), ExecutionContext{Target: wantTarget})

	if got.Name != p.Name() {
		t.Fatalf("probe name = %q, want %q", got.Name, p.Name())
	}
	if !reflect.DeepEqual(got.Target, wantTarget) {
		t.Fatalf("probe target = %#v, want %#v", got.Target, wantTarget)
	}
}
