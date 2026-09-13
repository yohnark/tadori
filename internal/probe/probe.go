// Package probe defines the execution contract shared by every diagnostic
// probe. Implementations live in the child packages under this directory.
package probe

import (
	"context"

	"github.com/yohnark/tadori/internal/model"
)

// ExecutionContext contains immutable input supplied to one probe run.
// Cancellation and deadlines belong in ctx, following the standard Go
// context contract.
type ExecutionContext struct {
	Target        model.Target
	SessionID     string
	ProbeID       string
	CorrelationID string
}

// Probe executes one kind of observation for an endpoint.
//
// Name must be stable and machine-readable, and should match the Name in the
// returned model.ProbeResult. Run returns a result even when execution fails;
// implementations should use model.ProbeStatusError with
// model.FailureReasonProbeExecution when no valid observation can be made.
// Captured output belongs in model.ProbeResult.Evidence, while normalized
// meaning belongs in model.ProbeResult.Interpretation. A probe must honor
// cancellation and deadlines from ctx.
type Probe interface {
	Name() string
	Run(ctx context.Context, execution ExecutionContext) model.ProbeResult
}
