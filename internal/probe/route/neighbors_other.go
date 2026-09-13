//go:build !linux && !windows

package route

import (
	"context"
	"net/netip"

	"github.com/yohnark/tadori/internal/model"
)

// SystemNeighborTable intentionally reports unsupported on platforms without
// a standard-library neighbor-cache API. No command or network scan is used.
type SystemNeighborTable struct{}

func (SystemNeighborTable) Neighbors(ctx context.Context, target netip.Addr, interfaceIndex int) (model.NeighborEvidence, error) {
	if err := ctx.Err(); err != nil {
		return model.NeighborEvidence{}, err
	}
	return model.NeighborEvidence{
		Observation: model.NeighborObservationUnsupported,
		Source:      "native-neighbor-api",
		Note:        "neighbor cache is unsupported; absence is not unreachable",
	}, ErrUnsupported
}
