//go:build windows

package route

import (
	"context"
	"net/netip"

	"github.com/yohnark/tadori/internal/model"
)

// SystemNeighborTable is backed by the Windows IP Helper implementation in
// neighbors_windows_native.go. Keeping the platform boundary here lets the
// route probe remain deterministic when a NeighborTable is injected.
type SystemNeighborTable struct{}

func (SystemNeighborTable) Neighbors(ctx context.Context, target netip.Addr, interfaceIndex int) (model.NeighborEvidence, error) {
	return windowsNeighborEvidence(ctx, target, interfaceIndex)
}
