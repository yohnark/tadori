//go:build !windows

package enterprise

import (
	"context"

	"github.com/yohnark/tadori/internal/model"
)

type platformSnapshotProvider struct{}

func (platformSnapshotProvider) Snapshot(context.Context, model.Target) (Snapshot, error) {
	return Snapshot{}, ErrUnsupportedPlatform
}
