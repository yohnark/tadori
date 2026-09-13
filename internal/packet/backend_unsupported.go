package packet

import (
	"context"
	"fmt"
)

type unsupportedBackend struct {
	reason string
}

// NewUnsupportedBackend is useful to embedders that want to make an
// unavailable capture mechanism explicit in the canonical report.
func NewUnsupportedBackend(reason string) Backend {
	return unsupportedBackend{reason: reason}
}

func (backend unsupportedBackend) Start(_ context.Context, scope Scope) (Capture, error) {
	if err := scope.validate(); err != nil {
		return nil, err
	}
	if backend.reason == "" {
		backend.reason = "packet capture is unavailable"
	}
	return nil, fmt.Errorf("%w: %s", ErrUnsupported, backend.reason)
}
