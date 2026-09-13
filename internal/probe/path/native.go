package path

import (
	"context"
	"fmt"

	"github.com/yohnark/tadori/internal/model"
)

type nativeObserver struct{}

func (nativeObserver) Observe(ctx context.Context, request Request) (Observation, error) {
	switch request.Protocol {
	case model.PathProtocolICMP:
		return observeNativeICMP(ctx, request)
	case model.PathProtocolTCP:
		return observeNativeTCP(ctx, request)
	default:
		return Observation{}, fmt.Errorf("%w: protocol %q", ErrUnsupported, request.Protocol)
	}
}
