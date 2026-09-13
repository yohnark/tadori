//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly && !solaris

package path

import (
	"context"
	"fmt"
)

func observeNativeICMP(context.Context, Request) (Observation, error) {
	return Observation{}, fmt.Errorf("%w: native ICMP path observation is not implemented on this platform", ErrUnsupported)
}

func observeNativeTCP(context.Context, Request) (Observation, error) {
	return Observation{}, fmt.Errorf("%w: native TTL-limited TCP path observation is not implemented on this platform", ErrUnsupported)
}
