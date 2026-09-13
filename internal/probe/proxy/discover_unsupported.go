//go:build !windows

package proxy

import "context"

func discoverPlatform(_ context.Context) (Discovery, error) {
	return Discovery{}, ErrUnsupportedPlatform
}
