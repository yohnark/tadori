//go:build !windows

package proxy

import "context"

func discoverPlatform(_ context.Context) (Discovery, error) {
	return Discovery{}, ErrUnsupportedPlatform
}

func resolveProxyForURL(_ context.Context, _ string, _ SourceConfiguration) (URLProxyResolution, error) {
	return URLProxyResolution{}, ErrUnsupportedPlatform
}
