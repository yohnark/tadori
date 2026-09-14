//go:build !windows

package proxy

import (
	"context"
	"strings"
)

func discoverPlatform(_ context.Context) (Discovery, error) {
	return Discovery{}, ErrUnsupportedPlatform
}

func resolveProxyForURL(ctx context.Context, targetURL string, config SourceConfiguration) (URLProxyResolution, error) {
	if err := ctx.Err(); err != nil {
		return URLProxyResolution{}, err
	}
	// Static selection and documented bypass matching are local operations and
	// do not require a Windows API. PAC/auto-detect still remains explicitly
	// unsupported here because evaluating it would require an unbounded script
	// runtime or a platform-specific resolver.
	if strings.TrimSpace(config.PACURL) == "" && !config.AutoDetect {
		return resolveStaticProxyForURL(targetURL, config)
	}
	return URLProxyResolution{}, ErrUnsupportedPlatform
}
