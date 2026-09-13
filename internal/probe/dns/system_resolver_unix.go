//go:build !windows

package dns

import (
	"context"
	"errors"
	"net"
	"os"
)

func newSystemResolver() Resolver { return net.DefaultResolver }

func newSystemEnvironmentProvider() EnvironmentProvider { return nil }

func systemResolutionSource() string { return "go-net.Resolver" }

func systemResolverSource(path string) string {
	if path != "" {
		return path
	}
	return "/etc/resolv.conf"
}

func systemResolverAddresses(ctx context.Context, path string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if path == "" {
		path = "/etc/resolv.conf"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return ParseResolverAddresses(data), nil
}
