//go:build windows

package route

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
)

// defaultGatewayChecker uses Windows' fixed ping.exe binary. It is bounded by
// the probe context and receives only package-generated flags plus a validated
// netip address; no shell, script, or caller-controlled command is involved.
func defaultGatewayChecker(ctx context.Context, gateway netip.Addr) error {
	args, err := pingArguments(gateway)
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, "ping.exe", args...)
	if _, err := command.Output(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, exec.ErrNotFound) {
			return ErrGatewayReachabilityUnsupported
		}
		return fmt.Errorf("%w: %v", errGatewayUnreachable, err)
	}
	return nil
}
