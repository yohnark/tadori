//go:build windows

package route

import (
	"context"
	"errors"
	"os/exec"
)

// SystemRouteTable obtains Windows' kernel route view through the fixed,
// read-only route.exe print operation. Arguments are constants selected by
// this package; callers cannot provide commands, scripts, or flags. Parsing
// is structured and performed separately from process execution.
type SystemRouteTable struct{}

func (SystemRouteTable) Routes(ctx context.Context) ([]Route, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	routes := make([]Route, 0)
	var failures []error
	for _, family := range []int{4, 6} {
		output, err := fixedRoutePrint(ctx, family)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		routes = append(routes, parseWindowsRouteOutput(string(output), family)...)
	}
	if len(routes) != 0 {
		return decorateWindowsInterfaces(routes), nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(failures) != 0 {
		return nil, errors.Join(ErrUnsupported, failures[0])
	}
	return nil, ErrUnsupported
}

func fixedRoutePrint(ctx context.Context, family int) ([]byte, error) {
	argument := "-4"
	if family == 6 {
		argument = "-6"
	}
	// route.exe is a fixed Windows system command. Do not replace this with
	// a shell or accept executable/argument values from a caller.
	return exec.CommandContext(ctx, "route.exe", "print", argument).CombinedOutput()
}
