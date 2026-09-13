//go:build !linux && !windows

package route

import "context"

// SystemRouteTable is a placeholder for platforms whose native route API is
// not part of the standard library. A caller can inject RouteTableFunc (and
// tests can do so without network access); this implementation reports the
// normalized unsupported result rather than running an arbitrary command.
type SystemRouteTable struct{}

func (SystemRouteTable) Routes(ctx context.Context) ([]Route, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, ErrUnsupported
}
