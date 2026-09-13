package route

import (
	"net/netip"
	"sort"
)

// Select chooses the route the kernel's longest-prefix routing rule would
// prefer from a supplied table. Among equally specific entries, the lowest
// metric wins. The final tie-breakers make fixture and evidence ordering
// deterministic.
func Select(routes []Route, target netip.Addr) (Route, bool) {
	if !target.IsValid() {
		return Route{}, false
	}
	candidates := make([]Route, 0, len(routes))
	for _, candidate := range routes {
		prefix := candidate.Destination
		if !prefix.IsValid() || !prefix.Contains(target) {
			continue
		}
		candidates = append(candidates, candidate)
	}
	if len(candidates) == 0 {
		return Route{}, false
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		ab, bb := a.Destination.Bits(), b.Destination.Bits()
		if ab != bb {
			return ab > bb
		}
		if a.Metric != b.Metric {
			return a.Metric < b.Metric
		}
		if a.InterfaceIndex != b.InterfaceIndex {
			return a.InterfaceIndex < b.InterfaceIndex
		}
		return a.Interface < b.Interface
	})
	return candidates[0], true
}

// SelectRoute is the descriptive alias used by callers that prefer an
// explicit function name.
func SelectRoute(routes []Route, target netip.Addr) (Route, bool) {
	return Select(routes, target)
}

// Default returns the selected default route for an address family. If
// family is invalid, the first preferred default route of either family is
// returned. This helper is useful when a caller wants default-route evidence
// separately from target-route evidence.
func Default(routes []Route, family int) (Route, bool) {
	filtered := make([]Route, 0, len(routes))
	for _, candidate := range routes {
		prefix := candidate.Destination
		if !prefix.IsValid() || prefix.Bits() != 0 {
			continue
		}
		if family == 4 && !prefix.Addr().Is4() {
			continue
		}
		if family == 6 && prefix.Addr().Is4() {
			continue
		}
		filtered = append(filtered, candidate)
	}
	if len(filtered) == 0 {
		return Route{}, false
	}
	sort.SliceStable(filtered, func(i, j int) bool {
		if filtered[i].Metric != filtered[j].Metric {
			return filtered[i].Metric < filtered[j].Metric
		}
		return filtered[i].InterfaceIndex < filtered[j].InterfaceIndex
	})
	return filtered[0], true
}

// SelectDefaultRoute is the descriptive alias for Default.
func SelectDefaultRoute(routes []Route, family int) (Route, bool) {
	return Default(routes, family)
}
