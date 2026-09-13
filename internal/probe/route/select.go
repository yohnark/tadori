package route

import (
	"net/netip"
	"sort"

	"github.com/yohnark/tadori/internal/model"
)

// Select chooses the route the kernel's longest-prefix routing rule would
// prefer from a supplied table. Among equally specific entries, the lowest
// metric wins. The final tie-breakers make fixture and evidence ordering
// deterministic.
func Select(routes []Route, target netip.Addr) (Route, bool) {
	selection, ok := SelectDetailed(routes, target)
	if !ok {
		return Route{}, false
	}
	return selection.Selected, true
}

// SelectDetailed applies the route precedence available in the normalized
// table: longest matching prefix, then lowest metric. Interface and textual
// ordering are stable fallbacks for deterministic output only. A tie before
// those fallbacks is reported as ambiguous because the generic table does not
// expose a platform's remaining equal-cost selection state.
func SelectDetailed(routes []Route, target netip.Addr) (Selection, bool) {
	target = model.NormalizeAddr(target)
	if !target.IsValid() {
		return Selection{}, false
	}
	candidates := make([]Route, 0, len(routes))
	for _, candidate := range routes {
		candidate = normalizeRoute(candidate)
		prefix := candidate.Destination
		if !prefix.IsValid() || !prefix.Contains(target) {
			continue
		}
		candidates = append(candidates, candidate)
	}
	if len(candidates) == 0 {
		return Selection{}, false
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
	ambiguous := false
	if len(candidates) > 1 {
		first := candidates[0]
		for _, candidate := range candidates[1:] {
			if candidate.Destination.Bits() != first.Destination.Bits() || candidate.Metric != first.Metric {
				break
			}
			if !sameRoute(candidate, first) {
				ambiguous = true
				break
			}
		}
	}
	return Selection{Target: target, Selected: candidates[0], Candidates: candidates, Ambiguous: ambiguous}, true
}

// SelectRouteDetailed is the descriptive alias for SelectDetailed.
func SelectRouteDetailed(routes []Route, target netip.Addr) (Selection, bool) {
	return SelectDetailed(routes, target)
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
		candidate = normalizeRoute(candidate)
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

func normalizeRoute(route Route) Route {
	route.Destination = model.NormalizePrefix(route.Destination)
	route.Gateway = model.NormalizeAddr(route.Gateway)
	route.Source = model.NormalizeAddr(route.Source)
	if address, err := netip.ParseAddr(route.Interface); err == nil {
		route.Interface = model.NormalizeAddr(address).String()
	}
	return route
}

func sameRoute(left, right Route) bool {
	return left.Destination == right.Destination &&
		left.Gateway == right.Gateway &&
		left.Interface == right.Interface &&
		left.InterfaceIndex == right.InterfaceIndex &&
		left.Metric == right.Metric &&
		left.Source == right.Source &&
		left.InterfaceType == right.InterfaceType &&
		left.VPNOrTunnel == right.VPNOrTunnel &&
		left.VirtualAdapter == right.VirtualAdapter
}

func normalizeRoutePrefix(prefix netip.Prefix) netip.Prefix {
	return model.NormalizePrefix(prefix).Masked()
}
