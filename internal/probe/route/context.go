package route

import (
	"encoding/json"
	"net/netip"
	"sort"
	"strings"

	"github.com/yohnark/tadori/internal/model"
	"github.com/yohnark/tadori/internal/probe/interfacecfg"
)

// BuildNetworkContext derives target scope from a selected route plus the
// interface that route names. It deliberately refuses to call a private
// address same-link: on-link is established by the route's absent gateway.
func BuildNetworkContext(target model.Target, selection Selection, interfaces []interfacecfg.InterfaceState, neighbor *model.NeighborEvidence, provenance, evidenceIDs []string) model.NetworkContext {
	target = model.NormalizeTarget(target)
	context := model.NetworkContext{
		RequestedIdentity: target.RequestedIdentity,
		EffectiveRoute:    model.RouteDispositionUnknown,
		NetworkScope:      model.NetworkScopeUnknown,
		Provenance:        uniqueStrings(provenance),
		EvidenceIDs:       uniqueStrings(evidenceIDs),
		Neighbor:          cloneNeighbor(neighbor),
	}
	if !selection.Target.IsValid() {
		selection.Target = targetAddress(target)
	}
	if selection.Target.IsValid() {
		context.SelectedDestinationAddress = model.NormalizeAddr(selection.Target).String()
	}
	selected := normalizeRoute(selection.Selected)
	if !selected.Destination.IsValid() {
		return context
	}
	context.RoutePrefix = selected.Destination.String()
	context.RouteMetric = selected.Metric
	context.RouteSelectionAmbiguous = selection.Ambiguous
	context.Gateway = addrString(selected.Gateway)
	context.NextHop = context.Gateway
	if context.Gateway == "" {
		context.EffectiveRoute = model.RouteDispositionOnLink
		context.NextHop = "on-link"
	} else {
		context.EffectiveRoute = model.RouteDispositionRouted
	}

	iface := matchingInterface(selected, interfaces)
	if iface != nil {
		context.SelectedSourceInterface = iface.Name
		context.SelectedSourceInterfaceIndex = iface.Index
		context.VPNOrTunnelInvolvement = iface.VPN || strings.EqualFold(iface.Type, "vpn") || strings.EqualFold(iface.Type, "tunnel")
		context.VirtualAdapterInvolvement = iface.Virtual || context.VPNOrTunnelInvolvement || strings.EqualFold(iface.Type, "virtual")
		if len(context.Provenance) == 0 && context.SelectedSourceInterface != "" {
			context.Provenance = []string{"native-interface-api"}
		}
	}
	if context.SelectedSourceInterface == "" {
		context.SelectedSourceInterface = selected.Interface
	}
	if context.SelectedSourceInterfaceIndex == 0 {
		context.SelectedSourceInterfaceIndex = selected.InterfaceIndex
	}
	if selected.InterfaceType != "" && !context.VPNOrTunnelInvolvement {
		context.VPNOrTunnelInvolvement = strings.EqualFold(selected.InterfaceType, "vpn") || strings.EqualFold(selected.InterfaceType, "tunnel")
	}
	context.VPNOrTunnelInvolvement = context.VPNOrTunnelInvolvement || selected.VPNOrTunnel
	context.VirtualAdapterInvolvement = context.VirtualAdapterInvolvement || selected.VirtualAdapter
	if selected.Source.IsValid() {
		context.SelectedSourceAddress = addrString(selected.Source)
	}
	if context.SelectedSourceAddress == "" && iface != nil {
		context.SelectedSourceAddress = sourceAddress(*iface, selected, selection.Target)
	}

	for _, candidate := range selection.Candidates {
		candidate = normalizeRoute(candidate)
		if sameRoute(candidate, selected) {
			continue
		}
		context.CompetingRoutes = append(context.CompetingRoutes, model.RouteCandidate{
			RoutePrefix:    candidate.Destination.String(),
			Gateway:        addrString(candidate.Gateway),
			NextHop:        routeNextHop(candidate),
			Interface:      candidate.Interface,
			InterfaceIndex: candidate.InterfaceIndex,
			SourceAddress:  addrString(candidate.Source),
			Metric:         candidate.Metric,
			VPNOrTunnel:    candidate.VPNOrTunnel,
			VirtualAdapter: candidate.VirtualAdapter,
		})
	}

	destination := selection.Target
	if !destination.IsValid() {
		destination = targetAddress(target)
	}
	if selection.Ambiguous {
		context.NetworkScope = model.NetworkScopeUnknown
	} else if destination.IsValid() && destination.IsLoopback() {
		context.NetworkScope = model.NetworkScopeLoopback
	} else if destination.IsValid() && destination.IsLinkLocalUnicast() {
		context.NetworkScope = model.NetworkScopeLinkLocal
	} else if context.VPNOrTunnelInvolvement {
		context.NetworkScope = model.NetworkScopeVPNTunnelRouted
	} else if context.EffectiveRoute == model.RouteDispositionOnLink {
		context.NetworkScope = model.NetworkScopeSameLink
	} else if destination.IsValid() && destination.IsPrivate() {
		context.NetworkScope = model.NetworkScopePrivateRouted
	} else if context.EffectiveRoute == model.RouteDispositionRouted {
		context.NetworkScope = model.NetworkScopeExternalRouted
	}
	return context
}

// NetworkContextFromProbeResults reconstructs a context from the route and
// interface evidence already in a report. It never re-reads the host state,
// which keeps report construction tied to one observation window.
func NetworkContextFromProbeResults(target model.Target, probes []model.ProbeResult) (model.NetworkContext, bool) {
	var routeObservation *RouteObservation
	var routeEvidenceID string
	var routeSource string
	var interfaceEvidenceID string
	var interfaceSource string
	var interfaces []interfacecfg.InterfaceState
	targetRouteSeen := false
	for _, probe := range probes {
		if probe.Name == TargetRouteProbeName {
			targetRouteSeen = true
		}
	}
	for _, probe := range probes {
		for _, evidence := range probe.Evidence {
			if evidence.Kind == model.EvidenceKindRoute {
				observation, err := DecodeRouteEvidence(evidence)
				if err == nil && (observation.RouteType == "target" || !targetRouteSeen && routeObservation == nil && observation.RouteType == "gateway") {
					if observation.RouteType == "target" || routeObservation == nil {
						copy := observation
						routeObservation = &copy
						routeEvidenceID = evidence.ID
						routeSource = evidence.Source
					}
				}
			}
			if evidence.Kind == model.EvidenceKindInterfaceState && len(interfaces) == 0 {
				if err := json.Unmarshal(evidence.Raw, &interfaces); err == nil {
					interfaceEvidenceID = evidence.ID
					interfaceSource = evidence.Source
				}
			}
		}
	}
	if routeObservation == nil {
		if targetRouteSeen {
			for _, probe := range probes {
				if probe.Name != TargetRouteProbeName {
					continue
				}
				for _, evidence := range probe.Evidence {
					if evidence.Kind != model.EvidenceKindRoute {
						continue
					}
					return model.NetworkContext{
						RequestedIdentity: target.RequestedIdentity,
						EffectiveRoute:    model.RouteDispositionUnknown,
						NetworkScope:      model.NetworkScopeUnknown,
						Provenance:        uniqueStrings([]string{evidence.Source}),
						EvidenceIDs:       uniqueStrings([]string{evidence.ID}),
					}, true
				}
			}
		}
		return model.NetworkContext{}, false
	}
	selection, ok := selectionFromObservation(*routeObservation, target)
	if !ok {
		context := model.NetworkContext{RequestedIdentity: target.RequestedIdentity, EffectiveRoute: model.RouteDispositionUnknown, NetworkScope: model.NetworkScopeUnknown, EvidenceIDs: []string{routeEvidenceID}}
		if routeSource != "" {
			context.Provenance = []string{routeSource}
		}
		return context, true
	}
	provenance := []string{routeSource}
	if interfaceEvidenceID != "" {
		if interfaceSource == "" {
			interfaceSource = "native-interface-api"
		}
		provenance = append(provenance, interfaceSource)
	}
	if routeObservation.Neighbor != nil && routeObservation.Neighbor.Source != "" {
		provenance = append(provenance, routeObservation.Neighbor.Source)
	}
	context := BuildNetworkContext(target, selection, interfaces, routeObservation.Neighbor, provenance, []string{routeEvidenceID, interfaceEvidenceID})
	return context, true
}

func selectionFromObservation(observation RouteObservation, target model.Target) (Selection, bool) {
	prefix, err := netip.ParsePrefix(observation.RoutePrefix)
	if err != nil {
		prefix, err = netip.ParsePrefix(observation.Destination)
	}
	if err != nil {
		return Selection{}, false
	}
	selected := Route{Destination: prefix, Interface: observation.Interface, InterfaceIndex: observation.InterfaceIndex, Metric: observation.Metric, InterfaceType: observation.InterfaceType, VPNOrTunnel: observation.VPNOrTunnel, VirtualAdapter: observation.VirtualAdapter}
	if gateway, parseErr := netip.ParseAddr(observation.Gateway); parseErr == nil {
		selected.Gateway = gateway
	}
	if source, parseErr := netip.ParseAddr(observation.SourceAddress); parseErr == nil {
		selected.Source = source
	}
	selection := Selection{Selected: selected, Candidates: []Route{selected}, Ambiguous: observation.RouteSelectionAmbiguous}
	if targetIP, parseErr := netip.ParseAddr(observation.TargetIP); parseErr == nil {
		selection.Target = targetIP
	} else {
		selection.Target = targetAddress(target)
	}
	for _, candidate := range observation.CompetingRoutes {
		candidatePrefix, parseErr := netip.ParsePrefix(candidate.RoutePrefix)
		if parseErr != nil {
			continue
		}
		value := Route{Destination: candidatePrefix, Interface: candidate.Interface, InterfaceIndex: candidate.InterfaceIndex, Metric: candidate.Metric, InterfaceType: "", VPNOrTunnel: candidate.VPNOrTunnel, VirtualAdapter: candidate.VirtualAdapter}
		if gateway, parseErr := netip.ParseAddr(candidate.Gateway); parseErr == nil {
			value.Gateway = gateway
		}
		if source, parseErr := netip.ParseAddr(candidate.SourceAddress); parseErr == nil {
			value.Source = source
		}
		selection.Candidates = append(selection.Candidates, value)
	}
	return selection, true
}

func targetAddress(target model.Target) netip.Addr {
	for _, value := range []string{selectedEndpointAddress(target), target.LiteralIP, target.RequestedIdentity} {
		if address, err := parseContextAddress(value); err == nil {
			return address
		}
	}
	for _, value := range target.ResolvedAddresses {
		if address, err := parseContextAddress(value); err == nil {
			return address
		}
	}
	return netip.Addr{}
}

func selectedEndpointAddress(target model.Target) string {
	if target.SelectedEndpoint != nil {
		return target.SelectedEndpoint.Address
	}
	return ""
}

func parseContextAddress(value string) (netip.Addr, error) {
	value = strings.Trim(strings.TrimSpace(value), "[]")
	if percent := strings.LastIndexByte(value, '%'); percent > 0 {
		value = value[:percent]
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, err
	}
	return model.NormalizeAddr(address), nil
}

func matchingInterface(selected Route, interfaces []interfacecfg.InterfaceState) *interfacecfg.InterfaceState {
	for index := range interfaces {
		iface := &interfaces[index]
		if selected.InterfaceIndex != 0 && iface.Index == selected.InterfaceIndex {
			return iface
		}
	}
	for index := range interfaces {
		iface := &interfaces[index]
		if selected.Interface != "" && iface.Name == selected.Interface {
			return iface
		}
		for _, address := range iface.Addresses {
			if address.IP.IsValid() && model.NormalizeAddr(address.IP).String() == selected.Interface {
				return iface
			}
		}
	}
	return nil
}

func sourceAddress(iface interfacecfg.InterfaceState, selected Route, target netip.Addr) string {
	if !target.IsValid() {
		target = selected.Destination.Addr()
	}
	type candidate struct {
		address netip.Addr
		score   int
	}
	candidates := make([]candidate, 0, len(iface.Addresses))
	for _, value := range iface.Addresses {
		address := model.NormalizeAddr(value.IP)
		if !address.IsValid() || address.IsUnspecified() || address.Is4() != target.Is4() {
			continue
		}
		score := 2
		if selected.Destination.Bits() > 0 && selected.Destination.Contains(address) {
			score = 0
		} else if selected.Gateway.IsValid() && !selected.Gateway.IsUnspecified() && value.Prefix > 0 {
			prefix := netip.PrefixFrom(address, value.Prefix).Masked()
			if prefix.Contains(selected.Gateway) {
				score = 0
			}
		} else if address.IsLinkLocalUnicast() == target.IsLinkLocalUnicast() {
			score = 1
		}
		candidates = append(candidates, candidate{address: address, score: score})
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score < candidates[j].score
		}
		return candidates[i].address.String() < candidates[j].address.String()
	})
	if len(candidates) == 0 {
		return ""
	}
	return candidates[0].address.String()
}

func routeNextHop(route Route) string {
	if gateway := addrString(route.Gateway); gateway != "" {
		return gateway
	}
	return "on-link"
}

func cloneNeighbor(neighbor *model.NeighborEvidence) *model.NeighborEvidence {
	if neighbor == nil {
		return nil
	}
	copy := *neighbor
	copy.Entries = append([]model.NeighborEntry(nil), neighbor.Entries...)
	return &copy
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
