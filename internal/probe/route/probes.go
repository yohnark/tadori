package route

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"

	"github.com/yohnark/tadori/internal/model"
	"github.com/yohnark/tadori/internal/probe"
)

const (
	DefaultRouteProbeName = "default_route"
	TargetRouteProbeName  = "target_route"
	GatewayProbeName      = "gateway_reachability"
)

// DefaultRouteProbe reports whether the selected endpoint actually depends on
// a default route. It intentionally remains separate from TargetRouteProbe so
// callers can distinguish default-route evidence from a route to one target.
type DefaultRouteProbe struct {
	Provider RouteTable
	Timeout  time.Duration
	// TargetIP may be populated by an integration layer after DNS selection.
	// It is used only to decide the destination family and whether a default
	// route is applicable; default-route evidence remains separate from the
	// target route.
	TargetIP netip.Addr
}

func NewDefaultRouteProbe(providers ...RouteTable) *DefaultRouteProbe {
	var provider RouteTable = SystemRouteTable{}
	if len(providers) != 0 && providers[0] != nil {
		provider = providers[0]
	}
	return &DefaultRouteProbe{Provider: provider, Timeout: defaultProbeTimeout}
}

func (p *DefaultRouteProbe) Name() string { return DefaultRouteProbeName }

func (p *DefaultRouteProbe) Run(ctx context.Context, execution probe.ExecutionContext) model.ProbeResult {
	started := time.Now().UTC()
	callCtx, cancel := boundedContext(ctx, p.Timeout)
	defer cancel()
	routes, err := p.routes(callCtx)
	completed := time.Now().UTC()
	if err != nil {
		evidence := []model.Evidence{routeErrorEvidence("default-route-1", err)}
		return routeResult(execution.Target, p.Name(), started, completed, evidence, statusForError(err), reasonForError(err), model.LayerRoute, model.FaultDomainRouting)
	}
	targetIP, targetErr := p.targetAddress(execution.Target)
	if targetErr == nil {
		if selection, found := SelectDetailed(routes, targetIP); found && selection.Selected.Destination.Bits() != 0 {
			// A more-specific target route is the route the endpoint actually
			// uses. A default route is not required merely because this separate
			// observation lane exists.
			raw := selectedRouteEvidence("default", selection, targetIP.String(), nil)
			raw.DefaultRouteApplicable = boolPointer(false)
			raw.Error = "default route is not required; a more-specific target route is selected"
			return routeResult(execution.Target, p.Name(), started, completed, []model.Evidence{routeEvidence("default-route-1", raw)}, model.ProbeStatusPassed, model.FailureReasonNone, model.LayerRoute, model.FaultDomainRouting)
		}
		if targetIP.IsLoopback() || targetIP.IsLinkLocalUnicast() {
			selection, found := SelectDetailed(routes, targetIP)
			if !found {
				// A default route is not an applicable external check for a
				// local-scope literal, even when the platform does not expose
				// its loopback or link-local route in the table.
				selection = Selection{Target: targetIP, Selected: Route{Destination: netip.PrefixFrom(targetIP, targetIP.BitLen())}, Candidates: nil}
			}
			raw := selectedRouteEvidence("default", selection, targetIP.String(), nil)
			raw.DefaultRouteApplicable = boolPointer(false)
			raw.Error = "default route is not applicable to the selected local-scope target"
			return routeResult(execution.Target, p.Name(), started, completed, []model.Evidence{routeEvidence("default-route-1", raw)}, model.ProbeStatusPassed, model.FailureReasonNone, model.LayerRoute, model.FaultDomainRouting)
		}
	}
	family := targetFamily(execution.Target)
	if targetIP.IsValid() {
		if targetIP.Is4() {
			family = 4
		} else {
			family = 6
		}
	}
	selected, found := Default(routes, family)
	if !found {
		raw := map[string]any{"route_type": "default", "routes_observed": len(routes)}
		return routeResult(execution.Target, p.Name(), started, completed, []model.Evidence{routeEvidence("default-route-1", raw)}, model.ProbeStatusFailed, model.FailureReasonNoRoute, model.LayerRoute, model.FaultDomainRouting)
	}
	raw := selectedRouteEvidence("default", Selection{Selected: selected, Candidates: []Route{selected}}, "", nil)
	raw.DefaultRouteApplicable = boolPointer(true)
	return routeResult(execution.Target, p.Name(), started, completed, []model.Evidence{routeEvidence("default-route-1", raw)}, model.ProbeStatusPassed, model.FailureReasonNone, model.LayerRoute, model.FaultDomainRouting)
}

// RunForAddress applies the family/local-scope decision to an already
// resolved address without changing the canonical target or doing DNS work.
func (p *DefaultRouteProbe) RunForAddress(ctx context.Context, execution probe.ExecutionContext, targetIP netip.Addr) model.ProbeResult {
	clone := *p
	clone.TargetIP = targetIP
	return clone.Run(ctx, execution)
}

func (p *DefaultRouteProbe) targetAddress(target model.Target) (netip.Addr, error) {
	if p.TargetIP.IsValid() {
		return model.NormalizeAddr(p.TargetIP), nil
	}
	if address := targetAddress(target); address.IsValid() {
		return address, nil
	}
	return parseTargetAddress(target.RequestedIdentity)
}

func routeIsOnLink(route Route) bool {
	return !route.Gateway.IsValid() || route.Gateway.IsUnspecified()
}

func (p *DefaultRouteProbe) routes(ctx context.Context) ([]Route, error) {
	provider := p.Provider
	if provider == nil {
		provider = SystemRouteTable{}
	}
	return provider.Routes(ctx)
}

// TargetRouteProbe selects the effective route toward execution.Target's
// canonical requested identity.
// It accepts a literal IPv4 or IPv6 address, allowing deterministic tests and
// avoiding an implicit DNS query. Name resolution is owned by the DNS lane.
type TargetRouteProbe struct {
	Provider  RouteTable
	Timeout   time.Duration
	Neighbors NeighborTable
	// TargetIP may be populated by an integration layer after DNS has
	// selected an address. When valid it takes precedence over the requested
	// identity.
	TargetIP netip.Addr
}

// EffectiveRouteProbe is a descriptive alias for TargetRouteProbe.
type EffectiveRouteProbe = TargetRouteProbe

func NewTargetRouteProbe(providers ...RouteTable) *TargetRouteProbe {
	var provider RouteTable = SystemRouteTable{}
	if len(providers) != 0 && providers[0] != nil {
		provider = providers[0]
	}
	return &TargetRouteProbe{Provider: provider, Timeout: defaultProbeTimeout, Neighbors: SystemNeighborTable{}}
}

// NewEffectiveRouteProbe is the descriptive constructor alias.
func NewEffectiveRouteProbe(providers ...RouteTable) *TargetRouteProbe {
	return NewTargetRouteProbe(providers...)
}

func (p *TargetRouteProbe) Name() string { return TargetRouteProbeName }

func (p *TargetRouteProbe) Run(ctx context.Context, execution probe.ExecutionContext) model.ProbeResult {
	started := time.Now().UTC()
	callCtx, cancel := boundedContext(ctx, p.Timeout)
	defer cancel()
	targetIP, parseErr := p.targetAddress(execution.Target)
	if parseErr != nil {
		completed := time.Now().UTC()
		raw := map[string]any{"route_type": "target", "target": execution.Target.RequestedIdentity, "error": parseErr.Error()}
		return routeResult(execution.Target, p.Name(), started, completed, []model.Evidence{routeEvidence("target-route-1", raw)}, model.ProbeStatusFailed, model.FailureReasonInvalidRoute, model.LayerRoute, model.FaultDomainRouting)
	}
	routes, err := p.routes(callCtx)
	completed := time.Now().UTC()
	if err != nil {
		evidence := []model.Evidence{routeErrorEvidence("target-route-1", err)}
		return routeResult(execution.Target, p.Name(), started, completed, evidence, statusForError(err), reasonForError(err), model.LayerRoute, model.FaultDomainRouting)
	}
	selection, found := SelectDetailed(routes, targetIP)
	if !found {
		raw := map[string]any{"route_type": "target", "target_ip": targetIP, "routes_observed": len(routes)}
		return routeResult(execution.Target, p.Name(), started, completed, []model.Evidence{routeEvidence("target-route-1", raw)}, model.ProbeStatusFailed, model.FailureReasonNoRoute, model.LayerRoute, model.FaultDomainRouting)
	}
	raw := selectedRouteEvidence("target", selection, targetIP.String(), p.neighborEvidence(callCtx, targetIP, selection.Selected))
	return routeResult(execution.Target, p.Name(), started, completed, []model.Evidence{routeEvidence("target-route-1", raw)}, model.ProbeStatusPassed, model.FailureReasonNone, model.LayerRoute, model.FaultDomainRouting)
}

// RunForAddress selects a route for an already-resolved address without
// changing the canonical model.Target or performing an implicit DNS query.
func (p *TargetRouteProbe) RunForAddress(ctx context.Context, execution probe.ExecutionContext, targetIP netip.Addr) model.ProbeResult {
	clone := *p
	clone.TargetIP = targetIP
	return clone.Run(ctx, execution)
}

func (p *TargetRouteProbe) targetAddress(target model.Target) (netip.Addr, error) {
	if p.TargetIP.IsValid() {
		return model.NormalizeAddr(p.TargetIP), nil
	}
	if address := targetAddress(target); address.IsValid() {
		return address, nil
	}
	return parseTargetAddress(target.RequestedIdentity)
}

func (p *TargetRouteProbe) routes(ctx context.Context) ([]Route, error) {
	provider := p.Provider
	if provider == nil {
		provider = SystemRouteTable{}
	}
	return provider.Routes(ctx)
}

func (p *TargetRouteProbe) neighborEvidence(ctx context.Context, target netip.Addr, selected Route) *model.NeighborEvidence {
	provider := p.Neighbors
	if provider == nil {
		provider = SystemNeighborTable{}
	}
	lookup := target
	if selected.Gateway.IsValid() && !selected.Gateway.IsUnspecified() {
		lookup = selected.Gateway
	}
	evidence, err := provider.Neighbors(ctx, lookup, selected.InterfaceIndex)
	if err != nil {
		if evidence.Observation == "" {
			evidence.Observation = model.NeighborObservationError
		}
		if evidence.Note == "" {
			evidence.Note = err.Error()
		}
		return &evidence
	}
	if evidence.Observation == "" {
		evidence.Observation = model.NeighborObservationUnknown
	}
	return &evidence
}

// GatewayProbe checks the next-hop gateway selected for the target. Failure
// is intentionally represented only on this supporting probe result; callers
// must not promote it to an end-to-end connectivity finding by itself. An
// unavailable optional checker is reported as skipped rather than as a route
// inspection failure.
type GatewayProbe struct {
	Provider RouteTable
	Checker  ReachabilityChecker
	Timeout  time.Duration
	// TargetIP may be populated by an integration layer after DNS selection.
	TargetIP netip.Addr
}

func NewGatewayProbe(providers ...RouteTable) *GatewayProbe {
	var provider RouteTable = SystemRouteTable{}
	if len(providers) != 0 && providers[0] != nil {
		provider = providers[0]
	}
	return &GatewayProbe{Provider: provider, Checker: defaultGatewayChecker, Timeout: defaultProbeTimeout}
}

func (p *GatewayProbe) Name() string { return GatewayProbeName }

func (p *GatewayProbe) Run(ctx context.Context, execution probe.ExecutionContext) model.ProbeResult {
	started := time.Now().UTC()
	callCtx, cancel := boundedContext(ctx, p.Timeout)
	defer cancel()
	routes, err := p.routes(callCtx)
	completed := time.Now().UTC()
	if err != nil {
		evidence := []model.Evidence{routeEvidence("gateway-reachability-1", map[string]any{"error": err.Error(), "supporting_only": true})}
		return routeResult(execution.Target, p.Name(), started, completed, evidence, statusForError(err), reasonForError(err), model.LayerGateway, model.FaultDomainGateway)
	}
	var selection Selection
	var found bool
	targetIP, parseErr := p.targetAddress(execution.Target)
	if parseErr == nil {
		selection, found = SelectDetailed(routes, targetIP)
	} else {
		selected, selectedFound := Default(routes, targetFamily(execution.Target))
		selection = Selection{Selected: selected, Candidates: []Route{selected}}
		found = selectedFound
	}
	if !found {
		raw := map[string]any{"route_type": "gateway", "supporting_only": true, "routes_observed": len(routes)}
		return routeResult(execution.Target, p.Name(), started, completed, []model.Evidence{routeEvidence("gateway-reachability-1", raw)}, model.ProbeStatusFailed, model.FailureReasonNoRoute, model.LayerGateway, model.FaultDomainRouting)
	}
	if targetIP.IsValid() && (targetIP.IsLoopback() || targetIP.IsLinkLocalUnicast()) {
		// Loopback and link-local are local route boundaries. Even if a
		// malformed fixture or platform row supplies a gateway, never run an
		// external gateway check for these destinations.
		raw := selectedRouteEvidence("gateway", selection, "", nil)
		raw.GatewayTested = boolPointer(false)
		raw.Reachable = nil
		raw.SupportingOnly = true
		return routeResult(execution.Target, p.Name(), started, completed, []model.Evidence{routeEvidence("gateway-reachability-1", raw)}, model.ProbeStatusPassed, model.FailureReasonNone, model.LayerGateway, model.FaultDomainGateway)
	}
	if routeIsOnLink(selection.Selected) {
		// Directly connected target: there is no gateway to ping. Record that
		// fact as successful local evidence rather than inventing a failure.
		raw := selectedRouteEvidence("gateway", selection, "", nil)
		raw.GatewayTested = boolPointer(false)
		raw.Reachable = nil
		raw.SupportingOnly = true
		return routeResult(execution.Target, p.Name(), started, completed, []model.Evidence{routeEvidence("gateway-reachability-1", raw)}, model.ProbeStatusPassed, model.FailureReasonNone, model.LayerGateway, model.FaultDomainGateway)
	}
	checker := p.Checker
	if checker == nil {
		checker = defaultGatewayChecker
	}
	err = checker(callCtx, selection.Selected.Gateway)
	completed = time.Now().UTC()
	raw := selectedRouteEvidence("gateway", selection, "", nil)
	raw.GatewayTested = boolPointer(true)
	raw.Reachable = boolPointer(err == nil)
	raw.SupportingOnly = true
	if err != nil {
		raw.Error = err.Error()
		if gatewayCheckUnsupported(err) {
			// Route discovery above succeeded. The optional gateway check was
			// unavailable, so do not describe the selected route as untested or
			// turn the missing capability into a reachability failure.
			raw.GatewayTested = boolPointer(false)
			raw.Reachable = nil
			raw.Error = ErrGatewayReachabilityUnsupported.Error()
			return routeResult(execution.Target, p.Name(), started, completed, []model.Evidence{routeEvidence("gateway-reachability-1", raw)}, model.ProbeStatusSkipped, model.FailureReasonUnsupported, model.LayerGateway, model.FaultDomainGateway)
		}
		status := model.ProbeStatusFailed
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			status = model.ProbeStatusError
		}
		return routeResult(execution.Target, p.Name(), started, completed, []model.Evidence{routeEvidence("gateway-reachability-1", raw)}, status, gatewayReason(err), model.LayerGateway, model.FaultDomainGateway)
	}
	return routeResult(execution.Target, p.Name(), started, completed, []model.Evidence{routeEvidence("gateway-reachability-1", raw)}, model.ProbeStatusPassed, model.FailureReasonNone, model.LayerGateway, model.FaultDomainGateway)
}

// RunForAddress checks the gateway on the route selected for targetIP.
func (p *GatewayProbe) RunForAddress(ctx context.Context, execution probe.ExecutionContext, targetIP netip.Addr) model.ProbeResult {
	clone := *p
	clone.TargetIP = targetIP
	return clone.Run(ctx, execution)
}

func (p *GatewayProbe) targetAddress(target model.Target) (netip.Addr, error) {
	if p.TargetIP.IsValid() {
		return model.NormalizeAddr(p.TargetIP), nil
	}
	if address := targetAddress(target); address.IsValid() {
		return address, nil
	}
	return parseTargetAddress(target.RequestedIdentity)
}

func (p *GatewayProbe) routes(ctx context.Context) ([]Route, error) {
	provider := p.Provider
	if provider == nil {
		provider = SystemRouteTable{}
	}
	return provider.Routes(ctx)
}

func parseTargetAddress(host string) (netip.Addr, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return netip.Addr{}, errors.New("target host is empty")
	}
	if percent := strings.LastIndexByte(host, '%'); percent > 0 {
		host = host[:percent]
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, err
	}
	return model.NormalizeAddr(address), nil
}

func targetFamily(target model.Target) int {
	address := targetAddress(target)
	if !address.IsValid() {
		return 0
	}
	if address.Is4() {
		return 4
	}
	return 6
}

func selectedRouteEvidence(routeType string, selection Selection, target string, neighbor *model.NeighborEvidence) RouteObservation {
	selected := normalizeRoute(selection.Selected)
	gateway := addrString(selected.Gateway)
	effective := model.RouteDispositionOnLink
	nextHop := "on-link"
	if gateway != "" {
		effective = model.RouteDispositionRouted
		nextHop = gateway
	}
	observation := RouteObservation{
		RouteType:               routeType,
		TargetIP:                target,
		Destination:             selected.Destination.String(),
		Gateway:                 gateway,
		Interface:               selected.Interface,
		InterfaceIndex:          selected.InterfaceIndex,
		SourceAddress:           addrString(selected.Source),
		Metric:                  selected.Metric,
		EffectiveRoute:          effective,
		RoutePrefix:             selected.Destination.String(),
		NextHop:                 nextHop,
		InterfaceType:           selected.InterfaceType,
		VPNOrTunnel:             selected.VPNOrTunnel,
		VirtualAdapter:          selected.VirtualAdapter,
		RouteSelectionAmbiguous: selection.Ambiguous,
		Neighbor:                neighbor,
	}
	for _, candidate := range selection.Candidates {
		candidate = normalizeRoute(candidate)
		if sameRoute(candidate, selected) {
			continue
		}
		observation.CompetingRoutes = append(observation.CompetingRoutes, routeEvidenceCandidate(candidate))
	}
	return observation
}

func routeEvidenceCandidate(route Route) RouteEvidenceCandidate {
	route = normalizeRoute(route)
	gateway := addrString(route.Gateway)
	nextHop := "on-link"
	if gateway != "" {
		nextHop = gateway
	}
	return RouteEvidenceCandidate{
		RoutePrefix: route.Destination.String(), Gateway: gateway, NextHop: nextHop,
		Interface: route.Interface, InterfaceIndex: route.InterfaceIndex,
		SourceAddress: addrString(route.Source), Metric: route.Metric,
		VPNOrTunnel: route.VPNOrTunnel, VirtualAdapter: route.VirtualAdapter,
	}
}

func addrString(address netip.Addr) string {
	if !address.IsValid() || address.IsUnspecified() {
		return ""
	}
	return model.NormalizeAddr(address).String()
}

func boolPointer(value bool) *bool { return &value }

// DecodeRouteEvidence decodes the known structured route shape and fills
// fields emitted by older route probes when possible.
func DecodeRouteEvidence(evidence model.Evidence) (RouteObservation, error) {
	if evidence.Kind != model.EvidenceKindRoute {
		return RouteObservation{}, errors.New("evidence is not route evidence")
	}
	var observation RouteObservation
	if err := json.Unmarshal(evidence.Raw, &observation); err != nil {
		return RouteObservation{}, err
	}
	if observation.RoutePrefix == "" {
		observation.RoutePrefix = observation.Destination
	}
	if gateway, err := netip.ParseAddr(observation.Gateway); err == nil && gateway.IsUnspecified() {
		observation.Gateway = ""
	}
	hasRoute := observation.RoutePrefix != "" || observation.Gateway != "" || observation.Interface != "" || observation.InterfaceIndex != 0
	if observation.EffectiveRoute == "" && hasRoute {
		if observation.Gateway == "" {
			observation.EffectiveRoute = model.RouteDispositionOnLink
		} else {
			observation.EffectiveRoute = model.RouteDispositionRouted
		}
	}
	if observation.NextHop == "" && hasRoute {
		if observation.Gateway == "" {
			observation.NextHop = "on-link"
		} else {
			observation.NextHop = observation.Gateway
		}
	}
	return observation, nil
}

func routeEvidence(id string, raw any) model.Evidence {
	bytes, err := json.Marshal(raw)
	if err != nil {
		bytes = []byte(`{"error":"evidence serialization failed"}`)
	}
	now := time.Now().UTC()
	return model.Evidence{ID: id, Kind: model.EvidenceKindRoute, Source: "native-route-api", CapturedAt: &now, Raw: bytes}
}

func routeErrorEvidence(id string, err error) model.Evidence {
	return routeEvidence(id, map[string]any{"error": err.Error()})
}

func routeResult(target model.Target, name string, started, completed time.Time, evidence []model.Evidence, status model.ProbeStatus, reason model.FailureReason, layer model.Layer, domain model.FaultDomain) model.ProbeResult {
	duration := completed.Sub(started).Milliseconds()
	if duration < 0 {
		duration = 0
	}
	return model.ProbeResult{Name: name, Target: target, Status: status, Timing: model.Timing{StartedAt: &started, CompletedAt: &completed, DurationMS: duration}, Evidence: evidence, Interpretation: model.ProbeInterpretation{FailureReason: reason, Layer: layer, FaultDomain: domain}}
}

func statusForError(err error) model.ProbeStatus {
	if errors.Is(err, context.DeadlineExceeded) {
		return model.ProbeStatusFailed
	}
	var timeoutError net.Error
	if errors.As(err, &timeoutError) && timeoutError.Timeout() {
		return model.ProbeStatusFailed
	}
	return model.ProbeStatusError
}

func reasonForError(err error) model.FailureReason {
	if errors.Is(err, context.DeadlineExceeded) {
		return model.FailureReason(FailureReasonProbeTimeout)
	}
	var timeoutError net.Error
	if errors.As(err, &timeoutError) && timeoutError.Timeout() {
		return model.FailureReason(FailureReasonProbeTimeout)
	}
	if errors.Is(err, ErrUnsupported) {
		return model.FailureReasonUnsupported
	}
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		return model.FailureReason(FailureReasonInsufficientPrivilege)
	}
	return model.FailureReasonProbeExecution
}

func gatewayReason(err error) model.FailureReason {
	if errors.Is(err, context.DeadlineExceeded) {
		return model.FailureReason(FailureReasonProbeTimeout)
	}
	var timeoutError net.Error
	if errors.As(err, &timeoutError) && timeoutError.Timeout() {
		return model.FailureReason(FailureReasonProbeTimeout)
	}
	if errors.Is(err, ErrUnsupported) {
		return model.FailureReasonUnsupported
	}
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		return model.FailureReason(FailureReasonInsufficientPrivilege)
	}
	return model.FailureReasonGatewayUnreachable
}

func gatewayCheckUnsupported(err error) bool {
	return errors.Is(err, ErrGatewayReachabilityUnsupported) || errors.Is(err, ErrUnsupported)
}
