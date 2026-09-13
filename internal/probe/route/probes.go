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

// DefaultRouteProbe emits only default-route observations. It intentionally
// remains separate from TargetRouteProbe so callers can distinguish a missing
// default route from a missing route to one particular target.
type DefaultRouteProbe struct {
	Provider RouteTable
	Timeout  time.Duration
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
	family := targetFamily(execution.Target)
	selected, found := Default(routes, family)
	if !found {
		raw := map[string]any{"route_type": "default", "routes_observed": len(routes)}
		return routeResult(execution.Target, p.Name(), started, completed, []model.Evidence{routeEvidence("default-route-1", raw)}, model.ProbeStatusFailed, model.FailureReasonNoRoute, model.LayerRoute, model.FaultDomainRouting)
	}
	raw := selectedRouteEvidence("default", selected, "")
	return routeResult(execution.Target, p.Name(), started, completed, []model.Evidence{routeEvidence("default-route-1", raw)}, model.ProbeStatusPassed, model.FailureReasonNone, model.LayerRoute, model.FaultDomainRouting)
}

func (p *DefaultRouteProbe) routes(ctx context.Context) ([]Route, error) {
	provider := p.Provider
	if provider == nil {
		provider = SystemRouteTable{}
	}
	return provider.Routes(ctx)
}

// TargetRouteProbe selects the effective route toward execution.Target.Host.
// It accepts a literal IPv4 or IPv6 address, allowing deterministic tests and
// avoiding an implicit DNS query. Name resolution is owned by the DNS lane.
type TargetRouteProbe struct {
	Provider RouteTable
	Timeout  time.Duration
	// TargetIP may be populated by an integration layer after DNS has
	// selected an address. When valid it takes precedence over Target.Host.
	TargetIP netip.Addr
}

// EffectiveRouteProbe is a descriptive alias for TargetRouteProbe.
type EffectiveRouteProbe = TargetRouteProbe

func NewTargetRouteProbe(providers ...RouteTable) *TargetRouteProbe {
	var provider RouteTable = SystemRouteTable{}
	if len(providers) != 0 && providers[0] != nil {
		provider = providers[0]
	}
	return &TargetRouteProbe{Provider: provider, Timeout: defaultProbeTimeout}
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
		raw := map[string]any{"route_type": "target", "target": execution.Target.Host, "error": parseErr.Error()}
		return routeResult(execution.Target, p.Name(), started, completed, []model.Evidence{routeEvidence("target-route-1", raw)}, model.ProbeStatusFailed, model.FailureReasonInvalidRoute, model.LayerRoute, model.FaultDomainRouting)
	}
	routes, err := p.routes(callCtx)
	completed := time.Now().UTC()
	if err != nil {
		evidence := []model.Evidence{routeErrorEvidence("target-route-1", err)}
		return routeResult(execution.Target, p.Name(), started, completed, evidence, statusForError(err), reasonForError(err), model.LayerRoute, model.FaultDomainRouting)
	}
	selected, found := Select(routes, targetIP)
	if !found {
		raw := map[string]any{"route_type": "target", "target_ip": targetIP, "routes_observed": len(routes)}
		return routeResult(execution.Target, p.Name(), started, completed, []model.Evidence{routeEvidence("target-route-1", raw)}, model.ProbeStatusFailed, model.FailureReasonNoRoute, model.LayerRoute, model.FaultDomainRouting)
	}
	raw := selectedRouteEvidence("target", selected, targetIP.String())
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
	return parseTargetAddress(target.Host)
}

func (p *TargetRouteProbe) routes(ctx context.Context) ([]Route, error) {
	provider := p.Provider
	if provider == nil {
		provider = SystemRouteTable{}
	}
	return provider.Routes(ctx)
}

// GatewayProbe checks the next-hop gateway selected for the target. Failure
// is intentionally represented only on this supporting probe result; callers
// must not promote it to an end-to-end connectivity finding by itself.
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
	var selected Route
	var found bool
	targetIP, parseErr := p.targetAddress(execution.Target)
	if parseErr == nil {
		selected, found = Select(routes, targetIP)
	} else {
		selected, found = Default(routes, targetFamily(execution.Target))
	}
	if !found {
		raw := map[string]any{"route_type": "gateway", "supporting_only": true, "routes_observed": len(routes)}
		return routeResult(execution.Target, p.Name(), started, completed, []model.Evidence{routeEvidence("gateway-reachability-1", raw)}, model.ProbeStatusFailed, model.FailureReasonNoRoute, model.LayerGateway, model.FaultDomainRouting)
	}
	if !selected.Gateway.IsValid() || selected.Gateway.IsUnspecified() {
		// Directly connected target: there is no gateway to ping. Record that
		// fact as successful local evidence rather than inventing a failure.
		raw := selectedRouteEvidence("gateway", selected, "")
		raw["gateway_tested"] = false
		raw["reachable"] = nil
		raw["supporting_only"] = true
		return routeResult(execution.Target, p.Name(), started, completed, []model.Evidence{routeEvidence("gateway-reachability-1", raw)}, model.ProbeStatusPassed, model.FailureReasonNone, model.LayerGateway, model.FaultDomainGateway)
	}
	checker := p.Checker
	if checker == nil {
		checker = defaultGatewayChecker
	}
	err = checker(callCtx, selected.Gateway)
	completed = time.Now().UTC()
	raw := selectedRouteEvidence("gateway", selected, "")
	raw["gateway_tested"] = true
	raw["reachable"] = err == nil
	raw["supporting_only"] = true
	if err != nil {
		raw["error"] = err.Error()
		status := model.ProbeStatusFailed
		if errors.Is(err, ErrUnsupported) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
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
	return parseTargetAddress(target.Host)
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
	address, err := parseTargetAddress(target.Host)
	if err != nil {
		return 0
	}
	if address.Is4() {
		return 4
	}
	return 6
}

func selectedRouteEvidence(routeType string, selected Route, target string) map[string]any {
	selected = normalizeRoute(selected)
	return map[string]any{
		"route_type":      routeType,
		"target_ip":       target,
		"destination":     selected.Destination,
		"gateway":         selected.Gateway,
		"interface":       selected.Interface,
		"interface_index": selected.InterfaceIndex,
		"metric":          selected.Metric,
	}
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
