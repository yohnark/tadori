// Package environment collects and normalizes target-independent local
// networking context. It composes the existing interface, route, proxy, and
// enterprise authorities; it does not run a destination probe.
package environment

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/yohnark/tadori/internal/model"
	"github.com/yohnark/tadori/internal/probe/enterprise"
	"github.com/yohnark/tadori/internal/probe/interfacecfg"
	"github.com/yohnark/tadori/internal/probe/proxy"
	"github.com/yohnark/tadori/internal/probe/route"
	"github.com/yohnark/tadori/internal/version"
)

const (
	DefaultTimeout = 8 * time.Second
	maxRoutes      = 512
)

// ProxyProvider is the small adapter needed to keep proxy discovery
// injectable in deterministic tests.
type ProxyProvider interface {
	Discover(context.Context) (proxy.Discovery, error)
}

type ProxyProviderFunc func(context.Context) (proxy.Discovery, error)

func (f ProxyProviderFunc) Discover(ctx context.Context) (proxy.Discovery, error) { return f(ctx) }

// RuntimeProvider supplies the non-network execution context. Runtime values
// are included because they determine how unsupported or partial observations
// should be interpreted.
type RuntimeProvider interface {
	Snapshot(context.Context) (model.EnvironmentRuntimeObservation, error)
}

type RuntimeProviderFunc func(context.Context) (model.EnvironmentRuntimeObservation, error)

func (f RuntimeProviderFunc) Snapshot(ctx context.Context) (model.EnvironmentRuntimeObservation, error) {
	return f(ctx)
}

// Provider is the raw collection boundary. Collection keeps component errors
// separate so one unavailable subsystem cannot erase useful local facts.
type Provider interface {
	Snapshot(context.Context) (Collection, error)
}

type ProviderFunc func(context.Context) (Collection, error)

func (f ProviderFunc) Snapshot(ctx context.Context) (Collection, error) { return f(ctx) }

// Collection is an internal-to-the-backend normalized input assembled from
// existing probe authorities. Known flags distinguish an empty successful
// subsystem from one for which no evidence was available.
type Collection struct {
	Interfaces            []interfacecfg.InterfaceState
	InterfacesKnown       bool
	InterfacesUnsupported bool
	InterfaceError        string
	DNS                   interfacecfg.Snapshot
	DNSKnown              bool
	DNSUnsupported        bool
	DNSError              string
	Routes                []route.Route
	RoutesKnown           bool
	RouteError            string
	RouteUnsupported      bool
	WinHTTP               proxy.ConfigurationObservation
	WinHTTPKnown          bool
	WinINET               proxy.ConfigurationObservation
	WinINETKnown          bool
	ProxyError            string
	ProxyUnsupported      bool
	Firewall              enterprise.FirewallObservation
	FirewallKnown         bool
	TrustStore            enterprise.TrustStoreObservation
	TrustKnown            bool
	EnterpriseError       string
	EnterpriseUnsupported bool
	Runtime               model.EnvironmentRuntimeObservation
	RuntimeKnown          bool
	Provenance            []string
	EvidenceIDs           []string
	Limitations           []string
}

// SystemProvider composes the existing platform authorities. The enterprise
// provider supplies Windows proxy/firewall/trust/adapter context; interfaces
// and routes remain owned by their existing packages.
type SystemProvider struct {
	Interfaces interfacecfg.SnapshotProvider
	Routes     route.RouteTable
	Proxy      ProxyProvider
	Enterprise enterprise.EnvironmentSnapshotProvider
	Runtime    RuntimeProvider
}

// Snapshot collects every independent component and returns partial
// collection data alongside any provider-level error.
func (p SystemProvider) Snapshot(ctx context.Context) (Collection, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	collection := Collection{}
	var providerErrs []error

	interfacesProvider := p.Interfaces
	if interfacesProvider == nil {
		interfacesProvider = interfacecfg.SystemProvider{}
	}
	interfaceSnapshot, err := interfacesProvider.Snapshot(ctx)
	collection.Interfaces = append([]interfacecfg.InterfaceState(nil), interfaceSnapshot.Interfaces...)
	collection.InterfacesKnown = err == nil || len(interfaceSnapshot.Interfaces) > 0
	collection.DNS = interfaceSnapshot
	collection.DNSKnown = err == nil || len(interfaceSnapshot.DNSServers) > 0 || interfaceSnapshot.ResolverError != "" || len(interfaceSnapshot.DNSSuffixes) > 0 || len(interfaceSnapshot.SearchList) > 0
	if err != nil {
		collection.InterfaceError = safeError(err)
		collection.DNSError = safeError(err)
		providerErrs = append(providerErrs, err)
	}
	if interfaceSnapshot.ResolverError != "" {
		collection.DNSError = interfaceSnapshot.ResolverError
	}

	routesProvider := p.Routes
	if routesProvider == nil {
		routesProvider = route.SystemRouteTable{}
	}
	collection.Routes, err = routesProvider.Routes(ctx)
	collection.RoutesKnown = err == nil || len(collection.Routes) > 0
	if err != nil {
		collection.RouteError = safeError(err)
		collection.RouteUnsupported = errors.Is(err, route.ErrUnsupported)
		providerErrs = append(providerErrs, err)
	}

	enterpriseProvider := p.Enterprise
	if enterpriseProvider == nil {
		enterpriseProvider = enterpriseEnvironmentProvider{}
	}
	local, enterpriseErr := enterpriseProvider.SnapshotEnvironment(ctx)
	if enterpriseErr != nil {
		collection.EnterpriseError = safeError(enterpriseErr)
		collection.EnterpriseUnsupported = errors.Is(enterpriseErr, enterprise.ErrUnsupportedPlatform)
		providerErrs = append(providerErrs, enterpriseErr)
	} else {
		collection.WinHTTP = proxy.NormalizeConfiguration(local.Proxy.WinHTTP)
		collection.WinINET = proxy.NormalizeConfiguration(local.Proxy.WinINET)
		collection.WinHTTPKnown = true
		collection.WinINETKnown = true
		collection.Firewall = local.Firewall
		collection.FirewallKnown = true
		collection.TrustStore = local.TrustStore
		collection.TrustKnown = true
		collection.Provenance = append(collection.Provenance, "windows-enterprise")
		for _, issue := range local.Issues {
			collection.Limitations = appendUnique(collection.Limitations, issueLabel(issue))
		}
	}

	// Proxy discovery remains a separately injectable authority. It fills the
	// proxy fields when the enterprise adapter is unavailable or unsupported.
	if !collection.WinHTTPKnown || !collection.WinINETKnown {
		proxyProvider := p.Proxy
		if proxyProvider == nil {
			proxyProvider = ProxyProviderFunc(proxy.Discover)
		}
		discovery, proxyErr := proxyProvider.Discover(ctx)
		if proxyErr != nil {
			collection.ProxyError = safeError(proxyErr)
			collection.ProxyUnsupported = errors.Is(proxyErr, proxy.ErrUnsupportedPlatform)
			providerErrs = append(providerErrs, proxyErr)
		} else {
			collection.WinHTTP = proxy.NormalizeConfiguration(discovery.WinHTTP)
			collection.WinINET = proxy.NormalizeConfiguration(discovery.WinINET)
			collection.WinHTTPKnown = true
			collection.WinINETKnown = true
			collection.Provenance = append(collection.Provenance, "proxy-discovery")
		}
	}

	runtimeProvider := p.Runtime
	if runtimeProvider == nil {
		runtimeProvider = runtimeProviderFunc(defaultRuntimeSnapshot)
	}
	collection.Runtime, err = runtimeProvider.Snapshot(ctx)
	collection.RuntimeKnown = err == nil
	if err != nil {
		collection.Limitations = appendUnique(collection.Limitations, "runtime: "+safeError(err))
		providerErrs = append(providerErrs, err)
	}
	if ctx.Err() != nil {
		return collection, ctx.Err()
	}
	return collection, errors.Join(providerErrs...)
}

type enterpriseEnvironmentProvider struct{}

func (enterpriseEnvironmentProvider) SnapshotEnvironment(ctx context.Context) (enterprise.EnvironmentSnapshot, error) {
	return enterprise.CollectEnvironment(ctx)
}

type runtimeProviderFunc func(context.Context) (model.EnvironmentRuntimeObservation, error)

func (f runtimeProviderFunc) Snapshot(ctx context.Context) (model.EnvironmentRuntimeObservation, error) {
	return f(ctx)
}

func defaultRuntimeSnapshot(ctx context.Context) (model.EnvironmentRuntimeObservation, error) {
	if err := ctx.Err(); err != nil {
		return model.EnvironmentRuntimeObservation{}, err
	}
	return model.EnvironmentRuntimeObservation{
		State: model.EnvironmentStateObserved, OS: runtime.GOOS, Arch: runtime.GOARCH,
		RuntimeVersion: runtime.Version(), TadoriVersion: version.Version,
		Privilege: "unknown", Provenance: []string{"runtime:go"},
	}, nil
}

// Options configures one bounded environment collection.
type Options struct {
	Provider      Provider
	Runtime       RuntimeProvider
	Timeout       time.Duration
	Now           func() time.Time
	TadoriVersion string
}

// Collector owns the bounded collection lifecycle and canonical projection.
type Collector struct {
	provider Provider
	runtime  RuntimeProvider
	timeout  time.Duration
	now      func() time.Time
	version  string
}

func New(options ...Options) *Collector {
	var option Options
	if len(options) > 0 {
		option = options[0]
	}
	provider := option.Provider
	if provider == nil {
		provider = SystemProvider{}
	}
	runtimeProvider := option.Runtime
	if runtimeProvider == nil {
		runtimeProvider = runtimeProviderFunc(defaultRuntimeSnapshot)
	}
	timeout := option.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	now := option.Now
	if now == nil {
		now = time.Now
	}
	tadoriVersion := option.TadoriVersion
	if tadoriVersion == "" {
		tadoriVersion = version.Version
	}
	return &Collector{provider: provider, runtime: runtimeProvider, timeout: timeout, now: now, version: tadoriVersion}
}

// Collect returns a canonical snapshot. Partial component failures are
// represented in the snapshot; a non-nil error is reserved for cancellation
// or a provider-level failure that did not yield usable collection data.
func Collect(ctx context.Context, options ...Options) (model.EnvironmentSnapshot, error) {
	return New(options...).Collect(ctx)
}

func (c *Collector) Collect(ctx context.Context) (model.EnvironmentSnapshot, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if c == nil {
		c = New()
	}
	callCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	collection, providerErr := c.provider.Snapshot(callCtx)
	if !collection.RuntimeKnown {
		if runtimeValue, err := c.runtime.Snapshot(callCtx); err == nil {
			collection.Runtime = runtimeValue
			collection.RuntimeKnown = true
		} else {
			collection.Limitations = appendUnique(collection.Limitations, "runtime: "+safeError(err))
		}
	}
	now := c.now
	captured := now().UTC()
	snapshot := Build(collection, captured)
	if c.version != "" {
		snapshot.Runtime.TadoriVersion = c.version
	}
	if providerErr != nil && callCtx.Err() == nil {
		snapshot.Limitations = appendUnique(snapshot.Limitations, "collection: "+safeError(providerErr))
	}
	snapshot = *model.NormalizeEnvironmentSnapshot(&snapshot)
	if err := ctx.Err(); err != nil {
		return snapshot, err
	}
	if callCtx.Err() != nil {
		return snapshot, callCtx.Err()
	}
	return snapshot, nil
}

// Build projects a component collection into the canonical environment
// contract. It never performs I/O and is therefore the primary deterministic
// test seam.
func Build(collection Collection, capturedAt time.Time) model.EnvironmentSnapshot {
	snapshot := model.EnvironmentSnapshot{
		SchemaVersion:   model.EnvironmentSnapshotSchemaVersion,
		CapturedAt:      capturedAt.UTC(),
		State:           model.EnvironmentStateUnknown,
		InterfacesState: model.EnvironmentStateUnknown,
		DNS:             model.EnvironmentDNSObservation{State: model.EnvironmentStateUnknown, Certainty: model.ObservationCertaintyUnknown},
		Routing:         model.EnvironmentRoutingObservation{State: model.EnvironmentStateUnknown, Certainty: model.ObservationCertaintyUnknown},
		Proxy:           model.EnvironmentProxyObservation{State: model.EnvironmentStateUnknown, Certainty: model.ObservationCertaintyUnknown},
		VPN:             model.EnvironmentVPNObservation{State: model.EnvironmentStateUnknown, Certainty: model.ObservationCertaintyUnknown},
		Firewall:        model.EnterpriseFirewallObservation{State: model.EnterpriseObservationStateUnknown, BlockCausality: model.EnterpriseFirewallCausalityNotEstablished, Certainty: model.ObservationCertaintyUnknown},
		Trust:           model.EnvironmentTrustObservation{State: model.EnvironmentStateUnknown, Certainty: model.ObservationCertaintyUnknown},
		Runtime:         collection.Runtime,
		Provenance:      append([]string(nil), collection.Provenance...), EvidenceIDs: append([]string(nil), collection.EvidenceIDs...), Limitations: append([]string(nil), collection.Limitations...),
	}
	snapshot.Interfaces = buildInterfaces(collection, &snapshot)
	if collection.InterfacesUnsupported {
		snapshot.InterfacesState = model.EnvironmentStateUnsupported
	} else if collection.InterfacesKnown {
		snapshot.InterfacesState = model.EnvironmentStateObserved
	}
	snapshot.DNS = buildDNS(collection, &snapshot)
	snapshot.Routing = buildRouting(collection, &snapshot)
	snapshot.Proxy = buildProxy(collection, &snapshot)
	snapshot.VPN = buildVPN(collection, snapshot.Interfaces, snapshot.Routing, &snapshot)
	snapshot.Firewall = buildFirewall(collection, &snapshot)
	snapshot.Trust = buildTrust(collection, &snapshot)
	if !collection.RuntimeKnown && snapshot.Runtime.State == "" {
		snapshot.Runtime = model.EnvironmentRuntimeObservation{State: model.EnvironmentStateUnknown, Privilege: "unknown"}
	}
	if snapshot.Runtime.TadoriVersion == "" {
		snapshot.Runtime.TadoriVersion = version.Version
	}
	if snapshot.Runtime.OS == "" {
		snapshot.Runtime.OS = runtime.GOOS
	}
	if snapshot.Runtime.Arch == "" {
		snapshot.Runtime.Arch = runtime.GOARCH
	}
	if snapshot.Runtime.RuntimeVersion == "" {
		snapshot.Runtime.RuntimeVersion = runtime.Version()
	}
	snapshot.Runtime.Capabilities = capabilities(snapshot)
	snapshot.State = overallState(snapshot)
	return *model.NormalizeEnvironmentSnapshot(&snapshot)
}

func buildInterfaces(collection Collection, snapshot *model.EnvironmentSnapshot) []model.EnvironmentInterface {
	if !collection.InterfacesKnown && len(collection.Interfaces) == 0 {
		if collection.InterfacesUnsupported {
			snapshot.Limitations = appendUnique(snapshot.Limitations, "interfaces: unsupported")
		}
		return nil
	}
	result := make([]model.EnvironmentInterface, 0, len(collection.Interfaces))
	for _, value := range collection.Interfaces {
		item := model.EnvironmentInterface{
			Index: value.Index, Name: value.Name, Description: value.Description, Type: value.Type,
			Hardware: value.Hardware, MTU: value.MTU, Up: value.Up, Loopback: value.Loopback,
			VPN: value.VPN, Virtual: value.Virtual, DNSSuffix: value.DNSSuffix,
			DNSServers: addressesToStrings(value.DNSServers), DNSSearchList: append([]string(nil), value.DNSSearchList...),
			State: model.EnvironmentStateObserved, Certainty: model.ObservationCertaintyObserved,
			Provenance: []string{"interfacecfg:" + nonEmpty(valueSource(collection), "interface-state")},
		}
		for _, address := range value.Addresses {
			item.Addresses = append(item.Addresses, model.EnvironmentAddress{IP: address.IP.String(), Prefix: address.Prefix})
		}
		result = append(result, item)
	}
	if collection.InterfaceError != "" {
		snapshot.Limitations = appendUnique(snapshot.Limitations, "interfaces: "+collection.InterfaceError)
	}
	return result
}

func buildDNS(collection Collection, snapshot *model.EnvironmentSnapshot) model.EnvironmentDNSObservation {
	value := collection.DNS
	result := model.EnvironmentDNSObservation{
		Servers: addressesToStrings(value.DNSServers), Suffixes: append([]string(nil), value.DNSSuffixes...), SearchList: append([]string(nil), value.SearchList...),
		NRPT: append([]model.NameResolutionPolicyRule(nil), value.NRPT...), HostsFileEntries: append([]model.NameResolutionHostEntry(nil), value.HostsFileEntries...),
		ResolverError: value.ResolverError, NRPTError: value.NRPTError, HostsFileError: value.HostsFileError,
		Certainty: model.ObservationCertaintyConfigured, Provenance: []string{"interfacecfg:dns_configuration"},
	}
	if !collection.DNSKnown {
		result.State, result.Certainty = model.EnvironmentStateUnknown, model.ObservationCertaintyUnknown
		if collection.DNSUnsupported {
			result.State, result.Certainty = model.EnvironmentStateUnsupported, model.ObservationCertaintyUnsupported
		}
		if collection.DNSError != "" {
			result.Limitations = append(result.Limitations, collection.DNSError)
		}
		return result
	}
	result.State = model.EnvironmentStateObserved
	if collection.DNSError != "" || result.ResolverError != "" || result.NRPTError != "" || result.HostsFileError != "" {
		result.State = model.EnvironmentStatePartial
		result.Certainty = model.ObservationCertaintyUnknown
		if collection.DNSError != "" {
			result.Limitations = appendUnique(result.Limitations, collection.DNSError)
		}
	}
	if len(result.NRPT) > 0 {
		result.Certainty = model.ObservationCertaintyConfigured
	}
	return result
}

func buildRouting(collection Collection, snapshot *model.EnvironmentSnapshot) model.EnvironmentRoutingObservation {
	result := model.EnvironmentRoutingObservation{RouteTableKnown: collection.RoutesKnown, Error: collection.RouteError, Certainty: model.ObservationCertaintyUnknown, Provenance: []string{"route:table"}}
	for _, value := range boundedRoutes(collection.Routes) {
		result.Routes = append(result.Routes, canonicalRoute(value, false))
	}
	if !collection.RoutesKnown {
		if collection.RouteUnsupported {
			result.State, result.Certainty = model.EnvironmentStateUnsupported, model.ObservationCertaintyUnsupported
		} else {
			result.State = model.EnvironmentStateUnknown
		}
		if result.Error != "" {
			result.Limitations = append(result.Limitations, result.Error)
		}
		return result
	}
	result.State, result.Certainty = model.EnvironmentStateObserved, model.ObservationCertaintyObserved
	if selected, ok := route.Default(collection.Routes, 4); ok {
		value := canonicalRoute(selected, true)
		result.DefaultIPv4 = &value
		markSelectedRoute(result.Routes, value)
	}
	if selected, ok := route.Default(collection.Routes, 6); ok {
		value := canonicalRoute(selected, true)
		result.DefaultIPv6 = &value
		markSelectedRoute(result.Routes, value)
	}
	if len(result.Routes) == 0 {
		result.State = model.EnvironmentStatePartial
		result.Certainty = model.ObservationCertaintyUnknown
	}
	if collection.RouteError != "" {
		result.State = model.EnvironmentStatePartial
		result.Limitations = appendUnique(result.Limitations, collection.RouteError)
	}
	return result
}

func buildProxy(collection Collection, snapshot *model.EnvironmentSnapshot) model.EnvironmentProxyObservation {
	result := model.EnvironmentProxyObservation{
		WinHTTP:    proxySource("winhttp", collection.WinHTTP, collection.WinHTTPKnown),
		WinINET:    proxySource("wininet", collection.WinINET, collection.WinINETKnown),
		Certainty:  model.ObservationCertaintyUnknown,
		Provenance: []string{"proxy:winhttp", "proxy:wininet"},
	}
	result.ConfigurationKnown = collection.WinHTTPKnown && collection.WinINETKnown
	if collection.WinHTTPKnown || collection.WinINETKnown {
		result.Certainty = model.ObservationCertaintyConfigured
		result.State = model.EnvironmentStateConfigured
	}
	if collection.WinHTTPKnown && collection.WinINETKnown && !sameProxy(result.WinHTTP, result.WinINET) {
		result.ConfigurationDiverges = true
		result.State = model.EnvironmentStateConflicting
		result.Certainty = model.ObservationCertaintyConflicting
		result.Conflicts = append(result.Conflicts, model.ObservationConflict{Field: "proxy.winhttp_vs_wininet", Values: []string{proxyFingerprint(result.WinHTTP), proxyFingerprint(result.WinINET)}, Provenance: []string{"proxy:winhttp", "proxy:wininet"}})
	}
	if !collection.WinHTTPKnown && !collection.WinINETKnown {
		if collection.ProxyUnsupported {
			result.State, result.Certainty = model.EnvironmentStateUnsupported, model.ObservationCertaintyUnsupported
			result.WinHTTP = unsupportedProxySource("winhttp")
			result.WinINET = unsupportedProxySource("wininet")
		} else {
			result.State = model.EnvironmentStateUnknown
		}
	}
	if collection.WinHTTPKnown != collection.WinINETKnown && result.State == model.EnvironmentStateConfigured {
		result.State, result.Certainty = model.EnvironmentStatePartial, model.ObservationCertaintyUnknown
	}
	if collection.ProxyError != "" {
		result.Limitations = append(result.Limitations, collection.ProxyError)
		if result.State == model.EnvironmentStateConfigured {
			result.State = model.EnvironmentStatePartial
		}
	}
	// URL-specific PAC use has no target-independent evidence. Keep this
	// explicit so a configured PAC URL cannot become an effective path claim.
	result.EffectiveUseTargetBounded = true
	return result
}

func unsupportedProxySource(source string) model.EnvironmentProxySource {
	return model.EnvironmentProxySource{Source: source, State: model.EnvironmentStateUnsupported, Certainty: model.ObservationCertaintyUnsupported}
}

func proxySource(source string, value proxy.ConfigurationObservation, known bool) model.EnvironmentProxySource {
	if !known {
		return model.EnvironmentProxySource{Source: source, State: model.EnvironmentStateUnknown, Certainty: model.ObservationCertaintyUnknown}
	}
	state := model.EnvironmentStateConfigured
	certainty := model.ObservationCertaintyConfigured
	switch value.State {
	case proxy.StateConfigurationUnavailable:
		state, certainty = model.EnvironmentStateUnknown, model.ObservationCertaintyUnknown
	case proxy.StateUnsupportedPlatform:
		state, certainty = model.EnvironmentStateUnsupported, model.ObservationCertaintyUnsupported
	case proxy.StateMalformedProxyEndpoint:
		state, certainty = model.EnvironmentStatePartial, model.ObservationCertaintyUnknown
	}
	return model.EnvironmentProxySource{Source: source, State: state, Direct: value.Direct, StaticProxyConfigured: value.StaticProxyConfigured, ProxyEndpoints: append([]string(nil), value.ProxyEndpoints...), ProxyBypass: append([]string(nil), value.ProxyBypass...), PACConfigured: value.PACConfigured, PACURL: value.PACURL, AutoDetect: value.AutoDetect, Error: value.Error, Certainty: certainty, Provenance: []string{"proxy:" + source}}
}

func buildVPN(collection Collection, interfaces []model.EnvironmentInterface, routing model.EnvironmentRoutingObservation, snapshot *model.EnvironmentSnapshot) model.EnvironmentVPNObservation {
	result := model.EnvironmentVPNObservation{PresentKnown: collection.InterfacesKnown, RouteParticipationKnown: routing.RouteTableKnown, Certainty: model.ObservationCertaintyObserved, Provenance: []string{"interfacecfg:adapter-classification", "route:default-selection"}}
	for _, value := range interfaces {
		if value.VPN {
			result.Present = true
			if value.Up {
				result.ActiveAdapters = append(result.ActiveAdapters, value.Name)
			}
		}
		if value.Virtual {
			result.VirtualAdapters = append(result.VirtualAdapters, value.Name)
		}
	}
	if !collection.InterfacesKnown {
		result.State, result.Certainty = model.EnvironmentStateUnknown, model.ObservationCertaintyUnknown
	}
	for _, value := range []*model.EnvironmentRoute{routing.DefaultIPv4, routing.DefaultIPv6} {
		if value == nil || (!value.VPNOrTunnel && !value.VirtualAdapter) {
			continue
		}
		family := "ipv6"
		if strings.Contains(value.RoutePrefix, ":") {
			family = "ipv6"
		} else {
			family = "ipv4"
		}
		result.RouteParticipation = append(result.RouteParticipation, family+":"+value.Interface)
	}
	if result.Present && result.RouteParticipationKnown {
		result.State = model.EnvironmentStateObserved
	}
	if result.Present && !result.RouteParticipationKnown {
		result.Limitations = append(result.Limitations, "VPN adapter presence observed; selected route participation is unknown")
	}
	if !result.PresentKnown {
		result.State = model.EnvironmentStateUnknown
	}
	return result
}

func buildFirewall(collection Collection, snapshot *model.EnvironmentSnapshot) model.EnterpriseFirewallObservation {
	value := collection.Firewall
	result := model.EnterpriseFirewallObservation{
		State:          model.EnterpriseObservationStateObserved,
		Available:      value.Available,
		Error:          value.Error,
		Insufficient:   value.Insufficient,
		BlockCausality: model.EnterpriseFirewallCausalityNotEstablished,
		Certainty:      model.ObservationCertaintyObserved,
		Provenance:     []string{"windows-firewall-profile"},
	}
	for _, profile := range value.Profiles {
		result.Profiles = append(result.Profiles, model.EnterpriseFirewallProfileObservation{
			Name: profile.Name, FirewallEnabled: cloneBool(profile.FirewallEnabled),
			BlockInboundExceptions: cloneBool(profile.BlockInboundExceptions),
			PolicyPresent:          profile.PolicyPresent, EffectiveState: firewallState(profile.FirewallEnabled),
			BlockCausality: model.EnterpriseFirewallCausalityNotEstablished,
			Certainty:      model.ObservationCertaintyObserved, Provenance: []string{"windows-firewall-profile"},
		})
	}
	if !collection.FirewallKnown {
		result = model.EnterpriseFirewallObservation{State: model.EnterpriseObservationStateUnknown, BlockCausality: model.EnterpriseFirewallCausalityNotEstablished, Certainty: model.ObservationCertaintyUnknown}
		if collection.EnterpriseUnsupported {
			result.State = model.EnterpriseObservationStateUnsupported
			result.Certainty = model.ObservationCertaintyUnsupported
		}
		if collection.EnterpriseError != "" {
			result.Limitations = append(result.Limitations, collection.EnterpriseError)
		}
		return result
	}
	if result.State == "" {
		result.State = model.EnterpriseObservationStateObserved
	}
	if result.BlockCausality == "" {
		result.BlockCausality = model.EnterpriseFirewallCausalityNotEstablished
	}
	return result
}

func cloneBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func firewallState(value *bool) string {
	if value == nil {
		return string(model.EnterpriseObservationStateUnknown)
	}
	if *value {
		return "enabled"
	}
	return "disabled"
}

func buildTrust(collection Collection, snapshot *model.EnvironmentSnapshot) model.EnvironmentTrustObservation {
	value := collection.TrustStore
	result := model.EnvironmentTrustObservation{Available: value.Available, RootCount: value.RootCount, InsufficientPrivilege: value.Insufficient, Error: value.Error, Certainty: model.ObservationCertaintyObserved, Provenance: []string{"crypto/x509.SystemCertPool"}}
	if !collection.TrustKnown {
		result.State, result.Certainty = model.EnvironmentStateUnknown, model.ObservationCertaintyUnknown
		if collection.EnterpriseUnsupported {
			result.State, result.Certainty = model.EnvironmentStateUnsupported, model.ObservationCertaintyUnsupported
		}
		if collection.EnterpriseError != "" {
			result.Limitations = append(result.Limitations, collection.EnterpriseError)
		}
		return result
	}
	if !value.Available {
		result.State = model.EnvironmentStatePartial
		result.Certainty = model.ObservationCertaintyUnknown
	}
	if value.Insufficient {
		result.State = model.EnvironmentStateUnsupported
		result.Certainty = model.ObservationCertaintyUnsupported
	}
	return result
}

func capabilities(snapshot model.EnvironmentSnapshot) []model.EnvironmentCapability {
	result := []model.EnvironmentCapability{
		{Name: "interfaces", State: capabilityState(snapshot.InterfacesState)},
		{Name: "dns_configuration", State: capabilityState(snapshot.DNS.State)},
		{Name: "route_table", State: capabilityState(snapshot.Routing.State)},
		{Name: "winhttp_proxy", State: capabilityState(snapshot.Proxy.WinHTTP.State), Detail: snapshot.Proxy.WinHTTP.Error},
		{Name: "wininet_proxy", State: capabilityState(snapshot.Proxy.WinINET.State), Detail: snapshot.Proxy.WinINET.Error},
		{Name: "firewall_profile", State: enterpriseCapabilityState(snapshot.Firewall.State), Detail: snapshot.Firewall.Error},
		{Name: "trust_store", State: capabilityState(snapshot.Trust.State), Detail: snapshot.Trust.Error},
	}
	if snapshot.DNS.NRPTError != "" {
		result = append(result, model.EnvironmentCapability{Name: "nrpt", State: model.EnvironmentCapabilityPartial, Detail: snapshot.DNS.NRPTError})
	} else if snapshot.DNS.State == model.EnvironmentStateUnsupported {
		result = append(result, model.EnvironmentCapability{Name: "nrpt", State: model.EnvironmentCapabilityUnsupported})
	} else {
		result = append(result, model.EnvironmentCapability{Name: "nrpt", State: model.EnvironmentCapabilityAvailable})
	}
	return result
}

func capabilityState(state model.EnvironmentObservationState) model.EnvironmentCapabilityState {
	switch state {
	case model.EnvironmentStateObserved, model.EnvironmentStateConfigured, model.EnvironmentStateInferred:
		return model.EnvironmentCapabilityAvailable
	case model.EnvironmentStatePartial, model.EnvironmentStateConflicting:
		return model.EnvironmentCapabilityPartial
	case model.EnvironmentStateUnsupported:
		return model.EnvironmentCapabilityUnsupported
	default:
		return model.EnvironmentCapabilityUnknown
	}
}

func enterpriseCapabilityState(state model.EnterpriseObservationState) model.EnvironmentCapabilityState {
	switch state {
	case model.EnterpriseObservationStateObserved:
		return model.EnvironmentCapabilityAvailable
	case model.EnterpriseObservationStatePartial:
		return model.EnvironmentCapabilityPartial
	case model.EnterpriseObservationStateUnsupported, model.EnterpriseObservationStateUnavailable:
		return model.EnvironmentCapabilityUnsupported
	default:
		return model.EnvironmentCapabilityUnknown
	}
}

func overallState(snapshot model.EnvironmentSnapshot) model.EnvironmentObservationState {
	states := []model.EnvironmentObservationState{snapshot.InterfacesState, snapshot.DNS.State, snapshot.Routing.State, snapshot.Proxy.State, snapshot.VPN.State, snapshot.Trust.State, model.EnvironmentObservationState(snapshot.Firewall.State), snapshot.Runtime.State}
	if len(snapshot.Interfaces) == 0 && snapshot.DNS.State == model.EnvironmentStateUnknown && snapshot.Routing.State == model.EnvironmentStateUnknown && snapshot.Proxy.State == model.EnvironmentStateUnknown {
		return model.EnvironmentStateUnknown
	}
	partial := false
	unsupported := 0
	for _, state := range states {
		switch state {
		case model.EnvironmentStateConflicting:
			return model.EnvironmentStateConflicting
		case model.EnvironmentStatePartial, model.EnvironmentStateUnknown:
			partial = true
		case model.EnvironmentStateUnsupported:
			unsupported++
		}
	}
	if partial {
		return model.EnvironmentStatePartial
	}
	if len(snapshot.Limitations) > 0 {
		return model.EnvironmentStatePartial
	}
	if unsupported == len(states) {
		return model.EnvironmentStateUnsupported
	}
	return model.EnvironmentStateObserved
}

func canonicalRoute(value route.Route, selected bool) model.EnvironmentRoute {
	nextHop := "on-link"
	gateway := normalizedAddress(value.Gateway)
	if gateway != "" {
		nextHop = gateway
	}
	return model.EnvironmentRoute{RoutePrefix: value.Destination.String(), Gateway: gateway, NextHop: nextHop, Interface: value.Interface, InterfaceIndex: value.InterfaceIndex, SourceAddress: normalizedAddress(value.Source), Metric: value.Metric, InterfaceType: value.InterfaceType, VPNOrTunnel: value.VPNOrTunnel, VirtualAdapter: value.VirtualAdapter, Selected: selected}
}

func markSelectedRoute(routes []model.EnvironmentRoute, selected model.EnvironmentRoute) {
	for index := range routes {
		if environmentRouteEqual(routes[index], selected) {
			routes[index].Selected = true
		}
	}
}

func environmentRouteEqual(left, right model.EnvironmentRoute) bool {
	return left.RoutePrefix == right.RoutePrefix && left.Gateway == right.Gateway && left.Interface == right.Interface && left.InterfaceIndex == right.InterfaceIndex && left.Metric == right.Metric
}

func boundedRoutes(values []route.Route) []route.Route {
	result := append([]route.Route(nil), values...)
	sort.SliceStable(result, func(i, j int) bool {
		left, right := result[i], result[j]
		if left.Destination.String() != right.Destination.String() {
			return left.Destination.String() < right.Destination.String()
		}
		if left.Metric != right.Metric {
			return left.Metric < right.Metric
		}
		if left.InterfaceIndex != right.InterfaceIndex {
			return left.InterfaceIndex < right.InterfaceIndex
		}
		return left.Interface < right.Interface
	})
	if len(result) > maxRoutes {
		result = result[:maxRoutes]
	}
	return result
}

func addressesToStrings(values []netip.Addr) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value.IsValid() {
			result = append(result, value.Unmap().String())
		}
	}
	return result
}

func normalizedAddress(value netip.Addr) string {
	if !value.IsValid() || value.IsUnspecified() {
		return ""
	}
	return value.Unmap().String()
}

func sameProxy(left, right model.EnvironmentProxySource) bool {
	return left.State == right.State && left.Direct == right.Direct && left.StaticProxyConfigured == right.StaticProxyConfigured && left.PACConfigured == right.PACConfigured && left.PACURL == right.PACURL && left.AutoDetect == right.AutoDetect && equalStrings(left.ProxyEndpoints, right.ProxyEndpoints) && equalStrings(left.ProxyBypass, right.ProxyBypass)
}

func proxyFingerprint(value model.EnvironmentProxySource) string {
	encoded, err := json.Marshal(struct {
		State     string   `json:"state"`
		Direct    bool     `json:"direct"`
		Endpoints []string `json:"endpoints"`
		Bypass    []string `json:"bypass"`
		PAC       bool     `json:"pac"`
		PACURL    string   `json:"pac_url"`
		Auto      bool     `json:"auto"`
	}{string(value.State), value.Direct, value.ProxyEndpoints, value.ProxyBypass, value.PACConfigured, value.PACURL, value.AutoDetect})
	if err != nil {
		return string(value.State)
	}
	return string(encoded)
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func nonEmpty(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func valueSource(collection Collection) string {
	if len(collection.Provenance) > 0 {
		return collection.Provenance[0]
	}
	return "interface-state"
}

func issueLabel(issue enterprise.ObservationIssue) string {
	value := strings.TrimSpace(issue.Subsystem + ": " + issue.Kind)
	if issue.Error != "" {
		value += ": " + safeError(errors.New(issue.Error))
	}
	return value
}

func safeError(err error) string {
	if err == nil {
		return ""
	}
	value := strings.TrimSpace(err.Error())
	if len(value) > 256 {
		return value[:256]
	}
	return value
}

func appendUnique(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	for _, current := range values {
		if current == value {
			return values
		}
	}
	return append(values, value)
}

// BuildFromProbeResults reuses the canonical evidence produced by a normal
// target diagnosis. It intentionally projects only target-independent lanes;
// target route, effective proxy use, and paired certificates are excluded.
func BuildFromProbeResults(probes []model.ProbeResult, capturedAt time.Time) *model.EnvironmentSnapshot {
	if capturedAt.IsZero() {
		capturedAt = earliestProbeTime(probes)
	}
	collection := Collection{}
	var dnsSeen, interfaceSeen, routeSeen, proxySeen, firewallSeen, trustSeen bool
	for _, probe := range probes {
		for _, evidence := range probe.Evidence {
			collection.EvidenceIDs = appendUnique(collection.EvidenceIDs, evidence.ID)
			collection.Provenance = appendUnique(collection.Provenance, evidence.Source)
			switch evidence.Kind {
			case model.EvidenceKindInterfaceState:
				var interfaces []interfacecfg.InterfaceState
				if err := json.Unmarshal(evidence.Raw, &interfaces); err == nil {
					collection.Interfaces = append([]interfacecfg.InterfaceState(nil), interfaces...)
					collection.InterfacesKnown, interfaceSeen = true, true
				}
			case model.EvidenceKindDNSConfiguration:
				var value struct {
					Servers    []netip.Addr                     `json:"servers"`
					Interfaces []interfacecfg.InterfaceState    `json:"interfaces"`
					Suffixes   []string                         `json:"suffixes"`
					SearchList []string                         `json:"search_list"`
					NRPT       []model.NameResolutionPolicyRule `json:"nrpt"`
					NRPTError  string                           `json:"nrpt_error"`
					Hosts      []model.NameResolutionHostEntry  `json:"hosts_file_entries"`
					HostsError string                           `json:"hosts_file_error"`
					Error      string                           `json:"error"`
				}
				if err := json.Unmarshal(evidence.Raw, &value); err == nil {
					collection.DNS.DNSServers = value.Servers
					collection.DNS.Interfaces = value.Interfaces
					if !interfaceSeen && len(value.Interfaces) > 0 {
						collection.Interfaces = append([]interfacecfg.InterfaceState(nil), value.Interfaces...)
						collection.InterfacesKnown, interfaceSeen = true, true
					}
					collection.DNS.DNSSuffixes = value.Suffixes
					collection.DNS.SearchList = value.SearchList
					collection.DNS.NRPT = value.NRPT
					collection.DNS.NRPTError = value.NRPTError
					collection.DNS.HostsFileEntries = value.Hosts
					collection.DNS.HostsFileError = value.HostsError
					collection.DNS.ResolverError = value.Error
					collection.DNSKnown, dnsSeen = true, true
				}
			case model.EvidenceKindRoute:
				observation, err := route.DecodeRouteEvidence(evidence)
				if err == nil && observation.RouteType == "default" {
					if prefix, parseErr := netip.ParsePrefix(observation.RoutePrefix); parseErr == nil {
						value := route.Route{Destination: prefix, Interface: observation.Interface, InterfaceIndex: observation.InterfaceIndex, Metric: observation.Metric, InterfaceType: observation.InterfaceType, VPNOrTunnel: observation.VPNOrTunnel, VirtualAdapter: observation.VirtualAdapter}
						if address, parseErr := netip.ParseAddr(observation.Gateway); parseErr == nil {
							value.Gateway = address
						}
						if address, parseErr := netip.ParseAddr(observation.SourceAddress); parseErr == nil {
							value.Source = address
						}
						collection.Routes = append(collection.Routes, value)
						collection.RoutesKnown, routeSeen = true, true
					}
				}
			case model.EvidenceKindWinHTTPProxy, model.EvidenceKindProxyConfiguration:
				var value proxy.ConfigurationObservation
				if err := json.Unmarshal(evidence.Raw, &value); err == nil && (evidence.Kind == model.EvidenceKindWinHTTPProxy || value.State != "") {
					if evidence.Kind == model.EvidenceKindWinHTTPProxy || strings.Contains(strings.ToLower(evidence.ID), "winhttp") {
						collection.WinHTTP = value
						collection.WinHTTPKnown, proxySeen = true, true
					}
				}
			case model.EvidenceKindWinINETProxy:
				var value proxy.ConfigurationObservation
				if err := json.Unmarshal(evidence.Raw, &value); err == nil {
					collection.WinINET = value
					collection.WinINETKnown, proxySeen = true, true
				}
			case model.EvidenceKindFirewallProfile:
				var value enterprise.FirewallObservation
				if err := json.Unmarshal(evidence.Raw, &value); err == nil {
					collection.Firewall = value
					collection.FirewallKnown, firewallSeen = true, true
				}
			case model.EvidenceKindTLSTrust:
				var value struct {
					TrustStore enterprise.TrustStoreObservation `json:"trust_store"`
				}
				if err := json.Unmarshal(evidence.Raw, &value); err == nil {
					collection.TrustStore = value.TrustStore
					collection.TrustKnown, trustSeen = true, true
				}
			}
		}
		if probe.Interpretation.FailureReason == model.FailureReasonUnsupported {
			collection.Limitations = appendUnique(collection.Limitations, probe.Name+": unsupported")
			switch probe.Name {
			case interfacecfg.InterfaceProbeName:
				collection.InterfacesUnsupported = true
			case interfacecfg.DNSProbeName:
				collection.DNSUnsupported = true
			case proxy.Name:
				collection.ProxyUnsupported = true
			}
		}
	}
	_ = dnsSeen
	_ = interfaceSeen
	_ = routeSeen
	_ = proxySeen
	_ = firewallSeen
	_ = trustSeen
	collection.InterfacesKnown = interfaceSeen
	collection.DNSKnown = dnsSeen
	collection.RoutesKnown = routeSeen
	if !proxySeen {
		collection.ProxyUnsupported = hasProbeFailure(probes, "proxy")
	}
	return snapshotPointer(Build(collection, capturedAt))
}

func earliestProbeTime(probes []model.ProbeResult) time.Time {
	var earliest time.Time
	for _, probe := range probes {
		if probe.Timing.StartedAt != nil && (earliest.IsZero() || probe.Timing.StartedAt.Before(earliest)) {
			earliest = *probe.Timing.StartedAt
		}
		for _, evidence := range probe.Evidence {
			if evidence.CapturedAt != nil && (earliest.IsZero() || evidence.CapturedAt.Before(earliest)) {
				earliest = *evidence.CapturedAt
			}
		}
	}
	return earliest
}

func snapshotPointer(value model.EnvironmentSnapshot) *model.EnvironmentSnapshot { return &value }

func hasProbeFailure(probes []model.ProbeResult, part string) bool {
	for _, probe := range probes {
		if strings.Contains(strings.ToLower(probe.Name), part) && probe.Interpretation.FailureReason == model.FailureReasonUnsupported {
			return true
		}
	}
	return false
}
