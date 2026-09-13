package dns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/yohnark/tadori/internal/model"
	"github.com/yohnark/tadori/internal/probe"
)

const (
	defaultLookupTimeout = 5 * time.Second
	probeName            = "dns"
)

// Resolver is the portion of net.Resolver used by Probe. Keeping this
// interface local makes DNS behavior straightforward to test with a fake.
type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

// ResolverConfigProvider reports resolver addresses known to the host. The
// addresses are evidence, not an instruction to use a public resolver. A
// provider may return no addresses when configuration is unavailable.
type ResolverConfigProvider interface {
	ResolverAddresses(context.Context) ([]string, error)
}

// ResolverConfigFunc adapts a function into a ResolverConfigProvider.
type ResolverConfigFunc func(context.Context) ([]string, error)

// ResolverAddresses implements ResolverConfigProvider.
func (f ResolverConfigFunc) ResolverAddresses(ctx context.Context) ([]string, error) {
	return f(ctx)
}

// StaticResolverConfig is a deterministic resolver configuration source,
// useful for callers and tests that already have resolver addresses.
type StaticResolverConfig []string

// ResolverAddresses implements ResolverConfigProvider.
func (s StaticResolverConfig) ResolverAddresses(context.Context) ([]string, error) {
	return append([]string(nil), s...), nil
}

// ResolutionInterface is the DNS-relevant portion of one host interface.
// Its servers and suffixes are configuration candidates; they are not an
// assertion about the path selected for a particular query.
type ResolutionInterface struct {
	Index          int      `json:"index"`
	Name           string   `json:"name"`
	Up             bool     `json:"up"`
	Loopback       bool     `json:"loopback"`
	VirtualAdapter bool     `json:"virtual_adapter,omitempty"`
	VPN            bool     `json:"vpn,omitempty"`
	DNSServers     []string `json:"dns_servers,omitempty"`
	DNSSuffix      string   `json:"dns_suffix,omitempty"`
	DNSSearchList  []string `json:"dns_search_list,omitempty"`
}

// ResolutionEnvironment contains host state used to assemble a normalized
// name-resolution observation. It is an adapter boundary, not a second target
// representation.
type ResolutionEnvironment struct {
	Interfaces        []ResolutionInterface            `json:"interfaces,omitempty"`
	CandidateSuffixes []string                         `json:"candidate_suffixes,omitempty"`
	SearchList        []string                         `json:"search_list,omitempty"`
	NRPT              []model.NameResolutionPolicyRule `json:"nrpt,omitempty"`
	HostsFileEntries  []model.NameResolutionHostEntry  `json:"hosts_file_entries,omitempty"`
	Source            string                           `json:"source,omitempty"`
	Error             string                           `json:"error,omitempty"`
	ResolverError     string                           `json:"resolver_error,omitempty"`
	PolicyError       string                           `json:"policy_error,omitempty"`
	HostsFileError    string                           `json:"hosts_file_error,omitempty"`
}

// EnvironmentProvider supplies native host state relevant to name
// resolution. Windows supplies this through interfacecfg's native snapshot;
// tests can use a deterministic fixture provider.
type EnvironmentProvider interface {
	ResolutionEnvironment(context.Context) (ResolutionEnvironment, error)
}

// EffectivePathProvider can report additional provenance that a resolver API
// actually exposes. A provider may leave resolver/interface fields empty when
// the underlying operating system does not expose those selections.
type EffectivePathProvider interface {
	EffectivePath(context.Context, string) (model.NameResolutionPath, error)
}

// EnvironmentProviderFunc adapts a function to EnvironmentProvider.
type EnvironmentProviderFunc func(context.Context) (ResolutionEnvironment, error)

func (f EnvironmentProviderFunc) ResolutionEnvironment(ctx context.Context) (ResolutionEnvironment, error) {
	return f(ctx)
}

// Probe collects resolver configuration and A/AAAA observations for a target.
// It implements probe.Probe.
type Probe struct {
	resolver       Resolver
	config         ResolverConfigProvider
	environment    EnvironmentProvider
	timeout        time.Duration
	now            func() time.Time
	resolverSet    bool
	configSet      bool
	environmentSet bool
}

// DNSProbe is an expressive alias for Probe.
type DNSProbe = Probe

// Option configures a DNS Probe.
type Option func(*Probe)

// New constructs a DNS probe using the platform resolver and host
// configuration adapters. Lookup time is bounded to five seconds by default.
func New(opts ...Option) *Probe {
	p := &Probe{
		resolver:    newSystemResolver(),
		config:      SystemResolverConfig{},
		environment: newSystemEnvironmentProvider(),
		timeout:     defaultLookupTimeout,
		now:         time.Now,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(p)
		}
	}
	if p.resolver == nil {
		p.resolver = newSystemResolver()
	}
	if p.config == nil {
		p.config = SystemResolverConfig{}
	}
	if p.timeout <= 0 {
		p.timeout = defaultLookupTimeout
	}
	if p.now == nil {
		p.now = time.Now
	}
	return p
}

// NewProbe is a descriptive synonym for New.
func NewProbe(opts ...Option) *Probe { return New(opts...) }

// NewWithResolver constructs a probe with a supplied resolver. The supplied
// resolver is considered usable even when host resolver configuration cannot
// be read, which is useful for embedded resolvers and tests.
func NewWithResolver(resolver Resolver, opts ...Option) *Probe {
	p := New(opts...)
	p.resolver = resolver
	p.resolverSet = true
	return p
}

// WithResolver supplies the resolver implementation used for A and AAAA
// lookups.
func WithResolver(resolver Resolver) Option {
	return func(p *Probe) {
		p.resolver = resolver
		p.resolverSet = resolver != nil
	}
}

// WithLookupTimeout bounds configuration reads and the complete A/AAAA lookup
// operation. A non-positive timeout is ignored.
func WithLookupTimeout(timeout time.Duration) Option {
	return func(p *Probe) {
		if timeout > 0 {
			p.timeout = timeout
		}
	}
}

// WithTimeout is a short synonym for WithLookupTimeout.
func WithTimeout(timeout time.Duration) Option { return WithLookupTimeout(timeout) }

// WithNow replaces the clock used for result timing. It is primarily useful
// for deterministic tests.
func WithNow(now func() time.Time) Option {
	return func(p *Probe) {
		if now != nil {
			p.now = now
		}
	}
}

// WithEnvironmentProvider supplies deterministic or embedded host state for
// path assembly. A nil provider disables environment collection.
func WithEnvironmentProvider(provider EnvironmentProvider) Option {
	return func(p *Probe) {
		p.environment = provider
		p.environmentSet = true
	}
}

// WithResolutionEnvironment is a function-oriented synonym for
// WithEnvironmentProvider.
func WithResolutionEnvironment(provider func(context.Context) (ResolutionEnvironment, error)) Option {
	return WithEnvironmentProvider(EnvironmentProviderFunc(provider))
}

// WithResolverConfig supplies a resolver configuration source. In addition to
// ResolverConfigProvider, this accepts the common Nameservers method shape so
// small fakes do not need an adapter:
//
//	Nameservers(context.Context) ([]string, error)
//	Nameservers() ([]string, error)
//	ResolverAddresses() ([]string, error)
//
// Unsupported values are retained as a configuration error and are surfaced
// in evidence rather than silently falling back to a public resolver.
func WithResolverConfig(source any) Option {
	return func(p *Probe) {
		p.configSet = true
		p.config = adaptResolverConfig(source)
	}
}

// WithConfigProvider is a synonym for WithResolverConfig.
func WithConfigProvider(source any) Option { return WithResolverConfig(source) }

// WithResolverAddresses supplies configured nameservers directly and uses
// those nameservers for lookups. No implicit public resolver is introduced.
func WithResolverAddresses(addresses ...string) Option {
	return func(p *Probe) {
		p.configSet = true
		p.config = StaticResolverConfig(addresses)
		p.resolver = resolverForAddresses(addresses)
		p.resolverSet = true
	}
}

// WithNameservers is a synonym for WithResolverAddresses.
func WithNameservers(addresses ...string) Option { return WithResolverAddresses(addresses...) }

// WithConfiguredResolvers is the slice-taking form of WithResolverAddresses.
// It is convenient when resolver addresses come from another structured
// configuration value.
func WithConfiguredResolvers(addresses []string) Option {
	return WithResolverAddresses(addresses...)
}

// Name implements probe.Probe.
func (p *Probe) Name() string { return probeName }

var _ probe.Probe = (*Probe)(nil)

// Run executes a bounded DNS configuration and A/AAAA lookup. Configuration
// and resolution observations are always kept as separate evidence records.
func (p *Probe) Run(ctx context.Context, execution probe.ExecutionContext) model.ProbeResult {
	started := p.clockNow()
	target := model.NormalizeTarget(execution.Target)
	result := model.ProbeResult{
		Name:   probeName,
		Target: target,
		Status: model.ProbeStatusError,
		Interpretation: model.ProbeInterpretation{
			FailureReason: model.FailureReasonProbeExecution,
			Layer:         model.LayerDNS,
			FaultDomain:   model.FaultDomainDNS,
		},
	}

	finish := func() model.ProbeResult {
		completed := p.clockNow()
		result.Timing.StartedAt = timePtr(started)
		result.Timing.CompletedAt = timePtr(completed)
		result.Timing.DurationMS = completed.Sub(started).Milliseconds()
		if result.Timing.DurationMS < 0 {
			result.Timing.DurationMS = 0
		}
		return result
	}

	host, err := targetHost(execution.Target)
	if err != nil {
		result.Evidence = append(result.Evidence, makeResolutionEvidence("", nil, nil, nil, err, "malformed_target"))
		return finish()
	}
	if target.LiteralIP != "" {
		resolution := resolutionEvidence{Host: host}
		if address, parseErr := netip.ParseAddr(target.LiteralIP); parseErr == nil {
			if address.Is4() {
				resolution.A = []string{target.LiteralIP}
			} else {
				resolution.AAAA = []string{target.LiteralIP}
			}
		}
		result.Status = model.ProbeStatusPassed
		result.Interpretation = model.ProbeInterpretation{
			FailureReason: model.FailureReasonNone,
			Layer:         model.LayerDNS,
			FaultDomain:   model.FaultDomainDNS,
		}
		result.Evidence = append(result.Evidence, model.Evidence{
			ID: "dns-resolution", Kind: model.EvidenceKindDNSResolution, Source: "canonical-literal",
			Raw: mustJSON(resolution),
		})
		result.NameResolution = literalNameResolution(target, host)
		return finish()
	}

	lookupCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	environment, environmentErr := p.environmentBounded(lookupCtx)
	if environmentErr != nil && !errors.Is(environmentErr, context.Canceled) && !errors.Is(environmentErr, context.DeadlineExceeded) {
		// Environment collection is supporting context. Preserve the error in
		// configuration evidence while allowing the resolver lane to make its
		// own observation. Do not overwrite a native source label.
		if environment.Error == "" {
			environment.Error = environmentErr.Error()
		}
		if environment.Source == "" {
			environment.Source = "environment-error"
		}
	}
	addresses, configErr := p.configAddressesBounded(lookupCtx)
	configEvidence := resolverConfigEvidence(addresses, configErr, p.configSource(), environment)
	result.Evidence = append(result.Evidence, configEvidence)
	if configErr != nil {
		kind := errorKind(configErr)
		if kind == "timeout" {
			result.Interpretation.FailureReason = model.FailureReasonDNSTimeout
			result.Status = model.ProbeStatusFailed
		} else {
			result.Interpretation.FailureReason = model.FailureReasonDNSResolverFailure
			result.Status = model.ProbeStatusError
		}
		result.Evidence = append(result.Evidence, makeResolutionEvidence(host, nil, nil, nil, configErr, kind))
		result.NameResolution = buildNameResolution(lookupCtx, host, addresses, environment, p.resolver, lookupResult{}, configErr, result.Evidence)
		return finish()
	}
	if err := lookupCtx.Err(); err != nil {
		result.Interpretation.FailureReason = contextReason(err)
		result.Status = model.ProbeStatusFailed
		result.Evidence = append(result.Evidence, makeResolutionEvidence(host, nil, nil, nil, err, errorKind(err)))
		result.NameResolution = buildNameResolution(lookupCtx, host, addresses, environment, p.resolver, lookupResult{}, err, result.Evidence)
		return finish()
	}
	if len(addresses) == 0 && (!p.resolverSet || p.configSet) {
		// The existing #2 contract has no dedicated no-configured-resolver
		// reason. Keep the exact distinction in evidence and use its DNS
		// resolver-failure umbrella for machine interpretation.
		err = errNoConfiguredResolver
		result.Interpretation.FailureReason = model.FailureReasonDNSResolverFailure
		result.Status = model.ProbeStatusError
		result.Evidence = append(result.Evidence, makeResolutionEvidence(host, nil, nil, nil, err, "no_configured_resolver"))
		result.NameResolution = buildNameResolution(lookupCtx, host, addresses, environment, p.resolver, lookupResult{}, err, result.Evidence)
		return finish()
	}

	resolution, lookupErr := p.lookupHostBounded(lookupCtx, host)
	if lookupErr != nil {
		result.Interpretation.FailureReason = contextReason(lookupErr)
		result.Status = model.ProbeStatusFailed
		result.Evidence = append(result.Evidence, makeResolutionEvidence(host, nil, nil, addresses, lookupErr, errorKind(lookupErr)))
		result.NameResolution = buildNameResolution(lookupCtx, host, addresses, environment, p.resolver, resolution, lookupErr, result.Evidence)
		return finish()
	}
	result.Evidence = append(result.Evidence, makeResolutionEvidence(host, resolution.a, resolution.aaaa, addresses, nil, ""))
	result.Evidence[len(result.Evidence)-1].Raw = mustJSON(resolutionEvidence{
		Host:      host,
		Resolvers: append([]string(nil), addresses...),
		A:         append([]string(nil), resolution.a...),
		AAAA:      append([]string(nil), resolution.aaaa...),
		Results:   resolution.results,
	})

	result.Status, result.Interpretation.FailureReason = resolutionStatus(resolution)
	result.NameResolution = buildNameResolution(lookupCtx, host, addresses, environment, p.resolver, resolution, nil, result.Evidence)
	return finish()
}

type lookupResult struct {
	a, aaaa        []string
	selected       string
	selectedFamily string
	results        []familyResult
	failures       []lookupFailure
}

type lookupFailure struct {
	family string
	err    error
	kind   string
}

// DNSFamilyResult records one A or AAAA lookup, including a family-specific
// error when that family could not be queried.
type DNSFamilyResult struct {
	Family    string   `json:"family"`
	Addresses []string `json:"addresses,omitempty"`
	Error     string   `json:"error,omitempty"`
	ErrorKind string   `json:"error_kind,omitempty"`
}

// DNSResolutionEvidence is the structured raw observation emitted for DNS
// lookups. Addresses are strings in presentation-neutral IP notation.
type DNSResolutionEvidence struct {
	Host      string            `json:"host"`
	Resolvers []string          `json:"resolvers,omitempty"`
	A         []string          `json:"a,omitempty"`
	AAAA      []string          `json:"aaaa,omitempty"`
	Results   []DNSFamilyResult `json:"results"`
}

// DNSConfigurationEvidence is the structured raw observation emitted for
// resolver configuration.
type DNSConfigurationEvidence struct {
	Configured  bool                   `json:"configured"`
	Resolvers   []string               `json:"resolvers,omitempty"`
	Source      string                 `json:"source,omitempty"`
	Environment *ResolutionEnvironment `json:"environment,omitempty"`
	Error       string                 `json:"error,omitempty"`
	ErrorKind   string                 `json:"error_kind,omitempty"`
}

type familyResult = DNSFamilyResult
type resolutionEvidence = DNSResolutionEvidence

func (p *Probe) lookupHost(ctx context.Context, host string) lookupResult {
	var out lookupResult
	for _, family := range []struct {
		network string
		name    string
	}{
		{network: "ip4", name: "A"},
		{network: "ip6", name: "AAAA"},
	} {
		addrs, err := p.resolver.LookupNetIP(ctx, family.network, host)
		converted := make([]string, 0, len(addrs))
		for _, addr := range addrs {
			converted = append(converted, model.NormalizeAddr(addr).String())
		}
		fr := familyResult{Family: family.name, Addresses: converted}
		if err != nil {
			kind := errorKind(err)
			fr.Error = err.Error()
			fr.ErrorKind = kind
			out.failures = append(out.failures, lookupFailure{family: family.name, err: err, kind: kind})
		}
		out.results = append(out.results, fr)
		if family.name == "A" {
			out.a = converted
		} else {
			out.aaaa = converted
		}
		if out.selected == "" && len(converted) != 0 {
			out.selected = converted[0]
			out.selectedFamily = family.name
		}
	}
	return out
}

// lookupHostBounded protects the probe from a resolver implementation that
// does not promptly honor cancellation. The channel is buffered so such an
// implementation can finish later without blocking a goroutine forever.
func (p *Probe) lookupHostBounded(ctx context.Context, host string) (lookupResult, error) {
	result := make(chan lookupResult, 1)
	go func() { result <- p.lookupHost(ctx, host) }()
	select {
	case lookup := <-result:
		return lookup, nil
	case <-ctx.Done():
		return lookupResult{}, ctx.Err()
	}
}

func resolutionStatus(r lookupResult) (model.ProbeStatus, model.FailureReason) {
	if len(r.failures) == 0 {
		if len(r.a) == 0 && len(r.aaaa) == 0 {
			return model.ProbeStatusFailed, model.FailureReasonDNSNoAnswer
		}
		return model.ProbeStatusPassed, model.FailureReasonNone
	}
	for _, failure := range r.failures {
		if failure.kind == "timeout" {
			return model.ProbeStatusFailed, model.FailureReasonDNSTimeout
		}
	}
	// A name-not-found result for one address family is normal when the other
	// family has answers. Only report NXDOMAIN when no address was returned.
	allNotFound := true
	allNoAnswer := true
	for _, failure := range r.failures {
		if failure.kind != "not_found" {
			allNotFound = false
		}
		if failure.kind != "no_answer" {
			allNoAnswer = false
		}
	}
	if len(r.a) == 0 && len(r.aaaa) == 0 && allNotFound {
		return model.ProbeStatusFailed, model.FailureReasonDNSNXDomain
	}
	if len(r.a) == 0 && len(r.aaaa) == 0 && allNoAnswer {
		return model.ProbeStatusFailed, model.FailureReasonDNSNoAnswer
	}
	negativeOnly := true
	for _, failure := range r.failures {
		if failure.kind != "not_found" && failure.kind != "no_answer" {
			negativeOnly = false
		}
	}
	if len(r.a) == 0 && len(r.aaaa) == 0 && negativeOnly {
		return model.ProbeStatusFailed, model.FailureReasonDNSNoAnswer
	}
	for _, failure := range r.failures {
		if failure.kind != "not_found" && failure.kind != "no_answer" {
			return model.ProbeStatusFailed, model.FailureReasonDNSResolverFailure
		}
	}
	if len(r.a) == 0 && len(r.aaaa) == 0 {
		return model.ProbeStatusFailed, model.FailureReasonDNSNoAnswer
	}
	return model.ProbeStatusPassed, model.FailureReasonNone
}

func targetHost(target model.Target) (string, error) {
	target = model.NormalizeTarget(target)
	if err := target.Validate(); err != nil {
		return "", fmt.Errorf("malformed target: %w", err)
	}
	host := strings.TrimSpace(target.RequestedIdentity)
	if host == "" {
		return "", errors.New("malformed target: identity is empty")
	}
	return host, nil
}

func (p *Probe) configAddresses(ctx context.Context) ([]string, error) {
	if p.config == nil {
		return nil, nil
	}
	addresses, err := p.config.ResolverAddresses(ctx)
	return normalizeResolverAddresses(addresses), err
}

// configAddressesBounded applies the same deadline guarantee to a custom
// configuration provider as lookupHostBounded does to a resolver.
func (p *Probe) configAddressesBounded(ctx context.Context) ([]string, error) {
	type configResult struct {
		addresses []string
		err       error
	}
	result := make(chan configResult, 1)
	go func() {
		addresses, err := p.configAddresses(ctx)
		result <- configResult{addresses: addresses, err: err}
	}()
	select {
	case value := <-result:
		return value.addresses, value.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (p *Probe) environmentBounded(ctx context.Context) (ResolutionEnvironment, error) {
	if p.environment == nil || (!p.environmentSet && (p.configSet || p.resolverSet)) {
		return ResolutionEnvironment{}, nil
	}
	type environmentResult struct {
		environment ResolutionEnvironment
		err         error
	}
	result := make(chan environmentResult, 1)
	go func() {
		environment, err := p.environment.ResolutionEnvironment(ctx)
		result <- environmentResult{environment: environment, err: err}
	}()
	select {
	case value := <-result:
		return value.environment, value.err
	case <-ctx.Done():
		return ResolutionEnvironment{}, ctx.Err()
	}
}

func (p *Probe) configSource() string {
	if source, ok := p.config.(interface{ Source() string }); ok {
		return source.Source()
	}
	return "configured"
}

func (p *Probe) clockNow() time.Time {
	if p == nil || p.now == nil {
		return time.Now()
	}
	return p.now()
}

func makeResolutionEvidence(host string, a, aaaa, resolvers []string, err error, kind string) model.Evidence {
	value := resolutionEvidence{Host: host, Resolvers: append([]string(nil), resolvers...), A: append([]string(nil), a...), AAAA: append([]string(nil), aaaa...)}
	if err != nil {
		value.Results = []familyResult{{Family: "lookup", Error: err.Error(), ErrorKind: kind}}
	}
	return model.Evidence{ID: "dns/resolution", Kind: model.EvidenceKindDNSResolution, Source: systemResolutionSource(), Raw: mustJSON(value)}
}

func resolverConfigEvidence(addresses []string, err error, source string, environment ResolutionEnvironment) model.Evidence {
	value := DNSConfigurationEvidence{Configured: len(addresses) > 0, Resolvers: append([]string(nil), addresses...), Source: source}
	if len(environment.Interfaces) != 0 || len(environment.CandidateSuffixes) != 0 || len(environment.SearchList) != 0 || len(environment.NRPT) != 0 || len(environment.HostsFileEntries) != 0 || environment.Source != "" || environment.Error != "" || environment.ResolverError != "" || environment.PolicyError != "" || environment.HostsFileError != "" {
		value.Environment = &environment
	}
	if err != nil {
		value.Error = err.Error()
		value.ErrorKind = "configuration_failure"
	} else if len(addresses) == 0 {
		value.ErrorKind = "no_configured_resolver"
	}
	return model.Evidence{ID: "dns/configuration", Kind: model.EvidenceKindDNSConfiguration, Source: source, Raw: mustJSON(value)}
}

func literalNameResolution(target model.Target, host string) *model.NameResolutionObservation {
	observation := model.NameResolutionObservation{
		RequestedName: host,
		EffectivePath: &model.NameResolutionPath{
			State:       model.NameResolutionPathEffective,
			Mechanism:   model.NameResolutionMechanismLiteralIP,
			Certainty:   model.NameResolutionCertaintyObserved,
			Provenance:  "canonical target literal; DNS was skipped",
			EvidenceIDs: []string{"dns-resolution"},
		},
		EvidenceIDs: []string{"dns-resolution"},
	}
	if address, err := netip.ParseAddr(target.LiteralIP); err == nil {
		address = model.NormalizeAddr(address)
		if address.Is4() {
			observation.A = []string{address.String()}
			observation.SelectedFamily = "A"
		} else {
			observation.AAAA = []string{address.String()}
			observation.SelectedFamily = "AAAA"
		}
		observation.SelectedAddress = address.String()
		observation.EffectivePath.A = append([]string(nil), observation.A...)
		observation.EffectivePath.AAAA = append([]string(nil), observation.AAAA...)
	}
	normalized := model.NormalizeNameResolutionObservation(observation)
	return &normalized
}

func buildNameResolution(ctx context.Context, host string, configured []string, environment ResolutionEnvironment, resolver Resolver, resolution lookupResult, lookupErr error, evidence []model.Evidence) *model.NameResolutionObservation {
	observation := model.NameResolutionObservation{
		RequestedName:     host,
		CandidateSuffixes: append([]string(nil), environment.CandidateSuffixes...),
		EvidenceIDs:       evidenceIDs(evidence),
	}
	if environment.Error != "" {
		observation.Limitations = append(observation.Limitations, "name-resolution environment: "+environment.Error)
	}
	if environment.ResolverError != "" {
		observation.Limitations = append(observation.Limitations, "configured resolver state: "+environment.ResolverError)
	}
	if environment.PolicyError != "" {
		observation.Limitations = append(observation.Limitations, "NRPT policy: "+environment.PolicyError)
	}
	if environment.HostsFileError != "" {
		observation.Limitations = append(observation.Limitations, "hosts file: "+environment.HostsFileError)
	}
	if lookupErr != nil {
		observation.Limitations = append(observation.Limitations, "resolution attempt: "+lookupErr.Error())
	}
	for _, failure := range resolution.failures {
		if failure.err != nil {
			observation.Limitations = append(observation.Limitations, failure.family+" lookup: "+failure.err.Error())
		}
	}
	for _, suffix := range environment.SearchList {
		observation.CandidateSuffixes = appendUniqueName(observation.CandidateSuffixes, suffix)
	}
	for _, iface := range environment.Interfaces {
		observation.CandidateSuffixes = appendUniqueName(observation.CandidateSuffixes, iface.DNSSuffix)
		for _, suffix := range iface.DNSSearchList {
			observation.CandidateSuffixes = appendUniqueName(observation.CandidateSuffixes, suffix)
		}
	}
	observation.CandidateNamespaces = append([]string(nil), observation.CandidateSuffixes...)
	observation.CandidateNames = candidateNames(host, observation.CandidateSuffixes)

	configuredPathResolvers := make(map[string]struct{})
	for _, iface := range environment.Interfaces {
		for _, server := range iface.DNSServers {
			server = normalizeResolverValue(server)
			if server == "" {
				continue
			}
			configuredPathResolvers[server] = struct{}{}
			namespaces := make([]string, 0, len(iface.DNSSearchList)+1)
			namespaces = appendUniqueName(namespaces, iface.DNSSuffix)
			for _, suffix := range iface.DNSSearchList {
				namespaces = appendUniqueName(namespaces, suffix)
			}
			path := model.NameResolutionPath{
				State:          model.NameResolutionPathConfiguredCandidate,
				Mechanism:      model.NameResolutionMechanismDNS,
				Resolver:       server,
				Interface:      iface.Name,
				InterfaceIndex: iface.Index,
				VirtualAdapter: iface.VirtualAdapter,
				VPN:            iface.VPN,
				Namespaces:     namespaces,
				Certainty:      model.NameResolutionCertaintyConfigured,
				Provenance:     "interface-specific DNS configuration; not proof of query selection",
				EvidenceIDs:    []string{"dns/configuration"},
			}
			observation.Paths = append(observation.Paths, path)
		}
	}
	for _, server := range configured {
		server = normalizeResolverValue(server)
		if server == "" {
			continue
		}
		if _, exists := configuredPathResolvers[server]; exists {
			continue
		}
		observation.Paths = append(observation.Paths, model.NameResolutionPath{
			State:       model.NameResolutionPathConfiguredCandidate,
			Mechanism:   model.NameResolutionMechanismDNS,
			Resolver:    server,
			Certainty:   model.NameResolutionCertaintyConfigured,
			Provenance:  "configured resolver candidate; not proof of query selection",
			EvidenceIDs: []string{"dns/configuration"},
		})
		configuredPathResolvers[server] = struct{}{}
	}

	matchedPolicies := model.NameResolutionPoliciesForNames(observation.CandidateNames, environment.NRPT)
	for _, rule := range matchedPolicies {
		for _, namespace := range rule.Namespaces {
			observation.CandidateNamespaces = appendUniqueName(observation.CandidateNamespaces, namespace)
		}
		servers := rule.NameServers
		if len(servers) == 0 {
			servers = []string{""}
		}
		for _, server := range servers {
			observation.Paths = append(observation.Paths, model.NameResolutionPath{
				State:        model.NameResolutionPathPolicyCandidate,
				Mechanism:    model.NameResolutionMechanismDNS,
				Resolver:     server,
				VPN:          rule.VPNRequired,
				Namespace:    firstPolicyNamespace(rule),
				Namespaces:   append([]string(nil), rule.Namespaces...),
				PolicySource: rule.Source,
				PolicyRule:   rule.RuleID,
				Certainty:    model.NameResolutionCertaintyConfigured,
				Provenance:   "matching NRPT namespace policy; not proof of query selection",
				EvidenceIDs:  []string{"dns/configuration"},
			})
		}
	}
	for _, entry := range environment.HostsFileEntries {
		if strings.EqualFold(strings.TrimSuffix(entry.Name, "."), strings.TrimSuffix(host, ".")) {
			observation.HostsFileEntries = append(observation.HostsFileEntries, entry)
			observation.Paths = append(observation.Paths, model.NameResolutionPath{
				State:       model.NameResolutionPathConfiguredCandidate,
				Mechanism:   model.NameResolutionMechanismHostsFile,
				A:           hostEntryFamily(entry.Addresses, true),
				AAAA:        hostEntryFamily(entry.Addresses, false),
				Certainty:   model.NameResolutionCertaintyConfigured,
				Provenance:  entry.Source + "; matching entry is a candidate, not proof of selection",
				EvidenceIDs: []string{"dns/configuration"},
			})
		}
	}

	observation.A = append([]string(nil), resolution.a...)
	observation.AAAA = append([]string(nil), resolution.aaaa...)
	observation.SelectedAddress = resolution.selected
	observation.SelectedFamily = resolution.selectedFamily
	effective := effectivePath(ctx, resolver, host, resolution, lookupErr)
	if effective != nil {
		effective.A = append([]string(nil), observation.A...)
		effective.AAAA = append([]string(nil), observation.AAAA...)
		effective.EvidenceIDs = evidenceIDs(evidence)
		if len(matchedPolicies) > 0 {
			rule := matchedPolicies[0]
			if effective.Namespace == "" {
				effective.Namespace = firstPolicyNamespace(rule)
			}
			if effective.PolicySource == "" {
				effective.PolicySource = rule.Source
			}
			if effective.PolicyRule == "" {
				effective.PolicyRule = rule.RuleID
			}
			if rule.VPNRequired {
				effective.VPN = true
			}
		}
		observation.EffectivePath = effective
		observation.Paths = append(observation.Paths, *effective)
	}
	normalized := model.NormalizeNameResolutionObservation(observation)
	return &normalized
}

func effectivePath(ctx context.Context, resolver Resolver, host string, resolution lookupResult, lookupErr error) *model.NameResolutionPath {
	// A configuration or context failure means the query was not observed by
	// this probe. Do not let a resolver adapter manufacture an effective path
	// for work that never reached the operating-system query API.
	if lookupErr != nil {
		return nil
	}
	if provider, ok := resolver.(EffectivePathProvider); ok {
		if path, err := provider.EffectivePath(ctx, host); err == nil {
			if path.State == "" {
				path.State = model.NameResolutionPathEffective
			}
			if path.Mechanism == "" {
				path.Mechanism = model.NameResolutionMechanismUnknown
			}
			if path.Certainty == "" {
				path.Certainty = model.NameResolutionCertaintyObserved
			}
			return &path
		}
	}
	if len(resolution.failures) == 0 && resolution.selected == "" && len(resolution.a) == 0 && len(resolution.aaaa) == 0 {
		return nil
	}
	provenance := "resolver returned a result; server and interface provenance are unavailable"
	if len(resolution.failures) != 0 {
		provenance = "effective resolver attempt failed; server and interface provenance are unavailable"
	}
	return &model.NameResolutionPath{
		State:       model.NameResolutionPathEffective,
		Mechanism:   model.NameResolutionMechanismDNS,
		Certainty:   model.NameResolutionCertaintyObserved,
		Provenance:  provenance,
		EvidenceIDs: []string{"dns/resolution"},
	}
}

func evidenceIDs(evidence []model.Evidence) []string {
	ids := make([]string, 0, len(evidence))
	for _, item := range evidence {
		if item.ID != "" {
			ids = append(ids, item.ID)
		}
	}
	return ids
}

func candidateNames(host string, suffixes []string) []string {
	result := []string{host}
	if strings.Contains(host, ".") {
		return result
	}
	for _, suffix := range suffixes {
		suffix = strings.Trim(strings.TrimSpace(suffix), ".")
		if suffix != "" {
			result = appendUniqueName(result, host+"."+suffix)
		}
	}
	return result
}

func normalizeResolverValue(value string) string {
	value = strings.Trim(strings.TrimSpace(value), "[]")
	if address, err := netip.ParseAddr(value); err == nil {
		return model.NormalizeAddr(address).String()
	}
	return value
}

func appendUniqueName(values []string, value string) []string {
	value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if value == "" {
		return values
	}
	for _, existing := range values {
		if strings.EqualFold(existing, value) {
			return values
		}
	}
	return append(values, value)
}

func firstPolicyNamespace(rule model.NameResolutionPolicyRule) string {
	if len(rule.Namespaces) == 0 {
		return ""
	}
	return strings.TrimPrefix(strings.TrimSpace(rule.Namespaces[0]), ".")
}

func hostEntryFamily(addresses []string, ipv4 bool) []string {
	result := make([]string, 0)
	for _, value := range addresses {
		address, err := netip.ParseAddr(strings.Trim(value, "[]"))
		if err != nil {
			continue
		}
		if (ipv4 && address.Is4()) || (!ipv4 && address.Is6()) {
			result = append(result, model.NormalizeAddr(address).String())
		}
	}
	return result
}

func mustJSON(value any) json.RawMessage {
	data, err := json.Marshal(value)
	if err != nil {
		return json.RawMessage(`{"error":"could not encode DNS evidence"}`)
	}
	return data
}

func timePtr(value time.Time) *time.Time { return &value }

var errNoConfiguredResolver = errors.New("no configured resolver")

func contextReason(err error) model.FailureReason {
	if errors.Is(err, context.DeadlineExceeded) {
		return model.FailureReasonDNSTimeout
	}
	return model.FailureReasonDNSResolverFailure
}

func errorKind(err error) string {
	if err == nil {
		return ""
	}
	if classified, ok := err.(interface{ DNSKind() string }); ok {
		if kind := classified.DNSKind(); kind != "" {
			return kind
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsTimeout {
			return "timeout"
		}
		if dnsErr.IsNotFound {
			if isNoAnswerText(dnsErr.Err) {
				return "no_answer"
			}
			return "not_found"
		}
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	text := strings.ToLower(err.Error())
	if isNoAnswerText(text) {
		return "no_answer"
	}
	if strings.Contains(text, "no such host") || strings.Contains(text, "nxdomain") || strings.Contains(text, "name or service not known") {
		return "not_found"
	}
	if strings.Contains(text, "timeout") || strings.Contains(text, "timed out") {
		return "timeout"
	}
	return "resolver_failure"
}

func isNoAnswerText(text string) bool {
	text = strings.ToLower(text)
	return strings.Contains(text, "no answer") || strings.Contains(text, "no data") || strings.Contains(text, "nodata")
}

func normalizeResolverAddresses(addresses []string) []string {
	seen := make(map[string]struct{}, len(addresses))
	out := make([]string, 0, len(addresses))
	for _, address := range addresses {
		address = strings.TrimSpace(address)
		if address == "" {
			continue
		}
		if parsed, err := netip.ParseAddr(strings.Trim(address, "[]")); err == nil {
			address = model.NormalizeAddr(parsed).String()
		}
		if _, ok := seen[address]; ok {
			continue
		}
		seen[address] = struct{}{}
		out = append(out, address)
	}
	return out
}

func adaptResolverConfig(source any) ResolverConfigProvider {
	switch provider := source.(type) {
	case nil:
		return ResolverConfigFunc(func(context.Context) ([]string, error) { return nil, nil })
	case ResolverConfigProvider:
		return provider
	case []string:
		return StaticResolverConfig(provider)
	case interface {
		Nameservers(context.Context) ([]string, error)
	}:
		return ResolverConfigFunc(provider.Nameservers)
	case interface{ Nameservers() ([]string, error) }:
		return ResolverConfigFunc(func(context.Context) ([]string, error) { return provider.Nameservers() })
	case interface{ ResolverAddresses() ([]string, error) }:
		return ResolverConfigFunc(func(context.Context) ([]string, error) { return provider.ResolverAddresses() })
	case func(context.Context) ([]string, error):
		return ResolverConfigFunc(provider)
	case func() ([]string, error):
		return ResolverConfigFunc(func(context.Context) ([]string, error) { return provider() })
	default:
		return ResolverConfigFunc(func(context.Context) ([]string, error) {
			return nil, fmt.Errorf("unsupported resolver configuration source %T", source)
		})
	}
}

func resolverForAddresses(addresses []string) Resolver {
	addresses = normalizeResolverAddresses(addresses)
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			if len(addresses) == 0 {
				return nil, errNoConfiguredResolver
			}
			var lastErr error
			for _, address := range addresses {
				if _, _, err := net.SplitHostPort(address); err != nil {
					if ip := net.ParseIP(strings.Trim(address, "[]")); ip != nil {
						address = net.JoinHostPort(strings.Trim(address, "[]"), "53")
					} else {
						address = net.JoinHostPort(address, "53")
					}
				}
				connection, err := (&net.Dialer{}).DialContext(ctx, network, address)
				if err == nil {
					return connection, nil
				}
				lastErr = err
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
			}
			return nil, lastErr
		},
	}
}

// SystemResolverConfig reads resolver addresses from the operating system.
// Platform-specific implementations use the native Windows adapter API or
// the Unix resolver configuration file; no public resolver fallback is added.
type SystemResolverConfig struct {
	// Path overrides the resolver configuration source. On Unix it is a
	// resolv.conf-style file; on Windows it is a fixture/test file and an empty
	// path uses native adapter state.
	Path string
}

// Source implements the optional source label used in evidence.
func (s SystemResolverConfig) Source() string {
	return systemResolverSource(s.Path)
}

// ResolverAddresses implements ResolverConfigProvider.
func (s SystemResolverConfig) ResolverAddresses(ctx context.Context) ([]string, error) {
	return systemResolverAddresses(ctx, s.Path)
}

// ParseResolverAddresses parses nameserver directives in resolv.conf-style
// data. It preserves order while removing duplicates.
func ParseResolverAddresses(data []byte) []string {
	var addresses []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.EqualFold(fields[0], "nameserver") {
			addresses = append(addresses, fields[1])
		}
	}
	return normalizeResolverAddresses(addresses)
}

// ParseWindowsResolverAddresses remains a compatibility parser for existing
// fixture callers. Production Windows collection uses GetAdaptersAddresses;
// this function does not execute or depend on ipconfig.
func ParseWindowsResolverAddresses(data []byte) []string {
	var addresses []string
	collect := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "dns servers") {
			candidate, hasDelimiter := windowsDNSValue(trimmed)
			if !hasDelimiter {
				collect = false
				continue
			}
			collect = true
			if candidate != "" {
				addresses = append(addresses, candidate)
			}
			continue
		}
		if collect {
			candidate := strings.TrimSpace(trimmed)
			if net.ParseIP(candidate) != nil {
				addresses = append(addresses, candidate)
				continue
			}
			collect = false
		}
	}
	return normalizeResolverAddresses(addresses)
}

// windowsDNSValue returns the IP value following the DNS Servers label and
// whether that label has a usable colon delimiter. It scans every colon and
// accepts only a suffix that is exactly one IP address, so an IPv6 value's
// internal colons cannot be mistaken for the label delimiter.
func windowsDNSValue(line string) (string, bool) {
	for index, character := range line {
		if character != ':' {
			continue
		}
		candidate := strings.TrimSpace(line[index+1:])
		if candidate == "" {
			return "", true
		}
		if net.ParseIP(candidate) != nil {
			return candidate, true
		}
	}
	return "", false
}
