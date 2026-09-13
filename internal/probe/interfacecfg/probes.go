package interfacecfg

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/yohnark/tadori/internal/model"
	"github.com/yohnark/tadori/internal/probe"
)

const (
	InterfaceProbeName  = "interface_state"
	DNSProbeName        = "dns_configuration"
	defaultProbeTimeout = 2 * time.Second
)

func boundedContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(parent, timeout)
}

// InterfaceProbe reports interface flags and all IPv4/IPv6 addresses and
// prefixes.  Loopback state is retained as evidence but does not count as a
// usable active interface.
type InterfaceProbe struct {
	Provider SnapshotProvider
	Timeout  time.Duration
}

// InterfaceConfigProbe is a descriptive alias for InterfaceProbe.
type InterfaceConfigProbe = InterfaceProbe

func NewInterfaceProbe(providers ...SnapshotProvider) *InterfaceProbe {
	var provider SnapshotProvider = SystemProvider{}
	if len(providers) != 0 && providers[0] != nil {
		provider = providers[0]
	}
	return &InterfaceProbe{Provider: provider, Timeout: defaultProbeTimeout}
}

// NewProbe is a concise alias for NewInterfaceProbe.
func NewProbe(providers ...SnapshotProvider) *InterfaceProbe {
	return NewInterfaceProbe(providers...)
}

// NewInterfaceConfigProbe is the descriptive constructor alias.
func NewInterfaceConfigProbe(providers ...SnapshotProvider) *InterfaceProbe {
	return NewInterfaceProbe(providers...)
}

func (p *InterfaceProbe) Name() string { return InterfaceProbeName }

func (p *InterfaceProbe) Run(ctx context.Context, execution probe.ExecutionContext) model.ProbeResult {
	started := time.Now().UTC()
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = defaultProbeTimeout
	}
	callCtx, cancel := boundedContext(ctx, timeout)
	defer cancel()
	provider := p.Provider
	if provider == nil {
		provider = SystemProvider{}
	}
	snapshot, err := provider.Snapshot(callCtx)
	snapshot.Interfaces = normalizeInterfaceStates(snapshot.Interfaces)
	completed := time.Now().UTC()
	if err != nil {
		evidence := make([]model.Evidence, 0, 2)
		if len(snapshot.Interfaces) != 0 {
			evidence = append(evidence, makeEvidence("interface-state-1", model.EvidenceKindInterfaceState, snapshot.Source, snapshot.Interfaces, snapshot.CapturedAt))
		}
		evidence = append(evidence, makeEvidence("interface-state-error-1", model.EvidenceKindInterfaceState, "native-interface-api", map[string]any{"error": err.Error()}, completed))
		return result(execution.Target, p.Name(), started, completed, evidence, statusForError(err), reasonForError(err), model.LayerInterface, model.FaultDomainLocal)
	}
	raw := snapshot.Interfaces
	evidence := []model.Evidence{makeEvidence("interface-state-1", model.EvidenceKindInterfaceState, snapshot.Source, raw, snapshot.CapturedAt)}
	active, usable := false, false
	for _, iface := range snapshot.Interfaces {
		if iface.Up && !iface.Loopback {
			active = true
		}
		if iface.Up && !iface.Loopback {
			for _, address := range iface.Addresses {
				if usableAddress(address) {
					usable = true
				}
			}
		}
	}
	status := model.ProbeStatusPassed
	reason := model.FailureReasonNone
	if !active {
		status, reason = model.ProbeStatusFailed, model.FailureReasonInterfaceDown
	} else if !usable {
		status, reason = model.ProbeStatusFailed, model.FailureReasonNoIPAddress
	}
	return result(execution.Target, p.Name(), started, completed, evidence, status, reason, model.LayerInterface, model.FaultDomainLocal)
}

// DNSProbe records configured DNS server addresses as local evidence.  It
// does not resolve names and an empty configuration is not promoted to an
// end-to-end network failure; the DNS lane owns resolver behavior.
type DNSProbe struct {
	Provider SnapshotProvider
	Timeout  time.Duration
}

// DNSConfigProbe is a descriptive alias for DNSProbe.
type DNSConfigProbe = DNSProbe

func NewDNSProbe(providers ...SnapshotProvider) *DNSProbe {
	var provider SnapshotProvider = SystemProvider{}
	if len(providers) != 0 && providers[0] != nil {
		provider = providers[0]
	}
	return &DNSProbe{Provider: provider, Timeout: defaultProbeTimeout}
}

// NewDNSConfigProbe is the descriptive constructor alias.
func NewDNSConfigProbe(providers ...SnapshotProvider) *DNSProbe {
	return NewDNSProbe(providers...)
}

func (p *DNSProbe) Name() string { return DNSProbeName }

func (p *DNSProbe) Run(ctx context.Context, execution probe.ExecutionContext) model.ProbeResult {
	started := time.Now().UTC()
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = defaultProbeTimeout
	}
	callCtx, cancel := boundedContext(ctx, timeout)
	defer cancel()
	provider := p.Provider
	if provider == nil {
		provider = SystemProvider{}
	}
	snapshot, err := provider.Snapshot(callCtx)
	snapshot.DNSServers = normalizeAddresses(snapshot.DNSServers)
	completed := time.Now().UTC()
	if err != nil {
		reason := dnsConfigReason(err)
		status := model.ProbeStatusError
		if reason == model.FailureReasonDNSTimeout {
			status = model.ProbeStatusFailed
		}
		raw := struct {
			Servers          []netip.Addr                     `json:"servers"`
			Interfaces       []InterfaceState                 `json:"interfaces,omitempty"`
			Suffixes         []string                         `json:"suffixes,omitempty"`
			SearchList       []string                         `json:"search_list,omitempty"`
			NRPT             []model.NameResolutionPolicyRule `json:"nrpt,omitempty"`
			NRPTError        string                           `json:"nrpt_error,omitempty"`
			HostsFileEntries []model.NameResolutionHostEntry  `json:"hosts_file_entries,omitempty"`
			HostsFileError   string                           `json:"hosts_file_error,omitempty"`
			Source           string                           `json:"source,omitempty"`
			Error            string                           `json:"error"`
			Kind             string                           `json:"error_kind,omitempty"`
		}{Servers: snapshot.DNSServers, Interfaces: snapshot.Interfaces, Suffixes: snapshot.DNSSuffixes, SearchList: snapshot.SearchList, NRPT: snapshot.NRPT, NRPTError: snapshot.NRPTError, HostsFileEntries: snapshot.HostsFileEntries, HostsFileError: snapshot.HostsFileError, Source: snapshot.Source, Error: err.Error(), Kind: classifyResolverError(err)}
		evidence := []model.Evidence{makeEvidence("dns-configuration-1", model.EvidenceKindDNSConfiguration, "native-resolver-api", raw, completed)}
		return result(execution.Target, p.Name(), started, completed, evidence, status, reason, model.LayerDNS, model.FaultDomainLocal)
	}
	if snapshot.ResolverError != "" {
		raw := struct {
			Servers          []netip.Addr                     `json:"servers"`
			Interfaces       []InterfaceState                 `json:"interfaces,omitempty"`
			Suffixes         []string                         `json:"suffixes,omitempty"`
			SearchList       []string                         `json:"search_list,omitempty"`
			NRPT             []model.NameResolutionPolicyRule `json:"nrpt,omitempty"`
			NRPTError        string                           `json:"nrpt_error,omitempty"`
			HostsFileEntries []model.NameResolutionHostEntry  `json:"hosts_file_entries,omitempty"`
			HostsFileError   string                           `json:"hosts_file_error,omitempty"`
			Source           string                           `json:"source,omitempty"`
			Error            string                           `json:"error"`
			Kind             string                           `json:"error_kind,omitempty"`
		}{Servers: snapshot.DNSServers, Interfaces: snapshot.Interfaces, Suffixes: snapshot.DNSSuffixes, SearchList: snapshot.SearchList, NRPT: snapshot.NRPT, NRPTError: snapshot.NRPTError, HostsFileEntries: snapshot.HostsFileEntries, HostsFileError: snapshot.HostsFileError, Source: snapshot.Source, Error: snapshot.ResolverError, Kind: snapshot.ResolverErrorKind}
		evidence := []model.Evidence{makeEvidence("dns-configuration-1", model.EvidenceKindDNSConfiguration, snapshot.Source, raw, snapshot.CapturedAt)}
		status := model.ProbeStatusError
		reason := model.FailureReasonDNSResolverFailure
		switch snapshot.ResolverErrorKind {
		case "timeout":
			status, reason = model.ProbeStatusFailed, model.FailureReasonDNSTimeout
		case "unsupported":
			reason = model.FailureReasonUnsupported
		case "insufficient_privilege":
			reason = model.FailureReason(FailureReasonInsufficientPrivilege)
		}
		return result(execution.Target, p.Name(), started, completed, evidence, status, reason, model.LayerDNS, model.FaultDomainLocal)
	}
	raw := struct {
		Servers          []netip.Addr                     `json:"servers"`
		Interfaces       []InterfaceState                 `json:"interfaces,omitempty"`
		Suffixes         []string                         `json:"suffixes,omitempty"`
		SearchList       []string                         `json:"search_list,omitempty"`
		NRPT             []model.NameResolutionPolicyRule `json:"nrpt,omitempty"`
		NRPTError        string                           `json:"nrpt_error,omitempty"`
		HostsFileEntries []model.NameResolutionHostEntry  `json:"hosts_file_entries,omitempty"`
		HostsFileError   string                           `json:"hosts_file_error,omitempty"`
		Source           string                           `json:"source,omitempty"`
	}{Servers: snapshot.DNSServers, Interfaces: snapshot.Interfaces, Suffixes: snapshot.DNSSuffixes, SearchList: snapshot.SearchList, NRPT: snapshot.NRPT, NRPTError: snapshot.NRPTError, HostsFileEntries: snapshot.HostsFileEntries, HostsFileError: snapshot.HostsFileError, Source: snapshot.Source}
	evidence := []model.Evidence{makeEvidence("dns-configuration-1", model.EvidenceKindDNSConfiguration, snapshot.Source, raw, snapshot.CapturedAt)}
	return result(execution.Target, p.Name(), started, completed, evidence, model.ProbeStatusPassed, model.FailureReasonNone, model.LayerDNS, model.FaultDomainLocal)
}

func result(target model.Target, name string, started, completed time.Time, evidence []model.Evidence, status model.ProbeStatus, reason model.FailureReason, layer model.Layer, domain model.FaultDomain) model.ProbeResult {
	duration := completed.Sub(started).Milliseconds()
	if duration < 0 {
		duration = 0
	}
	return model.ProbeResult{
		Name: name, Target: target, Status: status,
		Timing:         model.Timing{StartedAt: &started, CompletedAt: &completed, DurationMS: duration},
		Evidence:       evidence,
		Interpretation: model.ProbeInterpretation{FailureReason: reason, Layer: layer, FaultDomain: domain},
	}
}

func makeEvidence(id string, kind model.EvidenceKind, source string, value any, capturedAt time.Time) model.Evidence {
	raw, err := json.Marshal(value)
	if err != nil {
		raw, _ = json.Marshal(map[string]string{"error": "evidence serialization failed"})
	}
	if capturedAt.IsZero() {
		capturedAt = time.Now().UTC()
	}
	captured := capturedAt
	return model.Evidence{ID: id, Kind: kind, Source: source, CapturedAt: &captured, Raw: raw}
}

func normalizeInterfaceStates(interfaces []InterfaceState) []InterfaceState {
	if interfaces == nil {
		return nil
	}
	normalized := append([]InterfaceState(nil), interfaces...)
	for index := range normalized {
		if normalized[index].Addresses != nil {
			normalized[index].Addresses = append([]Address(nil), normalized[index].Addresses...)
			for addressIndex := range normalized[index].Addresses {
				normalized[index].Addresses[addressIndex] = normalizeAddress(normalized[index].Addresses[addressIndex])
			}
		}
		if normalized[index].DNSServers != nil {
			normalized[index].DNSServers = normalizeAddresses(normalized[index].DNSServers)
		}
		if normalized[index].DNSSearchList != nil {
			normalized[index].DNSSearchList = append([]string(nil), normalized[index].DNSSearchList...)
		}
	}
	return normalized
}

func normalizeAddresses(addresses []netip.Addr) []netip.Addr {
	if addresses == nil {
		return nil
	}
	normalized := append([]netip.Addr(nil), addresses...)
	for index := range normalized {
		normalized[index] = model.NormalizeAddr(normalized[index])
	}
	return normalized
}

func normalizeAddress(address Address) Address {
	if !address.IP.Is4In6() {
		return address
	}
	if address.Prefix > 32 {
		if address.Prefix < 96 {
			return address
		}
		address.Prefix -= 96
	}
	address.IP = model.NormalizeAddr(address.IP)
	return address
}

func statusForError(err error) model.ProbeStatus {
	if errors.Is(err, context.DeadlineExceeded) {
		return model.ProbeStatusFailed
	}
	var timeoutError net.Error
	if errors.As(err, &timeoutError) && timeoutError.Timeout() {
		return model.ProbeStatusFailed
	}
	if errors.Is(err, ErrUnsupported) {
		return model.ProbeStatusError
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

func dnsConfigReason(err error) model.FailureReason {
	if errors.Is(err, context.DeadlineExceeded) {
		return model.FailureReasonDNSTimeout
	}
	var timeoutError net.Error
	if errors.As(err, &timeoutError) && timeoutError.Timeout() {
		return model.FailureReasonDNSTimeout
	}
	if errors.Is(err, ErrUnsupported) {
		return model.FailureReasonUnsupported
	}
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		return model.FailureReason(FailureReasonInsufficientPrivilege)
	}
	return model.FailureReasonDNSResolverFailure
}
