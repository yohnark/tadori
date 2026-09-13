package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

// ApplicationProtocol identifies the higher-layer protocol a service profile
// may probe. It is deliberately separate from TransportProtocol: a service
// profile supplies intent, while the lower-layer probes remain reusable for
// every profile.
type ApplicationProtocol string

const (
	ApplicationProtocolNone   ApplicationProtocol = ""
	ApplicationProtocolHTTP   ApplicationProtocol = "http"
	ApplicationProtocolHTTPS  ApplicationProtocol = "https"
	ApplicationProtocolSMB    ApplicationProtocol = "smb"
	ApplicationProtocolRDP    ApplicationProtocol = "rdp"
	ApplicationProtocolSSH    ApplicationProtocol = "ssh"
	ApplicationProtocolDNS    ApplicationProtocol = "dns"
	ApplicationProtocolCustom ApplicationProtocol = "custom"
	ApplicationProtocolTLS    ApplicationProtocol = "custom_tls"
)

// TransportProtocol identifies the transport used by a service profile.
// TransportUDPAndTCP represents a service such as DNS for which both
// transports are applicable; it is not a port classifier.
type TransportProtocol string

const (
	TransportTCP       TransportProtocol = "tcp"
	TransportUDP       TransportProtocol = "udp"
	TransportUDPAndTCP TransportProtocol = "udp+tcp"
)

// ProbeIntent describes the applicable higher-layer observation. Profiles
// describe intent only; this issue does not add protocol implementations for
// SMB, RDP, SSH, or DNS.
type ProbeIntent string

const (
	ProbeIntentHTTP          ProbeIntent = "http_request"
	ProbeIntentTLS           ProbeIntent = "tls_handshake"
	ProbeIntentSMB           ProbeIntent = "smb_session"
	ProbeIntentRDP           ProbeIntent = "rdp_session"
	ProbeIntentSSH           ProbeIntent = "ssh_session"
	ProbeIntentDNS           ProbeIntent = "dns_query"
	ProbeIntentTCPConnection ProbeIntent = "tcp_connection"
)

// ServiceProfileID is the stable identifier used by the CLI and UI. Labels
// belong to ServiceProfile and are not used as parsing rules.
type ServiceProfileID string

const (
	ServiceProfileHTTP      ServiceProfileID = "http"
	ServiceProfileHTTPS     ServiceProfileID = "https"
	ServiceProfileSMB       ServiceProfileID = "smb"
	ServiceProfileRDP       ServiceProfileID = "rdp"
	ServiceProfileSSH       ServiceProfileID = "ssh"
	ServiceProfileDNS       ServiceProfileID = "dns"
	ServiceProfileCustomTCP ServiceProfileID = "custom_tcp"
	ServiceProfileCustomTLS ServiceProfileID = "custom_tls"
)

// ServiceProfile is an extensible description of a service endpoint. The
// profile owns defaults and probe intent; an explicit port always overrides
// DefaultPort.
type ServiceProfile struct {
	ID                   ServiceProfileID    `json:"id"`
	Label                string              `json:"label"`
	ApplicationProtocol  ApplicationProtocol `json:"application_protocol"`
	TransportProtocol    TransportProtocol   `json:"transport_protocol"`
	ApplicableTransports []TransportProtocol `json:"applicable_transports"`
	DefaultPort          uint16              `json:"default_port,omitempty"`
	ProbeIntents         []ProbeIntent       `json:"probe_intents,omitempty"`
}

var serviceProfiles = map[ServiceProfileID]ServiceProfile{
	ServiceProfileHTTP: {
		ID: ServiceProfileHTTP, Label: "HTTP", ApplicationProtocol: ApplicationProtocolHTTP,
		TransportProtocol: TransportTCP, ApplicableTransports: []TransportProtocol{TransportTCP},
		DefaultPort: 80, ProbeIntents: []ProbeIntent{ProbeIntentTCPConnection, ProbeIntentHTTP},
	},
	ServiceProfileHTTPS: {
		ID: ServiceProfileHTTPS, Label: "HTTPS", ApplicationProtocol: ApplicationProtocolHTTPS,
		TransportProtocol: TransportTCP, ApplicableTransports: []TransportProtocol{TransportTCP},
		DefaultPort: 443, ProbeIntents: []ProbeIntent{ProbeIntentTCPConnection, ProbeIntentTLS, ProbeIntentHTTP},
	},
	ServiceProfileSMB: {
		ID: ServiceProfileSMB, Label: "File sharing (SMB)", ApplicationProtocol: ApplicationProtocolSMB,
		TransportProtocol: TransportTCP, ApplicableTransports: []TransportProtocol{TransportTCP},
		DefaultPort: 445, ProbeIntents: []ProbeIntent{ProbeIntentTCPConnection, ProbeIntentSMB},
	},
	ServiceProfileRDP: {
		ID: ServiceProfileRDP, Label: "RDP", ApplicationProtocol: ApplicationProtocolRDP,
		TransportProtocol: TransportTCP, ApplicableTransports: []TransportProtocol{TransportTCP},
		DefaultPort: 3389, ProbeIntents: []ProbeIntent{ProbeIntentTCPConnection, ProbeIntentRDP},
	},
	ServiceProfileSSH: {
		ID: ServiceProfileSSH, Label: "SSH", ApplicationProtocol: ApplicationProtocolSSH,
		TransportProtocol: TransportTCP, ApplicableTransports: []TransportProtocol{TransportTCP},
		DefaultPort: 22, ProbeIntents: []ProbeIntent{ProbeIntentTCPConnection, ProbeIntentSSH},
	},
	ServiceProfileDNS: {
		ID: ServiceProfileDNS, Label: "DNS", ApplicationProtocol: ApplicationProtocolDNS,
		TransportProtocol: TransportUDPAndTCP, ApplicableTransports: []TransportProtocol{TransportUDP, TransportTCP},
		DefaultPort: 53, ProbeIntents: []ProbeIntent{ProbeIntentTCPConnection, ProbeIntentDNS},
	},
	ServiceProfileCustomTCP: {
		ID: ServiceProfileCustomTCP, Label: "Custom TCP", ApplicationProtocol: ApplicationProtocolCustom,
		TransportProtocol: TransportTCP, ApplicableTransports: []TransportProtocol{TransportTCP},
		ProbeIntents: []ProbeIntent{ProbeIntentTCPConnection},
	},
	ServiceProfileCustomTLS: {
		ID: ServiceProfileCustomTLS, Label: "Custom TLS", ApplicationProtocol: ApplicationProtocolTLS,
		TransportProtocol: TransportTCP, ApplicableTransports: []TransportProtocol{TransportTCP},
		ProbeIntents: []ProbeIntent{ProbeIntentTCPConnection, ProbeIntentTLS},
	},
}

// ServiceProfiles returns the registered profiles in stable UI order.
func ServiceProfiles() []ServiceProfile {
	ids := []ServiceProfileID{
		ServiceProfileHTTP, ServiceProfileHTTPS, ServiceProfileSMB, ServiceProfileRDP,
		ServiceProfileSSH, ServiceProfileDNS, ServiceProfileCustomTCP, ServiceProfileCustomTLS,
	}
	profiles := make([]ServiceProfile, 0, len(ids))
	for _, id := range ids {
		profiles = append(profiles, cloneServiceProfile(serviceProfiles[id]))
	}
	return profiles
}

// LookupServiceProfile resolves stable IDs and friendly aliases. Empty input
// selects HTTP, which preserves convenient hostname diagnosis and defaults to
// port 80 without inferring a service from an explicit port.
func LookupServiceProfile(value ServiceProfileID) (ServiceProfile, error) {
	if value == "" {
		value = ServiceProfileHTTP
	}
	normalized := strings.ToLower(strings.TrimSpace(string(value)))
	switch normalized {
	case "http":
		normalized = string(ServiceProfileHTTP)
	case "https":
		normalized = string(ServiceProfileHTTPS)
	case "smb", "file", "filesharing", "file-sharing":
		normalized = string(ServiceProfileSMB)
	case "rdp":
		normalized = string(ServiceProfileRDP)
	case "ssh":
		normalized = string(ServiceProfileSSH)
	case "dns":
		normalized = string(ServiceProfileDNS)
	case "tcp", "custom-tcp":
		normalized = string(ServiceProfileCustomTCP)
	case "tls", "custom-tls":
		normalized = string(ServiceProfileCustomTLS)
	}
	profile, ok := serviceProfiles[ServiceProfileID(normalized)]
	if !ok {
		return ServiceProfile{}, fmt.Errorf("unknown service profile %q", value)
	}
	return cloneServiceProfile(profile), nil
}

func cloneServiceProfile(profile ServiceProfile) ServiceProfile {
	profile.ApplicableTransports = append([]TransportProtocol(nil), profile.ApplicableTransports...)
	profile.ProbeIntents = append([]ProbeIntent(nil), profile.ProbeIntents...)
	return profile
}

// TargetIntent is the structured input accepted by the backend. Input is the
// only free-form destination value; service and port are explicit overrides.
// A pointer port preserves the difference between omitted and invalid zero.
type TargetIntent struct {
	Input   string           `json:"input"`
	Service ServiceProfileID `json:"service,omitempty"`
	Port    *uint16          `json:"port,omitempty"`
}

// UnmarshalJSON accepts the structured intent contract and the original
// string shorthand. The latter keeps existing diagnose API callers working;
// both forms become this same canonical intent before parsing.
func (intent *TargetIntent) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return fmt.Errorf("target intent must be a string or object")
	}
	if data[0] == '"' {
		var input string
		if err := json.Unmarshal(data, &input); err != nil {
			return err
		}
		intent.Input = input
		intent.Service = ""
		intent.Port = nil
		return nil
	}
	type targetIntent TargetIntent
	var decoded targetIntent
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	*intent = TargetIntent(decoded)
	return nil
}

// Endpoint is a concrete network endpoint. It is intentionally distinct from
// Target.RequestedIdentity: a resolved address is not the requested identity,
// and a tested endpoint is not merely a name-resolution result.
type Endpoint struct {
	Address string `json:"address"`
	Port    uint16 `json:"port"`
}

// Target is the canonical normalized service endpoint. OriginalInput is kept
// for provenance. RequestedIdentity is the hostname or explicitly requested
// literal; LiteralIP is populated only when the input explicitly supplied an
// IP literal. ResolvedAddresses, SelectedEndpoint, and TestedEndpoint are
// separate lifecycle facts and are never used as aliases for identity.
type Target struct {
	OriginalInput       string              `json:"original_input"`
	RequestedIdentity   string              `json:"requested_identity"`
	LiteralIP           string              `json:"literal_ip,omitempty"`
	Service             ServiceProfile      `json:"service"`
	ApplicationProtocol ApplicationProtocol `json:"application_protocol"`
	TransportProtocol   TransportProtocol   `json:"transport_protocol"`
	Port                uint16              `json:"port"`
	Resource            string              `json:"resource,omitempty"`
	ResolvedAddresses   []string            `json:"resolved_addresses,omitempty"`
	SelectedEndpoint    *Endpoint           `json:"selected_endpoint,omitempty"`
	TestedEndpoint      *Endpoint           `json:"tested_endpoint,omitempty"`
	NetworkContext      *NetworkContext     `json:"network_context,omitempty"`
}

// ParseTarget is the one canonical target parser. It accepts URLs, names,
// literal addresses, bracketed IPv6 endpoints, and UNC paths. It does not
// infer a service from a port: a bare host:443 remains the default HTTP
// profile unless the caller explicitly selects another service.
func ParseTarget(intent TargetIntent) (Target, error) {
	raw := intent.Input
	if strings.TrimSpace(raw) == "" {
		return Target{}, fmt.Errorf("diagnose target is empty")
	}
	if strings.TrimSpace(raw) != raw {
		return Target{}, fmt.Errorf("diagnose target must not contain surrounding whitespace")
	}
	if strings.IndexFunc(raw, func(r rune) bool { return unicode.IsControl(r) }) >= 0 {
		return Target{}, fmt.Errorf("diagnose target contains a control character")
	}

	var (
		host           string
		resource       string
		inputPort      uint16
		hasInputPort   bool
		profile        ServiceProfile
		hasInputScheme bool
	)

	if isUNC(raw) {
		var err error
		host, resource, err = parseUNC(raw)
		if err != nil {
			return Target{}, err
		}
		profile, err = LookupServiceProfile(ServiceProfileSMB)
		if err != nil {
			return Target{}, err
		}
		hasInputScheme = true
	} else if !isLiteralAddressInput(raw) && (strings.Contains(raw, "://") || hasURIStyleScheme(raw) && !looksLikeHostPort(raw)) {
		parsed, err := url.Parse(raw)
		if err != nil {
			return Target{}, fmt.Errorf("parse diagnose target: %w", err)
		}
		if parsed.Scheme == "" {
			return Target{}, fmt.Errorf("diagnose target must include a host")
		}
		profile, err = profileForScheme(parsed.Scheme)
		if err != nil {
			return Target{}, err
		}
		if parsed.User != nil || parsed.Host == "" || parsed.Hostname() == "" {
			return Target{}, fmt.Errorf("diagnose target must include a host without user information")
		}
		host = parsed.Hostname()
		if parsed.Port() != "" {
			inputPort, err = parsePort(parsed.Port())
			if err != nil {
				return Target{}, err
			}
			hasInputPort = true
		}
		resource = parsed.EscapedPath()
		if parsed.RawQuery != "" {
			resource += "?" + parsed.RawQuery
		}
		if parsed.Fragment != "" {
			return Target{}, fmt.Errorf("diagnose target must not contain a URL fragment")
		}
		hasInputScheme = true
	} else {
		var err error
		host, inputPort, hasInputPort, err = parseHostInput(raw)
		if err != nil {
			return Target{}, err
		}
	}

	canonicalIdentity, literalIP, err := canonicalIdentity(host)
	if err != nil {
		return Target{}, err
	}

	if intent.Service != "" {
		explicitProfile, lookupErr := LookupServiceProfile(intent.Service)
		if lookupErr != nil {
			return Target{}, lookupErr
		}
		if hasInputScheme && explicitProfile.ID != profile.ID {
			return Target{}, fmt.Errorf("conflicting explicit service %q and target service %q", explicitProfile.ID, profile.ID)
		}
		profile = explicitProfile
	}
	if !hasInputScheme {
		var lookupErr error
		if intent.Service != "" {
			profile, lookupErr = LookupServiceProfile(intent.Service)
		} else {
			profile, lookupErr = LookupServiceProfile(ServiceProfileHTTP)
		}
		if lookupErr != nil {
			return Target{}, lookupErr
		}
	}

	port := inputPort
	if intent.Port != nil {
		if *intent.Port == 0 {
			return Target{}, fmt.Errorf("diagnose target port must be between 1 and 65535")
		}
		if hasInputPort && inputPort != *intent.Port {
			return Target{}, fmt.Errorf("conflicting explicit ports %d and %d", inputPort, *intent.Port)
		}
		port = *intent.Port
		hasInputPort = true
	}
	if !hasInputPort {
		port = profile.DefaultPort
		if port == 0 {
			return Target{}, fmt.Errorf("service %s requires an explicit port", profile.Label)
		}
	}

	return Target{
		OriginalInput:       raw,
		RequestedIdentity:   canonicalIdentity,
		LiteralIP:           literalIP,
		Service:             profile,
		ApplicationProtocol: profile.ApplicationProtocol,
		TransportProtocol:   profile.TransportProtocol,
		Port:                port,
		Resource:            resource,
	}, nil
}

// NewTarget constructs a canonical lower-layer target for callers that
// already hold a separate identity and port. User-facing input should prefer
// ParseTarget so URL/UNC resources and explicit conflict checks are retained.
func NewTarget(identity string, port uint16) Target {
	if port == 0 {
		return Target{RequestedIdentity: identity}
	}
	value := port
	target, err := ParseTarget(TargetIntent{Input: identity, Port: &value})
	if err == nil {
		return target
	}
	return Target{OriginalInput: identity, RequestedIdentity: identity, Port: port}
}

func isUNC(raw string) bool {
	return strings.HasPrefix(raw, `\`)
}

func parseUNC(raw string) (string, string, error) {
	trimmed := strings.TrimLeft(raw, `\`)
	parts := strings.Split(trimmed, `\`)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("UNC target must include a host and share")
	}
	for _, part := range parts {
		if part == "" {
			return "", "", fmt.Errorf("UNC target contains an empty path component")
		}
	}
	return parts[0], "/" + strings.Join(parts[1:], "/"), nil
}

func hasURIStyleScheme(raw string) bool {
	colon := strings.IndexByte(raw, ':')
	if colon <= 0 {
		return false
	}
	for index, character := range raw[:colon] {
		if (index == 0 && !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z'))) ||
			(index > 0 && !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '+' || character == '-' || character == '.')) {
			return false
		}
	}
	return true
}

func isLiteralAddressInput(raw string) bool {
	_, err := netip.ParseAddr(raw)
	return err == nil
}

func looksLikeHostPort(raw string) bool {
	if strings.Count(raw, ":") != 1 || strings.ContainsAny(raw, "/\\") {
		return false
	}
	separator := strings.IndexByte(raw, ':')
	if separator <= 0 || separator == len(raw)-1 {
		return false
	}
	return !strings.EqualFold(raw[:separator], "javascript")
}

func profileForScheme(scheme string) (ServiceProfile, error) {
	switch strings.ToLower(scheme) {
	case "http":
		return LookupServiceProfile(ServiceProfileHTTP)
	case "https":
		return LookupServiceProfile(ServiceProfileHTTPS)
	case "smb":
		return LookupServiceProfile(ServiceProfileSMB)
	case "rdp":
		return LookupServiceProfile(ServiceProfileRDP)
	case "ssh":
		return LookupServiceProfile(ServiceProfileSSH)
	case "dns":
		return LookupServiceProfile(ServiceProfileDNS)
	case "tcp":
		return LookupServiceProfile(ServiceProfileCustomTCP)
	case "tls":
		return LookupServiceProfile(ServiceProfileCustomTLS)
	default:
		return ServiceProfile{}, fmt.Errorf("unsupported diagnose target scheme %q", scheme)
	}
}

func parseHostInput(raw string) (host string, port uint16, hasPort bool, err error) {
	if address, parseErr := netip.ParseAddr(raw); parseErr == nil {
		return address.String(), 0, false, nil
	}
	if strings.HasPrefix(raw, "[") {
		closeBracket := strings.IndexByte(raw, ']')
		if closeBracket < 0 {
			return "", 0, false, fmt.Errorf("diagnose target has malformed IPv6 brackets")
		}
		host = raw[1:closeBracket]
		if _, parseErr := netip.ParseAddr(host); parseErr != nil {
			return "", 0, false, fmt.Errorf("diagnose target bracketed host is not a valid IPv6 literal")
		}
		rest := raw[closeBracket+1:]
		if rest == "" {
			return host, 0, false, nil
		}
		if !strings.HasPrefix(rest, ":") {
			return "", 0, false, fmt.Errorf("diagnose target has malformed IPv6 endpoint")
		}
		port, err = parsePort(rest[1:])
		return host, port, err == nil, err
	}
	if hostPart, portPart, splitErr := net.SplitHostPort(raw); splitErr == nil {
		if hostPart == "" {
			return "", 0, false, fmt.Errorf("diagnose target must include a host")
		}
		port, err = parsePort(portPart)
		return hostPart, port, err == nil, err
	}
	if strings.Count(raw, ":") == 1 {
		separator := strings.LastIndexByte(raw, ':')
		if separator == 0 || separator == len(raw)-1 {
			return "", 0, false, fmt.Errorf("diagnose target must include a host and port")
		}
		host = raw[:separator]
		port, err = parsePort(raw[separator+1:])
		return host, port, err == nil, err
	}
	if strings.Contains(raw, ":") {
		return "", 0, false, fmt.Errorf("IPv6 target with a port must use [addr]:port")
	}
	return raw, 0, false, nil
}

func parsePort(raw string) (uint16, error) {
	if raw == "" {
		return 0, fmt.Errorf("diagnose target must include a port between 1 and 65535")
	}
	value, err := strconv.ParseUint(raw, 10, 16)
	if err != nil || value == 0 {
		return 0, fmt.Errorf("diagnose target has an invalid port %q", raw)
	}
	return uint16(value), nil
}

func canonicalIdentity(host string) (identity, literal string, err error) {
	if host == "" || strings.IndexFunc(host, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return "", "", fmt.Errorf("diagnose target must include a valid host")
	}
	if address, parseErr := netip.ParseAddr(host); parseErr == nil {
		address = NormalizeAddr(address)
		return address.String(), address.String(), nil
	}
	if len(host) > 253 || strings.ContainsAny(host, "[]/") {
		return "", "", fmt.Errorf("diagnose target has an invalid hostname")
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || strings.Contains(host, "..") {
		return "", "", fmt.Errorf("diagnose target has an invalid hostname")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", "", fmt.Errorf("diagnose target has an invalid hostname")
		}
		for _, character := range label {
			if character != '-' && character != '_' && character != '.' &&
				!((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9')) && character <= unicode.MaxASCII {
				return "", "", fmt.Errorf("diagnose target has an invalid hostname")
			}
		}
	}
	return host, "", nil
}

// NormalizeTarget validates the canonical fields and fills a profile for
// callers that construct a target directly (notably lower-level probe users).
// User-facing input should use ParseTarget so conflict detection and
// provenance are applied before execution.
func NormalizeTarget(target Target) Target {
	if target.RequestedIdentity == "" && target.OriginalInput != "" {
		if parsed, err := ParseTarget(TargetIntent{Input: target.OriginalInput}); err == nil {
			return parsed
		}
	}
	if target.Service.ID == "" {
		if profile, err := LookupServiceProfile(ServiceProfileHTTP); err == nil {
			target.Service = profile
		}
	}
	if target.ApplicationProtocol == "" {
		target.ApplicationProtocol = target.Service.ApplicationProtocol
	}
	if target.TransportProtocol == "" {
		target.TransportProtocol = target.Service.TransportProtocol
	}
	if target.Port == 0 {
		target.Port = target.Service.DefaultPort
	}
	if target.LiteralIP == "" {
		if address, err := netip.ParseAddr(target.RequestedIdentity); err == nil {
			target.LiteralIP = NormalizeAddr(address).String()
			target.RequestedIdentity = target.LiteralIP
		}
	}
	if target.ResolvedAddresses != nil {
		target.ResolvedAddresses = append([]string(nil), target.ResolvedAddresses...)
	}
	if target.NetworkContext != nil {
		context := *target.NetworkContext
		context.CompetingRoutes = append([]RouteCandidate(nil), target.NetworkContext.CompetingRoutes...)
		context.Provenance = append([]string(nil), target.NetworkContext.Provenance...)
		context.EvidenceIDs = append([]string(nil), target.NetworkContext.EvidenceIDs...)
		if target.NetworkContext.Neighbor != nil {
			neighbor := *target.NetworkContext.Neighbor
			neighbor.Entries = append([]NeighborEntry(nil), target.NetworkContext.Neighbor.Entries...)
			context.Neighbor = &neighbor
		}
		target.NetworkContext = &context
	}
	return target
}

// HTTPURL builds the only URL needed by the HTTP-family probes from the
// canonical target. It does not parse or infer target semantics.
func (target Target) HTTPURL() (string, error) {
	target = NormalizeTarget(target)
	if target.ApplicationProtocol != ApplicationProtocolHTTP && target.ApplicationProtocol != ApplicationProtocolHTTPS {
		return "", fmt.Errorf("service %s does not support HTTP requests", target.Service.Label)
	}
	host := target.RequestedIdentity
	if host == "" {
		return "", fmt.Errorf("target identity is empty")
	}
	base := (&url.URL{Scheme: string(target.ApplicationProtocol), Host: net.JoinHostPort(host, strconv.Itoa(int(target.Port)))}).String()
	if target.Resource == "" {
		return base, nil
	}
	if !strings.HasPrefix(target.Resource, "/") && !strings.HasPrefix(target.Resource, "?") {
		return "", fmt.Errorf("target resource must be a path or query")
	}
	return base + target.Resource, nil
}

// Validate checks the canonical identity fields without reinterpreting the
// original input. It is the validation hook shared by lower-level probes that
// may receive a Target constructed by an embedding caller.
func (target Target) Validate() error {
	target = NormalizeTarget(target)
	identity, literal, err := canonicalIdentity(target.RequestedIdentity)
	if err != nil {
		return err
	}
	if target.LiteralIP != "" && target.LiteralIP != literal {
		return fmt.Errorf("target literal IP does not match requested identity")
	}
	if literal != "" && target.LiteralIP == "" {
		return fmt.Errorf("target literal IP is missing for an explicit address")
	}
	if identity != target.RequestedIdentity {
		return fmt.Errorf("target requested identity is not canonical")
	}
	return nil
}

// EndpointAddress returns a dialable host:port for the selected or requested
// endpoint. It is shared by lower-layer probes so they do not reparse the
// original input.
func (target Target) EndpointAddress() (string, error) {
	target = NormalizeTarget(target)
	if err := target.Validate(); err != nil {
		return "", err
	}
	if target.Port == 0 {
		return "", fmt.Errorf("target port is required")
	}
	address := target.RequestedIdentity
	if target.SelectedEndpoint != nil && target.SelectedEndpoint.Address != "" {
		address = target.SelectedEndpoint.Address
	}
	if address == "" {
		return "", fmt.Errorf("target identity is empty")
	}
	if strings.ContainsAny(address, "[]") {
		return "", fmt.Errorf("target identity has malformed brackets")
	}
	if strings.Contains(address, ":") {
		if _, err := netip.ParseAddr(address); err != nil {
			return "", fmt.Errorf("target identity is not a valid IPv6 literal")
		}
	}
	return net.JoinHostPort(address, strconv.Itoa(int(target.Port))), nil
}

// MatchesAddress reports whether an observed address can belong to this
// target. It considers the requested identity and explicitly recorded
// resolution facts without collapsing those facts into one host field.
func (target Target) MatchesAddress(address string) bool {
	target = NormalizeTarget(target)
	address = strings.Trim(strings.TrimSpace(address), "[]")
	if address == "" {
		return false
	}
	if parsed, err := netip.ParseAddr(address); err == nil {
		address = NormalizeAddr(parsed).String()
	}
	candidates := []string{target.LiteralIP, target.RequestedIdentity}
	candidates = append(candidates, target.ResolvedAddresses...)
	if target.SelectedEndpoint != nil {
		candidates = append(candidates, target.SelectedEndpoint.Address)
	}
	if target.TestedEndpoint != nil {
		candidates = append(candidates, target.TestedEndpoint.Address)
	}
	for _, candidate := range candidates {
		candidate = strings.Trim(strings.TrimSpace(candidate), "[]")
		if parsed, err := netip.ParseAddr(candidate); err == nil {
			candidate = NormalizeAddr(parsed).String()
		}
		if strings.EqualFold(candidate, address) {
			return true
		}
	}
	return false
}
