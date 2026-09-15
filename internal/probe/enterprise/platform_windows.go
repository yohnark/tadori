//go:build windows

package enterprise

import (
	"bufio"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/yohnark/tadori/internal/model"
	"github.com/yohnark/tadori/internal/probe/proxy"
)

// The Windows provider uses read-only WinHTTP, IP Helper, and registry APIs.
// No command interpreter, PowerShell, or user-selected executable is invoked.
var (
	iphlpapiDLL          = syscall.NewLazyDLL("iphlpapi.dll")
	getAdaptersAddresses = iphlpapiDLL.NewProc("GetAdaptersAddresses")
	getBestRoute2        = iphlpapiDLL.NewProc("GetBestRoute2")
	advapi32DLL          = syscall.NewLazyDLL("advapi32.dll")
	regOpenKeyEx         = advapi32DLL.NewProc("RegOpenKeyExW")
	regQueryValueEx      = advapi32DLL.NewProc("RegQueryValueExW")
	regCloseKey          = advapi32DLL.NewProc("RegCloseKey")
)

const (
	familyUnspec              = 0
	getAdaptersAddressesFlags = 0x0080 // GAA_FLAG_INCLUDE_GATEWAYS
	errorBufferOverflow       = 111
	errorFileNotFound         = 2
	errorAccessDenied         = 5
	hkeyLocalMachine          = 0x80000002
	keyRead                   = 0x20019
	regDWORD                  = 4
	maxAdapters               = 128
	ifOperStatusUp            = 1
	ifTypePPP                 = 23
	ifTypeSoftwareLoopback    = 24
	ifTypeTunnel              = 131
	ifTypeIEEE80211           = 71
	ifTypeWWAN                = 243
)

type platformSnapshotProvider struct{}

func (platformSnapshotProvider) Snapshot(ctx context.Context, target model.Target) (Snapshot, error) {
	local, err := (platformSnapshotProvider{}).SnapshotEnvironment(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot := Snapshot{
		Proxy: local.Proxy, TrustStore: local.TrustStore, Firewall: local.Firewall,
		Adapters: local.Adapters, Issues: local.Issues,
	}

	targetURL, targetErr := targetURLForSnapshot(target)
	if targetErr != nil {
		snapshot.Issues = append(snapshot.Issues, ObservationIssue{Subsystem: "connectivity", Kind: "invalid_target", Error: targetErr.Error()})
		return snapshot, nil
	}

	for _, source := range []struct {
		name   string
		config proxy.SourceConfiguration
		path   string
	}{
		{name: "wininet", config: local.Proxy.WinINET, path: PathBrowserWinINET},
		{name: "winhttp", config: local.Proxy.WinHTTP, path: PathServiceWinHTTP},
	} {
		effective := resolveEffectiveProxy(ctx, targetURL, source.name, source.config)
		if effective.Error != "" {
			snapshot.EffectiveProxy = append(snapshot.EffectiveProxy, effective)
			snapshot.Issues = append(snapshot.Issues, ObservationIssue{Subsystem: "proxy", Kind: "url_resolution", Error: effective.Error})
			continue
		}
		mode := effective.Mode
		if effective.Endpoint == "" {
			mode = PathModeDirect
		}
		path := observePath(ctx, target, source.path, source.name, mode, effective.Endpoint)
		if path.ProxyAuthenticationHint || path.ConnectOutcome == ConnectAuthRequired {
			effective.Decision = model.EnterpriseProxyDecisionAuthenticationRequired
		}
		snapshot.Paths = append(snapshot.Paths, path)
		snapshot.EffectiveProxy = append(snapshot.EffectiveProxy, effective)
	}

	application := observePath(ctx, target, PathApplicationDirect, "direct", PathModeDirect, "")
	snapshot.Paths = append(snapshot.Paths, application)
	snapshot.TLS = compareTLS(snapshot.Paths)
	if routes, routeIssues := collectEffectiveRoutes(ctx, target, snapshot.Paths, snapshot.Adapters); len(routes) != 0 {
		snapshot.Routes = routes
		snapshot.Issues = append(snapshot.Issues, routeIssues...)
	} else {
		snapshot.Issues = append(snapshot.Issues, routeIssues...)
	}
	return snapshot, nil
}

// SnapshotEnvironment collects only local enterprise state. Keeping this
// boundary separate lets the target-independent environment workflow reuse
// the same native collectors without resolving PAC or opening any path.
func (platformSnapshotProvider) SnapshotEnvironment(ctx context.Context) (EnvironmentSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return EnvironmentSnapshot{}, err
	}
	discovery, err := proxy.Discover(ctx)
	if err != nil {
		return EnvironmentSnapshot{}, err
	}
	snapshot := EnvironmentSnapshot{Proxy: discovery, TrustStore: collectTrustStore()}
	if firewall, firewallErr := collectFirewallProfiles(); firewallErr != nil {
		snapshot.Firewall = firewall
		snapshot.Issues = append(snapshot.Issues, issueFromError("firewall", firewallErr))
	} else {
		snapshot.Firewall = firewall
	}
	if adapters, adapterErr := collectAdapters(); adapterErr != nil {
		snapshot.Issues = append(snapshot.Issues, issueFromError("adapter", adapterErr))
	} else {
		snapshot.Adapters = adapters
	}
	if snapshot.TrustStore.Error != "" {
		snapshot.Issues = append(snapshot.Issues, ObservationIssue{Subsystem: "trust_store", Kind: "collection", Error: snapshot.TrustStore.Error, Insufficient: snapshot.TrustStore.Insufficient})
	}
	return snapshot, nil
}

func targetURLForSnapshot(target model.Target) (string, error) {
	return target.HTTPURL()
}

func resolveEffectiveProxy(ctx context.Context, targetURL, source string, config proxy.SourceConfiguration) EffectiveProxy {
	observed := proxy.NormalizeConfiguration(config)
	effective := EffectiveProxy{
		Source: source, Decision: model.EnterpriseProxyDecisionUnknown, Mode: PathModeUnknown,
		PACUsed: observed.PACConfigured, AutoDetect: observed.AutoDetect,
	}
	if !config.Available {
		effective.Error = observed.Error
		if effective.Error == "" {
			effective.Error = "proxy configuration unavailable"
		}
		return effective
	}
	effective.ResolutionAttempted = true
	resolution, err := proxy.ResolveProxyForURL(ctx, targetURL, config)
	if err != nil {
		effective.Error = err.Error()
		if observed.PACConfigured {
			effective.Decision = model.EnterpriseProxyDecisionPACResultUnavailable
		}
		return effective
	}
	effective.ResolutionOK = true
	effective.Bypass = resolution.Bypass
	effective.BypassMatched = resolution.BypassMatched
	effective.PACUsed = effective.PACUsed || resolution.UsedPAC
	effective.AutoDetect = effective.AutoDetect || resolution.AutoDetect
	if resolution.BypassMatched {
		effective.Decision = model.EnterpriseProxyDecisionBypassMatch
		effective.Mode = PathModeDirect
		return effective
	}
	if resolution.Direct || resolution.Proxy == "" {
		effective.Decision = model.EnterpriseProxyDecisionDirect
		effective.Mode = PathModeDirect
		return effective
	}
	endpoints, endpointErr := proxy.ProxyEndpoints(resolution.Proxy)
	if endpointErr != nil || len(endpoints) == 0 {
		effective.Error = "effective proxy endpoint is malformed"
		return effective
	}
	effective.Endpoint = endpoints[0]
	if effective.PACUsed {
		effective.Decision = model.EnterpriseProxyDecisionPACSelectedProxy
		effective.Mode = PathModePAC
	} else {
		effective.Decision = model.EnterpriseProxyDecisionStaticProxy
		effective.Mode = PathModeProxy
	}
	return effective
}

func observePath(ctx context.Context, target model.Target, name, source, mode, endpoint string) PathObservation {
	path := PathObservation{Name: name, Source: source, Mode: mode, Endpoint: endpoint, ConnectOutcome: ConnectNotApplicable}
	targetURL, err := target.HTTPURL()
	if err != nil {
		path.FailureReason = model.FailureReasonProbeExecution
		path.Error = err.Error()
		return path
	}
	parsed, err := url.Parse(targetURL)
	if err != nil {
		path.FailureReason = model.FailureReasonProbeExecution
		path.Error = "canonical target URL is malformed"
		return path
	}
	if mode == PathModeProxy || mode == PathModePAC {
		var connectivity connectResult
		if parsed.Scheme == "https" {
			connectivity = probeCONNECT(ctx, parsed, endpoint)
		} else {
			connectivity = probeProxyTCP(ctx, endpoint)
		}
		path.TCPConnected = connectivity.connected
		path.ConnectOutcome = connectivity.outcome
		path.ConnectStatusCode = connectivity.statusCode
		path.ProxyAuthenticationHint = connectivity.authRequired
		if connectivity.outcome == ConnectAuthRequired {
			path.FailureReason = model.FailureReasonProxyAuthenticationRequired
			path.Error = "proxy requested authentication"
			return path
		}
		if connectivity.outcome == ConnectDenied {
			path.FailureReason = model.FailureReasonProxyConnectDenied
			path.Error = "proxy denied HTTP CONNECT"
			return path
		}
		if connectivity.outcome != ConnectSucceeded {
			path.FailureReason = model.FailureReasonProxyUnavailable
			path.Error = connectivity.error
			return path
		}
	}
	observed := ProbeHTTPPath(ctx, target, name, source, mode, endpoint, 5*time.Second)
	if mode == PathModeProxy || mode == PathModePAC {
		// Preserve the explicit endpoint/CONNECT observation even when the
		// subsequent HTTP/TLS request fails after the proxy socket was known to
		// be reachable. For an HTTP target CONNECT is not applicable; retain a
		// 407 discovered by the HTTP request itself.
		observed.TCPConnected = observed.TCPConnected || path.TCPConnected
		if parsed.Scheme == "https" {
			observed.ConnectOutcome = path.ConnectOutcome
			observed.ConnectStatusCode = path.ConnectStatusCode
		} else if observed.ConnectOutcome == ConnectAuthRequired {
			observed.ConnectStatusCode = observed.HTTPStatusCode
		} else {
			observed.ConnectOutcome = ConnectNotApplicable
		}
		observed.ProxyAuthenticationHint = observed.ProxyAuthenticationHint || path.ProxyAuthenticationHint
	}
	return observed
}

type connectResult struct {
	connected    bool
	outcome      string
	statusCode   int
	authRequired bool
	error        string
}

func probeCONNECT(ctx context.Context, target *url.URL, endpoint string) connectResult {
	result := connectResult{outcome: ConnectUnavailable}
	if endpoint == "" {
		result.outcome = ConnectNotTested
		result.error = "proxy endpoint is unavailable"
		return result
	}
	host := target.Hostname()
	port := target.Port()
	if port == "" {
		if target.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	address := net.JoinHostPort(host, port)
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(callCtx, "tcp", endpoint)
	if err != nil {
		if errors.Is(callCtx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
			result.outcome = ConnectTimeout
		} else {
			result.outcome = ConnectUnavailable
		}
		result.error = safeErrorString(err.Error())
		return result
	}
	result.connected = true
	defer connection.Close()
	if deadline, ok := callCtx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if _, err := fmt.Fprintf(connection, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: Keep-Alive\r\n\r\n", address, address); err != nil {
		result.outcome = ConnectUnavailable
		result.error = safeErrorString(err.Error())
		return result
	}
	reader := bufio.NewReader(io.LimitReader(connection, 64*1024))
	request := &stdhttp.Request{Method: stdhttp.MethodConnect, URL: &url.URL{Host: address}}
	response, err := stdhttp.ReadResponse(reader, request)
	if err != nil {
		result.outcome = ConnectUnavailable
		result.error = safeErrorString(err.Error())
		return result
	}
	if response.Body != nil {
		response.Body.Close()
	}
	result.statusCode = response.StatusCode
	switch {
	case response.StatusCode == stdhttp.StatusProxyAuthRequired:
		result.outcome = ConnectAuthRequired
		result.authRequired = true
	case response.StatusCode >= 200 && response.StatusCode < 300:
		result.outcome = ConnectSucceeded
	case response.StatusCode >= 400:
		result.outcome = ConnectDenied
	default:
		result.outcome = ConnectDenied
	}
	return result
}

func probeProxyTCP(ctx context.Context, endpoint string) connectResult {
	result := connectResult{outcome: ConnectUnavailable}
	if endpoint == "" {
		result.error = "proxy endpoint is unavailable"
		return result
	}
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(callCtx, "tcp", endpoint)
	if err != nil {
		if errors.Is(callCtx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
			result.outcome = ConnectTimeout
		} else {
			result.outcome = ConnectUnavailable
		}
		result.error = safeErrorString(err.Error())
		return result
	}
	result.connected = true
	result.outcome = ConnectSucceeded
	if connection != nil {
		_ = connection.Close()
	}
	return result
}

func collectTrustStore() TrustStoreObservation {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		return TrustStoreObservation{Source: "crypto/x509.SystemCertPool", Error: safeErrorString(errorString(err, "system trust store unavailable"))}
	}
	return TrustStoreObservation{Source: "crypto/x509.SystemCertPool", Available: true, RootCount: len(pool.Subjects())}
}

func errorString(err error, fallback string) string {
	if err == nil {
		return fallback
	}
	return err.Error()
}

func issueFromError(subsystem string, err error) ObservationIssue {
	issue := ObservationIssue{Subsystem: subsystem, Kind: "collection", Error: safeErrorString(err.Error())}
	if errors.Is(err, syscall.Errno(errorAccessDenied)) {
		issue.Insufficient = true
	}
	return issue
}

type ipAdapterAddresses struct {
	Length                uint32
	IfIndex               uint32
	Next                  *ipAdapterAddresses
	AdapterName           *byte
	FirstUnicastAddress   uintptr
	FirstAnycastAddress   uintptr
	FirstMulticastAddress uintptr
	FirstDNSAddress       uintptr
	DNSSuffix             *uint16
	Description           *uint16
	FriendlyName          *uint16
	PhysicalAddress       [8]byte
	PhysicalAddressLength uint32
	Flags                 uint32
	MTU                   uint32
	IfType                uint32
	OperStatus            uint32
	IPv6IfIndex           uint32
	ZoneIndices           [16]uint32
}

func collectAdapters() ([]AdapterObservation, error) {
	size := uint32(16 * 1024)
	var data []byte
	var ret uintptr
	for attempt := 0; attempt < 2; attempt++ {
		data = make([]byte, size)
		ret, _, _ = getAdaptersAddresses.Call(familyUnspec, getAdaptersAddressesFlags, 0, uintptr(unsafe.Pointer(&data[0])), uintptr(unsafe.Pointer(&size)))
		if ret == 0 {
			break
		}
		if ret != errorBufferOverflow {
			return nil, syscall.Errno(ret)
		}
		if size == 0 {
			return nil, errors.New("GetAdaptersAddresses returned an empty buffer size")
		}
	}
	if ret != 0 {
		return nil, syscall.Errno(ret)
	}
	if len(data) < int(unsafe.Sizeof(ipAdapterAddresses{})) {
		return nil, errors.New("GetAdaptersAddresses returned a truncated buffer")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		interfaces = nil
	}
	names := make(map[int]string, len(interfaces))
	for _, iface := range interfaces {
		names[iface.Index] = iface.Name
	}
	result := make([]AdapterObservation, 0)
	for current, count := (*ipAdapterAddresses)(unsafe.Pointer(&data[0])), 0; current != nil && count < maxAdapters; current, count = current.Next, count+1 {
		if current.Length < uint32(unsafe.Offsetof(ipAdapterAddresses{}.IfType))+4 {
			break
		}
		name := readUTF16Bounded(current.FriendlyName)
		if name == "" {
			name = names[int(current.IfIndex)]
		}
		if name == "" {
			name = "interface-" + strconv.FormatUint(uint64(current.IfIndex), 10)
		}
		interfaceIndex := current.IfIndex
		if interfaceIndex == 0 {
			interfaceIndex = current.IPv6IfIndex
		}
		vpn, virtual := classifyAdapter(name, current.IfType)
		result = append(result, AdapterObservation{
			Index: int(interfaceIndex), Name: name, Type: adapterType(current.IfType, vpn, virtual),
			IfType: current.IfType, Operational: current.OperStatus == ifOperStatusUp, VPN: vpn, Virtual: virtual,
		})
	}
	return result, nil
}

func readUTF16Bounded(value *uint16) string {
	if value == nil {
		return ""
	}
	const maxCharacters = 1024
	values := unsafe.Slice(value, maxCharacters)
	for index, character := range values {
		if character == 0 {
			return syscall.UTF16ToString(values[:index])
		}
	}
	return syscall.UTF16ToString(values)
}

func classifyAdapter(name string, ifType uint32) (vpn, virtual bool) {
	lower := strings.ToLower(name)
	virtual = ifType == ifTypeSoftwareLoopback || ifType == ifTypeTunnel || containsAny(lower, "virtual", "hyper-v", "vmware", "virtualbox", "vbox", "tap", "tun", "wsl", "docker", "container")
	vpn = ifType == ifTypePPP || ifType == ifTypeTunnel || containsAny(lower, "vpn", "wireguard", "openvpn", "cisco", "globalprotect", "fortinet", "anyconnect")
	return vpn, virtual
}

func adapterType(ifType uint32, vpn, virtual bool) string {
	if vpn {
		return "vpn"
	}
	if virtual {
		return "virtual"
	}
	switch ifType {
	case ifTypeIEEE80211:
		return "wifi"
	case ifTypeWWAN:
		return "wwan"
	case ifTypePPP:
		return "point_to_point"
	default:
		return "physical_or_unknown"
	}
}

func containsAny(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if strings.Contains(value, candidate) {
			return true
		}
	}
	return false
}

func collectFirewallProfiles() (FirewallObservation, error) {
	result := FirewallObservation{Source: "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy"}
	base := result.Source
	for _, name := range []string{"DomainProfile", "StandardProfile", "PublicProfile"} {
		profile := FirewallProfile{Name: name}
		keyPath := base + "\\" + name
		key, err := openRegistryKey(keyPath)
		if err != nil {
			if errors.Is(err, syscall.Errno(errorFileNotFound)) {
				continue
			}
			if errors.Is(err, syscall.Errno(errorAccessDenied)) {
				result.Insufficient = true
			}
			result.Error = err.Error()
			return result, err
		}
		profile.PolicyPresent = true
		if value, ok, queryErr := queryRegistryDWORD(key, "EnableFirewall"); queryErr == nil && ok {
			enabled := value != 0
			profile.FirewallEnabled = &enabled
		}
		if value, ok, queryErr := queryRegistryDWORD(key, "DoNotAllowExceptions"); queryErr == nil && ok {
			blocked := value != 0
			profile.BlockInboundExceptions = &blocked
		}
		regCloseKey.Call(uintptr(key))
		result.Profiles = append(result.Profiles, profile)
	}
	result.Available = len(result.Profiles) > 0
	if !result.Available {
		result.Error = "Windows firewall profile state unavailable"
		return result, errors.New(result.Error)
	}
	return result, nil
}

func openRegistryKey(path string) (syscall.Handle, error) {
	pathPointer, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var key syscall.Handle
	ret, _, _ := regOpenKeyEx.Call(hkeyLocalMachine, uintptr(unsafe.Pointer(pathPointer)), 0, keyRead, uintptr(unsafe.Pointer(&key)))
	if ret != 0 {
		return 0, syscall.Errno(ret)
	}
	return key, nil
}

func queryRegistryDWORD(key syscall.Handle, name string) (uint32, bool, error) {
	namePointer, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, false, err
	}
	var valueType uint32
	var value uint32
	size := uint32(unsafe.Sizeof(value))
	ret, _, _ := regQueryValueEx.Call(uintptr(key), uintptr(unsafe.Pointer(namePointer)), 0, uintptr(unsafe.Pointer(&valueType)), uintptr(unsafe.Pointer(&value)), uintptr(unsafe.Pointer(&size)))
	if ret == errorFileNotFound {
		return 0, false, nil
	}
	if ret != 0 {
		return 0, false, syscall.Errno(ret)
	}
	if valueType != regDWORD || size < 4 {
		return 0, false, errors.New("unexpected firewall profile value type")
	}
	return value, true, nil
}

type sockaddrInet struct {
	Family uint16
	Port   uint16
	Data   [24]byte
}

type ipAddressPrefix struct {
	Prefix       sockaddrInet
	PrefixLength uint8
	Padding      [3]byte
}

type mibIPForwardRow2 struct {
	InterfaceLuid        uint64
	InterfaceIndex       uint32
	DestinationPrefix    ipAddressPrefix
	NextHop              sockaddrInet
	SitePrefixLength     uint8
	Padding              [3]byte
	ValidLifetime        uint32
	PreferredLifetime    uint32
	Metric               uint32
	Protocol             uint32
	Loopback             uint8
	AutoconfigureAddress uint8
	Publish              uint8
	Immortal             uint8
	Age                  uint32
	Origin               uint32
}

func collectEffectiveRoutes(ctx context.Context, target model.Target, paths []PathObservation, adapters []AdapterObservation) ([]RouteObservation, []ObservationIssue) {
	addresses := make(map[string]netip.Addr)
	if ip, ok := parseNetip(target.LiteralIP); ok {
		addresses[PathApplicationDirect] = ip
	} else if len(target.ResolvedAddresses) > 0 {
		if ip, ok := parseNetip(target.ResolvedAddresses[0]); ok {
			addresses[PathApplicationDirect] = ip
		}
	}
	for _, path := range paths {
		if path.Endpoint == "" {
			continue
		}
		host, _, err := net.SplitHostPort(path.Endpoint)
		if err != nil {
			continue
		}
		if ip, ok := parseNetip(host); ok {
			addresses[path.Name] = ip
			continue
		}
		if resolved, resolveErr := net.DefaultResolver.LookupNetIP(ctx, "ip", host); resolveErr == nil && len(resolved) > 0 {
			addresses[path.Name] = resolved[0].Unmap()
		}
	}
	byIndex := make(map[int]string, len(adapters))
	for _, adapter := range adapters {
		byIndex[adapter.Index] = adapter.Name
	}
	routes := make([]RouteObservation, 0)
	issues := make([]ObservationIssue, 0)
	for pathName, address := range addresses {
		row, err := bestRoute2(address)
		observation := RouteObservation{Path: pathName, Destination: address.String()}
		if err != nil {
			observation.Error = safeErrorString(err.Error())
			issues = append(issues, ObservationIssue{Subsystem: "route", Kind: "best_route", Error: observation.Error})
			routes = append(routes, observation)
			continue
		}
		observation.Available = true
		observation.InterfaceIndex = int(row.InterfaceIndex)
		observation.Interface = byIndex[observation.InterfaceIndex]
		observation.NextHop = sockaddrString(row.NextHop)
		routes = append(routes, observation)
	}
	return routes, issues
}

func parseNetip(value string) (netip.Addr, bool) {
	parsed, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, false
	}
	return parsed.Unmap(), true
}

func bestRoute2(address netip.Addr) (mibIPForwardRow2, error) {
	var destination sockaddrInet
	if address.Is4() {
		destination.Family = 2
		v4 := address.As4()
		copy(destination.Data[0:4], v4[:])
	} else {
		destination.Family = 23
		v6 := address.As16()
		copy(destination.Data[4:20], v6[:])
	}
	var row mibIPForwardRow2
	var selected sockaddrInet
	ret, _, _ := getBestRoute2.Call(0, 0, 0, uintptr(unsafe.Pointer(&destination)), 0, uintptr(unsafe.Pointer(&row)), uintptr(unsafe.Pointer(&selected)))
	if ret != 0 {
		return row, syscall.Errno(ret)
	}
	return row, nil
}

func sockaddrString(value sockaddrInet) string {
	switch value.Family {
	case 2:
		var bytes [4]byte
		copy(bytes[:], value.Data[0:4])
		return net.IP(bytes[:]).String()
	case 23:
		var bytes [16]byte
		copy(bytes[:], value.Data[4:20])
		return net.IP(bytes[:]).String()
	default:
		return ""
	}
}
