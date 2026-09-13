//go:build windows

package dns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"syscall"

	"github.com/yohnark/tadori/internal/model"
	"github.com/yohnark/tadori/internal/probe/interfacecfg"
	"golang.org/x/sys/windows"
)

const dnsFreeRecordList = 1

type windowsDNSResolver struct{}

type windowsDNSError struct {
	status error
	kind   string
}

func (e *windowsDNSError) Error() string {
	return fmt.Sprintf("Windows DNS query failed (%s): %v", e.kind, e.status)
}

func (e *windowsDNSError) Unwrap() error { return e.status }

func (e *windowsDNSError) DNSKind() string { return e.kind }

func (windowsDNSResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	queryType := uint16(0)
	switch network {
	case "ip4":
		queryType = windows.DNS_TYPE_A
	case "ip6":
		queryType = windows.DNS_TYPE_AAAA
	default:
		return nil, fmt.Errorf("unsupported Windows DNS address family %q", network)
	}
	type queryResult struct {
		addresses []netip.Addr
		err       error
	}
	results := make(chan queryResult, 1)
	go func() {
		var records *windows.DNSRecord
		status := windows.DnsQuery(host, queryType, 0, nil, &records, nil)
		if records != nil {
			defer windows.DnsRecordListFree(records, dnsFreeRecordList)
		}
		if status != nil {
			results <- queryResult{err: &windowsDNSError{status: status, kind: windowsDNSQueryErrorKind(status)}}
			return
		}
		addresses := parseWindowsDNSRecords(records, queryType)
		if len(addresses) == 0 {
			results <- queryResult{err: &windowsDNSError{status: windows.DNS_INFO_NO_RECORDS, kind: "no_answer"}}
			return
		}
		results <- queryResult{addresses: addresses}
	}()
	select {
	case result := <-results:
		return result.addresses, result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (windowsDNSResolver) EffectivePath(context.Context, string) (model.NameResolutionPath, error) {
	return model.NameResolutionPath{
		State:       model.NameResolutionPathEffective,
		Mechanism:   model.NameResolutionMechanismDNS,
		Certainty:   model.NameResolutionCertaintyObserved,
		Provenance:  "Windows DNS Client via dnsapi.DnsQuery_W; resolver server and interface are not exposed by this API",
		EvidenceIDs: []string{"dns/resolution"},
	}, nil
}

func parseWindowsDNSRecords(records *windows.DNSRecord, queryType uint16) []netip.Addr {
	addresses := make([]netip.Addr, 0)
	for record := records; record != nil; record = record.Next {
		if record.Type != queryType {
			continue
		}
		var address netip.Addr
		if queryType == windows.DNS_TYPE_A && len(record.Data) >= 4 {
			address = netip.AddrFrom4([4]byte{record.Data[0], record.Data[1], record.Data[2], record.Data[3]})
		}
		if queryType == windows.DNS_TYPE_AAAA && len(record.Data) >= 16 {
			var bytes [16]byte
			copy(bytes[:], record.Data[:16])
			address = netip.AddrFrom16(bytes)
		}
		if address.IsValid() {
			address = model.NormalizeAddr(address)
			duplicate := false
			for _, existing := range addresses {
				if existing == address {
					duplicate = true
					break
				}
			}
			if !duplicate {
				addresses = append(addresses, address)
			}
		}
	}
	return addresses
}

func windowsDNSQueryErrorKind(err error) string {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return "resolver_failure"
	}
	switch errno {
	case windows.DNS_ERROR_RCODE_NAME_ERROR, windows.DNS_ERROR_NAME_DOES_NOT_EXIST:
		return "not_found"
	case windows.DNS_INFO_NO_RECORDS, windows.DNS_ERROR_RCODE_NXRRSET:
		return "no_answer"
	default:
		return "resolver_failure"
	}
}

func newSystemResolver() Resolver { return windowsDNSResolver{} }

func newSystemEnvironmentProvider() EnvironmentProvider { return windowsEnvironmentProvider{} }

func systemResolutionSource() string { return "dnsapi.DnsQuery_W" }

func systemResolverSource(path string) string {
	if path != "" {
		return path
	}
	return "GetAdaptersAddresses"
}

func systemResolverAddresses(ctx context.Context, path string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, nil
			}
			return nil, err
		}
		return ParseResolverAddresses(data), nil
	}
	snapshot, err := interfacecfg.Collect(ctx)
	if err != nil {
		return nil, err
	}
	addresses := make([]string, 0, len(snapshot.DNSServers))
	for _, address := range snapshot.DNSServers {
		addresses = append(addresses, model.NormalizeAddr(address).String())
	}
	return normalizeResolverAddresses(addresses), nil
}

type windowsEnvironmentProvider struct{}

func (windowsEnvironmentProvider) ResolutionEnvironment(ctx context.Context) (ResolutionEnvironment, error) {
	snapshot, err := interfacecfg.Collect(ctx)
	environment := ResolutionEnvironment{
		CandidateSuffixes: append([]string(nil), snapshot.DNSSuffixes...),
		SearchList:        append([]string(nil), snapshot.SearchList...),
		NRPT:              append([]model.NameResolutionPolicyRule(nil), snapshot.NRPT...),
		HostsFileEntries:  append([]model.NameResolutionHostEntry(nil), snapshot.HostsFileEntries...),
		Source:            snapshot.Source,
		ResolverError:     snapshot.ResolverError,
		PolicyError:       snapshot.NRPTError,
		HostsFileError:    snapshot.HostsFileError,
	}
	if err != nil {
		environment.Error = err.Error()
	}
	for _, iface := range snapshot.Interfaces {
		resolutionInterface := ResolutionInterface{
			Index:          iface.Index,
			Name:           iface.Name,
			Up:             iface.Up,
			Loopback:       iface.Loopback,
			VirtualAdapter: iface.VirtualAdapter,
			VPN:            iface.VPN,
			DNSSuffix:      iface.DNSSuffix,
			DNSSearchList:  append([]string(nil), iface.DNSSearchList...),
		}
		for _, server := range iface.DNSServers {
			resolutionInterface.DNSServers = append(resolutionInterface.DNSServers, model.NormalizeAddr(server).String())
		}
		environment.Interfaces = append(environment.Interfaces, resolutionInterface)
	}
	return environment, err
}
