package orchestrate

import (
	"reflect"
	"strings"
	"testing"

	"github.com/yohnark/tadori/internal/model"
)

func TestCanonicalTargetParsing(t *testing.T) {
	cases := []struct {
		name          string
		input         string
		service       model.ServiceProfileID
		port          *uint16
		wantIdentity  string
		wantLiteral   string
		wantService   model.ServiceProfileID
		wantProtocol  model.ApplicationProtocol
		wantTransport model.TransportProtocol
		wantPort      uint16
		wantResource  string
		wantErr       string
	}{
		{name: "https default port", input: "https://example.com/path", wantIdentity: "example.com", wantService: model.ServiceProfileHTTPS, wantProtocol: model.ApplicationProtocolHTTPS, wantTransport: model.TransportTCP, wantPort: 443, wantResource: "/path"},
		{name: "http default port", input: "http://example.com", wantIdentity: "example.com", wantService: model.ServiceProfileHTTP, wantProtocol: model.ApplicationProtocolHTTP, wantTransport: model.TransportTCP, wantPort: 80},
		{name: "URL explicit non-default port", input: "https://example.com:8443/foo", wantIdentity: "example.com", wantService: model.ServiceProfileHTTPS, wantPort: 8443, wantResource: "/foo"},
		{name: "hostname only", input: "example.com", wantIdentity: "example.com", wantService: model.ServiceProfileHTTP, wantPort: 80},
		{name: "hostname port remains ambiguous", input: "example.com:443", wantIdentity: "example.com", wantService: model.ServiceProfileHTTP, wantProtocol: model.ApplicationProtocolHTTP, wantPort: 443},
		{name: "IPv4", input: "10.0.10.25", wantIdentity: "10.0.10.25", wantLiteral: "10.0.10.25", wantService: model.ServiceProfileHTTP, wantPort: 80},
		{name: "IPv4 explicit port", input: "10.0.10.25:445", wantIdentity: "10.0.10.25", wantLiteral: "10.0.10.25", wantService: model.ServiceProfileHTTP, wantPort: 445},
		{name: "IPv6 literal", input: "2001:db8::1", wantIdentity: "2001:db8::1", wantLiteral: "2001:db8::1", wantService: model.ServiceProfileHTTP, wantPort: 80},
		{name: "IPv6 link-local literal", input: "fe80::1", wantIdentity: "fe80::1", wantLiteral: "fe80::1", wantService: model.ServiceProfileHTTP, wantPort: 80},
		{name: "IPv6 literal explicit port", input: "[2001:db8::1]:8443", wantIdentity: "2001:db8::1", wantLiteral: "2001:db8::1", wantService: model.ServiceProfileHTTP, wantPort: 8443},
		{name: "UNC share", input: `\fileserver01\share`, wantIdentity: "fileserver01", wantService: model.ServiceProfileSMB, wantProtocol: model.ApplicationProtocolSMB, wantPort: 445, wantResource: "/share"},
		{name: "explicit SMB port override", input: "fileserver01", service: model.ServiceProfileSMB, port: uint16Pointer(1445), wantIdentity: "fileserver01", wantService: model.ServiceProfileSMB, wantPort: 1445},
		{name: "DNS has both transports", input: "resolver.example", service: model.ServiceProfileDNS, wantIdentity: "resolver.example", wantService: model.ServiceProfileDNS, wantTransport: model.TransportUDPAndTCP, wantPort: 53},
		{name: "conflicting URL service", input: "https://example.com", service: model.ServiceProfileHTTP, wantErr: "conflicting explicit service"},
		{name: "conflicting URL and API port", input: "https://example.com:8443", port: uint16Pointer(9443), wantErr: "conflicting explicit ports"},
		{name: "custom service requires port", input: "example.com", service: model.ServiceProfileCustomTCP, wantErr: "requires an explicit port"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target, err := model.ParseTarget(model.TargetIntent{Input: tc.input, Service: tc.service, Port: tc.port})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("ParseTarget() error = %v, want substring %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTarget() error = %v", err)
			}
			if target.OriginalInput != tc.input {
				t.Errorf("OriginalInput = %q, want %q", target.OriginalInput, tc.input)
			}
			if target.RequestedIdentity != tc.wantIdentity || target.LiteralIP != tc.wantLiteral {
				t.Errorf("identity/literal = %q/%q, want %q/%q", target.RequestedIdentity, target.LiteralIP, tc.wantIdentity, tc.wantLiteral)
			}
			if target.Service.ID != tc.wantService || target.Port != tc.wantPort {
				t.Errorf("service/port = %q/%d, want %q/%d", target.Service.ID, target.Port, tc.wantService, tc.wantPort)
			}
			if tc.wantProtocol != "" && target.ApplicationProtocol != tc.wantProtocol {
				t.Errorf("application protocol = %q, want %q", target.ApplicationProtocol, tc.wantProtocol)
			}
			if tc.wantTransport != "" && target.TransportProtocol != tc.wantTransport {
				t.Errorf("transport = %q, want %q", target.TransportProtocol, tc.wantTransport)
			}
			if target.Resource != tc.wantResource {
				t.Errorf("resource = %q, want %q", target.Resource, tc.wantResource)
			}
		})
	}
}

func TestServiceProfilesAreExtensibleAndPortDefaultsAreProfileOwned(t *testing.T) {
	profiles := model.ServiceProfiles()
	if len(profiles) < 8 {
		t.Fatalf("profiles = %d, want at least 8", len(profiles))
	}
	for _, profile := range profiles {
		if profile.ID == "" || profile.Label == "" || len(profile.ApplicableTransports) == 0 {
			t.Errorf("incomplete profile: %#v", profile)
		}
	}
	target, err := model.ParseTarget(model.TargetIntent{Input: "server.example", Service: model.ServiceProfileSMB, Port: uint16Pointer(1445)})
	if err != nil {
		t.Fatal(err)
	}
	if target.Port != 1445 || target.Service.DefaultPort != 445 {
		t.Fatalf("explicit service port override = %#v", target)
	}
	if !reflect.DeepEqual(target.ResolvedAddresses, []string(nil)) {
		t.Fatalf("parser populated resolution facts: %#v", target.ResolvedAddresses)
	}
}

func TestLiteralTargetDoesNotRequireNameResolution(t *testing.T) {
	target, err := model.ParseTarget(model.TargetIntent{Input: "10.0.10.25:445"})
	if err != nil {
		t.Fatal(err)
	}
	if target.LiteralIP == "" {
		t.Fatal("literal IP was not recorded")
	}
	if target.RequestedIdentity != target.LiteralIP {
		t.Fatalf("literal identity = %q, literal = %q", target.RequestedIdentity, target.LiteralIP)
	}
	if !target.MatchesAddress("10.0.10.25") {
		t.Fatal("literal target did not match its concrete address")
	}
}

func uint16Pointer(value uint16) *uint16 { return &value }
