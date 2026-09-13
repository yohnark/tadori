package orchestrate

import "testing"

func TestParseTarget(t *testing.T) {
	cases := []struct {
		name       string
		input      string
		wantHost   string
		wantPort   uint16
		wantScheme string
		wantErr    bool
	}{
		{name: "https default port", input: "https://example.com", wantHost: "example.com", wantPort: 443, wantScheme: "https"},
		{name: "http default port", input: "http://example.com", wantHost: "example.com", wantPort: 80, wantScheme: "http"},
		{name: "explicit port", input: "https://example.com:8443/path", wantHost: "example.com", wantPort: 8443, wantScheme: "https"},
		{name: "arbitrary host port", input: "example.com:9443", wantHost: "example.com", wantPort: 9443},
		{name: "IPv4 host port", input: "127.0.0.1:1", wantHost: "127.0.0.1", wantPort: 1},
		{name: "IPv6 host port", input: "[2001:db8::1]:9443", wantHost: "2001:db8::1", wantPort: 9443},
		{name: "mapped IPv4 literal", input: "http://[::ffff:10.0.10.10]:8080", wantHost: "10.0.10.10", wantPort: 8080, wantScheme: "http"},
		{name: "empty", input: "", wantErr: true},
		{name: "whitespace", input: " https://example.com", wantErr: true},
		{name: "unsupported scheme", input: "ftp://example.com", wantErr: true},
		{name: "missing host", input: "https:///path", wantErr: true},
		{name: "invalid port", input: "https://example.com:notaport", wantErr: true},
		{name: "host port missing brackets", input: "2001:db8::1:443", wantErr: true},
		{name: "host port zero", input: "example.com:0", wantErr: true},
		{name: "host port missing", input: "example.com", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target, err := ParseTarget(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseTarget(%q) = %+v, want error", tc.input, target)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTarget(%q) unexpected error: %v", tc.input, err)
			}
			if target.Host != tc.wantHost {
				t.Errorf("Host = %q, want %q", target.Host, tc.wantHost)
			}
			if target.Port != tc.wantPort {
				t.Errorf("Port = %d, want %d", target.Port, tc.wantPort)
			}
			if target.Scheme != tc.wantScheme {
				t.Errorf("Scheme = %q, want %q", target.Scheme, tc.wantScheme)
			}
			if tc.wantScheme != "" && target.URL != tc.input {
				t.Errorf("URL = %q, want %q", target.URL, tc.input)
			}
			if tc.wantScheme == "" && target.URL != "" {
				t.Errorf("host:port target URL = %q, want empty", target.URL)
			}
		})
	}
}
