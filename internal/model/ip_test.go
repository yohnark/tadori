package model

import (
	"net/netip"
	"testing"
)

func TestNormalizeAddr(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "IPv4", input: "10.0.10.10", want: "10.0.10.10"},
		{name: "IPv4-mapped IPv6", input: "::ffff:10.0.10.10", want: "10.0.10.10"},
		{name: "IPv4 loopback", input: "::ffff:127.0.0.1", want: "127.0.0.1"},
		{name: "genuine IPv6", input: "2001:db8::10", want: "2001:db8::10"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := NormalizeAddr(netip.MustParseAddr(test.input)).String()
			if got != test.want {
				t.Fatalf("NormalizeAddr(%q) = %q, want %q", test.input, got, test.want)
			}
		})
	}
}

func TestNormalizePrefixPreservesEquivalentPrefixLength(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "mapped IPv4 network", input: "::ffff:10.0.10.10/120", want: "10.0.10.0/24"},
		{name: "mapped IPv4 default", input: "::ffff:0.0.0.0/96", want: "0.0.0.0/0"},
		{name: "mapped IPv6 partial /24", input: "::ffff:10.0.10.10/24", want: "::ffff:10.0.10.10/24"},
		{name: "mapped IPv6 partial /95", input: "::ffff:10.0.10.10/95", want: "::ffff:10.0.10.10/95"},
		{name: "genuine IPv6 network", input: "2001:db8::10/64", want: "2001:db8::10/64"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := NormalizePrefix(netip.MustParsePrefix(test.input)).String()
			if got != test.want {
				t.Fatalf("NormalizePrefix(%q) = %q, want %q", test.input, got, test.want)
			}
		})
	}
}
