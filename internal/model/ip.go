package model

import "net/netip"

// NormalizeAddr returns the canonical representation of an IP address for
// model and evidence values. IPv4-mapped IPv6 addresses are represented as
// IPv4; genuine IPv6 addresses are returned unchanged.
func NormalizeAddr(address netip.Addr) netip.Addr {
	return address.Unmap()
}

// NormalizePrefix returns the canonical representation of an IP prefix. A
// mapped IPv6 prefix uses 96 bits for the IPv4-mapped prefix, so those bits are
// removed when the prefix becomes IPv4. Prefixes that cannot be represented as
// IPv4 without changing their network are left as IPv6 prefixes.
func NormalizePrefix(prefix netip.Prefix) netip.Prefix {
	if !prefix.IsValid() || !prefix.Addr().Is4In6() {
		return prefix
	}

	bits := prefix.Bits()
	switch {
	case bits >= 96:
		bits -= 96
	case bits > 32:
		// There is no equivalent IPv4 prefix for this partially specified
		// mapped IPv6 network.
		return prefix
	}

	return netip.PrefixFrom(prefix.Addr().Unmap(), bits).Masked()
}

// NormalizeTarget canonicalizes a literal IP in target.Host while preserving
// Target.URL, which records the endpoint supplied by the caller.
func NormalizeTarget(target Target) Target {
	if address, err := netip.ParseAddr(target.Host); err == nil {
		target.Host = NormalizeAddr(address).String()
	}
	return target
}
