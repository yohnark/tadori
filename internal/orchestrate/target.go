// Package orchestrate wires the independently implemented probe packages,
// the diagnosis engine, and the report renderer into one end-to-end
// diagnostic run. It contains no probe logic, diagnosis rules, or
// presentation formatting of its own.
package orchestrate

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/yohnark/tadori/internal/model"
)

// ParseTarget normalizes a user-supplied endpoint into a model.Target. It
// accepts ordinary HTTP(S) URLs and arbitrary host:port endpoints. A bare
// host without a port is intentionally rejected because transport-aware
// diagnosis must not invent an application port.
func ParseTarget(raw string) (model.Target, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return model.Target{}, fmt.Errorf("diagnose target is empty")
	}
	if trimmed != raw {
		return model.Target{}, fmt.Errorf("diagnose target must not contain surrounding whitespace")
	}

	if !strings.Contains(raw, "://") {
		// url.Parse treats host:port input as a URI with an opaque scheme.
		// Prefer the unambiguous host:port grammar, but retain the existing
		// unsupported-scheme diagnostic for inputs such as
		// javascript:alert(1).
		if _, port, splitErr := net.SplitHostPort(raw); splitErr == nil {
			if _, portErr := parseTargetPort(port); portErr == nil {
				return parseHostPortTarget(raw)
			}
		}
		if parsed, parseErr := url.Parse(raw); parseErr == nil && parsed.Scheme != "" && parsed.Scheme != "http" && parsed.Scheme != "https" {
			return model.Target{}, fmt.Errorf("unsupported diagnose target scheme %q: must be http or https", parsed.Scheme)
		}
		return parseHostPortTarget(raw)
	}

	u, err := url.Parse(raw)
	if err != nil {
		return model.Target{}, fmt.Errorf("parse diagnose target: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return model.Target{}, fmt.Errorf("unsupported diagnose target scheme %q: must be http or https", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return model.Target{}, fmt.Errorf("diagnose target must include a host")
	}

	port := u.Port()
	var portNumber uint16
	if port != "" {
		portNumber, err = parseTargetPort(port)
		if err != nil {
			return model.Target{}, err
		}
	} else if u.Scheme == "https" {
		portNumber = 443
	} else {
		portNumber = 80
	}

	return model.Target{
		URL:    raw,
		Scheme: u.Scheme,
		Host:   canonicalHost(host),
		Port:   portNumber,
		Path:   u.EscapedPath(),
	}, nil
}

func parseHostPortTarget(raw string) (model.Target, error) {
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		return model.Target{}, fmt.Errorf("parse diagnose target host:port: %w", err)
	}
	if host == "" {
		return model.Target{}, fmt.Errorf("diagnose target must include a host")
	}
	portNumber, err := parseTargetPort(port)
	if err != nil {
		return model.Target{}, err
	}
	return model.Target{Host: canonicalHost(host), Port: portNumber}, nil
}

func parseTargetPort(port string) (uint16, error) {
	if port == "" {
		return 0, fmt.Errorf("diagnose target must include a port between 1 and 65535")
	}
	value, err := strconv.ParseUint(port, 10, 16)
	if err != nil || value == 0 {
		if err == nil {
			err = fmt.Errorf("port must be between 1 and 65535")
		}
		return 0, fmt.Errorf("diagnose target has an invalid port: %w", err)
	}
	return uint16(value), nil
}

func canonicalHost(host string) string {
	if address, err := netip.ParseAddr(host); err == nil {
		return model.NormalizeAddr(address).String()
	}
	return host
}
