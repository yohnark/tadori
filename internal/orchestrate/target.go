// Package orchestrate wires the independently implemented probe packages,
// the diagnosis engine, and the report renderer into one end-to-end
// diagnostic run. It contains no probe logic, diagnosis rules, or
// presentation formatting of its own.
package orchestrate

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/yohnark/tadori/internal/model"
)

// ParseTarget normalizes a user-supplied endpoint into a model.Target. Only
// http and https schemes are accepted, matching the http probe's contract.
func ParseTarget(raw string) (model.Target, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return model.Target{}, fmt.Errorf("diagnose target is empty")
	}
	if trimmed != raw {
		return model.Target{}, fmt.Errorf("diagnose target must not contain surrounding whitespace")
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
		value, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return model.Target{}, fmt.Errorf("diagnose target has an invalid port: %w", err)
		}
		portNumber = uint16(value)
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

func canonicalHost(host string) string {
	if address, err := netip.ParseAddr(host); err == nil {
		return model.NormalizeAddr(address).String()
	}
	return host
}
