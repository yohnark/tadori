package diagnosis

import (
	"sort"

	"github.com/yohnark/tadori/internal/model"
)

// Diagnose returns the deterministic interpretation of collected probe
// results. The returned slice is newly allocated and the input is never
// modified. At most one primary finding is returned, followed by an optional
// gateway finding when gateway failure is useful supporting evidence.
//
// A result's normalized FailureReason is authoritative. Status and Layer are
// used to recognize successful observations and to resolve contradictory
// observations; raw evidence is intentionally never decoded.
func Diagnose(probes []model.ProbeResult) []model.DiagnosticFinding {
	observations := normalize(probes)
	if len(observations) == 0 {
		return nil
	}

	// Rules are ordered from the earliest decisive boundary to the latest.
	// Keeping this as a slice (rather than ranging over a map) makes both
	// precedence and output stable.
	for _, rule := range rules {
		matches := matching(observations, rule.reason)
		if len(matches) == 0 || contradicted(matches[0].reason, observations) {
			continue
		}

		finding := makeFinding(rule.reason, matches)
		if rule.reason == model.FailureReasonGatewayUnreachable {
			return []model.DiagnosticFinding{finding}
		}

		// Gateway reachability is supporting evidence rather than a claim that
		// the gateway is necessarily the root cause. Preserve it as a second
		// machine-readable finding when a later decisive failure exists.
		gateway := matching(observations, model.FailureReasonGatewayUnreachable)
		if len(gateway) != 0 && !contradicted(gateway[0].reason, observations) {
			return []model.DiagnosticFinding{finding, makeFinding(model.FailureReasonGatewayUnreachable, gateway)}
		}
		return []model.DiagnosticFinding{finding}
	}

	// A gateway result is supporting evidence and can still be useful when no
	// decisive layer produced a finding.
	if gateway := matching(observations, model.FailureReasonGatewayUnreachable); len(gateway) != 0 && !contradicted(gateway[0].reason, observations) {
		return []model.DiagnosticFinding{makeFinding(model.FailureReasonGatewayUnreachable, gateway)}
	}

	return nil
}

// Findings is an explicit alias for callers that prefer the output-oriented
// name. It has the same pure and deterministic behavior as Diagnose.
func Findings(probes []model.ProbeResult) []model.DiagnosticFinding {
	return Diagnose(probes)
}

// Analyze is an alias for Diagnose retained as a discoverable interpretation
// entry point.
func Analyze(probes []model.ProbeResult) []model.DiagnosticFinding {
	return Diagnose(probes)
}

// DiagnoseReport returns a copy of report with Findings replaced by the
// interpretation of report.Probes. It does not change report status or raw
// probe evidence.
func DiagnoseReport(report model.DiagnosticReport) model.DiagnosticReport {
	report.Findings = Diagnose(report.Probes)
	return report
}

// Apply is a concise alias for DiagnoseReport.
func Apply(report model.DiagnosticReport) model.DiagnosticReport {
	return DiagnoseReport(report)
}

type rule struct {
	reason model.FailureReason
}

// This table is the diagnosis policy. Reasons in the same layer are ordered
// from more specific to less specific where the contract supplies that
// distinction (for example NXDOMAIN before resolver timeout).
var rules = []rule{
	{reason: model.FailureReasonInterfaceDown},
	{reason: model.FailureReasonNoIPAddress},
	{reason: model.FailureReasonNoRoute},
	{reason: model.FailureReasonInvalidRoute},
	{reason: model.FailureReasonDNSNXDomain},
	{reason: model.FailureReasonDNSNoAnswer},
	{reason: model.FailureReasonDNSTimeout},
	{reason: model.FailureReasonDNSResolverFailure},
	{reason: model.FailureReasonProxyConfigurationFailure},
	{reason: model.FailureReasonProxyUnavailable},
	{reason: model.FailureReasonProxyAuthenticationRequired},
	{reason: model.FailureReasonNetworkUnreachable},
	{reason: model.FailureReasonFirewallBlocked},
	{reason: model.FailureReasonTCPTimeout},
	{reason: model.FailureReasonTCPConnectionRefused},
	{reason: model.FailureReasonTCPConnectionReset},
	{reason: model.FailureReasonTLSHandshakeFailure},
	{reason: model.FailureReasonCertificateValidationFailure},
	{reason: model.FailureReasonHTTPStatusCode},
	{reason: model.FailureReasonHTTPFailure},
	{reason: model.FailureReasonProbeExecution},
}

type observation struct {
	result model.ProbeResult
	reason model.FailureReason
}

func normalize(probes []model.ProbeResult) []observation {
	observations := make([]observation, 0, len(probes))
	for _, result := range probes {
		reason := result.Interpretation.FailureReason
		if reason == "" {
			// FailureReasonNone is the canonical success value, but accepting
			// the zero value for a passed fixture keeps interpretation tolerant
			// of callers that only populate the required status and layer.
			if result.Status == model.ProbeStatusPassed {
				reason = model.FailureReasonNone
			} else {
				reason = model.FailureReasonUnknown
			}
		}
		observations = append(observations, observation{result: result, reason: reason})
	}
	return observations
}

func matching(observations []observation, reason model.FailureReason) []observation {
	matches := make([]observation, 0)
	for _, observation := range observations {
		if observation.reason == reason {
			matches = append(matches, observation)
		}
	}
	return matches
}

func makeFinding(reason model.FailureReason, matches []observation) model.DiagnosticFinding {
	layer, domain := semantics(reason)
	probeNames := make([]string, 0, len(matches))
	evidenceIDs := make([]string, 0)
	for _, match := range matches {
		if match.result.Name != "" {
			probeNames = append(probeNames, match.result.Name)
		}
		for _, evidence := range match.result.Evidence {
			if evidence.ID != "" {
				evidenceIDs = append(evidenceIDs, evidence.ID)
			}
		}
	}
	sort.Strings(probeNames)
	sort.Strings(evidenceIDs)
	return model.DiagnosticFinding{
		FailureReason: reason,
		Layer:         layer,
		FaultDomain:   domain,
		ProbeNames:    unique(probeNames),
		EvidenceIDs:   unique(evidenceIDs),
	}
}

func unique(values []string) []string {
	if len(values) < 2 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}

// semantics intentionally derives output boundaries from machine-readable
// FailureReason constants. It never examines probe names, raw errors, or
// presentation text.
func semantics(reason model.FailureReason) (model.Layer, model.FaultDomain) {
	switch reason {
	case model.FailureReasonInterfaceDown:
		return model.LayerInterface, model.FaultDomainLocal
	case model.FailureReasonNoIPAddress:
		return model.LayerIPConfiguration, model.FaultDomainLocal
	case model.FailureReasonNoRoute, model.FailureReasonInvalidRoute:
		return model.LayerRoute, model.FaultDomainRouting
	case model.FailureReasonGatewayUnreachable:
		return model.LayerGateway, model.FaultDomainGateway
	case model.FailureReasonDNSNXDomain, model.FailureReasonDNSNoAnswer,
		model.FailureReasonDNSTimeout, model.FailureReasonDNSResolverFailure:
		return model.LayerDNS, model.FaultDomainDNS
	case model.FailureReasonProxyConfigurationFailure,
		model.FailureReasonProxyUnavailable,
		model.FailureReasonProxyAuthenticationRequired:
		return model.LayerProxy, model.FaultDomainProxy
	case model.FailureReasonNetworkUnreachable:
		return model.LayerNetwork, model.FaultDomainNetwork
	case model.FailureReasonFirewallBlocked:
		return model.LayerNetwork, model.FaultDomainFirewall
	case model.FailureReasonTCPTimeout,
		model.FailureReasonTCPConnectionRefused,
		model.FailureReasonTCPConnectionReset:
		return model.LayerTCP, model.FaultDomainTransport
	case model.FailureReasonTLSHandshakeFailure,
		model.FailureReasonCertificateValidationFailure:
		return model.LayerTLS, model.FaultDomainTLS
	case model.FailureReasonHTTPStatusCode, model.FailureReasonHTTPFailure:
		return model.LayerHTTP, model.FaultDomainHTTP
	case model.FailureReasonProbeExecution:
		return model.LayerUnknown, model.FaultDomainUnknown
	default:
		return model.LayerUnknown, model.FaultDomainUnknown
	}
}

func contradicted(reason model.FailureReason, observations []observation) bool {
	// A normalized success at the same or a later boundary is stronger than a
	// contradictory failed observation. DNS is intentionally treated as its
	// own branch: a successful TCP connection does not prove hostname lookup
	// succeeded, and vice versa.
	for _, observation := range observations {
		if observation.result.Status != model.ProbeStatusPassed || observation.reason != model.FailureReasonNone {
			continue
		}
		layer := observation.result.Interpretation.Layer
		switch reason {
		case model.FailureReasonInterfaceDown, model.FailureReasonNoIPAddress,
			model.FailureReasonNoRoute, model.FailureReasonInvalidRoute,
			model.FailureReasonGatewayUnreachable, model.FailureReasonNetworkUnreachable,
			model.FailureReasonFirewallBlocked:
			if layer == model.LayerTCP || layer == model.LayerTLS || layer == model.LayerHTTP {
				return true
			}
		case model.FailureReasonDNSNXDomain, model.FailureReasonDNSNoAnswer,
			model.FailureReasonDNSTimeout, model.FailureReasonDNSResolverFailure:
			if layer == model.LayerDNS {
				return true
			}
		case model.FailureReasonProxyConfigurationFailure,
			model.FailureReasonProxyUnavailable,
			model.FailureReasonProxyAuthenticationRequired:
			if layer == model.LayerProxy {
				return true
			}
		case model.FailureReasonTCPTimeout, model.FailureReasonTCPConnectionRefused,
			model.FailureReasonTCPConnectionReset:
			if layer == model.LayerTCP || layer == model.LayerTLS || layer == model.LayerHTTP {
				return true
			}
		case model.FailureReasonTLSHandshakeFailure,
			model.FailureReasonCertificateValidationFailure:
			if layer == model.LayerTLS || layer == model.LayerHTTP {
				return true
			}
		case model.FailureReasonHTTPStatusCode, model.FailureReasonHTTPFailure:
			if layer == model.LayerHTTP {
				return true
			}
		case model.FailureReasonProbeExecution:
			// Generic execution errors are only useful when no normalized
			// success exists at all; do not let one stale error override proof
			// that the path works.
			if layer != model.LayerUnknown {
				return true
			}
		}
	}
	return false
}
