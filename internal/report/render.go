// Package report contains presentation-only projections of the canonical
// diagnostic model.  It deliberately does not run probes or interpret their
// observations.
package report

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/yohnark/tadori/internal/model"
)

// MarshalJSON returns the canonical JSON representation of report.
//
// The model's JSON tags and field order are the canonical contract. Timestamp
// marshalers normalize report, probe, and evidence timestamps to UTC without
// changing the supplied report or inspecting Evidence.Raw.
func MarshalJSON(report model.DiagnosticReport) ([]byte, error) {
	return MarshalExportJSON(report)
}

// RenderJSON is an explicit presentation-oriented alias for MarshalJSON.
// Callers that render more than one format can use the same vocabulary for
// both projections.
func RenderJSON(report model.DiagnosticReport) ([]byte, error) {
	return MarshalJSON(report)
}

// JSON is a short alias for RenderJSON for callers that select the output
// format at the call site.
func JSON(report model.DiagnosticReport) ([]byte, error) {
	return RenderJSON(report)
}

// WriteJSON writes the canonical JSON representation to w without appending a
// newline.  The absence of a newline keeps the returned document identical to
// MarshalJSON and leaves stream framing to the caller.
func WriteJSON(w io.Writer, report model.DiagnosticReport) error {
	return writeExportJSON(w, report)
}

// RenderHuman returns a concise, deterministic terminal projection of report.
// All interpretation and finding values are copied from the structured model;
// no meaning is inferred from raw evidence or from error text.  Slices are
// traversed in their supplied order so probe/evidence/finding ordering is
// retained.
func RenderHuman(report model.DiagnosticReport) string {
	var out strings.Builder

	fmt.Fprintf(&out, "Status: %s\n", report.Status)
	fmt.Fprintf(&out, "Target: %s\n", formatTarget(report.Target))
	if report.Target.Service.Label != "" {
		fmt.Fprintf(&out, "Service: %s\n", report.Target.Service.Label)
	}
	if report.Target.TransportProtocol != "" {
		fmt.Fprintf(&out, "Transport: %s\n", report.Target.TransportProtocol)
	}
	if report.Target.Port != 0 {
		fmt.Fprintf(&out, "Port: %d\n", report.Target.Port)
	}
	if report.Target.Resource != "" {
		fmt.Fprintf(&out, "Resource: %s\n", report.Target.Resource)
	}
	if report.Target.SelectedEndpoint != nil {
		fmt.Fprintf(&out, "Tadori probe candidate: %s\n", formatEndpoint(*report.Target.SelectedEndpoint))
	}
	if report.Target.TestedEndpoint != nil {
		fmt.Fprintf(&out, "Transport-tested endpoint: %s\n", formatEndpoint(*report.Target.TestedEndpoint))
	}
	if report.StartedAt != nil || report.CompletedAt != nil {
		out.WriteString("Report timing:")
		if report.StartedAt != nil {
			fmt.Fprintf(&out, " started_at=%s", strconv.Quote(formatTimestamp(*report.StartedAt)))
		}
		if report.CompletedAt != nil {
			fmt.Fprintf(&out, " completed_at=%s", strconv.Quote(formatTimestamp(*report.CompletedAt)))
		}
		out.WriteByte('\n')
	}

	renderNameResolution(&out, report)

	out.WriteString("Probes:\n")
	if len(report.Probes) == 0 {
		out.WriteString("  (none)\n")
	} else {
		for i, probe := range report.Probes {
			fmt.Fprintf(&out, "  %d. %s: %s (%s)\n", i+1, probe.Name, probe.Status, formatTiming(probe.Timing))
			fmt.Fprintf(&out, "     interpretation: failure_reason=%s layer=%s fault_domain=%s\n",
				probe.Interpretation.FailureReason,
				probe.Interpretation.Layer,
				probe.Interpretation.FaultDomain,
			)
		}
	}

	if report.Target.NetworkContext != nil {
		renderNetworkContext(&out, *report.Target.NetworkContext)
	}

	if hasEnterprisePolicyObservation(report.Observations.EnterprisePolicy) {
		renderEnterprisePolicy(&out, report.Observations.EnterprisePolicy)
	}

	out.WriteString("Evidence:\n")
	evidenceCount := 0
	for _, probe := range report.Probes {
		for _, evidence := range probe.Evidence {
			evidenceCount++
			fmt.Fprintf(&out, "  - %s: kind=%s", evidence.ID, evidence.Kind)
			if evidence.Source != "" {
				fmt.Fprintf(&out, " source=%s", evidence.Source)
			}
			if evidence.CapturedAt != nil {
				fmt.Fprintf(&out, " captured_at=%s", formatTimestamp(*evidence.CapturedAt))
			}
			// Raw is intentionally written as supplied.  It is evidence, not
			// an input to renderer policy.
			fmt.Fprintf(&out, " raw=%s\n", evidence.Raw)
		}
	}
	if evidenceCount == 0 {
		out.WriteString("  (none)\n")
	}

	out.WriteString("Path:\n")
	out.WriteString("  note: observed responders and inferred segments are not exact physical topology\n")
	pathCount := 0
	for _, probe := range report.Probes {
		for _, evidence := range probe.Evidence {
			if evidence.Kind != model.EvidenceKindPathObservation {
				continue
			}
			observation, err := model.DecodePathObservation(evidence)
			if err != nil {
				continue
			}
			pathCount++
			fmt.Fprintf(&out, "  - protocol=%s destination=%s port_aware=%t destination_reached=%t\n",
				observation.Protocol,
				formatPathDestination(observation.Destination, observation.DestinationPort),
				observation.PortAware,
				observation.DestinationReached,
			)
			for _, hop := range observation.Hops {
				fmt.Fprintf(&out, "    ttl=%d state=%s", hop.TTL, hop.State)
				if len(hop.Responders) > 0 {
					responders := make([]string, 0, len(hop.Responders))
					for _, responder := range hop.Responders {
						value := responder.Address
						if responder.Response != "" {
							value += ":" + responder.Response
						}
						responders = append(responders, value)
					}
					fmt.Fprintf(&out, " responders=%s", strings.Join(responders, ","))
				}
				out.WriteByte('\n')
			}
			for _, segment := range observation.Segments {
				fmt.Fprintf(&out, "    segment=%s ttl=%d-%d\n", segment.Kind, segment.FromTTL, segment.ToTTL)
			}
		}
	}
	if pathCount == 0 {
		out.WriteString("  (none)\n")
	}

	out.WriteString("Findings:\n")
	if len(report.Findings) == 0 {
		out.WriteString("  (none)\n")
	} else {
		for _, finding := range report.Findings {
			fmt.Fprintf(&out, "  - failure_reason=%s layer=%s fault_domain=%s",
				finding.FailureReason,
				finding.Layer,
				finding.FaultDomain,
			)
			if len(finding.ProbeNames) > 0 {
				fmt.Fprintf(&out, " probes=%s", strings.Join(finding.ProbeNames, ","))
			}
			if len(finding.EvidenceIDs) > 0 {
				fmt.Fprintf(&out, " evidence=%s", strings.Join(finding.EvidenceIDs, ","))
			}
			out.WriteByte('\n')
		}
	}

	return out.String()
}

func renderNameResolution(out *strings.Builder, diagnosticReport model.DiagnosticReport) {
	out.WriteString("Name Resolution:\n")
	observation := firstNameResolution(diagnosticReport)
	if observation == nil {
		out.WriteString("  (none)\n")
		return
	}
	fmt.Fprintf(out, "  Requested name: %s\n", valueOrUnavailable(observation.RequestedName))
	if observation.EffectivePath == nil {
		out.WriteString("  Resolution path: not observed\n")
	} else {
		fmt.Fprintf(out, "  Resolution path: %s\n", nameResolutionPathLabel(*observation.EffectivePath))
		fmt.Fprintf(out, "  Certainty: %s\n", valueOrUnavailable(string(observation.EffectivePath.Certainty)))
		fmt.Fprintf(out, "  Provenance: %s\n", valueOrUnavailable(observation.EffectivePath.Provenance))
		fmt.Fprintf(out, "  Interface: %s\n", valueOrUnavailable(observation.EffectivePath.Interface))
		fmt.Fprintf(out, "  Resolver: %s\n", valueOrUnavailable(observation.EffectivePath.Resolver))
		fmt.Fprintf(out, "  Policy: %s\n", nameResolutionPolicyLabel(*observation.EffectivePath))
	}
	if len(observation.A) > 0 {
		fmt.Fprintf(out, "  Answers A: %s\n", strings.Join(observation.A, ", "))
	} else {
		out.WriteString("  Answers A: (none)\n")
	}
	if len(observation.AAAA) > 0 {
		fmt.Fprintf(out, "  Answers AAAA: %s\n", strings.Join(observation.AAAA, ", "))
	} else {
		out.WriteString("  Answers AAAA: (none)\n")
	}
	fmt.Fprintf(out, "  Resolver representative answer (not OS/application selection): %s\n", valueOrUnavailable(observation.SelectedAddress))
	if len(observation.CandidateNames) > 0 {
		fmt.Fprintf(out, "  Candidate names: %s\n", strings.Join(observation.CandidateNames, ", "))
	}
	if len(observation.CandidateSuffixes) > 0 {
		fmt.Fprintf(out, "  Search suffixes: %s\n", strings.Join(observation.CandidateSuffixes, ", "))
	}
	if len(observation.CandidateNamespaces) > 0 {
		fmt.Fprintf(out, "  Candidate namespaces: %s\n", strings.Join(observation.CandidateNamespaces, ", "))
	}
	if len(observation.Limitations) > 0 {
		fmt.Fprintf(out, "  Limitations: %s\n", strings.Join(observation.Limitations, " | "))
	}
	if len(observation.Paths) > 0 {
		out.WriteString("  Candidate paths:\n")
		for _, path := range observation.Paths {
			if path.State == model.NameResolutionPathEffective {
				continue
			}
			fmt.Fprintf(out, "    - state=%s mechanism=%s resolver=%s interface=%s namespace=%s certainty=%s\n",
				path.State, path.Mechanism, valueOrUnavailable(path.Resolver), valueOrUnavailable(path.Interface), valueOrUnavailable(path.Namespace), valueOrUnavailable(string(path.Certainty)))
		}
	}
}

func hasEnterprisePolicyObservation(observation model.EnterprisePolicyObservation) bool {
	if observation.State != "" || observation.RequestedIdentity != "" || observation.Unsupported ||
		observation.EffectiveDecisionKnown || observation.EffectiveDecisionDiverges || len(observation.Paths) > 0 {
		return true
	}
	for _, source := range []model.EnterpriseProxySourceObservation{observation.WinHTTP, observation.WinINET} {
		if source.Configuration.Certainty != "" || source.Effective.Observed || source.PAC.Configured {
			return true
		}
	}
	return false
}

func renderEnterprisePolicy(out *strings.Builder, observation model.EnterprisePolicyObservation) {
	out.WriteString("Enterprise Proxy Decisions:\n")
	if observation.RequestedIdentity != "" {
		fmt.Fprintf(out, "  Target identity: %s\n", observation.RequestedIdentity)
	}
	fmt.Fprintf(out, "  Effective decision divergence: %s\n", knownBoolText(observation.EffectiveDecisionDiverges, observation.EffectiveDecisionKnown))
	renderEnterpriseSource(out, "WinHTTP", observation.WinHTTP)
	renderEnterpriseSource(out, "WinINET", observation.WinINET)
}

func renderEnterpriseSource(out *strings.Builder, label string, source model.EnterpriseProxySourceObservation) {
	fmt.Fprintf(out, "  %s:\n", label)
	fmt.Fprintf(out, "    configuration: %s\n", valueOrUnavailable(source.Configuration.State))
	fmt.Fprintf(out, "    PAC URL: %s\n", valueOrUnavailable(firstNonEmpty(source.Configuration.PACURL, source.PAC.URL)))
	fmt.Fprintf(out, "    effective decision: %s\n", valueOrUnavailable(source.Effective.Decision))
	fmt.Fprintf(out, "    effective mode: %s\n", valueOrUnavailable(source.Effective.Mode))
	fmt.Fprintf(out, "    effective endpoint: %s\n", valueOrUnavailable(source.Effective.Endpoint))
	known := source.Effective.Observed || source.Effective.ResolutionAttempted
	fmt.Fprintf(out, "    target-specific result observed: %s\n", knownBoolText(source.Effective.Observed, known))
	fmt.Fprintf(out, "    resolution succeeded: %s\n", knownBoolText(source.Effective.ResolutionOK, known))
	fmt.Fprintf(out, "    bypass matched: %s\n", knownBoolText(source.Effective.BypassMatched, known))
	for _, endpoint := range source.EndpointReachability {
		fmt.Fprintf(out, "    endpoint observation: endpoint=%s reachability=%s connect=%s status=%d\n",
			valueOrUnavailable(endpoint.Endpoint), valueOrUnavailable(endpoint.Reachability), valueOrUnavailable(endpoint.ConnectOutcome), endpoint.StatusCode)
	}
}

func knownBoolText(value, known bool) string {
	if !known {
		return "not observable"
	}
	return strconv.FormatBool(value)
}

func formatEndpoint(endpoint model.Endpoint) string {
	value := net.JoinHostPort(endpoint.Address, strconv.Itoa(int(endpoint.Port)))
	if endpoint.Family != "" {
		value += " [" + string(endpoint.Family) + "]"
	}
	if endpoint.SelectionReason != "" {
		value += " (" + string(endpoint.SelectionReason) + ")"
	}
	return value
}

func firstNameResolution(diagnosticReport model.DiagnosticReport) *model.NameResolutionObservation {
	for _, probe := range diagnosticReport.Probes {
		if probe.NameResolution != nil {
			return probe.NameResolution
		}
	}
	return nil
}

func nameResolutionPathLabel(path model.NameResolutionPath) string {
	if path.Mechanism == model.NameResolutionMechanismLiteralIP {
		return "Literal IP"
	}
	if path.Mechanism == model.NameResolutionMechanismHostsFile {
		return "Hosts file candidate"
	}
	if path.VPN {
		return "VPN / Corporate DNS"
	}
	if path.Mechanism == model.NameResolutionMechanismDNS {
		return "System DNS client"
	}
	return string(path.Mechanism)
}

func nameResolutionPolicyLabel(path model.NameResolutionPath) string {
	parts := make([]string, 0, 3)
	if path.Namespace != "" {
		parts = append(parts, path.Namespace)
	}
	if path.PolicySource != "" {
		parts = append(parts, path.PolicySource)
	}
	if path.PolicyRule != "" {
		parts = append(parts, path.PolicyRule)
	}
	if len(parts) == 0 {
		return "not observed"
	}
	return strings.Join(parts, " / ")
}

func valueOrUnavailable(value string) string {
	if value == "" {
		return "not observable"
	}
	return value
}

// RenderTerminal is the terminal-rendering name retained for callers that
// distinguish terminal output from other human-readable projections.
func RenderTerminal(report model.DiagnosticReport) string {
	return RenderHuman(report)
}

// Human is a short alias for RenderHuman.
func Human(report model.DiagnosticReport) string {
	return RenderHuman(report)
}

// WriteHuman writes the terminal projection to w without changing it.  A
// newline is part of the human-readable document returned by RenderHuman.
func WriteHuman(w io.Writer, report model.DiagnosticReport) error {
	if w == nil {
		return errors.New("report: nil human-readable writer")
	}
	_, err := io.WriteString(w, RenderHuman(report))
	return err
}

// WriteTerminal is the writer form of RenderTerminal.
func WriteTerminal(w io.Writer, report model.DiagnosticReport) error {
	return WriteHuman(w, report)
}

func formatTarget(target model.Target) string {
	if target.RequestedIdentity != "" {
		return target.RequestedIdentity
	}
	if target.OriginalInput != "" {
		return target.OriginalInput
	}
	return "(unspecified)"
}

func renderNetworkContext(out *strings.Builder, context model.NetworkContext) {
	out.WriteString("Network Context:\n")
	fmt.Fprintf(out, "  Network scope: %s\n", networkScopeLabel(context.NetworkScope))
	if context.RequestedIdentity != "" {
		fmt.Fprintf(out, "  Requested identity: %s\n", context.RequestedIdentity)
	}
	if context.SelectedDestinationAddress != "" {
		fmt.Fprintf(out, "  Selected destination: %s\n", context.SelectedDestinationAddress)
	}
	if context.SelectedSourceInterface != "" {
		if context.SelectedSourceInterfaceIndex != 0 {
			fmt.Fprintf(out, "  Source interface: %s (index %d)\n", context.SelectedSourceInterface, context.SelectedSourceInterfaceIndex)
		} else {
			fmt.Fprintf(out, "  Source interface: %s\n", context.SelectedSourceInterface)
		}
	} else {
		out.WriteString("  Source interface: Unknown\n")
	}
	if context.SelectedSourceAddress != "" {
		fmt.Fprintf(out, "  Source address: %s\n", context.SelectedSourceAddress)
	} else {
		out.WriteString("  Source address: Unknown\n")
	}
	fmt.Fprintf(out, "  Route: %s\n", routeDispositionLabel(context.EffectiveRoute))
	if context.RoutePrefix != "" {
		fmt.Fprintf(out, "  Route prefix: %s\n", context.RoutePrefix)
	}
	if context.Gateway != "" {
		fmt.Fprintf(out, "  Gateway: %s\n", context.Gateway)
	} else {
		out.WriteString("  Gateway: Not applicable\n")
	}
	if context.NextHop != "" {
		fmt.Fprintf(out, "  Next hop: %s\n", context.NextHop)
	}
	fmt.Fprintf(out, "  Route metric: %d\n", context.RouteMetric)
	if context.VPNOrTunnelInvolvement {
		out.WriteString("  VPN/tunnel involvement: observed\n")
	}
	if context.VirtualAdapterInvolvement {
		out.WriteString("  Virtual adapter involvement: observed\n")
	}
	if context.Neighbor != nil {
		fmt.Fprintf(out, "  Neighbor evidence: %s\n", context.Neighbor.Observation)
		if context.Neighbor.Note != "" {
			fmt.Fprintf(out, "  Neighbor note: %s\n", context.Neighbor.Note)
		}
	}
	if len(context.CompetingRoutes) > 0 {
		fmt.Fprintf(out, "  Competing routes: %d\n", len(context.CompetingRoutes))
	}
	if context.RouteSelectionAmbiguous {
		out.WriteString("  Route selection: ambiguous\n")
	}
	if len(context.EvidenceIDs) > 0 {
		fmt.Fprintf(out, "  Context evidence: %s\n", strings.Join(context.EvidenceIDs, ","))
	}
}

func networkScopeLabel(scope model.NetworkScope) string {
	switch scope {
	case model.NetworkScopeLoopback:
		return "Loopback"
	case model.NetworkScopeLinkLocal:
		return "Link-local"
	case model.NetworkScopeSameLink:
		return "Local link"
	case model.NetworkScopePrivateRouted:
		return "Private routed"
	case model.NetworkScopeVPNTunnelRouted:
		return "VPN / tunnel routed"
	case model.NetworkScopeExternalRouted:
		return "External routed"
	default:
		return "Unknown"
	}
}

func routeDispositionLabel(disposition model.RouteDisposition) string {
	switch disposition {
	case model.RouteDispositionOnLink:
		return "On-link"
	case model.RouteDispositionRouted:
		return "Routed"
	default:
		return "Unknown"
	}
}

func formatPathDestination(host string, port uint16) string {
	if host == "" {
		return "(unspecified)"
	}
	if port == 0 {
		return host
	}
	return netJoinHostPort(host, port)
}

func netJoinHostPort(host string, port uint16) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func formatTiming(timing model.Timing) string {
	parts := []string{fmt.Sprintf("duration_ms=%d", timing.DurationMS)}
	if timing.StartedAt != nil {
		parts = append(parts, "started_at="+strconv.Quote(formatTimestamp(*timing.StartedAt)))
	}
	if timing.CompletedAt != nil {
		parts = append(parts, "completed_at="+strconv.Quote(formatTimestamp(*timing.CompletedAt)))
	}
	return strings.Join(parts, ", ")
}

// formatTimestamp is presentation-only. Human output uses one explicit zone
// for every timestamp in a report and does not alter the model value.
func formatTimestamp(timestamp time.Time) string {
	return timestamp.UTC().Format(time.RFC3339Nano)
}
