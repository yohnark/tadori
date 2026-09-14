package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"sort"
	"strings"

	"github.com/yohnark/tadori/internal/model"
)

// RenderHTML returns the deterministic, semantic HTML projection of report.
// The projection is deliberately built from the report-level normalized
// observations and findings. Raw probe evidence is listed only as provenance;
// it is never decoded to create a semantic label or conclusion.
func RenderHTML(report model.DiagnosticReport) ([]byte, error) {
	canonical, err := MarshalJSON(report)
	if err != nil {
		return nil, err
	}

	var out bytes.Buffer
	out.WriteString("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
	out.WriteString("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
	out.WriteString("<title>Tadori diagnostic report</title>")
	out.WriteString("<style>")
	out.WriteString(reportCSS)
	out.WriteString(reportDestinationStatusCSS)
	out.WriteString("</style></head><body><main class=\"report\">")
	out.WriteString("<header class=\"report-header\"><p class=\"eyebrow\">Tadori diagnostic report</p>")
	out.WriteString("<h1>")
	writeText(&out, targetLabel(report))
	out.WriteString("</h1><div class=\"header-meta\">")
	field(&out, "Status", string(report.Status), statusTone(string(report.Status)))
	field(&out, "Schema", report.SchemaVersion, "neutral")
	if report.SessionID != "" {
		field(&out, "Session", report.SessionID, "neutral")
	}
	out.WriteString("</div></header>")

	renderDestinationStatus(&out, report)
	renderConclusion(&out, report)
	renderTarget(&out, report)
	renderObservationSections(&out, report)
	renderFindings(&out, report)
	renderLimitations(&out, report)
	renderProvenance(&out, report)

	out.WriteString("<section class=\"section canonical\"><h2>Canonical JSON</h2>")
	out.WriteString("<p class=\"section-note\">This embedded document is the canonical machine-readable report.</p>")
	out.WriteString("<details><summary>Show canonical JSON</summary><pre><code>")
	writeText(&out, string(canonical))
	out.WriteString("</code></pre></details></section>")
	out.WriteString("</main></body></html>")
	return out.Bytes(), nil
}

func renderDestinationStatus(out *bytes.Buffer, diagnosticReport model.DiagnosticReport) {
	status := DestinationStatusForReport(diagnosticReport)
	tone := destinationStatusTone(status.Status)
	out.WriteString("<section class=\"destination-status ")
	writeText(out, tone)
	out.WriteString("\" aria-labelledby=\"destination-status-title\"><p class=\"eyebrow\">Destination Status</p><h2 id=\"destination-status-title\"><span aria-hidden=\"true\">●</span> ")
	writeText(out, strings.ToUpper(status.Label))
	out.WriteString("</h2><p class=\"destination-status-detail\">")
	writeText(out, status.Detail)
	out.WriteString("</p><dl class=\"destination-status-facts\">")
	fact(out, "Requested service", status.RequestedService)
	fact(out, "Requested identity", status.RequestedIdentity)
	fact(out, "Effective endpoint", endpointLabel(status.EffectiveEndpoint))
	if status.FailureReason != model.FailureReasonNone && status.FailureReason != "" {
		fact(out, "Failure reason", string(status.FailureReason))
	}
	out.WriteString("</dl>")
	renderProvenanceRefs(out, status.Provenance, status.EvidenceIDs, status.ProbeNames)
	out.WriteString("</section>")
}

// MarshalHTML is the marshal-shaped alias for RenderHTML.
func MarshalHTML(report model.DiagnosticReport) ([]byte, error) {
	return RenderHTML(report)
}

// WriteHTML writes RenderHTML without adding a trailing newline.
func WriteHTML(w io.Writer, report model.DiagnosticReport) error {
	if w == nil {
		return errors.New("report: nil HTML writer")
	}
	document, err := RenderHTML(report)
	if err != nil {
		return err
	}
	_, err = w.Write(document)
	return err
}

// HTML is a short alias for RenderHTML for format selection at call sites.
func HTML(report model.DiagnosticReport) ([]byte, error) {
	return RenderHTML(report)
}

// HTMLInlineStyleCSPSource returns the CSP hash source for the complete
// inline style element emitted by RenderHTML. The value is deterministic and
// lets the HTTP adapter permit this style block without permitting arbitrary
// inline styles.
func HTMLInlineStyleCSPSource() string {
	hash := sha256.Sum256([]byte(reportCSS + reportDestinationStatusCSS))
	return "'sha256-" + base64.StdEncoding.EncodeToString(hash[:]) + "'"
}

func renderConclusion(out *bytes.Buffer, diagnosticReport model.DiagnosticReport) {
	out.WriteString("<section class=\"section conclusion\"><h2>Conclusion and diagnostic boundary</h2>")
	out.WriteString("<div class=\"conclusion-grid\">")
	field(out, "Execution status", string(diagnosticReport.Status), statusTone(string(diagnosticReport.Status)))
	field(out, "Conclusion", conclusionLabel(diagnosticReport), conclusionTone(diagnosticReport))
	out.WriteString("</div>")
	out.WriteString("<p class=\"boundary\">The conclusion is limited to the canonical observations collected in this session. An unknown, unsupported, partial, or conflicting observation is not promoted to a stronger claim.</p>")
	out.WriteString("</section>")
}

func renderTarget(out *bytes.Buffer, diagnosticReport model.DiagnosticReport) {
	target := diagnosticReport.Observations.Endpoint
	out.WriteString("<section class=\"section\"><h2>Target and service</h2><dl class=\"facts\">")
	fact(out, "Requested identity", target.RequestedIdentity)
	fact(out, "Original input", target.OriginalInput)
	fact(out, "Service", serviceLabel(target.Service))
	fact(out, "Application protocol", string(target.ApplicationProtocol))
	fact(out, "Transport protocol", string(target.TransportProtocol))
	fact(out, "Port", uint16Text(target.Port))
	fact(out, "Resource", target.Resource)
	fact(out, "Endpoint certainty", string(target.Certainty))
	fact(out, "Endpoint provenance", strings.Join(target.Provenance, ", "))
	out.WriteString("</dl>")
	renderEndpoints(out, target)
	out.WriteString("</section>")
}

func renderEndpoints(out *bytes.Buffer, observation model.EndpointObservation) {
	out.WriteString("<div class=\"subsection\"><h3>Endpoint selection</h3><dl class=\"facts\">")
	fact(out, "Selected probe candidate", endpointLabel(observation.SelectedEndpoint))
	fact(out, "Transport-tested endpoint", endpointLabel(observation.TestedEndpoint))
	fact(out, "Resolved candidates", endpointCandidates(observation.ResolvedCandidates))
	fact(out, "Probe candidates", endpointCandidates(observation.ProbeCandidates))
	out.WriteString("</dl>")
	renderStringList(out, "Endpoint limitations", observation.Limitations)
	renderConflicts(out, observation.Conflicts)
	out.WriteString("</div>")
}

func renderObservationSections(out *bytes.Buffer, diagnosticReport model.DiagnosticReport) {
	observations := diagnosticReport.Observations
	renderNameResolutionSemantic(out, observations.NameResolution)
	renderNetworkContextSemantic(out, observations.NetworkContext)
	renderTransport(out, observations.Transport)
	renderSecurity(out, observations.Security)
	renderApplication(out, observations.Application)
	renderPaths(out, observations)
	renderEnterprise(out, observations.EnterprisePolicy)
}

func renderNameResolutionSemantic(out *bytes.Buffer, observation model.NameResolutionObservation) {
	out.WriteString("<section class=\"section\"><h2>DNS and name resolution</h2><dl class=\"facts\">")
	fact(out, "Requested name", observation.RequestedName)
	fact(out, "Resolution certainty", string(observation.Certainty))
	fact(out, "Effective path", nameResolutionPathValue(observation.EffectivePath))
	fact(out, "Selected address", observation.SelectedAddress)
	fact(out, "A answers", strings.Join(observation.A, ", "))
	fact(out, "AAAA answers", strings.Join(observation.AAAA, ", "))
	fact(out, "Candidate names", strings.Join(observation.CandidateNames, ", "))
	fact(out, "Candidate suffixes", strings.Join(observation.CandidateSuffixes, ", "))
	fact(out, "Candidate namespaces", strings.Join(observation.CandidateNamespaces, ", "))
	out.WriteString("</dl>")
	if observation.EffectivePath != nil {
		path := observation.EffectivePath
		out.WriteString("<div class=\"subsection\"><h3>Effective resolver path</h3><dl class=\"facts\">")
		fact(out, "Mechanism", string(path.Mechanism))
		fact(out, "Interface", path.Interface)
		fact(out, "Resolver", path.Resolver)
		fact(out, "Namespace", path.Namespace)
		fact(out, "Policy source", path.PolicySource)
		fact(out, "Policy rule", path.PolicyRule)
		fact(out, "VPN involvement", boolState(path.VPN))
		fact(out, "Provenance", path.Provenance)
		out.WriteString("</dl></div>")
	}
	if len(observation.Paths) > 0 {
		out.WriteString("<details class=\"structured\"><summary>Candidate resolution paths</summary><table><thead><tr><th>State</th><th>Mechanism</th><th>Resolver</th><th>Interface</th><th>Certainty</th></tr></thead><tbody>")
		for _, path := range observation.Paths {
			out.WriteString("<tr><td>")
			writeText(out, string(path.State))
			out.WriteString("</td><td>")
			writeText(out, string(path.Mechanism))
			out.WriteString("</td><td>")
			writeText(out, path.Resolver)
			out.WriteString("</td><td>")
			writeText(out, path.Interface)
			out.WriteString("</td><td>")
			writeText(out, string(path.Certainty))
			out.WriteString("</td></tr>")
		}
		out.WriteString("</tbody></table></details>")
	}
	renderStringList(out, "Resolution limitations", observation.Limitations)
	renderProvenanceRefs(out, observation.Provenance, observation.EvidenceIDs, observation.ProbeNames)
	renderConflicts(out, observation.Conflicts)
	out.WriteString("</section>")
}

func renderNetworkContextSemantic(out *bytes.Buffer, context model.NetworkContext) {
	out.WriteString("<section class=\"section\"><h2>Network context</h2><dl class=\"facts\">")
	fact(out, "Network scope", string(context.NetworkScope))
	fact(out, "Requested identity", context.RequestedIdentity)
	fact(out, "Selected destination", context.SelectedDestinationAddress)
	fact(out, "Source interface", context.SelectedSourceInterface)
	fact(out, "Source address", context.SelectedSourceAddress)
	fact(out, "Effective route", string(context.EffectiveRoute))
	fact(out, "Route prefix", context.RoutePrefix)
	fact(out, "Gateway", context.Gateway)
	fact(out, "Next hop", context.NextHop)
	fact(out, "Route metric", intText(context.RouteMetric))
	fact(out, "VPN/tunnel involvement", boolState(context.VPNOrTunnelInvolvement))
	fact(out, "Virtual adapter involvement", boolState(context.VirtualAdapterInvolvement))
	fact(out, "Route selection ambiguous", boolState(context.RouteSelectionAmbiguous))
	fact(out, "Certainty", string(context.Certainty))
	fact(out, "Failure reason", string(context.FailureReason))
	if context.Neighbor != nil {
		fact(out, "Neighbor observation", string(context.Neighbor.Observation))
		fact(out, "Neighbor note", context.Neighbor.Note)
	}
	out.WriteString("</dl>")
	if len(context.CompetingRoutes) > 0 {
		renderJSONDetails(out, "Competing routes", context.CompetingRoutes)
	}
	renderProvenanceRefs(out, context.Provenance, context.EvidenceIDs, nil)
	renderStringList(out, "Network limitations", context.Limitations)
	renderConflicts(out, context.Conflicts)
	out.WriteString("</section>")
}

func renderTransport(out *bytes.Buffer, observation model.TransportObservation) {
	out.WriteString("<section class=\"section\"><h2>Transport</h2><dl class=\"facts\">")
	fact(out, "Applicable", string(observation.Applicability))
	fact(out, "Connected", boolState(observation.Connected))
	fact(out, "Connection outcome", string(observation.ConnectionOutcome))
	fact(out, "Remote endpoint", endpointLabel(observation.RemoteEndpoint))
	fact(out, "Local endpoint", observation.LocalEndpoint)
	fact(out, "Duration", durationValue(observation.Timing.DurationMS))
	fact(out, "Failure reason", string(observation.FailureReason))
	fact(out, "Certainty", string(observation.Certainty))
	out.WriteString("</dl>")
	renderStringList(out, "Transport limitations", observation.Limitations)
	renderProvenanceRefs(out, observation.Provenance, observation.EvidenceIDs, observation.ProbeNames)
	renderConflicts(out, observation.Conflicts)
	out.WriteString("</section>")
}

func renderSecurity(out *bytes.Buffer, observation model.SecurityObservation) {
	out.WriteString("<section class=\"section\"><h2>TLS and security</h2><dl class=\"facts\">")
	fact(out, "Applicable", string(observation.Applicability))
	fact(out, "Attempted", boolState(observation.Attempted))
	fact(out, "Handshake complete", boolState(observation.HandshakeComplete))
	fact(out, "Certificate validation", string(observation.CertificateValidation))
	fact(out, "Negotiated protocol", observation.NegotiatedProtocol)
	fact(out, "Cipher suite", observation.CipherSuite)
	fact(out, "Server name", observation.ServerName)
	fact(out, "Peer certificate count", intText(observation.PeerCertificateCount))
	if len(observation.Certificates) > 0 {
		fact(out, "Leaf certificate subject", observation.Certificates[0].Subject)
		fact(out, "Leaf certificate issuer", observation.Certificates[0].Issuer)
		fact(out, "Leaf certificate SHA-256", observation.Certificates[0].SHA256)
	}
	fact(out, "Certainty", string(observation.Certainty))
	out.WriteString("</dl>")
	renderTLSInspection(out, observation.TLSInspection)
	renderStringList(out, "Security limitations", observation.Limitations)
	renderProvenanceRefs(out, observation.Provenance, observation.EvidenceIDs, observation.ProbeNames)
	renderConflicts(out, observation.Conflicts)
	out.WriteString("</section>")
}

func renderTLSInspection(out *bytes.Buffer, observation model.TLSInspectionAssessment) {
	out.WriteString("<div class=\"subsection tls-inspection\"><h3>TLS inspection assessment</h3>")
	out.WriteString("<p class=\"section-note\">This assessment correlates presented certificate facts with explicit enterprise and comparison evidence. Proxy configuration, local trust, or an unfamiliar issuer alone does not establish inspection.</p><dl class=\"facts\">")
	fact(out, "Assessment", string(observation.State))
	fact(out, "Assessment certainty", string(observation.Certainty))
	fact(out, "Requested hostname", observation.RequestedHostname)
	fact(out, "Presented leaf subject", observation.PresentedLeafSubject)
	fact(out, "Presented leaf SANs", strings.Join(observation.PresentedLeafSANs, ", "))
	fact(out, "Presented leaf issuer", observation.PresentedLeafIssuer)
	fact(out, "Presented issuer chain", strings.Join(observation.PresentedIssuerChain, " → "))
	fact(out, "Certificate validation", string(observation.CertificateValidation))
	fact(out, "Locally trusted", knownBool(observation.LocallyTrusted, observation.LocalTrustKnown))
	fact(out, "Trusted corporate/private root", knownBool(observation.TrustedCorporatePrivateRoot, observation.TrustedCorporatePrivateRootKnown))
	fact(out, "Enterprise proxy observed", knownBool(observation.EnterpriseProxyObserved, observation.EnterpriseProxyKnown))
	fact(out, "Enterprise policy observed", knownBool(observation.EnterprisePolicyObserved, observation.EnterprisePolicyKnown))
	fact(out, "Origin comparison", knownBool(observation.ChainDiverges, observation.ChainDivergenceKnown))
	fact(out, "Origin leaf SHA-256", observation.OriginLeafSHA256)
	fact(out, "Presented leaf SHA-256", observation.PresentedLeafSHA256)
	fact(out, "Issuer changed", knownBool(observation.IssuerChanged, observation.IssuerChangeKnown))
	out.WriteString("</dl>")
	renderStringList(out, "Assessment signals", observation.Signals)
	renderStringList(out, "Assessment limitations", observation.Limitations)
	renderProvenanceRefs(out, observation.Provenance, observation.EvidenceIDs, nil)
	renderConflicts(out, observation.Conflicts)
	out.WriteString("</div>")
}

func renderApplication(out *bytes.Buffer, observation model.ApplicationObservation) {
	out.WriteString("<section class=\"section\"><h2>Application and service</h2><dl class=\"facts\">")
	fact(out, "Applicable", string(observation.Applicability))
	fact(out, "Request attempted", boolState(observation.RequestAttempted))
	fact(out, "Response received", boolState(observation.ResponseReceived))
	fact(out, "Transport connected", boolState(observation.TransportConnected))
	fact(out, "Protocol", string(observation.Protocol))
	fact(out, "Protocol result", string(observation.ProtocolResult))
	fact(out, "Result", string(observation.Result))
	fact(out, "Response status", intText(observation.StatusCode))
	fact(out, "HTTP status", observation.Status)
	fact(out, "Server identification", observation.ServerIdentification)
	fact(out, "Requested resource", observation.RequestedResource)
	fact(out, "Endpoint used", endpointLabel(observation.EndpointUsed))
	fact(out, "Failure reason", string(observation.FailureReason))
	fact(out, "Certainty", string(observation.Certainty))
	out.WriteString("</dl>")
	renderStringList(out, "Application limitations", observation.Limitations)
	renderProvenanceRefs(out, observation.Provenance, observation.EvidenceIDs, observation.ProbeNames)
	if observation.DNS != nil {
		renderJSONDetails(out, "DNS service observation", observation.DNS)
	}
	if observation.SMB != nil {
		renderJSONDetails(out, "SMB service observation", observation.SMB)
	}
	renderConflicts(out, observation.Conflicts)
	out.WriteString("</section>")
}

func renderPaths(out *bytes.Buffer, observations model.Observations) {
	out.WriteString("<section class=\"section\"><h2>Observed path summary</h2>")
	out.WriteString("<p class=\"section-note\">Observed responders describe probe visibility and are not a physical topology claim.</p>")
	if len(observations.Paths) == 0 && len(observations.PathCorrelations) == 0 {
		state(out, "Path observations", "unknown or unavailable", "unknown")
	} else {
		for index, path := range observations.Paths {
			out.WriteString("<article class=\"observation-card\"><h3>Path ")
			writeText(out, intText(index+1))
			out.WriteString("</h3><dl class=\"facts\">")
			fact(out, "Protocol", string(path.Protocol))
			fact(out, "Destination", pathDestination(path.Destination, path.DestinationPort))
			fact(out, "Status", string(path.Status))
			fact(out, "Destination reached", boolState(path.DestinationReached))
			fact(out, "Port aware", boolState(path.PortAware))
			fact(out, "Hop count", intText(len(path.Hops)))
			out.WriteString("</dl>")
			renderPathHops(out, path)
			renderPathSegments(out, path)
			out.WriteString("</article>")
		}
	}
	if len(observations.PathCorrelations) > 0 {
		renderJSONDetails(out, "Path correlations", observations.PathCorrelations)
	}
	if len(observations.PathProvenance) > 0 {
		renderJSONDetails(out, "Path provenance", observations.PathProvenance)
	}
	renderDivergences(out, observations.Divergences)
	out.WriteString("</section>")
}

func renderPathHops(out *bytes.Buffer, path model.PathObservation) {
	if len(path.Hops) == 0 {
		return
	}
	out.WriteString("<table><caption>Observed path hops</caption><thead><tr><th>TTL</th><th>State</th><th>Responders</th></tr></thead><tbody>")
	for _, hop := range path.Hops {
		out.WriteString("<tr><td>")
		writeText(out, intText(int(hop.TTL)))
		out.WriteString("</td><td>")
		writeText(out, string(hop.State))
		out.WriteString("</td><td>")
		responders := make([]string, 0, len(hop.Responders))
		for _, responder := range hop.Responders {
			responders = append(responders, firstNonEmpty(responder.Address, responder.Response))
		}
		writeText(out, strings.Join(responders, ", "))
		out.WriteString("</td></tr>")
	}
	out.WriteString("</tbody></table>")
}

func renderPathSegments(out *bytes.Buffer, path model.PathObservation) {
	if len(path.Segments) == 0 {
		return
	}
	out.WriteString("<details class=\"structured\"><summary>Observed and bounded path segments</summary><table><thead><tr><th>Kind</th><th>TTL range</th><th>Responders</th></tr></thead><tbody>")
	for _, segment := range path.Segments {
		out.WriteString("<tr><td>")
		writeText(out, string(segment.Kind))
		out.WriteString("</td><td>")
		writeText(out, fmt.Sprintf("%d-%d", segment.FromTTL, segment.ToTTL))
		out.WriteString("</td><td>")
		responders := make([]string, 0, len(segment.Responders))
		for _, responder := range segment.Responders {
			responders = append(responders, firstNonEmpty(responder.Address, responder.Response))
		}
		writeText(out, strings.Join(responders, ", "))
		out.WriteString("</td></tr>")
	}
	out.WriteString("</tbody></table></details>")
}

func renderEnterprise(out *bytes.Buffer, observation model.EnterprisePolicyObservation) {
	out.WriteString("<section class=\"section\"><h2>Enterprise policy and proxy observations</h2><dl class=\"facts\">")
	fact(out, "State", string(observation.State))
	fact(out, "Unsupported", boolState(observation.Unsupported))
	fact(out, "Requested identity", observation.RequestedIdentity)
	fact(out, "Proxy configuration divergence", knownBool(observation.ProxyConfigurationDiverges, observation.ProxyConfigurationKnown))
	fact(out, "Effective decision divergence", knownBool(observation.EffectiveDecisionDiverges, observation.EffectiveDecisionKnown))
	fact(out, "Certainty", string(observation.Certainty))
	out.WriteString("</dl>")
	renderEnterpriseProxy(out, "WinHTTP", observation.WinHTTP)
	renderEnterpriseProxy(out, "WinINET", observation.WinINET)
	renderEnterprisePaths(out, observation.Paths)
	renderJSONDetails(out, "Direct versus proxy", observation.DirectVsProxy)
	renderEnterpriseFirewall(out, observation.Firewall)
	renderEnterpriseNetwork(out, observation.Network)
	renderEnterpriseTLS(out, observation.TLS)
	renderStringList(out, "Enterprise limitations", observation.Limitations)
	renderProvenanceRefs(out, observation.Provenance, observation.EvidenceIDs, observation.ProbeNames)
	renderConflicts(out, observation.Conflicts)
	out.WriteString("</section>")
}

func renderEnterpriseProxy(out *bytes.Buffer, label string, observation model.EnterpriseProxySourceObservation) {
	out.WriteString("<article class=\"observation-card\"><h3>")
	writeText(out, label)
	out.WriteString("</h3><dl class=\"facts\">")
	fact(out, "Source", observation.Source)
	fact(out, "Configuration state", observation.Configuration.State)
	fact(out, "Proxy endpoints", strings.Join(observation.Configuration.ProxyEndpoints, ", "))
	fact(out, "PAC URL", observation.Configuration.PACURL)
	fact(out, "Bypass patterns", strings.Join(observation.Configuration.ProxyBypass, ", "))
	fact(out, "Effective decision", observation.Effective.Decision)
	fact(out, "Effective result observed", boolState(observation.Effective.Observed))
	fact(out, "Resolution attempted", boolState(observation.Effective.ResolutionAttempted))
	fact(out, "Bypass matched", boolState(observation.Effective.BypassMatched))
	fact(out, "Effective mode", observation.Effective.Mode)
	fact(out, "Effective endpoint", observation.Effective.Endpoint)
	fact(out, "Effective resolution succeeded", boolState(observation.Effective.ResolutionOK))
	fact(out, "PAC mode", observation.PAC.Mode)
	fact(out, "PAC decision", observation.PAC.Decision)
	fact(out, "PAC configured", boolState(observation.PAC.Configured))
	fact(out, "PAC resolution observed", boolState(observation.PAC.ResolutionObserved))
	fact(out, "PAC resolution succeeded", boolState(observation.PAC.ResolutionOK))
	fact(out, "PAC used", boolState(observation.PAC.Used))
	fact(out, "Certainty", string(observation.Certainty))
	out.WriteString("</dl>")
	if len(observation.EndpointReachability) > 0 {
		out.WriteString("<table><caption>Selected proxy endpoint observations</caption><thead><tr><th>Endpoint</th><th>Reachability</th><th>CONNECT outcome</th><th>Status</th><th>Certainty</th></tr></thead><tbody>")
		for _, endpoint := range observation.EndpointReachability {
			out.WriteString("<tr><td>")
			writeText(out, endpoint.Endpoint)
			out.WriteString("</td><td>")
			writeText(out, endpoint.Reachability)
			out.WriteString("</td><td>")
			writeText(out, endpoint.ConnectOutcome)
			out.WriteString("</td><td>")
			writeText(out, intText(endpoint.StatusCode))
			out.WriteString("</td><td>")
			writeText(out, string(endpoint.Certainty))
			out.WriteString("</td></tr>")
		}
		out.WriteString("</tbody></table>")
	}
	renderStringList(out, "Limitations", observation.Limitations)
	renderProvenanceRefs(out, observation.Provenance, observation.EvidenceIDs, nil)
	out.WriteString("</article>")
}

func renderEnterprisePaths(out *bytes.Buffer, paths []model.EnterprisePathObservation) {
	if len(paths) == 0 {
		return
	}
	out.WriteString("<article class=\"observation-card\"><h3>Collected enterprise paths</h3><table><thead><tr><th>Name</th><th>Mode</th><th>Endpoint</th><th>Outcome</th><th>Certainty</th></tr></thead><tbody>")
	for _, path := range paths {
		out.WriteString("<tr><td>")
		writeText(out, path.Name)
		out.WriteString("</td><td>")
		writeText(out, path.Mode)
		out.WriteString("</td><td>")
		writeText(out, path.Endpoint)
		out.WriteString("</td><td>")
		writeText(out, firstNonEmpty(path.ConnectOutcome, string(path.FailureReason)))
		out.WriteString("</td><td>")
		writeText(out, string(path.Certainty))
		out.WriteString("</td></tr>")
	}
	out.WriteString("</tbody></table></article>")
}

func renderEnterpriseFirewall(out *bytes.Buffer, observation model.EnterpriseFirewallObservation) {
	out.WriteString("<div class=\"subsection\"><h3>Firewall observations</h3><dl class=\"facts\">")
	fact(out, "State", string(observation.State))
	fact(out, "Available", boolState(observation.Available))
	fact(out, "Block causality", observation.BlockCausality)
	fact(out, "Certainty", string(observation.Certainty))
	out.WriteString("</dl>")
	if len(observation.Profiles) > 0 {
		renderJSONDetails(out, "Firewall profiles", observation.Profiles)
	}
	renderStringList(out, "Limitations", observation.Limitations)
	out.WriteString("</div>")
}

func renderEnterpriseNetwork(out *bytes.Buffer, observation model.EnterpriseNetworkCorrelationObservation) {
	out.WriteString("<div class=\"subsection\"><h3>Enterprise network correlation</h3><dl class=\"facts\">")
	fact(out, "VPN adapter present", knownBool(observation.VPNAdapterPresent, observation.VPNAdapterPresentKnown))
	fact(out, "Virtual adapter present", knownBool(observation.VirtualAdapterPresent, observation.VirtualAdapterPresentKnown))
	fact(out, "Selected route uses VPN", knownBool(observation.SelectedRouteUsesVPN, observation.SelectedRouteUsesVPNKnown))
	fact(out, "Selected route uses virtual adapter", knownBool(observation.SelectedRouteUsesVirtual, observation.SelectedRouteUsesVirtualKnown))
	fact(out, "Route difference", knownBool(observation.RouteDifference, observation.RouteDifferenceKnown))
	fact(out, "Network context referenced", boolState(observation.NetworkContextReferenced))
	fact(out, "Certainty", string(observation.Certainty))
	out.WriteString("</dl></div>")
}

func renderEnterpriseTLS(out *bytes.Buffer, observation model.EnterpriseTLSPolicyObservation) {
	out.WriteString("<div class=\"subsection\"><h3>Enterprise TLS policy</h3><dl class=\"facts\">")
	fact(out, "State", string(observation.State))
	fact(out, "Direct certificate subject", observation.DirectCertificateSubject)
	fact(out, "Proxy certificate subject", observation.ProxyCertificateSubject)
	fact(out, "Certificates differ", knownBool(observation.CertificatesDiffer, observation.CertificatesDifferKnown))
	fact(out, "Direct certificate issuer", observation.DirectCertificateIssuer)
	fact(out, "Proxy certificate issuer", observation.ProxyCertificateIssuer)
	fact(out, "Issuers differ", knownBool(observation.IssuersDiffer, observation.IssuersDifferKnown))
	fact(out, "Both trusted", knownBool(observation.BothTrusted, observation.BothTrustedKnown))
	fact(out, "Both hostnames verified", knownBool(observation.BothHostnameVerified, observation.BothHostnameKnown))
	fact(out, "Possible interception", boolState(observation.PossibleInterception))
	fact(out, "Interception suspicion", observation.InterceptionSuspicion)
	fact(out, "Interception basis", observation.InterceptionBasis)
	fact(out, "Trust mismatch", knownBool(observation.TrustMismatch, observation.TrustMismatchKnown))
	fact(out, "Trusted corporate/private root", knownBool(observation.TrustedCorporatePrivateRoot, observation.TrustedCorporatePrivateRootKnown))
	fact(out, "Certainty", string(observation.Certainty))
	out.WriteString("</dl>")
	renderStringList(out, "Limitations", observation.Limitations)
	renderConflicts(out, observation.Conflicts)
	out.WriteString("</div>")
}

func renderFindings(out *bytes.Buffer, diagnosticReport model.DiagnosticReport) {
	out.WriteString("<section class=\"section\"><h2>Findings</h2>")
	if len(diagnosticReport.Findings) == 0 {
		state(out, "Findings", "none recorded", "neutral")
	} else {
		for index, finding := range diagnosticReport.Findings {
			out.WriteString("<article class=\"finding\"><h3>Finding ")
			writeText(out, intText(index+1))
			out.WriteString("</h3><dl class=\"facts\">")
			fact(out, "Failure reason", string(finding.FailureReason))
			fact(out, "Layer", string(finding.Layer))
			fact(out, "Fault domain", string(finding.FaultDomain))
			fact(out, "Probe names", strings.Join(finding.ProbeNames, ", "))
			fact(out, "Evidence IDs", strings.Join(finding.EvidenceIDs, ", "))
			out.WriteString("</dl></article>")
		}
	}
	out.WriteString("</section>")
}

func renderLimitations(out *bytes.Buffer, diagnosticReport model.DiagnosticReport) {
	out.WriteString("<section class=\"section\"><h2>Limitations and conflicts</h2>")
	limitations := append([]string(nil), diagnosticReport.Observations.Endpoint.Limitations...)
	limitations = append(limitations, diagnosticReport.Observations.NameResolution.Limitations...)
	limitations = append(limitations, diagnosticReport.Observations.Transport.Limitations...)
	limitations = append(limitations, diagnosticReport.Observations.Security.Limitations...)
	limitations = append(limitations, diagnosticReport.Observations.Application.Limitations...)
	limitations = append(limitations, diagnosticReport.Observations.EnterprisePolicy.Limitations...)
	limitations = uniqueSorted(limitations)
	if len(limitations) == 0 {
		state(out, "Limitations", "none recorded", "neutral")
	} else {
		renderList(out, "Limitations", limitations)
	}
	renderConflicts(out, diagnosticReport.Observations.Conflicts)
	renderDivergences(out, diagnosticReport.Observations.Divergences)
	out.WriteString("</section>")
}

func renderProvenance(out *bytes.Buffer, diagnosticReport model.DiagnosticReport) {
	out.WriteString("<section class=\"section\"><h2>Evidence and provenance</h2>")
	refs := make([]provenanceRow, 0)
	for _, probe := range diagnosticReport.Probes {
		for _, evidence := range probe.Evidence {
			refs = append(refs, provenanceRow{Probe: probe.Name, ProbeID: probe.ProbeID, EvidenceID: evidence.ID, Kind: string(evidence.Kind), Source: evidence.Source})
		}
	}
	if len(refs) == 0 {
		state(out, "Evidence", "none recorded", "neutral")
	} else {
		out.WriteString("<table><caption>Raw evidence references (secondary)</caption><thead><tr><th>Probe</th><th>Evidence ID</th><th>Kind</th><th>Source</th></tr></thead><tbody>")
		for _, ref := range refs {
			out.WriteString("<tr><td>")
			writeText(out, ref.Probe)
			out.WriteString("</td><td>")
			writeText(out, ref.EvidenceID)
			out.WriteString("</td><td>")
			writeText(out, ref.Kind)
			out.WriteString("</td><td>")
			writeText(out, ref.Source)
			out.WriteString("</td></tr>")
		}
		out.WriteString("</tbody></table>")
	}
	out.WriteString("<p class=\"section-note\">Semantic sections above use normalized observations and findings. Raw evidence is not interpreted by this renderer.</p></section>")
}

type provenanceRow struct {
	Probe      string
	ProbeID    string
	EvidenceID string
	Kind       string
	Source     string
}

func renderProvenanceRefs(out *bytes.Buffer, provenance, evidenceIDs, probeNames []string) {
	if len(provenance) == 0 && len(evidenceIDs) == 0 && len(probeNames) == 0 {
		return
	}
	out.WriteString("<div class=\"provenance\"><h4>Provenance references</h4><dl class=\"facts\">")
	fact(out, "Provenance", strings.Join(provenance, ", "))
	fact(out, "Probe names", strings.Join(probeNames, ", "))
	fact(out, "Evidence IDs", strings.Join(evidenceIDs, ", "))
	out.WriteString("</dl></div>")
}

func renderStringList(out *bytes.Buffer, title string, values []string) {
	if len(values) == 0 {
		return
	}
	renderList(out, title, values)
}

func renderList(out *bytes.Buffer, title string, values []string) {
	out.WriteString("<div class=\"list\"><h3>")
	writeText(out, title)
	out.WriteString("</h3><ul>")
	for _, value := range values {
		out.WriteString("<li>")
		writeText(out, value)
		out.WriteString("</li>")
	}
	out.WriteString("</ul></div>")
}

func renderConflicts(out *bytes.Buffer, conflicts []model.ObservationConflict) {
	if len(conflicts) == 0 {
		return
	}
	out.WriteString("<div class=\"conflicts\"><h3>Conflicting observations</h3><ul>")
	for _, conflict := range conflicts {
		out.WriteString("<li><strong>")
		writeText(out, conflict.Field)
		out.WriteString("</strong>: ")
		writeText(out, strings.Join(conflict.Values, " / "))
		if len(conflict.Provenance) > 0 {
			out.WriteString(" <span class=\"muted\">provenance: ")
			writeText(out, strings.Join(conflict.Provenance, ", "))
			out.WriteString("</span>")
		}
		out.WriteString("</li>")
	}
	out.WriteString("</ul></div>")
}

func renderDivergences(out *bytes.Buffer, divergences []model.ObservationDivergence) {
	if len(divergences) == 0 {
		return
	}
	out.WriteString("<div class=\"conflicts\"><h3>Observation divergences</h3><ul>")
	for _, divergence := range divergences {
		out.WriteString("<li><strong>")
		writeText(out, divergence.Field)
		out.WriteString("</strong>: path=")
		writeText(out, strings.Join(divergence.PathValues, ", "))
		out.WriteString("; packet_flow=")
		writeText(out, strings.Join(divergence.PacketFlowValues, ", "))
		out.WriteString("</li>")
	}
	out.WriteString("</ul></div>")
}

func renderJSONDetails(out *bytes.Buffer, title string, value any) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return
	}
	out.WriteString("<details class=\"structured\"><summary>")
	writeText(out, title)
	out.WriteString("</summary><pre><code>")
	writeText(out, string(encoded))
	out.WriteString("</code></pre></details>")
}

func field(out *bytes.Buffer, label, value, tone string) {
	out.WriteString("<div class=\"field\"><span class=\"field-label\">")
	writeText(out, label)
	out.WriteString("</span><span class=\"value ")
	writeText(out, tone)
	out.WriteString("\">")
	writeText(out, displayValue(value))
	out.WriteString("</span></div>")
}

func fact(out *bytes.Buffer, label, value string) {
	out.WriteString("<dt>")
	writeText(out, label)
	out.WriteString("</dt><dd>")
	writeText(out, displayValue(value))
	out.WriteString("</dd>")
}

func state(out *bytes.Buffer, label, value, tone string) {
	out.WriteString("<p class=\"state ")
	writeText(out, tone)
	out.WriteString("\"><strong>")
	writeText(out, label)
	out.WriteString(":</strong> ")
	writeText(out, value)
	out.WriteString("</p>")
}

func writeText(out *bytes.Buffer, value string) {
	_, _ = io.WriteString(out, html.EscapeString(value))
}

func targetLabel(diagnosticReport model.DiagnosticReport) string {
	target := diagnosticReport.Observations.Endpoint
	return firstNonEmpty(target.RequestedIdentity, target.OriginalInput, "unspecified target")
}

func conclusionLabel(diagnosticReport model.DiagnosticReport) string {
	if len(diagnosticReport.Findings) == 0 {
		if diagnosticReport.Status == model.ReportStatusComplete {
			return "No canonical finding recorded"
		}
		return "No canonical finding recorded; execution is incomplete"
	}
	return fmt.Sprintf("%d canonical finding(s) recorded", len(diagnosticReport.Findings))
}

func conclusionTone(diagnosticReport model.DiagnosticReport) string {
	if len(diagnosticReport.Findings) > 0 {
		return "warning"
	}
	if diagnosticReport.Status == model.ReportStatusComplete {
		return "positive"
	}
	return "unknown"
}

func statusTone(status string) string {
	switch status {
	case string(model.ReportStatusComplete), string(model.ProbeStatusPassed):
		return "positive"
	case string(model.ReportStatusIncomplete), string(model.ProbeStatusFailed), string(model.ProbeStatusError):
		return "warning"
	default:
		return "neutral"
	}
}

func destinationStatusTone(status DestinationStatusState) string {
	switch status {
	case DestinationStatusReachable:
		return "positive"
	case DestinationStatusUnreachable:
		return "negative"
	case DestinationStatusDegraded:
		return "warning"
	default:
		return "neutral"
	}
}

func displayValue(value string) string {
	if value == "" {
		return "unknown / not observed"
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func boolState(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func knownBool(value, known bool) string {
	if !known {
		return "unknown"
	}
	return boolState(value)
}

func intText(value int) string { return fmt.Sprintf("%d", value) }

func durationValue(value int64) string {
	if value <= 0 {
		return ""
	}
	return fmt.Sprintf("%d ms", value)
}

func uint16Text(value uint16) string {
	if value == 0 {
		return ""
	}
	return fmt.Sprintf("%d", value)
}

func serviceLabel(value model.ServiceProfile) string {
	if value.Label != "" {
		return value.Label
	}
	return string(value.ID)
}

func endpointLabel(endpoint *model.Endpoint) string {
	if endpoint == nil {
		return ""
	}
	return formatEndpoint(*endpoint)
}

func endpointCandidates(candidates []model.EndpointCandidate) string {
	values := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		value := candidate.Address
		if candidate.Family != "" {
			value += " [" + string(candidate.Family) + "]"
		}
		if candidate.Certainty != "" {
			value += " (" + string(candidate.Certainty) + ")"
		}
		values = append(values, value)
	}
	return strings.Join(values, ", ")
}

func nameResolutionPathValue(path *model.NameResolutionPath) string {
	if path == nil {
		return ""
	}
	return firstNonEmpty(string(path.Mechanism), path.Interface, path.Resolver)
}

func pathDestination(host string, port uint16) string {
	return formatPathDestination(host, port)
}

// reportCSS is inline so an exported report remains a portable single file.
const reportCSS = `:root{color-scheme:light dark;--bg:#f5f7fb;--surface:#fff;--text:#172033;--muted:#617089;--line:#dce2ec;--accent:#2859c5;--positive:#147a4b;--warning:#9a5a00;--unknown:#6e4c9e}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.report{max-width:1120px;margin:0 auto;padding:32px 20px 64px}.report-header{border-bottom:2px solid var(--accent);padding-bottom:20px}.eyebrow{color:var(--accent);font-size:12px;font-weight:700;letter-spacing:.12em;text-transform:uppercase}.report h1{font-size:32px;line-height:1.15;margin:8px 0 18px;overflow-wrap:anywhere}.header-meta,.conclusion-grid{display:flex;flex-wrap:wrap;gap:10px}.field{background:var(--surface);border:1px solid var(--line);border-radius:8px;display:flex;flex-direction:column;gap:2px;min-width:150px;padding:9px 12px}.field-label{color:var(--muted);font-size:11px;font-weight:700;text-transform:uppercase}.value{overflow-wrap:anywhere}.positive{color:var(--positive)}.warning{color:var(--warning)}.unknown{color:var(--unknown)}.section{background:var(--surface);border:1px solid var(--line);border-radius:10px;margin-top:18px;padding:20px}.section h2{font-size:21px;margin:0 0 14px}.section h3{font-size:16px;margin:16px 0 8px}.section h4{font-size:13px;margin:14px 0 6px}.section-note,.boundary,.muted{color:var(--muted)}.boundary{border-left:3px solid var(--accent);margin:16px 0 0;padding-left:12px}.facts{display:grid;grid-template-columns:minmax(170px,.36fr) minmax(0,1fr);margin:0}.facts dt,.facts dd{border-bottom:1px solid var(--line);margin:0;padding:8px 0;overflow-wrap:anywhere}.facts dt{color:var(--muted);font-weight:650;padding-right:14px}.facts dd{min-width:0}.subsection,.observation-card,.finding,.provenance{border-top:1px solid var(--line);margin-top:18px;padding-top:6px}.observation-card,.finding{border:1px solid var(--line);border-radius:8px;margin-top:12px;padding:12px}.list ul,.conflicts ul{margin:6px 0 0;padding-left:22px}.conflicts{border-left:3px solid var(--warning);margin-top:16px;padding-left:12px}.state{border:1px solid var(--line);border-radius:7px;padding:10px 12px}.structured summary,details summary{cursor:pointer;color:var(--accent);font-weight:650}pre{background:#111827;border-radius:7px;color:#e5e7eb;max-height:480px;overflow:auto;padding:14px;white-space:pre-wrap;word-break:break-word}code{font:12px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace}table{border-collapse:collapse;display:block;overflow-x:auto;width:100%}caption{text-align:left;color:var(--muted);font-size:13px;padding:8px 0;text-align:left}th,td{border-bottom:1px solid var(--line);padding:8px;text-align:left;vertical-align:top;white-space:nowrap}th{color:var(--muted);font-size:12px;text-transform:uppercase}@media(max-width:640px){.report{padding:20px 12px 40px}.report h1{font-size:25px}.section{padding:14px}.facts{display:block}.facts dt{border-bottom:0;padding-top:10px}.facts dd{padding-top:0}.field{min-width:130px}}@media(prefers-color-scheme:dark){:root{--bg:#111827;--surface:#1f2937;--text:#eef2ff;--muted:#aab4c6;--line:#374151;--accent:#91aaf7;--positive:#71d3a0;--warning:#ffbe70;--unknown:#c8a8ee}pre{background:#0b1020}}`

const reportDestinationStatusCSS = `.destination-status{background:var(--surface);border:1px solid var(--line);border-left:4px solid var(--muted);border-radius:8px;margin-top:18px;padding:16px 18px}.destination-status.positive{border-left-color:var(--positive)}.destination-status.warning{border-left-color:var(--warning)}.destination-status.negative{border-left-color:#b42318}.destination-status h2{font-size:24px;letter-spacing:.04em;margin:2px 0 4px}.destination-status h2 span{font-size:16px}.destination-status-detail{margin:0 0 12px;color:var(--muted)}.destination-status-facts{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:0 18px;margin:0}.destination-status-facts dt,.destination-status-facts dd{margin:0;padding:3px 0;overflow-wrap:anywhere}.destination-status-facts dt{color:var(--muted);font-size:12px;font-weight:650}.destination-status-facts dd{min-width:0}@media(max-width:640px){.destination-status-facts{display:block}.destination-status-facts dt{padding-top:6px}.destination-status-facts dd{padding-top:0}}`
