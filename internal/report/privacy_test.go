package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/yohnark/tadori/internal/model"
)

func TestMarshalExportJSONCarriesPolicyAndOmitsSensitiveEvidence(t *testing.T) {
	source := model.DiagnosticReport{
		SchemaVersion: model.DiagnosticSchemaVersion,
		Target:        model.Target{RequestedIdentity: "service.internal.example", Resource: "/health?token=secret-token"},
		Status:        model.ReportStatusComplete,
		Probes: []model.ProbeResult{{
			Name: "http",
			Evidence: []model.Evidence{{
				ID:   "http-1",
				Kind: model.EvidenceKindHTTPResponse,
				Raw:  json.RawMessage(`{"headers":{"Authorization":"Bearer secret-token","X-Trace":"kept"},"body":"response-secret","url":"https://service.internal.example/health?key=secret-token"}`),
			}},
		}},
	}
	encoded, err := MarshalExportJSON(source)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	var metadata PrivacyMetadata
	if err := json.Unmarshal(document["privacy"], &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.Policy != "tadori/export-redaction" || metadata.Version != "1" {
		t.Fatalf("privacy metadata = %#v", metadata)
	}
	output := string(encoded)
	for _, forbidden := range []string{"secret-token", "response-secret", "Authorization"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("export retained %q: %s", forbidden, output)
		}
	}
	if !strings.Contains(output, "service.internal.example") || !strings.Contains(output, "X-Trace") {
		t.Fatalf("export lost safe diagnostic evidence: %s", output)
	}
}

func TestRenderHTMLIncludesPrivacyInventoryAndRedactsProjection(t *testing.T) {
	source := semanticHTMLFixture()
	source.Target.OriginalInput = "https://operator.example/health?credential=secret-token"
	source.Probes[0].Evidence[0].Raw = json.RawMessage(`{"url":"https://operator.example/health?credential=secret-token","body":"response-secret"}`)
	document, err := RenderHTML(source)
	if err != nil {
		t.Fatal(err)
	}
	output := string(document)
	for _, want := range []string{"Export privacy preview", "usernames and local profile paths", "cookies and authorization headers", "tadori/export-redaction"} {
		if !strings.Contains(output, want) {
			t.Errorf("HTML missing privacy inventory item %q", want)
		}
	}
	for _, forbidden := range []string{"secret-token", "response-secret"} {
		if strings.Contains(output, forbidden) {
			t.Errorf("HTML retained sensitive value %q", forbidden)
		}
	}
}

func TestRenderFQDNExportCarriesDeterministicPrivacyComments(t *testing.T) {
	first := RenderFQDNExport([]string{"internal.example", "public.example", "internal.example"})
	second := RenderFQDNExport([]string{"public.example", "internal.example"})
	if string(first) != string(second) {
		t.Fatalf("FQDN export is not deterministic\nfirst: %s\nsecond: %s", first, second)
	}
	output := string(first)
	for _, want := range []string{"# tadori_privacy_policy=tadori/export-redaction", "# tadori_privacy_version=1", "internal.example\n", "public.example\n"} {
		if !strings.Contains(output, want) {
			t.Errorf("FQDN export missing %q: %s", want, output)
		}
	}
}
