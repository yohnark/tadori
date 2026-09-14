package privacy

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/yohnark/tadori/internal/model"
)

func TestProjectReportRedactsStructuredSensitiveFieldsAndPreservesEvidence(t *testing.T) {
	target, err := model.ParseTarget(model.TargetIntent{Input: "https://diagnostic.example/health?user=alice"})
	if err != nil {
		t.Fatal(err)
	}
	target.Resource = "/health?token=opaque-token"
	target.OriginalInput = "https://diagnostic.example/health?user=alice#private"
	report := model.DiagnosticReport{
		SchemaVersion: model.DiagnosticSchemaVersion,
		Target:        target,
		SessionID:     "session-operator-42",
		Status:        model.ReportStatusComplete,
		Observations: model.Observations{
			Endpoint: model.EndpointObservation{
				OriginalInput:     target.OriginalInput,
				RequestedIdentity: "diagnostic.example",
				Resource:          target.Resource,
				SelectedEndpoint:  &model.Endpoint{Address: "192.0.2.10", Port: 443},
			},
			NameResolution: model.NameResolutionObservation{
				RequestedName:   "diagnostic.example",
				A:               []string{"192.0.2.10"},
				AAAA:            []string{"2001:db8::10"},
				SelectedAddress: "192.0.2.10",
			},
			Security: model.SecurityObservation{
				Certificates: []model.TLSCertificateObservation{{
					Subject:        "CN=diagnostic.example",
					Issuer:         "CN=Example Root CA",
					DNSNames:       []string{"diagnostic.example"},
					IPAddresses:    []string{"192.0.2.10"},
					EmailAddresses: []string{"alice@example.invalid"},
				}},
			},
			Application: model.ApplicationObservation{
				URL:               "https://diagnostic.example/health?api_key=opaque-token#private",
				RequestedResource: "/health?api_key=opaque-token",
			},
		},
		Probes: []model.ProbeResult{{
			Name:      "http",
			SessionID: "session-operator-42",
			ProbeID:   "probe-http-1",
			Evidence: []model.Evidence{{
				ID:   "http-1",
				Kind: model.EvidenceKindHTTPResponse,
				Raw:  json.RawMessage(`{"url":"https://diagnostic.example/health?token=opaque-token#private","headers":{"Authorization":"Bearer bearer-secret","Cookie":"sid=cookie-secret","Location":"https://diagnostic.example/next?secret=opaque-token","Content-Type":"text/plain"},"body":"response-secret","username":"alice","path":"C:\\Users\\alice\\Documents\\report.txt","token":"opaque-token","safe":"diagnostic evidence"}`),
			}},
		}},
	}
	original := report

	projection, err := ProjectReport(report)
	if err != nil {
		t.Fatal(err)
	}
	if !projection.Changed {
		t.Fatal("sensitive report was not changed")
	}
	if !reflect.DeepEqual(report, original) {
		t.Fatal("privacy projection mutated the source report")
	}

	encoded, err := json.Marshal(projection.Report)
	if err != nil {
		t.Fatal(err)
	}
	output := string(encoded)
	for _, forbidden := range []string{
		"opaque-token",
		"bearer-secret",
		"cookie-secret",
		"response-secret",
		"alice",
		"private",
		"api_key",
		"alice@example.invalid",
	} {
		if strings.Contains(output, forbidden) {
			t.Errorf("export retained %q: %s", forbidden, output)
		}
	}
	for _, included := range []string{"diagnostic.example", "192.0.2.10", "2001:db8::10", "CN=diagnostic.example", "session-operator-42", "diagnostic evidence"} {
		if !strings.Contains(output, included) {
			t.Errorf("export lost included diagnostic value %q: %s", included, output)
		}
	}
	if projection.Metadata.Policy != PolicyName || projection.Metadata.Version != PolicyVersion || len(projection.Metadata.Included) == 0 || len(projection.Metadata.Excluded) == 0 {
		t.Fatalf("incomplete metadata: %#v", projection.Metadata)
	}
}

func TestRedactRawSanitizesUnexpectedTextWithoutDiscardingSafeText(t *testing.T) {
	safe := json.RawMessage(`"safe protocol evidence"`)
	redacted, changed, err := RedactRaw(safe)
	if err != nil {
		t.Fatal(err)
	}
	if changed || string(redacted) != string(safe) {
		t.Fatalf("safe text changed: changed=%t raw=%s", changed, redacted)
	}

	sensitive := json.RawMessage(`"Authorization: Bearer opaque-token"`)
	redacted, changed, err = RedactRaw(sensitive)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || strings.Contains(string(redacted), "opaque-token") {
		t.Fatalf("unexpected evidence retained a credential: changed=%t raw=%s", changed, redacted)
	}
}

func TestProjectBrowserCaptureKeepsMetadataOnlyShape(t *testing.T) {
	report := model.BrowserCaptureReport{
		SchemaVersion: model.BrowserCaptureSchemaVersion,
		SessionID:     "capture-session-1",
		Browser:       "edge",
		Observations: model.Observations{
			BrowserCapture: &model.BrowserCaptureObservation{
				SessionID:    "capture-session-1",
				ProxyAddress: "127.0.0.1:32123",
				Destinations: []model.BrowserCaptureDestination{{
					RequestedHostname: "internal.example",
					ConnectedAddress:  "2001:db8::20",
				}},
			},
		},
	}
	projection, err := ProjectBrowserCapture(report)
	if err != nil {
		t.Fatal(err)
	}
	if projection.Changed {
		t.Fatal("metadata-only capture was unexpectedly changed")
	}
	if !reflect.DeepEqual(projection.Report, report) {
		t.Fatalf("capture projection changed facts: %#v", projection.Report)
	}
	if !strings.Contains(strings.Join(projection.Metadata.Included, " "), "destination_hostnames") {
		t.Fatalf("capture metadata omitted hostname disclosure: %#v", projection.Metadata)
	}
}
