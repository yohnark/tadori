package model

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestEndpointCandidatesFromAnswersPreservesFamilyAndOrder(t *testing.T) {
	candidates := EndpointCandidatesFromAnswers(
		[]string{"192.0.2.20", "192.0.2.10", "192.0.2.20"},
		[]string{"2001:db8::20", "2001:db8::10"},
	)
	want := []EndpointCandidate{
		{Address: "192.0.2.20", Family: EndpointFamilyIPv4, Order: 1},
		{Address: "192.0.2.10", Family: EndpointFamilyIPv4, Order: 2},
		{Address: "2001:db8::20", Family: EndpointFamilyIPv6, Order: 3},
		{Address: "2001:db8::10", Family: EndpointFamilyIPv6, Order: 4},
	}
	if !reflect.DeepEqual(candidates, want) {
		t.Fatalf("candidates = %#v, want %#v", candidates, want)
	}

	bounded := LimitEndpointCandidates(candidates, 3)
	if !reflect.DeepEqual(bounded, want[:3]) {
		t.Fatalf("bounded candidates = %#v, want %#v", bounded, want[:3])
	}
	if len(candidates) != 4 {
		t.Fatalf("limiting returned the complete list by reference: %#v", candidates)
	}
}

func TestEndpointCandidatesNormalizeMappedAndBracketedAddresses(t *testing.T) {
	candidates := EndpointCandidatesFromAnswers(
		[]string{"[192.0.2.1]", "::ffff:192.0.2.2"},
		[]string{"[2001:0DB8:0:0:0:0:0:1]"},
	)
	if len(candidates) != 3 {
		t.Fatalf("candidate count = %d, want 3: %#v", len(candidates), candidates)
	}
	if candidates[0].Address != "192.0.2.1" || candidates[1].Address != "192.0.2.2" || candidates[2].Address != "2001:db8::1" {
		t.Fatalf("normalized candidates = %#v", candidates)
	}
	if candidates[1].Family != EndpointFamilyIPv4 || candidates[2].Family != EndpointFamilyIPv6 {
		t.Fatalf("candidate families = %#v", candidates)
	}
}

func TestProbeEndpointCandidatesLiteralIPIsSingleAndDeterministic(t *testing.T) {
	for _, test := range []struct {
		name    string
		literal string
		family  EndpointFamily
	}{
		{name: "ipv4", literal: "192.0.2.44", family: EndpointFamilyIPv4},
		{name: "ipv6", literal: "2001:db8::44", family: EndpointFamilyIPv6},
	} {
		t.Run(test.name, func(t *testing.T) {
			target := Target{RequestedIdentity: test.literal, LiteralIP: test.literal, Port: 443, ResolvedCandidates: []EndpointCandidate{
				{Address: "192.0.2.99", Family: EndpointFamilyIPv4, Order: 1},
			}}
			got := target.ProbeEndpointCandidates()
			want := []EndpointCandidate{{Address: test.literal, Family: test.family, Order: 1}}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("probe candidates = %#v, want %#v", got, want)
			}
		})
	}
}

func TestTargetEndpointSelectionMetadataDoesNotClaimOSSelection(t *testing.T) {
	target := Target{
		RequestedIdentity:  "service.example",
		Port:               443,
		ResolvedCandidates: EndpointCandidatesFromAnswers([]string{"192.0.2.10"}, []string{"2001:db8::10"}),
		SelectedEndpoint: &Endpoint{
			Address: "192.0.2.10", Port: 443, Family: EndpointFamilyIPv4,
			SelectionReason: EndpointSelectionDeterministic,
			Provenance:      "tadori bounded deterministic candidate selection",
		},
	}
	raw, err := json.Marshal(target)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Target
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.ResolvedCandidates) != 2 || decoded.ResolvedCandidates[1].Family != EndpointFamilyIPv6 {
		t.Fatalf("resolved candidates were not preserved: %#v", decoded.ResolvedCandidates)
	}
	if decoded.SelectedEndpoint == nil || decoded.SelectedEndpoint.SelectionReason != EndpointSelectionDeterministic || decoded.SelectedEndpoint.Provenance == "" {
		t.Fatalf("selection metadata = %#v", decoded.SelectedEndpoint)
	}
	if decoded.TestedEndpoint != nil {
		t.Fatalf("unobserved endpoint was populated: %#v", decoded.TestedEndpoint)
	}
}

func TestNormalizeTargetCopiesCandidateAndAttemptSlices(t *testing.T) {
	target := Target{
		RequestedIdentity: "service.example",
		Port:              443,
		ResolvedCandidates: []EndpointCandidate{{
			Address: "192.0.2.10", Family: EndpointFamilyIPv4, Order: 1,
		}},
		ProbeCandidates: []EndpointCandidate{{
			Address: "2001:db8::10", Family: EndpointFamilyIPv6, Order: 1,
		}},
		CandidateAttempts: []EndpointAttempt{{
			Candidate:     EndpointCandidate{Address: "192.0.2.10", Family: EndpointFamilyIPv4, Order: 1},
			Status:        ProbeStatusFailed,
			FailureReason: FailureReasonTCPConnectionRefused,
		}},
	}
	normalized := NormalizeTarget(target)
	target.ResolvedCandidates[0].Address = "changed"
	target.ProbeCandidates[0].Address = "changed"
	target.CandidateAttempts[0].Candidate.Address = "changed"
	if normalized.ResolvedCandidates[0].Address != "192.0.2.10" || normalized.ProbeCandidates[0].Address != "2001:db8::10" || normalized.CandidateAttempts[0].Candidate.Address != "192.0.2.10" {
		t.Fatalf("normalized target shares mutable candidate state: %#v", normalized)
	}
}
