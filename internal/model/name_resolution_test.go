package model

import "testing"

func TestNameResolutionPoliciesForNamesMatchesSuffixExpandedShortName(t *testing.T) {
	rules := []NameResolutionPolicyRule{
		{Namespaces: []string{".example"}, RuleID: "broad"},
		{Namespaces: []string{".corp.example"}, RuleID: "specific"},
		{Namespaces: []string{"other.example"}, RuleID: "other"},
	}
	got := NameResolutionPoliciesForNames([]string{"fileserver", "fileserver.corp.example"}, rules)
	if len(got) != 2 || got[0].RuleID != "specific" || got[1].RuleID != "broad" {
		t.Fatalf("matching rules = %#v, want specific then broad", got)
	}
}

func TestNormalizeNameResolutionObservationPreservesPathRoleAndNormalizesAddresses(t *testing.T) {
	observation := NormalizeNameResolutionObservation(NameResolutionObservation{
		RequestedName:   "Fileserver.Corp.Example.",
		A:               []string{"::ffff:10.0.0.2", "10.0.0.2"},
		SelectedAddress: "10.0.0.2",
		Limitations:     []string{"unknown provenance", "unknown provenance"},
		Paths: []NameResolutionPath{{
			State:      NameResolutionPathConfiguredCandidate,
			Mechanism:  NameResolutionMechanismDNS,
			Resolver:   "[2001:db8::53]",
			Namespaces: []string{"Corp.Example.", "corp.example"},
			Certainty:  NameResolutionCertaintyConfigured,
			Provenance: "configuration only",
		}},
	})
	if observation.RequestedName != "fileserver.corp.example" {
		t.Fatalf("requested name = %q, want normalized name", observation.RequestedName)
	}
	if len(observation.A) != 1 || observation.A[0] != "10.0.0.2" {
		t.Fatalf("normalized A answers = %#v", observation.A)
	}
	if len(observation.Paths) != 1 || observation.Paths[0].Resolver != "2001:db8::53" || len(observation.Paths[0].Namespaces) != 1 {
		t.Fatalf("normalized candidate path = %#v", observation.Paths)
	}
	if len(observation.Limitations) != 1 {
		t.Fatalf("limitations = %#v, want one deduplicated limitation", observation.Limitations)
	}
	if observation.Paths[0].State != NameResolutionPathConfiguredCandidate || observation.Paths[0].Certainty != NameResolutionCertaintyConfigured {
		t.Fatalf("path certainty/role changed: %#v", observation.Paths[0])
	}
}
