package model

import (
	"net/netip"
	"sort"
	"strings"
)

// NameResolutionPathState describes the evidence role of a resolution path.
// A configured or policy path is a candidate only; it is never evidence that
// Windows used that server or interface for the query.
type NameResolutionPathState string

const (
	NameResolutionPathConfiguredCandidate NameResolutionPathState = "configured_candidate"
	NameResolutionPathPolicyCandidate     NameResolutionPathState = "policy_candidate"
	NameResolutionPathEffective           NameResolutionPathState = "effective"
)

// NameResolutionMechanism identifies the resolver mechanism represented by a
// path. The Windows DNS client value includes the system resolver's policy and
// cache behavior; it does not claim that a packet was sent to a particular
// server.
type NameResolutionMechanism string

const (
	NameResolutionMechanismDNS       NameResolutionMechanism = "dns"
	NameResolutionMechanismHostsFile NameResolutionMechanism = "hosts_file"
	NameResolutionMechanismLiteralIP NameResolutionMechanism = "literal_ip"
	NameResolutionMechanismUnknown   NameResolutionMechanism = "unknown"
)

// NameResolutionCertainty records how strongly a path is supported. In
// particular, configured is weaker than observed and must not be presented as
// the resolver that actually answered a name.
type NameResolutionCertainty string

const (
	NameResolutionCertaintyConfigured NameResolutionCertainty = "configured"
	NameResolutionCertaintyObserved   NameResolutionCertainty = "observed"
	NameResolutionCertaintyInferred   NameResolutionCertainty = "inferred"
	NameResolutionCertaintyUnknown    NameResolutionCertainty = "unknown"
)

// NameResolutionPath is one candidate or effective resolution path. Resolver
// and Interface are intentionally optional: Windows' synchronous DNS query
// API returns answers but does not identify the server/interface selected by
// the DNS client. Empty values are therefore more truthful than guesses.
type NameResolutionPath struct {
	State          NameResolutionPathState `json:"state"`
	Mechanism      NameResolutionMechanism `json:"mechanism"`
	Resolver       string                  `json:"resolver,omitempty"`
	Interface      string                  `json:"interface,omitempty"`
	InterfaceIndex int                     `json:"interface_index,omitempty"`
	VirtualAdapter bool                    `json:"virtual_adapter,omitempty"`
	VPN            bool                    `json:"vpn,omitempty"`
	Namespace      string                  `json:"namespace,omitempty"`
	Namespaces     []string                `json:"namespaces,omitempty"`
	PolicySource   string                  `json:"policy_source,omitempty"`
	PolicyRule     string                  `json:"policy_rule,omitempty"`
	A              []string                `json:"a,omitempty"`
	AAAA           []string                `json:"aaaa,omitempty"`
	Certainty      NameResolutionCertainty `json:"certainty"`
	Provenance     string                  `json:"provenance,omitempty"`
	EvidenceIDs    []string                `json:"evidence_ids,omitempty"`
}

// NameResolutionPolicyRule is the normalized subset of an NRPT rule needed
// to explain namespace routing. Nameservers are configuration evidence, not
// proof that a matching query used one of them.
type NameResolutionPolicyRule struct {
	Namespaces               []string `json:"namespaces"`
	NameServers              []string `json:"name_servers,omitempty"`
	Source                   string   `json:"source,omitempty"`
	RuleID                   string   `json:"rule_id,omitempty"`
	VPNRequired              bool     `json:"vpn_required,omitempty"`
	DNSSECValidationRequired bool     `json:"dnssec_validation_required,omitempty"`
}

// NameResolutionHostEntry is an observable hosts-file candidate. Reading a
// matching entry proves that the local file contains it, not that the DNS
// client selected it for a particular query.
type NameResolutionHostEntry struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
	Source    string   `json:"source,omitempty"`
}

// NameResolutionObservation is the canonical normalized observation for one
// requested name. It deliberately remains separate from Target: a requested
// identity is not replaced by an answer, and configured paths are not promoted
// to effective provenance.
type NameResolutionObservation struct {
	RequestedName       string               `json:"requested_name"`
	CandidateNames      []string             `json:"candidate_names,omitempty"`
	CandidateSuffixes   []string             `json:"candidate_suffixes,omitempty"`
	CandidateNamespaces []string             `json:"candidate_namespaces,omitempty"`
	Paths               []NameResolutionPath `json:"paths,omitempty"`
	EffectivePath       *NameResolutionPath  `json:"effective_path,omitempty"`
	A                   []string             `json:"a,omitempty"`
	AAAA                []string             `json:"aaaa,omitempty"`
	// SelectedAddress is the resolver observation's deterministic
	// representative answer. It is not evidence of OS/application endpoint
	// selection; transport owns TestedEndpoint and Tadori owns its probe
	// candidate on Target.
	SelectedAddress  string                    `json:"selected_address,omitempty"`
	SelectedFamily   string                    `json:"selected_family,omitempty"`
	HostsFileEntries []NameResolutionHostEntry `json:"hosts_file_entries,omitempty"`
	Limitations      []string                  `json:"limitations,omitempty"`
	EvidenceIDs      []string                  `json:"evidence_ids,omitempty"`
}

// NormalizeNameResolutionObservation returns a copy with stable IP and
// namespace forms and duplicate addresses removed. It does not reorder paths
// because path order reflects the evidence assembly order.
func NormalizeNameResolutionObservation(observation NameResolutionObservation) NameResolutionObservation {
	observation.RequestedName = normalizeNameValue(observation.RequestedName)
	observation.CandidateNames = uniqueNameValues(observation.CandidateNames)
	observation.CandidateSuffixes = uniqueNameValues(observation.CandidateSuffixes)
	observation.CandidateNamespaces = uniqueNameValues(observation.CandidateNamespaces)
	observation.A = uniqueIPValues(observation.A)
	observation.AAAA = uniqueIPValues(observation.AAAA)
	observation.SelectedAddress = normalizeAddressText(observation.SelectedAddress)
	observation.Limitations = uniqueStringValues(observation.Limitations)
	observation.EvidenceIDs = uniqueStringValues(observation.EvidenceIDs)
	for index := range observation.Paths {
		observation.Paths[index] = normalizeNameResolutionPath(observation.Paths[index])
	}
	if observation.EffectivePath != nil {
		path := normalizeNameResolutionPath(*observation.EffectivePath)
		observation.EffectivePath = &path
	}
	for index := range observation.HostsFileEntries {
		observation.HostsFileEntries[index].Name = normalizeNameValue(observation.HostsFileEntries[index].Name)
		observation.HostsFileEntries[index].Addresses = uniqueIPValues(observation.HostsFileEntries[index].Addresses)
	}
	return observation
}

// NameResolutionPoliciesForName returns matching NRPT rules in deterministic
// order, with the most specific namespace first. A leading dot in a Windows
// suffix rule matches the suffix itself and all names below it.
func NameResolutionPoliciesForName(name string, rules []NameResolutionPolicyRule) []NameResolutionPolicyRule {
	return NameResolutionPoliciesForNames([]string{name}, rules)
}

// NameResolutionPoliciesForNames returns matching NRPT rules for any of the
// supplied candidate names. This matters for a short requested name: the
// namespace rule can match only after a DNS search suffix is applied.
func NameResolutionPoliciesForNames(names []string, rules []NameResolutionPolicyRule) []NameResolutionPolicyRule {
	normalizedNames := uniqueNameValues(names)
	matches := make([]NameResolutionPolicyRule, 0)
	seen := make(map[string]struct{})
	for _, name := range normalizedNames {
		for _, rule := range rules {
			matched := false
			for _, namespace := range rule.Namespaces {
				if nameMatchesNamespace(name, namespace) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
			key := rule.Source + "\x00" + rule.RuleID
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			matches = append(matches, rule)
		}
	}
	sort.SliceStable(matches, func(i, j int) bool {
		left, right := longestNamespace(matches[i]), longestNamespace(matches[j])
		if left != right {
			return left > right
		}
		if matches[i].Source != matches[j].Source {
			return matches[i].Source < matches[j].Source
		}
		return matches[i].RuleID < matches[j].RuleID
	})
	return matches
}

func normalizeNameResolutionPath(path NameResolutionPath) NameResolutionPath {
	path.Resolver = normalizeAddressText(path.Resolver)
	path.A = uniqueIPValues(path.A)
	path.AAAA = uniqueIPValues(path.AAAA)
	path.Namespaces = uniqueNameValues(path.Namespaces)
	path.Namespace = normalizeNameValue(path.Namespace)
	path.EvidenceIDs = uniqueStringValues(path.EvidenceIDs)
	return path
}

func uniqueIPValues(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		normalized := normalizeAddressText(value)
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}
	return result
}

func uniqueNameValues(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		normalized := normalizeNameValue(value)
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}
	return result
}

func uniqueStringValues(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func normalizeNameValue(value string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
}

func normalizeAddressText(value string) string {
	value = strings.Trim(strings.TrimSpace(value), "[]")
	if address, err := netip.ParseAddr(value); err == nil {
		return NormalizeAddr(address).String()
	}
	return value
}

func nameMatchesNamespace(name, namespace string) bool {
	name = normalizeNameValue(name)
	namespace = strings.TrimPrefix(normalizeNameValue(namespace), ".")
	if namespace == "" {
		return false
	}
	return name == namespace || strings.HasSuffix(name, "."+namespace)
}

func longestNamespace(rule NameResolutionPolicyRule) int {
	longest := 0
	for _, namespace := range rule.Namespaces {
		if length := len(normalizeNameValue(namespace)); length > longest {
			longest = length
		}
	}
	return longest
}
