package web

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/yohnark/tadori/internal/model"
)

func TestPathGraphProjectionCoversRepresentativePathSemantics(t *testing.T) {
	fixtures := representativeUIFixtures()

	t.Run("linear path keeps TTL order and destination confirmation distinct", func(t *testing.T) {
		view, err := BuildDiagnosticView(fixtures["complete-observable-path"])
		if err != nil {
			t.Fatal(err)
		}
		graph := pathGraphFor(view, model.PathProtocolTCP, 443)
		if !graph.Supported {
			t.Fatal("observed path graph is not supported")
		}
		if len(graph.Groups) != 5 || len(graph.Nodes) != 5 {
			t.Fatalf("linear graph groups/nodes = %d/%d, want 5/5: %#v", len(graph.Groups), len(graph.Nodes), graph)
		}
		for index, ttl := range []uint8{0, 1, 2, 3, 0} {
			if graph.Groups[index].FromTTL != ttl || graph.Groups[index].ToTTL != ttl {
				t.Fatalf("group %d TTL = %d-%d, want %d", index, graph.Groups[index].FromTTL, graph.Groups[index].ToTTL, ttl)
			}
		}
		destination := graph.Nodes[len(graph.Nodes)-1]
		if destination.Kind != pathGraphNodeDestination || !destination.DestinationConfirmed || destination.Role != pathGraphRoleDestination {
			t.Fatalf("destination node = %#v", destination)
		}
		if graph.Edges[len(graph.Edges)-1].Kind != pathGraphEdgeDestinationConfirm {
			t.Fatalf("last edge = %#v", graph.Edges[len(graph.Edges)-1])
		}
	})

	t.Run("long unobservable range remains explicit after a responder", func(t *testing.T) {
		view, err := BuildDiagnosticView(fixtures["destination-reached-unobservable-intermediate"])
		if err != nil {
			t.Fatal(err)
		}
		graph := pathGraphFor(view, model.PathProtocolTCP, 443)
		var ranges []PathGraphNodeView
		for _, node := range graph.Nodes {
			if node.Kind == pathGraphNodeUnobservableRange {
				ranges = append(ranges, node)
			}
		}
		if len(ranges) != 1 || ranges[0].TTLFrom != 2 || ranges[0].TTLTo != 4 {
			t.Fatalf("unobservable graph nodes = %#v, want one TTL 2-4 range", ranges)
		}
		if ranges[0].Address != "" || ranges[0].Certainty != model.ObservationCertaintyUnknown || !strings.Contains(ranges[0].Detail, "not packet loss") {
			t.Fatalf("unobservable range lost its semantics: %#v", ranges[0])
		}
		if !graph.DestinationReached || !graph.DestinationTCPConnected {
			t.Fatalf("destination confirmation was lost after the range: %#v", graph)
		}
		if !strings.Contains(strings.Join(graph.Limitations, " "), "independent of visibility") {
			t.Fatalf("range limitation does not preserve destination independence: %#v", graph.Limitations)
		}
	})

	t.Run("multiple responders remain separate nodes in one TTL group", func(t *testing.T) {
		view, err := BuildDiagnosticView(fixtures["multiple-responders"])
		if err != nil {
			t.Fatal(err)
		}
		graph := pathGraphFor(view, model.PathProtocolICMP, 443)
		var ecmpGroup PathGraphGroupView
		for _, group := range graph.Groups {
			if group.FromTTL == 2 && group.ToTTL == 2 {
				ecmpGroup = group
				break
			}
		}
		if len(ecmpGroup.NodeIDs) != 2 {
			t.Fatalf("ECMP group node IDs = %v, want two distinct nodes", ecmpGroup.NodeIDs)
		}
		addresses := make(map[string]bool)
		for _, node := range graph.Nodes {
			if node.TTL == 2 {
				addresses[node.Address] = true
			}
		}
		if !addresses["198.51.100.1"] || !addresses["198.51.100.2"] || len(addresses) != 2 {
			t.Fatalf("ECMP addresses = %v", addresses)
		}
	})

	t.Run("ICMP and TCP visibility retain independent lane context", func(t *testing.T) {
		view, err := BuildDiagnosticView(fixtures["icmp-unobservable-tcp-reaches"])
		if err != nil {
			t.Fatal(err)
		}
		icmp := pathGraphFor(view, model.PathProtocolICMP, 443)
		tcp := pathGraphFor(view, model.PathProtocolTCP, 443)
		if icmp.PortAware || !tcp.PortAware {
			t.Fatalf("unexpected port context: icmp=%t tcp=%t", icmp.PortAware, tcp.PortAware)
		}
		if icmp.DestinationReached || !tcp.DestinationTCPConnected {
			t.Fatalf("protocol lanes disagreed or were promoted: icmp=%#v tcp=%#v", icmp, tcp)
		}
		if !strings.Contains(strings.Join(icmp.Limitations, " "), "does not prove destination-port connectivity") {
			t.Fatalf("ICMP limitation missing: %#v", icmp.Limitations)
		}
	})
}

func TestPathGraphProjectionIsDeterministicForUnorderedCanonicalSlices(t *testing.T) {
	fixture := representativeUIFixtures()["multiple-responders"]
	observation := fixture.Observations.Paths[0]
	if len(observation.Hops) < 2 {
		t.Fatal("fixture does not contain enough hops")
	}
	shuffled := observation
	shuffled.Hops = append([]model.PathHop(nil), observation.Hops...)
	for left, right := 0, len(shuffled.Hops)-1; left < right; left, right = left+1, right-1 {
		shuffled.Hops[left], shuffled.Hops[right] = shuffled.Hops[right], shuffled.Hops[left]
	}
	for index := range shuffled.Hops {
		if shuffled.Hops[index].TTL != 2 {
			continue
		}
		shuffled.Hops[index].Responders = append([]model.PathResponder(nil), observation.Hops[index].Responders...)
		for left, right := 0, len(shuffled.Hops[index].Responders)-1; left < right; left, right = left+1, right-1 {
			shuffled.Hops[index].Responders[left], shuffled.Hops[index].Responders[right] = shuffled.Hops[index].Responders[right], shuffled.Hops[index].Responders[left]
		}
		break
	}

	first := buildPathGraphView(observation, []string{"path/icmp"}, []string{"probe:path-ecmp"}, pathObservationLimitations(observation))
	second := buildPathGraphView(shuffled, []string{"path/icmp"}, []string{"probe:path-ecmp"}, pathObservationLimitations(shuffled))
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) || string(firstJSON) != string(secondJSON) {
		t.Fatalf("graph projection changed with canonical slice order\nfirst: %s\nsecond: %s", firstJSON, secondJSON)
	}
}

func pathGraphFor(view DiagnosticViewModel, protocol model.PathProtocol, port uint16) PathGraphView {
	for _, path := range view.Paths {
		if path.Protocol == protocol && path.DestinationPort == port {
			return path.Graph
		}
	}
	panic(fmt.Sprintf("path graph %s/%d not found", protocol, port))
}
