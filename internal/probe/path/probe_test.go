package path

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/yohnark/tadori/internal/model"
	probecontract "github.com/yohnark/tadori/internal/probe"
)

func TestProbePreservesMultipleRespondersAndUnobservableTTLs(t *testing.T) {
	observer := ObserverFunc(func(_ context.Context, request Request) (Observation, error) {
		if request.Protocol == model.PathProtocolICMP {
			switch request.TTL {
			case 1:
				if request.Attempt == 0 {
					return Observation{Responders: []model.PathResponder{{Address: "10.0.0.1", Response: "icmp_time_exceeded"}}}, nil
				}
				return Observation{Responders: []model.PathResponder{{Address: "10.0.0.2", Response: "icmp_time_exceeded"}}}, nil
			case 3:
				return Observation{Responders: []model.PathResponder{{Address: "10.0.0.3", Response: "icmp_echo_reply"}}, DestinationReached: true}, nil
			}
			return Observation{}, nil
		}
		if request.TTL == 3 {
			return Observation{Responders: []model.PathResponder{{Address: "198.51.100.10", Response: "tcp_connected"}}, DestinationReached: true}, nil
		}
		return Observation{}, nil
	})

	result := New(Config{
		Timeout:   time.Second,
		MaxTTL:    4,
		Attempts:  2,
		Observer:  observer,
		Protocols: []model.PathProtocol{model.PathProtocolICMP, model.PathProtocolTCP},
	}).Run(context.Background(), probecontract.ExecutionContext{Target: model.NewTarget("198.51.100.10", 8443)})

	if result.Status != model.ProbeStatusPassed {
		t.Fatalf("status = %q, want passed", result.Status)
	}
	if result.Interpretation.Layer != model.LayerTCP || result.Interpretation.FailureReason != model.FailureReasonNone {
		t.Fatalf("interpretation = %#v, want successful TCP endpoint evidence", result.Interpretation)
	}
	if len(result.Evidence) != 2 {
		t.Fatalf("evidence count = %d, want two protocol observations", len(result.Evidence))
	}

	var observations []model.PathObservation
	for _, evidence := range result.Evidence {
		observation, err := model.DecodePathObservation(evidence)
		if err != nil {
			t.Fatalf("decode %s: %v", evidence.ID, err)
		}
		observations = append(observations, observation)
	}
	icmp := findObservation(t, observations, model.PathProtocolICMP)
	if len(icmp.Hops) != 3 {
		t.Fatalf("ICMP hops = %d, want through destination TTL", len(icmp.Hops))
	}
	if len(icmp.Hops[0].Responders) != 2 || icmp.Hops[0].State != model.PathHopStateObserved {
		t.Fatalf("multiple TTL-1 responders were not retained: %#v", icmp.Hops[0])
	}
	if icmp.Hops[1].State != model.PathHopStateUnobservable || len(icmp.Hops[1].Responders) != 0 {
		t.Fatalf("missing TTL response was not represented as unobservable: %#v", icmp.Hops[1])
	}
	if !hasSegment(icmp.Segments, model.PathSegmentUnobservable) || !hasSegment(icmp.Segments, model.PathSegmentInferred) {
		t.Fatalf("segment distinctions were not preserved: %#v", icmp.Segments)
	}
	if icmp.DestinationPort != 8443 || icmp.PortAware {
		t.Fatalf("ICMP port correlation metadata is wrong: %#v", icmp)
	}

	tcp := findObservation(t, observations, model.PathProtocolTCP)
	if !tcp.PortAware || tcp.DestinationPort != 8443 || !tcp.DestinationReached {
		t.Fatalf("TCP destination-port observation is incomplete: %#v", tcp)
	}
	if tcp.Hops[0].State != model.PathHopStateUnobservable || tcp.Hops[1].State != model.PathHopStateUnobservable {
		t.Fatalf("TCP missing intermediate responses were treated as loss: %#v", tcp.Hops)
	}

	correlations := model.CorrelatePathObservations(observations...)
	if len(correlations) != 1 || !correlations[0].TCPDestinationReached || correlations[0].ICMPDestinationReached != icmp.DestinationReached {
		t.Fatalf("protocol observations were not correlated by endpoint: %#v", correlations)
	}
}

func TestProbeKeepsTCPPathWhenICMPIsUnsupported(t *testing.T) {
	result := New(Config{
		Timeout:  time.Second,
		MaxTTL:   1,
		Attempts: 1,
		Observer: ObserverFunc(func(_ context.Context, request Request) (Observation, error) {
			if request.Protocol == model.PathProtocolICMP {
				return Observation{}, ErrUnsupported
			}
			return Observation{Responders: []model.PathResponder{{Address: "127.0.0.1"}}, DestinationReached: true}, nil
		}),
	}).Run(context.Background(), probecontract.ExecutionContext{Target: model.NewTarget("127.0.0.1", 9)})

	if result.Status != model.ProbeStatusPassed || result.Interpretation.Layer != model.LayerTCP {
		t.Fatalf("TCP observation did not survive unsupported ICMP: %#v", result)
	}
	var sawUnsupported bool
	for _, evidence := range result.Evidence {
		observation, err := model.DecodePathObservation(evidence)
		if err != nil {
			t.Fatal(err)
		}
		if observation.Protocol == model.PathProtocolICMP && observation.Status == model.PathObservationStatusUnsupported {
			sawUnsupported = true
		}
	}
	if !sawUnsupported {
		t.Fatalf("unsupported ICMP observation was not retained: %#v", result.Evidence)
	}
}

func TestProbeBoundsObserverAndHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	observerStarted := make(chan struct{})
	var once sync.Once
	observer := ObserverFunc(func(ctx context.Context, _ Request) (Observation, error) {
		once.Do(func() { close(observerStarted) })
		<-ctx.Done()
		return Observation{}, ctx.Err()
	})
	go func() {
		<-observerStarted
		cancel()
	}()

	result := New(Config{Timeout: time.Second, MaxTTL: 2, Attempts: 1, Observer: observer}).Run(ctx, probecontract.ExecutionContext{Target: model.NewTarget("example.com", 443)})
	if result.Status != model.ProbeStatusError || result.Interpretation.FailureReason != FailureReasonPathCancellation {
		t.Fatalf("cancellation result = %#v, want bounded cancellation", result)
	}
}

func TestProbeUnknownProtocolIsAnError(t *testing.T) {
	result := New(Config{Protocols: []model.PathProtocol{"udp"}, Observer: ObserverFunc(func(context.Context, Request) (Observation, error) {
		return Observation{}, errors.New("observer should not be called")
	})}).Run(context.Background(), probecontract.ExecutionContext{Target: model.NewTarget("example.com", 443)})
	if result.Status != model.ProbeStatusError || result.Interpretation.FailureReason != FailureReasonPathObservation {
		t.Fatalf("unknown protocol result = %#v", result)
	}
}

func TestProbeICMPOperationalFailureIsICMPOnly(t *testing.T) {
	result := New(Config{
		Protocols: []model.PathProtocol{model.PathProtocolICMP},
		Observer: ObserverFunc(func(context.Context, Request) (Observation, error) {
			return Observation{}, errors.New("icmp receive failed")
		}),
	}).Run(context.Background(), probecontract.ExecutionContext{Target: model.NewTarget("198.51.100.1", 443)})
	if result.Status != model.ProbeStatusError || result.Interpretation.FailureReason != model.FailureReasonICMPFailure || result.Interpretation.Layer != model.LayerICMP {
		t.Fatalf("ICMP operational failure was promoted: %#v", result)
	}
}

func findObservation(t *testing.T, observations []model.PathObservation, protocol model.PathProtocol) model.PathObservation {
	t.Helper()
	for _, observation := range observations {
		if observation.Protocol == protocol {
			return observation
		}
	}
	t.Fatalf("observation %q not found", protocol)
	return model.PathObservation{}
}

func hasSegment(segments []model.PathSegment, kind model.PathSegmentKind) bool {
	for _, segment := range segments {
		if segment.Kind == kind {
			return true
		}
	}
	return false
}

func TestPathObservationJSONRoundTrip(t *testing.T) {
	observation := model.PathObservation{
		Status:             model.PathObservationStatusObserved,
		Protocol:           model.PathProtocolTCP,
		Destination:        "198.51.100.10",
		DestinationPort:    9443,
		PortAware:          true,
		MaxTTL:             3,
		AttemptsPerTTL:     2,
		DestinationReached: true,
		Hops:               []model.PathHop{{TTL: 1, State: model.PathHopStateUnobservable, Attempts: 2}},
		Segments:           []model.PathSegment{{Kind: model.PathSegmentUnobservable, FromTTL: 1, ToTTL: 1}},
	}
	encoded, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	var decoded model.PathObservation
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, observation) {
		t.Fatalf("path observation round trip changed value: %#v != %#v", decoded, observation)
	}
}
