package client

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type consumerFlowVector struct {
	Consumer string `json:"consumer"`
	Cases    []struct {
		Name     string `json:"name"`
		Capacity int    `json:"capacity"`
		Events   []struct {
			At       int64  `json:"at"`
			Out      *int   `json:"out"`
			In       *int   `json:"in"`
			Known    *int   `json:"known"`
			Count    bool   `json:"count"`
			Protocol string `json:"protocol"`
			Flags    string `json:"flags"`
		} `json:"events"`
		Results []any `json:"results"`
	} `json:"cases"`
}

func tcpFlagsFromLetters(letters string) byte {
	var flags byte
	for _, letter := range letters {
		switch letter {
		case 'S':
			flags |= tcpFlagSYN
		case 'A':
			flags |= tcpFlagACK
		case 'F':
			flags |= tcpFlagFIN
		case 'R':
			flags |= tcpFlagRST
		}
	}
	return flags
}

// Every case of peer-egress-consumer-flows-v1.json through the real consumer: packets out of the
// TUN, replies back from the egress, and whether a flow is still remembered at a given time.
func TestConsumerFlowsMatchTheSharedVector(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "..", "protocol", "test-vectors", "peer-egress-consumer-flows-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector consumerFlowVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	for _, c := range vector.Cases {
		harness := newConsumerHarness(t, consumerRules(), map[int64]bool{2: true})
		harness.consumer.configure(consumerRules(), egressDefaultMeshCIDR, vector.Consumer, flowEpoch)
		harness.consumer.flowCapacity = c.Capacity
		protocols := map[int]string{}
		at := func(seconds int64) time.Time { return flowEpoch.Add(time.Duration(seconds) * time.Second) }
		for index, event := range c.Events {
			now := at(event.At)
			var got any
			switch {
			case event.Out != nil:
				port := uint16(*event.Out)
				protocols[*event.Out] = event.Protocol
				var packet []byte
				if event.Protocol == "udp" {
					packet = buildUDPDatagram(udpDatagram{SourceIP: testAddr(t, vector.Consumer), DestinationIP: testAddr(t, "203.0.113.10"),
						SourcePort: port, DestinationPort: 443, Payload: []byte("q")})
				} else {
					packet = buildTCPSegment(tcpSegment{SourceIP: testAddr(t, vector.Consumer), DestinationIP: testAddr(t, "203.0.113.10"),
						SourcePort: port, DestinationPort: 443, Seq: 1000, Ack: 1, Flags: tcpFlagsFromLetters(event.Flags), Window: 65535})
				}
				got = harness.consumer.handleOutbound(packet, now).String()
			case event.In != nil:
				port := uint16(*event.In)
				var packet []byte
				if protocols[*event.In] == "udp" {
					packet = buildUDPDatagram(udpDatagram{SourceIP: testAddr(t, "203.0.113.10"), DestinationIP: testAddr(t, vector.Consumer),
						SourcePort: 443, DestinationPort: port, Payload: []byte("r")})
				} else {
					packet = buildTCPSegment(tcpSegment{SourceIP: testAddr(t, "203.0.113.10"), DestinationIP: testAddr(t, vector.Consumer),
						SourcePort: 443, DestinationPort: port, Seq: 1, Ack: 1001, Flags: tcpFlagsFromLetters(event.Flags), Window: 65535})
				}
				before := len(harness.toTun)
				harness.consumer.handleInbound(encodePeerEgressFrame(peerEgressTypeIPPacket, false, packet), 2, now)
				got = "return-no-flow"
				if len(harness.toTun) > before {
					got = "delivered"
				}
			case event.Known != nil:
				harness.consumer.mu.Lock()
				flow := harness.consumer.liveFlowLocked(egressFlowKey{protocol: protocolNumberForEgressName(protocols[*event.Known]),
					consumerIP: testAddr(t, vector.Consumer), consumerPort: uint16(*event.Known),
					remoteIP: testAddr(t, "203.0.113.10"), remotePort: 443}, now)
				harness.consumer.mu.Unlock()
				got = flow != nil
			default:
				harness.consumer.mu.Lock()
				harness.consumer.sweepLocked(now)
				count := len(harness.consumer.flows)
				harness.consumer.mu.Unlock()
				got = float64(count)
			}
			if got != c.Results[index] {
				t.Errorf("%s event %d: %v, want %v", c.Name, index, got, c.Results[index])
			}
		}
	}
}
