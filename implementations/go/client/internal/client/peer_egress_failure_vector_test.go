package client

import (
	"encoding/hex"
	"testing"
)

// Binds what the consumer writes back into the TUN to protocol/test-vectors/peer-egress-failure-v1.json.
//
// Three runtimes that reset a flow at different sequence numbers would leave the application
// hanging on one of them: a reset a stack does not accept is a reset that was not sent.

type egressFailureVector struct {
	ResetOnPurge struct {
		Cases []struct {
			Name         string `json:"name"`
			ConsumerIP   string `json:"consumerIp"`
			ConsumerPort uint16 `json:"consumerPort"`
			RemoteIP     string `json:"remoteIp"`
			RemotePort   uint16 `json:"remotePort"`
			AppAck       uint32 `json:"appAck"`
			AppSeqNext   uint32 `json:"appSeqNext"`
			Expect       struct {
				PacketHex string `json:"packetHex"`
			} `json:"expect"`
		} `json:"cases"`
	} `json:"resetOnPurge"`
	ResetOnPacket struct {
		Cases []egressFailurePacketCase `json:"cases"`
	} `json:"resetOnPacket"`
	UnreachableOnDatagram struct {
		Cases []egressFailurePacketCase `json:"cases"`
	} `json:"unreachableOnDatagram"`
}

type egressFailurePacketCase struct {
	Name      string `json:"name"`
	PacketHex string `json:"packetHex"`
	Expect    struct {
		PacketHex string `json:"packetHex"`
	} `json:"expect"`
}

func loadEgressFailureVector(t *testing.T) egressFailureVector {
	t.Helper()
	var vector egressFailureVector
	readEgressVector(t, "peer-egress-failure-v1.json", &vector)
	if len(vector.ResetOnPurge.Cases) == 0 || len(vector.ResetOnPacket.Cases) == 0 ||
		len(vector.UnreachableOnDatagram.Cases) == 0 {
		t.Fatal("failure vector is missing a section")
	}
	return vector
}

func TestEgressFailureVectors(t *testing.T) {
	vector := loadEgressFailureVector(t)

	for _, c := range vector.ResetOnPurge.Cases {
		flow := &egressConsumerFlow{
			Key: egressFlowKey{
				protocol:     ipv4ProtocolTCP,
				consumerIP:   testAddr(t, c.ConsumerIP),
				consumerPort: c.ConsumerPort,
				remoteIP:     testAddr(t, c.RemoteIP),
				remotePort:   c.RemotePort,
			},
			AppAckKnown: true, AppAck: c.AppAck, AppSeqNext: c.AppSeqNext,
		}
		if got := hex.EncodeToString(egressFlowResetPacket(flow)); got != c.Expect.PacketHex {
			t.Errorf("purge %s:\n got %s\nwant %s", c.Name, got, c.Expect.PacketHex)
		}
	}

	for _, c := range vector.ResetOnPacket.Cases {
		packet, _ := hex.DecodeString(c.PacketHex)
		if got := hex.EncodeToString(egressFailurePacket(packet, ipv4ProtocolTCP)); got != c.Expect.PacketHex {
			t.Errorf("packet %s:\n got %s\nwant %s", c.Name, got, c.Expect.PacketHex)
		}
	}

	for _, c := range vector.UnreachableOnDatagram.Cases {
		packet, _ := hex.DecodeString(c.PacketHex)
		if got := hex.EncodeToString(egressFailurePacket(packet, ipv4ProtocolUDP)); got != c.Expect.PacketHex {
			t.Errorf("datagram %s:\n got %s\nwant %s", c.Name, got, c.Expect.PacketHex)
		}
	}
}
