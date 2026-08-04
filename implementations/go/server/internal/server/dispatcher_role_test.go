package server

import (
	"testing"

	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
)

func TestPacketAllowedForRoleUsesClientFrameWhitelist(t *testing.T) {
	allowedControl := []protocol.Packet{
		protocol.MessageRequest{}, protocol.HeartbeatRequest{},
		protocol.HeartbeatResponse{}, protocol.LogoutRequest{},
	}
	allowedData := []protocol.Packet{
		protocol.NatMessage{}, protocol.HeartbeatRequest{},
		protocol.HeartbeatResponse{}, protocol.LogoutRequest{},
	}
	serverResponses := []protocol.Packet{
		protocol.LoginResponse{}, protocol.MessageResponse{}, protocol.LogoutResponse{},
	}

	for _, packet := range allowedControl {
		if !packetAllowedForRole(protocol.ConnectionRoleControl, packet) {
			t.Errorf("control rejected %T", packet)
		}
	}
	for _, packet := range allowedData {
		if !packetAllowedForRole(protocol.ConnectionRoleData, packet) {
			t.Errorf("data rejected %T", packet)
		}
	}
	for _, packet := range serverResponses {
		if packetAllowedForRole(protocol.ConnectionRoleControl, packet) {
			t.Errorf("control accepted server response %T", packet)
		}
		if packetAllowedForRole(protocol.ConnectionRoleData, packet) {
			t.Errorf("data accepted server response %T", packet)
		}
	}
	if packetAllowedForRole(protocol.ConnectionRoleControl, protocol.NatMessage{}) {
		t.Error("control accepted NAT_MESSAGE")
	}
	if packetAllowedForRole(protocol.ConnectionRoleData, protocol.MessageRequest{}) {
		t.Error("data accepted MESSAGE_REQUEST")
	}
}
