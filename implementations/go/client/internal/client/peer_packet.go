package client

import (
	"encoding/binary"
	"net"
	"strconv"
)

const (
	ipv4ProtocolICMP = 1
	ipv4ProtocolTCP  = 6
	ipv4ProtocolUDP  = 17

	icmpEchoReply   = 0
	icmpEchoRequest = 8
)

func peerPacketDestinationIPv4(packet []byte) string {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return ""
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl {
		return ""
	}
	return net.IPv4(packet[16], packet[17], packet[18], packet[19]).String()
}

func peerPacketSourceIPv4(packet []byte) string {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return ""
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl {
		return ""
	}
	return net.IPv4(packet[12], packet[13], packet[14], packet[15]).String()
}

func peerPacketProtocol(packet []byte) int {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return 0
	}
	return int(packet[9])
}

func peerPacketFlowKey(packet []byte) string {
	source := peerPacketSourceIPv4(packet)
	target := peerPacketDestinationIPv4(packet)
	if source == "" || target == "" {
		return ""
	}
	protocol := peerPacketProtocol(packet)
	sourcePort, targetPort := 0, 0
	ihl := int(packet[0]&0x0f) * 4
	if (protocol == ipv4ProtocolTCP || protocol == ipv4ProtocolUDP) && len(packet) >= ihl+4 {
		sourcePort = int(binary.BigEndian.Uint16(packet[ihl : ihl+2]))
		targetPort = int(binary.BigEndian.Uint16(packet[ihl+2 : ihl+4]))
	}
	return source + ":" + strconv.Itoa(sourcePort) + "->" + target + ":" + strconv.Itoa(targetPort) + "/" + strconv.Itoa(protocol)
}

func peerPacketICMPEchoReplyFor(packet []byte, localVirtualIP string) []byte {
	if !peerPacketIsICMPEchoRequestFor(packet, localVirtualIP) {
		return nil
	}
	ihl := int(packet[0]&0x0f) * 4
	totalLength := peerPacketTotalLength(packet)
	reply := append([]byte(nil), packet[:totalLength]...)
	copy(reply[12:16], packet[16:20])
	copy(reply[16:20], packet[12:16])
	reply[8] = 64
	reply[10] = 0
	reply[11] = 0

	reply[ihl] = icmpEchoReply
	reply[ihl+1] = 0
	reply[ihl+2] = 0
	reply[ihl+3] = 0
	icmpChecksum := peerPacketChecksum(reply[ihl:totalLength])
	binary.BigEndian.PutUint16(reply[ihl+2:ihl+4], icmpChecksum)

	ipChecksum := peerPacketChecksum(reply[:ihl])
	binary.BigEndian.PutUint16(reply[10:12], ipChecksum)
	return reply
}

func peerPacketIsICMPEchoRequestFor(packet []byte, localVirtualIP string) bool {
	if peerPacketDestinationIPv4(packet) != localVirtualIP {
		return false
	}
	ihl := int(packet[0]&0x0f) * 4
	totalLength := peerPacketTotalLength(packet)
	return totalLength >= ihl+8 &&
		totalLength <= len(packet) &&
		peerPacketProtocol(packet) == ipv4ProtocolICMP &&
		int(packet[ihl]) == icmpEchoRequest &&
		int(packet[ihl+1]) == 0
}

func peerPacketTotalLength(packet []byte) int {
	if len(packet) < 4 {
		return 0
	}
	totalLength := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLength > 0 && totalLength <= len(packet) {
		return totalLength
	}
	return len(packet)
}

func peerPacketChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
