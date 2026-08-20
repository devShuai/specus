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

	icmpEchoReply              = 0
	icmpEchoRequest            = 8
	icmpDestinationUnreachable = 3
	icmpFragmentationNeeded    = 4
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

func peerPacketMatchesAuthenticatedEndpoints(packet []byte, peerVirtualIP, localVirtualIP string) bool {
	return peerVirtualIP != "" && localVirtualIP != "" &&
		peerPacketSourceIPv4(packet) == peerVirtualIP &&
		peerPacketDestinationIPv4(packet) == localVirtualIP
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

func peerPacketClampTCPMSS(packet []byte, pathMTU int) []byte {
	if len(packet) < 20 || packet[0]>>4 != 4 || peerPacketProtocol(packet) != ipv4ProtocolTCP {
		return packet
	}
	ipHeaderLength := int(packet[0]&0x0f) * 4
	totalLength := peerPacketTotalLength(packet)
	if ipHeaderLength < 20 || totalLength < ipHeaderLength+20 || packet[ipHeaderLength+13]&0x02 == 0 {
		return packet
	}
	tcpHeaderLength := int(packet[ipHeaderLength+12]>>4) * 4
	if tcpHeaderLength < 20 || totalLength < ipHeaderLength+tcpHeaderLength {
		return packet
	}
	maxMSS := max(536, pathMTU-ipHeaderLength-20)
	for cursor, end := ipHeaderLength+20, ipHeaderLength+tcpHeaderLength; cursor < end; {
		kind := packet[cursor]
		if kind == 0 {
			break
		}
		if kind == 1 {
			cursor++
			continue
		}
		if cursor+1 >= end {
			break
		}
		optionLength := int(packet[cursor+1])
		if optionLength < 2 || cursor+optionLength > end {
			break
		}
		if kind == 2 && optionLength == 4 {
			advertised := int(binary.BigEndian.Uint16(packet[cursor+2 : cursor+4]))
			if advertised <= maxMSS {
				return packet
			}
			clamped := append([]byte(nil), packet...)
			binary.BigEndian.PutUint16(clamped[cursor+2:cursor+4], uint16(maxMSS))
			clamped[ipHeaderLength+16] = 0
			clamped[ipHeaderLength+17] = 0
			binary.BigEndian.PutUint16(
				clamped[ipHeaderLength+16:ipHeaderLength+18],
				peerPacketTCPChecksum(clamped, ipHeaderLength, totalLength-ipHeaderLength))
			return clamped
		}
		cursor += optionLength
	}
	return packet
}

func peerPacketICMPFragmentationNeededFor(packet []byte, pathMTU int) []byte {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return nil
	}
	originalHeaderLength := int(packet[0]&0x0f) * 4
	if originalHeaderLength < 20 || len(packet) < originalHeaderLength {
		return nil
	}
	originalLength := peerPacketTotalLength(packet)
	quotedLength := min(originalLength, originalHeaderLength+8)
	response := make([]byte, 20+8+quotedLength)
	response[0] = 0x45
	binary.BigEndian.PutUint16(response[2:4], uint16(len(response)))
	response[8] = 64
	response[9] = ipv4ProtocolICMP
	copy(response[12:16], packet[16:20])
	copy(response[16:20], packet[12:16])
	response[20] = icmpDestinationUnreachable
	response[21] = icmpFragmentationNeeded
	binary.BigEndian.PutUint16(response[26:28], uint16(pathMTU))
	copy(response[28:], packet[:quotedLength])
	binary.BigEndian.PutUint16(response[22:24], peerPacketChecksum(response[20:]))
	binary.BigEndian.PutUint16(response[10:12], peerPacketChecksum(response[:20]))
	return response
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

func peerPacketTCPChecksum(packet []byte, tcpOffset, tcpLength int) uint16 {
	var sum uint32
	for index := 12; index < 20; index += 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[index : index+2]))
	}
	sum += ipv4ProtocolTCP
	sum += uint32(tcpLength)
	segment := packet[tcpOffset : tcpOffset+tcpLength]
	for index := 0; index+1 < len(segment); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(segment[index : index+2]))
	}
	if len(segment)%2 == 1 {
		sum += uint32(segment[len(segment)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
