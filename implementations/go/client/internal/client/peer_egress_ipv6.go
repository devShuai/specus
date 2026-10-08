package client

import (
	"strconv"
	"strings"
)

// IPv6 addresses and prefixes as peer egress reads them (protocol/spec/peer-egress.md, IPv6 写法).
//
// One spelling for a consumer rule's match and an egress policy's destination rule, written out
// here rather than taken from net/netip, which also reads a dotted IPv4 tail and a zone and prints an
// IPv4-mapped address in dotted form. The Java, .NET, C and TypeScript implementations parse the same
// way, and the vector's ipv6Prefixes section pins every refusal a runtime parser tends to let through.

const egressMaxPrefix6 = 128

// egressCIDR6 is an IPv6 prefix with its host bits clear.
type egressCIDR6 struct {
	network   [16]byte
	prefixLen int
}

// parseEgressAddress6 reads RFC 4291 2.2 forms 1 and 2: eight groups of one to four hex digits, at
// most one "::" standing for one or more zero groups. No dotted IPv4 tail, no zone, no brackets.
func parseEgressAddress6(text string) ([16]byte, bool) {
	var address [16]byte
	if text == "" || len(text) > 39 {
		return address, false
	}
	for index := 0; index < len(text); index++ {
		if !isEgressHexDigit(text[index]) && text[index] != ':' {
			return address, false
		}
	}
	if strings.Contains(text, ":::") || strings.Count(text, "::") > 1 {
		return address, false
	}
	var groups []uint16
	if head, tail, compressed := strings.Cut(text, "::"); compressed {
		high, okHigh := egressHexGroups(head)
		low, okLow := egressHexGroups(tail)
		if !okHigh || !okLow || len(high)+len(low) > 7 {
			return address, false
		}
		groups = append(append(high, make([]uint16, 8-len(high)-len(low))...), low...)
	} else {
		all, ok := egressHexGroups(text)
		if !ok || len(all) != 8 {
			return address, false
		}
		groups = all
	}
	for index, group := range groups {
		address[2*index] = byte(group >> 8)
		address[2*index+1] = byte(group)
	}
	return address, true
}

// egressHexGroups splits colon-separated groups of one to four hex digits; "" is no groups.
func egressHexGroups(part string) ([]uint16, bool) {
	if part == "" {
		return nil, true
	}
	var groups []uint16
	for _, group := range strings.Split(part, ":") {
		if len(group) < 1 || len(group) > 4 {
			return nil, false
		}
		value, err := strconv.ParseUint(group, 16, 16)
		if err != nil {
			return nil, false
		}
		groups = append(groups, uint16(value))
	}
	return groups, true
}

func isEgressHexDigit(character byte) bool {
	return (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') ||
		(character >= 'A' && character <= 'F')
}

// parseEgressCIDR6 reads an IPv6 address or address/length: the length 0-128 in decimal without a
// leading zero, the host bits clear. A bare address is a /128. hadLength reports whether a length
// was written, which is all a server needs to store the spelling back.
func parseEgressCIDR6(text string) (cidr egressCIDR6, hadLength bool, ok bool) {
	addressPart, lengthPart, hasLength := strings.Cut(text, "/")
	address, ok := parseEgressAddress6(addressPart)
	if !ok {
		return egressCIDR6{}, false, false
	}
	if !hasLength {
		return egressCIDR6{network: address, prefixLen: egressMaxPrefix6}, false, true
	}
	if lengthPart == "" || len(lengthPart) > 3 || (len(lengthPart) > 1 && lengthPart[0] == '0') {
		return egressCIDR6{}, false, false
	}
	length := 0
	for index := 0; index < len(lengthPart); index++ {
		character := lengthPart[index]
		if character < '0' || character > '9' {
			return egressCIDR6{}, false, false
		}
		length = length*10 + int(character-'0')
	}
	if length > egressMaxPrefix6 {
		return egressCIDR6{}, false, false
	}
	cidr = egressCIDR6{network: address, prefixLen: length}
	if cidr.masked() != address {
		// Host bits set. Refused rather than masked, as for IPv4.
		return egressCIDR6{}, false, false
	}
	return cidr, true, true
}

// masked is the network with every bit past the prefix cleared.
func (c egressCIDR6) masked() [16]byte {
	return maskEgressAddress6(c.network, c.prefixLen)
}

func maskEgressAddress6(address [16]byte, prefixLen int) [16]byte {
	var out [16]byte
	for index := 0; index < 16; index++ {
		bits := prefixLen - index*8
		switch {
		case bits >= 8:
			out[index] = address[index]
		case bits > 0:
			out[index] = address[index] & (0xff << uint(8-bits))
		}
	}
	return out
}

func (c egressCIDR6) contains(address [16]byte) bool {
	return maskEgressAddress6(address, c.prefixLen) == c.network
}

// mapped reports whether the prefix lies in ::ffff:0:0/96, where IPv4 destinations are spelled in
// IPv6 APIs. No packet on the wire carries one, so a consumer rule there would never match anything.
func (c egressCIDR6) mapped() bool {
	for index := 0; index < 10; index++ {
		if c.network[index] != 0 {
			return false
		}
	}
	return c.network[10] == 0xff && c.network[11] == 0xff
}

// formatEgressAddress6 writes RFC 5952 section 4: lower case, no leading zeros in a group, and the
// longest run of two or more zero groups (the leftmost of equal runs) as "::". Never the dotted form
// of section 5, so what it writes reads back through parseEgressAddress6.
func formatEgressAddress6(address [16]byte) string {
	var groups [8]uint16
	for index := range groups {
		groups[index] = uint16(address[2*index])<<8 | uint16(address[2*index+1])
	}
	bestStart, bestLength := -1, 0
	for index := 0; index < 8; {
		if groups[index] != 0 {
			index++
			continue
		}
		end := index
		for end < 8 && groups[end] == 0 {
			end++
		}
		if end-index > bestLength {
			bestStart, bestLength = index, end-index
		}
		index = end
	}
	hex := func(from, to int) string {
		parts := make([]string, 0, to-from)
		for index := from; index < to; index++ {
			parts = append(parts, strconv.FormatUint(uint64(groups[index]), 16))
		}
		return strings.Join(parts, ":")
	}
	if bestLength < 2 {
		return hex(0, 8)
	}
	return hex(0, bestStart) + "::" + hex(bestStart+bestLength, 8)
}
