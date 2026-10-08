package peeregress

import (
	"strconv"
	"strings"
)

// IPv6 addresses and prefixes as peer egress reads them (protocol/spec/peer-egress.md, IPv6 写法):
// the spelling a consumer rule's match and an egress policy's destination rule share, pinned by the
// ipv6Prefixes section of protocol/test-vectors/peer-egress-rules-v1.json.
//
// Written out rather than taken from net/netip, which also reads a dotted IPv4 tail and a zone and
// prints an IPv4-mapped address in dotted form; the clients and the other servers refuse the former
// and never write the latter.

// MaxPrefix6 is the widest IPv6 prefix length.
const MaxPrefix6 = 128

// CIDR6 is an IPv6 prefix with its host bits clear.
type CIDR6 struct {
	Network   [16]byte
	PrefixLen int
}

// ParseAddress6 reads RFC 4291 2.2 forms 1 and 2: eight groups of one to four hex digits, at most
// one "::" standing for one or more zero groups. No dotted IPv4 tail, no zone, no brackets.
func ParseAddress6(text string) ([16]byte, bool) {
	var address [16]byte
	if text == "" || len(text) > 39 {
		return address, false
	}
	for index := 0; index < len(text); index++ {
		character := text[index]
		hex := (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') ||
			(character >= 'A' && character <= 'F')
		if !hex && character != ':' {
			return address, false
		}
	}
	if strings.Contains(text, ":::") || strings.Count(text, "::") > 1 {
		return address, false
	}
	var groups []uint16
	if head, tail, compressed := strings.Cut(text, "::"); compressed {
		high, okHigh := hexGroups(head)
		low, okLow := hexGroups(tail)
		if !okHigh || !okLow || len(high)+len(low) > 7 {
			return address, false
		}
		groups = append(append(high, make([]uint16, 8-len(high)-len(low))...), low...)
	} else {
		all, ok := hexGroups(text)
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

func hexGroups(part string) ([]uint16, bool) {
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

// ParseCIDR6 reads an IPv6 address or address/length: the length 0-128 in decimal without a leading
// zero, the host bits clear. A bare address is a /128; hadLength reports whether a length was written.
func ParseCIDR6(text string) (cidr CIDR6, hadLength bool, ok bool) {
	addressPart, lengthPart, hasLength := strings.Cut(text, "/")
	address, ok := ParseAddress6(addressPart)
	if !ok {
		return CIDR6{}, false, false
	}
	if !hasLength {
		return CIDR6{Network: address, PrefixLen: MaxPrefix6}, false, true
	}
	if lengthPart == "" || len(lengthPart) > 3 || (len(lengthPart) > 1 && lengthPart[0] == '0') {
		return CIDR6{}, false, false
	}
	length := 0
	for index := 0; index < len(lengthPart); index++ {
		character := lengthPart[index]
		if character < '0' || character > '9' {
			return CIDR6{}, false, false
		}
		length = length*10 + int(character-'0')
	}
	if length > MaxPrefix6 || mask6(address, length) != address {
		return CIDR6{}, false, false
	}
	return CIDR6{Network: address, PrefixLen: length}, true, true
}

func mask6(address [16]byte, prefixLen int) [16]byte {
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

// Contains reports whether an address lies in the prefix.
func (c CIDR6) Contains(address [16]byte) bool {
	return mask6(address, c.PrefixLen) == c.Network
}

// Mapped reports whether the prefix lies in ::ffff:0:0/96, where IPv4 destinations are spelled in
// IPv6 APIs. No packet carries one, so a consumer rule there would never match.
func (c CIDR6) Mapped() bool {
	for index := 0; index < 10; index++ {
		if c.Network[index] != 0 {
			return false
		}
	}
	return c.Network[10] == 0xff && c.Network[11] == 0xff
}

// FormatAddress6 writes RFC 5952 section 4: lower case, no leading zeros in a group, the longest run
// of two or more zero groups (the leftmost of equal runs) as "::". Never the dotted form of section
// 5, so what it writes reads back through ParseAddress6.
func FormatAddress6(address [16]byte) string {
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

// StoredDestinationCIDR is what a server stores for an egress policy's destination CIDR, already
// trimmed: an IPv4 one as written, since it has one spelling, and an IPv6 one in RFC 5952 form with
// the /length kept only when it was written. false when the egress could not read it
// (protocol/test-vectors/peer-egress-management-v1.json).
func StoredDestinationCIDR(text string) (string, bool) {
	if !strings.Contains(text, ":") {
		_, ok := ParseCIDR(text)
		return text, ok
	}
	cidr, hadLength, ok := ParseCIDR6(text)
	if !ok {
		return "", false
	}
	stored := FormatAddress6(cidr.Network)
	if hadLength {
		stored += "/" + strconv.Itoa(cidr.PrefixLen)
	}
	return stored, true
}
