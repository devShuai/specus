package peeregress

import "strings"

// MaxPrefix is the widest IPv4 prefix length.
const MaxPrefix = 32

// CIDR is an IPv4 prefix.
//
// Parsing is strict on purpose: a prefix whose host bits are set is rejected rather than masked,
// and a leading-zero octet is rejected rather than tolerated. Runtimes disagree about 010 — decimal
// ten or octal eight — and an access rule that means different things in different implementations
// is worse than one the operator has to rewrite.
type CIDR struct {
	Network   uint32
	PrefixLen int
}

// ParseCIDR reads an IPv4 address or prefix. A bare address becomes a /32.
func ParseCIDR(text string) (CIDR, bool) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return CIDR{}, false
	}
	addressPart, prefixPart, hasPrefix := strings.Cut(trimmed, "/")
	address, ok := ParseAddress(addressPart)
	if !ok {
		return CIDR{}, false
	}
	if !hasPrefix {
		return CIDR{Network: address, PrefixLen: MaxPrefix}, true
	}
	if prefixPart == "" || len(prefixPart) > 2 {
		return CIDR{}, false
	}
	if len(prefixPart) > 1 && prefixPart[0] == '0' {
		return CIDR{}, false
	}
	prefix := 0
	for i := 0; i < len(prefixPart); i++ {
		c := prefixPart[i]
		if c < '0' || c > '9' {
			return CIDR{}, false
		}
		prefix = prefix*10 + int(c-'0')
	}
	if prefix > MaxPrefix {
		return CIDR{}, false
	}
	if address&^maskFor(prefix) != 0 {
		return CIDR{}, false
	}
	return CIDR{Network: address, PrefixLen: prefix}, true
}

// ParseAddress reads four canonical dotted-decimal octets.
func ParseAddress(text string) (uint32, bool) {
	var value uint32
	octets := 0
	start := 0
	for i := 0; i <= len(text); i++ {
		if i != len(text) && text[i] != '.' {
			continue
		}
		digits := i - start
		if digits < 1 || digits > 3 || octets > 3 {
			return 0, false
		}
		if digits > 1 && text[start] == '0' {
			return 0, false
		}
		part := 0
		for j := start; j < i; j++ {
			c := text[j]
			if c < '0' || c > '9' {
				return 0, false
			}
			part = part*10 + int(c-'0')
		}
		if part > 255 {
			return 0, false
		}
		value = value<<8 | uint32(part)
		octets++
		start = i + 1
	}
	if octets != 4 {
		return 0, false
	}
	return value, true
}

// FormatAddress renders an address in dotted-decimal form.
func FormatAddress(value uint32) string {
	buf := make([]byte, 0, 15)
	for shift := 24; shift >= 0; shift -= 8 {
		if shift != 24 {
			buf = append(buf, '.')
		}
		buf = appendUint(buf, byte(value>>uint(shift)))
	}
	return string(buf)
}

func appendUint(buf []byte, v byte) []byte {
	if v >= 100 {
		buf = append(buf, '0'+v/100)
	}
	if v >= 10 {
		buf = append(buf, '0'+(v/10)%10)
	}
	return append(buf, '0'+v%10)
}

func maskFor(prefixLen int) uint32 {
	if prefixLen == 0 {
		return 0
	}
	return ^uint32(0) << uint(MaxPrefix-prefixLen)
}

// Contains reports whether the address falls inside the prefix.
func (c CIDR) Contains(address uint32) bool {
	mask := maskFor(c.PrefixLen)
	return address&mask == c.Network&mask
}

// Overlaps reports whether the two prefixes share any address.
func (c CIDR) Overlaps(other CIDR) bool {
	shared := c.PrefixLen
	if other.PrefixLen < shared {
		shared = other.PrefixLen
	}
	mask := maskFor(shared)
	return c.Network&mask == other.Network&mask
}

// String renders the prefix in canonical form.
func (c CIDR) String() string {
	return FormatAddress(c.Network) + "/" + itoa(c.PrefixLen)
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [3]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

func containedIn(address uint32, cidrs []string) bool {
	for _, text := range cidrs {
		if cidr, ok := ParseCIDR(text); ok && cidr.Contains(address) {
			return true
		}
	}
	return false
}
