"""The IPv6 address and prefix spelling peer egress reads (protocol/spec/peer-egress.md, IPv6 写法).

One grammar for a consumer rule's match and an egress policy's destination CIDR, written out here
rather than taken from ipaddress: ipaddress also reads a dotted IPv4 tail and a zone index, both of
which the implementations refuse, and prints an IPv4-mapped address in dotted form, which they do
not. Every expectation the generators emit is checked against this module, and the valid spellings
are cross-checked against ipaddress so the module cannot drift from what the numbers mean.
"""
import ipaddress
import re

HEX_GROUP = re.compile(r"[0-9A-Fa-f]{1,4}")
PREFIX = re.compile(r"0|[1-9][0-9]{0,2}")
MAX_PREFIX = 128
# ::ffff:0:0/96, the IPv4-mapped block: the top 96 bits of every address in it.
MAPPED_HIGH = 0xFFFF


def _groups(part):
    if part == "":
        return []
    values = []
    for group in part.split(":"):
        if not HEX_GROUP.fullmatch(group):
            return None
        values.append(int(group, 16))
    return values


def parse_address(text):
    """RFC 4291 2.2 forms 1 and 2: eight groups of one to four hex digits, at most one '::' for one
    or more zero groups. No dotted IPv4 tail, no zone, no brackets, no surrounding space. Returns
    the address as an int, or None."""
    if not text or len(text) > 39 or not all(c in "0123456789abcdefABCDEF:" for c in text):
        return None
    if ":::" in text or text.count("::") > 1:
        return None
    if "::" in text:
        head, tail = text.split("::")
        high, low = _groups(head), _groups(tail)
        if high is None or low is None or len(high) + len(low) > 7:
            return None
        values = high + [0] * (8 - len(high) - len(low)) + low
    else:
        values = _groups(text)
        if values is None or len(values) != 8:
            return None
    result = 0
    for value in values:
        result = result << 16 | value
    return result


def parse_prefix(text):
    """An address or address/length, length 0-128 in decimal without a leading zero, host bits
    zero. A bare address is a /128. Returns (address, length, had_slash) or None."""
    address_text, slash, length_text = text.partition("/")
    address = parse_address(address_text)
    if address is None:
        return None
    if not slash:
        return address, MAX_PREFIX, False
    if not PREFIX.fullmatch(length_text) or int(length_text) > MAX_PREFIX:
        return None
    length = int(length_text)
    host = (1 << (MAX_PREFIX - length)) - 1
    if address & host:
        return None
    return address, length, True


def format_address(value):
    """RFC 5952 section 4: lower case, no leading zeros in a group, the longest run of two or more
    zero groups (the leftmost of equal runs) written '::'. Never the dotted form of section 5, so
    the result reads back through parse_address."""
    groups = [(value >> (112 - 16 * index)) & 0xFFFF for index in range(8)]
    best_start, best_length, index = -1, 0, 0
    while index < 8:
        if groups[index] != 0:
            index += 1
            continue
        end = index
        while end < 8 and groups[end] == 0:
            end += 1
        if end - index > best_length:
            best_start, best_length = index, end - index
        index = end
    if best_length < 2:
        return ":".join(f"{group:x}" for group in groups)
    head = ":".join(f"{group:x}" for group in groups[:best_start])
    tail = ":".join(f"{group:x}" for group in groups[best_start + best_length:])
    return f"{head}::{tail}"


def canonical(text):
    """What a server stores for a destination CIDR written in IPv6: the address in RFC 5952 form,
    with the /length kept only when it was written. None when the text does not read."""
    parsed = parse_prefix(text)
    if parsed is None:
        return None
    address, length, had_slash = parsed
    return format_address(address) + (f"/{length}" if had_slash else "")


def is_mapped(address):
    """Whether an address lies in ::ffff:0:0/96, where IPv4 destinations are spelled in IPv6 APIs."""
    return address >> 32 == MAPPED_HIGH


def contains(network, length, address):
    shift = MAX_PREFIX - length
    return network >> shift == address >> shift


def cross_check(text):
    """Assert that a spelling this module reads means what ipaddress says it means, and that the
    canonical form is ipaddress's own compression wherever that is not the dotted form."""
    parsed = parse_prefix(text)
    if parsed is None:
        return
    address, length, _ = parsed
    network = ipaddress.IPv6Network((address, length), strict=True)
    assert int(network.network_address) == address, text
    compressed = ipaddress.IPv6Address(address).compressed
    if "." not in compressed:
        assert compressed == format_address(address), (text, compressed, format_address(address))
