package com.theshuai.common.peeregress;

import java.util.ArrayList;
import java.util.List;

/**
 * IPv6 prefix with its host bits clear, read with the spelling {@code protocol/spec/peer-egress.md}
 * pins (IPv6 写法) for a consumer rule's match and an egress policy's destination rule alike.
 *
 * <p>Written out rather than taken from {@link java.net.InetAddress}, which also reads a dotted IPv4
 * tail, a zone, brackets and more, turns an IPv4-mapped address into an {@code Inet4Address}, and
 * writes addresses uncompressed. The other implementations parse the same way; the
 * {@code ipv6Prefixes} section of {@code protocol/test-vectors/peer-egress-rules-v1.json} pins every
 * refusal a runtime parser lets through.
 *
 * @param high the first 64 bits of the network
 * @param low the last 64 bits of the network
 */
public record Ipv6Cidr(long high, long low, int prefixLength) {
    public static final int MAX_PREFIX = 128;

    /** Returns null when the text is not an IPv6 address or address/length in the pinned spelling. */
    public static Ipv6Cidr parse(String text) {
        Parsed parsed = parseWithLength(text);
        return parsed == null ? null : parsed.cidr();
    }

    /** The prefix and whether a length was written, which is all a server needs to store it back. */
    public record Parsed(Ipv6Cidr cidr, boolean hadLength) {
    }

    /**
     * Reads an IPv6 address or address/length: the length 0-128 in decimal without a leading zero,
     * the host bits clear. A bare address is a /128. Returns null otherwise.
     */
    public static Parsed parseWithLength(String text) {
        if (text == null) {
            return null;
        }
        int slash = text.indexOf('/');
        long[] address = parseAddress(slash < 0 ? text : text.substring(0, slash));
        if (address == null) {
            return null;
        }
        if (slash < 0) {
            return new Parsed(new Ipv6Cidr(address[0], address[1], MAX_PREFIX), false);
        }
        String lengthPart = text.substring(slash + 1);
        if (lengthPart.isEmpty() || lengthPart.length() > 3
                || (lengthPart.length() > 1 && lengthPart.charAt(0) == '0')) {
            return null;
        }
        int length = 0;
        for (int index = 0; index < lengthPart.length(); index++) {
            char c = lengthPart.charAt(index);
            if (c < '0' || c > '9') {
                return null;
            }
            length = length * 10 + (c - '0');
        }
        if (length > MAX_PREFIX) {
            return null;
        }
        Ipv6Cidr cidr = new Ipv6Cidr(address[0], address[1], length);
        if ((address[0] & ~highMask(length)) != 0 || (address[1] & ~lowMask(length)) != 0) {
            // Host bits set. Refused rather than masked, as for IPv4.
            return null;
        }
        return new Parsed(cidr, true);
    }

    /**
     * Reads RFC 4291 2.2 forms 1 and 2: eight groups of one to four hex digits, at most one
     * {@code ::} standing for one or more zero groups. No dotted IPv4 tail, no zone, no brackets, no
     * surrounding space. Returns the address as {high, low}, or null.
     */
    public static long[] parseAddress(String text) {
        if (text == null || text.isEmpty() || text.length() > 39) {
            return null;
        }
        for (int index = 0; index < text.length(); index++) {
            char c = text.charAt(index);
            if (!isHexDigit(c) && c != ':') {
                return null;
            }
        }
        if (text.contains(":::")) {
            return null;
        }
        int compressed = text.indexOf("::");
        if (compressed >= 0 && text.indexOf("::", compressed + 1) >= 0) {
            return null;
        }
        List<Integer> groups;
        if (compressed >= 0) {
            List<Integer> head = hexGroups(text.substring(0, compressed));
            List<Integer> tail = hexGroups(text.substring(compressed + 2));
            if (head == null || tail == null || head.size() + tail.size() > 7) {
                return null;
            }
            groups = new ArrayList<>(head);
            for (int index = head.size() + tail.size(); index < 8; index++) {
                groups.add(0);
            }
            groups.addAll(tail);
        } else {
            groups = hexGroups(text);
            if (groups == null || groups.size() != 8) {
                return null;
            }
        }
        long high = 0;
        long low = 0;
        for (int index = 0; index < 4; index++) {
            high = (high << 16) | groups.get(index);
            low = (low << 16) | groups.get(index + 4);
        }
        return new long[] {high, low};
    }

    /** Whether an address, as {high, low}, lies in the prefix. */
    public boolean contains(long[] address) {
        return (address[0] & highMask(prefixLength)) == high && (address[1] & lowMask(prefixLength)) == low;
    }

    /**
     * Whether the prefix lies in {@code ::ffff:0:0/96}, where IPv4 destinations are spelled in IPv6
     * APIs. No packet carries one, so a consumer rule there would never match anything.
     */
    public boolean mapped() {
        return high == 0 && (low >>> 32) == 0xFFFFL;
    }

    /**
     * Writes RFC 5952 section 4: lower case, no leading zeros in a group, the longest run of two or
     * more zero groups (the leftmost of equal runs) as {@code ::}. Never the dotted form of section
     * 5, so what it writes reads back through {@link #parseAddress}.
     */
    public static String formatAddress(long high, long low) {
        int[] groups = new int[8];
        for (int index = 0; index < 4; index++) {
            groups[index] = (int) ((high >>> (48 - 16 * index)) & 0xFFFF);
            groups[index + 4] = (int) ((low >>> (48 - 16 * index)) & 0xFFFF);
        }
        int bestStart = -1;
        int bestLength = 0;
        for (int index = 0; index < 8;) {
            if (groups[index] != 0) {
                index++;
                continue;
            }
            int end = index;
            while (end < 8 && groups[end] == 0) {
                end++;
            }
            if (end - index > bestLength) {
                bestStart = index;
                bestLength = end - index;
            }
            index = end;
        }
        if (bestLength < 2) {
            return hex(groups, 0, 8);
        }
        return hex(groups, 0, bestStart) + "::" + hex(groups, bestStart + bestLength, 8);
    }

    /**
     * What a server stores for an egress policy's destination CIDR, already trimmed: an IPv4 one as
     * written, since it has one spelling, and an IPv6 one in RFC 5952 form with the /length kept only
     * when it was written. Null when the egress could not read it
     * ({@code protocol/test-vectors/peer-egress-management-v1.json}).
     */
    public static String storedDestinationCidr(String text) {
        if (text == null) {
            return null;
        }
        if (text.indexOf(':') < 0) {
            return Ipv4Cidr.parse(text) == null ? null : text;
        }
        Parsed parsed = parseWithLength(text);
        if (parsed == null) {
            return null;
        }
        String address = formatAddress(parsed.cidr().high(), parsed.cidr().low());
        return parsed.hadLength() ? address + "/" + parsed.cidr().prefixLength() : address;
    }

    @Override
    public String toString() {
        return formatAddress(high, low) + "/" + prefixLength;
    }

    private static long highMask(int length) {
        if (length <= 0) {
            return 0;
        }
        return length >= 64 ? -1L : -1L << (64 - length);
    }

    private static long lowMask(int length) {
        if (length <= 64) {
            return 0;
        }
        return length >= 128 ? -1L : -1L << (128 - length);
    }

    private static boolean isHexDigit(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    private static List<Integer> hexGroups(String part) {
        List<Integer> groups = new ArrayList<>();
        if (part.isEmpty()) {
            return groups;
        }
        // split with a negative limit keeps trailing empty strings, so "1:" is two groups, one empty.
        for (String group : part.split(":", -1)) {
            if (group.isEmpty() || group.length() > 4) {
                return null;
            }
            groups.add(Integer.parseInt(group, 16));
        }
        return groups;
    }

    private static String hex(int[] groups, int from, int to) {
        StringBuilder text = new StringBuilder();
        for (int index = from; index < to; index++) {
            if (index > from) {
                text.append(':');
            }
            text.append(Integer.toHexString(groups[index]));
        }
        return text.toString();
    }
}
