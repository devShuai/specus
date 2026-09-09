package com.theshuai.common.peeregress;

/**
 * IPv4 prefix used by both consumer rule matching and egress authorization.
 *
 * <p>Parsing is deliberately strict: a prefix whose host bits are set is rejected rather than
 * masked. Implementations normalise differently, and a rule that silently changes meaning between
 * runtimes is worse than one the user has to rewrite.
 */
public record Ipv4Cidr(int network, int prefixLength) {
    public static final int MAX_PREFIX = 32;

    /** Returns null when the text is not a canonical IPv4 address or prefix. */
    public static Ipv4Cidr parse(String text) {
        if (text == null) {
            return null;
        }
        String trimmed = text.trim();
        if (trimmed.isEmpty()) {
            return null;
        }
        int slash = trimmed.indexOf('/');
        String addressPart = slash < 0 ? trimmed : trimmed.substring(0, slash);
        Integer address = parseAddress(addressPart);
        if (address == null) {
            return null;
        }
        if (slash < 0) {
            return new Ipv4Cidr(address, MAX_PREFIX);
        }
        String prefixPart = trimmed.substring(slash + 1);
        if (prefixPart.isEmpty() || prefixPart.length() > 2) {
            return null;
        }
        int prefix = 0;
        for (int i = 0; i < prefixPart.length(); i++) {
            char c = prefixPart.charAt(i);
            if (c < '0' || c > '9') {
                return null;
            }
            prefix = prefix * 10 + (c - '0');
        }
        if (prefixPart.length() > 1 && prefixPart.charAt(0) == '0') {
            return null;
        }
        if (prefix > MAX_PREFIX) {
            return null;
        }
        if ((address & ~maskFor(prefix)) != 0) {
            // Host bits set. Rejected rather than masked; see the class comment.
            return null;
        }
        return new Ipv4Cidr(address, prefix);
    }

    /**
     * Returns null when the text is not four canonical dotted-decimal octets.
     *
     * <p>A leading zero is rejected rather than tolerated. Runtimes disagree about {@code 010}:
     * some read decimal ten, some read octal eight, and an address that changes meaning between
     * implementations is exactly the kind of ambiguity an access rule must not carry.
     */
    public static Integer parseAddress(String text) {
        if (text == null) {
            return null;
        }
        int value = 0;
        int octets = 0;
        int start = 0;
        int length = text.length();
        for (int i = 0; i <= length; i++) {
            if (i != length && text.charAt(i) != '.') {
                continue;
            }
            int digits = i - start;
            if (digits < 1 || digits > 3 || octets > 3) {
                return null;
            }
            if (digits > 1 && text.charAt(start) == '0') {
                return null;
            }
            int part = 0;
            for (int j = start; j < i; j++) {
                char c = text.charAt(j);
                if (c < '0' || c > '9') {
                    return null;
                }
                part = part * 10 + (c - '0');
            }
            if (part > 255) {
                return null;
            }
            value = (value << 8) | part;
            octets++;
            start = i + 1;
        }
        return octets == 4 ? value : null;
    }

    public static String format(int address) {
        return ((address >>> 24) & 0xFF) + "." + ((address >>> 16) & 0xFF) + "."
                + ((address >>> 8) & 0xFF) + "." + (address & 0xFF);
    }

    private static int maskFor(int prefixLength) {
        return prefixLength == 0 ? 0 : (int) (0xFFFFFFFFL << (MAX_PREFIX - prefixLength));
    }

    public boolean contains(int address) {
        int mask = maskFor(prefixLength);
        return (address & mask) == (network & mask);
    }

    public boolean overlaps(Ipv4Cidr other) {
        if (other == null) {
            return false;
        }
        int shared = Math.min(prefixLength, other.prefixLength);
        int mask = maskFor(shared);
        return (network & mask) == (other.network & mask);
    }

    @Override
    public String toString() {
        return format(network) + "/" + prefixLength;
    }
}
