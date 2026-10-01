package com.theshuai.common.peeregress;

import java.util.Locale;

/**
 * Names in phase two of peer egress: how a query name, a rule match and a bound name are compared,
 * and which names are well formed. See protocol/spec/peer-egress-dns.md; the same rules as the Go
 * and .NET clients, checked against protocol/test-vectors/peer-egress-dns-v1.json.
 */
public final class PeerEgressNames {
    private PeerEgressNames() {
    }

    /** No trailing dots, lower case. */
    public static String normalize(String name) {
        return stripTrailingDots(name == null ? "" : name.trim()).toLowerCase(Locale.ROOT);
    }

    /**
     * Whether a name is one to resolve: ASCII labels of 1-63 bytes from a-z, 0-9 and '-', not starting
     * or ending with '-', at least two labels, at most 253 bytes, and not all digits (which would be an
     * address). IDN must arrive as punycode.
     */
    public static boolean valid(String name) {
        String text = normalize(name);
        if (text.isEmpty() || text.length() > 253) {
            return false;
        }
        String[] labels = text.split("\\.", -1);
        if (labels.length < 2) {
            return false;
        }
        boolean numeric = true;
        for (String label : labels) {
            if (label.isEmpty() || label.length() > 63 || label.charAt(0) == '-'
                    || label.charAt(label.length() - 1) == '-') {
                return false;
            }
            for (int i = 0; i < label.length(); i++) {
                char c = label.charAt(i);
                if ((c >= 'a' && c <= 'z') || c == '-') {
                    numeric = false;
                } else if (c < '0' || c > '9') {
                    return false;
                }
            }
        }
        return !numeric;
    }

    /**
     * Whether a rule's match names a domain rather than failing to be an address: it starts with
     * {@code *}, or carries a letter or a non-ASCII character. A match that is neither an address
     * nor this -- {@code 1.2.3.4-5} -- is a malformed address, not a name made of digits.
     */
    public static boolean namesDomain(String match) {
        String text = match == null ? "" : match.trim();
        if (text.startsWith("*")) {
            return true;
        }
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (Character.isLetter(c) || c > 127) {
                return true;
            }
        }
        return false;
    }

    /**
     * Whether a domain rule's match is well formed: {@code name} or {@code *.name}, trailing dots
     * and case ignored, with the name's labels as {@link #valid} requires them. A Unicode name is
     * refused rather than converted: IDN is written as punycode. {@code *} is only ever the whole
     * leftmost label.
     */
    public static boolean validMatch(String match) {
        if (!namesDomain(match)) {
            return false;
        }
        // Checked before lower-casing, which can turn a non-ASCII letter into an ASCII one (the
        // Kelvin sign becomes k) and let a Unicode name through as punycode-clean.
        for (int i = 0; i < match.length(); i++) {
            if (match.charAt(i) > 127) {
                return false;
            }
        }
        String text = normalize(match);
        if (text.startsWith("*.")) {
            text = text.substring(2);
        }
        if (text.isEmpty() || text.indexOf('*') >= 0) {
            return false;
        }
        return valid(text);
    }

    /**
     * How a domain rule's match ranks for a normalised query name, smaller winning, or -1 when it
     * does not cover the name at all. An exact match is 0 and beats every suffix; among suffixes the
     * one with more labels ranks first, so {@code *.cdn.example.com} beats {@code *.example.com}. A
     * suffix never covers its own apex.
     */
    public static int coverage(String match, String normalizedName) {
        String base = normalize(match);
        if (base.startsWith("*.")) {
            base = base.substring(2);
            if (!normalizedName.endsWith("." + base)) {
                return -1;
            }
            // Ranked below every exact match; among suffixes, more labels rank higher.
            return Integer.MAX_VALUE - base.split("\\.", -1).length;
        }
        return normalizedName.equals(base) ? 0 : -1;
    }

    private static String stripTrailingDots(String text) {
        int end = text.length();
        while (end > 0 && text.charAt(end - 1) == '.') {
            end--;
        }
        return text.substring(0, end);
    }
}
