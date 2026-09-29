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

    /** No trailing dot, lower case. */
    public static String normalize(String name) {
        String text = name == null ? "" : name.trim();
        if (text.endsWith(".")) {
            text = text.substring(0, text.length() - 1);
        }
        return text.toLowerCase(Locale.ROOT);
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
}
