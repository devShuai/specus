package com.theshuai.specusclient.client;

import com.theshuai.specusclient.bean.UpstreamTlsConfig;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UpstreamTlsPolicyTests {
    /**
     * The default has to verify. Anything able to answer on the target address would otherwise be
     * accepted, and the tunnel would carry the result to a remote user who cannot tell.
     */
    @Test
    void defaultPolicyVerifies() {
        UpstreamTlsPolicy policy = new UpstreamTlsPolicy(new UpstreamTlsConfig());

        assertTrue(policy.verifies());
        assertFalse(policy.pins());
        assertNotNull(policy.buildContext());
    }

    /** A null configuration must not become a permissive one. */
    @Test
    void missingConfigurationStillVerifies() {
        assertTrue(new UpstreamTlsPolicy(null).verifies());
    }

    /** The opt-out still exists, because some deployments genuinely cannot do better. */
    @Test
    void explicitOptOutIsHonoured() {
        UpstreamTlsConfig config = new UpstreamTlsConfig();
        config.setInsecureSkipVerify(true);
        UpstreamTlsPolicy policy = new UpstreamTlsPolicy(config);

        assertFalse(policy.verifies());
        assertNotNull(policy.buildContext());
    }

    @Test
    void pinningIsRecognisedAndNormalised() {
        String digest = "a".repeat(64);
        UpstreamTlsConfig config = new UpstreamTlsConfig();
        config.setPinnedCertificateSha256(List.of(digest));

        UpstreamTlsPolicy policy = new UpstreamTlsPolicy(config);
        assertTrue(policy.pins());
        assertTrue(policy.verifies());
        assertNotNull(policy.buildContext());
    }

    /** A fingerprint copied out of a tool has colons and uppercase; it is the same pin. */
    @Test
    void fingerprintsAreAcceptedInTheFormToolsPrint() {
        String plain = "0123456789abcdef".repeat(4);
        StringBuilder colonised = new StringBuilder();
        for (int i = 0; i < plain.length(); i += 2) {
            if (i > 0) {
                colonised.append(':');
            }
            colonised.append(plain, i, i + 2);
        }

        Set<String> normalized = UpstreamTlsPolicy.normalizedPins(
                List.of(colonised.toString().toUpperCase(java.util.Locale.ROOT)));
        assertEquals(Set.of(plain), normalized);
    }

    @Test
    void blankEntriesAreIgnored() {
        assertTrue(UpstreamTlsPolicy.normalizedPins(List.of("", "   ")).isEmpty());
        assertTrue(UpstreamTlsPolicy.normalizedPins(null).isEmpty());
    }

    /**
     * Misconfiguration has to fail rather than quietly fall back to trusting everything, which is
     * the failure mode this whole change exists to remove.
     */
    @Test
    void misconfigurationFailsRatherThanFallingBack() {
        UpstreamTlsConfig shortPin = new UpstreamTlsConfig();
        shortPin.setPinnedCertificateSha256(List.of("abcd"));
        assertThrows(IllegalStateException.class,
                () -> new UpstreamTlsPolicy(shortPin).buildContext());

        UpstreamTlsConfig notHex = new UpstreamTlsConfig();
        notHex.setPinnedCertificateSha256(List.of("z".repeat(64)));
        assertThrows(IllegalStateException.class,
                () -> new UpstreamTlsPolicy(notHex).buildContext());

        UpstreamTlsConfig missingCa = new UpstreamTlsConfig();
        missingCa.setCaCertificatePath("no-such-file.pem");
        assertThrows(IllegalStateException.class,
                () -> new UpstreamTlsPolicy(missingCa).buildContext());
    }

    /** If startup never publishes a policy, the handlers must still verify. */
    @Test
    void holderDefaultsToVerifying() {
        assertTrue(UpstreamTlsPolicyHolder.current().verifies());

        UpstreamTlsConfig permissive = new UpstreamTlsConfig();
        permissive.setInsecureSkipVerify(true);
        try {
            UpstreamTlsPolicyHolder.configure(permissive);
            assertFalse(UpstreamTlsPolicyHolder.current().verifies());
        } finally {
            UpstreamTlsPolicyHolder.configure(new UpstreamTlsConfig());
        }
        assertTrue(UpstreamTlsPolicyHolder.current().verifies());
    }
}
