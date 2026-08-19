package com.theshuai.specus.android;

import org.junit.After;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

/**
 * The phone routinely sits on networks nobody controls, so accepting any certificate on the
 * forwarding leg is worse here than on a server. These pin the policy that replaced it.
 */
public class UpstreamTlsPolicyTest {
    @After
    public void resetPolicy() {
        UpstreamTlsPolicy.configure(null);
    }

    @Test
    public void defaultPolicyVerifies() {
        UpstreamTlsPolicy policy = new UpstreamTlsPolicy(false, null, Collections.emptyList());

        assertTrue(policy.verifies());
        assertFalse(policy.pins());
        assertNotNull(policy.buildContext());
    }

    /** If configuration never arrives, the transports must still check certificates. */
    @Test
    public void holderDefaultsToVerifying() {
        assertTrue(UpstreamTlsPolicy.current().verifies());

        UpstreamTlsPolicy.configure(new UpstreamTlsPolicy(true, null, Collections.emptyList()));
        assertFalse(UpstreamTlsPolicy.current().verifies());

        UpstreamTlsPolicy.configure(null);
        assertTrue("clearing the policy must return to verifying, not to trusting everything",
                UpstreamTlsPolicy.current().verifies());
    }

    /** The opt-out still exists, because some deployments genuinely cannot do better. */
    @Test
    public void explicitOptOutIsHonoured() {
        UpstreamTlsPolicy policy = new UpstreamTlsPolicy(true, null, Collections.emptyList());

        assertFalse(policy.verifies());
        assertNotNull(policy.buildContext());
    }

    @Test
    public void pinningIsRecognised() {
        UpstreamTlsPolicy policy = new UpstreamTlsPolicy(
                false, null, Collections.singletonList(repeat("a", 64)));

        assertTrue(policy.pins());
        assertTrue(policy.verifies());
        assertNotNull(policy.buildContext());
    }

    /** A fingerprint copied out of a tool has colons and uppercase; it is the same pin. */
    @Test
    public void fingerprintsAreAcceptedInTheFormToolsPrint() {
        String plain = repeat("0123456789abcdef", 4);
        StringBuilder colonised = new StringBuilder();
        for (int i = 0; i < plain.length(); i += 2) {
            if (i > 0) {
                colonised.append(':');
            }
            colonised.append(plain, i, i + 2);
        }

        Set<String> normalized = UpstreamTlsPolicy.normalizedPins(
                Collections.singletonList(colonised.toString().toUpperCase(Locale.ROOT)));
        assertEquals(Collections.singleton(plain), normalized);
    }

    @Test
    public void blankEntriesAreIgnored() {
        assertTrue(UpstreamTlsPolicy.normalizedPins(Arrays.asList("", "   ")).isEmpty());
        assertTrue(UpstreamTlsPolicy.normalizedPins(null).isEmpty());
    }

    /**
     * Misconfiguration has to fail rather than quietly fall back to trusting everything, which is
     * the failure mode this change exists to remove.
     */
    @Test
    public void misconfigurationFailsRatherThanFallingBack() {
        List<String> tooShort = Collections.singletonList("abcd");
        assertThrows(IllegalStateException.class,
                () -> new UpstreamTlsPolicy(false, null, tooShort));

        List<String> notHex = Collections.singletonList(repeat("z", 64));
        assertThrows(IllegalStateException.class,
                () -> new UpstreamTlsPolicy(false, null, notHex));

        UpstreamTlsPolicy missingCa =
                new UpstreamTlsPolicy(false, "no-such-file.pem", Collections.emptyList());
        assertThrows(IllegalStateException.class, missingCa::buildContext);
    }

    private static String repeat(String value, int times) {
        StringBuilder builder = new StringBuilder(value.length() * times);
        for (int i = 0; i < times; i++) {
            builder.append(value);
        }
        return builder.toString();
    }
}
