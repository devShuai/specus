package com.theshuai.specus.android;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

/**
 * The shared adversarial corpus in {@code protocol/test-vectors/adversarial-inputs.json}.
 *
 * <p>One implementation rejecting a hostile input does not mean the input is handled: an attacker
 * picks whichever node runs the most permissive implementation. Java, Go, .NET and Android all run
 * this same file, so a gap in one of them shows up as a failure rather than as a difference nobody
 * thought to look for.
 *
 * <p>The requirement per case is either a clean rejection or a value the caller can safely use —
 * never an unhandled exception, and never so slow that a hostile packet could stall a receive loop.
 */
public class SharedAdversarialVectorTest {
    @Test
    public void everySharedCaseIsHandled() throws Exception {
        JSONObject document = ProtocolVectorTestSupport.read("adversarial-inputs.json");
        JSONArray cases = document.getJSONArray("cases");
        assertTrue("the shared corpus is empty; the file was not read", cases.length() > 0);

        for (int index = 0; index < cases.length(); index++) {
            JSONObject testCase = cases.getJSONObject(index);
            String name = testCase.getString("name");
            byte[] payload = ProtocolVectorTestSupport.hex(testCase.getString("payloadHex"));

            long startedAt = System.nanoTime();
            decodeAllReachable(payload);
            long elapsedMillis = (System.nanoTime() - startedAt) / 1_000_000L;

            assertTrue(name + " took " + elapsedMillis + "ms to decide; a hostile input must not "
                    + "stall a receive loop", elapsedMillis < 1_000L);
        }
    }

    /**
     * Feeds one payload to every decoder a datagram can reach before anything has authenticated
     * it. An unhandled exception here fails the test, which is the outcome being ruled out.
     */
    private static void decodeAllReachable(byte[] payload) {
        PeerAppMessageCodec.looksLike(payload);
        PeerAppMessageCodec.decode(payload);
        PeerPathMtu.looksLike(payload);
        PeerPathMtu.decode(payload);
        PeerUdpProbeCodec.decode(payload, 0, payload.length);
    }
}
