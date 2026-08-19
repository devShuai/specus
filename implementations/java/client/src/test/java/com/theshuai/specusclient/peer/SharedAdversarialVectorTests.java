package com.theshuai.specusclient.peer;

import com.fasterxml.jackson.databind.JsonNode;
import com.theshuai.common.util.JsonUtil;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertTrue;

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
class SharedAdversarialVectorTests {
    @Test
    void everySharedCaseIsHandled() throws IOException {
        JsonNode document = readVector("adversarial-inputs.json");
        JsonNode cases = document.get("cases");

        assertTrue(cases != null && cases.size() > 0,
                "the shared corpus is empty; the file was not read");

        for (JsonNode testCase : cases) {
            String name = testCase.get("name").asText();
            byte[] payload = HexFormat.of().parseHex(testCase.get("payloadHex").asText());

            long startedAt = System.nanoTime();
            decodeAllReachable(payload);
            long elapsedMillis = (System.nanoTime() - startedAt) / 1_000_000L;

            assertTrue(elapsedMillis < 1_000L, name + " took " + elapsedMillis
                    + "ms to decide; a hostile input must not stall a receive loop");
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
    }

    private static JsonNode readVector(String name) throws IOException {
        Path current = Path.of("").toAbsolutePath();
        for (int depth = 0; current != null && depth < 8; depth++, current = current.getParent()) {
            Path candidate = current.resolve("protocol/test-vectors").resolve(name);
            if (Files.isRegularFile(candidate)) {
                return JsonUtil.readString(Files.readString(candidate));
            }
        }
        throw new IllegalStateException("cannot locate protocol vector: " + name);
    }
}
