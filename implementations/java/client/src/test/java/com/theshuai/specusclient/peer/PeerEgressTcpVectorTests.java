package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.specusclient.peer.PeerEgressSegment.Segment;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import org.junit.jupiter.api.Test;

/**
 * Replays {@code peer-egress-tcp-v1.json} against the Java user-space TCP stack.
 *
 * <p>The fixture is the same one Go asserts against and .NET will, so this is what "three runtimes
 * agree" means in practice. Its expectations were recorded from the Go stack, so passing here
 * proves agreement rather than independent correctness; the argument for the behaviour itself lives
 * beside the Go implementation, case by case against the RFCs.
 */
class PeerEgressTcpVectorTests {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final HexFormat HEX = HexFormat.of();

    private static JsonNode readVector(String name) throws IOException {
        Path directory = Path.of("").toAbsolutePath();
        for (int depth = 0; depth < 8 && directory != null; depth++) {
            Path candidate = directory.resolve("protocol").resolve("test-vectors").resolve(name);
            if (Files.exists(candidate)) {
                return MAPPER.readTree(Files.readString(candidate));
            }
            directory = directory.getParent();
        }
        throw new IOException("cannot locate " + name);
    }

    private static int parseAddress(String dotted) {
        String[] parts = dotted.split("\\.");
        int value = 0;
        for (String part : parts) {
            value = (value << 8) | Integer.parseInt(part);
        }
        return value;
    }

    private static int flagsOf(JsonNode names) {
        int flags = 0;
        if (names == null) {
            return 0;
        }
        for (JsonNode name : names) {
            flags |= switch (name.asText().toUpperCase(Locale.ROOT)) {
                case "FIN" -> PeerEgressSegment.FLAG_FIN;
                case "SYN" -> PeerEgressSegment.FLAG_SYN;
                case "RST" -> PeerEgressSegment.FLAG_RST;
                case "PSH" -> PeerEgressSegment.FLAG_PSH;
                case "ACK" -> PeerEgressSegment.FLAG_ACK;
                default -> 0;
            };
        }
        return flags;
    }

    private static List<String> flagNames(int flags) {
        List<String> names = new ArrayList<>(3);
        if ((flags & PeerEgressSegment.FLAG_FIN) != 0) {
            names.add("FIN");
        }
        if ((flags & PeerEgressSegment.FLAG_SYN) != 0) {
            names.add("SYN");
        }
        if ((flags & PeerEgressSegment.FLAG_RST) != 0) {
            names.add("RST");
        }
        if ((flags & PeerEgressSegment.FLAG_PSH) != 0) {
            names.add("PSH");
        }
        if ((flags & PeerEgressSegment.FLAG_ACK) != 0) {
            names.add("ACK");
        }
        return names;
    }

    private static byte[] decodeHex(JsonNode node) {
        if (node == null || node.isNull() || node.asText().isEmpty()) {
            return new byte[0];
        }
        return HEX.parseHex(node.asText());
    }

    private static List<String> expectedFlagNames(JsonNode node) {
        List<String> names = new ArrayList<>();
        for (JsonNode entry : node) {
            names.add(entry.asText());
        }
        return names;
    }

    @Test
    void tcpStackMatchesSharedVector() throws IOException {
        JsonNode vector = readVector("peer-egress-tcp-v1.json");
        JsonNode params = vector.get("params");
        assertNotNull(params, "vector carried no params");

        int localIp = parseAddress(params.get("egressIp").asText());
        int remoteIp = parseAddress(params.get("consumerIp").asText());
        int consumerPort = params.get("consumerPort").asInt();
        int targetPort = params.get("targetPort").asInt();
        int pathMtu = params.get("pathMtu").asInt();
        long idleTimeoutMs = params.get("idleTimeoutMs").asLong();
        int iss = (int) params.get("iss").asLong();
        long epochMs = params.get("epochMs").asLong();

        JsonNode cases = vector.get("cases");
        assertTrue(cases != null && cases.size() > 0, "vector carried no cases");

        for (JsonNode testCase : cases) {
            String name = testCase.get("name").asText();
            PeerEgressTcpConnection connection = null;
            long nowMs = epochMs;
            int stepIndex = 0;

            for (JsonNode step : testCase.get("steps")) {
                nowMs += step.path("advanceMs").asLong(0);
                String action = step.get("do").asText();
                PeerEgressTcpConnection.Output output = new PeerEgressTcpConnection.Output();

                switch (action) {
                    case "segment" -> {
                        Segment segment = new Segment(
                                remoteIp, localIp, consumerPort, targetPort,
                                (int) step.path("seq").asLong(0),
                                (int) step.path("ack").asLong(0),
                                flagsOf(step.get("flags")),
                                step.path("window").asInt(0),
                                step.path("mss").asInt(0),
                                decodeHex(step.get("payloadHex")));
                        if (connection == null) {
                            connection = PeerEgressTcpConnection.accept(
                                    segment, iss, pathMtu, idleTimeoutMs, nowMs, output);
                        } else {
                            output = connection.onSegment(segment, nowMs);
                        }
                    }
                    case "appData" ->
                            output = connection.onAppData(decodeHex(step.get("dataHex")), nowMs);
                    case "appClose" -> output = connection.onAppClose(nowMs);
                    case "abort" -> output = connection.abort();
                    case "tick" -> output = connection.onTick(nowMs);
                    default -> throw new IllegalStateException("unknown step " + action);
                }

                assertStep(name, stepIndex, step.get("expect"), connection, output);
                stepIndex++;
            }
        }
    }

    private static void assertStep(
            String name,
            int index,
            JsonNode expect,
            PeerEgressTcpConnection connection,
            PeerEgressTcpConnection.Output output) {
        String where = name + " step " + index;

        assertEquals(expect.get("state").asText(), connection.state().name(), where + " state");
        assertEquals(
                expect.path("deliverHex").asText(""),
                output.deliver.length == 0 ? "" : HEX.formatHex(output.deliver),
                where + " delivered bytes");
        assertEquals(expect.path("closeApp").asBoolean(false), output.closeApp, where + " closeApp");
        assertEquals(expect.path("done").asBoolean(false), output.done, where + " done");
        assertEquals(expect.path("reset").asBoolean(false), output.reset, where + " reset");

        JsonNode expectedSegments = expect.get("segments");
        assertEquals(expectedSegments.size(), output.segments.size(), where + " segment count");
        for (int position = 0; position < output.segments.size(); position++) {
            Segment produced = PeerEgressSegment.parse(output.segments.get(position));
            assertNotNull(produced, where + " emitted a segment it cannot parse back");
            JsonNode wanted = expectedSegments.get(position);
            String at = where + " segment " + position;

            assertEquals(expectedFlagNames(wanted.get("flags")), flagNames(produced.flags()), at + " flags");
            assertEquals((int) wanted.get("seq").asLong(), produced.seq(), at + " seq");
            assertEquals((int) wanted.get("ack").asLong(), produced.ack(), at + " ack");
            assertEquals(wanted.get("window").asInt(), produced.window(), at + " window");
            assertEquals(wanted.path("mss").asInt(0), produced.mss(), at + " mss");
            assertEquals(
                    wanted.path("payloadHex").asText(""),
                    produced.payload().length == 0 ? "" : HEX.formatHex(produced.payload()),
                    at + " payload");
        }
    }
}
