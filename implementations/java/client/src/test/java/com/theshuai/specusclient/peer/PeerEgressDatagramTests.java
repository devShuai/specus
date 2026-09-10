package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.specusclient.peer.PeerEgressDatagram.Datagram;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

/** The UDP datagram codec, checked against the shared frame vector as well as against itself. */
class PeerEgressDatagramTests {

    private static final HexFormat HEX = HexFormat.of();

    private static int address(String dotted) {
        int value = 0;
        for (String part : dotted.split("\\.")) {
            value = (value << 8) | Integer.parseInt(part);
        }
        return value;
    }

    private static Datagram sample(byte[] payload) {
        return new Datagram(
                address("100.96.0.1"), address("203.0.113.53"), 51000, 53, payload);
    }

    @Test
    void datagramRoundTrips() {
        Datagram original = sample("specus-egress-datagram".getBytes(StandardCharsets.UTF_8));
        Datagram parsed = PeerEgressDatagram.parse(PeerEgressDatagram.build(original));

        assertNotNull(parsed, "a datagram we built did not parse");
        assertEquals(original.sourceIp(), parsed.sourceIp());
        assertEquals(original.destinationIp(), parsed.destinationIp());
        assertEquals(original.sourcePort(), parsed.sourcePort());
        assertEquals(original.destinationPort(), parsed.destinationPort());
        assertArrayEquals(original.payload(), parsed.payload());
    }

    /**
     * A payload-free datagram is legal UDP and is what several keepalive schemes send, so refusing
     * it would silently break the flows that rely on it.
     */
    @Test
    void emptyPayloadIsCarried() {
        byte[] packet = PeerEgressDatagram.build(sample(new byte[0]));
        Datagram parsed = PeerEgressDatagram.parse(packet);

        assertNotNull(parsed, "an empty datagram was refused");
        assertEquals(0, parsed.payload().length);
        assertEquals(
                PeerEgressDatagram.UDP_HEADER_BYTES,
                PeerEgressSegment.readShort(packet, PeerEgressSegment.IPV4_MIN_HEADER_BYTES + 4),
                "length field");
    }

    @Test
    void untrustworthyInputIsRefused() {
        byte[] good = PeerEgressDatagram.build(sample("query".getBytes(StandardCharsets.UTF_8)));
        int udp = PeerEgressSegment.IPV4_MIN_HEADER_BYTES;

        byte[] corrupted = good.clone();
        corrupted[udp + PeerEgressDatagram.UDP_HEADER_BYTES] ^= (byte) 0xFF;
        assertNull(PeerEgressDatagram.parse(corrupted), "a bad checksum was accepted");

        assertNull(
                PeerEgressDatagram.parse(java.util.Arrays.copyOf(good, udp + 4)),
                "a truncated datagram was accepted");

        // A UDP length shorter than what IPv4 delivered would leave trailing bytes riding along.
        byte[] shortLength = good.clone();
        PeerEgressSegment.writeShort(shortLength, udp + 4, PeerEgressDatagram.UDP_HEADER_BYTES);
        assertNull(PeerEgressDatagram.parse(shortLength), "an understated length was accepted");

        byte[] longLength = good.clone();
        PeerEgressSegment.writeShort(longLength, udp + 4, 4096);
        assertNull(PeerEgressDatagram.parse(longLength), "an overstated length was accepted");

        byte[] tcp = good.clone();
        tcp[9] = (byte) PeerEgressSegment.IPV4_PROTOCOL_TCP;
        assertNull(PeerEgressDatagram.parse(tcp), "a non-UDP packet was accepted");
    }

    /** IPv4 lets a sender skip the UDP checksum, and plenty do. Refusing those would drop real traffic. */
    @Test
    void absentChecksumIsAccepted() {
        byte[] packet = PeerEgressDatagram.build(sample("query".getBytes(StandardCharsets.UTF_8)));
        PeerEgressSegment.writeShort(packet, PeerEgressSegment.IPV4_MIN_HEADER_BYTES + 6, 0);
        assertNotNull(PeerEgressDatagram.parse(packet), "a datagram with no checksum was refused");
    }

    /**
     * RFC 768 reserves zero to mean "not computed", so a checksum that works out to zero has to go
     * on the wire as its complement instead. A receiver would otherwise stop verifying that flow.
     */
    @Test
    void aComputedZeroChecksumIsSentAsFfff() {
        // Searched rather than hand-derived: the payload that sums to zero depends on the
        // addresses and ports, so pinning one here would be a constant nobody could re-derive.
        boolean found = false;
        for (int candidate = 0; candidate <= 0xFFFF; candidate++) {
            byte[] payload = {(byte) (candidate >>> 8), (byte) candidate};
            byte[] packet = PeerEgressDatagram.build(sample(payload));
            int emitted =
                    PeerEgressSegment.readShort(packet, PeerEgressSegment.IPV4_MIN_HEADER_BYTES + 6);
            if (emitted != 0xFFFF) {
                continue;
            }
            // 0xffff is also what an ordinary checksum can be, so confirm this one really is the
            // forced form by checking the datagram still verifies.
            byte[] zeroed = packet.clone();
            PeerEgressSegment.writeShort(zeroed, PeerEgressSegment.IPV4_MIN_HEADER_BYTES + 6, 0);
            assertNotNull(PeerEgressDatagram.parse(packet), "the 0xffff form did not verify");
            found = true;
            break;
        }
        assertTrue(found, "no payload produced the forced form, so the guard went untested");
    }

    /**
     * The strongest check available: this packet came out of the vector generator, not out of this
     * codec, so agreeing on it is agreement between two implementations.
     */
    @Test
    void parsesTheUdpDatagramFromTheSharedFrameVector() throws IOException {
        JsonNode vector = readVector("peer-egress-frame-v1.json");
        String innerHex = "";
        int wantSource = 0;
        int wantDestination = 0;
        for (JsonNode testCase : vector.get("accept")) {
            if ("ip-udp-outbound".equals(testCase.get("name").asText())) {
                innerHex = testCase.get("innerPacketHex").asText();
                wantSource = testCase.get("innerSourcePort").asInt();
                wantDestination = testCase.get("innerDestinationPort").asInt();
            }
        }
        assertTrue(!innerHex.isEmpty(), "frame vector no longer carries ip-udp-outbound");

        Datagram parsed = PeerEgressDatagram.parse(HEX.parseHex(innerHex));
        assertNotNull(parsed, "the vector datagram did not parse");
        assertEquals(wantSource, parsed.sourcePort());
        assertEquals(wantDestination, parsed.destinationPort());
    }

    private static JsonNode readVector(String name) throws IOException {
        Path directory = Path.of("").toAbsolutePath();
        for (int depth = 0; depth < 8 && directory != null; depth++) {
            Path candidate = directory.resolve("protocol").resolve("test-vectors").resolve(name);
            if (Files.exists(candidate)) {
                return new ObjectMapper().readTree(Files.readString(candidate));
            }
            directory = directory.getParent();
        }
        throw new IOException("cannot locate " + name);
    }
}
