package com.theshuai.specusclient.peer;

import static com.theshuai.specusclient.peer.PeerEgressIpv6Harness.CONSUMER_MESH;
import static com.theshuai.specusclient.peer.PeerEgressIpv6Harness.EPOCH;
import static com.theshuai.specusclient.peer.PeerEgressIpv6Harness.address4;
import static com.theshuai.specusclient.peer.PeerEgressIpv6Harness.address6;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.theshuai.common.peeregress.Ipv4Cidr;
import com.theshuai.common.peeregress.PeerEgressAuthorization;
import com.theshuai.common.peeregress.PeerEgressCodes;
import com.theshuai.common.peeregress.PeerEgressFrame;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The egress side of the IPv6 data plane against {@code protocol/test-vectors/peer-egress-ipv6-v1.json}:
 * the derived device address, the frames an egress that announces {@code ipv6PacketCapable} reads,
 * and the packets its codec writes.
 */
class PeerEgressIpv6PacketTests {

    private static final HexFormat HEX = HexFormat.of();

    @Test
    void meshAddressMatchesSharedVector() throws IOException {
        JsonNode section = PeerEgressIpv6Harness.vector().path("meshAddress");
        assertEquals(PeerEgressAuthorization.MESH_PREFIX6, section.path("prefix").asText(),
                "the vector's prefix is not the one this build derives in and refuses");
        assertFalse(section.path("derive").isEmpty(), "no derive cases");
        assertFalse(section.path("underive").isEmpty(), "no underive cases");
        for (JsonNode testCase : section.path("derive")) {
            String mesh = testCase.path("meshIpv4").asText();
            PeerEgressIpv6Packet.Address derived = PeerEgressIpv6Packet.deviceAddress(mesh);
            assertNotNull(derived, mesh + ": did not derive");
            assertEquals(testCase.path("ipv6").asText(), derived.format(), mesh);
        }
        for (JsonNode testCase : section.path("underive")) {
            String text = testCase.path("ipv6").asText();
            Integer meshIpv4 = PeerEgressIpv6Packet.meshIpv4(address6(text));
            if (testCase.path("meshIpv4").isNull()) {
                assertNull(meshIpv4, text + ": read back an address from outside the prefix");
            } else {
                assertNotNull(meshIpv4, text + ": read back nothing");
                assertEquals(testCase.path("meshIpv4").asText(), Ipv4Cidr.format(meshIpv4), text);
            }
        }
        assertNull(PeerEgressIpv6Packet.deviceAddress(""), "a session without a mesh address derived one");
        assertNull(PeerEgressIpv6Packet.deviceAddress(null), "a session without a mesh address derived one");
    }

    /**
     * An egress with the data plane reads every accepted frame's tuple; without it the same frame is
     * refused as before. One that the vector says is refused by protocol is refused by the runtime
     * with that code, and nothing is dialled for it.
     */
    @Test
    void framesAcceptSharedVector() throws IOException {
        JsonNode accept = PeerEgressIpv6Harness.vector().path("frames").path("accept");
        assertFalse(accept.isEmpty(), "no accepted frames");
        int refusals = 0;
        for (JsonNode testCase : accept) {
            String name = testCase.path("name").asText();
            byte[] raw = HEX.parseHex(testCase.path("frameHex").asText());
            PeerEgressFrame.Decoded frame = PeerEgressFrame.parse(raw, true);
            assertNull(frame.code(), name + ": refused with " + frame.code());
            PeerEgressFrame.Inner inner = frame.inner();
            assertTrue(inner.ipv6(), name + ": not read as IPv6");
            assertEquals(testCase.path("innerSourceIp").asText(), inner.sourceIp(), name + ": source");
            assertEquals(testCase.path("innerDestinationIp").asText(), inner.destinationIp(), name + ": destination");
            assertEquals(testCase.path("innerNextHeader").asInt(), inner.protocol(), name + ": next header");
            assertEquals(testCase.path("innerSourcePort").asInt(), inner.sourcePort(), name + ": source port");
            assertEquals(testCase.path("innerDestinationPort").asInt(), inner.destinationPort(),
                    name + ": destination port");

            // Without the data plane the same frame is refused as it always was.
            assertEquals(PeerEgressCodes.IPV6_UNSUPPORTED, PeerEgressFrame.parse(raw).code(), name);
            assertEquals(PeerEgressCodes.IPV6_UNSUPPORTED, PeerEgressFrame.parse(raw, false).code(), name);

            String egressCode = testCase.path("egressCode").asText("");
            if (egressCode.isEmpty()) {
                continue;
            }
            refusals++;
            PeerEgressIpv6Harness harness = new PeerEgressIpv6Harness("::/0");
            harness.runtime.handleFrame(7, CONSUMER_MESH, raw, EPOCH);
            assertEquals(List.of(egressCode), harness.rejectCodes(), name + ": the runtime's refusal");
            assertEquals(0, harness.dialCount(), name + ": a refused packet was dialled");
        }
        assertTrue(refusals > 0, "the vector carried no frame the runtime refuses");
    }

    /** The consumer-to-egress frames the runtime does not refuse open a flow to the IPv6 destination. */
    @Test
    void vectorFramesOpenFlows() throws IOException {
        int opened = 0;
        for (JsonNode testCase : PeerEgressIpv6Harness.vector().path("frames").path("accept")) {
            if (!"consumer-to-egress".equals(testCase.path("direction").asText())
                    || !testCase.path("egressCode").asText("").isEmpty()) {
                continue;
            }
            opened++;
            String name = testCase.path("name").asText();
            PeerEgressIpv6Harness harness = new PeerEgressIpv6Harness("2001:db8:1::/48");
            harness.runtime.handleFrame(7, CONSUMER_MESH, HEX.parseHex(testCase.path("frameHex").asText()), EPOCH);
            PeerEgressIpv6Harness.waitFor(name + " to open", () -> harness.runtime.flowCount() == 1);
            assertEquals(List.of(testCase.path("innerDestinationIp").asText() + " "
                    + testCase.path("innerDestinationPort").asInt()), harness.dialed(), name + ": dialled");
            assertEquals(List.of(), harness.rejectCodes(), name + ": refused");
            harness.runtime.shutdown(EPOCH);
        }
        assertTrue(opened > 0, "the vector carried no consumer-to-egress frame to open");
    }

    @Test
    void framesRejectSharedVector() throws IOException {
        JsonNode reject = PeerEgressIpv6Harness.vector().path("frames").path("reject");
        assertFalse(reject.isEmpty(), "no rejected frames");
        for (JsonNode testCase : reject) {
            String name = testCase.path("name").asText();
            PeerEgressFrame.Decoded frame = PeerEgressFrame.parse(HEX.parseHex(testCase.path("frameHex").asText()), true);
            assertEquals(testCase.path("code").asText(), frame.code(), name);
        }
    }

    /**
     * The returning SYN-ACK in the vector is exactly what the codec writes for the same segment:
     * header fields, hop limit and the checksum over the RFC 8200 pseudo-header.
     */
    @Test
    void segmentEncodingMatchesSharedVector() throws IOException {
        int checked = 0;
        for (JsonNode testCase : PeerEgressIpv6Harness.vector().path("frames").path("accept")) {
            if (!"egress-to-consumer".equals(testCase.path("direction").asText())) {
                continue;
            }
            checked++;
            String name = testCase.path("name").asText();
            byte[] raw = HEX.parseHex(testCase.path("frameHex").asText());
            PeerEgressFrame.Decoded frame = PeerEgressFrame.parse(raw, true);
            assertNull(frame.code(), name);
            PeerEgressSegment.Segment segment = PeerEgressIpv6Packet.parseSegment(frame.body());
            assertNotNull(segment, name + ": the segment does not parse, or its checksum is wrong");
            assertEquals(HEX.formatHex(frame.body()), HEX.formatHex(PeerEgressSegment.build(segment)), name);
            // And the frame around it.
            assertEquals(HEX.formatHex(raw), HEX.formatHex(PeerEgressIpv6Harness.frameFor(PeerEgressSegment.build(segment))),
                    name + ": frame");
        }
        assertTrue(checked > 0, "the vector carried no egress-to-consumer frame");
    }

    /**
     * The egress resets an unwanted IPv6 segment by the same RFC 793 rule the consumer does, so the
     * vector's consumer-side resets are what buildReset writes too.
     */
    @Test
    void resetMatchesSharedVector() throws IOException {
        JsonNode cases = PeerEgressIpv6Harness.vector().path("failure").path("resetOnPacket").path("cases");
        assertFalse(cases.isEmpty(), "no reset cases");
        for (JsonNode testCase : cases) {
            String name = testCase.path("name").asText();
            PeerEgressSegment.Segment segment = PeerEgressIpv6Packet.parseSegment(
                    HEX.parseHex(testCase.path("packetHex").asText()));
            assertNotNull(segment, name + ": the packet does not parse");
            assertEquals(testCase.path("expect").path("packetHex").asText(),
                    HEX.formatHex(PeerEgressSegment.buildReset(segment)), name);
        }
    }

    @Test
    void datagramRoundTrips() {
        PeerEgressDatagram.Datagram original = new PeerEgressDatagram.Datagram(0, 0, 51000, 53,
                "query".getBytes(StandardCharsets.US_ASCII),
                PeerEgressIpv6Packet.meshAddress(address4(CONSUMER_MESH)), address6("2001:db8:1::35"));
        byte[] packet = PeerEgressDatagram.build(original);
        assertEquals("60000000", HEX.formatHex(packet, 0, 4), "version, traffic class and flow label");
        assertEquals(PeerEgressIpv6Packet.HOP_LIMIT, packet[7] & 0xFF, "hop limit");

        PeerEgressDatagram.Datagram parsed = PeerEgressIpv6Packet.parseDatagram(packet);
        assertNotNull(parsed, "a datagram the codec wrote does not parse");
        assertEquals(original.sourceIp6(), parsed.sourceIp6());
        assertEquals(original.destinationIp6(), parsed.destinationIp6());
        assertEquals(51000, parsed.sourcePort());
        assertEquals(53, parsed.destinationPort());
        assertEquals("query", new String(parsed.payload(), StandardCharsets.US_ASCII));
        // An IPv4 reader takes none of it.
        assertNull(PeerEgressDatagram.parse(packet));

        // IPv6 has no optional UDP checksum.
        byte[] zeroed = packet.clone();
        zeroed[PeerEgressIpv6Packet.HEADER_BYTES + 6] = 0;
        zeroed[PeerEgressIpv6Packet.HEADER_BYTES + 7] = 0;
        assertNull(PeerEgressIpv6Packet.parseDatagram(zeroed), "a datagram without a checksum was accepted");
        byte[] damaged = packet.clone();
        damaged[damaged.length - 1] ^= (byte) 0xFF;
        assertNull(PeerEgressIpv6Packet.parseDatagram(damaged), "a datagram with a wrong checksum was accepted");
        byte[] trailing = java.util.Arrays.copyOf(packet, packet.length + 1);
        assertNull(PeerEgressIpv6Packet.parseDatagram(trailing), "a datagram longer than its header says was accepted");
    }

    /** The TCP reader holds an IPv6 segment to its checksum and its stated length, as the IPv4 one does. */
    @Test
    void segmentsAreValidated() {
        byte[] packet = PeerEgressSegment.build(PeerEgressIpv6Harness.syn6(40000, "2001:db8:1::c8", 443));
        PeerEgressSegment.Segment parsed = PeerEgressIpv6Packet.parseSegment(packet);
        assertNotNull(parsed);
        assertTrue(parsed.ipv6());
        assertEquals(1360, parsed.mss());
        assertNull(PeerEgressSegment.parse(packet), "an IPv4 reader took an IPv6 segment");
        byte[] damaged = packet.clone();
        damaged[damaged.length - 1] ^= 0x01;
        assertNull(PeerEgressIpv6Packet.parseSegment(damaged), "a segment with a wrong checksum was accepted");
        byte[] udp = packet.clone();
        udp[6] = 17;
        assertNull(PeerEgressIpv6Packet.parseSegment(udp), "a segment under another next header was read");
    }
}
