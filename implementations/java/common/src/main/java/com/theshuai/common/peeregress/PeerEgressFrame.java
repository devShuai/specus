package com.theshuai.common.peeregress;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * The {@code SPEG1} frame.
 *
 * <p>SPEG1 is the third plaintext type carried inside an SPM2 frame, alongside a bare IPv4 packet
 * and an STMSG2 application message. Egress traffic gets its own type on purpose: relaxing the
 * existing bare-IPv4 checks to carry it would weaken the mesh path, so the two are separated the
 * moment the payload is decrypted.
 *
 * <p>Wire format and rejection cases: {@code protocol/spec/peer-egress.md}, driven by
 * {@code protocol/test-vectors/peer-egress-frame-v1.json}.
 */
public final class PeerEgressFrame {

    public static final int HEADER_BYTES = 8;
    public static final int TYPE_IP_PACKET = 1;
    public static final int TYPE_CONTROL = 2;

    /**
     * bit0 is set by an egress device when it forwards while acting as a consumer itself. An egress
     * that receives it refuses: there are no multi-hop egress chains.
     */
    public static final int FLAG_HOP = 0x01;

    /** Control message types this version understands. */
    public static final String CONTROL_FLOW_REJECT = "flow-reject";

    /**
     * Reserved for phase two domain routing. Receiving it must be refused now rather than treated
     * as implemented, or a phase-one egress would look like it honours domain rules it does not.
     */
    public static final String CONTROL_FLOW_PURGE = "flow-purge";

    private static final byte[] MAGIC = "SPEG1".getBytes(StandardCharsets.US_ASCII);
    private static final int IPV4_MIN_HEADER_BYTES = 20;
    private static final int PROTOCOL_TCP = 6;
    private static final int PROTOCOL_UDP = 17;
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private PeerEgressFrame() {
    }

    /** The parsed IPv4 tuple of a type=1 body, filled only for that type. */
    public record Inner(
            String sourceIp,
            String destinationIp,
            int protocol,
            int sourcePort,
            int destinationPort) {

        static Inner empty() {
            return new Inner("", "", 0, 0, 0);
        }
    }

    /** One decoded frame, or the code it was refused with. */
    public record Decoded(int type, boolean hop, byte[] body, Inner inner, String code) {

        public boolean accepted() {
            return code == null;
        }

        static Decoded refused(String code) {
            return new Decoded(0, false, new byte[0], Inner.empty(), code);
        }
    }

    /**
     * Reports whether a decrypted payload carries the SPEG1 magic.
     *
     * <p>Only the magic is checked, so a frame that is addressed to the egress path but malformed is
     * still routed here and rejected with its own code, rather than falling through to the
     * bare-IPv4 checks and being dropped for the wrong reason.
     */
    public static boolean looksLikeFrame(byte[] payload) {
        if (payload == null || payload.length < MAGIC.length) {
            return false;
        }
        return Arrays.equals(payload, 0, MAGIC.length, MAGIC, 0, MAGIC.length);
    }

    /**
     * Decodes one frame, returning the failing result code on rejection.
     *
     * <p>The checks run in a fixed order so every implementation reports the same code for a frame
     * that violates more than one constraint.
     */
    public static Decoded parse(byte[] payload) {
        if (payload == null || payload.length < HEADER_BYTES) {
            return Decoded.refused(PeerEgressCodes.FRAME_TRUNCATED);
        }
        if (!Arrays.equals(payload, 0, MAGIC.length, MAGIC, 0, MAGIC.length)) {
            return Decoded.refused(PeerEgressCodes.FRAME_BAD_MAGIC);
        }
        int type = payload[5] & 0xFF;
        if (type != TYPE_IP_PACKET && type != TYPE_CONTROL) {
            return Decoded.refused(PeerEgressCodes.FRAME_UNKNOWN_TYPE);
        }
        int flags = payload[6] & 0xFF;
        // Reserved bits and the reserved byte are refused rather than ignored: tolerating them now
        // would make them unusable for a later version, since old builds would accept anything.
        if ((flags & ~FLAG_HOP) != 0 || payload[7] != 0) {
            return Decoded.refused(PeerEgressCodes.FRAME_RESERVED_SET);
        }
        boolean hop = (flags & FLAG_HOP) != 0;
        if (hop) {
            return Decoded.refused(PeerEgressCodes.HOP_NOT_ALLOWED);
        }
        byte[] body = Arrays.copyOfRange(payload, HEADER_BYTES, payload.length);

        if (type == TYPE_CONTROL) {
            String code = validateControlBody(body);
            if (code != null) {
                return Decoded.refused(code);
            }
            return new Decoded(type, false, body, Inner.empty(), null);
        }

        Decoded innerResult = parseInnerPacket(body);
        if (!innerResult.accepted()) {
            return innerResult;
        }
        return new Decoded(type, false, body, innerResult.inner(), null);
    }

    private static Decoded parseInnerPacket(byte[] body) {
        if (body.length < IPV4_MIN_HEADER_BYTES) {
            return Decoded.refused(PeerEgressCodes.FRAME_TRUNCATED);
        }
        if (((body[0] >>> 4) & 0x0F) != 4) {
            return Decoded.refused(PeerEgressCodes.IPV6_UNSUPPORTED);
        }
        int ihl = (body[0] & 0x0F) * 4;
        if (ihl < IPV4_MIN_HEADER_BYTES || body.length < ihl) {
            return Decoded.refused(PeerEgressCodes.FRAME_TRUNCATED);
        }
        int total = ((body[2] & 0xFF) << 8) | (body[3] & 0xFF);
        if (total < ihl || total > body.length) {
            return Decoded.refused(PeerEgressCodes.FRAME_TRUNCATED);
        }
        // A body longer than the IPv4 total length means trailing bytes rode along; refuse rather
        // than silently keeping the prefix.
        if (total != body.length) {
            return Decoded.refused(PeerEgressCodes.FRAME_TRAILING_BYTES);
        }

        int protocol = body[9] & 0xFF;
        int sourcePort = 0;
        int destinationPort = 0;
        if ((protocol == PROTOCOL_TCP || protocol == PROTOCOL_UDP) && body.length >= ihl + 4) {
            sourcePort = ((body[ihl] & 0xFF) << 8) | (body[ihl + 1] & 0xFF);
            destinationPort = ((body[ihl + 2] & 0xFF) << 8) | (body[ihl + 3] & 0xFF);
        }
        Inner inner = new Inner(
                dotted(body, 12), dotted(body, 16), protocol, sourcePort, destinationPort);
        return new Decoded(TYPE_IP_PACKET, false, body, inner, null);
    }

    private static String dotted(byte[] packet, int offset) {
        return (packet[offset] & 0xFF) + "."
                + (packet[offset + 1] & 0xFF) + "."
                + (packet[offset + 2] & 0xFF) + "."
                + (packet[offset + 3] & 0xFF);
    }

    private static String validateControlBody(byte[] body) {
        JsonNode node;
        try {
            node = MAPPER.readTree(body);
        } catch (Exception malformed) {
            return PeerEgressCodes.FRAME_MALFORMED_CONTROL;
        }
        if (node == null || !node.isObject()) {
            return PeerEgressCodes.FRAME_MALFORMED_CONTROL;
        }
        String type = node.path("type").asText("");
        if (CONTROL_FLOW_REJECT.equals(type) || CONTROL_FLOW_PURGE.equals(type)) {
            return null;
        }
        // Includes name-bind, which phase two defines. Refusing keeps a phase-one egress from
        // looking like it honours domain rules it does not implement.
        return PeerEgressCodes.CONTROL_UNSUPPORTED;
    }

    /**
     * One control message body.
     *
     * <p>Fields not carried by a given message type stay empty or zero and are left out of the
     * encoding, which is what makes the canonical bytes short enough to compare by eye.
     */
    public record Control(
            String type,
            String protocol,
            String sourceIp,
            int sourcePort,
            String destinationIp,
            int destinationPort,
            List<String> destinations,
            String code) {

        /** A flow-reject: the reason one flow was refused, for the consumer to display. */
        public static Control flowReject(String protocol, String sourceIp, int sourcePort,
                String destinationIp, int destinationPort, String code) {
            return new Control(CONTROL_FLOW_REJECT, protocol, sourceIp, sourcePort,
                    destinationIp, destinationPort, List.of(), code);
        }

        /** A flow-purge: the destinations whose established flows the egress should close. */
        public static Control flowPurge(List<String> destinations, String code) {
            return new Control(CONTROL_FLOW_PURGE, "", "", 0, "", 0,
                    destinations == null ? List.of() : List.copyOf(destinations), code);
        }
    }

    /**
     * Serialises a control message in the key order the spec fixes, so two implementations produce
     * byte-identical frames for the same message.
     *
     * <p>Assembled rather than handed to a serialiser's field ordering, because that ordering is a
     * property of the library rather than of the protocol, and the shared vector pins these exact
     * bytes. Values still go through the encoder: a code or a destination arrives from the wire.
     */
    public static byte[] encodeControl(Control control) {
        StringBuilder text = new StringBuilder(96).append('{');
        appendString(text, "type", control.type(), true);
        appendString(text, "protocol", control.protocol(), false);
        appendString(text, "sourceIp", control.sourceIp(), false);
        appendNumber(text, "sourcePort", control.sourcePort());
        appendString(text, "destinationIp", control.destinationIp(), false);
        appendNumber(text, "destinationPort", control.destinationPort());
        if (control.destinations() != null && !control.destinations().isEmpty()) {
            text.append(",\"destinations\":[");
            for (int index = 0; index < control.destinations().size(); index++) {
                if (index > 0) {
                    text.append(',');
                }
                text.append(quote(control.destinations().get(index)));
            }
            text.append(']');
        }
        appendString(text, "code", control.code(), false);
        return text.append('}').toString().getBytes(StandardCharsets.UTF_8);
    }

    private static void appendString(StringBuilder text, String name, String value, boolean first) {
        if (value == null || value.isEmpty()) {
            return;
        }
        if (!first) {
            text.append(',');
        }
        text.append('"').append(name).append("\":").append(quote(value));
    }

    private static void appendNumber(StringBuilder text, String name, int value) {
        if (value == 0) {
            return;
        }
        text.append(",\"").append(name).append("\":").append(value);
    }

    private static String quote(String value) {
        try {
            return MAPPER.writeValueAsString(value);
        } catch (JsonProcessingException impossible) {
            // Jackson cannot fail on a String; rethrowing keeps the signature honest anyway.
            throw new IllegalStateException(impossible);
        }
    }

    /** Reads a control body, returning null when it cannot be parsed. */
    public static Control decodeControl(byte[] body) {
        if (body == null || body.length == 0) {
            return null;
        }
        try {
            JsonNode node = MAPPER.readTree(body);
            if (!node.isObject()) {
                return null;
            }
            List<String> destinations = new ArrayList<>();
            for (JsonNode entry : node.path("destinations")) {
                destinations.add(entry.asText());
            }
            return new Control(
                    node.path("type").asText(""),
                    node.path("protocol").asText(""),
                    node.path("sourceIp").asText(""),
                    node.path("sourcePort").asInt(0),
                    node.path("destinationIp").asText(""),
                    node.path("destinationPort").asInt(0),
                    List.copyOf(destinations),
                    node.path("code").asText(""));
        } catch (IOException unreadable) {
            return null;
        }
    }

    /** Builds a frame. hop is set only when this node forwards as a consumer of another egress. */
    public static byte[] encode(int type, boolean hop, byte[] body) {
        byte[] payload = body == null ? new byte[0] : body;
        byte[] frame = new byte[HEADER_BYTES + payload.length];
        System.arraycopy(MAGIC, 0, frame, 0, MAGIC.length);
        frame[5] = (byte) type;
        frame[6] = (byte) (hop ? FLAG_HOP : 0);
        System.arraycopy(payload, 0, frame, HEADER_BYTES, payload.length);
        return frame;
    }
}
