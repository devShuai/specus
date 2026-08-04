package com.theshuai.specus.android;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;

/** Cheap, bounded decoder for the unauthenticated UDP probe envelope. */
final class PeerUdpProbeCodec {
    static final int MAX_PACKET_BYTES = 2_048;
    private static final byte[] MAGIC = "specus-peer-mesh".getBytes(StandardCharsets.US_ASCII);

    private PeerUdpProbeCodec() {
    }

    static JSONObject decode(byte[] packet, int offset, int length) {
        if (!looksPlausible(packet, offset, length) || !hasStrictScalarObjectShape(packet, offset, length)) {
            return null;
        }
        try {
            JSONObject probe = new JSONObject(new String(packet, offset, length, StandardCharsets.UTF_8));
            return "specus-peer-mesh".equals(probe.optString("magic", "")) ? probe : null;
        } catch (Exception ignored) {
            return null;
        }
    }

    private static boolean looksPlausible(byte[] packet, int offset, int length) {
        if (packet == null
                || offset < 0
                || length < MAGIC.length + 8
                || length > MAX_PACKET_BYTES
                || offset > packet.length - length
                || packet[offset] != '{'
                || packet[offset + length - 1] != '}') {
            return false;
        }
        int searchEnd = Math.min(offset + length, offset + 160);
        outer:
        for (int index = offset; index <= searchEnd - MAGIC.length; index++) {
            for (int magicIndex = 0; magicIndex < MAGIC.length; magicIndex++) {
                if (packet[index + magicIndex] != MAGIC[magicIndex]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    /** org.json accepts several non-JSON extensions, so validate the tiny probe object first. */
    private static boolean hasStrictScalarObjectShape(byte[] bytes, int offset, int length) {
        int end = offset + length - 1;
        int index = skipWhitespace(bytes, offset + 1, end);
        if (index == end) {
            return true;
        }
        while (index < end) {
            if (bytes[index] != '"') {
                return false;
            }
            index = skipString(bytes, index, end);
            if (index < 0) {
                return false;
            }
            index = skipWhitespace(bytes, index, end);
            if (index >= end || bytes[index++] != ':') {
                return false;
            }
            index = skipWhitespace(bytes, index, end);
            if (index >= end) {
                return false;
            }
            if (bytes[index] == '"') {
                index = skipString(bytes, index, end);
            } else if (bytes[index] == '-' || isDigit(bytes[index])) {
                index = skipNumber(bytes, index, end);
            } else if (matches(bytes, index, end, "true")) {
                index += 4;
            } else if (matches(bytes, index, end, "false")) {
                index += 5;
            } else if (matches(bytes, index, end, "null")) {
                index += 4;
            } else {
                return false;
            }
            if (index < 0) {
                return false;
            }
            index = skipWhitespace(bytes, index, end);
            if (index == end) {
                return true;
            }
            if (bytes[index++] != ',') {
                return false;
            }
            index = skipWhitespace(bytes, index, end);
        }
        return false;
    }

    private static int skipString(byte[] bytes, int quote, int end) {
        for (int index = quote + 1; index < end; index++) {
            int value = Byte.toUnsignedInt(bytes[index]);
            if (value == '"') {
                return index + 1;
            }
            if (value < 0x20) {
                return -1;
            }
            if (value != '\\') {
                continue;
            }
            if (++index >= end) {
                return -1;
            }
            int escaped = Byte.toUnsignedInt(bytes[index]);
            if (escaped == 'u') {
                for (int hex = 0; hex < 4; hex++) {
                    if (++index >= end || !isHex(bytes[index])) {
                        return -1;
                    }
                }
            } else if ("\"\\/bfnrt".indexOf(escaped) < 0) {
                return -1;
            }
        }
        return -1;
    }

    private static int skipNumber(byte[] bytes, int start, int end) {
        int index = start;
        if (bytes[index] == '-' && ++index >= end) {
            return -1;
        }
        if (bytes[index] == '0') {
            index++;
            if (index < end && isDigit(bytes[index])) {
                return -1;
            }
        } else {
            if (!isDigitOneToNine(bytes[index])) {
                return -1;
            }
            while (++index < end && isDigit(bytes[index])) {
                // consume integer digits
            }
        }
        if (index < end && bytes[index] == '.') {
            index++;
            if (index >= end || !isDigit(bytes[index])) {
                return -1;
            }
            while (++index < end && isDigit(bytes[index])) {
                // consume fraction digits
            }
        }
        if (index < end && (bytes[index] == 'e' || bytes[index] == 'E')) {
            index++;
            if (index < end && (bytes[index] == '+' || bytes[index] == '-')) {
                index++;
            }
            if (index >= end || !isDigit(bytes[index])) {
                return -1;
            }
            while (++index < end && isDigit(bytes[index])) {
                // consume exponent digits
            }
        }
        return index;
    }

    private static int skipWhitespace(byte[] bytes, int index, int end) {
        while (index < end) {
            byte value = bytes[index];
            if (value != ' ' && value != '\t' && value != '\r' && value != '\n') {
                break;
            }
            index++;
        }
        return index;
    }

    private static boolean matches(byte[] bytes, int index, int end, String value) {
        if (index > end - value.length()) {
            return false;
        }
        for (int part = 0; part < value.length(); part++) {
            if (bytes[index + part] != value.charAt(part)) {
                return false;
            }
        }
        return true;
    }

    private static boolean isDigit(byte value) {
        return value >= '0' && value <= '9';
    }

    private static boolean isDigitOneToNine(byte value) {
        return value >= '1' && value <= '9';
    }

    private static boolean isHex(byte value) {
        return isDigit(value)
                || (value >= 'a' && value <= 'f')
                || (value >= 'A' && value <= 'F');
    }
}
