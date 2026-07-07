package com.theshuai.tunnel.android;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

final class PeerAppMessageCodec {
    static final String TYPE_MESSAGE = "message";
    static final String TYPE_ACK = "ack";

    private static final byte[] PREFIX = "STMSG1\n".getBytes(StandardCharsets.US_ASCII);

    private PeerAppMessageCodec() {
    }

    static boolean looksLike(byte[] payload) {
        return payload != null
                && payload.length >= PREFIX.length
                && Arrays.equals(PREFIX, Arrays.copyOfRange(payload, 0, PREFIX.length));
    }

    static PeerAppMessage decode(byte[] payload) {
        if (!looksLike(payload)) {
            return null;
        }
        try {
            String jsonText = new String(payload, PREFIX.length, payload.length - PREFIX.length, StandardCharsets.UTF_8);
            JSONObject json = new JSONObject(jsonText);
            String type = json.optString("type", "");
            if (type.trim().isEmpty()) {
                return null;
            }
            PeerAppMessage message = new PeerAppMessage();
            message.type = type;
            message.id = json.optString("id", "");
            message.fromClientId = json.optLong("fromClientId", 0L);
            message.fromClientName = json.optString("fromClientName", "");
            message.toClientId = json.optLong("toClientId", 0L);
            message.toClientName = json.optString("toClientName", "");
            message.message = json.optString("message", "");
            message.createdAtMillis = json.optLong("createdAtMillis", 0L);
            return message;
        } catch (Exception ignored) {
            return null;
        }
    }

    static byte[] encode(PeerAppMessage message) throws Exception {
        JSONObject json = new JSONObject();
        json.put("type", text(message == null ? null : message.type));
        json.put("id", text(message == null ? null : message.id));
        json.put("fromClientId", message == null ? 0L : message.fromClientId);
        json.put("fromClientName", text(message == null ? null : message.fromClientName));
        json.put("toClientId", message == null ? 0L : message.toClientId);
        json.put("toClientName", text(message == null ? null : message.toClientName));
        json.put("message", text(message == null ? null : message.message));
        json.put("createdAtMillis", message == null ? 0L : message.createdAtMillis);
        byte[] body = json.toString().getBytes(StandardCharsets.UTF_8);
        byte[] payload = new byte[PREFIX.length + body.length];
        System.arraycopy(PREFIX, 0, payload, 0, PREFIX.length);
        System.arraycopy(body, 0, payload, PREFIX.length, body.length);
        return payload;
    }

    private static String text(String value) {
        return value == null ? "" : value;
    }

    static final class PeerAppMessage {
        String type;
        String id;
        long fromClientId;
        String fromClientName;
        long toClientId;
        String toClientName;
        String message;
        long createdAtMillis;
    }
}
