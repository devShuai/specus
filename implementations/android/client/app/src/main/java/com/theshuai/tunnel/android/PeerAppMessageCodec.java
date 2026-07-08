package com.theshuai.tunnel.android;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Locale;

final class PeerAppMessageCodec {
    static final String TYPE_MESSAGE = "message";
    static final String TYPE_ACK = "ack";

    private static final byte[] PREFIX_V1 = "STMSG1\n".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] PREFIX_V2 = "STMSG2\n".getBytes(StandardCharsets.US_ASCII);

    private PeerAppMessageCodec() {
    }

    static boolean looksLike(byte[] payload) {
        return payload != null
                && payload.length >= PREFIX_V1.length
                && (Arrays.equals(PREFIX_V1, Arrays.copyOfRange(payload, 0, PREFIX_V1.length))
                || Arrays.equals(PREFIX_V2, Arrays.copyOfRange(payload, 0, PREFIX_V2.length)));
    }

    static PeerAppMessage decode(byte[] payload) {
        if (!looksLike(payload)) {
            return null;
        }
        try {
            int prefixLength = prefixLength(payload);
            String jsonText = new String(payload, prefixLength, payload.length - prefixLength, StandardCharsets.UTF_8);
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
            message.attachment = json.optJSONObject("attachment");
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
        if (message != null && message.attachment != null) {
            json.put("attachment", message.attachment);
        }
        json.put("createdAtMillis", message == null ? 0L : message.createdAtMillis);
        byte[] body = json.toString().getBytes(StandardCharsets.UTF_8);
        byte[] payload = new byte[PREFIX_V2.length + body.length];
        System.arraycopy(PREFIX_V2, 0, payload, 0, PREFIX_V2.length);
        System.arraycopy(body, 0, payload, PREFIX_V2.length, body.length);
        return payload;
    }

    static String displayText(PeerAppMessage message) {
        if (message == null) {
            return "";
        }
        if (message.attachment == null) {
            return text(message.message);
        }
        String fileName = message.attachment.optString("fileName",
                text(message.attachment.optString("objectId", "attachment")));
        String mimeType = message.attachment.optString("mimeType", "application/octet-stream");
        long size = message.attachment.optLong("sizeBytes", 0L);
        String prefix = text(message.message).trim();
        return (prefix.isEmpty() ? "" : prefix + " ")
                + "[附件] " + fileName + " · " + mimeType + " · " + formatBytes(size);
    }

    private static int prefixLength(byte[] payload) {
        return Arrays.equals(PREFIX_V2, Arrays.copyOfRange(payload, 0, PREFIX_V2.length))
                ? PREFIX_V2.length
                : PREFIX_V1.length;
    }

    private static String text(String value) {
        return value == null ? "" : value;
    }

    private static String formatBytes(long bytes) {
        String[] units = {"B", "KB", "MB", "GB"};
        double value = Math.max(0L, bytes);
        int unit = 0;
        while (value >= 1024.0 && unit < units.length - 1) {
            value /= 1024.0;
            unit++;
        }
        return String.format(Locale.ROOT, value >= 10 || unit == 0 ? "%.0f %s" : "%.1f %s", value, units[unit]);
    }

    static final class PeerAppMessage {
        String type;
        String id;
        long fromClientId;
        String fromClientName;
        long toClientId;
        String toClientName;
        String message;
        JSONObject attachment;
        long createdAtMillis;
    }
}
