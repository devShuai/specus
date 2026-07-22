package com.theshuai.tunnel.android;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Locale;

final class PeerAppMessageCodec {
    static final String TYPE_MESSAGE = "message";
    static final String TYPE_ACK = "ack";

    private static final byte[] PREFIX = "STMSG2\n".getBytes(StandardCharsets.US_ASCII);

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
            message.attachment = json.optJSONObject("attachment");
            message.createdAtMillis = json.optLong("createdAtMillis", 0L);
            return message;
        } catch (Exception ignored) {
            return null;
        }
    }

    static byte[] encode(PeerAppMessage message) throws Exception {
        boolean attachmentV2 = message != null
                && TYPE_MESSAGE.equalsIgnoreCase(text(message.type))
                && message.attachment != null;
        StringBuilder json = new StringBuilder(256);
        json.append("{\"type\":").append(JSONObject.quote(text(message == null ? null : message.type)))
                .append(",\"id\":").append(JSONObject.quote(text(message == null ? null : message.id)))
                .append(",\"fromClientId\":").append(message == null ? 0L : message.fromClientId)
                .append(",\"fromClientName\":").append(JSONObject.quote(
                        text(message == null ? null : message.fromClientName)))
                .append(",\"toClientId\":").append(message == null ? 0L : message.toClientId)
                .append(",\"toClientName\":").append(JSONObject.quote(
                        text(message == null ? null : message.toClientName)))
                .append(",\"message\":").append(JSONObject.quote(
                        text(message == null ? null : message.message)));
        if (attachmentV2) {
            json.append(",\"attachment\":").append(message.attachment);
        }
        json.append(",\"createdAtMillis\":")
                .append(message == null ? 0L : message.createdAtMillis)
                .append('}');
        byte[] body = json.toString().getBytes(StandardCharsets.UTF_8);
        byte[] payload = new byte[PREFIX.length + body.length];
        System.arraycopy(PREFIX, 0, payload, 0, PREFIX.length);
        System.arraycopy(body, 0, payload, PREFIX.length, body.length);
        return payload;
    }

    static String displayText(PeerAppMessage message) {
        if (message == null) {
            return "";
        }
        if (message.attachment == null) {
            return text(message.message);
        }
        String fileName = firstNonBlank(
                message.attachment.optString("fileName", ""),
                message.attachment.optString("objectId", ""),
                "attachment");
        String mimeType = firstNonBlank(
                message.attachment.optString("mimeType", ""),
                "application/octet-stream");
        long size = message.attachment.optLong("sizeBytes", 0L);
        String prefix = text(message.message).trim();
        return (prefix.isEmpty() ? "" : prefix + " ")
                + "[附件] " + fileName + " · " + mimeType + " · "
                + (size > 0L ? formatBytes(size) : "-");
    }

    private static String text(String value) {
        return value == null ? "" : value;
    }

    private static String firstNonBlank(String... values) {
        if (values != null) {
            for (String value : values) {
                if (value != null && !value.trim().isEmpty()) {
                    return value.trim();
                }
            }
        }
        return "";
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
