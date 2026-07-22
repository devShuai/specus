package com.theshuai.tunnelclient.peer;

import com.theshuai.common.util.JsonUtil;
import lombok.Data;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

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
        String json = new String(payload, PREFIX.length, payload.length - PREFIX.length, StandardCharsets.UTF_8);
        PeerAppMessage message = JsonUtil.stringToObject(json, PeerAppMessage.class);
        return message != null && StringUtils.hasText(message.getType()) ? message : null;
    }

    static byte[] encode(PeerAppMessage message) {
        String json = JsonUtil.objectToString(message);
        byte[] body = (json == null ? "{}" : json).getBytes(StandardCharsets.UTF_8);
        byte[] payload = new byte[PREFIX.length + body.length];
        System.arraycopy(PREFIX, 0, payload, 0, PREFIX.length);
        System.arraycopy(body, 0, payload, PREFIX.length, body.length);
        return payload;
    }

    @Data
    static final class PeerAppMessage {
        private String type;
        private String id;
        private long fromClientId;
        private String fromClientName;
        private long toClientId;
        private String toClientName;
        private String message;
        private long createdAtMillis;
    }
}
