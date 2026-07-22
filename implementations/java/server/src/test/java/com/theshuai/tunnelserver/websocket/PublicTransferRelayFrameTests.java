package com.theshuai.tunnelserver.websocket;

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PublicTransferRelayFrameTests {
    @Test
    void decodesClientFrameAndAddsAuthenticatedSource() {
        byte[] app = appFrame(2, new byte[]{1, 2, 3});
        byte[] client = relayFrame("peer-b", "", app);

        PublicTransferRelayFrame.ClientFrame decoded =
                PublicTransferRelayFrame.decodeClient(ByteBuffer.wrap(client));

        assertEquals("peer-b", decoded.targetPeerId());
        assertEquals(2, decoded.appType());
        assertArrayEquals(app, decoded.appFrame());
        assertArrayEquals(relayFrame("peer-b", "peer-a", app),
                PublicTransferRelayFrame.encodeServer("peer-b", "peer-a", app));
    }

    @Test
    void rejectsSpoofedSourceAndTrailingAppBytes() {
        byte[] app = appFrame(1, new byte[]{4});
        assertThrows(IllegalArgumentException.class,
                () -> PublicTransferRelayFrame.decodeClient(
                        ByteBuffer.wrap(relayFrame("peer-b", "spoofed", app))));

        byte[] malformed = java.util.Arrays.copyOf(app, app.length + 1);
        assertThrows(IllegalArgumentException.class,
                () -> PublicTransferRelayFrame.decodeClient(
                        ByteBuffer.wrap(relayFrame("peer-b", "", malformed))));
    }

    private static byte[] relayFrame(String targetPeerId, String sourcePeerId, byte[] app) {
        byte[] target = targetPeerId.getBytes(StandardCharsets.UTF_8);
        byte[] source = sourcePeerId.getBytes(StandardCharsets.UTF_8);
        ByteBuffer frame = ByteBuffer.allocate(14 + target.length + source.length + app.length);
        frame.putInt(0x53545752).put((byte) 2).put((byte) 0);
        frame.putShort((short) target.length).putShort((short) source.length).putInt(app.length);
        frame.put(target).put(source).put(app);
        return frame.array();
    }

    private static byte[] appFrame(int type, byte[] payload) {
        ByteBuffer frame = ByteBuffer.allocate(72 + payload.length);
        frame.putInt(0x53544150).put((byte) 2).put((byte) type).putShort((short) 0);
        frame.put(new byte[16]);
        frame.putInt(0).putInt(1).putInt(payload.length).putInt(payload.length);
        frame.put(new byte[32]).put(payload);
        return frame.array();
    }
}
