package com.theshuai.tunnelclient.handler;

import com.theshuai.common.codec.PacketEncoder;
import com.theshuai.common.protocol.PacketCodec;
import com.theshuai.common.protocol.request.DirectHttpRequestPacket;
import com.theshuai.common.protocol.response.DirectHttpResponsePacket;
import io.netty.buffer.ByteBuf;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class DirectHttpRequestHandlerTests {

    @Test
    void shouldEncodeResponseWhenForwarderCompletesAsynchronously() throws Exception {
        EmbeddedChannel channel = new EmbeddedChannel(new DirectHttpRequestHandler(null), new PacketEncoder());
        try {
            DirectHttpRequestPacket request = new DirectHttpRequestPacket();
            request.setRequestId("request-id");
            request.setRequestMethod("GET");
            request.setRoute("missing");
            request.setRelativePath("/");
            channel.writeInbound(request);

            ByteBuf encoded = waitForOutbound(channel);
            try {
                DirectHttpResponsePacket response = assertInstanceOf(
                        DirectHttpResponsePacket.class,
                        PacketCodec.INSTANCE.decode(encoded)
                );
                assertEquals("request-id", response.getRequestId());
                assertEquals(502, response.getStatusCode());
            } finally {
                encoded.release();
            }
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    private ByteBuf waitForOutbound(EmbeddedChannel channel) throws InterruptedException {
        for (int attempt = 0; attempt < 100; attempt++) {
            ByteBuf encoded = channel.readOutbound();
            if (encoded != null) {
                return encoded;
            }
            Thread.sleep(10);
        }
        ByteBuf encoded = channel.readOutbound();
        assertNotNull(encoded, "HTTP 直转响应未经过 PacketEncoder");
        return encoded;
    }
}
