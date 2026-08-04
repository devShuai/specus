package com.theshuai.specusclient.handler;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.websocketx.PingWebSocketFrame;
import io.netty.handler.codec.http.websocketx.WebSocketClientHandshaker;
import io.netty.handler.codec.http.websocketx.WebSocketClientProtocolHandler;
import io.netty.handler.codec.http.websocketx.WebSocketFrame;

import java.util.List;

/**
 * Keeps RFC 6455 control frames visible to {@link WsLocalSpecusHandler}.
 *
 * <p>Netty's default client protocol handler locally answers PING, drops PONG and consumes CLOSE.
 * SWS2 instead needs the public browser and local upstream to remain the two control-frame
 * endpoints, so this handler disables CLOSE/PONG consumption and bypasses the default PING reply.</p>
 */
final class FramePreservingWebSocketClientProtocolHandler extends WebSocketClientProtocolHandler {

    FramePreservingWebSocketClientProtocolHandler(WebSocketClientHandshaker handshaker) {
        super(handshaker, false, false);
    }

    @Override
    protected void decode(ChannelHandlerContext context, WebSocketFrame frame,
                          List<Object> output) throws Exception {
        if (frame instanceof PingWebSocketFrame) {
            output.add(frame.retain());
            return;
        }
        super.decode(context, frame, output);
    }
}
