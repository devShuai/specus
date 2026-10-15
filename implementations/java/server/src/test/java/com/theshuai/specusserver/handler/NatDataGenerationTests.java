package com.theshuai.specusserver.handler;

import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.common.session.Session;
import com.theshuai.specusserver.attribute.ServerAttributes;
import com.theshuai.specusserver.http.HttpStreamExchange;
import com.theshuai.specusserver.http.WebSocketSpecusHandler;
import com.theshuai.specusserver.http.WebSocketStreamRegistry;
import com.theshuai.specusserver.session.ControlLifecycle;
import com.theshuai.specusserver.session.SessionUtil;
import com.theshuai.specusserver.server.RemotePortServerManager;
import com.theshuai.specusserver.server.TcpServer;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;

/** Deliberately hold physical close: registry detachment, not eventual socket close, is the fence. */
class NatDataGenerationTests {
    private final String name = "nat-generation-" + UUID.randomUUID();
    private final List<EmbeddedChannel> channels = new ArrayList<>();
    private final NatServerHandler handler = new NatServerHandler(null, null, null, null,
            mock(WebSocketStreamRegistry.class), mock(WebSocketSpecusHandler.class));

    @AfterEach void cleanup() {
        channels.forEach(channel -> {
            SessionUtil.unBindSession(channel);
            if (channel.pipeline().get(HoldClose.class) != null) channel.pipeline().remove(HoldClose.class);
            channel.finishAndReleaseAll();
        });
    }

    @Test void cachedIdentityCannotOpenHttpAfterDataUnbind() {
        var data = pair();
        prime();
        SessionUtil.unBindSession(data);
        assertThat(data.isActive()).isFalse();
        assertThat(handler.openHttpStream(new HttpStreamExchange(2), Map.of())).isFalse();
    }

    @Test void cachedIdentityCannotAcceptKeepaliveAfterDataUnbind() throws Exception {
        var data = pair();
        prime();
        SessionUtil.unBindSession(data);
        NatMessagePacket packet = new NatMessagePacket();
        packet.setNatMessageType(NatMessageType.KEEPALIVE);
        handler.channelRead(handler.getCtx(),packet); // A callback already queued before physical close.
        assertThat(data.isActive()).isFalse();
    }

    @Test void controlReplacementRejectsHttpWhileOldDataCloseIsDelayed() {
        var data = pair(new HoldClose());
        prime();
        control();
        assertThat(data.isActive()).isTrue();
        assertThat(handler.openHttpStream(new HttpStreamExchange(2), Map.of())).isFalse();
    }

    @Test void dataReplacementRejectsHttpWhileOldDataCloseIsDelayed() {
        var data = pair(new HoldClose());
        prime();
        var successor = new EmbeddedChannel(); channels.add(successor);
        assertThat(SessionUtil.bindDataSession(new Session(name), successor,
                SessionUtil.getChannel(name), 7L)).isTrue();
        assertThat(data.isActive()).isTrue();
        assertThat(handler.openHttpStream(new HttpStreamExchange(2), Map.of())).isFalse();
        assertThat(SessionUtil.getDataChannel(name)).isSameAs(successor);
    }

    @Test void detachedHttpCannotSendMoreRequestBody() {
        var data = pair(); prime(); SessionUtil.unBindSession(data);
        assertThat(handler.sendHttpData(1, new byte[]{1}).isCompletedExceptionally()).isTrue();
    }

    @Test void detachedHttpCannotFinishRequest() {
        var data = pair(); prime(); SessionUtil.unBindSession(data);
        assertThat(handler.finishHttpRequest(1, List.of()).isCompletedExceptionally()).isTrue();
    }

    @Test void retiredHandlerCannotReopenEvenBeforePhysicalClose() throws Exception {
        var data = pair(); prime();
        handler.channelInactive(handler.getCtx());
        assertThat(data.isActive()).isTrue();
        assertThat(handler.openHttpStream(new HttpStreamExchange(2), Map.of())).isFalse();
    }

    @Test void httpFlowDoesNotWaitForControlLifecycle() throws Exception {
        pair();
        try (var executor = Executors.newSingleThreadExecutor(); var lease = ControlLifecycle.acquire(701L, null)) {
            assertThat(executor.submit(() -> handler.openHttpStream(new HttpStreamExchange(1), Map.of()))
                    .get(2, TimeUnit.SECONDS)).isTrue();
        }
    }

    @Test void successorAlsoWaitsForAnUnregisteredListenerWhoseCloseIsStillPending() throws Exception {
        var ports=mock(RemotePortServerManager.class);var listener=mock(TcpServer.class);
        var stopped=new CompletableFuture<Void>();when(listener.closeAsync()).thenReturn(stopped);
        when(ports.bind(eq(19091),any())).thenReturn(listener);
        var parent=control();
        var nat=new NatServerHandler(null,null,ports,null,mock(WebSocketStreamRegistry.class),mock(WebSocketSpecusHandler.class));
        var data=new EmbeddedChannel(nat);channels.add(data);
        assertThat(SessionUtil.bindDataSession(new Session(name),data,parent,7L)).isTrue();
        var register=new NatMessagePacket();register.setNatMessageType(NatMessageType.REGISTER);
        register.setMetaData(Map.of("port",19091,"specusPort",8080,"specusAddress","127.0.0.1","clientName",name));data.writeInbound(register);
        NatMessagePacket result=data.readOutbound();assertThat(result.getMetaData().get("success")).isEqualTo(true);
        var unregister=new NatMessagePacket();unregister.setNatMessageType(NatMessageType.UNREGISTER);unregister.setMetaData(Map.of("port",19091));data.writeInbound(unregister);
        var candidate=new EmbeddedChannel();channels.add(candidate);
        try(var prepared=SessionUtil.prepareBinding(new Session(name),candidate,parent,7L,true)) {
            assertThat(prepared).isNotNull();
            assertThat(prepared.retired().isDone()).isFalse();assertThat(prepared.publish()).isFalse();
            stopped.complete(null);prepared.retired().get(1,TimeUnit.SECONDS);
            assertThat(prepared.publish()).isTrue();
        } finally {stopped.complete(null);}
    }

    private void prime() {
        assertThat(handler.openHttpStream(new HttpStreamExchange(1), Map.of())).isTrue();
    }

    private EmbeddedChannel control() {
        var channel = new EmbeddedChannel(); channels.add(channel);
        channel.attr(ServerAttributes.CLIENT_SESSION_ID).set(7L);
        SessionUtil.bindControlSession(new Session(name), channel);
        return channel;
    }

    private EmbeddedChannel pair(ChannelOutboundHandlerAdapter... interceptors) {
        var parent = control();
        var data = new EmbeddedChannel(); channels.add(data);
        for (var interceptor : interceptors) data.pipeline().addLast(interceptor);
        data.pipeline().addLast(handler);
        // The handler is added to an already-active EmbeddedChannel: deliver its activation explicitly.
        data.pipeline().fireChannelActive();
        assertThat(SessionUtil.bindDataSession(new Session(name), data, parent, 7L)).isTrue();
        return data;
    }

    private static final class HoldClose extends ChannelOutboundHandlerAdapter {
        @Override public void close(ChannelHandlerContext ctx, ChannelPromise promise) {
            // Physical socket remains active until cleanup removes this test-only interceptor.
        }
    }
}
