package com.theshuai.specusserver.handler;

import com.theshuai.common.codec.PacketCodecHandler;
import com.theshuai.common.codec.Spliter;
import com.theshuai.common.protocol.ConnectionRole;
import com.theshuai.common.protocol.PacketCodec;
import com.theshuai.common.protocol.request.LoginRequestPacket;
import com.theshuai.common.protocol.response.LoginResponsePacket;
import com.theshuai.specusclient.bean.SpecusBean;
import com.theshuai.specusclient.client.NettyClient;
import com.theshuai.specusclient.handler.LoginResponseHandler;
import com.theshuai.specusserver.config.NettyServerProperties;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.service.*;
import com.theshuai.specusserver.productmetrics.ProductMetricsService;
import com.theshuai.specusserver.session.SessionUtil;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** Real TCP and production login/codec; only native authentication and post-login DB effects are
 * mocked. A DATA event loop is held AFTER authentication was queued, not by timing sleeps. */
class ManagedLoginDataGenerationTests {
    @Test
    void pendingDataCannotFollowAReplacementControlUsingTheSameAuthSession() throws Exception {
        try (var fixture = new Fixture()) {
            fixture.login(ConnectionRole.CONTROL, 7);
            var pending = fixture.pendingData(7);
            fixture.login(ConnectionRole.CONTROL, 7);
            var successor = SessionUtil.getChannel(fixture.name);
            fixture.release.countDown();

            fixture.rejectedAndRetryable(pending);
            assertNull(SessionUtil.getDataChannel(fixture.name));
            assertSame(successor, SessionUtil.getChannel(fixture.name));
            assertTrue(successor.isActive());
            fixture.login(ConnectionRole.DATA, 7);
            assertNotNull(SessionUtil.getDataChannel(fixture.name), "a fresh DATA login must still work");
        }
    }

    @Test
    void pendingDataCannotFollowAReplacementControlUsingAnotherAuthSession() throws Exception {
        try (var fixture = new Fixture()) {
            fixture.login(ConnectionRole.CONTROL, 7);
            var pending = fixture.pendingData(7);
            fixture.login(ConnectionRole.CONTROL, 8);
            fixture.release.countDown();
            fixture.rejectedAndRetryable(pending);
            assertNull(SessionUtil.getDataChannel(fixture.name));
            fixture.login(ConnectionRole.DATA, 8);
            assertTrue(SessionUtil.getDataChannel(fixture.name).isActive());
        }
    }

    @Test
    void pendingDataCannotPublishAfterItsControlHasDisconnected() throws Exception {
        try (var fixture = new Fixture()) {
            fixture.login(ConnectionRole.CONTROL, 7);
            var control = SessionUtil.getChannel(fixture.name);
            var pending = fixture.pendingData(7);
            control.close().sync();
            control.eventLoop().submit(() -> {}).get(5, TimeUnit.SECONDS);
            assertNull(SessionUtil.getChannel(fixture.name));
            fixture.release.countDown();
            fixture.rejectedAndRetryable(pending);
            assertNull(SessionUtil.getDataChannel(fixture.name));
        }
    }

    @Test
    void pendingDataStillSucceedsWhenItsOriginalControlIsUnchanged() throws Exception {
        try (var fixture = new Fixture()) {
            fixture.login(ConnectionRole.CONTROL, 7);
            var control = SessionUtil.getChannel(fixture.name);
            var pending = fixture.pendingData(7);
            fixture.release.countDown();
            assertTrue(fixture.response(pending).isSuccess());
            assertSame(control, SessionUtil.getChannel(fixture.name));
            assertTrue(SessionUtil.getDataChannel(fixture.name).isActive());
        }
    }

    @Test
    void missingControlIsRejectedWithoutPermanentlyStoppingTheClient() throws Exception {
        try (var fixture = new Fixture()) {
            var pending = fixture.pendingData(7);
            fixture.release.countDown();
            fixture.rejectedAndRetryable(pending);
            assertNull(SessionUtil.getChannel(fixture.name));
            assertNull(SessionUtil.getDataChannel(fixture.name));
        }
    }

    private static final class Fixture implements AutoCloseable {
        final String name = "data-generation-" + UUID.randomUUID();
        final CountDownLatch reached = new CountDownLatch(1), release = new CountDownLatch(1);
        final ExecutorService loginExecutor = Executors.newSingleThreadExecutor();
        final EventLoopGroup boss = new MultiThreadIoEventLoopGroup(1, NioIoHandler.newFactory());
        // Three independent loops: the deliberately paused DATA must not hold either CONTROL.
        final EventLoopGroup worker = new MultiThreadIoEventLoopGroup(3, NioIoHandler.newFactory());
        final List<Socket> sockets = new ArrayList<>();
        final ConcurrentLinkedQueue<Channel> accepted = new ConcurrentLinkedQueue<>();
        final Channel server;

        Fixture() throws Exception {
            var account = new ClientAccount();account.setId(42L);account.setTenantId("t1");account.setClientName(name);
            var auth = mock(ClientAuthService.class);
            when(auth.authenticateNetty(any(), anyString(), anyString(), anyBoolean())).thenAnswer(invocation -> {
                LoginRequestPacket packet = invocation.getArgument(0);
                return AuthenticationResult.success(account, packet.getClientSessionId());
            });
            when(auth.controlClientId(anyString())).thenReturn(42L);
            when(auth.authenticateNetty(any(), anyString(), anyString(), anyBoolean(), any())).thenAnswer(invocation -> {
                LoginRequestPacket packet = invocation.getArgument(0);
                return AuthenticationResult.success(account, packet.getClientSessionId());
            });
            var handler = new ManagedLoginRequestHandler(auth, mock(ConnectionRecordService.class),
                    mock(NatControlService.class), mock(PeerSignalService.class), new NettyServerProperties(),
                    loginExecutor, mock(ProductMetricsService.class));
            server = new ServerBootstrap().group(boss, worker).channel(NioServerSocketChannel.class)
                    .childHandler(new ChannelInitializer<SocketChannel>() {
                        @Override protected void initChannel(SocketChannel channel) {
                            accepted.add(channel);
                            channel.pipeline().addLast(new Spliter(), PacketCodecHandler.INSTANCE,
                                    new ChannelInboundHandlerAdapter() {
                                        @Override public void channelRead(ChannelHandlerContext ctx, Object message) {
                                            ctx.fireChannelRead(message);
                                            if (message instanceof LoginRequestPacket packet
                                                    && ConnectionRole.DATA.equals(packet.getConnectionRole())) {
                                                reached.countDown();
                                                try {
                                                    if (!release.await(10, TimeUnit.SECONDS))
                                                        throw new AssertionError("test DATA gate was not released");
                                                } catch (InterruptedException interrupted) {
                                                    Thread.currentThread().interrupt();
                                                    throw new AssertionError(interrupted);
                                                }
                                            }
                                        }
                                    }, handler);
                        }
                    }).bind("127.0.0.1", 0).sync().channel();
        }

        Socket pendingData(long session) throws Exception {
            Socket socket = send(ConnectionRole.DATA, session);
            assertTrue(reached.await(5, TimeUnit.SECONDS));
            // The native authentication worker has finished and queued the event-loop bind.
            loginExecutor.submit(() -> {}).get(5, TimeUnit.SECONDS);
            return socket;
        }

        void login(String role, long session) throws Exception {
            var reply = response(send(role, session));
            assertTrue(reply.isSuccess(), reply.getReason());
        }

        Socket send(String role, long session) throws Exception {
            var socket = new Socket();sockets.add(socket);socket.setSoTimeout(5000);
            socket.connect(new InetSocketAddress("127.0.0.1", ((InetSocketAddress)server.localAddress()).getPort()), 5000);
            var packet = new LoginRequestPacket();packet.setClientName(name);packet.setAccessToken("fixture-token");
            packet.setClientSessionId(session);packet.setConnectionRole(role);
            var frame = Unpooled.buffer();
            try {
                PacketCodec.INSTANCE.encode(frame, packet);
                var bytes = new byte[frame.readableBytes()];frame.readBytes(bytes);socket.getOutputStream().write(bytes);
            } finally {frame.release();}
            return socket;
        }

        LoginResponsePacket response(Socket socket) throws Exception {
            var input = socket.getInputStream();var header = input.readNBytes(PacketCodec.HEADER_SIZE);
            assertEquals(PacketCodec.HEADER_SIZE, header.length, "expected a framed LOGIN_RESPONSE before EOF");
            int length = ByteBuffer.wrap(header).getInt(7);
            assertTrue(length > 0 && length <= PacketCodec.PRE_AUTH_MAX_FRAME_SIZE);
            var body = input.readNBytes(length);assertEquals(length, body.length);
            var frame = Unpooled.wrappedBuffer(header, body);
            try {return assertInstanceOf(LoginResponsePacket.class, PacketCodec.INSTANCE.decode(frame));}
            finally {frame.release();}
        }

        void rejectedAndRetryable(Socket socket) throws Exception {
            var reply = response(socket);assertFalse(reply.isSuccess(), "a superseded/missing CONTROL must reject DATA");
            assertEquals(-1, socket.getInputStream().read(), "rejected DATA must close after its failure reply");
            // Feed the actual serialized server response to the production client classifier.
            // No client-side policy changes: existing Java/Go/.NET versions recognize this reason.
            var bean = new SpecusBean();bean.setClientName(name);bean.setClientSessionId(7L);
            bean.setAccessToken("fixture-token");bean.setRemoteAddress("127.0.0.1");bean.setRemotePort(1);
            var client = new NettyClient(bean);
            var channel = new EmbeddedChannel(new LoginResponseHandler(client, ConnectionRole.DATA));
            try {
                channel.writeInbound(reply);
                assertFalse(client.isReconnectSuppressed(), "a transient CONTROL race must not stop all reconnects");
                assertFalse(channel.isActive());
            } finally {channel.finishAndReleaseAll();}
        }

        @Override public void close() throws Exception {
            release.countDown();
            for (var socket : sockets) socket.close();
            for (var channel : accepted) channel.close().awaitUninterruptibly(5, TimeUnit.SECONDS);
            server.close().awaitUninterruptibly(5, TimeUnit.SECONDS);
            loginExecutor.shutdown();assertTrue(loginExecutor.awaitTermination(5, TimeUnit.SECONDS));
            worker.shutdownGracefully(0, 1, TimeUnit.SECONDS).awaitUninterruptibly(5, TimeUnit.SECONDS);
            boss.shutdownGracefully(0, 1, TimeUnit.SECONDS).awaitUninterruptibly(5, TimeUnit.SECONDS);
            assertNull(SessionUtil.getChannel(name));assertNull(SessionUtil.getDataChannel(name));
        }
    }
}
