package com.theshuai.specusserver.http;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.common.codec.PacketCodecHandler;
import com.theshuai.common.codec.Spliter;
import com.theshuai.common.protocol.ConnectionRole;
import com.theshuai.common.protocol.MessageType;
import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.common.protocol.Packet;
import com.theshuai.common.protocol.request.LoginRequestPacket;
import com.theshuai.common.protocol.response.LoginResponsePacket;
import com.theshuai.common.protocol.response.MessageResponsePacket;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A tunnel client reduced to what the HTTP route lifecycle vector needs. It logs in over real TCP
 * with an access token it already holds, as the Java client does when it reconnects: the control
 * connection first, then the dedicated data connection. It records every NAT_CONTROL its control
 * connection receives, and answers every HTTP OPEN on its data connection with one fixed response
 * whatever the route, like a client that still forwards a route list the server no longer has.
 */
final class FakeTunnelClient implements AutoCloseable {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Duration LOGIN_TIMEOUT = Duration.ofSeconds(5);

    /** What the client answers to every HTTP stream: status, "Name:value" headers and body. */
    record Response(int status, List<String> headers, String body) {
    }

    private final EventLoopGroup group = new MultiThreadIoEventLoopGroup(1, NioIoHandler.newFactory());
    private final List<JsonNode> natControls = new CopyOnWriteArrayList<>();
    private final List<JsonNode> peerControls = new CopyOnWriteArrayList<>();
    private final Set<Integer> httpStreams = ConcurrentHashMap.newKeySet();
    private final AtomicInteger opens;
    private final Response response;
    private Channel control;
    private Channel data;
    private String controlLoginName;

    private FakeTunnelClient(AtomicInteger opens, Response response) {
        this.opens = opens;
        this.response = response;
    }

    /**
     * Logs in both connections; fails when either login is refused. Every OPEN the data connection
     * receives, HTTP or not, is counted in {@code opens}.
     */
    static FakeTunnelClient connect(int nettyPort, String clientName, long clientSessionId, String accessToken,
                                    AtomicInteger opens, Response response) throws Exception {
        FakeTunnelClient client = new FakeTunnelClient(opens, response);
        try {
            Answer control = client.login(nettyPort, clientName, clientSessionId, accessToken, ConnectionRole.CONTROL);
            client.control = accepted(control, ConnectionRole.CONTROL);
            client.controlLoginName = control.response().getClientName();
            client.data = accepted(client.login(nettyPort, clientName, clientSessionId, accessToken,
                    ConnectionRole.DATA), ConnectionRole.DATA);
            return client;
        } catch (Exception | AssertionError failure) {
            client.close();
            throw failure;
        }
    }

    /**
     * One control login with the token, whose answer is returned whatever it is; the connection is
     * closed afterwards and no data connection follows.
     */
    static LoginResponsePacket controlLoginAnswer(int nettyPort, String clientName, long clientSessionId,
                                                  String accessToken) throws Exception {
        FakeTunnelClient client = new FakeTunnelClient(new AtomicInteger(), new Response(200, List.of(), ""));
        try {
            return client.login(nettyPort, clientName, clientSessionId, accessToken, ConnectionRole.CONTROL)
                    .response();
        } finally {
            client.close();
        }
    }

    /** The client name the server answered the control login with: the name it bound the connection under. */
    String controlLoginName() {
        return controlLoginName;
    }

    /** Every NAT_CONTROL body received on the control connection, in order. */
    List<JsonNode> natControls() {
        return natControls;
    }

    /** Every PEER_CONTROL body received on the control connection, in order. */
    List<JsonNode> peerControls() {
        return peerControls;
    }

    /** Whether the control connection is still open. */
    boolean controlOpen() {
        return control.isActive();
    }

    /** Whether the server closed both connections within {@code timeout}. */
    boolean awaitClosed(Duration timeout) throws InterruptedException {
        long deadline = System.nanoTime() + timeout.toNanos();
        boolean controlClosed = control.closeFuture().await(timeout.toMillis());
        long remaining = Math.max(0, TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime()));
        return controlClosed && data.closeFuture().await(remaining);
    }

    @Override
    public void close() {
        for (Channel channel : new Channel[] {data, control}) {
            if (channel != null) {
                channel.close().awaitUninterruptibly(5, TimeUnit.SECONDS);
            }
        }
        group.shutdownGracefully(0, 1, TimeUnit.SECONDS).awaitUninterruptibly(5, TimeUnit.SECONDS);
    }

    private record Answer(Channel channel, LoginResponsePacket response) {
    }

    private static Channel accepted(Answer answer, String role) {
        if (!answer.response().isSuccess()) {
            answer.channel().close();
            throw new AssertionError(role + " login refused: " + answer.response().getReason());
        }
        return answer.channel();
    }

    private Answer login(int nettyPort, String clientName, long clientSessionId, String accessToken, String role)
            throws Exception {
        CompletableFuture<LoginResponsePacket> answer = new CompletableFuture<>();
        Channel channel = new Bootstrap()
                .group(group)
                .channel(NioSocketChannel.class)
                .option(ChannelOption.TCP_NODELAY, true)
                .handler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) {
                        ch.pipeline().addLast(new Spliter(), PacketCodecHandler.INSTANCE, new Inbound(answer));
                    }
                })
                .connect("127.0.0.1", nettyPort)
                .sync()
                .channel();
        LoginRequestPacket login = new LoginRequestPacket();
        login.setClientName(clientName);
        login.setClientSessionId(clientSessionId);
        login.setAccessToken(accessToken);
        login.setConnectionRole(role);
        channel.writeAndFlush(login);
        return new Answer(channel, answer.get(LOGIN_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS));
    }

    private void onNatMessage(ChannelHandlerContext ctx, NatMessagePacket packet) {
        int streamId = packet.getStreamId();
        if (packet.getNatMessageType() == NatMessageType.OPEN) {
            opens.incrementAndGet();
            Map<String, Object> metadata = packet.getMetaData();
            if (metadata != null && "http".equals(metadata.get("source"))) {
                httpStreams.add(streamId);
            }
        } else if (packet.getNatMessageType() == NatMessageType.FIN && httpStreams.remove(streamId)) {
            // The request is complete: answer with the response head, the body and FIN.
            NatMessagePacket head = new NatMessagePacket();
            head.setNatMessageType(NatMessageType.OPEN);
            head.setStreamId(streamId);
            head.setMetaData(Map.of("source", "http", "phase", "response",
                    "statusCode", response.status(), "headers", response.headers()));
            ctx.write(head);
            if (!response.body().isEmpty()) {
                NatMessagePacket body = new NatMessagePacket();
                body.setNatMessageType(NatMessageType.DATA);
                body.setStreamId(streamId);
                body.setData(response.body().getBytes(StandardCharsets.UTF_8));
                ctx.write(body);
            }
            NatMessagePacket fin = new NatMessagePacket();
            fin.setNatMessageType(NatMessageType.FIN);
            fin.setStreamId(streamId);
            ctx.writeAndFlush(fin);
        }
    }

    private final class Inbound extends SimpleChannelInboundHandler<Packet> {
        private final CompletableFuture<LoginResponsePacket> answer;

        Inbound(CompletableFuture<LoginResponsePacket> answer) {
            this.answer = answer;
        }

        @Override
        protected void channelRead0(ChannelHandlerContext ctx, Packet packet) throws Exception {
            if (packet instanceof LoginResponsePacket login) {
                answer.complete(login);
            } else if (packet instanceof MessageResponsePacket message
                    && message.getMessageType() == MessageType.NAT_CONTROL) {
                natControls.add(JSON.readTree(message.getMessage()));
            } else if (packet instanceof MessageResponsePacket message
                    && message.getMessageType() == MessageType.PEER_CONTROL) {
                peerControls.add(JSON.readTree(message.getMessage()));
            } else if (packet instanceof NatMessagePacket nat) {
                onNatMessage(ctx, nat);
            }
        }

        @Override
        public void channelInactive(ChannelHandlerContext ctx) throws Exception {
            answer.completeExceptionally(new IllegalStateException("connection closed before the login answer"));
            super.channelInactive(ctx);
        }
    }
}
