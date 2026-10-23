package com.theshuai.specusserver.http;

import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.common.protocol.WebSocketSpecusFrame;
import com.theshuai.common.session.Session;
import com.theshuai.specusserver.handler.NatServerHandler;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.service.ClientAccountService;
import com.theshuai.specusserver.management.service.HttpRouteService;
import com.theshuai.specusserver.session.SessionUtil;
import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.local.LocalAddress;
import io.netty.channel.local.LocalChannel;
import io.netty.channel.local.LocalIoHandler;
import io.netty.channel.local.LocalServerChannel;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/**
 * A route WebSocket end to end on the real servlet container: a JDK WebSocket plays the browser on
 * {@code /http/{client}/{route}/**}, and the device is a data connection over Netty's local
 * transport running the production {@link NatServerHandler}. The device returns credit for every
 * DATA frame on its own event loop a simulated round trip later, as a real client does across the
 * network, so a browser on loopback sends far faster than credit comes back: a 16 MiB message only
 * gets through when the server stops reading the browser instead of overrunning the stream queue.
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "spring.datasource.url=jdbc:sqlite::memory:",
                "spring.jpa.database-platform=org.hibernate.community.dialect.SQLiteDialect",
                "spring.jpa.hibernate.ddl-auto=create-drop",
                "specus.netty.port=0",
                "specus.database.seed-demo-client=false",
                "specus.env=dev",
                "specus.auth.username=admin",
                "specus.auth.password=admin"
        }
)
class HttpWebSocketTunnelTests {
    private static final String CLIENT = "ws-tunnel-client";
    private static final int MAX_MESSAGE_BYTES = 16 * 1024 * 1024;
    private static final Duration WAIT = Duration.ofSeconds(30);
    private static final Duration CREDIT_DELAY = Duration.ofMillis(20);

    @Value("${local.server.port}")
    private int port;

    @Autowired private ClientAccountService clientAccountService;
    @Autowired private ClientAccountRepository clientAccountRepository;
    @Autowired private HttpRouteService httpRouteService;
    @Autowired private WebSocketSpecusHandler webSocketHandler;
    @Autowired private WebSocketStreamRegistry webSocketRegistry;

    private Device device;

    @BeforeEach
    void connectDevice() throws Exception {
        if (clientAccountRepository.findByClientName(CLIENT).isEmpty()) {
            clientAccountService.createClient(new ClientAccountService.ClientMutation(CLIENT, true, 0));
            long clientId = clientAccountRepository.findByClientName(CLIENT).orElseThrow().getId();
            httpRouteService.createRoute(clientId,
                    new HttpRouteService.RouteMutation("route", "http://127.0.0.1:8080", true));
        }
        device = Device.connect(CLIENT, webSocketRegistry, webSocketHandler);
    }

    @AfterEach
    void closeDevice() {
        device.close();
    }

    @Test
    void browserMessagesUpToSixteenMebibytesReachTheDevice() throws Exception {
        Browser browser = Browser.open(port);
        try {
            byte[] binary = pattern(64 * 1024 + 1);
            browser.socket.sendBinary(ByteBuffer.wrap(binary), true).get(30, TimeUnit.SECONDS);
            assertMessage(device.nextMessage(), WebSocketSpecusFrame.OPCODE_BINARY, binary);

            byte[] text = "你好, WebSocket ".repeat(5_000).getBytes(StandardCharsets.UTF_8);
            assertThat(text.length).isGreaterThan(64 * 1024);
            browser.socket.sendText(new String(text, StandardCharsets.UTF_8), true).get(30, TimeUnit.SECONDS);
            assertMessage(device.nextMessage(), WebSocketSpecusFrame.OPCODE_TEXT, text);

            byte[] largest = pattern(MAX_MESSAGE_BYTES);
            browser.socket.sendBinary(ByteBuffer.wrap(largest), true).get(60, TimeUnit.SECONDS);
            assertMessage(device.nextMessage(), WebSocketSpecusFrame.OPCODE_BINARY, largest);

            assertThat(browser.closed).isNotDone();
            assertThat(device.resets()).isEmpty();
        } finally {
            browser.socket.abort();
        }
    }

    @Test
    void browserMessageOverSixteenMebibytesIsRefusedWith1009() throws Exception {
        Browser browser = Browser.open(port);
        try {
            browser.socket.sendBinary(ByteBuffer.wrap(pattern(MAX_MESSAGE_BYTES + 1)), true);

            assertThat(browser.closed.get(WAIT.toSeconds(), TimeUnit.SECONDS)).isEqualTo(1009);
            int streamId = device.streamId();
            await().atMost(WAIT).until(() -> device.finished(streamId));
            WebSocketSpecusFrame close = device.closeFrame(streamId);
            assertThat(close).isNotNull();
            assertThat(close.closeCode()).isEqualTo(1009);
            assertThat(device.messages).as("the refused message never completes on the device").isEmpty();
            assertThat(device.resets()).isEmpty();
        } finally {
            browser.socket.abort();
        }
    }

    @Test
    void browserLeavingWithoutCloseResetsTheStream() throws Exception {
        Browser browser = Browser.open(port);
        int streamId = device.streamId();
        browser.socket.abort();

        await().atMost(WAIT).until(() -> !device.resets().isEmpty());
        NatMessagePacket reset = device.resets().getFirst();
        assertThat(reset.getStreamId()).isEqualTo(streamId);
        assertThat(reset.getValue()).isEqualTo(31);
        assertThat(device.finished(streamId)).as("no FIN, the stream was cancelled").isFalse();
        await().atMost(WAIT).until(() -> webSocketRegistry.getByStreamId(streamId) == null);
    }

    private static void assertMessage(Device.Message message, int opcode, byte[] expected) throws Exception {
        assertThat(message).as("the device received the whole message").isNotNull();
        assertThat(message.opcode()).isEqualTo(opcode);
        assertThat(message.length()).isEqualTo(expected.length);
        assertThat(message.sha256()).isEqualTo(MessageDigest.getInstance("SHA-256").digest(expected));
    }

    private static byte[] pattern(int length) {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++) {
            bytes[i] = (byte) (i % 251);
        }
        return bytes;
    }

    /** The browser: a JDK WebSocket on the public route entry. */
    private record Browser(WebSocket socket, CompletableFuture<Integer> closed) {
        static Browser open(int port) throws Exception {
            CompletableFuture<Integer> closed = new CompletableFuture<>();
            WebSocket socket = HttpClient.newHttpClient().newWebSocketBuilder()
                    .buildAsync(URI.create("ws://localhost:" + port + "/http/" + CLIENT + "/route/socket"),
                            new WebSocket.Listener() {
                                @Override
                                public void onOpen(WebSocket webSocket) {
                                    webSocket.request(Long.MAX_VALUE);
                                }

                                @Override
                                public CompletionStage<?> onClose(WebSocket webSocket, int statusCode,
                                                                  String reason) {
                                    closed.complete(statusCode);
                                    return null;
                                }

                                @Override
                                public void onError(WebSocket webSocket, Throwable error) {
                                    closed.complete(-1);
                                }
                            })
                    .get(10, TimeUnit.SECONDS);
            return new Browser(socket, closed);
        }
    }

    /**
     * The device end of a data connection: records every NAT frame, reassembles the SWS2 messages
     * of WebSocket streams, and answers each DATA with a WINDOW_UPDATE for its bytes.
     */
    private static final class Device extends ChannelInboundHandlerAdapter implements AutoCloseable {
        record Message(int opcode, long length, byte[] sha256) {
        }

        private final EventLoopGroup group = new MultiThreadIoEventLoopGroup(2, LocalIoHandler.newFactory());
        private final List<NatMessagePacket> packets = new CopyOnWriteArrayList<>();
        private final BlockingQueue<Message> messages = new LinkedBlockingQueue<>();
        private int messageOpcode = -1;
        private long messageLength;
        private MessageDigest messageDigest;
        private Channel server;
        private Channel client;

        static Device connect(String clientName, WebSocketStreamRegistry registry,
                              WebSocketSpecusHandler handler) throws Exception {
            Device device = new Device();
            LocalAddress address = new LocalAddress("ws-tunnel-" + UUID.randomUUID());
            CompletableFuture<Channel> bound = new CompletableFuture<>();
            device.server = new ServerBootstrap()
                    .group(device.group)
                    .channel(LocalServerChannel.class)
                    .childHandler(new ChannelInitializer<LocalChannel>() {
                        @Override
                        protected void initChannel(LocalChannel channel) {
                            // Bound as the client's data connection before NatServerHandler sees it.
                            channel.pipeline().addLast(
                                    new ChannelInboundHandlerAdapter() {
                                        @Override
                                        public void channelActive(ChannelHandlerContext ctx) {
                                            SessionUtil.bindDataSession(new Session(clientName), ctx.channel());
                                            ctx.fireChannelActive();
                                            bound.complete(ctx.channel());
                                        }
                                    },
                                    new NatServerHandler(null, null, null, null, registry, handler));
                        }
                    })
                    .bind(address).sync().channel();
            device.client = new Bootstrap()
                    .group(device.group)
                    .channel(LocalChannel.class)
                    .handler(device)
                    .connect(address).sync().channel();
            bound.get(10, TimeUnit.SECONDS);
            return device;
        }

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
            if (!(msg instanceof NatMessagePacket packet)) {
                return;
            }
            packets.add(packet);
            if (packet.getNatMessageType() != NatMessageType.DATA) {
                return;
            }
            WebSocketSpecusFrame frame = WebSocketSpecusFrame.decode(packet.getData());
            if (frame.opcode() == WebSocketSpecusFrame.OPCODE_TEXT
                    || frame.opcode() == WebSocketSpecusFrame.OPCODE_BINARY) {
                messageOpcode = frame.opcode();
                messageLength = 0;
                messageDigest = MessageDigest.getInstance("SHA-256");
            }
            if (frame.opcode() < WebSocketSpecusFrame.OPCODE_CLOSE && messageDigest != null) {
                byte[] payload = frame.payload();
                messageLength += payload.length;
                messageDigest.update(payload);
                if (frame.finalFragment()) {
                    messages.add(new Message(messageOpcode, messageLength, messageDigest.digest()));
                    messageDigest = null;
                }
            }
            NatMessagePacket credit = new NatMessagePacket();
            credit.setNatMessageType(NatMessageType.WINDOW_UPDATE);
            credit.setStreamId(packet.getStreamId());
            credit.setValue(packet.getData().length);
            // Credit comes back a network round trip later, so a browser on loopback outruns it.
            ctx.executor().schedule(() -> ctx.writeAndFlush(credit), CREDIT_DELAY.toMillis(), TimeUnit.MILLISECONDS);
        }

        Message nextMessage() throws InterruptedException {
            return messages.poll(WAIT.toSeconds(), TimeUnit.SECONDS);
        }

        /** The stream of the browser that connected last. */
        int streamId() {
            await().atMost(WAIT).until(() -> packets.stream()
                    .anyMatch(packet -> packet.getNatMessageType() == NatMessageType.OPEN));
            return packets.stream().filter(packet -> packet.getNatMessageType() == NatMessageType.OPEN)
                    .reduce((first, second) -> second).orElseThrow().getStreamId();
        }

        boolean finished(int streamId) {
            return packets.stream().anyMatch(packet -> packet.getStreamId() == streamId
                    && packet.getNatMessageType() == NatMessageType.FIN);
        }

        WebSocketSpecusFrame closeFrame(int streamId) {
            return packets.stream()
                    .filter(packet -> packet.getStreamId() == streamId
                            && packet.getNatMessageType() == NatMessageType.DATA)
                    .map(packet -> WebSocketSpecusFrame.decode(packet.getData()))
                    .filter(frame -> frame.opcode() == WebSocketSpecusFrame.OPCODE_CLOSE)
                    .findFirst().orElse(null);
        }

        List<NatMessagePacket> resets() {
            return packets.stream().filter(packet -> packet.getNatMessageType() == NatMessageType.RST).toList();
        }

        @Override
        public void close() {
            for (Channel channel : new Channel[] {client, server}) {
                if (channel != null) {
                    channel.close().awaitUninterruptibly(5, TimeUnit.SECONDS);
                }
            }
            group.shutdownGracefully(0, 1, TimeUnit.SECONDS).awaitUninterruptibly(5, TimeUnit.SECONDS);
        }
    }
}
