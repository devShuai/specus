package com.theshuai.specusclient.handler;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.common.protocol.HttpRouteFailure;
import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.specusclient.bean.HttpSpecusConfig;
import com.theshuai.specusclient.bean.SpecusBean;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.channel.ConnectTimeoutException;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslHandshakeTimeoutException;
import io.netty.resolver.AddressResolver;
import io.netty.resolver.AddressResolverGroup;
import io.netty.resolver.InetNameResolver;
import io.netty.util.concurrent.EventExecutor;
import io.netty.util.concurrent.Promise;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NoRouteToHostException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import javax.net.ssl.KeyManagerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * An HTTP route stream that fails before its response OPEN says why on its RST
 * (protocol/spec/service-connectivity-check.md section 6.2), so the connectivity check can tell a
 * refused target from a route the device has not loaded.
 *
 * <p>Each failure here is a real one on loopback, sent through the client's own forwarder, and the
 * RST is read from the data connection: a closed port, a resolver answering that a name does not
 * exist, a lookup or a TLS handshake held past a short connect timeout, https spoken to plain HTTP,
 * an untrusted certificate, and targets that close, reset or answer garbage before the head. The
 * value and reason stay as they were; failures outside the set carry no {@code failure} key at all.
 */
class HttpRouteFailureTests {
    private static final String ROUTE = "svc";
    private static final int STREAM = 91;
    private static final String UNKNOWN_NAME = "specus-connectivity-check.invalid";

    private static final char[] KEYSTORE_PASSWORD = "route-failure-test".toCharArray();

    @TempDir
    static Path keystoreDirectory;
    private static EventLoopGroup serverGroup;
    private static SslContext untrustedTls;

    @BeforeAll
    static void startServers() throws Exception {
        serverGroup = new MultiThreadIoEventLoopGroup(1, NioIoHandler.newFactory());
        untrustedTls = SslContextBuilder.forServer(selfSignedKeyManager()).build();
    }

    @AfterAll
    static void stopServers() {
        serverGroup.shutdownGracefully(0, 1, TimeUnit.SECONDS).awaitUninterruptibly(5, TimeUnit.SECONDS);
    }

    /**
     * A key and self-signed certificate for a TLS target no trust store knows, made with the JDK's
     * own keytool: Netty's generator needs Bouncy Castle, or a keytool it does not find on Windows.
     */
    private static KeyManagerFactory selfSignedKeyManager() throws Exception {
        boolean windows = System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
        Path keytool = Path.of(System.getProperty("java.home"), "bin", windows ? "keytool.exe" : "keytool");
        Path keystore = keystoreDirectory.resolve("untrusted-target.p12");
        String password = new String(KEYSTORE_PASSWORD);
        Process process = new ProcessBuilder(keytool.toString(), "-genkeypair", "-alias", "target",
                "-keyalg", "EC", "-groupname", "secp256r1", "-dname", "CN=localhost", "-validity", "2",
                "-storetype", "PKCS12", "-keystore", keystore.toString(),
                "-storepass", password, "-keypass", password)
                .redirectErrorStream(true)
                .start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(process.waitFor(60, TimeUnit.SECONDS) && process.exitValue() == 0, "keytool failed: " + output);
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream input = Files.newInputStream(keystore)) {
            store.load(input, KEYSTORE_PASSWORD);
        }
        KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagers.init(store, KEYSTORE_PASSWORD);
        return keyManagers;
    }

    @Test
    void theFailureSetIsTheConnectivityVectorSet() throws Exception {
        JsonNode vector = new ObjectMapper().readTree(vectorFile().toFile());
        Set<String> expected = new TreeSet<>();
        vector.path("rstFailures").fieldNames().forEachRemaining(expected::add);
        Set<String> sent = new TreeSet<>();
        for (HttpRouteFailure failure : HttpRouteFailure.values()) {
            sent.add(failure.wireName());
            assertEquals(failure, HttpRouteFailure.fromWireName(failure.wireName()));
        }
        assertEquals(expected, sent);
        assertNull(HttpRouteFailure.fromWireName("connect-reset"));
        assertEquals("failure", HttpRouteFailure.METADATA_KEY);
    }

    // --- device-online: the route ---

    @Test
    void aRouteTheDeviceHasNotLoadedIsRouteNotLoaded() throws Exception {
        NatMessagePacket reset = resetFor(List.of(), null);
        assertFailure(HttpRouteFailure.ROUTE_NOT_LOADED, reset);
        assertEquals("未配置 HTTP route", reset.getMetaData().get("reason"));
    }

    @Test
    void aRouteWithoutATargetIsRouteNotLoaded() throws Exception {
        assertFailure(HttpRouteFailure.ROUTE_NOT_LOADED, resetFor(List.of(route("")), null));
    }

    // --- target-reachable ---

    @Test
    void aTargetTheRouteCannotUseIsTargetInvalid() throws Exception {
        assertFailure(HttpRouteFailure.TARGET_INVALID, resetFor(List.of(route("ftp://127.0.0.1/")), null));
    }

    @Test
    void aClosedPortIsConnectRefused() throws Exception {
        NatMessagePacket reset = resetFor(List.of(route("http://127.0.0.1:" + closedLoopbackPort())), null);
        assertFailure(HttpRouteFailure.CONNECT_REFUSED, reset);
    }

    @Test
    void aNameTheResolverDoesNotKnowIsDnsFailed() throws Exception {
        // What the system resolver raises for NXDOMAIN, without asking the network.
        NatMessagePacket reset = resetFor(List.of(route("http://" + UNKNOWN_NAME + ":8080")),
                new HttpUpstreamDial(5_000, new FixedLookup(host -> {
                    throw new UnknownHostException(host);
                })));
        assertFailure(HttpRouteFailure.DNS_FAILED, reset);
    }

    @Test
    void aLookupStillRunningWhenTheConnectTimeoutExpiresIsConnectTimeout() throws Exception {
        NatMessagePacket reset = resetFor(List.of(route("http://" + UNKNOWN_NAME + ":8080")),
                new HttpUpstreamDial(300, new FixedLookup(null)));
        assertFailure(HttpRouteFailure.CONNECT_TIMEOUT, reset);
    }

    @Test
    void aTlsHandshakeStillRunningWhenTheConnectTimeoutExpiresIsConnectTimeout() throws Exception {
        try (ServerSocket silent = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
            Thread acceptor = holdConnections(silent, socket -> sleepQuietly(Duration.ofSeconds(5)));
            NatMessagePacket reset = resetFor(List.of(route("https://127.0.0.1:" + silent.getLocalPort())),
                    new HttpUpstreamDial(300, HttpUpstreamDial.DEFAULT.resolver()));
            assertFailure(HttpRouteFailure.CONNECT_TIMEOUT, reset);
            acceptor.interrupt();
        }
    }

    @Test
    void httpsToAPlainHttpServerIsTlsFailed() throws Exception {
        try (ServerSocket plain = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
            holdConnections(plain, socket -> answer(socket,
                    "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"));
            NatMessagePacket reset = resetFor(List.of(route("https://127.0.0.1:" + plain.getLocalPort())), null);
            assertFailure(HttpRouteFailure.TLS_FAILED, reset);
        }
    }

    @Test
    void anUntrustedCertificateIsTlsFailed() throws Exception {
        SslContext serverTls = untrustedTls;
        Channel server = new ServerBootstrap()
                .group(serverGroup)
                .channel(NioServerSocketChannel.class)
                .childHandler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel channel) {
                        channel.pipeline().addLast(serverTls.newHandler(channel.alloc()));
                    }
                })
                .bind(InetAddress.getLoopbackAddress(), 0).sync().channel();
        try {
            int port = ((InetSocketAddress) server.localAddress()).getPort();
            NatMessagePacket reset = resetFor(List.of(route("https://127.0.0.1:" + port)), null);
            assertFailure(HttpRouteFailure.TLS_FAILED, reset);
        } finally {
            server.close().syncUninterruptibly();
        }
    }

    @Test
    void aTargetThatClosesBeforeTheHeadIsProtocolError() throws Exception {
        try (ServerSocket closing = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
            holdConnections(closing, socket -> {
                readRequestHead(socket);
                closeQuietly(socket);
            });
            assertProtocolErrorWithoutHead(closing);
        }
    }

    @Test
    void aTargetThatResetsBeforeTheHeadIsProtocolError() throws Exception {
        try (ServerSocket resetting = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
            holdConnections(resetting, socket -> {
                readRequestHead(socket);
                try {
                    socket.setSoLinger(true, 0);
                } catch (SocketException ignored) {
                    // Closed already.
                }
                closeQuietly(socket);
            });
            assertProtocolErrorWithoutHead(resetting);
        }
    }

    @Test
    void aTargetThatAnswersGarbageIsProtocolErrorAndNoHeadIsMadeUp() throws Exception {
        try (ServerSocket garbage = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
            holdConnections(garbage, socket -> {
                readRequestHead(socket);
                answer(socket, "SSH-2.0-OpenSSH_9.6\r\n\r\n");
                sleepQuietly(Duration.ofSeconds(2));
            });
            assertProtocolErrorWithoutHead(garbage);
        }
    }

    // --- what stays unclassified ---

    @Test
    void aMalformedRequestCarriesNoFailure() throws Exception {
        Map<String, Object> open = new HashMap<>(httpOpen());
        open.remove("method");
        NatMessagePacket reset = resetFor(List.of(route("http://127.0.0.1:" + closedLoopbackPort())), null, open);
        assertNoFailure(reset);
    }

    @Test
    void aLocalLimitCarriesNoFailure() throws Exception {
        Map<String, Object> open = new HashMap<>(httpOpen());
        open.put("contentLength", 64L * 1024 * 1024);
        NatMessagePacket reset = resetFor(List.of(route("http://127.0.0.1:" + closedLoopbackPort())), null, open);
        assertNoFailure(reset);
    }

    @Test
    void aFailureAfterTheResponseOpenCarriesNoFailure() throws Exception {
        try (ServerSocket truncating = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
            holdConnections(truncating, socket -> {
                readRequestHead(socket);
                answer(socket, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n0123456789");
                closeQuietly(socket);
            });
            Frames frames = new Frames();
            NatMessagePacket reset = resetFor(
                    List.of(route("http://127.0.0.1:" + truncating.getLocalPort())), null, httpOpen(), frames);
            assertEquals(1, frames.count(NatMessageType.OPEN), "the response OPEN went out first");
            assertNoFailure(reset);
        }
    }

    @Test
    void aStreamTheServerCancelsIsNotResetBack() throws Exception {
        NatClientHandler handler = new NatClientHandler(bean(List.of(route("http://" + UNKNOWN_NAME + ":8080"))));
        handler.useHttpUpstreamDial(new HttpUpstreamDial(500, new FixedLookup(null)));
        Frames frames = new Frames();
        EmbeddedChannel control = new EmbeddedChannel(frames, handler);
        try {
            control.writeInbound(open(STREAM, httpOpen()));
            control.writeInbound(rst(STREAM));
            sleepQuietly(Duration.ofMillis(1_500));
            control.runPendingTasks();
            assertEquals(0, frames.count(NatMessageType.RST), "a cancelled stream is not reset back");
            assertTrue(control.isActive());
        } finally {
            control.finishAndReleaseAll();
        }
    }

    // --- types no loopback failure produces ---

    @Test
    void theClassifierGoesByTypeForFailuresLoopbackCannotProduce() {
        assertEquals(HttpRouteFailure.UNREACHABLE,
                HttpRouteFailureClassifier.connectFailure(new NoRouteToHostException("no route")));
        assertEquals(HttpRouteFailure.CONNECT_TIMEOUT,
                HttpRouteFailureClassifier.connectFailure(new ConnectTimeoutException("timed out")));
        assertEquals(HttpRouteFailure.CONNECT_REFUSED,
                HttpRouteFailureClassifier.connectFailure(new ConnectException("refused")));
        assertEquals(HttpRouteFailure.DNS_FAILED,
                HttpRouteFailureClassifier.connectFailure(new UnknownHostException("nowhere")));
        assertEquals(HttpRouteFailure.CONNECT_TIMEOUT,
                HttpRouteFailureClassifier.handshakeFailure(new SslHandshakeTimeoutException("timed out")));
        // Message text never decides: a plain socket failure says nothing the type does not.
        assertNull(HttpRouteFailureClassifier.connectFailure(new SocketException("Network is unreachable")));
        assertNull(HttpRouteFailureClassifier.connectFailure(new SocketException("Connection refused")));
        assertNull(HttpRouteFailureClassifier.connectFailure(new IllegalStateException("anything")));
        assertNull(HttpRouteFailureClassifier.exchangeFailure(new IllegalStateException("local")));
        assertNull(HttpRouteFailureClassifier.carried(new IOException("unclassified")));
    }

    // --- helpers ---

    private static void assertProtocolErrorWithoutHead(ServerSocket target) throws Exception {
        Frames frames = new Frames();
        NatMessagePacket reset = resetFor(
                List.of(route("http://127.0.0.1:" + target.getLocalPort())), null, httpOpen(), frames);
        assertFailure(HttpRouteFailure.PROTOCOL_ERROR, reset);
        assertEquals(0, frames.count(NatMessageType.OPEN), "no response head is made up for the target");
    }

    private static void assertFailure(HttpRouteFailure expected, NatMessagePacket reset) {
        assertEquals(8, reset.getValue(), "the RST value is unchanged");
        Object reason = reset.getMetaData().get("reason");
        assertTrue(reason instanceof String text && !text.isBlank(), "the reason is still carried");
        assertEquals(expected.wireName(), reset.getMetaData().get(HttpRouteFailure.METADATA_KEY),
                "metadata " + reset.getMetaData());
    }

    private static void assertNoFailure(NatMessagePacket reset) {
        assertEquals(8, reset.getValue());
        assertNotNull(reset.getMetaData().get("reason"));
        assertFalse(reset.getMetaData().containsKey(HttpRouteFailure.METADATA_KEY),
                "metadata " + reset.getMetaData());
    }

    private static NatMessagePacket resetFor(List<HttpSpecusConfig> routes, HttpUpstreamDial dial) throws Exception {
        return resetFor(routes, dial, httpOpen());
    }

    private static NatMessagePacket resetFor(List<HttpSpecusConfig> routes, HttpUpstreamDial dial,
                                             Map<String, Object> openMetadata) throws Exception {
        return resetFor(routes, dial, openMetadata, new Frames());
    }

    /** Opens one GET on the route, ends its request, and returns the RST the client writes for it. */
    private static NatMessagePacket resetFor(List<HttpSpecusConfig> routes, HttpUpstreamDial dial,
                                             Map<String, Object> openMetadata, Frames frames) throws Exception {
        NatClientHandler handler = new NatClientHandler(bean(routes));
        if (dial != null) {
            handler.useHttpUpstreamDial(dial);
        }
        EmbeddedChannel control = new EmbeddedChannel(frames, handler);
        try {
            control.writeInbound(open(STREAM, openMetadata));
            control.writeInbound(fin(STREAM));
            NatMessagePacket reset = frames.await(control, NatMessageType.RST);
            assertNotNull(reset, "the stream must be reset");
            assertNotNull(reset.getMetaData(), "the RST carries metadata");
            assertTrue(control.isActive(), "one failing route does not close the data connection");
            return reset;
        } finally {
            control.finishAndReleaseAll();
        }
    }

    private static Map<String, Object> httpOpen() {
        return Map.of(
                "source", "http",
                "phase", "request",
                "method", "GET",
                "route", ROUTE,
                "relativePath", "/",
                "headers", List.of("Accept:*/*"));
    }

    private static HttpSpecusConfig route(String targetBaseUrl) {
        HttpSpecusConfig config = new HttpSpecusConfig();
        config.setRoute(ROUTE);
        config.setTargetBaseUrl(targetBaseUrl);
        return config;
    }

    private static SpecusBean bean(List<HttpSpecusConfig> routes) {
        SpecusBean bean = new SpecusBean();
        bean.setClientName("route-failure-test");
        bean.setRemoteAddress("127.0.0.1");
        bean.setSpecusConfigList(List.of());
        bean.setHttpSpecusConfigList(routes);
        return bean;
    }

    /** Serves each connection on its own thread until the socket is closed. */
    private static Thread holdConnections(ServerSocket server, Consumer<Socket> serve) {
        Thread acceptor = new Thread(() -> {
            try {
                while (!server.isClosed()) {
                    Socket socket = server.accept();
                    Thread connection = new Thread(() -> {
                        try {
                            serve.accept(socket);
                        } finally {
                            closeQuietly(socket);
                        }
                    }, "route-failure-target-connection");
                    connection.setDaemon(true);
                    connection.start();
                }
            } catch (IOException closed) {
                // The test is over.
            }
        }, "route-failure-target");
        acceptor.setDaemon(true);
        acceptor.start();
        return acceptor;
    }

    private static void readRequestHead(Socket socket) {
        try {
            socket.setSoTimeout(5_000);
            InputStream input = socket.getInputStream();
            ByteArrayOutputStream head = new ByteArrayOutputStream();
            int previous = -1;
            int current;
            int newlines = 0;
            while ((current = input.read()) >= 0) {
                head.write(current);
                if (current == '\n') {
                    newlines = previous == '\r' || previous == '\n' ? newlines + 1 : 1;
                    if (newlines == 2) {
                        return;
                    }
                } else if (current != '\r') {
                    newlines = 0;
                }
                previous = current;
            }
        } catch (IOException ignored) {
            // The client went away; the test reads what it sent.
        }
    }

    private static void answer(Socket socket, String response) {
        try {
            socket.getOutputStream().write(response.getBytes(StandardCharsets.ISO_8859_1));
            socket.getOutputStream().flush();
        } catch (IOException ignored) {
            // The client went away.
        }
    }

    private static void closeQuietly(Socket socket) {
        try {
            socket.close();
        } catch (IOException ignored) {
            // Closed already.
        }
    }

    private static void sleepQuietly(Duration duration) {
        try {
            Thread.sleep(duration.toMillis());
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    /** A loopback port that was free a moment ago, so a connect to it is refused. */
    private static int closedLoopbackPort() throws IOException {
        try (ServerSocket probe = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            return probe.getLocalPort();
        }
    }

    private static Path vectorFile() {
        Path current = Path.of("").toAbsolutePath();
        while (current != null) {
            Path candidate = current.resolve("protocol/test-vectors/service-connectivity-check-v1.json");
            if (Files.isRegularFile(candidate)) {
                return candidate;
            }
            current = current.getParent();
        }
        throw new IllegalStateException("service-connectivity-check-v1.json not found");
    }

    /** Answers every lookup with what {@code lookup} returns or throws; null never answers at all. */
    private static final class FixedLookup extends AddressResolverGroup<InetSocketAddress> {
        private final Lookup lookup;

        FixedLookup(Lookup lookup) {
            this.lookup = lookup;
        }

        @Override
        protected AddressResolver<InetSocketAddress> newResolver(EventExecutor executor) {
            return new InetNameResolver(executor) {
                @Override
                protected void doResolve(String host, Promise<InetAddress> promise) {
                    if (lookup == null) {
                        return;
                    }
                    try {
                        promise.setSuccess(lookup.resolve(host));
                    } catch (UnknownHostException notFound) {
                        promise.setFailure(notFound);
                    }
                }

                @Override
                protected void doResolveAll(String host, Promise<List<InetAddress>> promise) {
                    if (lookup == null) {
                        return;
                    }
                    try {
                        promise.setSuccess(List.of(lookup.resolve(host)));
                    } catch (UnknownHostException notFound) {
                        promise.setFailure(notFound);
                    }
                }
            }.asAddressResolver();
        }
    }

    @FunctionalInterface
    private interface Lookup {
        InetAddress resolve(String host) throws UnknownHostException;
    }

    /**
     * Collects what the client sends on the data connection, from whatever thread writes it; see
     * {@link NatLocalConnectFailureIsolationTests}.
     */
    private static final class Frames extends ChannelOutboundHandlerAdapter {
        private final Queue<NatMessagePacket> incoming = new ConcurrentLinkedQueue<>();
        private final List<NatMessagePacket> seen = new ArrayList<>();

        @Override
        public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) {
            if (msg instanceof NatMessagePacket packet) {
                incoming.add(packet);
            }
            promise.trySuccess();
        }

        private void drain() {
            NatMessagePacket packet;
            while ((packet = incoming.poll()) != null) {
                seen.add(packet);
            }
        }

        private int count(NatMessageType type) {
            drain();
            int count = 0;
            for (NatMessagePacket packet : seen) {
                if (packet.getStreamId() == STREAM && packet.getNatMessageType() == type) {
                    count++;
                }
            }
            return count;
        }

        private NatMessagePacket await(EmbeddedChannel control, NatMessageType type) throws Exception {
            long deadline = System.nanoTime() + Duration.ofSeconds(15).toNanos();
            while (System.nanoTime() < deadline) {
                control.runPendingTasks();
                drain();
                for (NatMessagePacket packet : seen) {
                    if (packet.getStreamId() == STREAM && packet.getNatMessageType() == type) {
                        return packet;
                    }
                }
                Thread.sleep(5);
            }
            return null;
        }
    }

    private static NatMessagePacket open(int streamId, Map<String, Object> metadata) {
        NatMessagePacket packet = new NatMessagePacket();
        packet.setNatMessageType(NatMessageType.OPEN);
        packet.setStreamId(streamId);
        packet.setMetaData(metadata);
        return packet;
    }

    private static NatMessagePacket fin(int streamId) {
        NatMessagePacket packet = new NatMessagePacket();
        packet.setNatMessageType(NatMessageType.FIN);
        packet.setStreamId(streamId);
        return packet;
    }

    private static NatMessagePacket rst(int streamId) {
        NatMessagePacket packet = new NatMessagePacket();
        packet.setNatMessageType(NatMessageType.RST);
        packet.setStreamId(streamId);
        packet.setValue(1);
        return packet;
    }
}
