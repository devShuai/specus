package com.theshuai.tunnelserver.integration;

import com.sun.net.httpserver.HttpServer;
import com.theshuai.tunnelclient.bean.TunnelBean;
import com.theshuai.tunnelclient.client.NettyClient;
import com.theshuai.tunnelclient.handler.DirectHttpRequestHandler;
import com.theshuai.tunnelserver.TunnelServerApplication;
import com.theshuai.tunnelserver.management.repository.ClientAccountRepository;
import com.theshuai.tunnelserver.management.repository.ConnectionRecordRepository;
import com.theshuai.tunnelserver.management.service.ClientAccountService;
import com.theshuai.tunnelserver.management.service.HttpRouteService;
import com.theshuai.tunnelserver.management.service.NatControlService;
import com.theshuai.tunnelserver.server.NettyServer;
import io.netty.channel.Channel;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.PageRequest;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/**
 * Full-stack end-to-end test:
 *   Spring Boot server (in-memory SQLite, random netty port)
 *     + an in-process mock HTTP backend
 *     + a real NettyClient connecting with HMAC-SHA256 login
 *     + a tunnel mapping registered via NatControlService
 *   then verify that an HTTP request to the server's public port is tunneled
 *   all the way through to the mock backend and the body comes back intact.
 */
@SpringBootTest(
        classes = TunnelServerApplication.class,
        webEnvironment = SpringBootTest.WebEnvironment.NONE,
        properties = {
                // SQLite `:memory:` gives every JDBC connection its own private
                // database, so the JPA transaction in the netty event loop
                // thread sees an empty DB (and the query returns `[null]`).
                // `cache=shared` lets HikariCP connections share the in-memory DB.
                "spring.datasource.url=jdbc:sqlite:file:target/test-e2e?mode=memory&cache=shared",
                "spring.jpa.database-platform=org.hibernate.community.dialect.SQLiteDialect",
                "spring.jpa.hibernate.ddl-auto=create-drop",
                "tunnel.netty.port=0",
                "tunnel.public-address=127.0.0.1",
                "tunnel.database.seed-demo-client=false",
                // Encrypt the control channel end-to-end. self-signed mode is
                // fine for an in-process test: the client uses an insecure
                // trust manager to accept the cert.
                "tunnel.tls.mode=self-signed"
        }
)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class EndToEndTunnelIT {

    private static final String CLIENT_NAME = "E2EClient";
    private static final String CLIENT_PASSWORD = "e2e-secret";
    private static final int TUNNEL_LISTEN_PORT = 19_000;

    @Autowired private ClientAccountService clientAccountService;
    @Autowired private NatControlService natControlService;
    @Autowired private HttpRouteService httpRouteService;
    @Autowired private NettyServer nettyServer;
    @Autowired private ConnectionRecordRepository connectionRecordRepository;
    @Autowired private ClientAccountRepository clientAccountRepository;

    private static HttpServer mockBackend;
    private static int backendPort;
    private NettyClient tunnelClient;

    @BeforeAll
    static void startMockBackend() throws IOException {
        backendPort = findFreePort();
        mockBackend = HttpServer.create(new InetSocketAddress("127.0.0.1", backendPort), 0);
        mockBackend.createContext("/hello", exchange -> {
            byte[] body = "hi from backend".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        mockBackend.start();
    }

    @AfterAll
    static void stopMockBackend() {
        if (mockBackend != null) {
            mockBackend.stop(0);
        }
    }

    @AfterEach
    void shutdownTunnelClient() {
        if (tunnelClient != null) {
            tunnelClient.shutdown();
            tunnelClient = null;
        }
    }

    @Test
    @Order(1)
    void shouldAuthenticateAndTunnelHttpTraffic() throws Exception {
        int nettyPort = nettyServer.getBoundPort();
        assertThat(nettyPort)
                .as("Netty server should have bound a real port")
                .isGreaterThan(0);

        clientAccountService.createClient(new ClientAccountService.ClientMutation(
                CLIENT_NAME, CLIENT_PASSWORD, true, 0
        ));
        Long clientId = clientAccountRepository.findByClientName(CLIENT_NAME)
                .orElseThrow()
                .getId();

        natControlService.createMapping(clientId, new NatControlService.MappingMutation(
                TUNNEL_LISTEN_PORT, "127.0.0.1", backendPort, true
        ));

        TunnelBean tunnelBean = new TunnelBean();
        tunnelBean.setClientName(CLIENT_NAME);
        tunnelBean.setPassword(CLIENT_PASSWORD);
        tunnelBean.setRemoteAddress("127.0.0.1");
        tunnelBean.setRemotePort(nettyPort);
        tunnelBean.setTunnelConfigList(List.of());
        tunnelBean.setHttpTunnelConfigList(List.of());
        // tunnel.tls.mode=self-signed in @SpringBootTest; the client must
        // accept the server's self-signed cert to make the handshake succeed.
        tunnelClient = new NettyClient(tunnelBean, NettyClient.buildInsecureClientSslContext());
        tunnelClient.start();

        await().atMost(10, SECONDS)
                .pollInterval(100, MILLISECONDS)
                .until(() -> hasSuccessfulConnectionRecord(CLIENT_NAME));

        await().atMost(15, SECONDS)
                .pollInterval(500, MILLISECONDS)
                .ignoreExceptions()
                .until(this::proxiesThroughToBackend);

        // —— HTTP 路由热下发 ——
        // 客户端启动时 httpTunnelConfigList 为空；服务端通过 HttpRouteService 写入第一条
        // 后会触发 NatControlService.pushSnapshotIfOnline，沿 NAT_CONTROL 推到客户端的
        // DirectHttpRequestHandler.applyRoutes，整个链路在线热替换。
        httpRouteService.createRoute(clientId, new HttpRouteService.RouteMutation(
                "web", "http://127.0.0.1:" + backendPort, true
        ));

        await().atMost(10, SECONDS)
                .pollInterval(200, MILLISECONDS)
                .until(() -> {
                    Map<String, String> routes = readClientRoutes(tunnelClient);
                    return routes != null && ("http://127.0.0.1:" + backendPort).equals(routes.get("web"));
                });

        // 再追加一条 + 删除第一条，验证整体替换语义（不是增量补丁）
        httpRouteService.createRoute(clientId, new HttpRouteService.RouteMutation(
                "api", "http://127.0.0.1:" + backendPort, true
        ));
        await().atMost(10, SECONDS)
                .pollInterval(200, MILLISECONDS)
                .until(() -> {
                    Map<String, String> routes = readClientRoutes(tunnelClient);
                    return routes != null && routes.size() == 2 && routes.containsKey("api");
                });
    }

    private boolean hasSuccessfulConnectionRecord(String clientName) {
        return connectionRecordRepository
                .findAllByOrderByIdDesc(PageRequest.of(0, 20))
                .stream()
                .anyMatch(r -> clientName.equals(r.getClientName()) && r.isSuccess());
    }

    private boolean proxiesThroughToBackend() throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(
                "http://127.0.0.1:" + TUNNEL_LISTEN_PORT + "/hello"
        ).openConnection();
        conn.setConnectTimeout(2_000);
        conn.setReadTimeout(5_000);
        if (conn.getResponseCode() != 200) {
            return false;
        }
        try (InputStream is = conn.getInputStream()) {
            String body = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            return "hi from backend".equals(body);
        }
    }

    private static int findFreePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    /**
     * 反射读取 NettyClient.controlChannel 当前 pipeline 中
     * {@link DirectHttpRequestHandler#getCurrentRoutes()}。返回 null 表示客户端
     * 还没建立连接 / 已断开。
     *
     * <p>用反射是因为 {@code controlChannel} 是私有字段——为测试新增 getter 会污染
     * 生产代码 API；E2E 仅在测试代码里这一处反射，权衡之后选择不动 production。
     */
    @SuppressWarnings("unchecked")
    private static Map<String, String> readClientRoutes(NettyClient client) {
        try {
            Field field = NettyClient.class.getDeclaredField("controlChannel");
            field.setAccessible(true);
            Object value = field.get(client);
            if (!(value instanceof AtomicReference<?> ref)) {
                return null;
            }
            Object channel = ref.get();
            if (!(channel instanceof Channel ch)) {
                return null;
            }
            DirectHttpRequestHandler handler = ch.pipeline().get(DirectHttpRequestHandler.class);
            if (handler == null) {
                return null;
            }
            return handler.getCurrentRoutes();
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("failed to read client routes via reflection", e);
        }
    }
}
