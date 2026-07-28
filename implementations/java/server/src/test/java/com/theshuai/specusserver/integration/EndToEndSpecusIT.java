package com.theshuai.specusserver.integration;

import com.sun.net.httpserver.HttpServer;
import com.theshuai.common.clientauth.ClientAuthLoginRequest;
import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import com.theshuai.common.clientauth.ClientAuthSigner;
import com.theshuai.common.clientauth.ClientEnvironmentInfo;
import com.theshuai.specusclient.bean.SpecusBean;
import com.theshuai.specusclient.client.NettyClient;
import com.theshuai.specusclient.handler.NatClientHandler;
import com.theshuai.specusserver.SpecusServerApplication;
import com.theshuai.specusserver.management.repository.ConnectionRecordRepository;
import com.theshuai.specusserver.management.service.ClientAuthService;
import com.theshuai.specusserver.management.service.ClientCredentialService;
import com.theshuai.specusserver.management.service.HttpRouteService;
import com.theshuai.specusserver.management.service.NatControlService;
import com.theshuai.specusserver.management.tenant.TenantContext;
import com.theshuai.specusserver.server.NettyServer;
import io.netty.channel.Channel;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;
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
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/**
 * Full-stack end-to-end test:
 *   Spring Boot server (in-memory SQLite, random netty port)
 *     + an in-process mock HTTP backend
 *     + a real NettyClient connecting with HTTP-issued access token
 *     + a specus mapping registered via NatControlService
 *   then verify that an HTTP request to the server's public port is proxied
 *   all the way through to the mock backend and the body comes back intact.
 */
@SpringBootTest(
        classes = SpecusServerApplication.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                // SQLite `:memory:` gives every JDBC connection its own private
                // database, so the JPA transaction in the netty event loop
                // thread sees an empty DB (and the query returns `[null]`).
                // `cache=shared` lets HikariCP connections share the in-memory DB.
                "spring.datasource.url=jdbc:sqlite:file:target/test-e2e?mode=memory&cache=shared",
                "spring.jpa.database-platform=org.hibernate.community.dialect.SQLiteDialect",
                "spring.jpa.hibernate.ddl-auto=create-drop",
                "specus.netty.port=0",
                "specus.public-address=127.0.0.1",
                "specus.database.seed-demo-client=false",
                "specus.tls.mode=disabled"
        }
)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class EndToEndSpecusIT {

    private static final String API_KEY = "e2e-client";
    private static final String API_SECRET = "e2e-secret";
    private static final int SPECUS_LISTEN_PORT = 19_000;

    @Autowired private ClientCredentialService clientCredentialService;
    @Autowired private ClientAuthService clientAuthService;
    @Autowired private NatControlService natControlService;
    @Autowired private HttpRouteService httpRouteService;
    @Autowired private NettyServer nettyServer;
    @Autowired private ConnectionRecordRepository connectionRecordRepository;
    @LocalServerPort private int httpPort;

    private static HttpServer mockBackend;
    private static int backendPort;
    private NettyClient specusClient;

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
        mockBackend.createContext("/fragmented", exchange -> {
            byte[] chunk = new byte[4 * 1024];
            java.util.Arrays.fill(chunk, (byte) 0x5a);
            int chunks = 256;
            exchange.sendResponseHeaders(200, (long) chunk.length * chunks);
            for (int index = 0; index < chunks; index++) {
                exchange.getResponseBody().write(chunk);
                exchange.getResponseBody().flush();
            }
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
    void shutdownSpecusClient() {
        if (specusClient != null) {
            specusClient.shutdown();
            specusClient = null;
        }
    }

    @Test
    @Order(1)
    void shouldAuthenticateAndSpecusHttpTraffic() throws Exception {
        int nettyPort = nettyServer.getBoundPort();
        assertThat(nettyPort)
                .as("Netty server should have bound a real port")
                .isGreaterThan(0);

        clientCredentialService.create(TenantContext.defaultTenant(), new ClientCredentialService.CredentialMutation(
                API_KEY, API_SECRET, true, 2
        ));
        ClientAuthLoginResponse login = clientAuthService.login(apiKeyLoginRequest(), "127.0.0.1");
        Long clientId = login.getClientId();
        String clientName = login.getClientName();

        httpRouteService.createRoute(clientId, new HttpRouteService.RouteMutation(
                "web", "http://127.0.0.1:" + backendPort, true
        ));

        SpecusBean specusBean = new SpecusBean();
        specusBean.setClientName(clientName);
        specusBean.setClientSessionId(login.getClientSessionId());
        specusBean.setAccessToken(login.getAccessToken());
        specusBean.setRemoteAddress("127.0.0.1");
        specusBean.setRemotePort(nettyPort);
        specusBean.setSpecusConfigList(List.of());
        specusBean.setHttpSpecusConfigList(List.of());
        specusClient = new NettyClient(specusBean);
        specusClient.start();

        await().atMost(10, SECONDS)
                .pollInterval(100, MILLISECONDS)
                .until(() -> hasSuccessfulConnectionRecord(clientName));

        await().atMost(10, SECONDS)
                .pollInterval(200, MILLISECONDS)
                .until(() -> {
                    Map<String, String> routes = readClientRoutes(specusClient);
                    return routes != null && ("http://127.0.0.1:" + backendPort).equals(routes.get("web"));
                });

        // No TCP mapping has been registered yet. HTTP stream DATA must still be accepted on
        // the authenticated DATA connection, including a full 1 MiB window split into small chunks.
        await().atMost(15, SECONDS)
                .pollInterval(500, MILLISECONDS)
                .ignoreExceptions()
                .until(() -> proxiesFragmentedHttpRoute(clientName));

        natControlService.createMapping(clientId, new NatControlService.MappingMutation(
                SPECUS_LISTEN_PORT, "127.0.0.1", backendPort, true
        ));
        await().atMost(15, SECONDS)
                .pollInterval(500, MILLISECONDS)
                .ignoreExceptions()
                .until(this::proxiesThroughToBackend);

        // Add another route after login to verify online hot replacement semantics.
        httpRouteService.createRoute(clientId, new HttpRouteService.RouteMutation(
                "api", "http://127.0.0.1:" + backendPort, true
        ));
        await().atMost(10, SECONDS)
                .pollInterval(200, MILLISECONDS)
                .until(() -> {
                    Map<String, String> routes = readClientRoutes(specusClient);
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
                "http://127.0.0.1:" + SPECUS_LISTEN_PORT + "/hello"
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

    private boolean proxiesFragmentedHttpRoute(String clientName) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(
                "http://127.0.0.1:" + httpPort + "/http/" + clientName + "/web/fragmented"
        ).openConnection();
        conn.setConnectTimeout(2_000);
        conn.setReadTimeout(10_000);
        if (conn.getResponseCode() != 200) {
            return false;
        }
        try (InputStream input = conn.getInputStream()) {
            byte[] body = input.readAllBytes();
            return body.length == 1024 * 1024
                    && body[0] == (byte) 0x5a
                    && body[body.length - 1] == (byte) 0x5a;
        }
    }

    private static int findFreePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    /**
     * 反射读取 NettyClient.dataChannel 当前 pipeline 中
     * NatClientHandler 的当前路由。返回 null 表示客户端还没建立连接 / 已断开。
     *
     * <p>用反射是因为 {@code controlChannel} 是私有字段——为测试新增 getter 会污染
     * 生产代码 API。
     */
    private static Map<String, String> readClientRoutes(NettyClient client) {
        try {
            Field field = NettyClient.class.getDeclaredField("dataChannel");
            field.setAccessible(true);
            Object value = field.get(client);
            if (!(value instanceof AtomicReference<?> ref)) {
                return null;
            }
            Object channel = ref.get();
            if (!(channel instanceof Channel ch)) {
                return null;
            }
            NatClientHandler handler = ch.pipeline().get(NatClientHandler.class);
            if (handler == null) {
                return null;
            }
            var routesField = NatClientHandler.class.getDeclaredField("httpRoutes");
            routesField.setAccessible(true);
            Object routes = routesField.get(handler);
            return routes instanceof Map<?, ?> map
                    ? map.entrySet().stream().collect(java.util.stream.Collectors.toUnmodifiableMap(
                            entry -> String.valueOf(entry.getKey()),
                            entry -> String.valueOf(entry.getValue())))
                    : null;
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("failed to read client routes via reflection", e);
        }
    }

    private static ClientAuthLoginRequest apiKeyLoginRequest() {
        ClientEnvironmentInfo environment = new ClientEnvironmentInfo();
        environment.setMachineFingerprint("e2e-machine-" + UUID.randomUUID());
        environment.setHostname("e2e-host");
        environment.setOsUser("e2e-user");
        environment.setOsName("JUnit");
        environment.setOsVersion("1");
        environment.setOsArch("test");
        environment.setJavaVersion(System.getProperty("java.version", ""));
        environment.setStartedAt("2026-06-22T00:00:00Z");

        String timestamp = String.valueOf(System.currentTimeMillis());
        String nonce = UUID.randomUUID().toString().replace("-", "");
        ClientAuthLoginRequest request = new ClientAuthLoginRequest();
        request.setApiKey(API_KEY);
        request.setTimestamp(timestamp);
        request.setNonce(nonce);
        request.setEnvironment(environment);
        request.setSignature(ClientAuthSigner.signApiKey(API_KEY, timestamp, nonce, environment, API_SECRET));
        return request;
    }

}
