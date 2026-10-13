package com.theshuai.specusserver.http;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.common.clientauth.ClientAuthLoginRequest;
import com.theshuai.common.clientauth.ClientAuthSigner;
import com.theshuai.common.clientauth.ClientEnvironmentInfo;
import com.theshuai.common.util.JsonUtil;
import com.theshuai.specusserver.management.model.ManagementRole;
import com.theshuai.specusserver.management.model.ManagementUser;
import com.theshuai.specusserver.management.repository.ClientSessionRepository;
import com.theshuai.specusserver.management.repository.ManagementUserRepository;
import com.theshuai.specusserver.management.service.ClientAuthService;
import com.theshuai.specusserver.management.tenant.TenantContext;
import com.theshuai.specusserver.security.LocalTokenService;
import com.theshuai.specusserver.server.NettyServer;
import com.theshuai.specusserver.session.SessionUtil;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Replays every {@code server.scenarios} entry of {@code protocol/test-vectors/http-route-lifecycle-v1.json}
 * against the running server: the admin REST API for every management operation, the public
 * {@code /http/{client}/{route}/**} entry over real HTTP (WebSocket upgrades over a raw socket, since
 * the JDK clients refuse to send the upgrade headers), and a {@link FakeTunnelClient} logged in over
 * real TCP through the production Netty pipeline, so the login push comes from
 * {@code ManagedLoginRequestHandler} calling {@code NatControlService.pushOnLogin}.
 *
 * <p>Scenarios share this server, so each one starts from a fresh state of its own instead: a new
 * API credential and a new client account with no routes, nothing another scenario touches. The
 * account comes from the real HTTP client login with that credential, the only way to obtain the
 * access token a Netty login needs, so its name is the one the server generates. Every
 * {@code connect} and {@code reconnect} reuses that token without a new HTTP login, as the Java
 * client does when it reconnects: the login push is then the only way the client learns what changed
 * while it was away.
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "spring.datasource.url=jdbc:sqlite::memory:",
                "spring.jpa.database-platform=org.hibernate.community.dialect.SQLiteDialect",
                "spring.jpa.hibernate.ddl-auto=create-drop",
                "specus.netty.port=0",
                "specus.database.seed-demo-client=false",
                "specus.client-packages.github-release-fallback-enabled=false",
                "specus.env=test",
                "specus.auth.username=root-operator",
                "specus.auth.password=root-operator-password"
        }
)
class HttpRouteLifecycleVectorTests {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final JsonNode VECTOR = readVector();
    private static final String TENANT = TenantContext.DEFAULT_TENANT_ID;
    private static final String ADMIN = "route-lifecycle-admin";
    private static final Duration WAIT = Duration.ofSeconds(5);

    @Value("${local.server.port}")
    private int port;

    @Autowired private NettyServer nettyServer;
    @Autowired private ManagementUserRepository userRepository;
    @Autowired private ClientSessionRepository sessionRepository;
    @Autowired private LocalTokenService tokens;

    private final HttpClient http = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();

    @TestFactory
    Stream<DynamicTest> serverScenarios() {
        return StreamSupport.stream(VECTOR.path("server").path("scenarios").spliterator(), false)
                .map(scenario -> DynamicTest.dynamicTest(scenario.get("id").asText(), () -> replay(scenario)));
    }

    private void replay(JsonNode scenario) throws Exception {
        try (Scenario run = new Scenario(scenario.get("id").asText())) {
            int index = 0;
            for (JsonNode step : scenario.get("steps")) {
                String label = scenario.get("id").asText() + " step #" + index++ + " (" + step.get("op").asText() + ")";
                try {
                    run.apply(step);
                } catch (AssertionError | Exception failure) {
                    throw new AssertionError(label + ": " + failure.getMessage(), failure);
                }
            }
        }
    }

    /** The state of one scenario: its credential, the current account, and the fake client. */
    private final class Scenario implements AutoCloseable {
        private final String adminToken;
        private final AtomicInteger opens = new AtomicInteger();
        private final Map<String, Long> routeIds = new HashMap<>();
        private final Map<String, Boolean> routeAuth = new HashMap<>();
        private final long clientSessionId;
        private final String accessToken;
        private long clientId;
        private String clientName;
        private String formerName;
        /** The name the last connect logged in with; reconnect presents the token under it again. */
        private String connectedName;
        private FakeTunnelClient client;

        Scenario(String id) throws Exception {
            ensureAdmin();
            adminToken = tokens.issueToken(ADMIN, TENANT, ManagementRole.ADMIN);
            JsonNode credential = ok(201, send("POST", "/api/admin/client-credentials",
                    "{\"enabled\":true,\"maxOnlineInstances\":2}", adminToken));
            JsonNode login = ok(200, send("POST", "/api/client/auth/login", JsonUtil.objectToString(
                    loginRequest(id, credential.get("credential").get("apiKey").asText(),
                            credential.get("secret").asText())), null));
            clientId = login.get("clientId").asLong();
            clientName = login.get("clientName").asText();
            clientSessionId = login.get("clientSessionId").asLong();
            accessToken = login.get("accessToken").asText();
        }

        void apply(JsonNode step) throws Exception {
            switch (step.get("op").asText()) {
                case "createRoute" -> createRoute(step);
                case "setRouteEnabled" -> setRouteEnabled(step);
                case "deleteRoute" -> deleteRoute(step);
                case "setClientEnabled" -> mutateClient(
                        "{\"enabled\":" + step.get("enabled").asBoolean() + "}", step);
                case "renameClient" -> {
                    String renamed = clientName + step.get("suffix").asText();
                    mutateClient(JSON.createObjectNode().put("clientName", renamed).toString(), step);
                    formerName = clientName;
                    clientName = renamed;
                }
                case "deleteClient" -> deleteClient(step);
                case "createClient" -> createClient();
                case "createFormerNameClient" -> createFormerNameClient(step);
                case "connect" -> connect(step);
                case "reconnect" -> reconnect(step);
                case "disconnect" -> disconnect();
                case "request" -> request(step);
                default -> throw new IllegalArgumentException("unknown op " + step.get("op").asText());
            }
        }

        private void createRoute(JsonNode step) throws Exception {
            String route = step.get("route").asText();
            boolean auth = step.get("auth").asBoolean();
            JsonNode credentials = VECTOR.get("basicCredentials");
            var body = JSON.createObjectNode()
                    .put("route", route)
                    .put("targetBaseUrl", VECTOR.get("targetBaseUrl").asText())
                    .put("enabled", true)
                    .put("authEnabled", auth);
            if (auth) {
                body.put("authUsername", credentials.get("username").asText())
                        .put("authPassword", credentials.get("password").asText());
            }
            int pushes = pushCount();
            JsonNode created = ok(201, send("POST", "/api/admin/clients/" + clientId + "/http-routes",
                    body.toString(), adminToken));
            routeIds.put(route, created.get("id").asLong());
            routeAuth.put(route, auth);
            expectPush(step, pushes);
        }

        private void setRouteEnabled(JsonNode step) throws Exception {
            String route = step.get("route").asText();
            String body = JSON.createObjectNode()
                    .put("route", route)
                    .put("targetBaseUrl", VECTOR.get("targetBaseUrl").asText())
                    .put("enabled", step.get("enabled").asBoolean())
                    .toString();
            int pushes = pushCount();
            ok(200, send("PUT", "/api/admin/http-routes/" + routeId(route), body, adminToken));
            expectPush(step, pushes);
        }

        private void deleteRoute(JsonNode step) throws Exception {
            String route = step.get("route").asText();
            int pushes = pushCount();
            ok(204, send("DELETE", "/api/admin/http-routes/" + routeId(route), null, adminToken));
            routeIds.remove(route);
            expectPush(step, pushes);
        }

        private void mutateClient(String body, JsonNode step) throws Exception {
            ok(200, send("PUT", "/api/admin/clients/" + clientId, body, adminToken));
            expectSessionClosed(step);
        }

        private void deleteClient(JsonNode step) throws Exception {
            ok(204, send("DELETE", "/api/admin/clients/" + clientId, null, adminToken));
            routeIds.clear();
            expectSessionClosed(step);
        }

        private void createClient() throws Exception {
            JsonNode created = ok(201, send("POST", "/api/admin/clients",
                    JSON.createObjectNode().put("clientName", clientName).toString(), adminToken));
            clientId = created.get("client").get("id").asLong();
            assertThat(created.get("client").get("clientName").asText()).isEqualTo(clientName);
        }

        /** Another account under the name before the last rename, with these routes; it never logs in. */
        private void createFormerNameClient(JsonNode step) throws Exception {
            assertThat(formerName).as("an earlier renameClient").isNotNull();
            JsonNode created = ok(201, send("POST", "/api/admin/clients",
                    JSON.createObjectNode().put("clientName", formerName).toString(), adminToken));
            long id = created.get("client").get("id").asLong();
            assertThat(id).as("a new account").isNotEqualTo(clientId);
            for (JsonNode route : step.get("routes")) {
                ok(201, send("POST", "/api/admin/clients/" + id + "/http-routes", JSON.createObjectNode()
                        .put("route", route.asText())
                        .put("targetBaseUrl", VECTOR.get("targetBaseUrl").asText())
                        .put("enabled", true)
                        .put("authEnabled", false)
                        .toString(), adminToken));
            }
        }

        private void connect(JsonNode step) throws Exception {
            assertThat(client).as("the fake client is offline before connect").isNull();
            client = connectFakeClient(clientName);
            connectedName = clientName;
            assertRoutes("login push", awaitPush(0), step.get("expectLoginPush"));
        }

        /** The token of the last connect again, under the name it logged in with then. */
        private void reconnect(JsonNode step) throws Exception {
            assertThat(client).as("the fake client is offline before reconnect").isNull();
            assertThat(connectedName).as("an earlier connect").isNotNull();
            if (step.get("expectRefused").asBoolean()) {
                var answer = FakeTunnelClient.controlLoginAnswer(nettyServer.getBoundPort(), connectedName,
                        clientSessionId, accessToken);
                assertThat(answer.isSuccess()).as("the token of " + connectedName + " logged in again as "
                        + answer.getClientName()).isFalse();
                return;
            }
            client = connectFakeClient(connectedName);
            assertThat(client.controlLoginName()).as("the name the control login answered with")
                    .isEqualTo(clientName);
            assertRoutes("login push", awaitPush(0), step.get("expectLoginPush"));
        }

        private FakeTunnelClient connectFakeClient(String loginName) throws Exception {
            JsonNode answer = VECTOR.get("fakeClientResponse");
            List<String> headers = new ArrayList<>();
            answer.get("headers").forEach(header -> headers.add(header.asText()));
            return FakeTunnelClient.connect(nettyServer.getBoundPort(), loginName, clientSessionId, accessToken,
                    opens, new FakeTunnelClient.Response(
                            answer.get("status").asInt(), headers, answer.get("body").asText()));
        }

        private void disconnect() {
            assertThat(client).as("the fake client is online").isNotNull();
            client.close();
            client = null;
            // Offline as the server sees it: sessions unbound and the client session closed, so the
            // next login is not raced by the disconnect bookkeeping of this one.
            awaitTrue("the server has the client offline", () -> SessionUtil.getChannel(clientName) == null
                    && SessionUtil.getDataChannel(clientName) == null
                    && sessionRepository.findById(clientSessionId)
                    .map(session -> !ClientAuthService.STATUS_NETTY_ONLINE.equals(session.getStatus()))
                    .orElse(true));
        }

        private void request(JsonNode step) throws Exception {
            String name = "former".equals(step.path("client").asText("current")) ? formerName : clientName;
            JsonNode route = step.get("route");
            String path = "/http/" + encode(name) + "/"
                    + (route == null || route.isNull() ? "" : encode(route.asText()) + step.path("path").asText(""));
            String authorization = switch (step.path("credentials").asText("none")) {
                case "none" -> null;
                case "valid" -> basic(VECTOR.get("basicCredentials").get("password").asText());
                case "wrong" -> basic("wrong");
                default -> throw new IllegalArgumentException("unknown credentials " + step.get("credentials"));
            };
            boolean websocket = step.path("websocket").asBoolean(false);
            int opensBefore = opens.get();
            Reply reply = websocket ? upgrade(path, authorization) : get(path, authorization);

            JsonNode expect = step.get("expect");
            String described = "GET " + path + (websocket ? " (WebSocket)" : "") + " -> " + reply.status()
                    + " " + reply.body();
            if (expect.has("status")) {
                assertThat(reply.status()).as(described).isEqualTo(expect.get("status").asInt());
            }
            if (expect.has("statusAnyOf")) {
                List<Integer> allowed = new ArrayList<>();
                expect.get("statusAnyOf").forEach(status -> allowed.add(status.asInt()));
                assertThat(reply.status()).as(described).isIn(allowed);
            }
            if (websocket) {
                assertThat(reply.status()).as(described).isNotEqualTo(101);
            }
            if (expect.path("noStore").asBoolean(false)) {
                assertThat(reply.header("Cache-Control")).as(described).contains("no-store");
            }
            if (expect.path("basicChallenge").asBoolean(false)) {
                assertThat(reply.header("WWW-Authenticate")).as(described).startsWith("Basic");
            }
            if (expect.has("body")) {
                assertThat(reply.body()).as(described).isEqualTo(expect.get("body").asText());
            }
            if (expect.has("forwarded")) {
                assertThat(opens.get() > opensBefore).as("forwarded to the client: " + described)
                        .isEqualTo(expect.get("forwarded").asBoolean());
            }
        }

        private void expectPush(JsonNode step, int pushesBefore) {
            JsonNode expected = step.get("expectPush");
            if (expected == null || expected.isNull()) {
                return;
            }
            assertThat(client).as("the fake client is online to receive the push").isNotNull();
            assertRoutes("push", awaitPush(pushesBefore), expected);
        }

        private void expectSessionClosed(JsonNode step) throws InterruptedException {
            if (!step.path("expectSessionClosed").asBoolean(false)) {
                return;
            }
            assertThat(client).as("the fake client is online").isNotNull();
            assertThat(client.awaitClosed(WAIT)).as("control and data connections closed within " + WAIT).isTrue();
            client.close();
            client = null;
        }

        private int pushCount() {
            return client == null ? 0 : client.natControls().size();
        }

        private JsonNode awaitPush(int index) {
            awaitTrue("NAT_CONTROL #" + index, () -> client.natControls().size() > index);
            return client.natControls().get(index);
        }

        private long routeId(String route) {
            Long id = routeIds.get(route);
            assertThat(id).as("route " + route + " was created").isNotNull();
            return id;
        }

        private String basic(String password) {
            String user = VECTOR.get("basicCredentials").get("username").asText();
            return "Basic " + Base64.getEncoder().encodeToString(
                    (user + ":" + password).getBytes(StandardCharsets.UTF_8));
        }

        @Override
        public void close() {
            if (client != null) {
                client.close();
            }
        }
    }

    private static void assertRoutes(String what, JsonNode natControl, JsonNode expected) {
        JsonNode list = natControl.get("httpSpecusConfigList");
        assertThat(list).as(what + " carries httpSpecusConfigList: " + natControl).isNotNull();
        assertThat(list.isArray()).as(what + " httpSpecusConfigList is an array: " + natControl).isTrue();
        Set<String> actual = new HashSet<>();
        list.forEach(route -> actual.add(route.get("route").asText()));
        Set<String> wanted = new HashSet<>();
        expected.forEach(route -> wanted.add(route.asText()));
        assertThat(actual).as(what + " route names: " + natControl).isEqualTo(wanted);
    }

    private static void awaitTrue(String what, BooleanSupplier condition) {
        long deadline = System.nanoTime() + WAIT.toNanos();
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("timed out after " + WAIT + " waiting for " + what);
            }
            try {
                Thread.sleep(20);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new AssertionError("interrupted waiting for " + what, interrupted);
            }
        }
    }

    // ---------------------------------------------------------------------------------------------

    /** A public-entry response: status, case-insensitive headers and body. */
    private record Reply(int status, Map<String, List<String>> headers, String body) {
        String header(String name) {
            List<String> values = headers.get(name);
            return values == null || values.isEmpty() ? "" : String.join(", ", values);
        }
    }

    private Reply get(String path, String authorization) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri(path)).GET();
        if (authorization != null) {
            builder.header("Authorization", authorization);
        }
        HttpResponse<String> response = http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        Map<String, List<String>> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        headers.putAll(response.headers().map());
        return new Reply(response.statusCode(), headers, response.body());
    }

    /** A WebSocket upgrade request with valid handshake headers, over a plain socket. */
    private Reply upgrade(String path, String authorization) throws IOException {
        byte[] key = new byte[16];
        ThreadLocalRandom.current().nextBytes(key);
        StringBuilder request = new StringBuilder()
                .append("GET ").append(path).append(" HTTP/1.1\r\n")
                .append("Host: 127.0.0.1:").append(port).append("\r\n")
                .append("Upgrade: websocket\r\n")
                .append("Connection: Upgrade\r\n")
                .append("Sec-WebSocket-Key: ").append(Base64.getEncoder().encodeToString(key)).append("\r\n")
                .append("Sec-WebSocket-Version: 13\r\n");
        if (authorization != null) {
            request.append("Authorization: ").append(authorization).append("\r\n");
        }
        request.append("\r\n");
        try (Socket socket = new Socket("127.0.0.1", port)) {
            socket.setSoTimeout((int) WAIT.toMillis());
            OutputStream out = socket.getOutputStream();
            out.write(request.toString().getBytes(StandardCharsets.US_ASCII));
            out.flush();
            InputStream in = new BufferedInputStream(socket.getInputStream());
            int status = Integer.parseInt(readLine(in).split(" ", 3)[1]);
            Map<String, List<String>> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            for (String line = readLine(in); !line.isEmpty(); line = readLine(in)) {
                int colon = line.indexOf(':');
                headers.computeIfAbsent(line.substring(0, colon).trim(), name -> new ArrayList<>())
                        .add(line.substring(colon + 1).trim());
            }
            return new Reply(status, headers, status == 101 ? "" : readBody(in, headers));
        }
    }

    private static String readBody(InputStream in, Map<String, List<String>> headers) throws IOException {
        List<String> length = headers.get("Content-Length");
        if (length != null) {
            return new String(in.readNBytes(Integer.parseInt(length.getFirst())), StandardCharsets.UTF_8);
        }
        List<String> encoding = headers.get("Transfer-Encoding");
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        if (encoding != null && encoding.getFirst().equalsIgnoreCase("chunked")) {
            for (int size = Integer.parseInt(readLine(in).split(";")[0].trim(), 16); size > 0;
                 size = Integer.parseInt(readLine(in).split(";")[0].trim(), 16)) {
                body.write(in.readNBytes(size));
                readLine(in);
            }
            return body.toString(StandardCharsets.UTF_8);
        }
        try {
            in.transferTo(body);
        } catch (SocketTimeoutException endOfUndelimitedBody) {
            // Neither length nor chunking, and the connection stays open: what arrived is the body.
        }
        return body.toString(StandardCharsets.UTF_8);
    }

    private static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream line = new ByteArrayOutputStream();
        for (int next = in.read(); next != '\n'; next = in.read()) {
            if (next < 0) {
                throw new IOException("connection closed inside a line");
            }
            if (next != '\r') {
                line.write(next);
            }
        }
        return line.toString(StandardCharsets.ISO_8859_1);
    }

    private HttpResponse<String> send(String method, String path, String body, String bearer) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri(path))
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody()
                        : HttpRequest.BodyPublishers.ofString(body));
        if (body != null) {
            builder.header("Content-Type", "application/json");
        }
        if (bearer != null) {
            builder.header("Authorization", "Bearer " + bearer);
        }
        return http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    /** Asserts the status of a management call and returns its JSON body, or null without one. */
    private static JsonNode ok(int status, HttpResponse<String> response) throws IOException {
        assertThat(response.statusCode()).as(response.request().method() + " " + response.uri().getPath()
                + " -> " + response.body()).isEqualTo(status);
        return response.body().isEmpty() ? null : JSON.readTree(response.body());
    }

    private URI uri(String path) {
        return URI.create("http://127.0.0.1:" + port + path);
    }

    private static String encode(String segment) {
        return URLEncoder.encode(segment, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private void ensureAdmin() {
        if (userRepository.findByTenantIdAndLoginNameNormalized(TENANT, ADMIN).isPresent()) {
            return;
        }
        ManagementUser user = new ManagementUser();
        user.setUsername("account-" + ADMIN);
        user.setLoginName(ADMIN);
        user.setLoginNameNormalized(ADMIN);
        user.setTenantId(TENANT);
        user.setPasswordHash("0".repeat(64));
        user.setRole(ManagementRole.ADMIN);
        user.setEnabled(true);
        user.setCreatedAt(Instant.now().toString());
        user.setUpdatedAt(Instant.now().toString());
        userRepository.save(user);
    }

    /** A signed API-key login as the Java client sends it; the hostname makes the account name. */
    private static ClientAuthLoginRequest loginRequest(String scenarioId, String apiKey, String secret) {
        ClientEnvironmentInfo environment = new ClientEnvironmentInfo();
        environment.setMachineFingerprint("route-lifecycle-" + UUID.randomUUID());
        environment.setHostname(scenarioId);
        environment.setOsUser("vector");
        environment.setOsName("JUnit");
        environment.setOsVersion("1");
        environment.setOsArch("test");
        environment.setJavaVersion(System.getProperty("java.version", ""));
        environment.setStartedAt(Instant.now().toString());
        String timestamp = String.valueOf(System.currentTimeMillis());
        String nonce = UUID.randomUUID().toString().replace("-", "");
        ClientAuthLoginRequest request = new ClientAuthLoginRequest();
        request.setApiKey(apiKey);
        request.setTimestamp(timestamp);
        request.setNonce(nonce);
        request.setEnvironment(environment);
        request.setSignature(ClientAuthSigner.signApiKey(apiKey, timestamp, nonce, environment, secret));
        return request;
    }

    private static JsonNode readVector() {
        Path current = Path.of("").toAbsolutePath();
        for (int depth = 0; current != null && depth < 8; depth++, current = current.getParent()) {
            Path candidate = current.resolve("protocol/test-vectors/http-route-lifecycle-v1.json");
            if (Files.isRegularFile(candidate)) {
                try {
                    return JSON.readTree(Files.readString(candidate, StandardCharsets.UTF_8));
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
            }
        }
        throw new IllegalStateException("cannot locate http-route-lifecycle-v1.json");
    }
}
