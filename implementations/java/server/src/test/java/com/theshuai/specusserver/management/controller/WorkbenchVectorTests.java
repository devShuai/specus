package com.theshuai.specusserver.management.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.LongNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.model.ManagementRole;
import com.theshuai.specusserver.management.service.HttpRouteService;
import com.theshuai.specusserver.management.service.ManagementUserService;
import com.theshuai.specusserver.management.service.NatControlService;
import com.theshuai.specusserver.management.service.PeerServiceDiscoveryService;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.IOException;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Replays every scenario and step of {@code protocol/test-vectors/service-workbench-v1.json} through
 * the real HTTP stack (protocol/spec/service-workbench.md section 14).
 *
 * <p>Each scenario starts from an empty store: the vector's accounts are created through the account
 * management, its objects inserted with their exact ids (one client per object, owned by the
 * object's owner), its rows written straight into the workbench table and the limiter emptied. API
 * steps go over HTTP with the bearer token of {@code as} and the workbench clock at
 * {@code baseTime + atMs}; status, Retry-After and the whole 200 body (times as instants) must match,
 * an error only by code. {@code sessionRejected} uses the token issued before the account was
 * deleted and must be refused without writing. Events go through the existing delete and account
 * paths, fixtures for create-object/change-owner, a moved-away table for store-down/store-up and the
 * sweep method for sweep. Afterwards the stored rows must equal {@code rowsAfter}.
 */
class WorkbenchVectorTests extends WorkbenchHttpTestSupport {
    private static final String VECTOR = "protocol/test-vectors/service-workbench-v1.json";
    private static final Pattern STAMP = Pattern.compile("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z");

    @Autowired private HttpRouteService httpRouteService;
    @Autowired private NatControlService natControlService;
    @Autowired private PeerServiceDiscoveryService peerServiceDiscoveryService;

    private int scenariosReplayed;
    private int stepsReplayed;

    @TestFactory
    List<DynamicTest> everyScenarioOfTheSharedVector() throws IOException {
        JsonNode vector = readVector();
        assertThat(vector.path("baseTime").asText()).isEqualTo(BASE_TIME.toString());
        List<DynamicTest> tests = new ArrayList<>();
        int scenarios = vector.path("scenarios").size();
        int steps = 0;
        for (JsonNode scenario : vector.path("scenarios")) {
            steps += scenario.path("steps").size();
            tests.add(DynamicTest.dynamicTest(scenario.path("name").asText(), () -> replay(scenario)));
        }
        int expectedSteps = steps;
        assertThat(scenarios).isEqualTo(15);
        assertThat(expectedSteps).isEqualTo(150);
        tests.add(DynamicTest.dynamicTest("every scenario and step was replayed", () -> {
            assertThat(scenariosReplayed).isEqualTo(scenarios);
            assertThat(stepsReplayed).isEqualTo(expectedSteps);
        }));
        return tests;
    }

    private void replay(JsonNode scenario) {
        String name = scenario.path("name").asText();
        freshState();
        try {
            Map<String, String> tokens = new HashMap<>();
            Map<String, ClientAccount> clientOf = new HashMap<>();
            for (JsonNode user : scenario.path("users")) {
                String tenantId = user.path("tenantId").asText();
                String username = user.path("username").asText();
                tokens.put(identity(tenantId, username), createUser(tenantId, username, user.path("admin").asBoolean()));
            }
            for (JsonNode object : scenario.path("objects")) {
                createVectorObject(object, clientOf);
            }
            for (JsonNode row : scenario.path("rows")) {
                insertRow(row.path("tenantId").asText(), row.path("username").asText(), row.path("list").asText(),
                        row.path("kind").asText(), row.path("id").asLong(), row.path("atMs").asLong());
            }
            int index = 0;
            for (JsonNode step : scenario.path("steps")) {
                String label = name + " step " + index++;
                at(step.path("atMs").asLong());
                if (step.has("event")) {
                    event(step, tokens, clientOf);
                } else {
                    call(label, step, tokens);
                }
                stepsReplayed++;
            }
            assertThat(rows()).as(name + " rowsAfter").isEqualTo(expectedRows(scenario.path("rowsAfter")));
            scenariosReplayed++;
        } finally {
            storeUp();
        }
    }

    private void call(String label, JsonNode step, Map<String, String> tokens) {
        JsonNode as = step.path("as");
        String token = as.isNull() ? null : tokens.get(identity(as.path("tenantId").asText(), as.path("username").asText()));
        assertThat(as.isNull() || token != null).as(label + " token").isTrue();
        String method = step.path("method").asText();
        String path = step.path("path").asText();
        JsonNode expect = step.path("expect");

        if (expect.path("sessionRejected").asBoolean()) {
            List<Row> before = rows();
            HttpResponse<String> response = send(method, path, token);
            assertThat(response.statusCode() / 100)
                    .as(label + " sessionRejected status " + response.statusCode()).isNotEqualTo(2);
            assertThat(rows()).as(label + " sessionRejected wrote nothing").isEqualTo(before);
            return;
        }

        HttpResponse<String> response = send(method, path, token);
        int status = expect.path("httpStatus").asInt();
        assertThat(response.statusCode()).as(label + " " + method + " " + path + " -> " + response.body())
                .isEqualTo(status);
        if (status != 401) {
            assertThat(response.headers().firstValue("Cache-Control")).as(label + " Cache-Control")
                    .hasValue("private, no-store");
        }
        if (expect.has("retryAfterSeconds")) {
            assertThat(response.headers().firstValue("Retry-After")).as(label + " Retry-After")
                    .hasValue(Long.toString(expect.path("retryAfterSeconds").asLong()));
        }
        if (status == 200) {
            JsonNode actual = json(response);
            assertTimesAreStamps(label, actual);
            assertThat(withInstants(actual)).as(label + " body " + response.body())
                    .isEqualTo(withInstants(expect.path("body")));
        } else if (expect.path("body").has("code")) {
            assertThat(json(response).path("code").asText()).as(label + " code")
                    .isEqualTo(expect.path("body").path("code").asText());
        }
    }

    private void event(JsonNode step, Map<String, String> tokens, Map<String, ClientAccount> clientOf) {
        String name = step.path("event").asText();
        switch (name) {
            case "delete-object" -> {
                String kind = step.path("kind").asText();
                long id = step.path("id").asLong();
                ClientAccount client = clientOf.get(objectKey(kind, id));
                var admin = tenantAdmin(client.getTenantId());
                switch (kind) {
                    case "http-route" -> httpRouteService.deleteRoute(admin, id);
                    case "tcp-mapping" -> natControlService.deleteMapping(admin, id);
                    case "peer-service" -> peerServiceDiscoveryService.deleteService(admin, id);
                    default -> throw new IllegalArgumentException(kind);
                }
                clientOf.remove(objectKey(kind, id));
            }
            case "create-object" -> createVectorObject(step, clientOf);
            case "change-owner" -> {
                ClientAccount client = clientOf.get(objectKey(step.path("kind").asText(), step.path("id").asLong()));
                client.setOwnerUsername(step.path("ownerUsername").asText());
                clientAccountRepository.saveAndFlush(client);
            }
            case "set-admin" -> managementUserService.updateUser(tenantAdmin(step.path("tenantId").asText()),
                    step.path("username").asText(), new ManagementUserService.UserMutation(null, null,
                            step.path("admin").asBoolean() ? ManagementRole.ADMIN : ManagementRole.USER, null));
            case "create-user" -> {
                String tenantId = step.path("tenantId").asText();
                String username = step.path("username").asText();
                tokens.put(identity(tenantId, username), createUser(tenantId, username, step.path("admin").asBoolean()));
            }
            // The token issued before the deletion stays in the map: sessionRejected replays it.
            case "delete-user" -> managementUserService.deleteUser(
                    tenantAdmin(step.path("tenantId").asText()), step.path("username").asText());
            case "store-down" -> storeDown();
            case "store-up" -> storeUp();
            case "sweep" -> workbenchService.sweepExpiredRecents();
            default -> throw new IllegalArgumentException("unknown event " + name);
        }
    }

    /** One client per object, owned by the object's owner, so an owner change touches only that object. */
    private void createVectorObject(JsonNode object, Map<String, ClientAccount> clientOf) {
        String kind = object.path("kind").asText();
        long id = object.path("id").asLong();
        ClientAccount client = createClient(object.path("tenantId").asText(), object.path("ownerUsername").asText());
        createObject(kind, id, client);
        clientOf.put(objectKey(kind, id), client);
    }

    private static List<Row> expectedRows(JsonNode rowsAfter) {
        assertThat(rowsAfter.isArray()).as("rowsAfter").isTrue();
        List<Row> rows = new ArrayList<>();
        for (JsonNode row : rowsAfter) {
            rows.add(new Row(row.path("tenantId").asText(), row.path("username").asText(), row.path("list").asText(),
                    row.path("kind").asText(), row.path("id").asLong(), row.path("atMs").asLong()));
        }
        rows.sort(ROW_ORDER);
        return rows;
    }

    private static void assertTimesAreStamps(String label, JsonNode body) {
        for (JsonNode entry : body.path("favorites")) {
            assertThat(entry.path("addedAt").asText()).as(label + " addedAt format").matches(STAMP);
        }
        for (JsonNode entry : body.path("recents")) {
            assertThat(entry.path("visitedAt").asText()).as(label + " visitedAt format").matches(STAMP);
        }
    }

    /** The document with addedAt/visitedAt replaced by epoch milliseconds: times compare as instants. */
    private static JsonNode withInstants(JsonNode body) {
        JsonNode copy = body.deepCopy();
        for (String list : List.of("favorites", "recents")) {
            for (JsonNode entry : copy.path(list)) {
                for (String field : List.of("addedAt", "visitedAt")) {
                    if (entry.has(field)) {
                        ((ObjectNode) entry).set(field,
                                LongNode.valueOf(Instant.parse(entry.path(field).asText()).toEpochMilli()));
                    }
                }
            }
        }
        return copy;
    }

    private static String identity(String tenantId, String username) {
        return tenantId + "\n" + username;
    }

    private static String objectKey(String kind, long id) {
        return kind + "/" + id;
    }

    private static JsonNode readVector() throws IOException {
        Path current = Path.of("").toAbsolutePath();
        for (int depth = 0; current != null && depth < 8; depth++, current = current.getParent()) {
            Path candidate = current.resolve(VECTOR);
            if (Files.isRegularFile(candidate)) {
                return JSON.readTree(Files.readString(candidate));
            }
        }
        throw new IllegalStateException("cannot locate " + VECTOR);
    }
}
