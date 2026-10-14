package com.theshuai.specusserver.management.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.tenant.TenantContext;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import static com.theshuai.specusserver.management.service.ClientOwnerTransferPlan.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ClientOwnerTransferPlanTests {
    private final ObjectMapper mapper = new ObjectMapper();
    private final ManagementContext admin = new ManagementContext(new TenantContext("tenant-a"), "admin", true);

    @TestFactory
    Stream<DynamicTest> sharedStructuralVectors() throws Exception {
        JsonNode vector = vector();
        assertThat(vector.path("version").intValue()).isEqualTo(1);
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode scenario : vector.path("cases")) {
            tests.add(DynamicTest.dynamicTest(scenario.path("name").textValue(), () -> {
                ObjectNode input = vector.path("base").deepCopy();
                vector.path("snapshots").path(scenario.path("snapshot").textValue()).fields()
                        .forEachRemaining(entry -> input.set(entry.getKey(), entry.getValue().deepCopy()));
                Snapshot snapshot = mapper.treeToValue(input, Snapshot.class);
                JsonNode before = mapper.valueToTree(snapshot);
                PathScope scope = scope(scenario.path("scope").textValue());
                long id = scenario.path("id").longValue();
                ManagementContext context = new ManagementContext(admin.tenant(), "admin",
                        scenario.path("admin").asBoolean(true));
                JsonNode request = scenario.get("request");
                if (request != null && request.isObject()
                        && "$current".equals(request.path("expectedRevision").asText())) {
                    request = request.deepCopy();
                    ((ObjectNode) request).put("expectedRevision", preview(context, scope, id, snapshot).revision());
                }
                JsonNode finalRequest = request;
                if (scenario.has("error")) {
                    assertThatThrownBy(() -> {
                        if (scenario.has("request")) prepare(context, scope, id, finalRequest, snapshot);
                        else preview(context, scope, id, snapshot);
                    }).isInstanceOfSatisfying(Failure.class, error -> {
                        assertThat(error.status()).isEqualTo(scenario.path("error").path("status").intValue());
                        assertThat(error.code()).isEqualTo(scenario.path("error").path("code").textValue());
                        assertThat(error.getMessage()).isEqualTo(error.code());
                    });
                } else if (scenario.has("preparedTarget")) {
                    Prepared prepared = prepare(context, scope, id, request, snapshot);
                    assertThat(prepared.requestedTargetUsername()).isEqualTo(scenario.path("preparedTarget").textValue());
                    assertThat(prepared.preview().accessRetained()).isTrue();
                } else {
                    Preview actual = preview(context, scope, id, snapshot);
                    JsonNode expected = scenario.path("preview");
                    JsonNode encoded = mapper.valueToTree(actual);
                    for (String field : List.of("clientId", "credentialId")) {
                        assertThat(encoded.get(field).isNull()).as(field).isEqualTo(expected.get(field).isNull());
                        if (!expected.get(field).isNull()) {
                            assertThat(encoded.get(field).longValue()).as(field).isEqualTo(expected.get(field).longValue());
                        }
                    }
                    for (String field : List.of("canTransfer", "conflictCode")) {
                        assertThat(encoded.get(field)).as(field).isEqualTo(expected.get(field));
                    }
                    assertThat(actual.scope()).isEqualTo(scope.wireName);
                    List<Long> expectedIds = new ArrayList<>();
                    expected.path("affectedClientIds").forEach(value -> expectedIds.add(value.longValue()));
                    assertThat(actual.affectedClients().stream().map(AffectedClient::id).toList()).isEqualTo(expectedIds);
                    assertThat(actual.affectedClientCount()).isEqualTo(actual.affectedClients().size());
                    assertThat(actual.revision() != null).isEqualTo(expected.path("hasRevision").booleanValue());
                    assertThat(actual.accessRetained()).isTrue();
                    for (AffectedClient client : actual.affectedClients()) {
                        ClientRow original = snapshot.clients().stream().filter(c -> c.id() == client.id()).findFirst().orElseThrow();
                        assertThat(client.clientName()).isEqualTo(original.clientName());
                        assertThat(client.ownerUsername()).isEqualTo(original.ownerUsername());
                        assertThat(client.enabled()).isEqualTo(original.enabled());
                    }
                    if (actual.credentialId() == null) {
                        assertThat(actual.credentialOwnerUsername()).isNull();
                        assertThat(actual.credentialEnabled()).isNull();
                    } else {
                        CredentialRow credential = snapshot.credentials().stream()
                                .filter(c -> c.id() == actual.credentialId()).findFirst().orElseThrow();
                        assertThat(actual.credentialOwnerUsername()).isEqualTo(credential.ownerUsername());
                        assertThat(actual.credentialEnabled()).isEqualTo(credential.enabled());
                    }
                    assertThat(encoded.toString()).doesNotContain("secret", "token", "fingerprint", "privateKey");
                }
                assertThat(mapper.<JsonNode>valueToTree(snapshot)).isEqualTo(before);
            }));
        }
        assertThat(tests).hasSize(29);
        return tests.stream();
    }

    @TestFactory
    Stream<DynamicTest> everyRelevantChangeInvalidatesRevision() throws Exception {
        ObjectNode base = vector().path("base").deepCopy();
        List<DynamicTest> tests = new ArrayList<>();
        for (String table : List.of("clients", "credentials", "peers")) {
            for (String field : List.of("ownerUsername", "enabled")) {
                tests.add(DynamicTest.dynamicTest(table + "." + field, () -> {
                    ObjectNode changed = base.deepCopy();
                    ObjectNode row = (ObjectNode) changed.path(table).get(0);
                    if (field.equals("enabled")) row.put(field, !row.path(field).booleanValue());
                    else row.put(field, "bob");
                    assertStale(base, changed);
                }));
            }
        }
        for (String table : List.of("clients", "peers")) {
            tests.add(DynamicTest.dynamicTest(table + ".clientName", () -> {
                ObjectNode changed = base.deepCopy();
                ((ObjectNode) changed.path(table).get(0)).put("clientName", "renamed");
                assertStale(base, changed);
            }));
        }
        tests.add(DynamicTest.dynamicTest("complete device/identity deletion", () -> {
            ObjectNode changed = base.deepCopy();
            ((ArrayNode) changed.path("clients")).remove(1);
            ((ArrayNode) changed.path("identities")).remove(1);
            assertStale(base, changed);
        }));
        tests.add(DynamicTest.dynamicTest("new device and relation", () -> {
            ObjectNode changed = base.deepCopy();
            ObjectNode client = changed.path("clients").get(1).deepCopy();
            client.put("id", 1003);
            ((ArrayNode) changed.path("clients")).add(client);
            ObjectNode identity = changed.path("identities").get(1).deepCopy();
            identity.put("id", 703).put("clientId", 1003);
            ((ArrayNode) changed.path("identities")).add(identity);
            assertStale(base, changed);
        }));
        tests.add(DynamicTest.dynamicTest("identity id changes without device count changes", () -> {
            ObjectNode changed = base.deepCopy();
            ((ObjectNode) changed.path("identities").get(0)).put("id", 799);
            assertStale(base, changed);
        }));
        tests.add(DynamicTest.dynamicTest("peer device disappears", () -> {
            ObjectNode changed = base.deepCopy();
            ((ArrayNode) changed.path("peers")).removeAll();
            assertStale(base, changed);
        }));
        tests.add(DynamicTest.dynamicTest("peer device id changes", () -> {
            ObjectNode changed = base.deepCopy();
            ((ObjectNode) changed.path("peers").get(0)).put("id", 899);
            assertStale(base, changed);
        }));
        return tests.stream();
    }

    @Test
    void revisionIsStatelessOrderIndependentAndBoundToTenantScopeAndPath() throws Exception {
        Snapshot snapshot = mapper.treeToValue(vector().path("base"), Snapshot.class);
        Preview original = preview(admin, PathScope.CREDENTIAL_GROUP, 501, snapshot);
        Snapshot reordered = new Snapshot(reverse(snapshot.clients()), reverse(snapshot.credentials()),
                reverse(snapshot.identities()), reverse(snapshot.peers()));
        assertThat(preview(admin, PathScope.CREDENTIAL_GROUP, 501, reordered)).isEqualTo(original);
        ManagementContext otherAdmin = new ManagementContext(admin.tenant(), "another-admin", true);
        assertThat(preview(otherAdmin, PathScope.CREDENTIAL_GROUP, 501, reordered).revision()).isEqualTo(original.revision());
        Snapshot otherTenant = new Snapshot(
                snapshot.clients().stream().map(c -> new ClientRow(c.id(), "tenant-b", c.clientName(), c.ownerUsername(), c.enabled())).toList(),
                snapshot.credentials().stream().map(c -> new CredentialRow(c.id(), "tenant-b", c.ownerUsername(), c.enabled())).toList(),
                snapshot.identities().stream().map(i -> new IdentityRow(i.id(), "tenant-b", i.credentialId(), i.clientId())).toList(),
                snapshot.peers().stream().map(p -> new PeerRow(p.id(), "tenant-b", p.clientId(), p.clientName(), p.ownerUsername(), p.enabled())).toList());
        assertThat(preview(new ManagementContext(new TenantContext("tenant-b"), "admin", true),
                PathScope.CREDENTIAL_GROUP, 501, otherTenant).revision()).isNotEqualTo(original.revision());
        Snapshot unique = new Snapshot(snapshot.clients(), snapshot.credentials(), List.of(snapshot.identities().getFirst()), snapshot.peers());
        assertThat(preview(admin, PathScope.SINGLE, 1001, unique).revision())
                .isNotEqualTo(preview(admin, PathScope.CREDENTIAL_GROUP, 501, unique).revision());
        Snapshot legacy = new Snapshot(snapshot.clients(), List.of(), List.of(), List.of());
        assertThat(preview(admin, PathScope.SINGLE, 1001, legacy).revision())
                .isNotEqualTo(preview(admin, PathScope.SINGLE, 1002, legacy).revision());
    }

    @Test
    void previewDoesNotTruncateLargeGroupsAndOwnsImmutableInputs() {
        List<ClientRow> clients = new ArrayList<>();
        List<IdentityRow> identities = new ArrayList<>();
        for (int n = 0; n < 1050; n++) {
            clients.add(new ClientRow(1001 + n, "tenant-a", "device-" + n, "alice", n % 2 == 0));
            identities.add(new IdentityRow(10001 + n, "tenant-a", 501, 1001 + n));
        }
        Snapshot snapshot = new Snapshot(clients, List.of(new CredentialRow(501, "tenant-a", "alice", false)), identities, List.of());
        clients.clear();
        identities.clear();
        Preview result = preview(admin, PathScope.CREDENTIAL_GROUP, 501, snapshot);
        assertThat(result.affectedClients()).hasSize(1050);
        assertThat(result.affectedClients().getLast().id()).isEqualTo(2050);
        assertThatThrownBy(() -> result.affectedClients().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> snapshot.clients().clear()).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void revisionIsOpaqueAndTextEncodingIsUnambiguous() throws Exception {
        ObjectNode base = vector().path("base").deepCopy();
        Snapshot original = mapper.treeToValue(base, Snapshot.class);
        String revision = preview(admin, PathScope.CREDENTIAL_GROUP, 501, original).revision();
        ObjectNode request = mapper.createObjectNode().put("scope", "credential-group")
                .put("targetUsername", "bob").put("expectedRevision", " " + revision);
        assertThatThrownBy(() -> prepare(admin, PathScope.CREDENTIAL_GROUP, 501, request, original))
                .isInstanceOfSatisfying(Failure.class, error -> assertThat(error.code()).isEqualTo("TRANSFER_PREVIEW_CHANGED"));
        ((ObjectNode) base.path("clients").get(0)).put("clientName", "one\ntwo").put("ownerUsername", "three");
        String first = preview(admin, PathScope.CREDENTIAL_GROUP, 501, mapper.treeToValue(base, Snapshot.class)).revision();
        ((ObjectNode) base.path("clients").get(0)).put("clientName", "one").put("ownerUsername", "two\nthree");
        assertThat(preview(admin, PathScope.CREDENTIAL_GROUP, 501, mapper.treeToValue(base, Snapshot.class)).revision()).isNotEqualTo(first);
    }

    private void assertStale(ObjectNode before, ObjectNode after) throws Exception {
        String old = preview(admin, PathScope.CREDENTIAL_GROUP, 501, mapper.treeToValue(before, Snapshot.class)).revision();
        Snapshot current = mapper.treeToValue(after, Snapshot.class);
        assertThat(preview(admin, PathScope.CREDENTIAL_GROUP, 501, current).revision()).isNotEqualTo(old);
        ObjectNode request = mapper.createObjectNode().put("scope", "credential-group")
                .put("targetUsername", "bob").put("expectedRevision", old);
        assertThatThrownBy(() -> prepare(admin, PathScope.CREDENTIAL_GROUP, 501, request, current))
                .isInstanceOfSatisfying(Failure.class, error -> {
                    assertThat(error.status()).isEqualTo(409);
                    assertThat(error.code()).isEqualTo("TRANSFER_PREVIEW_CHANGED");
                });
    }

    private JsonNode vector() throws Exception {
        Path root = Path.of("").toAbsolutePath();
        while (root != null && !Files.exists(root.resolve("protocol/test-vectors/client-owner-transfer-plan-v1.json"))) root = root.getParent();
        assertThat(root).as("repository shared ownership vectors").isNotNull();
        return mapper.readTree(Files.readString(root.resolve("protocol/test-vectors/client-owner-transfer-plan-v1.json")));
    }

    private static PathScope scope(String value) { return value.equals("single") ? PathScope.SINGLE : PathScope.CREDENTIAL_GROUP; }
    private static <T> List<T> reverse(List<T> input) {
        List<T> reversed = new ArrayList<>(input);
        Collections.reverse(reversed);
        return reversed;
    }
}
