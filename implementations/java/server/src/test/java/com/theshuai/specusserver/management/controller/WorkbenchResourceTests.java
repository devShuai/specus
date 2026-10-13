package com.theshuai.specusserver.management.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.theshuai.specusserver.management.model.ClientAccount;
import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;
import java.util.List;
import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The workbench API over HTTP beyond the shared vector: authentication, the cache policy of every
 * answer, isolation between identities (administrators included), ignored query and body, the
 * path validation Spring's own binding would get wrong, and the table's key layout.
 */
class WorkbenchResourceTests extends WorkbenchHttpTestSupport {
    private static final String BASE = "/api/admin/workbench";

    @Test
    void everyOperationNeedsASession() {
        for (String[] request : List.of(
                new String[]{"GET", BASE},
                new String[]{"PUT", BASE + "/favorites/http-route/1"},
                new String[]{"DELETE", BASE + "/favorites/http-route/1"},
                new String[]{"DELETE", BASE + "/favorites"},
                new String[]{"POST", BASE + "/recents/http-route/1"},
                new String[]{"DELETE", BASE + "/recents/http-route/1"},
                new String[]{"DELETE", BASE + "/recents"})) {
            assertThat(send(request[0], request[1], null).statusCode()).as(request[0] + " " + request[1]).isEqualTo(401);
            assertThat(send(request[0], request[1], "not-a-token").statusCode())
                    .as(request[0] + " " + request[1] + " with a forged token").isEqualTo(401);
        }
    }

    @Test
    void everyWorkbenchAnswerIsPrivateAndNotStored() {
        String alice = createUser("t1", "alice", false);
        ClientAccount client = createClient("t1", "alice");
        createObject("http-route", 1, client);

        assertNoStore(send("GET", BASE, alice), 200);
        assertNoStore(send("PUT", BASE + "/favorites/http-route/1", alice), 200);
        assertNoStore(send("PUT", BASE + "/favorites/http-route/042", alice), 400);
        assertNoStore(send("PUT", BASE + "/favorites/http-route/2", alice), 404);
        assertNoStore(send("DELETE", BASE + "/favorites", alice), 200);

        for (long id = 100; id < 150; id++) {
            insertRow("t1", "alice", "favorite", "http-route", id, id);
        }
        assertNoStore(send("PUT", BASE + "/favorites/http-route/1", alice), 409);

        for (int i = 0; i < 40; i++) {
            send("POST", BASE + "/recents/http-route/1", alice);
        }
        HttpResponse<String> limited = send("POST", BASE + "/recents/http-route/1", alice);
        assertNoStore(limited, 429);
        assertThat(limited.headers().firstValue("Retry-After")).hasValue("1");

        storeDown();
        try {
            HttpResponse<String> unavailable = send("GET", BASE, alice);
            assertNoStore(unavailable, 503);
            // A store that cannot be read never looks like empty lists.
            assertThat(json(unavailable).has("favorites")).isFalse();
            assertThat(json(unavailable).path("code").asText()).isEqualTo("WORKBENCH_UNAVAILABLE");
        } finally {
            storeUp();
        }

        // An account that still owns a client is not deleted (management-accounts.md 7.1).
        client.setOwnerUsername("workbench-fixture-admin");
        clientAccountRepository.saveAndFlush(client);
        managementUserService.deleteUser(tenantAdmin("t1"), "alice");
        HttpResponse<String> rejected = send("GET", BASE, alice);
        assertThat(rejected.statusCode()).isEqualTo(403);
        assertThat(rejected.headers().firstValue("Cache-Control")).hasValue("private, no-store");
    }

    @Test
    void anAdministratorReadsAndClearsOnlyTheirOwnLists() {
        String alice = createUser("t1", "alice", false);
        String root = createUser("t1", "root", true);
        ClientAccount client = createClient("t1", "alice");
        createObject("http-route", 1, client);
        createObject("tcp-mapping", 2, client);

        at(1_000);
        assertThat(send("PUT", BASE + "/favorites/http-route/1", alice).statusCode()).isEqualTo(200);
        assertThat(send("POST", BASE + "/recents/tcp-mapping/2", alice).statusCode()).isEqualTo(200);
        at(2_000);
        // The administrator sees alice's services in the lists, but the workbench is the caller's own.
        assertThat(send("PUT", BASE + "/favorites/tcp-mapping/2", root).statusCode()).isEqualTo(200);

        for (String query : List.of("", "?username=alice", "?tenantId=t1&username=alice", "?user=alice")) {
            JsonNode document = json(send("GET", BASE + query, root));
            assertThat(refs(document.path("favorites"))).as(query).containsExactly("tcp-mapping/2");
            assertThat(refs(document.path("recents"))).as(query).isEmpty();
        }

        String naming = "{\"tenantId\":\"t1\",\"username\":\"alice\"}";
        assertThat(send("DELETE", BASE + "/favorites?username=alice", root, naming).statusCode()).isEqualTo(200);
        assertThat(send("DELETE", BASE + "/recents?username=alice", root, naming).statusCode()).isEqualTo(200);
        assertThat(send("DELETE", BASE + "/favorites/http-route/1?username=alice", root, naming).statusCode())
                .isEqualTo(200);

        JsonNode own = json(send("GET", BASE, alice));
        assertThat(refs(own.path("favorites"))).containsExactly("http-route/1");
        assertThat(refs(own.path("recents"))).containsExactly("tcp-mapping/2");
        assertThat(refs(json(send("GET", BASE, root)).path("favorites"))).isEmpty();
        assertThat(rows()).extracting(Row::username).containsOnly("alice");
    }

    @Test
    void theRequestBodyIsNeverRead() {
        String alice = createUser("t1", "alice", false);
        ClientAccount client = createClient("t1", "alice");
        createObject("http-route", 7, client);

        at(5_000);
        String body = "{\"kind\":\"tcp-mapping\",\"id\":99,\"addedAt\":\"2020-01-01T00:00:00.000Z\","
                + "\"visitedAt\":\"2020-01-01T00:00:00.000Z\",\"username\":\"bob\"}";
        assertThat(send("PUT", BASE + "/favorites/http-route/7", alice, body).statusCode()).isEqualTo(200);
        assertThat(send("POST", BASE + "/recents/http-route/7", alice, "not json at all").statusCode()).isEqualTo(200);

        assertThat(rows()).containsExactly(
                new Row("t1", "alice", "favorite", "http-route", 7, 5_000),
                new Row("t1", "alice", "recent", "http-route", 7, 5_000));
    }

    @Test
    void idsAreValidatedAsTheRawPathSegment() {
        String alice = createUser("t1", "alice", false);
        ClientAccount client = createClient("t1", "alice");
        createObject("http-route", 42, client);

        // A Long binding would read every one of these as 42 (or 1); the contract refuses them.
        for (String id : List.of("042", "0042", "%2B42", "%2042", "42%20", "42.0", "4%2C2", "0x2A", "42L")) {
            for (String[] request : List.of(
                    new String[]{"PUT", BASE + "/favorites/http-route/" + id},
                    new String[]{"DELETE", BASE + "/favorites/http-route/" + id},
                    new String[]{"POST", BASE + "/recents/http-route/" + id},
                    new String[]{"DELETE", BASE + "/recents/http-route/" + id})) {
                HttpResponse<String> response = send(request[0], request[1], alice);
                assertThat(response.statusCode()).as(request[0] + " " + request[1]).isEqualTo(400);
                assertThat(json(response).path("code").asText()).isEqualTo("WORKBENCH_REQUEST_INVALID");
            }
        }
        assertThat(rows()).isEmpty();
        assertThat(send("PUT", BASE + "/favorites/http-route/42", alice).statusCode()).isEqualTo(200);
        assertThat(send("PUT", BASE + "/favorites/Http-Route/42", alice).statusCode()).isEqualTo(400);
        assertThat(send("PUT", BASE + "/favorites/http-route/9007199254740992", alice).statusCode()).isEqualTo(400);
        assertThat(send("PUT", BASE + "/favorites/http-route/99999999999999999999", alice).statusCode())
                .isEqualTo(400);
    }

    @Test
    void readingNeverWrites() {
        String alice = createUser("t1", "alice", false);
        // Expired and over-bound recents are filtered on read and only deleted by a write.
        at(40L * 24 * 3600 * 1000);
        insertRow("t1", "alice", "recent", "http-route", 1, 0);
        for (long id = 10; id < 32; id++) {
            insertRow("t1", "alice", "recent", "http-route", id, 39L * 24 * 3600 * 1000 + id);
        }
        List<Row> before = rows();
        JsonNode document = json(send("GET", BASE, alice));
        assertThat(document.path("recents")).hasSize(20);
        assertThat(rows()).isEqualTo(before);
    }

    @Test
    void oneRowPerReferenceAndIndexesForIdentityCascadeAndSweep() {
        String table = sql("table", TABLE);
        String primaryKey = table.substring(table.indexOf("primary key (") + "primary key (".length());
        assertThat(primaryKey.substring(0, primaryKey.indexOf(')')).split(", "))
                .containsExactlyInAnyOrder("tenant_id", "username", "list", "kind", "object_id");
        assertThat(sql("index", "idx_mwi_identity")).contains("(tenant_id, username)");
        assertThat(sql("index", "idx_mwi_object")).contains("(tenant_id, kind, object_id)");
        assertThat(sql("index", "idx_mwi_list_at")).contains("(list, at_ms)");
    }

    private String sql(String type, String name) {
        String sql = jdbcTemplate.queryForObject(
                "select sql from sqlite_master where type = ? and name = ?", String.class, type, name);
        return sql.toLowerCase(Locale.ROOT).replaceAll("\\s+", " ");
    }

    private static void assertNoStore(HttpResponse<String> response, int status) {
        assertThat(response.statusCode()).as(response.body()).isEqualTo(status);
        assertThat(response.headers().firstValue("Cache-Control")).as("Cache-Control of " + status)
                .hasValue("private, no-store");
    }

    static List<String> refs(JsonNode entries) {
        return java.util.stream.StreamSupport.stream(entries.spliterator(), false)
                .map(entry -> entry.path("kind").asText() + "/" + entry.path("id").asLong())
                .toList();
    }
}
