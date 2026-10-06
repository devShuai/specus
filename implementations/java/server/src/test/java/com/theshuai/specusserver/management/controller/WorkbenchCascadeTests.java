package com.theshuai.specusserver.management.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.theshuai.specusserver.management.model.ClientAccount;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static com.theshuai.specusserver.management.controller.WorkbenchResourceTests.refs;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Workbench references follow their objects and accounts through the existing delete endpoints
 * (protocol/spec/service-workbench.md sections 3 and 5.4): deleting a route, mapping or Peer service
 * removes every identity's references to it; deleting a client removes the references to everything
 * it carries although Java keeps those rows; deleting an account removes that identity's rows, so
 * the same name recreated starts empty. Disabling an account deletes nothing.
 */
class WorkbenchCascadeTests extends WorkbenchHttpTestSupport {
    private static final String BASE = "/api/admin/workbench";

    private String alice;
    private String bob;
    private String root;
    private ClientAccount aliceClient;
    private ClientAccount bobClient;

    @BeforeEach
    void twoClientsWithEveryKindAndThreeIdentitiesReferencingThem() {
        alice = createUser("t1", "alice", false);
        bob = createUser("t1", "bob", false);
        root = createUser("t1", "root", true);
        aliceClient = createClient("t1", "alice");
        bobClient = createClient("t1", "bob");
        createObject("http-route", 11, aliceClient);
        createObject("tcp-mapping", 12, aliceClient);
        createObject("peer-service", 13, aliceClient);
        createObject("http-route", 21, bobClient);
        createObject("tcp-mapping", 22, bobClient);
        createObject("peer-service", 23, bobClient);

        at(1_000);
        for (String reference : List.of("http-route/11", "tcp-mapping/12", "peer-service/13")) {
            ok("PUT", BASE + "/favorites/" + reference, alice);
            ok("POST", BASE + "/recents/" + reference, alice);
            ok("PUT", BASE + "/favorites/" + reference, root);
            ok("POST", BASE + "/recents/" + reference, root);
        }
        for (String reference : List.of("http-route/21", "tcp-mapping/22", "peer-service/23")) {
            ok("PUT", BASE + "/favorites/" + reference, bob);
            ok("PUT", BASE + "/favorites/" + reference, root);
        }
        assertThat(rows()).hasSize(18);
    }

    @Test
    void deletingARouteRemovesEveryReferenceToIt() {
        assertThat(send("DELETE", "/api/admin/http-routes/11", root).statusCode()).isEqualTo(204);
        assertThat(referencesTo("http-route", 11)).isEmpty();
        assertThat(rows()).hasSize(14);
        // An id handed out again starts without references.
        createObject("http-route", 11, aliceClient);
        assertThat(refs(json(send("GET", BASE, alice)).path("favorites"))).doesNotContain("http-route/11");
    }

    @Test
    void deletingAMappingRemovesEveryReferenceToIt() {
        assertThat(send("DELETE", "/api/admin/specus-mappings/12", alice).statusCode()).isEqualTo(204);
        assertThat(referencesTo("tcp-mapping", 12)).isEmpty();
        assertThat(rows()).hasSize(14);
    }

    @Test
    void deletingAPeerServiceRemovesEveryReferenceToIt() {
        assertThat(send("DELETE", "/api/admin/peer-mesh/services/23", root).statusCode()).isEqualTo(200);
        assertThat(referencesTo("peer-service", 23)).isEmpty();
        assertThat(rows()).hasSize(16);
    }

    @Test
    void deletingAClientRemovesTheReferencesToEverythingItCarries() {
        assertThat(send("DELETE", "/api/admin/clients/" + aliceClient.getId(), root).statusCode()).isEqualTo(204);

        // Java keeps the client's route and mapping rows; the workbench forgets them anyway.
        assertThat(httpRouteMappingRepository.findById(11L)).isPresent();
        assertThat(rows()).extracting(Row::id).containsOnly(21L, 22L, 23L);
        assertThat(rows()).hasSize(6);
        // The orphaned route cannot be added back: its client is gone.
        var orphan = send("PUT", BASE + "/favorites/http-route/11", root);
        assertThat(orphan.statusCode()).isEqualTo(404);
        assertThat(json(orphan).path("code").asText()).isEqualTo("WORKBENCH_TARGET_NOT_FOUND");
    }

    @Test
    void deletingAnAccountRemovesItsRowsAndTheSameNameStartsEmpty() {
        assertThat(send("DELETE", "/api/admin/users/alice", root).statusCode()).isEqualTo(204);
        assertThat(rows()).extracting(Row::username).containsOnly("bob", "root");
        assertThat(rows()).hasSize(12);

        // The old token can neither read nor write rows back.
        assertThat(send("POST", BASE + "/recents/http-route/11", alice).statusCode()).isEqualTo(403);
        assertThat(rows()).hasSize(12);

        String recreated = createUser("t1", "alice", false);
        JsonNode document = json(send("GET", BASE, recreated));
        assertThat(document.path("favorites")).isEmpty();
        assertThat(document.path("recents")).isEmpty();
    }

    @Test
    void disablingAnAccountDeletesNothing() {
        String disable = "{\"enabled\":false}";
        assertThat(send("PUT", "/api/admin/users/alice", root, disable).statusCode()).isEqualTo(200);
        assertThat(send("GET", BASE, alice).statusCode()).isEqualTo(403);
        assertThat(rows()).hasSize(18);

        assertThat(send("PUT", "/api/admin/users/alice", root, "{\"enabled\":true}").statusCode()).isEqualTo(200);
        assertThat(refs(json(send("GET", BASE, alice)).path("favorites")))
                .containsExactly("http-route/11", "tcp-mapping/12", "peer-service/13");
    }

    private List<Row> referencesTo(String kind, long id) {
        return rows().stream().filter(row -> row.kind().equals(kind) && row.id() == id).toList();
    }

    private void ok(String method, String path, String token) {
        var response = send(method, path, token);
        assertThat(response.statusCode()).as(method + " " + path + " -> " + response.body()).isEqualTo(200);
    }
}
