/* Exercise the actual private cache/outbox accounting and exhaustion paths without production
 * test hooks. Native SQLite/fanout tests below use the same implementation and public API. */
#include "../src/peer_mesh.c"
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL catalog reconnect line %d: %s\n", __LINE__, #c); return 1; } } while (0)
static void clear_fixture(void)
{
    for (size_t i = 0; i < ST_PEER_MESH_MAX_CATALOGS; ++i) {
        free(peer_catalogs[i].mdns_candidates);
        memset(&peer_catalogs[i], 0, sizeof(peer_catalogs[i]));
    }
    while (peer_control_withdrawal_head != NULL) {
        st_peer_mesh_control_transition *next = peer_control_withdrawal_head->next;
        free(peer_control_withdrawal_head); peer_control_withdrawal_head = next;
    }
    peer_control_withdrawal_tail = NULL;
    peer_control_withdrawal_count = peer_catalog_reserved_revisions = 0;
    peer_catalog_sequence = 0;
}
static pm_catalog *seed(size_t slot, long long cid, long long sid)
{
    pm_catalog *catalog = &peer_catalogs[slot];
    memset(catalog, 0, sizeof(*catalog));
    catalog->in_use = catalog->active = 1;
    snprintf(catalog->tenant_id, sizeof(catalog->tenant_id), "queue-tenant");
    snprintf(catalog->publisher_client_name, sizeof(catalog->publisher_client_name), "publisher");
    catalog->publisher_client_id = cid; catalog->publisher_session_id = sid;
    catalog->report_revision = LLONG_MAX; catalog->catalog_revision = 1;
    catalog->expires_at = time(NULL) + 300;
    catalog->rate.count = ST_PEER_REPORT_RATE_LIMIT;
    catalog->service_count = catalog->stats_count = 1;
    snprintf(catalog->service_ids[0], sizeof(catalog->service_ids[0]), "svc");
    snprintf(catalog->stats[0].service_id, sizeof(catalog->stats[0].service_id), "svc");
    catalog->stats[0].bytes_in = 987;
    return catalog;
}
static st_peer_mesh_runtime runtime_for(const char *path, long long cid, long long sid)
{
    st_peer_mesh_runtime runtime = {0};
    runtime.database_path = path; runtime.authenticated_client_id = cid;
    runtime.authenticated_tenant = "queue-tenant"; runtime.publisher_session_id = sid;
    runtime.peer_service_discovery_version = 2;
    return runtime;
}
static int metadata_cutover(void)
{
    clear_fixture();
    st_peer_mesh_runtime runtime = runtime_for("/not-a-real-database/metadata-only.db", 1, 50);
    pm_catalog *catalog = seed(0, 1, 50);
    catalog->mdns_candidates = calloc(1, sizeof(*catalog->mdns_candidates));
    CHECK(catalog->mdns_candidates != NULL); catalog->mdns_count = 1;
    peer_catalog_sequence = 10;
    st_peer_mesh_control_transition *item = NULL;
    CHECK(st_peer_mesh_control_connected_prepare(NULL, "publisher", &item) == -1 && item == NULL);
    st_peer_mesh_runtime invalid = runtime; invalid.authenticated_tenant = NULL;
    CHECK(st_peer_mesh_control_connected_prepare(&invalid, "publisher", &item) == -1 && item == NULL
        && peer_control_withdrawal_count == 0);
    CHECK(st_peer_mesh_control_connected_prepare(&runtime, "publisher", &item) == 0 && item != NULL);
    CHECK(catalog->report_revision == LLONG_MAX && catalog->mdns_count == 1 && catalog->stats[0].bytes_in == 987
        && catalog->rate.count == 20 && peer_catalog_sequence == 10 && peer_catalog_reserved_revisions == 1);
    st_peer_mesh_control_connected_abort(item);
    CHECK(peer_control_withdrawal_count == 0 && peer_catalog_reserved_revisions == 0 && catalog->in_use
        && catalog->report_revision == LLONG_MAX && catalog->mdns_count == 1);
    CHECK(st_peer_mesh_control_connected_prepare(&runtime, "publisher", &item) == 0 && item != NULL);
    CHECK(pm_next_catalog_revision_locked(10) == 11); /* An independent authorization refresh. */
    CHECK(st_peer_mesh_control_connected_commit(item) == 0 && !catalog->in_use && catalog->mdns_candidates == NULL
        && catalog->report_revision == 0 && catalog->rate.count == 0 && catalog->stats_count == 0);
    CHECK(peer_control_withdrawal_head && peer_control_withdrawal_head->revision == 12
        && peer_catalog_sequence == 12 && peer_control_withdrawal_count == 1 && !peer_catalog_reserved_revisions);
    CHECK(st_peer_mesh_control_connected_prepare(&runtime, "publisher", &item) == 0 && item == NULL);
    CHECK(st_peer_mesh_control_connected_commit(item) == 0 && peer_control_withdrawal_count == 1);
    clear_fixture();
    seed(0, 1, 50); peer_catalog_sequence = 10;
    CHECK(st_peer_mesh_control_connected_prepare(&runtime, "publisher", &item) == 0 && item);
    pm_client_deletion deletion = {0}; deletion.client.id = 1;
    snprintf(deletion.client.tenant_id, sizeof(deletion.client.tenant_id), "queue-tenant");
    CHECK(pm_prepare_deleted_catalogs(&deletion) == 0 && !peer_catalogs[0].in_use && deletion.withdrawal_count == 1);
    CHECK(st_peer_mesh_control_connected_commit(item) == 0 && peer_control_withdrawal_count == 0
        && peer_catalog_reserved_revisions == 0 && !peer_control_withdrawal_head && peer_catalog_sequence == 11);
    free(deletion.withdrawals); clear_fixture();
    puts("PASS metadata-only prepare/abort/commit, independent output clock, raw/rate/stats/mDNS reset and idempotent reconnect");
    return 0;
}
static int capacity_and_revision_budget(void)
{
    clear_fixture(); peer_catalog_sequence = 100;
    st_peer_mesh_control_transition *items[ST_PEER_MESH_MAX_CATALOGS];
    for (size_t i = 0; i < ST_PEER_MESH_MAX_CATALOGS; ++i) {
        seed(i, (long long)i + 1, (long long)i + 100);
        st_peer_mesh_runtime runtime = runtime_for("capacity.db", (long long)i + 1, (long long)i + 100);
        CHECK(st_peer_mesh_control_connected_prepare(&runtime, "publisher", &items[i]) == 0 && items[i]);
    }
    st_peer_mesh_runtime runtime = runtime_for("capacity.db", 1, 100);
    st_peer_mesh_control_transition *extra = NULL;
    CHECK(peer_control_withdrawal_count == ST_PEER_MESH_MAX_CATALOGS
        && st_peer_mesh_control_connected_prepare(&runtime, "publisher", &extra) == -1 && extra == NULL
        && peer_catalogs[0].report_revision == LLONG_MAX);
    st_peer_mesh_control_connected_abort(items[0]);
    CHECK(st_peer_mesh_control_connected_prepare(&runtime, "publisher", &items[0]) == 0 && items[0]);
    for (size_t i = 0; i < ST_PEER_MESH_MAX_CATALOGS; ++i) CHECK(st_peer_mesh_control_connected_commit(items[i]) == 0);
    CHECK(peer_control_withdrawal_count == ST_PEER_MESH_MAX_CATALOGS && peer_catalog_reserved_revisions == 0);
    seed(0, 90000, 90000); runtime = runtime_for("capacity.db", 90000, 90000);
    CHECK(st_peer_mesh_control_connected_prepare(&runtime, "publisher", &extra) == -1
        && peer_catalogs[0].report_revision == LLONG_MAX);
    clear_fixture();
    peer_catalog_sequence = LLONG_MAX - 2;
    seed(0, 1, 1); seed(1, 2, 2);
    runtime = runtime_for("budget.db", 1, 1);
    CHECK(st_peer_mesh_control_connected_prepare(&runtime, "publisher", &items[0]) == 0);
    runtime = runtime_for("budget.db", 2, 2);
    CHECK(st_peer_mesh_control_connected_prepare(&runtime, "publisher", &items[1]) == 0);
    CHECK(pm_next_catalog_revision_locked(1) == 0 && peer_catalog_sequence == LLONG_MAX - 2);
    CHECK(st_peer_mesh_control_connected_commit(items[0]) == 0 && peer_control_withdrawal_head->revision == LLONG_MAX - 1);
    CHECK(st_peer_mesh_control_connected_commit(items[1]) == 0 && peer_control_withdrawal_tail->revision == LLONG_MAX);
    seed(2, 3, 3); runtime = runtime_for("budget.db", 3, 3);
    CHECK(st_peer_mesh_control_connected_prepare(&runtime, "publisher", &extra) == -1 && peer_catalogs[2].in_use);
    clear_fixture();
    peer_catalog_sequence = LLONG_MAX - 2;
    seed(0, 1, 1); seed(1, 1, 2); seed(2, 2, 3);
    runtime = runtime_for("budget.db", 2, 3);
    CHECK(st_peer_mesh_control_connected_prepare(&runtime, "publisher", &extra) == 0 && extra);
    pm_client_deletion deletion = {0}; deletion.client.id = 1;
    snprintf(deletion.client.tenant_id, sizeof(deletion.client.tenant_id), "queue-tenant");
    CHECK(pm_prepare_deleted_catalogs(&deletion) == -1 && peer_catalogs[0].in_use && peer_catalogs[1].in_use
        && peer_catalog_sequence == LLONG_MAX - 2 && !deletion.prepared);
    st_peer_mesh_control_connected_abort(extra);
    CHECK(pm_prepare_deleted_catalogs(&deletion) == 0 && deletion.withdrawal_count == 2
        && deletion.withdrawals[0].catalog_revision == LLONG_MAX - 1 && deletion.withdrawals[1].catalog_revision == LLONG_MAX);
    free(deletion.withdrawals); clear_fixture();
    puts("PASS shared reserved/queued capacity, reclamation, signed clock exhaustion and deletion reservation fencing");
    return 0;
}
typedef struct { int failures_left; int count; int source_checks; size_t in_flight_charge; char messages[8][2048]; } capture;
static int online(void *ctx, long long cid, const char *name) { (void)ctx; (void)cid; (void)name; return 1; }
static int send_message(void *ctx, const char *target, const char *source, const char *message)
{
    (void)target; (void)source; capture *state = ctx;
    state->in_flight_charge = peer_control_withdrawal_count;
    if (state->count >= 8 || strlen(message) >= sizeof(state->messages[0])) return -1;
    snprintf(state->messages[state->count++], sizeof(state->messages[0]), "%s", message);
    if (state->failures_left > 0 && strstr(message, "\"publisherClientName\":\"publisher\"")) {
        --state->failures_left; return -1;
    }
    return 0;
}
static int source_changes_during_withdrawal(void *ctx) { return ++((capture *)ctx)->source_checks == 1; }
static int native_retry_and_fresh_raw_report(void)
{
    clear_fixture();
    char path[] = "/tmp/specus-c-catalog-reconnect-XXXXXX";
    int fd = mkstemp(path); CHECK(fd >= 0); close(fd);
    CHECK(st_storage_init(path, 0) == 0);
    st_storage_client publisher, recipient;
    CHECK(st_storage_upsert_client(path, 0, "queue-tenant", "publisher", "alice", 1, 60, &publisher) == 0
        && st_storage_upsert_client(path, 0, "queue-tenant", "recipient", "alice", 1, 60, &recipient) == 0);
    seed(0, publisher.id, 50); peer_catalog_sequence = 10;
    capture state = {.failures_left = 2};
    st_peer_mesh_runtime runtime = runtime_for(path, publisher.id, 50);
    runtime.ctx = &state; runtime.send = send_message; runtime.online = online;
    st_peer_mesh_control_transition *item = NULL;
    CHECK(st_peer_mesh_control_connected_prepare(&runtime, publisher.client_name, &item) == 0 && item
        && st_peer_mesh_control_connected_commit(item) == 0);
    CHECK(st_peer_mesh_drain_control_withdrawals(&runtime) == -1 && peer_control_withdrawal_count == 1
        && state.in_flight_charge == 1 && peer_control_withdrawal_head->audited);
    const char *report = "{\"type\":\"service-report\",\"enabled\":false,\"revision\":1,\"services\":[]}";
    st_peer_mesh_runtime other = runtime; other.authenticated_client_id = recipient.id; other.publisher_session_id = 51;
    CHECK(st_peer_mesh_handle_control(&other, recipient.client_name, NULL, report) == 0 && peer_control_withdrawal_count == 1);
    CHECK(st_peer_mesh_handle_control(&runtime, publisher.client_name, NULL, report) == -1
        && pm_find_catalog_locked(publisher.id, "queue-tenant", 50) == NULL && peer_control_withdrawal_count == 1);
    runtime.source_current = source_changes_during_withdrawal;
    CHECK(st_peer_mesh_handle_control(&runtime, publisher.client_name, NULL, report) == -1
        && peer_control_withdrawal_count == 0 && !pm_find_catalog_locked(publisher.id, "queue-tenant", 50)
        && state.source_checks == 2);
    runtime.source_current = NULL; /* Explicit trusted current replacement for the next operation. */
    CHECK(st_peer_mesh_handle_control(&runtime, publisher.client_name, NULL, report) == 0
        && peer_control_withdrawal_count == 0 && !peer_control_withdrawal_head && !peer_control_withdrawal_tail);
    CHECK(state.count == 5 && strcmp(state.messages[0], state.messages[2]) == 0
        && strcmp(state.messages[2], state.messages[3]) == 0 && strstr(state.messages[3], "\"services\":[]"));
    long long old_revision = 0, new_revision = 0;
    CHECK(st_json_get_i64(state.messages[3], "revision", &old_revision) == 0
        && st_json_get_i64(state.messages[4], "revision", &new_revision) == 0 && new_revision > old_revision);
    pm_catalog *fresh = pm_find_catalog_locked(publisher.id, "queue-tenant", 50);
    CHECK(fresh && fresh->report_revision == 1 && fresh->rate.count == 1 && fresh->stats_count == 0 && fresh->mdns_count == 0);
    CHECK(st_peer_mesh_handle_control(&runtime, publisher.client_name, NULL, report) == 0 && state.count == 5);
    st_storage_peer_mesh_service_audit audits[80]; size_t count = 0;
    CHECK(st_storage_list_peer_mesh_service_audits(path, "queue-tenant", audits, 80, &count) == 0);
    int reconnects = 0;
    for (size_t i = 0; i < count; ++i) if (strcmp(audits[i].reason, "control-reconnected") == 0) ++reconnects;
    CHECK(reconnects == 1);
    clear_fixture(); unlink(path);
    puts("PASS native audit-once, exact retry payload, in-flight charge, unrelated key progress, post-I/O source fence, raw1 restart and duplicate ignore");
    return 0;
}
int main(void)
{
    CHECK(setenv("SPECUS_PEER_MESH_ENABLED", "true", 1) == 0);
    CHECK(metadata_cutover() == 0 && capacity_and_revision_budget() == 0 && native_retry_and_fresh_raw_report() == 0);
    return 0;
}
