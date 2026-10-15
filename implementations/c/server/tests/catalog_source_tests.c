/* Actual cache implementation and SQLite authority, without production test hooks. */
#include "../src/peer_mesh.c"
#include <errno.h>
#include <sqlite3.h>
#include <unistd.h>

typedef struct {
    char directory[128], path[256];
    st_storage_client publisher, peer;
    st_storage_control_source guard;
    st_peer_mesh_runtime runtime;
    pthread_mutex_t lock;
    pthread_cond_t condition;
    int armed, ready, resume, sent, result, initialized;
} fixture;

static int execute(const char *path, const char *sql)
{
    sqlite3 *db = NULL;
    int rc = sqlite3_open(path, &db);
    if (rc == SQLITE_OK) { sqlite3_busy_timeout(db, 5000); rc = sqlite3_exec(db, sql, NULL, NULL, NULL); }
    sqlite3_close(db); return rc == SQLITE_OK ? 0 : -1;
}
static int audit_count(const char *path)
{
    sqlite3 *db = NULL; sqlite3_stmt *stmt = NULL; int count = -1;
    if (sqlite3_open(path, &db) == SQLITE_OK && sqlite3_prepare_v2(db,
        "SELECT COUNT(*) FROM peer_mesh_service_audit", -1, &stmt, NULL) == SQLITE_OK
        && sqlite3_step(stmt) == SQLITE_ROW) count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt); sqlite3_close(db); return count;
}
static int current(void *context)
{
    fixture *f = context;
    return st_storage_control_source_validate(f->path, &f->guard) == 0;
}
static int active(void *context) { (void)context; return 1; }
static int online(void *context, long long id, const char *name)
{
    (void)name; fixture *f = context;
    pthread_mutex_lock(&f->lock);
    if (id == f->peer.id && f->armed && !f->ready) {
        f->ready = 1;
        pthread_cond_broadcast(&f->condition);
        while (!f->resume) pthread_cond_wait(&f->condition, &f->lock);
    }
    pthread_mutex_unlock(&f->lock);
    return id == f->peer.id;
}
static int send_catalog(void *context, const char *target, const char *source, const char *message)
{
    (void)target; (void)source; fixture *f = context;
    if (strstr(message, "\"type\":\"service-catalog\"")) ++f->sent;
    return 0;
}
static int report(fixture *f, int revision, int bytes, const char *name)
{
    char message[1600];
    snprintf(message, sizeof(message),
        "{\"type\":\"service-report\",\"enabled\":true,\"revision\":%d,\"instanceId\":\"instance-%d\","
        "\"services\":[{\"serviceId\":\"svc-cache-source\",\"name\":\"untrusted-name\",\"transport\":\"tcp\",\"application\":\"http\",\"publishedPort\":18080}],"
        "\"stats\":[{\"serviceId\":\"svc-cache-source\",\"bytesIn\":%d,\"activeConnections\":1}],"
        "\"mdnsCandidates\":[{\"name\":\"%s\",\"application\":\"http\",\"targetHost\":\"127.0.0.1\",\"targetPort\":8080}]}",
        revision, revision, bytes, name);
    return st_peer_mesh_handle_control(&f->runtime, f->publisher.client_name, NULL, message);
}
static int snapshot(fixture *f, pm_catalog *out, char mdns[81])
{
    int found = 0;
    pthread_mutex_lock(&peer_catalog_lock);
    for (size_t i = 0; i < ST_PEER_MESH_MAX_CATALOGS; ++i) {
        pm_catalog *catalog = &peer_catalogs[i];
        if (catalog->in_use && catalog->publisher_client_id == f->publisher.id
            && catalog->publisher_session_id == f->guard.session_id
            && !strcmp(catalog->tenant_id, f->publisher.tenant_id)) {
            *out = *catalog;
            snprintf(mdns, 81, "%s", catalog->mdns_count ? catalog->mdns_candidates[0].name : "");
            found = 1; break;
        }
    }
    pthread_mutex_unlock(&peer_catalog_lock);
    return found ? 0 : -1;
}
static int prepare(fixture *f)
{
    memset(f, 0, sizeof(*f));
    snprintf(f->directory, sizeof(f->directory), "/tmp/specus-catalog-source-XXXXXX");
    if (!mkdtemp(f->directory)) return -1;
    snprintf(f->path, sizeof(f->path), "%s/specus.db", f->directory);
    pthread_mutex_init(&f->lock, NULL);
    pthread_condattr_t attr; pthread_condattr_init(&attr);
    pthread_condattr_setclock(&attr, CLOCK_MONOTONIC); pthread_cond_init(&f->condition, &attr); pthread_condattr_destroy(&attr);
    f->initialized = 1;
    st_storage_client_credential credential; st_storage_client_session session = {0};
    if (st_storage_init(f->path, 0) != 0
        || st_storage_upsert_client(f->path, 0, "catalog-source", "source-publisher", "alice", 1, 60, &f->publisher) != 0
        || st_storage_upsert_client(f->path, 0, "catalog-source", "source-peer", "alice", 1, 60, &f->peer) != 0
        || st_storage_insert_client_credential(f->path, "catalog-source", "alice", "catalog-key", "test-secret", 1, 10, &credential) != 0
        || st_storage_update_peer_mesh_device_enabled(f->path, &f->publisher, 1, NULL) != 0
        || st_storage_update_peer_mesh_device_enabled(f->path, &f->peer, 1, NULL) != 0
        || st_storage_upsert_peer_mesh_service_sharing(f->path, "catalog-source", 1, 1, "admin", NULL) != 0) return -1;
    session.client_id = f->publisher.id; session.identity_id = f->publisher.id; session.credential_id = credential.id;
    session.peer_service_discovery_version = 2;
    snprintf(session.tenant_id, sizeof(session.tenant_id), "catalog-source");
    snprintf(session.client_name, sizeof(session.client_name), "%s", f->publisher.client_name);
    snprintf(session.machine_fingerprint, sizeof(session.machine_fingerprint), "catalog-source-machine");
    snprintf(session.status, sizeof(session.status), "HTTP_AUTHENTICATED");
    snprintf(session.expires_at, sizeof(session.expires_at), "2999-01-01T00:00:00Z");
    memset(session.token_hash, 'a', 64); session.token_hash[64] = '\0';
    if (st_storage_create_client_session(f->path, &session, &session) != 0
        || st_storage_mark_client_session_online(f->path, session.id, "catalog-original", "127.0.0.1:9", "2026-10-16T00:00:00Z") != 0) return -1;
    f->guard.client_id = f->publisher.id; f->guard.session_id = session.id;
    snprintf(f->guard.tenant_id, sizeof(f->guard.tenant_id), "catalog-source");
    snprintf(f->guard.client_name, sizeof(f->guard.client_name), "%s", f->publisher.client_name);
    snprintf(f->guard.channel_id, sizeof(f->guard.channel_id), "catalog-original");
    snprintf(f->guard.token_hash, sizeof(f->guard.token_hash), "%s", session.token_hash);
    st_storage_peer_mesh_service service = {0};
    snprintf(service.tenant_id, sizeof(service.tenant_id), "catalog-source"); service.client_id = f->publisher.id;
    snprintf(service.client_name, sizeof(service.client_name), "%s", f->publisher.client_name);
    snprintf(service.service_id, sizeof(service.service_id), "svc-cache-source");
    snprintf(service.name, sizeof(service.name), "trusted-service");
    snprintf(service.transport, sizeof(service.transport), "tcp"); snprintf(service.application, sizeof(service.application), "http");
    snprintf(service.target_host, sizeof(service.target_host), "127.0.0.1"); service.target_port = 8080;
    service.published_port = 18080; service.enabled = 1; snprintf(service.visibility, sizeof(service.visibility), "OWNER");
    if (st_storage_upsert_peer_mesh_service(f->path, &service, NULL) != 0) return -1;
    f->runtime = (st_peer_mesh_runtime){.database_path=f->path, .send=send_catalog, .online=online, .ctx=f,
        .publisher_session_id=session.id, .peer_service_discovery_version=2,
        .authenticated_client_id=f->publisher.id, .authenticated_tenant=f->publisher.tenant_id,
        .source_active=active, .source_current=current, .control_source=&f->guard};
    return report(f, 1, 3, "Original Local");
}
static void cleanup(fixture *f)
{
    for (size_t i = 0; i < ST_PEER_MESH_MAX_CATALOGS; ++i) {
        free(peer_catalogs[i].mdns_candidates); memset(&peer_catalogs[i], 0, sizeof(peer_catalogs[i]));
    }
    peer_catalog_sequence = 0; peer_catalog_reserved_revisions = 0;
    if (f->initialized) { pthread_cond_destroy(&f->condition); pthread_mutex_destroy(&f->lock); }
    unlink(f->path); rmdir(f->directory);
}
static void *old_report(void *context)
{
    fixture *f = context; f->result = report(f, 100, 900, "Stale Local"); return NULL;
}
static int scenario(const char *mode)
{
    fixture f; int failed = 1, thread_started = 0; pthread_t thread;
    pm_catalog before = {0}, after = {0}; char old_mdns[81], new_mdns[81];
#define REQUIRE(c, text) do { if (!(c)) { fprintf(stderr, "FAIL catalog source %s: %s\n", mode, text); goto done; } } while (0)
    REQUIRE(prepare(&f) == 0, "real SQLite source, device/sharing/service and initial committed report");
    REQUIRE(snapshot(&f, &before, old_mdns) == 0 && before.report_revision == 1 && before.rate.count == 1
        && before.stats_count == 1 && before.stats[0].bytes_in == 3 && !strcmp(old_mdns, "Original Local"), "initial cache cohort");
    int sent = f.sent, audits = audit_count(f.path), rc;
    long long clock = peer_catalog_sequence;
    if (!strcmp(mode, "stale")) {
        pthread_mutex_lock(&f.lock); f.armed = 1; pthread_mutex_unlock(&f.lock);
        REQUIRE(pthread_create(&thread, NULL, old_report, &f) == 0, "start original in-flight report"); thread_started = 1;
        struct timespec deadline; clock_gettime(CLOCK_MONOTONIC, &deadline); deadline.tv_sec += 5;
        pthread_mutex_lock(&f.lock); int wait = 0;
        while (!f.ready && wait != ETIMEDOUT) wait = pthread_cond_timedwait(&f.condition, &f.lock, &deadline);
        int ready = f.ready; pthread_mutex_unlock(&f.lock);
        REQUIRE(ready, "pause after successful native source check/device write, before cache mutation");
        REQUIRE(st_storage_mark_client_session_online(f.path, f.guard.session_id, "catalog-replacement", "127.0.0.1:10", "2026-10-16T00:00:01Z") == 0,
            "independent native writer replaces physical epoch without waiting for cache/registry locks");
        pthread_mutex_lock(&f.lock); f.resume = 1; pthread_cond_broadcast(&f.condition); pthread_mutex_unlock(&f.lock);
        pthread_join(thread, NULL); thread_started = 0; rc = f.result;
    } else {
        if (!strcmp(mode, "audit-insert"))
            REQUIRE(execute(f.path, "CREATE TRIGGER fail_catalog_audit BEFORE INSERT ON peer_mesh_service_audit BEGIN SELECT RAISE(ABORT,'audit failure'); END") == 0, "actual audit INSERT fault");
        else if (!strcmp(mode, "audit-prune")) {
            for (int i = audits; i < 80; ++i)
                REQUIRE(st_storage_record_peer_mesh_service_audit(f.path, "fixture", "catalog-source", f.publisher.id, f.guard.session_id, NULL, "fill") == 0, "bounded native audit setup");
            audits = 80;
            REQUIRE(execute(f.path, "CREATE TRIGGER fail_catalog_prune BEFORE DELETE ON peer_mesh_service_audit BEGIN SELECT RAISE(ABORT,'retention failure'); END") == 0, "actual retention DELETE fault");
        } else {
            REQUIRE(execute(f.path, "CREATE TRIGGER change_catalog_authority AFTER INSERT ON peer_mesh_service_audit WHEN NEW.action='service-report' BEGIN UPDATE specus_client_session SET token_hash='changed'; END") == 0, "within-transaction authority-change fault");
        }
        rc = report(&f, 100, 900, "Failed Local");
    }
    REQUIRE(snapshot(&f, &after, new_mdns) == 0, "read actual cache after resumed/rejected report");
    fprintf(stderr, "OBSERVATION catalog source %s rc=%d raw=%lld rate=%u wire=%lld stats=%lld mdns=%s sentDelta=%d audits=%d\n",
        mode, rc, after.report_revision, after.rate.count, after.catalog_revision, after.stats[0].bytes_in, new_mdns, f.sent-sent, audit_count(f.path));
    REQUIRE(!strcmp(mode, "stale") ? rc == ST_STORAGE_CONTROL_SOURCE_RETIRED : rc == -1,
        "stale physical source is rejected; SQL/rolled-back authority failure is not permanent retirement");
    REQUIRE(after.report_revision == before.report_revision && after.catalog_revision == before.catalog_revision
        && after.created_at_millis == before.created_at_millis
        && !memcmp(&after.rate, &before.rate, sizeof(after.rate)) && after.stats[0].bytes_in == 3
        && after.mdns_count == before.mdns_count && !strcmp(old_mdns, new_mdns)
        && peer_catalog_sequence == clock && peer_catalog_reserved_revisions == 0 && f.sent == sent,
        "raw cursor/rate/stats/mDNS/output clock and fanout remain unchanged on failed native commit");
    REQUIRE(audit_count(f.path) == audits, "native audit and retention share rollback with cache acceptance");
    if (strcmp(mode, "stale")) REQUIRE(current(&f), "rolled-back authority fault leaves original source usable");
    if (!strcmp(mode, "stale")) snprintf(f.guard.channel_id, sizeof(f.guard.channel_id), "catalog-replacement");
    else REQUIRE(execute(f.path, "DROP TRIGGER IF EXISTS fail_catalog_audit; DROP TRIGGER IF EXISTS fail_catalog_prune; DROP TRIGGER IF EXISTS change_catalog_authority") == 0,
        "remove only the injected fixture fault");
    REQUIRE(report(&f, !strcmp(mode, "stale") ? 1 : 2, 7, "Recovered Local") == 0
        && snapshot(&f, &after, new_mdns) == 0, "valid original/replacement source can retry after failed acceptance");
    REQUIRE(after.report_revision == (!strcmp(mode, "stale") ? 1 : 2)
        && after.rate.count == (!strcmp(mode, "stale") ? 1U : 2U) && after.catalog_revision == before.catalog_revision + 1
        && after.stats[0].bytes_in == 7 && !strcmp(new_mdns, "Recovered Local") && f.sent == sent + 1
        && peer_catalog_reserved_revisions == 0 && audit_count(f.path) == (audits == 80 ? 80 : audits + 1),
        "retry uses one wire revision/audit, no leaked reservation or failed raw counter/rate; new physical source starts at raw1");
    failed = 0;
done:
    if (thread_started) {
        pthread_mutex_lock(&f.lock); f.resume = 1; pthread_cond_broadcast(&f.condition); pthread_mutex_unlock(&f.lock);
        pthread_join(thread, NULL);
    }
    cleanup(&f);
    printf("%s catalog source %s native epoch/commit and cache cohort\n", failed ? "FAIL" : "PASS", mode);
    return failed;
#undef REQUIRE
}
static int policy_scenario(const char *mode)
{
    fixture f; int failed = 1; pm_catalog before = {0}, after = {0}; char first[81], last[81], sql[1024];
#define REQUIRE(c, text) do { if (!(c)) { fprintf(stderr, "FAIL catalog policy %s: %s\n", mode, text); goto done; } } while (0)
    REQUIRE(prepare(&f) == 0 && snapshot(&f, &before, first) == 0, "initial real policy/cache cohort");
    const char *update = !strcmp(mode, "sharing") ? "UPDATE peer_mesh_service_sharing SET enabled=0;"
        : !strcmp(mode, "mdns") ? "UPDATE peer_mesh_service_sharing SET mdns_import_enabled=0;"
        : !strcmp(mode, "device") ? "UPDATE peer_mesh_device SET enabled=0;"
        : "UPDATE client_account SET owner_username='bob'; UPDATE peer_mesh_device SET owner_username='bob';";
    snprintf(sql, sizeof(sql), "CREATE TRIGGER mutate_catalog_policy AFTER INSERT ON peer_mesh_service_audit WHEN NEW.action='service-report' BEGIN %s END", update);
    REQUIRE(execute(f.path, sql) == 0, "actual audit-trigger policy mutation, not a fake snapshot");
    int sent = f.sent;
    int rc = report(&f, 100, 900, "Must Roll Back");
    REQUIRE(snapshot(&f, &after, last) == 0, "observe committed cache only");
    fprintf(stderr, "OBSERVATION catalog policy %s rc=%d raw=%lld stats=%lld mdns=%s\n", mode, rc, after.report_revision, after.stats[0].bytes_in, last);
    REQUIRE(rc == -1 && after.report_revision == before.report_revision && after.catalog_revision == before.catalog_revision
        && after.created_at_millis == before.created_at_millis
        && !memcmp(&after.rate, &before.rate, sizeof(after.rate)) && after.stats[0].bytes_in == 3
        && !strcmp(first, last) && after.pending_report == NULL && peer_catalog_reserved_revisions == 0
        && audit_count(f.path) == 1 && f.sent == sent && current(&f), "changed policy rolls back audit/private stage without retiring original CONTROL");
    st_storage_client client; st_storage_peer_mesh_device device; st_storage_peer_mesh_service_sharing sharing;
    REQUIRE(st_storage_get_client(f.path, f.publisher.id, &client) == 0 && !strcmp(client.owner_username, "alice")
        && st_storage_get_peer_mesh_device_by_client(f.path, client.tenant_id, client.id, &device) == 0 && device.enabled
        && st_storage_get_peer_mesh_service_sharing(f.path, client.tenant_id, &sharing) == 0 && sharing.enabled && sharing.mdns_import_enabled,
        "the actual native policy is also restored by rollback");
    failed = 0;
done:
    cleanup(&f); printf("%s catalog current policy %s postcheck\n", failed ? "FAIL" : "PASS", mode); return failed;
#undef REQUIRE
}

static int reservations(void)
{
    fixture f; int failed = 1; pm_catalog before = {0}, after = {0}; char first[81], last[81];
    pm_report_lease lease = {0}, conflict = {0}, fresh = {0};
#define REQUIRE(c, text) do { if (!(c)) { fprintf(stderr, "FAIL catalog reservations: %s\n", text); goto done; } } while (0)
    REQUIRE(prepare(&f) == 0 && snapshot(&f, &before, first) == 0, "initial committed cohort");
    lease.runtime = &f.runtime; lease.revision = 2;
    REQUIRE(pm_report_prepare(&lease, &f.publisher) == 0 && peer_catalog_reserved_revisions == 1,
        "reserve bounded cell and future output budget before native writer");
    lease.staged.report_revision = 999; lease.staged.stats[0].bytes_in = 999;
    REQUIRE(snapshot(&f, &after, last) == 0 && after.report_revision == 1 && after.stats[0].bytes_in == 3
        && !strcmp(first, last), "readers see committed data while private stage changes");
    conflict.runtime = &f.runtime; conflict.revision = 3;
    REQUIRE(pm_report_prepare(&conflict, &f.publisher) == -1 && conflict.slot == NULL
        && peer_catalog_reserved_revisions == 1, "conflicting report is nonblocking and owns no extra reservation");
    st_peer_mesh_control_transition *transition = NULL;
    REQUIRE(st_peer_mesh_control_connected_prepare(&f.runtime, f.publisher.client_name, &transition) == -1
        && transition == NULL && peer_control_withdrawal_count == 0, "reconnect does not erase an owned stage");
    pm_client_deletion deletion = {.client=f.publisher};
    REQUIRE(pm_prepare_deleted_catalogs(&deletion) == -1 && !deletion.prepared && deletion.withdrawals == NULL,
        "deletion remains retryable without clearing cache ahead of in-flight acceptance");
    pthread_mutex_lock(&peer_catalog_lock); lease.slot->expires_at = time(NULL) - 1; pthread_mutex_unlock(&peer_catalog_lock);
    REQUIRE(st_peer_mesh_expire_catalogs(&f.runtime) == 0 && lease.slot->pending_report == &lease,
        "expiry cannot reclaim a reserved cell");
    pthread_mutex_lock(&peer_catalog_lock); lease.slot->expires_at = before.expires_at; pthread_mutex_unlock(&peer_catalog_lock);
    pm_report_abort(&lease);
    REQUIRE(peer_catalog_reserved_revisions == 0 && snapshot(&f, &after, last) == 0 && after.pending_report == NULL
        && after.report_revision == 1 && after.stats[0].bytes_in == 3, "abort frees only reservation, not committed cohort");
    /* Metadata-only trusted reservation, as in the existing reconnect exhaustion tests. */
    st_peer_mesh_runtime trusted = f.runtime; trusted.control_source = NULL; trusted.publisher_session_id += 1000;
    fresh.runtime = &trusted; fresh.revision = 1;
    REQUIRE(pm_report_prepare(&fresh, &f.publisher) == 0 && !fresh.slot->in_use, "new empty slot remains unpublished");
    REQUIRE(st_peer_mesh_control_connected_prepare(&trusted, f.publisher.client_name, &transition) == -1 && transition == NULL
        && pm_prepare_deleted_catalogs(&deletion) == -1, "new pending key is visible to conflicting mutators even before in_use");
    pm_report_abort(&fresh);
    long long saved_sequence = peer_catalog_sequence;
    peer_catalog_sequence = LLONG_MAX - 1;
    lease.runtime = &f.runtime; lease.revision = 2;
    REQUIRE(pm_report_prepare(&lease, &f.publisher) == 0 && peer_catalog_reserved_revisions == 1
        && pm_next_catalog_revision_locked(0) == 0 && peer_catalog_sequence == LLONG_MAX - 1,
        "unrelated output cannot consume the report's reserved final wire revision");
    pm_report_abort(&lease);
    REQUIRE(pm_next_catalog_revision_locked(0) == LLONG_MAX && report(&f, 2, 999, "Exhausted") == -1
        && snapshot(&f, &after, last) == 0 && after.report_revision == 1 && after.stats[0].bytes_in == 3
        && audit_count(f.path) == 1 && after.pending_report == NULL && peer_catalog_reserved_revisions == 0,
        "clock exhaustion rejects before native acceptance and leaves committed cohort/audit intact");
    peer_catalog_sequence = saved_sequence;
    size_t live = 0;
    for (size_t i = 0; i < ST_PEER_MESH_MAX_CATALOGS; ++i) {
        REQUIRE(peer_catalogs[i].pending_report == NULL, "no dangling stack-owned stage");
        live += peer_catalogs[i].in_use != 0;
    }
    REQUIRE(live == 1 && peer_catalog_reserved_revisions == 0, "aborted empty reservation consumes no permanent table/clock capacity");
    failed = 0;
done:
    pm_report_abort(&lease); pm_report_abort(&fresh); pm_report_abort(&conflict);
    cleanup(&f); printf("%s private catalog staging, mutation conflicts, expiry and bounded reservation reclamation\n", failed ? "FAIL" : "PASS"); return failed;
#undef REQUIRE
}
int main(int argc, char **argv)
{
    setenv("SPECUS_PEER_MESH_ENABLED", "true", 1);
    if (argc == 2) return scenario(argv[1]);
    if (argc != 1) return 2;
    return scenario("stale") + scenario("audit-insert") + scenario("audit-prune") + scenario("trigger")
        + policy_scenario("sharing") + policy_scenario("mdns") + policy_scenario("device") + policy_scenario("owner")
        + reservations() ? 1 : 0;
}
