/* Private token-cache assertions use the real Peer implementation, not production test hooks. */
#include "../src/peer_mesh.c"
#include <sqlite3.h>
#include <stdarg.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL source storage line %d: %s\n", __LINE__, #c); return 1; } } while (0)
typedef struct {
    char path[320];
    st_storage_client source, target;
    st_storage_control_source guard;
    long long peer_id;
} fixture;

static int sql(fixture *f, const char *format, ...)
{
    va_list args; va_start(args, format); char *query = sqlite3_vmprintf(format, args); va_end(args);
    sqlite3 *db = NULL; int rc = sqlite3_open(f->path, &db);
    if (rc == SQLITE_OK) rc = sqlite3_exec(db, query, NULL, NULL, NULL);
    if (rc != SQLITE_OK) fprintf(stderr, "fixture SQL failure: %s\n", sqlite3_errmsg(db));
    sqlite3_free(query); sqlite3_close(db); return rc == SQLITE_OK ? 0 : -1;
}
static long long scalar(fixture *f, const char *query)
{
    sqlite3 *db = NULL; sqlite3_stmt *stmt = NULL; long long value = -1;
    if (sqlite3_open(f->path, &db) == SQLITE_OK && sqlite3_prepare_v2(db, query, -1, &stmt, NULL) == SQLITE_OK
        && sqlite3_step(stmt) == SQLITE_ROW) value = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt); sqlite3_close(db); return value;
}
static int zeros(const void *value, size_t length)
{
    const unsigned char *bytes = value;
    for (size_t i = 0; i < length; ++i) if (bytes[i]) return 0;
    return 1;
}
static int write_one(fixture *f, const st_storage_control_source *guard, int kind, int want_success)
{
    st_storage_peer_mesh_device device; memset(&device, 0xa5, sizeof(device));
    st_storage_peer_mesh_session session; memset(&session, 0xa5, sizeof(session));
    st_storage_peer_mesh_egress_activity activity = {0};
    snprintf(activity.tenant_id, sizeof(activity.tenant_id), "%s", f->source.tenant_id);
    snprintf(activity.egress_client_name, sizeof(activity.egress_client_name), "untrusted-name");
    activity.egress_client_id = f->source.id; activity.session_id = f->guard.session_id;
    activity.revision = 100; activity.active_flows = 9;
    snprintf(activity.reported_at, sizeof(activity.reported_at), "2026-10-16T00:00:00Z");
    int rc;
    switch (kind) {
    case 0: rc = st_storage_ensure_peer_mesh_device_from_control(f->path, guard, &f->source, &device); break;
    case 1: rc = st_storage_update_peer_mesh_device_report_from_control(f->path, guard, &f->source,
        NULL, "CONE", NULL, NULL, NULL, "127.0.0.1:9", "TUN", "guard0", "UP", NULL, &device); break;
    case 2: rc = st_storage_create_peer_mesh_session_from_control(f->path, guard, &f->source, &f->target,
        "DIRECT", "peer-hash", 600, &session); break;
    case 3: rc = st_storage_report_peer_mesh_session_from_control(f->path, guard, &f->source, f->peer_id,
        "DIRECT", "ACTIVE", 8, "local", "remote", 5, 7, 0, &session); break;
    default: rc = st_storage_upsert_peer_mesh_egress_activity_from_control(f->path, guard, &activity); break;
    }
    if ((rc == 0) != want_success) { fprintf(stderr, "write kind %d rc=%d expected success=%d\n", kind, rc, want_success); return 1; }
    if (!want_success && ((kind < 2 && !zeros(&device, sizeof(device)))
        || ((kind == 2 || kind == 3) && !zeros(&session, sizeof(session))))) return 1;
    return 0;
}
static int deny_all(fixture *f, const st_storage_control_source *guard)
{
    CHECK(sql(f, "DELETE FROM write_touch") == 0);
    for (int kind = 0; kind < 5; ++kind) CHECK(write_one(f, guard, kind, 0) == 0);
    CHECK(scalar(f, "SELECT COUNT(*) FROM write_touch") == 0);
    return 0;
}
static int fixture_init(fixture *f)
{
    CHECK(st_storage_init(f->path, 0) == 0);
    CHECK(st_storage_upsert_client(f->path, 0, "guard-tenant", "guard-source", "alice", 1, 60, &f->source) == 0);
    CHECK(st_storage_upsert_client(f->path, 0, "guard-tenant", "guard-target", "alice", 1, 60, &f->target) == 0);
    st_storage_client_credential credential;
    CHECK(st_storage_insert_client_credential(f->path, "guard-tenant", "alice", "guard-key", "guard-secret", 1, 10, &credential) == 0);
    st_storage_client_session native = {0};
    native.credential_id = credential.id; native.client_id = f->source.id; native.identity_id = f->source.id;
    snprintf(native.tenant_id, sizeof(native.tenant_id), "guard-tenant");
    snprintf(native.client_name, sizeof(native.client_name), "guard-source");
    memset(native.token_hash, 'a', 64); native.token_hash[64] = '\0';
    snprintf(native.status, sizeof(native.status), "HTTP_AUTHENTICATED");
    snprintf(native.machine_fingerprint, sizeof(native.machine_fingerprint), "guard-machine");
    snprintf(native.expires_at, sizeof(native.expires_at), "2999-01-01T00:00:00Z");
    CHECK(st_storage_create_client_session(f->path, &native, &native) == 0);
    CHECK(st_storage_mark_client_session_online(f->path, native.id, "physical-A", "127.0.0.1:9", "2026-10-16T00:00:00Z") == 0);
    f->guard.client_id = f->source.id; f->guard.session_id = native.id;
    snprintf(f->guard.tenant_id, sizeof(f->guard.tenant_id), "guard-tenant");
    snprintf(f->guard.client_name, sizeof(f->guard.client_name), "guard-source");
    snprintf(f->guard.channel_id, sizeof(f->guard.channel_id), "physical-A");
    snprintf(f->guard.token_hash, sizeof(f->guard.token_hash), "%s", native.token_hash);
    CHECK(st_storage_update_peer_mesh_device_enabled(f->path, &f->source, 1, NULL) == 0);
    CHECK(st_storage_update_peer_mesh_device_enabled(f->path, &f->target, 1, NULL) == 0);
    st_storage_peer_mesh_session session;
    CHECK(st_storage_create_peer_mesh_session(f->path, &f->source, &f->target, "DIRECT", "peer-hash", 600, &session) == 0);
    f->peer_id = session.id;
    CHECK(sql(f, "CREATE TABLE write_touch(n INTEGER);"
        "CREATE TRIGGER touch_device_insert AFTER INSERT ON peer_mesh_device BEGIN INSERT INTO write_touch VALUES(1); END;"
        "CREATE TRIGGER touch_device_update AFTER UPDATE ON peer_mesh_device BEGIN INSERT INTO write_touch VALUES(1); END;"
        "CREATE TRIGGER touch_peer_insert AFTER INSERT ON peer_mesh_session BEGIN INSERT INTO write_touch VALUES(1); END;"
        "CREATE TRIGGER touch_peer_update AFTER UPDATE ON peer_mesh_session BEGIN INSERT INTO write_touch VALUES(1); END;"
        "CREATE TRIGGER touch_egress_insert AFTER INSERT ON peer_mesh_egress_activity BEGIN INSERT INTO write_touch VALUES(1); END;"
        "CREATE TRIGGER touch_egress_update AFTER UPDATE ON peer_mesh_egress_activity BEGIN INSERT INTO write_touch VALUES(1); END;") == 0);
    return 0;
}
static int matrix(fixture *f)
{
    CHECK(st_storage_control_source_validate(f->path, &f->guard) == 0);
    for (int kind = 0; kind < 5; ++kind) CHECK(write_one(f, &f->guard, kind, 1) == 0);
    CHECK(scalar(f, "SELECT COUNT(*) FROM peer_mesh_egress_activity WHERE egress_client_name='guard-source'") == 1);
    CHECK(deny_all(f, NULL) == 0);
    for (int variant = 0; variant < 9; ++variant) {
        st_storage_control_source wrong = f->guard;
        switch (variant) {
        case 0: wrong.client_id++; break; case 1: wrong.session_id += 100; break;
        case 2: wrong.tenant_id[0] = 'X'; break; case 3: wrong.client_name[0] = 'X'; break;
        case 4: wrong.channel_id[0] = 'X'; break; case 5: wrong.token_hash[0] = 'X'; break;
        case 6: memset(wrong.channel_id, 'X', sizeof(wrong.channel_id)); break;
        case 7: wrong.token_hash[63] = '\0'; break;
        default: memset(wrong.tenant_id, 'X', sizeof(wrong.tenant_id)); break;
        }
        CHECK(st_storage_control_source_validate(f->path, &wrong) == ST_STORAGE_CONTROL_SOURCE_RETIRED);
        CHECK(deny_all(f, &wrong) == 0);
    }
    const char *mutations[] = {
        "UPDATE specus_client_session SET channel_id='physical-B'", "UPDATE specus_client_session SET status='OFFLINE'",
        "UPDATE specus_client_session SET expires_at='2000-01-01T00:00:00Z'", "UPDATE client_account SET enabled=0",
        "UPDATE client_account SET tenant_id='other'", "UPDATE client_account SET client_name=client_name||'-renamed'",
        "UPDATE specus_client_credential SET enabled=0", "UPDATE specus_client_credential SET tenant_id='other'",
        "UPDATE specus_client_session SET token_hash='other'", "UPDATE specus_client_session SET tenant_id='other'"
    };
    for (size_t i = 0; i < sizeof(mutations) / sizeof(mutations[0]); ++i) {
        CHECK(sql(f, "%s", mutations[i]) == 0);
        int expected = i == 3 || i == 6 ? ST_STORAGE_CONTROL_SOURCE_UNAVAILABLE : ST_STORAGE_CONTROL_SOURCE_RETIRED;
        CHECK(st_storage_control_source_validate(f->path, &f->guard) == expected);
        CHECK(deny_all(f, &f->guard) == 0);
        CHECK(sql(f, "UPDATE specus_client_session SET channel_id='physical-A',status='NETTY_ONLINE',"
            "expires_at='2999-01-01T00:00:00Z',token_hash='%q',tenant_id='guard-tenant';"
            "UPDATE client_account SET enabled=1,tenant_id='guard-tenant',client_name=CASE rowid WHEN %lld THEN 'guard-source' ELSE 'guard-target' END;"
            "UPDATE specus_client_credential SET enabled=1,tenant_id='guard-tenant'", f->guard.token_hash, f->source.id) == 0);
        CHECK(st_storage_control_source_validate(f->path, &f->guard) == 0);
        CHECK(write_one(f, &f->guard, (int)(i % 5), 1) == 0);
    }
    puts("PASS all five native writers: valid, NULL/malformed/mismatched source, replacement, status/expiry/account/credential loss; no persisted touch and cleared outputs");
    return 0;
}
static int rollback_and_token(fixture *f)
{
    const char *tables[] = {"peer_mesh_device", "peer_mesh_device", "peer_mesh_session", "peer_mesh_session", "peer_mesh_egress_activity"};
    const char *events[] = {"UPDATE", "UPDATE", "INSERT", "UPDATE", "UPDATE"};
    for (int kind = 0; kind < 5; ++kind) {
        CHECK(sql(f, "CREATE TRIGGER change_authority AFTER %s ON %s BEGIN UPDATE specus_client_session SET channel_id='trigger-channel'; END", events[kind], tables[kind]) == 0);
        CHECK(sql(f, "DELETE FROM write_touch") == 0);
        CHECK(write_one(f, &f->guard, kind, 0) == 0);
        CHECK(st_storage_control_source_validate(f->path, &f->guard) == 0);
        CHECK(scalar(f, "SELECT COUNT(*) FROM write_touch") == 0);
        CHECK(sql(f, "DROP TRIGGER change_authority") == 0);
        CHECK(write_one(f, &f->guard, kind, 1) == 0);
    }
    st_peer_mesh_runtime runtime = {0}; runtime.database_path = f->path; runtime.control_source = &f->guard;
    char message[80], token[64]; snprintf(message, sizeof(message), "{\"sessionId\":%lld}", f->peer_id);
    pm_remember_session_token(f->peer_id, "surviving-grant");
    CHECK(sql(f, "UPDATE specus_client_session SET channel_id='physical-B'") == 0);
    CHECK(pm_handle_report(&runtime, &f->source, "close", message) == ST_STORAGE_CONTROL_SOURCE_RETIRED);
    CHECK(pm_session_token_for(f->peer_id, token) && !strcmp(token, "surviving-grant"));
    snprintf(f->guard.channel_id, sizeof(f->guard.channel_id), "physical-B");
    CHECK(sql(f, "CREATE TRIGGER reject_close BEFORE UPDATE ON peer_mesh_session BEGIN SELECT RAISE(ABORT,'close denied'); END") == 0);
    CHECK(pm_handle_report(&runtime, &f->source, "close", message) != 0 && pm_session_token_for(f->peer_id, token));
    CHECK(scalar(f, "SELECT COUNT(*) FROM peer_mesh_session WHERE closed_at IS NOT NULL") == 0);
    CHECK(sql(f, "DROP TRIGGER reject_close") == 0);
    CHECK(pm_handle_report(&runtime, &f->source, "close", message) == 0 && !pm_session_token_for(f->peer_id, token));
    puts("PASS transaction-local authority change rolls back all five writers; stale/failing close preserves token; replacement successful close removes it");
    return 0;
}
int main(void)
{
    char dir[] = "/tmp/specus-control-source-XXXXXX";
    CHECK(mkdtemp(dir) != NULL); fixture f = {0}; snprintf(f.path, sizeof(f.path), "%s/specus.db", dir);
    int failed = fixture_init(&f) || matrix(&f) || rollback_and_token(&f);
    if (failed) fprintf(stderr, "fixture preserved: %s\n", dir);
    else { unlink(f.path); rmdir(dir); }
    return failed;
}
