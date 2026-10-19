#define _POSIX_C_SOURCE 200809L
#include "crypto.h"
#include "instant.h"
#include "instant_reference_cases.h"
#include "storage.h"
#include <sqlite3.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define CHECK(ok) do { if (!(ok)) { fprintf(stderr, "peer expiry failed line %d: %s\n", __LINE__, #ok); exit(1); } } while (0)
static const time_t seconds = 1789473600;
static long nanos;
static int clock_calls, advance_at_call;
static char path[] = "/tmp/specus-peer-expiry-XXXXXX";
static st_storage_client source, target;

int __real_clock_gettime(clockid_t id, struct timespec *out);
int __wrap_clock_gettime(clockid_t id, struct timespec *out)
{
    if (id != CLOCK_REALTIME) return __real_clock_gettime(id, out);
    if (++clock_calls == advance_at_call) nanos = 500000200L;
    out->tv_sec = seconds; out->tv_nsec = nanos; return 0;
}
/* The old SQL datetime('now') and the new C clock see the same instant. This keeps the
 * negative control about expiry semantics, not about two different wall clocks. */
static int sqlite_now64(sqlite3_vfs *vfs, sqlite3_int64 *out)
{
    (void)vfs;
    *out = 210866760000000LL + (sqlite3_int64)seconds * 1000 + nanos / 1000000;
    return SQLITE_OK;
}
static int sqlite_now(sqlite3_vfs *vfs, double *out)
{
    sqlite3_int64 value; sqlite_now64(vfs, &value); *out = (double)value / 86400000.0; return SQLITE_OK;
}
static void cleanup(void) { unlink(path); }
static long long scalar(sqlite3 *db, const char *sql)
{
    sqlite3_stmt *stmt = NULL;
    CHECK(sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW);
    long long value = sqlite3_column_int64(stmt, 0);
    CHECK(sqlite3_step(stmt) == SQLITE_DONE); sqlite3_finalize(stmt); return value;
}
static sqlite3 *open_fixture(void)
{
    sqlite3 *db = NULL; CHECK(sqlite3_open(path, &db) == SQLITE_OK); return db;
}
static void prepare_rows(int fractional, int legacy)
{
    unlink(path);
    nanos = fractional ? 500000000L : 0L;
    char current[ST_INSTANT_CAPACITY];
    CHECK(st_instant_now(current) == 0 && st_instant_public(current, current, sizeof(current)) == 0
        && strcmp(current, cutoffs[fractional]) == 0);
    CHECK(st_storage_init(path, 0) == 0);
    CHECK(st_storage_upsert_client(path, 0, "t1", "source", "alice", 1, 60, &source) == 0);
    CHECK(st_storage_upsert_client(path, 0, "t1", "target", "alice", 1, 60, &target) == 0);
    sqlite3 *db = open_fixture();
    CHECK(scalar(db, "SELECT CAST(strftime('%s','now') AS INTEGER)") == (long long)seconds);
    CHECK(sqlite3_exec(db, "DELETE FROM peer_mesh_session", NULL, NULL, NULL) == SQLITE_OK);
    uint8_t digest[ST_SHA256_LEN]; char hash[ST_SHA256_HEX_LEN + 1U];
    st_sha256((const uint8_t *)"probe-token", 11U, digest); st_hex_encode(digest, sizeof(digest), hash);
    sqlite3_stmt *stmt = NULL;
    CHECK(sqlite3_prepare_v2(db, "INSERT INTO peer_mesh_session(id,tenant_id,source_client_id,source_client_name,"
        "target_client_id,target_client_name,status,token_hash,expires_at,closed_at) "
        "VALUES(?1,?2,?3,'source',?4,'target',?5,?6,?7,?8)", -1, &stmt, NULL) == SQLITE_OK);
    for (int id = 1; id <= 11; ++id) {
        const char *expiry = id <= 7 ? values[fractional][id - 1] : id == 9 ? "invalid-time" : id == 10 ? "" : values[fractional][0];
        char normalized[ST_INSTANT_CAPACITY];
        if (!legacy && id != 9 && id != 10) { CHECK(st_instant_normalize(expiry, normalized) == 0); expiry = normalized; }
        CHECK(sqlite3_bind_int(stmt, 1, id) == SQLITE_OK
            && sqlite3_bind_text(stmt, 2, id == 11 ? "foreign" : "t1", -1, SQLITE_STATIC) == SQLITE_OK
            && sqlite3_bind_int64(stmt, 3, source.id) == SQLITE_OK && sqlite3_bind_int64(stmt, 4, target.id) == SQLITE_OK
            && sqlite3_bind_text(stmt, 5, id == 8 ? "CLOSED" : "ACTIVE", -1, SQLITE_STATIC) == SQLITE_OK
            && sqlite3_bind_text(stmt, 6, hash, -1, SQLITE_TRANSIENT) == SQLITE_OK
            && sqlite3_bind_text(stmt, 7, expiry, -1, SQLITE_TRANSIENT) == SQLITE_OK
            && sqlite3_bind_text(stmt, 8, id == 8 ? "preserved-close" : "", -1, SQLITE_STATIC) == SQLITE_OK
            && sqlite3_step(stmt) == SQLITE_DONE && sqlite3_reset(stmt) == SQLITE_OK && sqlite3_clear_bindings(stmt) == SQLITE_OK);
    }
    sqlite3_finalize(stmt); sqlite3_close(db);
    CHECK(st_storage_init(path, 0) == 0 && st_storage_init(path, 0) == 0);
}
static int live(int id) { return (id >= 5 && id <= 7) || id == 9 || id == 10; }
static void run(int mode, int fractional, int legacy)
{
    prepare_rows(fractional, legacy);
    st_storage_peer_mesh_session rows[12]; size_t count = 0U; long long total = 0;
    if (mode == 0) {
        CHECK(st_storage_page_peer_mesh_sessions_visible(path, "t1", "alice", 1, 1, 0, 12, rows, 12, &count, &total) == 0);
        CHECK(total == 5 && count == 5);
    } else if (mode == 1) {
        st_storage_peer_mesh_stats stats;
        CHECK(st_storage_peer_mesh_stats_visible(path, "t1", "alice", 1, &stats) == 0);
        st_storage_peer_mesh_stats_free(&stats);
    } else if (mode == 6) {
        CHECK(st_storage_open_peer_mesh_sessions_between(path, "t1", source.id, target.id, rows, 12, &count) == 0 && count == 5);
    } else for (int id = 1; id <= 10; ++id) {
        int expected = live(id);
        if (mode == 2) {
            CHECK(st_storage_report_peer_mesh_session(path, &source, id, "RELAY", "ACTIVE", 10, NULL, NULL, 11, 13, 0, &rows[0]) == 0);
            CHECK(rows[0].direct_bytes == (expected ? 11 : 0) && rows[0].relay_bytes == (expected ? 13 : 0));
        } else if (mode == 3 || mode == 4) {
            int result = st_storage_authorize_peer_mesh_relay(path, id, source.id, target.id, mode == 3 ? 17 : 0, mode == 3);
            CHECK(result == expected);
        } else CHECK(st_storage_verify_peer_mesh_probe(path, id, source.id, target.id, "probe-token") == expected);
    }
    if (mode == 0 || mode == 6) for (size_t i = 0; i < count; ++i) {
        CHECK(live((int)rows[i].id));
        if (rows[i].id <= 7) CHECK(strcmp(rows[i].expires_at, values[fractional][rows[i].id - 1]) == 0);
    }
    sqlite3 *db = open_fixture();
    CHECK(scalar(db, "SELECT count(*) FROM peer_mesh_session WHERE id<=4 AND status='CLOSED'") == 4);
    CHECK(scalar(db, "SELECT count(*) FROM peer_mesh_session WHERE id IN(5,6,7,9,10,11) AND status='ACTIVE'") == 6);
    CHECK(scalar(db, "SELECT count(*) FROM peer_mesh_session WHERE id=8 AND closed_at='preserved-close'") == 1);
    sqlite3_close(db);
    printf("peer expiry: entry=%d fractional=%d legacy=%d closes <=now, preserves future/invalid/closed/foreign rows\n", mode, fractional, legacy);
}
static void writer(int fractional)
{
    prepare_rows(fractional, 0);
    st_storage_peer_mesh_device device;
    CHECK(st_storage_update_peer_mesh_device_enabled(path, &source, 1, &device) == 0
        && st_storage_update_peer_mesh_device_enabled(path, &target, 1, &device) == 0);
    st_storage_peer_mesh_session session;
    CHECK(st_storage_create_peer_mesh_session(path, &source, &target, "DIRECT", "test-token-hash", 45, &session) == 0);
    CHECK(strcmp(session.expires_at, fractional ? "2026-09-15T12:00:45.500Z" : "2026-09-15T12:00:45Z") == 0);
    CHECK(strcmp(session.started_at, cutoffs[fractional]) == 0);
    sqlite3 *db = open_fixture();
    CHECK(scalar(db, fractional
        ? "SELECT count(*) FROM peer_mesh_session WHERE id=12 AND expires_at='2026-09-15T12:00:45.5000000Z'"
        : "SELECT count(*) FROM peer_mesh_session WHERE id=12 AND expires_at='2026-09-15T12:00:45.0000000Z'") == 1);
    CHECK(st_storage_create_peer_mesh_session(path, &source, &target, "DIRECT", "test", LLONG_MAX, NULL) == -1);
    CHECK(scalar(db, "SELECT count(*) FROM peer_mesh_session") == 12);
    sqlite3_close(db);
    printf("peer expiry: writer fractional=%d stores seven digits, returns public instant, preserves45s and rejects overflowing TTL\n", fractional);
}
static void migration(int fractional)
{
    prepare_rows(fractional, 1);
    sqlite3 *db = open_fixture();
    CHECK(scalar(db, "SELECT count(*) FROM peer_mesh_session WHERE length(expires_at)=28") == 9);
    CHECK(scalar(db, fractional
        ? "SELECT count(*) FROM peer_mesh_session WHERE id=4 AND expires_at='2026-09-15T12:00:00.5000000Z'"
        : "SELECT count(*) FROM peer_mesh_session WHERE id=4 AND expires_at='2026-09-15T12:00:00.0000000Z'") == 1);
    CHECK(scalar(db, "SELECT count(*) FROM peer_mesh_session WHERE (id=9 AND expires_at='invalid-time') OR (id=10 AND expires_at='')") == 2);
    CHECK(sqlite3_exec(db, "UPDATE peer_mesh_session SET expires_at='2026-09-15 12:00:00.500' WHERE id=4", NULL, NULL, NULL) == SQLITE_OK);
    sqlite3_close(db);
    CHECK(st_storage_init(path, 0) == 0);
    db = open_fixture();
    CHECK(scalar(db, "SELECT count(*) FROM peer_mesh_session WHERE id=4 AND expires_at='2026-09-15T12:00:00.5000000Z'") == 1);
    sqlite3_close(db);
    printf("peer expiry: migration fractional=%d actual repeated initialization normalizes ISO/SQLite rows and retains invalid/empty values\n", fractional);
}
static void write_boundary(int mode)
{
    prepare_rows(1, 0);
    sqlite3 *db = open_fixture();
    CHECK(sqlite3_exec(db, "UPDATE peer_mesh_session SET status='NEGOTIATING',expires_at='2026-09-15T12:00:00.5000001Z' WHERE id=6", NULL, NULL, NULL) == SQLITE_OK);
    sqlite3_close(db);
    clock_calls = 0; advance_at_call = 2;
    if (mode == 0) {
        st_storage_peer_mesh_session row;
        CHECK(st_storage_report_peer_mesh_session(path, &source, 6, "RELAY", "ACTIVE", 10, NULL, NULL, 11, 13, 0, &row) == 0);
        CHECK(strcmp(row.status, "NEGOTIATING") == 0 && row.direct_bytes == 0 && row.relay_bytes == 0);
    } else CHECK(st_storage_authorize_peer_mesh_relay(path, 6, source.id, target.id, mode == 1 ? 17 : 0, mode == 1) == 0);
    CHECK(clock_calls == 2); advance_at_call = 0;
    db = open_fixture();
    CHECK(scalar(db, "SELECT count(*) FROM peer_mesh_session WHERE id=6 AND status='NEGOTIATING' AND direct_bytes=0 AND relay_bytes=0") == 1);
    sqlite3_close(db);
    CHECK(st_storage_verify_peer_mesh_probe(path, 6, source.id, target.id, "probe-token") == 0);
    printf("peer expiry: conditional write mode=%d crosses100ns boundary after read, refuses activation/accounting, subsequent probe refuses\n", mode);
}
int main(int argc, char **argv)
{
    CHECK(setenv("SPECUS_DB_SEED_DEMO_CLIENT", "0", 1) == 0);
    CHECK(atexit(cleanup) == 0); int fd = mkstemp(path); CHECK(fd >= 0); close(fd);
    sqlite3_vfs fixed_vfs = *sqlite3_vfs_find(NULL);
    fixed_vfs.zName = "peer-expiry-reference-clock";
    fixed_vfs.xCurrentTime = sqlite_now; fixed_vfs.xCurrentTimeInt64 = sqlite_now64;
    CHECK(sqlite3_vfs_register(&fixed_vfs, 1) == SQLITE_OK);
    int first = argc > 1 ? atoi(argv[1]) : 0, last = argc > 1 ? first : 9;
    for (int mode = first; mode <= last; ++mode) {
        if (mode == 9) for (int operation = 0; operation < 3; ++operation) write_boundary(operation);
        else for (int fractional = 0; fractional < 2; ++fractional) {
            if (mode == 7) writer(fractional);
            else if (mode == 8) migration(fractional);
            else for (int legacy = 0; legacy < 2; ++legacy) run(mode, fractional, legacy);
        }
    }
    CHECK(sqlite3_vfs_unregister(&fixed_vfs) == SQLITE_OK);
    puts("peer expiry:28 entry boundary matrices,2 writer cases,2 migration cases,3 conditional-write races passed");
    return 0;
}
