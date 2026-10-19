#define _POSIX_C_SOURCE 200809L
#include "instant.h"
#include "instant_reference_cases.h"
#include "json.h"
#include "public_room.h"
#include "storage.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define CHECK(ok) do { if (!(ok)) { fprintf(stderr, "pairing expiry failed line %d: %s\n", __LINE__, #ok); exit(1); } } while (0)
static const time_t seconds = 1789473600;
static long nanos;
static int clock_calls, advance_at_call;
static char database[] = "/tmp/specus-pairing-expiry-XXXXXX";
time_t __wrap_time(time_t *out) { if (out != NULL) *out = seconds; return seconds; }
int __real_clock_gettime(clockid_t id, struct timespec *out);
int __wrap_clock_gettime(clockid_t id, struct timespec *out)
{
    if (id != CLOCK_REALTIME) return __real_clock_gettime(id, out);
    if (++clock_calls == advance_at_call) nanos = 500000200L;
    out->tv_sec = seconds; out->tv_nsec = nanos; return 0;
}
static int sqlite_now64(sqlite3_vfs *vfs, sqlite3_int64 *out)
{
    (void)vfs; *out = 210866760000000LL + (sqlite3_int64)seconds * 1000 + nanos / 1000000; return SQLITE_OK;
}
static int sqlite_now(sqlite3_vfs *vfs, double *out)
{
    sqlite3_int64 value; sqlite_now64(vfs, &value); *out = (double)value / 86400000.0; return SQLITE_OK;
}
static void cleanup(void) { st_public_room_reset_for_tests(); unlink(database); }
static sqlite3 *open_db(void) { sqlite3 *db = NULL; CHECK(sqlite3_open(database, &db) == SQLITE_OK); return db; }
static long long scalar(sqlite3 *db, const char *sql)
{
    sqlite3_stmt *stmt = NULL;
    CHECK(sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW);
    long long result = sqlite3_column_int64(stmt, 0);
    CHECK(sqlite3_step(stmt) == SQLITE_DONE); sqlite3_finalize(stmt); return result;
}
static int request(const char *suffix, const char *body, const char *source, char response[8192])
{
    char route[160]; snprintf(route, sizeof(route), "/api/public/transfer/rooms/%s", suffix);
    CHECK(st_public_room_build_response("POST", route, body, source, response, 8192U) > 0);
    CHECK(strstr(response, "Cache-Control: no-store\r\n") != NULL);
    return atoi(response + 9);
}
static void issue(char code[9], char response[8192])
{
    CHECK(request("pairing-codes", "{\"roomId\":\"expiry-room\",\"roomToken\":\"expiry-owner-token\",\"peerId\":\"owner\",\"role\":\"VIEWER\",\"maxUses\":1}", "127.0.0.1", response) == 200);
    const char *body = strstr(response, "\r\n\r\n"); CHECK(body != NULL);
    char *value = st_json_get_top_level_string(body + 4, "code");
    CHECK(value != NULL && strlen(value) == 8U); memcpy(code, value, 9U); free(value);
}
static void reset(int fractional)
{
    st_public_room_reset_for_tests(); unlink(database); nanos = fractional ? 500000000L : 0L;
    advance_at_call = 0; clock_calls = 0;
    char now[ST_INSTANT_CAPACITY]; CHECK(st_instant_now(now) == 0 && st_instant_public(now, now, sizeof(now)) == 0
        && strcmp(now, cutoffs[fractional]) == 0);
    CHECK(st_storage_init(database, 0) == 0);
    sqlite3 *db = open_db(); CHECK(scalar(db, "SELECT CAST(strftime('%s','now') AS INTEGER)") == (long long)seconds); sqlite3_close(db);
}
static void set_expiry(int id, const char *value)
{
    sqlite3 *db = open_db(); sqlite3_stmt *stmt = NULL;
    CHECK(sqlite3_prepare_v2(db, "UPDATE public_transfer_room_pairing_code SET expires_at=?1 WHERE id=?2", -1, &stmt, NULL) == SQLITE_OK
        && sqlite3_bind_text(stmt, 1, value, -1, SQLITE_TRANSIENT) == SQLITE_OK && sqlite3_bind_int(stmt, 2, id) == SQLITE_OK
        && sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db) == 1);
    sqlite3_finalize(stmt); sqlite3_close(db);
}
static int redeem(const char *code, const char *source)
{
    char body[128], response[8192]; snprintf(body, sizeof(body), "{\"code\":\"%s\",\"peerId\":\"guest\"}", code);
    int status = request("pairing-codes/redeem", body, source, response);
    if (status == 200) CHECK(strstr(response, nanos == 0
        ? "\"expiresAt\":\"2026-09-16T12:00:00Z\"" : "\"expiresAt\":\"2026-09-16T12:00:00.500Z\"") != NULL);
    return status;
}
static void boundaries(int fractional, int legacy)
{
    reset(fractional); char codes[7][9], response[8192];
    for (int i = 0; i < 7; ++i) {
        issue(codes[i], response); char stored[ST_INSTANT_CAPACITY];
        CHECK(st_instant_normalize(values[fractional][i], stored) == 0);
        set_expiry(i + 1, legacy ? values[fractional][i] : stored);
    }
    CHECK(st_storage_init(database, 0) == 0 && st_storage_init(database, 0) == 0);
    for (int i = 0; i < 7; ++i) {
        char source[32]; snprintf(source, sizeof(source), "127.0.0.%d", i + 1);
        int status = redeem(codes[i], source);
        if (status != (i >= 4 ? 200 : 400)) fprintf(stderr, "fractional=%d legacy=%d offset-index=%d status=%d\n", fractional, legacy, i, status);
        CHECK(status == (i >= 4 ? 200 : 400));
        if (i >= 4) CHECK(redeem(codes[i], source) == 400);
    }
    sqlite3 *db = open_db();
    CHECK(scalar(db, "SELECT count(*) FROM public_transfer_room_pairing_code WHERE used_count=1") == 3);
    CHECK(scalar(db, "SELECT count(*) FROM public_transfer_room_pairing_code WHERE id<=4 AND used_count=0") == 4);
    CHECK(scalar(db, "SELECT count(*) FROM public_transfer_room_access") == 3);
    sqlite3_close(db);
    printf("pairing expiry: fractional=%d legacy=%d seven HTTP-handler boundaries; only >now mints tokens, replay/no-store verified\n", fractional, legacy);
}
static void writer(void)
{
    reset(1); char code[9], response[8192]; issue(code, response);
    CHECK(strstr(response, "\"createdAt\":\"2026-09-15T12:00:00.500Z\"") != NULL);
    CHECK(strstr(response, "\"expiresAt\":\"2026-09-15T12:05:00.500Z\"") != NULL);
    sqlite3 *db = open_db();
    CHECK(scalar(db, "SELECT count(*) FROM public_transfer_room_pairing_code WHERE expires_at='2026-09-15T12:05:00.5000000Z'") == 1);
    sqlite3_close(db);
    set_expiry(1, "2026-09-15T12:05:00.500Z"); CHECK(st_storage_init(database, 0) == 0);
    db = open_db(); CHECK(scalar(db, "SELECT count(*) FROM public_transfer_room_pairing_code WHERE expires_at='2026-09-15T12:05:00.5000000Z'") == 1); sqlite3_close(db);
    puts("pairing expiry: actual issuer keeps300s fractional TTL, canonical storage/public view and startup migration");
}
static void write_boundary(void)
{
    reset(1); char code[9], response[8192]; issue(code, response);
    set_expiry(1, "2026-09-15T12:00:00.5000001Z");
    clock_calls = 0; advance_at_call = 2;
    char body[128]; snprintf(body, sizeof(body), "{\"code\":\"%s\",\"peerId\":\"guest\"}", code);
    int status = request("pairing-codes/redeem", body, "127.0.0.1", response);
    advance_at_call = 0;
    sqlite3 *db = open_db();
    long long used = scalar(db, "SELECT used_count FROM public_transfer_room_pairing_code WHERE id=1");
    long long tokens = scalar(db, "SELECT count(*) FROM public_transfer_room_access"); sqlite3_close(db);
    if (status != 400 || used != 0 || tokens != 0)
        fprintf(stderr, "pairing consume race: status=%d used=%lld tokens=%lld clock_calls=%d\n", status, used, tokens, clock_calls);
    CHECK(status == 400 && used == 0 && tokens == 0 && clock_calls >= 2);
    puts("pairing expiry: read-to-consume crosses100ns; transaction mints no token and preserves unused code");
}
int main(int argc, char **argv)
{
    CHECK(setenv("SPECUS_DB_SEED_DEMO_CLIENT", "0", 1) == 0
        && setenv("SPECUS_DATABASE_PATH", database, 1) == 0
        && setenv("SPECUS_AUTH_JWT_SECRET", "pairing-expiry-test-secret", 1) == 0);
    int fd = mkstemp(database); CHECK(fd >= 0); close(fd);
    CHECK(setenv("SPECUS_DATABASE_PATH", database, 1) == 0 && atexit(cleanup) == 0);
    sqlite3_vfs fixed = *sqlite3_vfs_find(NULL); fixed.zName = "pairing-expiry-clock";
    fixed.xCurrentTime = sqlite_now; fixed.xCurrentTimeInt64 = sqlite_now64; CHECK(sqlite3_vfs_register(&fixed, 1) == SQLITE_OK);
    int mode = argc > 1 ? atoi(argv[1]) : -1;
    if (mode < 0 || mode == 0) for (int f = 0; f < 2; ++f) for (int old = 0; old < 2; ++old) boundaries(f, old);
    if (mode < 0 || mode == 1) writer();
    if (mode < 0 || mode == 2) write_boundary();
    CHECK(sqlite3_vfs_unregister(&fixed) == SQLITE_OK); return 0;
}
