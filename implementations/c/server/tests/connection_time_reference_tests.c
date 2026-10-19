#define _POSIX_C_SOURCE 200809L
#include "storage.h"
#include "instant_reference_cases.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(ok) do { if (!(ok)) { fprintf(stderr, "connection time failed line%d\n", __LINE__); return 1; } } while (0)

static int scalar(sqlite3 *db, const char *sql, long long expected)
{
    sqlite3_stmt *stmt = NULL;
    int ok = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW
        && sqlite3_column_int64(stmt, 0) == expected && sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt); return ok;
}

static int list(const char *path, int visible, const char *from, const char *to, unsigned expected, int fractional)
{
    st_storage_connection rows[8] = {{0}}; size_t count = 0U; long long total = 0;
    int rc = visible ? st_storage_list_connections_visible(path, 1, -1, from, to, "t1", "alice", 0, 0, 20, rows, 8, &count, &total)
        : st_storage_list_connections(path, 1, -1, from, to, 0, 20, rows, 8, &count, &total);
    CHECK(rc == 0 && total == (long long)count);
    unsigned actual = 0U;
    for (size_t i = 0U; i < count; ++i) {
        CHECK(rows[i].id >= 1 && rows[i].id <= 7 && (actual & (1U << rows[i].id)) == 0U);
        actual |= 1U << rows[i].id;
        CHECK(strcmp(rows[i].connected_at, values[fractional][rows[i].id - 1]) == 0);
    }
    CHECK(actual == expected);
    return 0;
}

static int run(int fractional, int legacy)
{
    char path[] = "/tmp/specus-connection-time-XXXXXX";
    int fd = mkstemp(path); CHECK(fd >= 0); close(fd);
    CHECK(st_storage_init(path, 0) == 0);
    st_storage_client client;
    CHECK(st_storage_upsert_client(path, 0, "t1", "time-client", "alice", 1, 60, &client) == 0 && client.id == 1);
    for (int i = 0; i < 7; ++i) {
        char channel[8]; snprintf(channel, sizeof(channel), "c%d", i + 1); long long id = 0;
        CHECK(st_storage_record_connection_detail_with_tenant_and_id(path, "t1", client.id, client.client_name,
            channel, "127.0.0.1", 1, NULL, NULL, values[fractional][i], NULL, &id) == 0 && id == i + 1);
    }
    sqlite3 *db = NULL; CHECK(sqlite3_open(path, &db) == SQLITE_OK);
    CHECK(scalar(db, "SELECT count(*) FROM connection_record WHERE length(connected_at)=28", 7));
    if (legacy) {
        sqlite3_stmt *stmt = NULL;
        CHECK(sqlite3_prepare_v2(db, "UPDATE connection_record SET connected_at=?1 WHERE id=?2", -1, &stmt, NULL) == SQLITE_OK);
        for (int i = 0; i < 7; ++i) {
            CHECK(sqlite3_bind_text(stmt, 1, values[fractional][i], -1, SQLITE_STATIC) == SQLITE_OK
                && sqlite3_bind_int(stmt, 2, i + 1) == SQLITE_OK && sqlite3_step(stmt) == SQLITE_DONE
                && sqlite3_reset(stmt) == SQLITE_OK && sqlite3_clear_bindings(stmt) == SQLITE_OK);
        }
        sqlite3_finalize(stmt);
        CHECK(scalar(db, "SELECT count(*) FROM connection_record WHERE length(connected_at)=28", 0));
    }
    sqlite3_close(db);
    CHECK(st_storage_init(path, 0) == 0 && st_storage_init(path, 0) == 0);
    CHECK(sqlite3_open(path, &db) == SQLITE_OK
        && scalar(db, "SELECT count(*) FROM connection_record WHERE length(connected_at)=28", 7));
    sqlite3_close(db);
    for (int visible = 0; visible < 2; ++visible) {
        CHECK(list(path, visible, cutoffs[fractional], NULL, 0xf0U, fractional) == 0);
        CHECK(list(path, visible, NULL, cutoffs[fractional], 0x1eU, fractional) == 0);
        CHECK(list(path, visible, "2026-09-15", NULL, 0xfeU, fractional) == 0);
        char padded[64]; snprintf(padded, sizeof(padded), "  %s \t", cutoffs[fractional]);
        CHECK(list(path, visible, padded, NULL, 0xf0U, fractional) == 0);
    }
    int closed = -1;
    CHECK(st_storage_close_open_connections_before(path, cutoffs[fractional], "SERVER_RESTARTED", cutoffs[fractional], &closed) == 0 && closed == 3);
    CHECK(sqlite3_open(path, &db) == SQLITE_OK
        && scalar(db, "SELECT count(*) FROM connection_record WHERE id<=3 AND disconnected_at IS NOT NULL AND disconnect_reason='SERVER_RESTARTED'", 3)
        && scalar(db, "SELECT count(*) FROM connection_record WHERE id>=4 AND disconnected_at IS NULL", 4));
    sqlite3_stmt *stmt = NULL;
    CHECK(sqlite3_prepare_v2(db, "SELECT disconnected_at FROM connection_record WHERE id<=3", -1, &stmt, NULL) == SQLITE_OK);
    for (int i = 0; i < 3; ++i) CHECK(sqlite3_step(stmt) == SQLITE_ROW && strcmp((const char *)sqlite3_column_text(stmt, 0), cutoffs[fractional]) == 0);
    CHECK(sqlite3_step(stmt) == SQLITE_DONE); sqlite3_finalize(stmt); sqlite3_close(db);
    CHECK(st_storage_close_open_connections_before(path, cutoffs[fractional], "SERVER_RESTARTED", cutoffs[fractional], &closed) == 0 && closed == 0);
    CHECK(st_storage_close_open_connections(path, "SERVER_SHUTDOWN", cutoffs[fractional], &closed) == 0 && closed == 4);
    unlink(path);
    printf("connection time: fractional=%d legacy=%d actual writers/startup migration/lower upper visible views/strict restart/all shutdown passed\n", fractional, legacy);
    return 0;
}

int main(void)
{
    CHECK(setenv("SPECUS_DB_SEED_DEMO_CLIENT", "0", 1) == 0);
    for (int fractional = 0; fractional < 2; ++fractional)
        for (int legacy = 0; legacy < 2; ++legacy) CHECK(run(fractional, legacy) == 0);
    puts("connection time:4 actual storage scenarios passed; other expiry/reference methods remain pending");
    return 0;
}
