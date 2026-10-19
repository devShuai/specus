#include "instant_storage.h"
#include <stdio.h>
#include <string.h>

#define CHECK(ok) do { if (!(ok)) { fprintf(stderr, "instant migration failed line%d: %s\n", __LINE__, sqlite3_errmsg(db)); return 1; } } while (0)
static const char *old[] = {"2026-09-15T12:00:00Z", "2026-09-15T12:00:00.125Z",
    "2026-09-15T12:00:00.000123Z", "2026-09-15T12:00:00.000000123Z"};
static const char *normalized[] = {"2026-09-15T12:00:00.0000000Z", "2026-09-15T12:00:00.1250000Z",
    "2026-09-15T12:00:00.0001230Z", "2026-09-15T12:00:00.0000001Z"};

int main(void)
{
    sqlite3 *db = NULL;
    CHECK(sqlite3_open(":memory:", &db) == SQLITE_OK);
    CHECK(sqlite3_exec(db, "CREATE TABLE records(id INTEGER PRIMARY KEY,at TEXT);CREATE TABLE tickets(token TEXT PRIMARY KEY,at TEXT)", NULL, NULL, NULL) == SQLITE_OK);
    const int row_count = 2 * (int)ST_INSTANT_MIGRATION_BATCH + 7;
    for (int mode = 0; mode < 2; ++mode) {
        sqlite3_stmt *stmt = NULL;
        CHECK(sqlite3_prepare_v2(db, mode == 0 ? "INSERT INTO records VALUES(?1,?2)" : "INSERT INTO tickets VALUES(?1,?2)", -1, &stmt, NULL) == SQLITE_OK);
        for (int i = 1; i <= row_count; ++i) {
            char token[16]; snprintf(token, sizeof(token), "t%05d", i);
            CHECK((mode == 0 ? sqlite3_bind_int(stmt, 1, i) : sqlite3_bind_text(stmt, 1, token, -1, SQLITE_TRANSIENT)) == SQLITE_OK);
            CHECK(sqlite3_bind_text(stmt, 2, i % 97 == 0 ? "not-an-instant" : old[i % 4], -1, SQLITE_STATIC) == SQLITE_OK);
            CHECK(sqlite3_step(stmt) == SQLITE_DONE && sqlite3_reset(stmt) == SQLITE_OK && sqlite3_clear_bindings(stmt) == SQLITE_OK);
        }
        sqlite3_finalize(stmt);
    }
    long long changed = -1;
    CHECK(st_instant_migrate_column(db, "missing_table", "id", "at", &changed) == 0 && changed == 0);
    for (int mode = 0; mode < 2; ++mode) {
        const char *table = mode == 0 ? "records" : "tickets", *key = mode == 0 ? "id" : "token";
        CHECK(st_instant_migrate_column(db, table, key, "at", &changed) == 0 && changed == row_count - row_count / 97);
        for (int repeat = 0; repeat < 2; ++repeat) {
            sqlite3_stmt *stmt = NULL;
            CHECK(sqlite3_prepare_v2(db, mode == 0 ? "SELECT id,at FROM records ORDER BY id" : "SELECT token,at FROM tickets ORDER BY token", -1, &stmt, NULL) == SQLITE_OK);
            for (int i = 1; i <= row_count; ++i) {
                CHECK(sqlite3_step(stmt) == SQLITE_ROW);
                if (mode == 0) CHECK(sqlite3_column_type(stmt, 0) == SQLITE_INTEGER && sqlite3_column_int(stmt, 0) == i);
                else { char token[16]; snprintf(token, sizeof(token), "t%05d", i);
                    CHECK(sqlite3_column_type(stmt, 0) == SQLITE_TEXT && strcmp((const char *)sqlite3_column_text(stmt, 0), token) == 0); }
                const char *expected = i % 97 == 0 ? "not-an-instant" : normalized[i % 4];
                CHECK(sqlite3_column_type(stmt, 1) == SQLITE_TEXT && strcmp((const char *)sqlite3_column_text(stmt, 1), expected) == 0);
            }
            CHECK(sqlite3_step(stmt) == SQLITE_DONE); sqlite3_finalize(stmt);
            CHECK(st_instant_migrate_column(db, table, key, "at", &changed) == 0 && changed == 0);
        }
    }
    CHECK(st_instant_migrate_column(db, "records;DROP", "id", "at", &changed) == -1);
    CHECK(st_instant_migrate_column(db, "records", "id", "absent_column", &changed) == -1);
    CHECK(st_instant_migrate_column(db, "records", "absent_key", "at", &changed) == -1);
    CHECK(sqlite3_exec(db, "INSERT INTO records VALUES(2000,CAST(x'62616400737566666978' AS TEXT));INSERT INTO records VALUES(2001,NULL)", NULL, NULL, NULL) == SQLITE_OK);
    CHECK(st_instant_migrate_column(db, "records", "id", "at", &changed) == 0 && changed == 0);
    sqlite3_stmt *stmt = NULL;
    CHECK(sqlite3_prepare_v2(db, "SELECT hex(at) FROM records WHERE id=2000", -1, &stmt, NULL) == SQLITE_OK
        && sqlite3_step(stmt) == SQLITE_ROW && strcmp((const char *)sqlite3_column_text(stmt, 0), "62616400737566666978") == 0);
    sqlite3_finalize(stmt);
    CHECK(sqlite3_close(db) == SQLITE_OK);
    puts("instant migration:1007 numeric+1007 text rows,invalid paging/idempotence/missing table/NUL preserved passed; not production startup");
    return 0;
}
