#include "instant_storage.h"
#include "instant.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int identifier(const char *value)
{
    if (value == NULL || *value == '\0') return 0;
    size_t i = 0U;
    for (; value[i] != '\0' && i < 64U; ++i) {
        unsigned char c = (unsigned char)value[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'
              || (i > 0U && c >= '0' && c <= '9'))) return 0;
    }
    return i < 64U;
}

typedef struct { sqlite3_value *key; sqlite3_value *value; } instant_row;

static const char *instant_sqlite_text(sqlite3_value *value)
{
    if (sqlite3_value_type(value) != SQLITE_TEXT) return NULL;
    const char *text = (const char *)sqlite3_value_text(value);
    return text != NULL && strlen(text) == (size_t)sqlite3_value_bytes(value) ? text : NULL;
}

static void instant_sqlite_normalize(sqlite3_context *context, int count, sqlite3_value **args)
{
    (void)count;
    char result[ST_INSTANT_CAPACITY];
    if (st_instant_normalize(instant_sqlite_text(args[0]), result) != 0) sqlite3_result_null(context);
    else sqlite3_result_text(context, result, -1, SQLITE_TRANSIENT);
}

static void instant_sqlite_add_seconds(sqlite3_context *context, int count, sqlite3_value **args)
{
    (void)count;
    char result[ST_INSTANT_CAPACITY];
    if (sqlite3_value_type(args[1]) != SQLITE_INTEGER
        || st_instant_add_seconds(instant_sqlite_text(args[0]), sqlite3_value_int64(args[1]), result) != 0)
        sqlite3_result_null(context);
    else sqlite3_result_text(context, result, -1, SQLITE_TRANSIENT);
}

int st_instant_register_sqlite(sqlite3 *db)
{
    if (db == NULL) return -1;
    int flags = SQLITE_UTF8 | SQLITE_DETERMINISTIC;
    return sqlite3_create_function_v2(db, "specus_instant", 1, flags, NULL,
               instant_sqlite_normalize, NULL, NULL, NULL) == SQLITE_OK
        && sqlite3_create_function_v2(db, "specus_instant_add_seconds", 2, flags, NULL,
               instant_sqlite_add_seconds, NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
}

int st_instant_migrate_column(sqlite3 *db, const char *table, const char *key, const char *column,
                              long long *rewritten)
{
    if (rewritten != NULL) *rewritten = 0;
    if (db == NULL || !identifier(table) || !identifier(key) || !identifier(column)) return -1;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1", -1, &stmt, NULL) != SQLITE_OK) return -1;
    int rc = sqlite3_bind_text(stmt, 1, table, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc == SQLITE_DONE) return 0;
    if (rc != SQLITE_ROW) return -1;
    /* SQLite can interpret an unknown double-quoted identifier as a string literal. Prove both
     * columns exist before preparing keyset SQL; quoting alone is not a schema validation. */
    char metadata[96];
    int size = snprintf(metadata, sizeof(metadata), "PRAGMA table_info(\"%s\")", table);
    if (size < 0 || (size_t)size >= sizeof(metadata)
        || sqlite3_prepare_v2(db, metadata, -1, &stmt, NULL) != SQLITE_OK) return -1;
    int has_key = 0, has_column = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(stmt, 1);
        if (name != NULL) { has_key |= strcmp((const char *)name, key) == 0; has_column |= strcmp((const char *)name, column) == 0; }
    }
    sqlite3_finalize(stmt); stmt = NULL;
    if (rc != SQLITE_DONE || !has_key || !has_column) return -1;
    instant_row *rows = calloc(ST_INSTANT_MIGRATION_BATCH, sizeof(*rows));
    if (rows == NULL) return -1;
    sqlite3_value *after = NULL;
    long long total = 0;
    int result = 0;
    for (;;) {
        char sql[512];
        int n;
        if (after == NULL) n = snprintf(sql, sizeof(sql),
            "SELECT \"%s\",\"%s\" FROM \"%s\" WHERE \"%s\" IS NOT NULL AND \"%s\" IS NOT NULL "
            "AND length(\"%s\")<>28 ORDER BY \"%s\" LIMIT 500", key, column, table, key, column, column, key);
        else n = snprintf(sql, sizeof(sql),
            "SELECT \"%s\",\"%s\" FROM \"%s\" WHERE \"%s\" IS NOT NULL AND \"%s\" IS NOT NULL "
            "AND length(\"%s\")<>28 AND \"%s\">?1 ORDER BY \"%s\" LIMIT 500",
            key, column, table, key, column, column, key, key);
        if (n < 0 || (size_t)n >= sizeof(sql) || sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) { result = -1; break; }
        rc = after == NULL ? SQLITE_OK : sqlite3_bind_value(stmt, 1, after);
        size_t count = 0U;
        if (rc == SQLITE_OK) {
            while (count < ST_INSTANT_MIGRATION_BATCH && (rc = sqlite3_step(stmt)) == SQLITE_ROW) {
                rows[count].key = sqlite3_value_dup(sqlite3_column_value(stmt, 0));
                rows[count].value = sqlite3_value_dup(sqlite3_column_value(stmt, 1));
                if (rows[count].key == NULL || rows[count].value == NULL) { ++count; rc = SQLITE_NOMEM; break; }
                ++count;
            }
        }
        sqlite3_finalize(stmt); stmt = NULL;
        if (rc != SQLITE_ROW && rc != SQLITE_DONE) result = -1;
        if (result == 0 && count > 0U) {
            /*
             * One transaction per batch, unless the caller already holds one: in autocommit mode every
             * UPDATE would be its own commit and fsync, so a database with thousands of legacy rows
             * took one disk sync per row to start. Opened only once a row actually changes.
             */
            int own_transaction = 0;
            n = snprintf(sql, sizeof(sql), "UPDATE \"%s\" SET \"%s\"=?1 WHERE \"%s\"=?2 AND \"%s\"=?3", table, column, key, column);
            if (n < 0 || (size_t)n >= sizeof(sql) || sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) result = -1;
            for (size_t i = 0U; result == 0 && i < count; ++i) {
                if (sqlite3_value_type(rows[i].value) != SQLITE_TEXT) continue;
                const char *old = (const char *)sqlite3_value_text(rows[i].value);
                int bytes = sqlite3_value_bytes(rows[i].value);
                char normalized[ST_INSTANT_CAPACITY];
                if (old == NULL) { result = -1; break; }
                if (bytes < 0 || bytes >= 48 || (int)strlen(old) != bytes || st_instant_normalize(old, normalized) != 0) continue;
                if (!own_transaction && sqlite3_get_autocommit(db)) {
                    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) { result = -1; break; }
                    own_transaction = 1;
                }
                rc = sqlite3_bind_text(stmt, 1, normalized, -1, SQLITE_TRANSIENT);
                if (rc == SQLITE_OK) rc = sqlite3_bind_value(stmt, 2, rows[i].key);
                if (rc == SQLITE_OK) rc = sqlite3_bind_value(stmt, 3, rows[i].value);
                if (rc == SQLITE_OK) rc = sqlite3_step(stmt);
                if (rc != SQLITE_DONE) { result = -1; break; }
                total += sqlite3_changes(db);
                if (sqlite3_reset(stmt) != SQLITE_OK || sqlite3_clear_bindings(stmt) != SQLITE_OK) { result = -1; break; }
            }
            sqlite3_finalize(stmt); stmt = NULL;
            if (own_transaction && result == 0 && sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) result = -1;
            if (own_transaction && result != 0) (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        }
        sqlite3_value_free(after); after = NULL;
        if (result == 0 && count == ST_INSTANT_MIGRATION_BATCH) {
            after = rows[count - 1U].key; rows[count - 1U].key = NULL;
        }
        for (size_t i = 0U; i < count; ++i) {
            sqlite3_value_free(rows[i].key); sqlite3_value_free(rows[i].value);
            rows[i].key = NULL; rows[i].value = NULL;
        }
        if (result != 0 || count < ST_INSTANT_MIGRATION_BATCH) break;
    }
    sqlite3_value_free(after); free(rows);
    if (rewritten != NULL) *rewritten = total;
    return result;
}
