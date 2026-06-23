#include "storage.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int exec_sql(sqlite3 *db, const char *sql)
{
    char *error = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &error);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "sqlite error: %s\n", error == NULL ? sqlite3_errmsg(db) : error);
        sqlite3_free(error);
        return -1;
    }
    return 0;
}

static int open_db(const char *path, sqlite3 **db)
{
    int rc = sqlite3_open(path, db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "failed to open sqlite database %s: %s\n", path, sqlite3_errmsg(*db));
        sqlite3_close(*db);
        *db = NULL;
        return -1;
    }
    return 0;
}

int st_storage_init(const char *path, int seed_demo_client)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }

    int rc = exec_sql(db,
        "CREATE TABLE IF NOT EXISTS client_account ("
        "client_name TEXT PRIMARY KEY,"
        "enabled INTEGER NOT NULL DEFAULT 1,"
        "connection_limit_per_minute INTEGER NOT NULL DEFAULT 30,"
        "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ");"
        "CREATE TABLE IF NOT EXISTS tunnel_mapping ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "client_name TEXT NOT NULL,"
        "listen_port INTEGER NOT NULL,"
        "target_address TEXT NOT NULL,"
        "target_port INTEGER NOT NULL,"
        "enabled INTEGER NOT NULL DEFAULT 1,"
        "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "UNIQUE(client_name, listen_port)"
        ");"
        "CREATE TABLE IF NOT EXISTS connection_record ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "client_name TEXT NOT NULL,"
        "success INTEGER NOT NULL,"
        "reason TEXT,"
        "connected_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "disconnected_at TEXT"
        ");"
        "CREATE TABLE IF NOT EXISTS traffic_usage ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "client_name TEXT NOT NULL,"
        "usage_date TEXT NOT NULL,"
        "upload_bytes INTEGER NOT NULL DEFAULT 0,"
        "download_bytes INTEGER NOT NULL DEFAULT 0,"
        "UNIQUE(client_name, usage_date)"
        ");"
        "CREATE TABLE IF NOT EXISTS connection_stat ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "client_name TEXT NOT NULL,"
        "stat_date TEXT NOT NULL,"
        "success_count INTEGER NOT NULL DEFAULT 0,"
        "failure_count INTEGER NOT NULL DEFAULT 0,"
        "UNIQUE(client_name, stat_date)"
        ");");
    if (rc == 0 && seed_demo_client) {
        sqlite3_stmt *stmt = NULL;
        rc = sqlite3_prepare_v2(db,
            "INSERT OR IGNORE INTO client_account(client_name, enabled) VALUES(?,1)",
            -1,
            &stmt,
            NULL);
        if (rc == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, "Demo client", -1, SQLITE_STATIC);
            rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
        } else {
            rc = -1;
        }
        sqlite3_finalize(stmt);
    }

    sqlite3_close(db);
    return rc == 0 ? 0 : -1;
}

int st_storage_client_enabled(const char *path, const char *client_name)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT 1 FROM client_account WHERE client_name = ? AND enabled = 1",
        -1,
        &stmt,
        NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, client_name, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == SQLITE_ROW ? 0 : -1;
}

int st_storage_load_mappings(const char *path,
                             const char *client_name,
                             st_storage_mapping *mappings,
                             size_t max_mappings,
                             size_t *mapping_count)
{
    *mapping_count = 0;
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT listen_port, target_address, target_port "
        "FROM tunnel_mapping WHERE client_name = ? AND enabled = 1 ORDER BY listen_port",
        -1,
        &stmt,
        NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, client_name, -1, SQLITE_TRANSIENT);
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (*mapping_count >= max_mappings) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return -1;
        }
        st_storage_mapping *mapping = &mappings[*mapping_count];
        mapping->listen_port = sqlite3_column_int(stmt, 0);
        const unsigned char *address = sqlite3_column_text(stmt, 1);
        mapping->target_port = sqlite3_column_int(stmt, 2);
        if (address == NULL || strlen((const char *)address) >= sizeof(mapping->target_address)) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return -1;
        }
        strcpy(mapping->target_address, (const char *)address);
        ++*mapping_count;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == SQLITE_DONE ? 0 : -1;
}

int st_storage_upsert_mapping(const char *path,
                              const char *client_name,
                              int listen_port,
                              const char *target_address,
                              int target_port,
                              int enabled)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT INTO tunnel_mapping(client_name, listen_port, target_address, target_port, enabled) "
        "VALUES(?,?,?,?,?) "
        "ON CONFLICT(client_name, listen_port) DO UPDATE SET "
        "target_address = excluded.target_address,"
        "target_port = excluded.target_port,"
        "enabled = excluded.enabled,"
        "updated_at = CURRENT_TIMESTAMP",
        -1,
        &stmt,
        NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, client_name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 2, listen_port);
        sqlite3_bind_text(stmt, 3, target_address, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 4, target_port);
        sqlite3_bind_int(stmt, 5, enabled ? 1 : 0);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == 0 ? 0 : -1;
}

int st_storage_record_connection(const char *path,
                                 const char *client_name,
                                 int success,
                                 const char *reason,
                                 const char *connected_at)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT INTO connection_record(client_name, success, reason, connected_at, disconnected_at) "
        "VALUES(?,?,?,?,?)",
        -1,
        &stmt,
        NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, client_name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 2, success ? 1 : 0);
        if (reason == NULL) {
            sqlite3_bind_null(stmt, 3);
        } else {
            sqlite3_bind_text(stmt, 3, reason, -1, SQLITE_TRANSIENT);
        }
        sqlite3_bind_text(stmt, 4, connected_at, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, connected_at, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == 0 ? 0 : -1;
}

int st_storage_archive_connections(const char *path, const char *before_timestamp)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT INTO connection_stat(client_name, stat_date, success_count, failure_count) "
        "SELECT client_name, substr(connected_at, 1, 10), "
        "SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END), "
        "SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) "
        "FROM connection_record WHERE connected_at < ? "
        "GROUP BY client_name, substr(connected_at, 1, 10) "
        "ON CONFLICT(client_name, stat_date) DO UPDATE SET "
        "success_count = success_count + excluded.success_count, "
        "failure_count = failure_count + excluded.failure_count",
        -1,
        &stmt,
        NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, before_timestamp, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    if (rc == 0) {
        rc = sqlite3_prepare_v2(db,
            "DELETE FROM connection_record WHERE connected_at < ?",
            -1,
            &stmt,
            NULL);
        if (rc == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, before_timestamp, -1, SQLITE_TRANSIENT);
            rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
        } else {
            rc = -1;
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    return rc == 0 ? 0 : -1;
}

int st_storage_load_connection_stat(const char *path,
                                    const char *client_name,
                                    const char *stat_date,
                                    int *success_count,
                                    int *failure_count)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT success_count, failure_count FROM connection_stat "
        "WHERE client_name = ? AND stat_date = ?",
        -1,
        &stmt,
        NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, client_name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, stat_date, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    *success_count = sqlite3_column_int(stmt, 0);
    *failure_count = sqlite3_column_int(stmt, 1);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}
