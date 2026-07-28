#include "storage.h"

#include "crypto.h"

#include <ctype.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ST_STORAGE_PREVIEW_BYTES 1024U

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

static int copy_text_column(sqlite3_stmt *stmt, int column, char *out, size_t out_len)
{
    const unsigned char *value = sqlite3_column_text(stmt, column);
    const char *text = value == NULL ? "" : (const char *)value;
    if (strlen(text) >= out_len) {
        return -1;
    }
    strcpy(out, text);
    return 0;
}

static int table_has_column(sqlite3 *db, const char *table, const char *column)
{
    char sql[128];
    int written = snprintf(sql, sizeof(sql), "PRAGMA table_info(%s)", table);
    if (written < 0 || (size_t)written >= sizeof(sql)) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }
    int found = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(stmt, 1);
        if (name != NULL && strcmp((const char *)name, column) == 0) {
            found = 1;
            break;
        }
    }
    sqlite3_finalize(stmt);
    return found;
}

static int add_column_if_missing(sqlite3 *db, const char *table, const char *column, const char *definition)
{
    int has_column = table_has_column(db, table, column);
    if (has_column < 0) {
        return -1;
    }
    if (has_column) {
        return 0;
    }
    char sql[512];
    int written = snprintf(sql, sizeof(sql), "ALTER TABLE %s ADD COLUMN %s %s", table, column, definition);
    if (written < 0 || (size_t)written >= sizeof(sql)) {
        return -1;
    }
    return exec_sql(db, sql);
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

static const char *normalize_tenant_id(const char *tenant_id);

int st_storage_init(const char *path, int seed_demo_client)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }

    int rc = exec_sql(db,
        "CREATE TABLE IF NOT EXISTS client_account ("
        "tenant_id TEXT NOT NULL DEFAULT 'default',"
        "client_name TEXT PRIMARY KEY,"
        "owner_username TEXT NOT NULL DEFAULT 'admin',"
        "enabled INTEGER NOT NULL DEFAULT 1,"
        "connection_limit_per_minute INTEGER NOT NULL DEFAULT 30,"
        "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ");"
        "CREATE TABLE IF NOT EXISTS specus_management_user ("
        "username TEXT PRIMARY KEY,"
        "tenant_id TEXT NOT NULL DEFAULT 'default',"
        "password_hash TEXT NOT NULL,"
        "role TEXT NOT NULL DEFAULT 'USER',"
        "enabled INTEGER NOT NULL DEFAULT 1,"
        "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ");"
        "CREATE TABLE IF NOT EXISTS specus_client_credential ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "tenant_id TEXT NOT NULL DEFAULT 'default',"
        "owner_username TEXT,"
        "api_key TEXT NOT NULL UNIQUE,"
        "secret_hash TEXT NOT NULL,"
        "enabled INTEGER NOT NULL DEFAULT 1,"
        "max_online_instances INTEGER NOT NULL DEFAULT 2,"
        "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ");"
        "CREATE TABLE IF NOT EXISTS client_download_link ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "implementation TEXT NOT NULL,"
        "platform TEXT NOT NULL,"
        "arch TEXT NOT NULL,"
        "display_name TEXT NOT NULL,"
        "download_url TEXT NOT NULL,"
        "description TEXT,"
        "display_order INTEGER NOT NULL DEFAULT 0,"
        "enabled INTEGER NOT NULL DEFAULT 1,"
        "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ");"
        "CREATE TABLE IF NOT EXISTS specus_client_identity ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "tenant_id TEXT NOT NULL DEFAULT 'default',"
        "credential_id INTEGER NOT NULL,"
        "client_id INTEGER NOT NULL,"
        "client_name TEXT NOT NULL,"
        "machine_fingerprint TEXT NOT NULL,"
        "os_user TEXT NOT NULL,"
        "hostname TEXT,"
        "first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "UNIQUE(credential_id, machine_fingerprint, os_user)"
        ");"
        "CREATE TABLE IF NOT EXISTS specus_client_session ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "tenant_id TEXT NOT NULL DEFAULT 'default',"
        "credential_id INTEGER NOT NULL,"
        "identity_id INTEGER NOT NULL,"
        "client_id INTEGER NOT NULL,"
        "client_name TEXT NOT NULL,"
        "token_hash TEXT NOT NULL,"
        "status TEXT NOT NULL,"
        "machine_fingerprint TEXT NOT NULL,"
        "os_user TEXT NOT NULL,"
        "hostname TEXT,"
        "os_name TEXT,"
        "os_version TEXT,"
        "os_arch TEXT,"
        "client_version TEXT,"
        "java_version TEXT,"
        "local_addresses TEXT,"
        "message_send_capable INTEGER NOT NULL DEFAULT 0,"
        "message_receive_capable INTEGER NOT NULL DEFAULT 0,"
        "message_attachments_capable INTEGER NOT NULL DEFAULT 0,"
        "message_media_preview_capable INTEGER NOT NULL DEFAULT 0,"
        "message_max_attachment_bytes INTEGER NOT NULL DEFAULT 0,"
        "http_login_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "netty_connected_at TEXT,"
        "disconnected_at TEXT,"
        "expires_at TEXT NOT NULL,"
        "channel_id TEXT,"
        "remote_address TEXT"
        ");"
        "CREATE TABLE IF NOT EXISTS specus_mapping ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "client_name TEXT NOT NULL,"
        "listen_port INTEGER NOT NULL,"
        "target_address TEXT NOT NULL,"
        "target_port INTEGER NOT NULL,"
        "enabled INTEGER NOT NULL DEFAULT 1,"
        "detail_capture_enabled INTEGER NOT NULL DEFAULT 0,"
        "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "UNIQUE(client_name, listen_port)"
        ");"
        "CREATE TABLE IF NOT EXISTS http_route_mapping ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "client_name TEXT NOT NULL,"
        "route TEXT NOT NULL,"
        "target_base_url TEXT NOT NULL,"
        "enabled INTEGER NOT NULL DEFAULT 1,"
        "detail_capture_enabled INTEGER NOT NULL DEFAULT 0,"
        "path_rewrite_enabled INTEGER NOT NULL DEFAULT 0,"
        "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "UNIQUE(client_name, route)"
        ");"
        "CREATE TABLE IF NOT EXISTS connection_record ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "tenant_id TEXT NOT NULL DEFAULT 'default',"
        "client_id INTEGER,"
        "client_name TEXT NOT NULL,"
        "channel_id TEXT,"
        "remote_address TEXT,"
        "success INTEGER NOT NULL,"
        "reason TEXT,"
        "disconnect_reason TEXT,"
        "connected_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "disconnected_at TEXT"
        ");"
        "CREATE TABLE IF NOT EXISTS traffic_usage ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "client_id INTEGER,"
        "client_name TEXT NOT NULL,"
        "usage_date TEXT NOT NULL,"
        "upload_bytes INTEGER NOT NULL DEFAULT 0,"
        "download_bytes INTEGER NOT NULL DEFAULT 0,"
        "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "UNIQUE(client_name, usage_date)"
        ");"
        "CREATE TABLE IF NOT EXISTS resource_traffic_usage ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "client_id INTEGER,"
        "client_name TEXT NOT NULL,"
        "resource_type TEXT NOT NULL,"
        "resource_key TEXT NOT NULL,"
        "resource_id INTEGER,"
        "resource_name TEXT,"
        "usage_date TEXT NOT NULL,"
        "upload_bytes INTEGER NOT NULL DEFAULT 0,"
        "download_bytes INTEGER NOT NULL DEFAULT 0,"
        "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "UNIQUE(client_name, resource_type, resource_key, usage_date)"
        ");"
        "CREATE TABLE IF NOT EXISTS peer_mesh_device ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "tenant_id TEXT NOT NULL DEFAULT 'default',"
        "owner_username TEXT NOT NULL DEFAULT 'admin',"
        "client_id INTEGER NOT NULL,"
        "client_name TEXT NOT NULL,"
        "enabled INTEGER NOT NULL DEFAULT 0,"
        "virtual_ip TEXT,"
        "public_key TEXT,"
        "nat_type TEXT NOT NULL DEFAULT 'UNKNOWN',"
        "last_endpoint TEXT,"
        "virtual_device_mode TEXT NOT NULL DEFAULT 'UNSUPPORTED',"
        "virtual_device_name TEXT,"
        "virtual_device_status TEXT NOT NULL DEFAULT 'UNSUPPORTED',"
        "virtual_device_error TEXT,"
        "virtual_device_updated_at TEXT,"
        "last_seen_at TEXT,"
        "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "UNIQUE(tenant_id, client_id)"
        ");"
        "CREATE TABLE IF NOT EXISTS peer_mesh_session ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "tenant_id TEXT NOT NULL DEFAULT 'default',"
        "source_client_id INTEGER NOT NULL,"
        "source_client_name TEXT NOT NULL,"
        "target_client_id INTEGER NOT NULL,"
        "target_client_name TEXT NOT NULL,"
        "path_type TEXT NOT NULL DEFAULT 'DIRECT',"
        "status TEXT NOT NULL DEFAULT 'NEGOTIATING',"
        "token_hash TEXT,"
        "started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "expires_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "closed_at TEXT,"
        "rtt_millis INTEGER,"
        "local_endpoint TEXT,"
        "remote_endpoint TEXT,"
        "direct_bytes INTEGER NOT NULL DEFAULT 0,"
        "relay_bytes INTEGER NOT NULL DEFAULT 0,"
        "last_traffic_at TEXT"
        ");"
        "CREATE TABLE IF NOT EXISTS specus_http_traffic_exchange ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "tenant_id TEXT NOT NULL DEFAULT 'default',"
        "client_id INTEGER NOT NULL,"
        "client_name TEXT NOT NULL,"
        "route TEXT NOT NULL,"
        "resource_id INTEGER,"
        "resource_name TEXT NOT NULL,"
        "method TEXT NOT NULL,"
        "relative_path TEXT NOT NULL,"
        "raw_query TEXT,"
        "status_code INTEGER NOT NULL,"
        "success INTEGER NOT NULL,"
        "error TEXT,"
        "remote_address TEXT,"
        "request_bytes INTEGER NOT NULL DEFAULT 0,"
        "response_bytes INTEGER NOT NULL DEFAULT 0,"
        "elapsed_ms INTEGER NOT NULL DEFAULT 0,"
        "request_content_type TEXT,"
        "response_content_type TEXT,"
        "response_body_type TEXT,"
        "request_headers TEXT,"
        "response_headers TEXT,"
        "request_preview_hex TEXT,"
        "request_preview_text TEXT,"
        "response_preview_hex TEXT,"
        "response_preview_text TEXT,"
        "request_truncated INTEGER NOT NULL DEFAULT 0,"
        "response_truncated INTEGER NOT NULL DEFAULT 0,"
        "captured_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ");"
        "CREATE TABLE IF NOT EXISTS specus_tcp_traffic_frame ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "tenant_id TEXT NOT NULL DEFAULT 'default',"
        "client_id INTEGER NOT NULL,"
        "client_name TEXT NOT NULL,"
        "listen_port INTEGER NOT NULL,"
        "resource_id INTEGER,"
        "resource_name TEXT NOT NULL,"
        "channel_id TEXT NOT NULL,"
        "frame_direction TEXT NOT NULL,"
        "remote_address TEXT,"
        "source_address TEXT,"
        "source_port INTEGER,"
        "destination_address TEXT,"
        "destination_port INTEGER,"
        "stream_offset INTEGER,"
        "stream_end_offset INTEGER,"
        "frame_index INTEGER,"
        "payload_bytes INTEGER NOT NULL DEFAULT 0,"
        "payload_data BLOB,"
        "payload_preview_hex TEXT,"
        "payload_preview_text TEXT,"
        "truncated INTEGER NOT NULL DEFAULT 0,"
        "frame_time TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ");"
        "CREATE TABLE IF NOT EXISTS peer_mesh_acl ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "tenant_id TEXT NOT NULL DEFAULT 'default',"
        "owner_username TEXT NOT NULL DEFAULT 'admin',"
        "source_client_id INTEGER NOT NULL,"
        "source_client_name TEXT NOT NULL,"
        "target_client_id INTEGER NOT NULL,"
        "target_client_name TEXT NOT NULL,"
        "allowed INTEGER NOT NULL DEFAULT 1,"
        "direction TEXT NOT NULL DEFAULT 'OUTBOUND',"
        "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "UNIQUE(tenant_id, source_client_id, target_client_id)"
        ");"
        "CREATE TABLE IF NOT EXISTS connection_stat ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "client_id INTEGER,"
        "client_name TEXT NOT NULL,"
        "stat_date TEXT NOT NULL,"
        "success_count INTEGER NOT NULL DEFAULT 0,"
        "failure_count INTEGER NOT NULL DEFAULT 0,"
        "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "UNIQUE(client_name, stat_date)"
        ");");
    if (rc == 0) {
        rc = add_column_if_missing(db, "client_account", "tenant_id", "TEXT NOT NULL DEFAULT 'default'");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "client_account", "owner_username", "TEXT NOT NULL DEFAULT 'admin'");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "specus_management_user", "tenant_id", "TEXT NOT NULL DEFAULT 'default'");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "specus_management_user", "password_hash", "TEXT NOT NULL DEFAULT ''");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "specus_management_user", "role", "TEXT NOT NULL DEFAULT 'USER'");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "specus_management_user", "enabled", "INTEGER NOT NULL DEFAULT 1");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "specus_management_user", "created_at", "TEXT");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "specus_management_user", "updated_at", "TEXT");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "specus_mapping", "detail_capture_enabled", "INTEGER NOT NULL DEFAULT 0");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "http_route_mapping", "detail_capture_enabled", "INTEGER NOT NULL DEFAULT 0");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "http_route_mapping", "path_rewrite_enabled", "INTEGER NOT NULL DEFAULT 0");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "specus_client_session", "message_send_capable", "INTEGER NOT NULL DEFAULT 0");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "specus_client_session", "message_receive_capable", "INTEGER NOT NULL DEFAULT 0");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "specus_client_session", "message_attachments_capable", "INTEGER NOT NULL DEFAULT 0");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "specus_client_session", "message_media_preview_capable", "INTEGER NOT NULL DEFAULT 0");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "specus_client_session", "message_max_attachment_bytes", "INTEGER NOT NULL DEFAULT 0");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "connection_record", "tenant_id", "TEXT NOT NULL DEFAULT 'default'");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "connection_record", "client_id", "INTEGER");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "connection_record", "channel_id", "TEXT");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "connection_record", "remote_address", "TEXT");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "connection_record", "disconnect_reason", "TEXT");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "connection_stat", "client_id", "INTEGER");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "connection_stat", "updated_at", "TEXT");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "traffic_usage", "client_id", "INTEGER");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "traffic_usage", "updated_at", "TEXT");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "peer_mesh_acl", "direction", "TEXT NOT NULL DEFAULT 'OUTBOUND'");
    }
    if (rc == 0) {
        rc = exec_sql(db,
            "UPDATE connection_record "
            "SET tenant_id = COALESCE(("
            "SELECT c.tenant_id FROM client_account c "
            "WHERE c.rowid = connection_record.client_id LIMIT 1"
            "), ("
            "SELECT c.tenant_id FROM client_account c "
            "WHERE connection_record.client_id IS NULL AND c.client_name = connection_record.client_name LIMIT 1"
            "), tenant_id, 'default') "
            "WHERE tenant_id IS NULL OR tenant_id = '' OR tenant_id = 'default';");
    }
    if (rc == 0) {
        rc = exec_sql(db,
            "CREATE INDEX IF NOT EXISTS idx_connection_record_tenant ON connection_record(tenant_id);"
            "CREATE INDEX IF NOT EXISTS idx_connection_record_tenant_client_time ON connection_record(tenant_id, client_id, connected_at);"
            "CREATE INDEX IF NOT EXISTS idx_http_traffic_tenant ON specus_http_traffic_exchange(tenant_id);"
            "CREATE INDEX IF NOT EXISTS idx_http_traffic_client ON specus_http_traffic_exchange(client_id);"
            "CREATE INDEX IF NOT EXISTS idx_http_traffic_route ON specus_http_traffic_exchange(route);"
            "CREATE INDEX IF NOT EXISTS idx_http_traffic_body_type ON specus_http_traffic_exchange(response_body_type);"
            "CREATE INDEX IF NOT EXISTS idx_tcp_traffic_tenant ON specus_tcp_traffic_frame(tenant_id);"
            "CREATE INDEX IF NOT EXISTS idx_tcp_traffic_client ON specus_tcp_traffic_frame(client_id);"
            "CREATE INDEX IF NOT EXISTS idx_tcp_traffic_port ON specus_tcp_traffic_frame(listen_port);"
            "CREATE INDEX IF NOT EXISTS idx_tcp_traffic_stream ON specus_tcp_traffic_frame(tenant_id, channel_id, frame_direction, stream_offset);"
            "CREATE INDEX IF NOT EXISTS idx_client_credential_tenant ON specus_client_credential(tenant_id);"
            "CREATE INDEX IF NOT EXISTS idx_client_credential_owner ON specus_client_credential(tenant_id, owner_username);"
            "CREATE INDEX IF NOT EXISTS idx_client_download_impl ON client_download_link(implementation);"
            "CREATE INDEX IF NOT EXISTS idx_client_download_order ON client_download_link(display_order);"
            "CREATE INDEX IF NOT EXISTS idx_client_identity_tenant ON specus_client_identity(tenant_id);"
            "CREATE INDEX IF NOT EXISTS idx_client_identity_client ON specus_client_identity(client_id);"
            "CREATE INDEX IF NOT EXISTS idx_client_session_token ON specus_client_session(token_hash);"
            "CREATE INDEX IF NOT EXISTS idx_client_session_credential_status ON specus_client_session(credential_id, status);"
            "CREATE INDEX IF NOT EXISTS idx_client_session_machine_status ON specus_client_session(credential_id, machine_fingerprint, os_user, status);"
            "CREATE INDEX IF NOT EXISTS idx_peer_mesh_acl_source ON peer_mesh_acl(tenant_id, source_client_id);"
            "CREATE INDEX IF NOT EXISTS idx_peer_mesh_acl_target ON peer_mesh_acl(tenant_id, target_client_id);"
            "CREATE INDEX IF NOT EXISTS idx_peer_mesh_acl_owner ON peer_mesh_acl(tenant_id, owner_username);"
            "CREATE INDEX IF NOT EXISTS idx_peer_mesh_device_client ON peer_mesh_device(tenant_id, client_id);"
            "CREATE INDEX IF NOT EXISTS idx_peer_mesh_device_owner ON peer_mesh_device(tenant_id, owner_username);"
            "CREATE INDEX IF NOT EXISTS idx_peer_mesh_session_tenant ON peer_mesh_session(tenant_id);"
            "CREATE INDEX IF NOT EXISTS idx_peer_mesh_session_source ON peer_mesh_session(tenant_id, source_client_id);"
            "CREATE INDEX IF NOT EXISTS idx_peer_mesh_session_target ON peer_mesh_session(tenant_id, target_client_id);"
            "CREATE INDEX IF NOT EXISTS idx_peer_mesh_session_status ON peer_mesh_session(status);");
    }
    if (rc == 0 && seed_demo_client) {
        sqlite3_stmt *stmt = NULL;
        rc = sqlite3_prepare_v2(db,
            "INSERT OR IGNORE INTO client_account(tenant_id, client_name, owner_username, enabled) VALUES('default',?,'admin',1)",
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

int st_storage_count_clients_by_tenant(const char *path, const char *tenant_id, long long *count)
{
    if (count == NULL) {
        return -1;
    }
    *count = 0;
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
                                "SELECT COUNT(*) FROM client_account WHERE COALESCE(tenant_id, 'default') = ?",
                                -1,
                                &stmt,
                                NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *count = sqlite3_column_int64(stmt, 0);
        rc = 0;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc;
}

static int scan_client(sqlite3_stmt *stmt, st_storage_client *client)
{
    client->id = sqlite3_column_int64(stmt, 0);
    if (copy_text_column(stmt, 1, client->tenant_id, sizeof(client->tenant_id)) != 0
        || copy_text_column(stmt, 2, client->client_name, sizeof(client->client_name)) != 0
        || copy_text_column(stmt, 3, client->owner_username, sizeof(client->owner_username)) != 0
        || copy_text_column(stmt, 6, client->created_at, sizeof(client->created_at)) != 0
        || copy_text_column(stmt, 7, client->updated_at, sizeof(client->updated_at)) != 0) {
        return -1;
    }
    client->enabled = sqlite3_column_int(stmt, 4) != 0;
    client->connection_rate_limit_per_minute = sqlite3_column_int(stmt, 5);
    client->message_send_capable = sqlite3_column_int(stmt, 8) != 0;
    client->message_receive_capable = sqlite3_column_int(stmt, 9) != 0;
    client->message_attachments_capable = sqlite3_column_int(stmt, 10) != 0;
    client->message_media_preview_capable = sqlite3_column_int(stmt, 11) != 0;
    client->message_max_attachment_bytes = sqlite3_column_int64(stmt, 12);
    return 0;
}

static int scan_management_user(sqlite3_stmt *stmt, st_storage_management_user *user)
{
    if (copy_text_column(stmt, 0, user->username, sizeof(user->username)) != 0
        || copy_text_column(stmt, 1, user->tenant_id, sizeof(user->tenant_id)) != 0
        || copy_text_column(stmt, 2, user->password_hash, sizeof(user->password_hash)) != 0
        || copy_text_column(stmt, 3, user->role, sizeof(user->role)) != 0
        || copy_text_column(stmt, 5, user->created_at, sizeof(user->created_at)) != 0
        || copy_text_column(stmt, 6, user->updated_at, sizeof(user->updated_at)) != 0) {
        return -1;
    }
    user->enabled = sqlite3_column_int(stmt, 4) != 0;
    return 0;
}

static int scan_client_credential(sqlite3_stmt *stmt, st_storage_client_credential *credential)
{
    credential->id = sqlite3_column_int64(stmt, 0);
    if (copy_text_column(stmt, 1, credential->tenant_id, sizeof(credential->tenant_id)) != 0
        || copy_text_column(stmt, 2, credential->owner_username, sizeof(credential->owner_username)) != 0
        || copy_text_column(stmt, 3, credential->api_key, sizeof(credential->api_key)) != 0
        || copy_text_column(stmt, 4, credential->secret_hash, sizeof(credential->secret_hash)) != 0
        || copy_text_column(stmt, 7, credential->created_at, sizeof(credential->created_at)) != 0
        || copy_text_column(stmt, 8, credential->updated_at, sizeof(credential->updated_at)) != 0) {
        return -1;
    }
    credential->enabled = sqlite3_column_int(stmt, 5) != 0;
    credential->max_online_instances = sqlite3_column_int(stmt, 6);
    return 0;
}

static int scan_client_download_link(sqlite3_stmt *stmt, st_storage_client_download_link *link)
{
    link->id = sqlite3_column_int64(stmt, 0);
    if (copy_text_column(stmt, 1, link->implementation, sizeof(link->implementation)) != 0
        || copy_text_column(stmt, 2, link->platform, sizeof(link->platform)) != 0
        || copy_text_column(stmt, 3, link->arch, sizeof(link->arch)) != 0
        || copy_text_column(stmt, 4, link->display_name, sizeof(link->display_name)) != 0
        || copy_text_column(stmt, 5, link->download_url, sizeof(link->download_url)) != 0
        || copy_text_column(stmt, 6, link->description, sizeof(link->description)) != 0
        || copy_text_column(stmt, 9, link->created_at, sizeof(link->created_at)) != 0
        || copy_text_column(stmt, 10, link->updated_at, sizeof(link->updated_at)) != 0) {
        return -1;
    }
    link->display_order = sqlite3_column_int(stmt, 7);
    link->enabled = sqlite3_column_int(stmt, 8) != 0;
    return 0;
}

static int scan_client_identity(sqlite3_stmt *stmt, st_storage_client_identity *identity)
{
    identity->id = sqlite3_column_int64(stmt, 0);
    identity->credential_id = sqlite3_column_int64(stmt, 2);
    identity->client_id = sqlite3_column_int64(stmt, 3);
    if (copy_text_column(stmt, 1, identity->tenant_id, sizeof(identity->tenant_id)) != 0
        || copy_text_column(stmt, 4, identity->client_name, sizeof(identity->client_name)) != 0
        || copy_text_column(stmt, 5, identity->machine_fingerprint, sizeof(identity->machine_fingerprint)) != 0
        || copy_text_column(stmt, 6, identity->os_user, sizeof(identity->os_user)) != 0
        || copy_text_column(stmt, 7, identity->hostname, sizeof(identity->hostname)) != 0
        || copy_text_column(stmt, 8, identity->first_seen_at, sizeof(identity->first_seen_at)) != 0
        || copy_text_column(stmt, 9, identity->last_seen_at, sizeof(identity->last_seen_at)) != 0) {
        return -1;
    }
    return 0;
}

static int scan_client_session(sqlite3_stmt *stmt, st_storage_client_session *session)
{
    session->id = sqlite3_column_int64(stmt, 0);
    session->credential_id = sqlite3_column_int64(stmt, 2);
    session->identity_id = sqlite3_column_int64(stmt, 3);
    session->client_id = sqlite3_column_int64(stmt, 4);
    if (copy_text_column(stmt, 1, session->tenant_id, sizeof(session->tenant_id)) != 0
        || copy_text_column(stmt, 5, session->client_name, sizeof(session->client_name)) != 0
        || copy_text_column(stmt, 6, session->token_hash, sizeof(session->token_hash)) != 0
        || copy_text_column(stmt, 7, session->status, sizeof(session->status)) != 0
        || copy_text_column(stmt, 8, session->machine_fingerprint, sizeof(session->machine_fingerprint)) != 0
        || copy_text_column(stmt, 9, session->os_user, sizeof(session->os_user)) != 0
        || copy_text_column(stmt, 10, session->hostname, sizeof(session->hostname)) != 0
        || copy_text_column(stmt, 11, session->os_name, sizeof(session->os_name)) != 0
        || copy_text_column(stmt, 12, session->os_version, sizeof(session->os_version)) != 0
        || copy_text_column(stmt, 13, session->os_arch, sizeof(session->os_arch)) != 0
        || copy_text_column(stmt, 14, session->client_version, sizeof(session->client_version)) != 0
        || copy_text_column(stmt, 15, session->java_version, sizeof(session->java_version)) != 0
        || copy_text_column(stmt, 16, session->local_addresses, sizeof(session->local_addresses)) != 0
        || copy_text_column(stmt, 22, session->http_login_at, sizeof(session->http_login_at)) != 0
        || copy_text_column(stmt, 23, session->netty_connected_at, sizeof(session->netty_connected_at)) != 0
        || copy_text_column(stmt, 24, session->disconnected_at, sizeof(session->disconnected_at)) != 0
        || copy_text_column(stmt, 25, session->expires_at, sizeof(session->expires_at)) != 0
        || copy_text_column(stmt, 26, session->channel_id, sizeof(session->channel_id)) != 0
        || copy_text_column(stmt, 27, session->remote_address, sizeof(session->remote_address)) != 0) {
        return -1;
    }
    session->message_send_capable = sqlite3_column_int(stmt, 17) != 0;
    session->message_receive_capable = sqlite3_column_int(stmt, 18) != 0;
    session->message_attachments_capable = sqlite3_column_int(stmt, 19) != 0;
    session->message_media_preview_capable = sqlite3_column_int(stmt, 20) != 0;
    session->message_max_attachment_bytes = sqlite3_column_int64(stmt, 21);
    return 0;
}

static int scan_mapping(sqlite3_stmt *stmt, st_storage_mapping *mapping)
{
    mapping->id = sqlite3_column_int64(stmt, 0);
    mapping->client_id = sqlite3_column_int64(stmt, 1);
    if (copy_text_column(stmt, 2, mapping->client_name, sizeof(mapping->client_name)) != 0
        || copy_text_column(stmt, 4, mapping->target_address, sizeof(mapping->target_address)) != 0
        || copy_text_column(stmt, 8, mapping->created_at, sizeof(mapping->created_at)) != 0
        || copy_text_column(stmt, 9, mapping->updated_at, sizeof(mapping->updated_at)) != 0) {
        return -1;
    }
    mapping->listen_port = sqlite3_column_int(stmt, 3);
    mapping->target_port = sqlite3_column_int(stmt, 5);
    mapping->enabled = sqlite3_column_int(stmt, 6) != 0;
    mapping->detail_capture_enabled = sqlite3_column_int(stmt, 7) != 0;
    return 0;
}

static int scan_http_route(sqlite3_stmt *stmt, st_storage_http_route *route)
{
    route->id = sqlite3_column_int64(stmt, 0);
    route->client_id = sqlite3_column_int64(stmt, 1);
    if (copy_text_column(stmt, 2, route->client_name, sizeof(route->client_name)) != 0
        || copy_text_column(stmt, 3, route->route, sizeof(route->route)) != 0
        || copy_text_column(stmt, 4, route->target_base_url, sizeof(route->target_base_url)) != 0
        || copy_text_column(stmt, 8, route->created_at, sizeof(route->created_at)) != 0
        || copy_text_column(stmt, 9, route->updated_at, sizeof(route->updated_at)) != 0) {
        return -1;
    }
    route->enabled = sqlite3_column_int(stmt, 5) != 0;
    route->detail_capture_enabled = sqlite3_column_int(stmt, 6) != 0;
    route->path_rewrite_enabled = sqlite3_column_int(stmt, 7) != 0;
    return 0;
}

static int scan_connection(sqlite3_stmt *stmt, st_storage_connection *connection)
{
    connection->id = sqlite3_column_int64(stmt, 0);
    if (copy_text_column(stmt, 1, connection->tenant_id, sizeof(connection->tenant_id)) != 0) {
        return -1;
    }
    connection->client_id = sqlite3_column_type(stmt, 2) == SQLITE_NULL ? 0 : sqlite3_column_int64(stmt, 2);
    if (copy_text_column(stmt, 3, connection->client_name, sizeof(connection->client_name)) != 0
        || copy_text_column(stmt, 4, connection->channel_id, sizeof(connection->channel_id)) != 0
        || copy_text_column(stmt, 5, connection->remote_address, sizeof(connection->remote_address)) != 0
        || copy_text_column(stmt, 7, connection->failure_reason, sizeof(connection->failure_reason)) != 0
        || copy_text_column(stmt, 8, connection->disconnect_reason, sizeof(connection->disconnect_reason)) != 0
        || copy_text_column(stmt, 9, connection->connected_at, sizeof(connection->connected_at)) != 0
        || copy_text_column(stmt, 10, connection->disconnected_at, sizeof(connection->disconnected_at)) != 0) {
        return -1;
    }
    connection->success = sqlite3_column_int(stmt, 6) != 0;
    return 0;
}

static int scan_connection_stat(sqlite3_stmt *stmt, st_storage_connection_stat *stat)
{
    stat->id = sqlite3_column_int64(stmt, 0);
    stat->client_id = sqlite3_column_type(stmt, 1) == SQLITE_NULL ? 0 : sqlite3_column_int64(stmt, 1);
    if (copy_text_column(stmt, 2, stat->client_name, sizeof(stat->client_name)) != 0
        || copy_text_column(stmt, 3, stat->month, sizeof(stat->month)) != 0
        || copy_text_column(stmt, 7, stat->updated_at, sizeof(stat->updated_at)) != 0) {
        return -1;
    }
    stat->success = sqlite3_column_int64(stmt, 4);
    stat->failure = sqlite3_column_int64(stmt, 5);
    stat->total = sqlite3_column_int64(stmt, 6);
    return 0;
}

static int scan_traffic_usage(sqlite3_stmt *stmt, st_storage_traffic_usage *usage)
{
    usage->id = sqlite3_column_int64(stmt, 0);
    usage->client_id = sqlite3_column_type(stmt, 1) == SQLITE_NULL ? 0 : sqlite3_column_int64(stmt, 1);
    if (copy_text_column(stmt, 2, usage->client_name, sizeof(usage->client_name)) != 0
        || copy_text_column(stmt, 3, usage->usage_date, sizeof(usage->usage_date)) != 0
        || copy_text_column(stmt, 6, usage->updated_at, sizeof(usage->updated_at)) != 0) {
        return -1;
    }
    usage->upload_bytes = sqlite3_column_int64(stmt, 4);
    usage->download_bytes = sqlite3_column_int64(stmt, 5);
    return 0;
}

static int scan_resource_traffic_usage(sqlite3_stmt *stmt, st_storage_resource_traffic_usage *usage)
{
    usage->id = sqlite3_column_int64(stmt, 0);
    usage->client_id = sqlite3_column_type(stmt, 1) == SQLITE_NULL ? 0 : sqlite3_column_int64(stmt, 1);
    usage->resource_id = sqlite3_column_type(stmt, 5) == SQLITE_NULL ? 0 : sqlite3_column_int64(stmt, 5);
    if (copy_text_column(stmt, 2, usage->client_name, sizeof(usage->client_name)) != 0
        || copy_text_column(stmt, 3, usage->resource_type, sizeof(usage->resource_type)) != 0
        || copy_text_column(stmt, 4, usage->resource_key, sizeof(usage->resource_key)) != 0
        || copy_text_column(stmt, 6, usage->resource_name, sizeof(usage->resource_name)) != 0
        || copy_text_column(stmt, 7, usage->usage_date, sizeof(usage->usage_date)) != 0
        || copy_text_column(stmt, 10, usage->updated_at, sizeof(usage->updated_at)) != 0) {
        return -1;
    }
    usage->upload_bytes = sqlite3_column_int64(stmt, 8);
    usage->download_bytes = sqlite3_column_int64(stmt, 9);
    return 0;
}

static int scan_peer_mesh_device(sqlite3_stmt *stmt, st_storage_peer_mesh_device *device)
{
    device->id = sqlite3_column_int64(stmt, 0);
    device->client_id = sqlite3_column_int64(stmt, 3);
    if (copy_text_column(stmt, 1, device->tenant_id, sizeof(device->tenant_id)) != 0
        || copy_text_column(stmt, 2, device->owner_username, sizeof(device->owner_username)) != 0
        || copy_text_column(stmt, 4, device->client_name, sizeof(device->client_name)) != 0
        || copy_text_column(stmt, 6, device->virtual_ip, sizeof(device->virtual_ip)) != 0
        || copy_text_column(stmt, 7, device->public_key, sizeof(device->public_key)) != 0
        || copy_text_column(stmt, 8, device->nat_type, sizeof(device->nat_type)) != 0
        || copy_text_column(stmt, 9, device->last_endpoint, sizeof(device->last_endpoint)) != 0
        || copy_text_column(stmt, 10, device->virtual_device_mode, sizeof(device->virtual_device_mode)) != 0
        || copy_text_column(stmt, 11, device->virtual_device_name, sizeof(device->virtual_device_name)) != 0
        || copy_text_column(stmt, 12, device->virtual_device_status, sizeof(device->virtual_device_status)) != 0
        || copy_text_column(stmt, 13, device->virtual_device_error, sizeof(device->virtual_device_error)) != 0
        || copy_text_column(stmt, 14, device->virtual_device_updated_at, sizeof(device->virtual_device_updated_at)) != 0
        || copy_text_column(stmt, 15, device->last_seen_at, sizeof(device->last_seen_at)) != 0
        || copy_text_column(stmt, 16, device->updated_at, sizeof(device->updated_at)) != 0) {
        return -1;
    }
    device->enabled = sqlite3_column_int(stmt, 5) != 0;
    return 0;
}

static int scan_peer_mesh_acl(sqlite3_stmt *stmt, st_storage_peer_mesh_acl *acl)
{
    acl->id = sqlite3_column_int64(stmt, 0);
    acl->source_client_id = sqlite3_column_int64(stmt, 3);
    acl->target_client_id = sqlite3_column_int64(stmt, 5);
    if (copy_text_column(stmt, 1, acl->tenant_id, sizeof(acl->tenant_id)) != 0
        || copy_text_column(stmt, 2, acl->owner_username, sizeof(acl->owner_username)) != 0
        || copy_text_column(stmt, 4, acl->source_client_name, sizeof(acl->source_client_name)) != 0
        || copy_text_column(stmt, 6, acl->target_client_name, sizeof(acl->target_client_name)) != 0
        || copy_text_column(stmt, 8, acl->direction, sizeof(acl->direction)) != 0
        || copy_text_column(stmt, 9, acl->created_at, sizeof(acl->created_at)) != 0
        || copy_text_column(stmt, 10, acl->updated_at, sizeof(acl->updated_at)) != 0) {
        return -1;
    }
    acl->allowed = sqlite3_column_int(stmt, 7) != 0;
    return 0;
}

static int scan_peer_mesh_session(sqlite3_stmt *stmt, st_storage_peer_mesh_session *session)
{
    session->id = sqlite3_column_int64(stmt, 0);
    session->source_client_id = sqlite3_column_int64(stmt, 2);
    session->target_client_id = sqlite3_column_int64(stmt, 4);
    session->rtt_millis = sqlite3_column_type(stmt, 12) == SQLITE_NULL ? -1 : sqlite3_column_int64(stmt, 12);
    session->direct_bytes = sqlite3_column_int64(stmt, 15);
    session->relay_bytes = sqlite3_column_int64(stmt, 16);
    if (copy_text_column(stmt, 1, session->tenant_id, sizeof(session->tenant_id)) != 0
        || copy_text_column(stmt, 3, session->source_client_name, sizeof(session->source_client_name)) != 0
        || copy_text_column(stmt, 5, session->target_client_name, sizeof(session->target_client_name)) != 0
        || copy_text_column(stmt, 6, session->path_type, sizeof(session->path_type)) != 0
        || copy_text_column(stmt, 7, session->status, sizeof(session->status)) != 0
        || copy_text_column(stmt, 8, session->started_at, sizeof(session->started_at)) != 0
        || copy_text_column(stmt, 9, session->updated_at, sizeof(session->updated_at)) != 0
        || copy_text_column(stmt, 10, session->expires_at, sizeof(session->expires_at)) != 0
        || copy_text_column(stmt, 11, session->closed_at, sizeof(session->closed_at)) != 0
        || copy_text_column(stmt, 13, session->local_endpoint, sizeof(session->local_endpoint)) != 0
        || copy_text_column(stmt, 14, session->remote_endpoint, sizeof(session->remote_endpoint)) != 0
        || copy_text_column(stmt, 17, session->last_traffic_at, sizeof(session->last_traffic_at)) != 0) {
        return -1;
    }
    return 0;
}

static void bind_nullable_text(sqlite3_stmt *stmt, int index, const char *value)
{
    if (value == NULL || *value == '\0') {
        sqlite3_bind_null(stmt, index);
    } else {
        sqlite3_bind_text(stmt, index, value, -1, SQLITE_TRANSIENT);
    }
}

static void bind_nullable_text_limit(sqlite3_stmt *stmt, int index, const char *value, int max_len)
{
    if (value == NULL || *value == '\0') {
        sqlite3_bind_null(stmt, index);
        return;
    }
    int len = (int)strlen(value);
    if (len > max_len) {
        len = max_len;
    }
    sqlite3_bind_text(stmt, index, value, len, SQLITE_TRANSIENT);
}

static void build_hex_preview(const uint8_t *data, size_t len, char *out, size_t out_len)
{
    static const char hex[] = "0123456789abcdef";
    size_t preview_len = len < ST_STORAGE_PREVIEW_BYTES ? len : ST_STORAGE_PREVIEW_BYTES;
    size_t max_bytes = out_len > 0 ? (out_len - 1U) / 2U : 0U;
    if (preview_len > max_bytes) {
        preview_len = max_bytes;
    }
    for (size_t i = 0; i < preview_len; ++i) {
        out[i * 2U] = hex[(data[i] >> 4U) & 0x0fU];
        out[i * 2U + 1U] = hex[data[i] & 0x0fU];
    }
    if (out_len > 0) {
        out[preview_len * 2U] = '\0';
    }
}

static void build_text_preview(const uint8_t *data, size_t len, char *out, size_t out_len)
{
    size_t preview_len = len < ST_STORAGE_PREVIEW_BYTES ? len : ST_STORAGE_PREVIEW_BYTES;
    size_t w = 0;
    for (size_t i = 0; i < preview_len && w + 1U < out_len; ++i) {
        unsigned char ch = data[i];
        if (ch == '\r' || ch == '\n' || ch == '\t' || (ch >= 32U && ch < 127U)) {
            out[w++] = (char)ch;
        } else {
            out[w++] = '.';
        }
    }
    if (out_len > 0) {
        out[w] = '\0';
    }
}

static const char *classify_body_type(const char *content_type)
{
    if (content_type == NULL || *content_type == '\0') {
        return "unknown";
    }
    if (strstr(content_type, "json") != NULL) {
        return "json";
    }
    if (strstr(content_type, "text/") != NULL
        || strstr(content_type, "javascript") != NULL
        || strstr(content_type, "xml") != NULL
        || strstr(content_type, "css") != NULL
        || strstr(content_type, "html") != NULL) {
        return "text";
    }
    if (strstr(content_type, "image/") != NULL) {
        return "image";
    }
    if (strstr(content_type, "audio/") != NULL) {
        return "audio";
    }
    if (strstr(content_type, "video/") != NULL) {
        return "video";
    }
    return "binary";
}

static int scan_http_exchange(sqlite3_stmt *stmt, st_storage_http_exchange *item)
{
    item->id = sqlite3_column_int64(stmt, 0);
    if (copy_text_column(stmt, 1, item->tenant_id, sizeof(item->tenant_id)) != 0
        || copy_text_column(stmt, 3, item->client_name, sizeof(item->client_name)) != 0
        || copy_text_column(stmt, 4, item->route, sizeof(item->route)) != 0
        || copy_text_column(stmt, 6, item->resource_name, sizeof(item->resource_name)) != 0
        || copy_text_column(stmt, 7, item->method, sizeof(item->method)) != 0
        || copy_text_column(stmt, 8, item->relative_path, sizeof(item->relative_path)) != 0
        || copy_text_column(stmt, 9, item->raw_query, sizeof(item->raw_query)) != 0
        || copy_text_column(stmt, 12, item->error, sizeof(item->error)) != 0
        || copy_text_column(stmt, 13, item->remote_address, sizeof(item->remote_address)) != 0
        || copy_text_column(stmt, 17, item->request_content_type, sizeof(item->request_content_type)) != 0
        || copy_text_column(stmt, 18, item->response_content_type, sizeof(item->response_content_type)) != 0
        || copy_text_column(stmt, 19, item->response_body_type, sizeof(item->response_body_type)) != 0
        || copy_text_column(stmt, 20, item->request_headers, sizeof(item->request_headers)) != 0
        || copy_text_column(stmt, 21, item->response_headers, sizeof(item->response_headers)) != 0
        || copy_text_column(stmt, 22, item->request_preview_hex, sizeof(item->request_preview_hex)) != 0
        || copy_text_column(stmt, 23, item->request_preview_text, sizeof(item->request_preview_text)) != 0
        || copy_text_column(stmt, 24, item->response_preview_hex, sizeof(item->response_preview_hex)) != 0
        || copy_text_column(stmt, 25, item->response_preview_text, sizeof(item->response_preview_text)) != 0
        || copy_text_column(stmt, 28, item->captured_at, sizeof(item->captured_at)) != 0) {
        return -1;
    }
    item->client_id = sqlite3_column_int64(stmt, 2);
    item->resource_id = sqlite3_column_type(stmt, 5) == SQLITE_NULL ? 0 : sqlite3_column_int64(stmt, 5);
    item->status_code = sqlite3_column_int(stmt, 10);
    item->success = sqlite3_column_int(stmt, 11) != 0;
    item->request_bytes = sqlite3_column_int64(stmt, 14);
    item->response_bytes = sqlite3_column_int64(stmt, 15);
    item->elapsed_ms = sqlite3_column_int64(stmt, 16);
    item->request_truncated = sqlite3_column_int(stmt, 26) != 0;
    item->response_truncated = sqlite3_column_int(stmt, 27) != 0;
    return 0;
}

static int scan_tcp_frame(sqlite3_stmt *stmt, st_storage_tcp_frame *frame, int include_payload)
{
    frame->id = sqlite3_column_int64(stmt, 0);
    if (copy_text_column(stmt, 1, frame->tenant_id, sizeof(frame->tenant_id)) != 0
        || copy_text_column(stmt, 3, frame->client_name, sizeof(frame->client_name)) != 0
        || copy_text_column(stmt, 6, frame->resource_name, sizeof(frame->resource_name)) != 0
        || copy_text_column(stmt, 7, frame->channel_id, sizeof(frame->channel_id)) != 0
        || copy_text_column(stmt, 8, frame->direction, sizeof(frame->direction)) != 0
        || copy_text_column(stmt, 9, frame->remote_address, sizeof(frame->remote_address)) != 0
        || copy_text_column(stmt, 10, frame->source_address, sizeof(frame->source_address)) != 0
        || copy_text_column(stmt, 12, frame->destination_address, sizeof(frame->destination_address)) != 0
        || copy_text_column(stmt, 19, frame->payload_preview_hex, sizeof(frame->payload_preview_hex)) != 0
        || copy_text_column(stmt, 20, frame->payload_preview_text, sizeof(frame->payload_preview_text)) != 0
        || copy_text_column(stmt, 22, frame->frame_time, sizeof(frame->frame_time)) != 0) {
        return -1;
    }
    frame->client_id = sqlite3_column_int64(stmt, 2);
    frame->listen_port = sqlite3_column_int(stmt, 4);
    frame->resource_id = sqlite3_column_type(stmt, 5) == SQLITE_NULL ? 0 : sqlite3_column_int64(stmt, 5);
    frame->source_port = sqlite3_column_type(stmt, 11) == SQLITE_NULL ? 0 : sqlite3_column_int(stmt, 11);
    frame->destination_port = sqlite3_column_type(stmt, 13) == SQLITE_NULL ? 0 : sqlite3_column_int(stmt, 13);
    frame->stream_offset = sqlite3_column_type(stmt, 14) == SQLITE_NULL ? 0 : sqlite3_column_int64(stmt, 14);
    frame->stream_end_offset = sqlite3_column_type(stmt, 15) == SQLITE_NULL ? 0 : sqlite3_column_int64(stmt, 15);
    frame->frame_index = sqlite3_column_type(stmt, 16) == SQLITE_NULL ? 0 : sqlite3_column_int64(stmt, 16);
    frame->payload_bytes = sqlite3_column_int64(stmt, 17);
    frame->truncated = sqlite3_column_int(stmt, 21) != 0;
    frame->payload_data = NULL;
    frame->payload_data_len = 0;
    if (include_payload && sqlite3_column_type(stmt, 18) != SQLITE_NULL) {
        const void *blob = sqlite3_column_blob(stmt, 18);
        int len = sqlite3_column_bytes(stmt, 18);
        if (blob != NULL && len > 0) {
            frame->payload_data = (uint8_t *)malloc((size_t)len);
            if (frame->payload_data == NULL) {
                return -1;
            }
            memcpy(frame->payload_data, blob, (size_t)len);
            frame->payload_data_len = (size_t)len;
        }
    }
    return 0;
}

int st_storage_list_clients(const char *path,
                            st_storage_client *clients,
                            size_t max_clients,
                            size_t *client_count)
{
    *client_count = 0;
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT rowid, tenant_id, client_name, owner_username, enabled, "
        "connection_limit_per_minute, created_at, updated_at, "
        "COALESCE((SELECT message_send_capable FROM specus_client_session s WHERE s.client_id = client_account.rowid ORDER BY s.id DESC LIMIT 1), 0), "
        "COALESCE((SELECT message_receive_capable FROM specus_client_session s WHERE s.client_id = client_account.rowid ORDER BY s.id DESC LIMIT 1), 0), "
        "COALESCE((SELECT message_attachments_capable FROM specus_client_session s WHERE s.client_id = client_account.rowid ORDER BY s.id DESC LIMIT 1), 0), "
        "COALESCE((SELECT message_media_preview_capable FROM specus_client_session s WHERE s.client_id = client_account.rowid ORDER BY s.id DESC LIMIT 1), 0), "
        "COALESCE((SELECT message_max_attachment_bytes FROM specus_client_session s WHERE s.client_id = client_account.rowid ORDER BY s.id DESC LIMIT 1), 0) "
        "FROM client_account ORDER BY client_name",
        -1,
        &stmt,
        NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (*client_count >= max_clients || scan_client(stmt, &clients[*client_count]) != 0) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return -1;
        }
        ++*client_count;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == SQLITE_DONE ? 0 : -1;
}

int st_storage_get_client(const char *path, long long id, st_storage_client *client)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT rowid, tenant_id, client_name, owner_username, enabled, "
        "connection_limit_per_minute, created_at, updated_at, "
        "COALESCE((SELECT message_send_capable FROM specus_client_session s WHERE s.client_id = client_account.rowid ORDER BY s.id DESC LIMIT 1), 0), "
        "COALESCE((SELECT message_receive_capable FROM specus_client_session s WHERE s.client_id = client_account.rowid ORDER BY s.id DESC LIMIT 1), 0), "
        "COALESCE((SELECT message_attachments_capable FROM specus_client_session s WHERE s.client_id = client_account.rowid ORDER BY s.id DESC LIMIT 1), 0), "
        "COALESCE((SELECT message_media_preview_capable FROM specus_client_session s WHERE s.client_id = client_account.rowid ORDER BY s.id DESC LIMIT 1), 0), "
        "COALESCE((SELECT message_max_attachment_bytes FROM specus_client_session s WHERE s.client_id = client_account.rowid ORDER BY s.id DESC LIMIT 1), 0) "
        "FROM client_account WHERE rowid = ?",
        -1,
        &stmt,
        NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, id);
    rc = sqlite3_step(stmt);
    int ok = rc == SQLITE_ROW && scan_client(stmt, client) == 0;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return ok ? 0 : -1;
}

int st_storage_get_client_by_name(const char *path, const char *client_name, st_storage_client *client)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT rowid, tenant_id, client_name, owner_username, enabled, "
        "connection_limit_per_minute, created_at, updated_at, "
        "COALESCE((SELECT message_send_capable FROM specus_client_session s WHERE s.client_id = client_account.rowid ORDER BY s.id DESC LIMIT 1), 0), "
        "COALESCE((SELECT message_receive_capable FROM specus_client_session s WHERE s.client_id = client_account.rowid ORDER BY s.id DESC LIMIT 1), 0), "
        "COALESCE((SELECT message_attachments_capable FROM specus_client_session s WHERE s.client_id = client_account.rowid ORDER BY s.id DESC LIMIT 1), 0), "
        "COALESCE((SELECT message_media_preview_capable FROM specus_client_session s WHERE s.client_id = client_account.rowid ORDER BY s.id DESC LIMIT 1), 0), "
        "COALESCE((SELECT message_max_attachment_bytes FROM specus_client_session s WHERE s.client_id = client_account.rowid ORDER BY s.id DESC LIMIT 1), 0) "
        "FROM client_account WHERE client_name = ?",
        -1,
        &stmt,
        NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, client_name, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);
    int ok = rc == SQLITE_ROW && scan_client(stmt, client) == 0;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return ok ? 0 : -1;
}

int st_storage_list_management_users(const char *path,
                                     const char *tenant_id,
                                     st_storage_management_user *users,
                                     size_t max_users,
                                     size_t *user_count)
{
    *user_count = 0;
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    const char *sql = tenant_id != NULL && *tenant_id != '\0'
        ? "SELECT username, tenant_id, password_hash, role, enabled, created_at, updated_at "
          "FROM specus_management_user WHERE tenant_id = ? ORDER BY lower(username)"
        : "SELECT username, tenant_id, password_hash, role, enabled, created_at, updated_at "
          "FROM specus_management_user ORDER BY tenant_id, lower(username)";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    if (tenant_id != NULL && *tenant_id != '\0') {
        sqlite3_bind_text(stmt, 1, tenant_id, -1, SQLITE_TRANSIENT);
    }
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (*user_count >= max_users || scan_management_user(stmt, &users[*user_count]) != 0) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return -1;
        }
        ++*user_count;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == SQLITE_DONE ? 0 : -1;
}

int st_storage_get_management_user(const char *path,
                                   const char *username,
                                   st_storage_management_user *user)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT username, tenant_id, password_hash, role, enabled, created_at, updated_at "
        "FROM specus_management_user WHERE lower(username) = lower(?)",
        -1,
        &stmt,
        NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);
    int ok = rc == SQLITE_ROW && scan_management_user(stmt, user) == 0;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return ok ? 0 : -1;
}

int st_storage_create_management_user(const char *path,
                                      const char *username,
                                      const char *tenant_id,
                                      const char *password_hash,
                                      const char *role,
                                      int enabled,
                                      st_storage_management_user *out_user)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    if (tenant_id == NULL || *tenant_id == '\0') {
        tenant_id = "default";
    }
    if (role == NULL || *role == '\0') {
        role = "USER";
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT INTO specus_management_user(username, tenant_id, password_hash, role, enabled, created_at, updated_at) "
        "VALUES(?,?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)",
        -1,
        &stmt,
        NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, tenant_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, password_hash, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, role, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 5, enabled ? 1 : 0);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    if (rc != 0) {
        return -1;
    }
    return out_user == NULL ? 0 : st_storage_get_management_user(path, username, out_user);
}

int st_storage_update_management_user(const char *path,
                                      const char *username,
                                      const char *password_hash,
                                      const char *role,
                                      int enabled,
                                      st_storage_management_user *out_user)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "UPDATE specus_management_user SET "
        "password_hash = COALESCE(?, password_hash), "
        "role = COALESCE(?, role), "
        "enabled = ?, updated_at = CURRENT_TIMESTAMP "
        "WHERE lower(username) = lower(?)",
        -1,
        &stmt,
        NULL);
    if (rc == SQLITE_OK) {
        if (password_hash == NULL || *password_hash == '\0') {
            sqlite3_bind_null(stmt, 1);
        } else {
            sqlite3_bind_text(stmt, 1, password_hash, -1, SQLITE_TRANSIENT);
        }
        if (role == NULL || *role == '\0') {
            sqlite3_bind_null(stmt, 2);
        } else {
            sqlite3_bind_text(stmt, 2, role, -1, SQLITE_TRANSIENT);
        }
        sqlite3_bind_int(stmt, 3, enabled ? 1 : 0);
        sqlite3_bind_text(stmt, 4, username, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db) == 1 ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    if (rc != 0) {
        return -1;
    }
    return out_user == NULL ? 0 : st_storage_get_management_user(path, username, out_user);
}

int st_storage_delete_management_user(const char *path, const char *username)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "DELETE FROM specus_management_user WHERE lower(username) = lower(?)",
        -1,
        &stmt,
        NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db) == 1 ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == 0 ? 0 : -1;
}

int st_storage_get_client_credential_by_api_key(const char *path,
                                                const char *api_key,
                                                st_storage_client_credential *credential)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT id, tenant_id, owner_username, api_key, secret_hash, enabled, "
        "max_online_instances, created_at, updated_at "
        "FROM specus_client_credential WHERE api_key = ?",
        -1,
        &stmt,
        NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, api_key, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);
    int ok = rc == SQLITE_ROW && scan_client_credential(stmt, credential) == 0;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return ok ? 0 : -1;
}

int st_storage_get_client_credential(const char *path,
                                     long long id,
                                     st_storage_client_credential *credential)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT id, tenant_id, owner_username, api_key, secret_hash, enabled, "
        "max_online_instances, created_at, updated_at "
        "FROM specus_client_credential WHERE id = ?",
        -1,
        &stmt,
        NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, id);
    rc = sqlite3_step(stmt);
    int ok = rc == SQLITE_ROW && scan_client_credential(stmt, credential) == 0;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return ok ? 0 : -1;
}

int st_storage_list_client_credentials(const char *path,
                                       const char *tenant_id,
                                       st_storage_client_credential *credentials,
                                       size_t max_credentials,
                                       size_t *credential_count)
{
    *credential_count = 0;
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT id, tenant_id, owner_username, api_key, secret_hash, enabled, "
        "max_online_instances, created_at, updated_at "
        "FROM specus_client_credential WHERE tenant_id = ? ORDER BY id DESC",
        -1,
        &stmt,
        NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, tenant_id == NULL || *tenant_id == '\0' ? "default" : tenant_id, -1, SQLITE_TRANSIENT);
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (*credential_count >= max_credentials) {
            break;
        }
        if (scan_client_credential(stmt, &credentials[*credential_count]) != 0) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return -1;
        }
        ++(*credential_count);
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == SQLITE_DONE || *credential_count == max_credentials ? 0 : -1;
}

int st_storage_upsert_client_credential(const char *path,
                                        long long id,
                                        const char *tenant_id,
                                        const char *owner_username,
                                        const char *api_key,
                                        const char *secret_hash,
                                        int enabled,
                                        int max_online_instances,
                                        st_storage_client_credential *out_credential)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    if (tenant_id == NULL || *tenant_id == '\0') {
        tenant_id = "default";
    }
    if (owner_username == NULL) {
        owner_username = "";
    }
    if (max_online_instances <= 0) {
        max_online_instances = 2;
    }
    sqlite3_stmt *stmt = NULL;
    const char *sql_insert =
        "INSERT INTO specus_client_credential(tenant_id, owner_username, api_key, secret_hash, enabled, max_online_instances, created_at, updated_at) "
        "VALUES(?,?,?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP) "
        "ON CONFLICT(api_key) DO UPDATE SET "
        "tenant_id = excluded.tenant_id,"
        "owner_username = excluded.owner_username,"
        "secret_hash = excluded.secret_hash,"
        "enabled = excluded.enabled,"
        "max_online_instances = excluded.max_online_instances,"
        "updated_at = CURRENT_TIMESTAMP";
    const char *sql_update =
        "UPDATE specus_client_credential SET tenant_id = ?, owner_username = ?, api_key = ?, secret_hash = ?, "
        "enabled = ?, max_online_instances = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?";
    int rc = sqlite3_prepare_v2(db, id > 0 ? sql_update : sql_insert, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, tenant_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, owner_username, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, api_key, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, secret_hash, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 5, enabled ? 1 : 0);
        sqlite3_bind_int(stmt, 6, max_online_instances);
        if (id > 0) {
            sqlite3_bind_int64(stmt, 7, id);
        }
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
        if (id > 0 && sqlite3_changes(db) != 1) {
            rc = -1;
        }
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    if (rc != 0) {
        return -1;
    }
    return out_credential == NULL ? 0 : st_storage_get_client_credential_by_api_key(path, api_key, out_credential);
}

int st_storage_delete_client_credential(const char *path, long long id)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "DELETE FROM specus_client_credential WHERE id = ?",
        -1,
        &stmt,
        NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, id);
        rc = sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db) == 1 ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == 0 ? 0 : -1;
}

int st_storage_list_client_download_links(const char *path,
                                          int enabled_only,
                                          st_storage_client_download_link *links,
                                          size_t max_links,
                                          size_t *link_count)
{
    *link_count = 0;
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    const char *sql_admin =
        "SELECT id, implementation, platform, arch, display_name, download_url, description, "
        "display_order, enabled, created_at, updated_at "
        "FROM client_download_link ORDER BY display_order ASC, id ASC";
    const char *sql_public =
        "SELECT id, implementation, platform, arch, display_name, download_url, description, "
        "display_order, enabled, created_at, updated_at "
        "FROM client_download_link WHERE enabled = 1 ORDER BY implementation ASC, display_order ASC, id ASC";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, enabled_only ? sql_public : sql_admin, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (*link_count >= max_links) {
            break;
        }
        if (scan_client_download_link(stmt, &links[*link_count]) != 0) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return -1;
        }
        ++(*link_count);
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == SQLITE_DONE || *link_count == max_links ? 0 : -1;
}

int st_storage_get_client_download_link(const char *path,
                                        long long id,
                                        st_storage_client_download_link *link)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT id, implementation, platform, arch, display_name, download_url, description, "
        "display_order, enabled, created_at, updated_at "
        "FROM client_download_link WHERE id = ?",
        -1,
        &stmt,
        NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, id);
    rc = sqlite3_step(stmt);
    int ok = rc == SQLITE_ROW && scan_client_download_link(stmt, link) == 0;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return ok ? 0 : -1;
}

int st_storage_upsert_client_download_link(const char *path,
                                           long long id,
                                           const char *implementation,
                                           const char *platform,
                                           const char *arch,
                                           const char *display_name,
                                           const char *download_url,
                                           const char *description,
                                           int display_order,
                                           int enabled,
                                           st_storage_client_download_link *out_link)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    const char *sql_insert =
        "INSERT INTO client_download_link(implementation, platform, arch, display_name, download_url, "
        "description, display_order, enabled, created_at, updated_at) "
        "VALUES(?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)";
    const char *sql_update =
        "UPDATE client_download_link SET implementation = ?, platform = ?, arch = ?, display_name = ?, "
        "download_url = ?, description = ?, display_order = ?, enabled = ?, updated_at = CURRENT_TIMESTAMP "
        "WHERE id = ?";
    int rc = sqlite3_prepare_v2(db, id > 0 ? sql_update : sql_insert, -1, &stmt, NULL);
    long long written_id = id;
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, implementation, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, platform, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, arch, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, display_name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, download_url, -1, SQLITE_TRANSIENT);
        bind_nullable_text_limit(stmt, 6, description, 512);
        sqlite3_bind_int(stmt, 7, display_order);
        sqlite3_bind_int(stmt, 8, enabled ? 1 : 0);
        if (id > 0) {
            sqlite3_bind_int64(stmt, 9, id);
        }
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
        if (id > 0 && sqlite3_changes(db) != 1) {
            rc = -1;
        }
        if (rc == 0 && id <= 0) {
            written_id = sqlite3_last_insert_rowid(db);
        }
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    if (rc != 0) {
        return -1;
    }
    return out_link == NULL ? 0 : st_storage_get_client_download_link(path, written_id, out_link);
}

int st_storage_delete_client_download_link(const char *path, long long id)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "DELETE FROM client_download_link WHERE id = ?",
        -1,
        &stmt,
        NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, id);
        rc = sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db) == 1 ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == 0 ? 0 : -1;
}

static void slug_text(const char *value, const char *fallback, char *out, size_t out_len)
{
    if (out_len == 0) {
        return;
    }
    size_t w = 0;
    const char *source = value != NULL && *value != '\0' ? value : fallback;
    for (const unsigned char *p = (const unsigned char *)source; *p != '\0' && w + 1U < out_len && w < 50U; ++p) {
        int ch = tolower(*p);
        if ((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '-') {
            out[w++] = (char)ch;
        } else if (w > 0 && out[w - 1U] != '-') {
            out[w++] = '-';
        }
    }
    while (w > 0 && out[w - 1U] == '-') {
        --w;
    }
    if (w == 0) {
        snprintf(out, out_len, "%s", fallback == NULL || *fallback == '\0' ? "client" : fallback);
        return;
    }
    out[w] = '\0';
}

static int client_name_exists(sqlite3 *db, const char *client_name)
{
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, "SELECT 1 FROM client_account WHERE client_name = ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, client_name, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_ROW ? 1 : (rc == SQLITE_DONE ? 0 : -1);
}

static int build_client_name(sqlite3 *db,
                             const st_storage_client_credential *credential,
                             const char *machine_fingerprint,
                             const char *os_user,
                             const char *hostname,
                             char *out,
                             size_t out_len)
{
    char host_slug[64];
    char user_slug[64];
    slug_text(hostname, "client", host_slug, sizeof(host_slug));
    slug_text(os_user, "user", user_slug, sizeof(user_slug));
    char seed[512];
    int written = snprintf(seed,
                           sizeof(seed),
                           "%lld\n%s\n%s",
                           credential->id,
                           machine_fingerprint == NULL ? "" : machine_fingerprint,
                           os_user == NULL ? "" : os_user);
    if (written < 0 || (size_t)written >= sizeof(seed)) {
        return -1;
    }
    uint8_t digest[ST_SHA256_LEN];
    char hex[ST_SHA256_HEX_LEN + 1];
    st_sha256((const uint8_t *)seed, strlen(seed), digest);
    st_hex_encode(digest, sizeof(digest), hex);
    char base[121];
    snprintf(base, sizeof(base), "%.50s-%.50s-%.8s", host_slug, user_slug, hex);
    for (int i = 1; i < 1000; ++i) {
        if (i == 1) {
            snprintf(out, out_len, "%s", base);
        } else {
            snprintf(out, out_len, "%.112s-%d", base, i);
        }
        int exists = client_name_exists(db, out);
        if (exists == 0) {
            return 0;
        }
        if (exists < 0) {
            return -1;
        }
    }
    return -1;
}

static int load_identity_by_machine(sqlite3 *db,
                                    long long credential_id,
                                    const char *machine_fingerprint,
                                    const char *os_user,
                                    st_storage_client_identity *identity)
{
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT id, tenant_id, credential_id, client_id, client_name, machine_fingerprint, os_user, "
        "hostname, first_seen_at, last_seen_at "
        "FROM specus_client_identity WHERE credential_id = ? AND machine_fingerprint = ? AND os_user = ?",
        -1,
        &stmt,
        NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, credential_id);
    sqlite3_bind_text(stmt, 2, machine_fingerprint, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, os_user, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);
    int ok = rc == SQLITE_ROW && scan_client_identity(stmt, identity) == 0;
    sqlite3_finalize(stmt);
    return ok ? 0 : -1;
}

int st_storage_find_or_create_client_identity(const char *path,
                                              const st_storage_client_credential *credential,
                                              const char *machine_fingerprint,
                                              const char *os_user,
                                              const char *hostname,
                                              st_storage_client_identity *identity)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    if (load_identity_by_machine(db, credential->id, machine_fingerprint, os_user, identity) == 0) {
        sqlite3_stmt *update = NULL;
        int rc = sqlite3_prepare_v2(db,
            "UPDATE specus_client_identity SET hostname = ?, last_seen_at = CURRENT_TIMESTAMP WHERE id = ?",
            -1,
            &update,
            NULL);
        if (rc == SQLITE_OK) {
            sqlite3_bind_text(update, 1, hostname == NULL ? "" : hostname, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(update, 2, identity->id);
            rc = sqlite3_step(update) == SQLITE_DONE ? 0 : -1;
        } else {
            rc = -1;
        }
        sqlite3_finalize(update);
        if (rc == 0) {
            rc = load_identity_by_machine(db, credential->id, machine_fingerprint, os_user, identity);
        }
        sqlite3_close(db);
        return rc == 0 ? 0 : -1;
    }

    char client_name[121];
    if (build_client_name(db, credential, machine_fingerprint, os_user, hostname, client_name, sizeof(client_name)) != 0) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_stmt *client_stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT INTO client_account(tenant_id, client_name, owner_username, enabled, connection_limit_per_minute, created_at, updated_at) "
        "VALUES(?,?,?,?,30,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)",
        -1,
        &client_stmt,
        NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(client_stmt, 1, credential->tenant_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(client_stmt, 2, client_name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(client_stmt, 3, credential->owner_username, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(client_stmt, 4, 1);
        rc = sqlite3_step(client_stmt) == SQLITE_DONE ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(client_stmt);
    long long client_id = sqlite3_last_insert_rowid(db);
    if (rc != 0 || client_id <= 0) {
        sqlite3_close(db);
        return -1;
    }

    sqlite3_stmt *identity_stmt = NULL;
    rc = sqlite3_prepare_v2(db,
        "INSERT INTO specus_client_identity(tenant_id, credential_id, client_id, client_name, machine_fingerprint, os_user, hostname, first_seen_at, last_seen_at) "
        "VALUES(?,?,?,?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)",
        -1,
        &identity_stmt,
        NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(identity_stmt, 1, credential->tenant_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(identity_stmt, 2, credential->id);
        sqlite3_bind_int64(identity_stmt, 3, client_id);
        sqlite3_bind_text(identity_stmt, 4, client_name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(identity_stmt, 5, machine_fingerprint, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(identity_stmt, 6, os_user, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(identity_stmt, 7, hostname == NULL ? "" : hostname, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(identity_stmt) == SQLITE_DONE ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(identity_stmt);
    if (rc == 0) {
        rc = load_identity_by_machine(db, credential->id, machine_fingerprint, os_user, identity);
    }
    sqlite3_close(db);
    return rc == 0 ? 0 : -1;
}

int st_storage_close_http_authenticated_sessions(const char *path,
                                                 long long credential_id,
                                                 const char *machine_fingerprint,
                                                 const char *os_user,
                                                 const char *disconnected_at)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "UPDATE specus_client_session SET status = 'DISCONNECTED', disconnected_at = ? "
        "WHERE credential_id = ? AND machine_fingerprint = ? AND os_user = ? AND status = 'HTTP_AUTHENTICATED'",
        -1,
        &stmt,
        NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, disconnected_at == NULL ? "" : disconnected_at, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 2, credential_id);
        sqlite3_bind_text(stmt, 3, machine_fingerprint, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, os_user, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == 0 ? 0 : -1;
}

static int load_client_session_by_id(const char *path, long long id, st_storage_client_session *session)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT id, tenant_id, credential_id, identity_id, client_id, client_name, token_hash, status, "
        "machine_fingerprint, os_user, hostname, os_name, os_version, os_arch, client_version, java_version, "
        "local_addresses, message_send_capable, message_receive_capable, message_attachments_capable, "
        "message_media_preview_capable, message_max_attachment_bytes, http_login_at, netty_connected_at, "
        "disconnected_at, expires_at, channel_id, remote_address "
        "FROM specus_client_session WHERE id = ?",
        -1,
        &stmt,
        NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, id);
    rc = sqlite3_step(stmt);
    int ok = rc == SQLITE_ROW && scan_client_session(stmt, session) == 0;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return ok ? 0 : -1;
}

int st_storage_create_client_session(const char *path,
                                     const st_storage_client_session *session,
                                     st_storage_client_session *out_session)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT INTO specus_client_session(tenant_id, credential_id, identity_id, client_id, client_name, token_hash, status, "
        "machine_fingerprint, os_user, hostname, os_name, os_version, os_arch, client_version, java_version, local_addresses, "
        "message_send_capable, message_receive_capable, message_attachments_capable, message_media_preview_capable, "
        "message_max_attachment_bytes, http_login_at, expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        -1,
        &stmt,
        NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, session->tenant_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 2, session->credential_id);
        sqlite3_bind_int64(stmt, 3, session->identity_id);
        sqlite3_bind_int64(stmt, 4, session->client_id);
        sqlite3_bind_text(stmt, 5, session->client_name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 6, session->token_hash, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 7, session->status, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 8, session->machine_fingerprint, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 9, session->os_user, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 10, session->hostname, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 11, session->os_name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 12, session->os_version, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 13, session->os_arch, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 14, session->client_version, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 15, session->java_version, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 16, session->local_addresses, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 17, session->message_send_capable ? 1 : 0);
        sqlite3_bind_int(stmt, 18, session->message_receive_capable ? 1 : 0);
        sqlite3_bind_int(stmt, 19, session->message_attachments_capable ? 1 : 0);
        sqlite3_bind_int(stmt, 20, session->message_media_preview_capable ? 1 : 0);
        sqlite3_bind_int64(stmt, 21, session->message_max_attachment_bytes < 0 ? 0 : session->message_max_attachment_bytes);
        sqlite3_bind_text(stmt, 22, session->http_login_at, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 23, session->expires_at, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    long long id = sqlite3_last_insert_rowid(db);
    sqlite3_close(db);
    if (rc != 0 || id <= 0) {
        return -1;
    }
    return out_session == NULL ? 0 : load_client_session_by_id(path, id, out_session);
}

int st_storage_get_client_session_for_login(const char *path,
                                            long long id,
                                            const char *token_hash,
                                            st_storage_client_session *session)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT id, tenant_id, credential_id, identity_id, client_id, client_name, token_hash, status, "
        "machine_fingerprint, os_user, hostname, os_name, os_version, os_arch, client_version, java_version, "
        "local_addresses, message_send_capable, message_receive_capable, message_attachments_capable, "
        "message_media_preview_capable, message_max_attachment_bytes, http_login_at, netty_connected_at, "
        "disconnected_at, expires_at, channel_id, remote_address "
        "FROM specus_client_session WHERE id = ? AND token_hash = ?",
        -1,
        &stmt,
        NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, id);
    sqlite3_bind_text(stmt, 2, token_hash, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);
    int ok = rc == SQLITE_ROW && scan_client_session(stmt, session) == 0;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return ok ? 0 : -1;
}

static int count_online_client_sessions(const char *path,
                                        const char *sql,
                                        long long credential_id,
                                        const char *machine_fingerprint,
                                        const char *os_user,
                                        long long exclude_session_id,
                                        int *count)
{
    *count = 0;
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, credential_id);
        int next = 2;
        if (machine_fingerprint != NULL) {
            sqlite3_bind_text(stmt, next++, machine_fingerprint, -1, SQLITE_TRANSIENT);
        }
        if (os_user != NULL) {
            sqlite3_bind_text(stmt, next++, os_user, -1, SQLITE_TRANSIENT);
        }
        sqlite3_bind_int64(stmt, next, exclude_session_id);
        rc = sqlite3_step(stmt);
        if (rc == SQLITE_ROW) {
            *count = sqlite3_column_int(stmt, 0);
            rc = 0;
        } else {
            rc = -1;
        }
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == 0 ? 0 : -1;
}

int st_storage_count_online_sessions_by_machine(const char *path,
                                                long long credential_id,
                                                const char *machine_fingerprint,
                                                const char *os_user,
                                                long long exclude_session_id,
                                                int *count)
{
    return count_online_client_sessions(path,
        "SELECT COUNT(*) FROM specus_client_session "
        "WHERE credential_id = ? AND machine_fingerprint = ? AND os_user = ? "
        "AND id <> ? AND status = 'NETTY_ONLINE'",
        credential_id,
        machine_fingerprint,
        os_user,
        exclude_session_id,
        count);
}

int st_storage_count_online_sessions_by_credential(const char *path,
                                                   long long credential_id,
                                                   long long exclude_session_id,
                                                   int *count)
{
    return count_online_client_sessions(path,
        "SELECT COUNT(*) FROM specus_client_session "
        "WHERE credential_id = ? AND id <> ? AND status = 'NETTY_ONLINE'",
        credential_id,
        NULL,
        NULL,
        exclude_session_id,
        count);
}

int st_storage_mark_client_session_online(const char *path,
                                          long long id,
                                          const char *channel_id,
                                          const char *remote_address,
                                          const char *connected_at)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "UPDATE specus_client_session SET status = 'NETTY_ONLINE', netty_connected_at = ?, "
        "disconnected_at = NULL, channel_id = ?, remote_address = ? WHERE id = ?",
        -1,
        &stmt,
        NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, connected_at == NULL ? "" : connected_at, -1, SQLITE_TRANSIENT);
        if (channel_id == NULL || *channel_id == '\0') {
            sqlite3_bind_null(stmt, 2);
        } else {
            sqlite3_bind_text(stmt, 2, channel_id, -1, SQLITE_TRANSIENT);
        }
        if (remote_address == NULL || *remote_address == '\0') {
            sqlite3_bind_null(stmt, 3);
        } else {
            sqlite3_bind_text(stmt, 3, remote_address, -1, SQLITE_TRANSIENT);
        }
        sqlite3_bind_int64(stmt, 4, id);
        rc = sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db) == 1 ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == 0 ? 0 : -1;
}

int st_storage_mark_client_session_disconnected(const char *path,
                                                long long id,
                                                const char *disconnected_at)
{
    if (id <= 0) {
        return 0;
    }
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "UPDATE specus_client_session SET status = 'DISCONNECTED', disconnected_at = COALESCE(disconnected_at, ?) "
        "WHERE id = ?",
        -1,
        &stmt,
        NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, disconnected_at == NULL ? "" : disconnected_at, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 2, id);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == 0 ? 0 : -1;
}

int st_storage_close_client_sessions_by_status(const char *path,
                                               const char *from_status,
                                               const char *disconnected_at)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "UPDATE specus_client_session SET status = 'DISCONNECTED', disconnected_at = COALESCE(disconnected_at, ?) "
        "WHERE status = ?",
        -1,
        &stmt,
        NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, disconnected_at == NULL ? "" : disconnected_at, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, from_status == NULL ? "" : from_status, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == 0 ? 0 : -1;
}

int st_storage_upsert_client(const char *path,
                             long long id,
                             const char *tenant_id,
                             const char *client_name,
                             const char *owner_username,
                             int enabled,
                             int connection_rate_limit_per_minute,
                             st_storage_client *out_client)
{
    st_storage_client existing;
    int has_existing = id > 0 && st_storage_get_client(path, id, &existing) == 0;
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    if (tenant_id == NULL || *tenant_id == '\0') {
        tenant_id = "default";
    }
    if (owner_username == NULL || *owner_username == '\0') {
        owner_username = "admin";
    }
    if (connection_rate_limit_per_minute <= 0) {
        connection_rate_limit_per_minute = 30;
    }
    sqlite3_stmt *stmt = NULL;
    int rc;
    if (id > 0) {
        rc = sqlite3_prepare_v2(db,
            "UPDATE client_account SET tenant_id = ?, client_name = ?, owner_username = ?, "
            "enabled = ?, connection_limit_per_minute = ?, updated_at = CURRENT_TIMESTAMP "
            "WHERE rowid = ?",
            -1,
            &stmt,
            NULL);
        if (rc == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, tenant_id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, client_name, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 3, owner_username, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(stmt, 4, enabled ? 1 : 0);
            sqlite3_bind_int(stmt, 5, connection_rate_limit_per_minute);
            sqlite3_bind_int64(stmt, 6, id);
            rc = sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db) == 1 ? 0 : -1;
        } else {
            rc = -1;
        }
        sqlite3_finalize(stmt);
        if (rc == 0 && has_existing && strcmp(existing.client_name, client_name) != 0) {
            rc = sqlite3_prepare_v2(db,
                "UPDATE specus_mapping SET client_name = ?, updated_at = CURRENT_TIMESTAMP WHERE client_name = ?",
                -1,
                &stmt,
                NULL);
            if (rc == SQLITE_OK) {
                sqlite3_bind_text(stmt, 1, client_name, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 2, existing.client_name, -1, SQLITE_TRANSIENT);
                rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
            } else {
                rc = -1;
            }
            sqlite3_finalize(stmt);
        }
        if (rc == 0 && has_existing && strcmp(existing.client_name, client_name) != 0) {
            rc = sqlite3_prepare_v2(db,
                "UPDATE http_route_mapping SET client_name = ?, updated_at = CURRENT_TIMESTAMP WHERE client_name = ?",
                -1,
                &stmt,
                NULL);
            if (rc == SQLITE_OK) {
                sqlite3_bind_text(stmt, 1, client_name, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 2, existing.client_name, -1, SQLITE_TRANSIENT);
                rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
            } else {
                rc = -1;
            }
            sqlite3_finalize(stmt);
        }
    } else {
        rc = sqlite3_prepare_v2(db,
            "INSERT INTO client_account(tenant_id, client_name, owner_username, enabled, connection_limit_per_minute) "
            "VALUES(?,?,?,?,?)",
            -1,
            &stmt,
            NULL);
        if (rc == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, tenant_id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, client_name, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 3, owner_username, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(stmt, 4, enabled ? 1 : 0);
            sqlite3_bind_int(stmt, 5, connection_rate_limit_per_minute);
            rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
            id = sqlite3_last_insert_rowid(db);
        } else {
            rc = -1;
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    if (rc != 0) {
        return -1;
    }
    return out_client == NULL ? 0 : st_storage_get_client(path, id, out_client);
}

int st_storage_delete_client(const char *path, long long id)
{
    st_storage_client client;
    if (st_storage_get_client(path, id, &client) != 0) {
        return -1;
    }
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, "DELETE FROM specus_mapping WHERE client_name = ?", -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, client.client_name, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    if (rc == 0) {
        rc = sqlite3_prepare_v2(db, "DELETE FROM http_route_mapping WHERE client_name = ?", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, client.client_name, -1, SQLITE_TRANSIENT);
            rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
        } else {
            rc = -1;
        }
        sqlite3_finalize(stmt);
    }
    if (rc == 0) {
        rc = sqlite3_prepare_v2(db, "DELETE FROM client_account WHERE rowid = ?", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, id);
            rc = sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db) == 1 ? 0 : -1;
        } else {
            rc = -1;
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    return rc == 0 ? 0 : -1;
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
        "SELECT m.id, c.rowid, m.client_name, m.listen_port, m.target_address, m.target_port, "
        "m.enabled, m.detail_capture_enabled, m.created_at, m.updated_at "
        "FROM specus_mapping m JOIN client_account c ON c.client_name = m.client_name "
        "WHERE m.client_name = ? AND m.enabled = 1 ORDER BY m.listen_port",
        -1,
        &stmt,
        NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, client_name, -1, SQLITE_TRANSIENT);
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (*mapping_count >= max_mappings || scan_mapping(stmt, &mappings[*mapping_count]) != 0) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return -1;
        }
        ++*mapping_count;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == SQLITE_DONE ? 0 : -1;
}

int st_storage_list_mappings(const char *path,
                             long long client_id,
                             st_storage_mapping *mappings,
                             size_t max_mappings,
                             size_t *mapping_count)
{
    *mapping_count = 0;
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    const char *sql_all =
        "SELECT m.id, c.rowid, m.client_name, m.listen_port, m.target_address, m.target_port, "
        "m.enabled, m.detail_capture_enabled, m.created_at, m.updated_at "
        "FROM specus_mapping m JOIN client_account c ON c.client_name = m.client_name "
        "ORDER BY m.id DESC";
    const char *sql_filtered =
        "SELECT m.id, c.rowid, m.client_name, m.listen_port, m.target_address, m.target_port, "
        "m.enabled, m.detail_capture_enabled, m.created_at, m.updated_at "
        "FROM specus_mapping m JOIN client_account c ON c.client_name = m.client_name "
        "WHERE c.rowid = ? ORDER BY m.id DESC";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, client_id > 0 ? sql_filtered : sql_all, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    if (client_id > 0) {
        sqlite3_bind_int64(stmt, 1, client_id);
    }
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (*mapping_count >= max_mappings || scan_mapping(stmt, &mappings[*mapping_count]) != 0) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return -1;
        }
        ++*mapping_count;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int load_mapping_by_id(const char *path, long long id, st_storage_mapping *mapping)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT m.id, c.rowid, m.client_name, m.listen_port, m.target_address, m.target_port, "
        "m.enabled, m.detail_capture_enabled, m.created_at, m.updated_at "
        "FROM specus_mapping m JOIN client_account c ON c.client_name = m.client_name "
        "WHERE m.id = ?",
        -1,
        &stmt,
        NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, id);
    rc = sqlite3_step(stmt);
    int ok = rc == SQLITE_ROW && scan_mapping(stmt, mapping) == 0;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return ok ? 0 : -1;
}

int st_storage_get_mapping(const char *path, long long id, st_storage_mapping *mapping)
{
    return load_mapping_by_id(path, id, mapping);
}

static int load_mapping_by_client_port(const char *path,
                                       const char *client_name,
                                       int listen_port,
                                       st_storage_mapping *mapping)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT m.id, c.rowid, m.client_name, m.listen_port, m.target_address, m.target_port, "
        "m.enabled, m.detail_capture_enabled, m.created_at, m.updated_at "
        "FROM specus_mapping m JOIN client_account c ON c.client_name = m.client_name "
        "WHERE m.client_name = ? AND m.listen_port = ?",
        -1,
        &stmt,
        NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, client_name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, listen_port);
    rc = sqlite3_step(stmt);
    int ok = rc == SQLITE_ROW && scan_mapping(stmt, mapping) == 0;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return ok ? 0 : -1;
}

int st_storage_get_mapping_by_client_port(const char *path,
                                          const char *client_name,
                                          int listen_port,
                                          st_storage_mapping *mapping)
{
    return load_mapping_by_client_port(path, client_name, listen_port, mapping);
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
        "INSERT INTO specus_mapping(client_name, listen_port, target_address, target_port, enabled) "
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

int st_storage_create_mapping_for_client(const char *path,
                                         long long client_id,
                                         int listen_port,
                                         const char *target_address,
                                         int target_port,
                                         int enabled,
                                         int detail_capture_enabled,
                                         st_storage_mapping *out_mapping)
{
    st_storage_client client;
    if (st_storage_get_client(path, client_id, &client) != 0) {
        return -1;
    }
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT INTO specus_mapping(client_name, listen_port, target_address, target_port, enabled, detail_capture_enabled) "
        "VALUES(?,?,?,?,?,?) "
        "ON CONFLICT(client_name, listen_port) DO UPDATE SET "
        "target_address = excluded.target_address,"
        "target_port = excluded.target_port,"
        "enabled = excluded.enabled,"
        "detail_capture_enabled = excluded.detail_capture_enabled,"
        "updated_at = CURRENT_TIMESTAMP",
        -1,
        &stmt,
        NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, client.client_name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 2, listen_port);
        sqlite3_bind_text(stmt, 3, target_address, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 4, target_port);
        sqlite3_bind_int(stmt, 5, enabled ? 1 : 0);
        sqlite3_bind_int(stmt, 6, detail_capture_enabled ? 1 : 0);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    if (rc != 0) {
        return -1;
    }
    return out_mapping == NULL ? 0 : load_mapping_by_client_port(path, client.client_name, listen_port, out_mapping);
}

int st_storage_update_mapping_by_id(const char *path,
                                    long long id,
                                    int listen_port,
                                    const char *target_address,
                                    int target_port,
                                    int enabled,
                                    int detail_capture_enabled,
                                    st_storage_mapping *out_mapping)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "UPDATE specus_mapping SET listen_port = ?, target_address = ?, target_port = ?, "
        "enabled = ?, detail_capture_enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        -1,
        &stmt,
        NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, listen_port);
        sqlite3_bind_text(stmt, 2, target_address, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 3, target_port);
        sqlite3_bind_int(stmt, 4, enabled ? 1 : 0);
        sqlite3_bind_int(stmt, 5, detail_capture_enabled ? 1 : 0);
        sqlite3_bind_int64(stmt, 6, id);
        rc = sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db) == 1 ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    if (rc != 0) {
        return -1;
    }
    return out_mapping == NULL ? 0 : load_mapping_by_id(path, id, out_mapping);
}

int st_storage_delete_mapping_by_id(const char *path, long long id)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, "DELETE FROM specus_mapping WHERE id = ?", -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, id);
        rc = sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db) == 1 ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == 0 ? 0 : -1;
}

int st_storage_load_http_routes(const char *path,
                                const char *client_name,
                                st_storage_http_route *routes,
                                size_t max_routes,
                                size_t *route_count)
{
    *route_count = 0;
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT r.id, c.rowid, r.client_name, r.route, r.target_base_url, "
        "r.enabled, r.detail_capture_enabled, r.path_rewrite_enabled, r.created_at, r.updated_at "
        "FROM http_route_mapping r JOIN client_account c ON c.client_name = r.client_name "
        "WHERE r.client_name = ? AND r.enabled = 1 ORDER BY r.route",
        -1,
        &stmt,
        NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, client_name, -1, SQLITE_TRANSIENT);
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (*route_count >= max_routes || scan_http_route(stmt, &routes[*route_count]) != 0) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return -1;
        }
        ++*route_count;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == SQLITE_DONE ? 0 : -1;
}

int st_storage_list_http_routes(const char *path,
                                long long client_id,
                                st_storage_http_route *routes,
                                size_t max_routes,
                                size_t *route_count)
{
    *route_count = 0;
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    const char *sql_all =
        "SELECT r.id, c.rowid, r.client_name, r.route, r.target_base_url, "
        "r.enabled, r.detail_capture_enabled, r.path_rewrite_enabled, r.created_at, r.updated_at "
        "FROM http_route_mapping r JOIN client_account c ON c.client_name = r.client_name "
        "ORDER BY r.id DESC";
    const char *sql_filtered =
        "SELECT r.id, c.rowid, r.client_name, r.route, r.target_base_url, "
        "r.enabled, r.detail_capture_enabled, r.path_rewrite_enabled, r.created_at, r.updated_at "
        "FROM http_route_mapping r JOIN client_account c ON c.client_name = r.client_name "
        "WHERE c.rowid = ? ORDER BY r.id DESC";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, client_id > 0 ? sql_filtered : sql_all, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    if (client_id > 0) {
        sqlite3_bind_int64(stmt, 1, client_id);
    }
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (*route_count >= max_routes || scan_http_route(stmt, &routes[*route_count]) != 0) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return -1;
        }
        ++*route_count;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int load_http_route_by_id(const char *path, long long id, st_storage_http_route *route)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT r.id, c.rowid, r.client_name, r.route, r.target_base_url, "
        "r.enabled, r.detail_capture_enabled, r.path_rewrite_enabled, r.created_at, r.updated_at "
        "FROM http_route_mapping r JOIN client_account c ON c.client_name = r.client_name "
        "WHERE r.id = ?",
        -1,
        &stmt,
        NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, id);
    rc = sqlite3_step(stmt);
    int ok = rc == SQLITE_ROW && scan_http_route(stmt, route) == 0;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return ok ? 0 : -1;
}

int st_storage_get_http_route(const char *path, long long id, st_storage_http_route *route)
{
    return load_http_route_by_id(path, id, route);
}

static int load_http_route_by_client_route(const char *path,
                                           const char *client_name,
                                           const char *route_name,
                                           st_storage_http_route *route)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT r.id, c.rowid, r.client_name, r.route, r.target_base_url, "
        "r.enabled, r.detail_capture_enabled, r.path_rewrite_enabled, r.created_at, r.updated_at "
        "FROM http_route_mapping r JOIN client_account c ON c.client_name = r.client_name "
        "WHERE r.client_name = ? AND r.route = ?",
        -1,
        &stmt,
        NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, client_name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, route_name, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);
    int ok = rc == SQLITE_ROW && scan_http_route(stmt, route) == 0;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return ok ? 0 : -1;
}

int st_storage_get_http_route_by_client_route(const char *path,
                                              const char *client_name,
                                              const char *route_name,
                                              st_storage_http_route *route)
{
    return load_http_route_by_client_route(path, client_name, route_name, route);
}

int st_storage_create_http_route_for_client(const char *path,
                                            long long client_id,
                                            const char *route,
                                            const char *target_base_url,
                                            int enabled,
                                            int detail_capture_enabled,
                                            int path_rewrite_enabled,
                                            st_storage_http_route *out_route)
{
    st_storage_client client;
    if (st_storage_get_client(path, client_id, &client) != 0) {
        return -1;
    }
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT INTO http_route_mapping(client_name, route, target_base_url, enabled, detail_capture_enabled, path_rewrite_enabled) "
        "VALUES(?,?,?,?,?,?) "
        "ON CONFLICT(client_name, route) DO UPDATE SET "
        "target_base_url = excluded.target_base_url,"
        "enabled = excluded.enabled,"
        "detail_capture_enabled = excluded.detail_capture_enabled,"
        "path_rewrite_enabled = excluded.path_rewrite_enabled,"
        "updated_at = CURRENT_TIMESTAMP",
        -1,
        &stmt,
        NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, client.client_name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, route, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, target_base_url, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 4, enabled ? 1 : 0);
        sqlite3_bind_int(stmt, 5, detail_capture_enabled ? 1 : 0);
        sqlite3_bind_int(stmt, 6, path_rewrite_enabled ? 1 : 0);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    if (rc != 0) {
        return -1;
    }
    return out_route == NULL ? 0 : load_http_route_by_client_route(path, client.client_name, route, out_route);
}

int st_storage_update_http_route_by_id(const char *path,
                                       long long id,
                                       const char *route,
                                       const char *target_base_url,
                                       int enabled,
                                       int detail_capture_enabled,
                                       int path_rewrite_enabled,
                                       st_storage_http_route *out_route)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "UPDATE http_route_mapping SET route = ?, target_base_url = ?, enabled = ?, "
        "detail_capture_enabled = ?, path_rewrite_enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        -1,
        &stmt,
        NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, route, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, target_base_url, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 3, enabled ? 1 : 0);
        sqlite3_bind_int(stmt, 4, detail_capture_enabled ? 1 : 0);
        sqlite3_bind_int(stmt, 5, path_rewrite_enabled ? 1 : 0);
        sqlite3_bind_int64(stmt, 6, id);
        rc = sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db) == 1 ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    if (rc != 0) {
        return -1;
    }
    return out_route == NULL ? 0 : load_http_route_by_id(path, id, out_route);
}

int st_storage_delete_http_route_by_id(const char *path, long long id)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, "DELETE FROM http_route_mapping WHERE id = ?", -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, id);
        rc = sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db) == 1 ? 0 : -1;
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
    return st_storage_record_connection_detail(path,
                                               0,
                                               client_name,
                                               NULL,
                                               NULL,
                                               success,
                                               reason,
                                               success ? NULL : "LOGIN_FAILURE",
                                               connected_at,
                                               success ? NULL : connected_at);
}

int st_storage_record_connection_detail(const char *path,
                                        long long client_id,
                                        const char *client_name,
                                        const char *channel_id,
                                        const char *remote_address,
                                        int success,
                                        const char *failure_reason,
                                        const char *disconnect_reason,
                                        const char *connected_at,
                                        const char *disconnected_at)
{
    return st_storage_record_connection_detail_with_id(path,
                                                       client_id,
                                                       client_name,
                                                       channel_id,
                                                       remote_address,
                                                       success,
                                                       failure_reason,
                                                       disconnect_reason,
                                                       connected_at,
                                                       disconnected_at,
                                                       NULL);
}

int st_storage_record_connection_detail_with_id(const char *path,
                                                long long client_id,
                                                const char *client_name,
                                                const char *channel_id,
                                                const char *remote_address,
                                                int success,
                                                const char *failure_reason,
                                                const char *disconnect_reason,
                                                const char *connected_at,
                                                const char *disconnected_at,
                                                long long *record_id)
{
    return st_storage_record_connection_detail_with_tenant_and_id(path,
                                                                  NULL,
                                                                  client_id,
                                                                  client_name,
                                                                  channel_id,
                                                                  remote_address,
                                                                  success,
                                                                  failure_reason,
                                                                  disconnect_reason,
                                                                  connected_at,
                                                                  disconnected_at,
                                                                  record_id);
}

int st_storage_record_connection_detail_with_tenant_and_id(const char *path,
                                                           const char *tenant_id,
                                                           long long client_id,
                                                           const char *client_name,
                                                           const char *channel_id,
                                                           const char *remote_address,
                                                           int success,
                                                           const char *failure_reason,
                                                           const char *disconnect_reason,
                                                           const char *connected_at,
                                                           const char *disconnected_at,
                                                           long long *record_id)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT INTO connection_record(tenant_id, client_id, client_name, channel_id, remote_address, success, reason, "
        "disconnect_reason, connected_at, disconnected_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
        -1,
        &stmt,
        NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
        if (client_id > 0) {
            sqlite3_bind_int64(stmt, 2, client_id);
        } else {
            sqlite3_bind_null(stmt, 2);
        }
        sqlite3_bind_text(stmt, 3, client_name, -1, SQLITE_TRANSIENT);
        if (channel_id == NULL) {
            sqlite3_bind_null(stmt, 4);
        } else {
            sqlite3_bind_text(stmt, 4, channel_id, -1, SQLITE_TRANSIENT);
        }
        if (remote_address == NULL) {
            sqlite3_bind_null(stmt, 5);
        } else {
            sqlite3_bind_text(stmt, 5, remote_address, -1, SQLITE_TRANSIENT);
        }
        sqlite3_bind_int(stmt, 6, success ? 1 : 0);
        if (failure_reason == NULL) {
            sqlite3_bind_null(stmt, 7);
        } else {
            sqlite3_bind_text(stmt, 7, failure_reason, -1, SQLITE_TRANSIENT);
        }
        if (disconnect_reason == NULL) {
            sqlite3_bind_null(stmt, 8);
        } else {
            sqlite3_bind_text(stmt, 8, disconnect_reason, -1, SQLITE_TRANSIENT);
        }
        sqlite3_bind_text(stmt, 9, connected_at, -1, SQLITE_TRANSIENT);
        if (disconnected_at == NULL) {
            sqlite3_bind_null(stmt, 10);
        } else {
            sqlite3_bind_text(stmt, 10, disconnected_at, -1, SQLITE_TRANSIENT);
        }
        if (sqlite3_step(stmt) == SQLITE_DONE) {
            rc = 0;
            if (record_id != NULL) {
                *record_id = sqlite3_last_insert_rowid(db);
            }
        } else {
            rc = -1;
        }
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == 0 ? 0 : -1;
}

int st_storage_mark_connection_disconnected(const char *path,
                                            long long id,
                                            const char *disconnect_reason,
                                            const char *disconnected_at)
{
    if (id <= 0) {
        return -1;
    }
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
                                "UPDATE connection_record SET disconnect_reason=?, disconnected_at=? WHERE id=?",
                                -1,
                                &stmt,
                                NULL);
    if (rc == SQLITE_OK) {
        if (disconnect_reason == NULL) {
            sqlite3_bind_null(stmt, 1);
        } else {
            sqlite3_bind_text(stmt, 1, disconnect_reason, -1, SQLITE_TRANSIENT);
        }
        if (disconnected_at == NULL) {
            sqlite3_bind_null(stmt, 2);
        } else {
            sqlite3_bind_text(stmt, 2, disconnected_at, -1, SQLITE_TRANSIENT);
        }
        sqlite3_bind_int64(stmt, 3, id);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == 0 ? 0 : -1;
}

static int append_connection_filters(sqlite3 *db,
                                     sqlite3_stmt *stmt,
                                     long long client_id,
                                     int success_filter,
                                     const char *from,
                                     const char *to,
                                     int *index)
{
    (void)db;
    if (client_id > 0) {
        sqlite3_bind_int64(stmt, (*index)++, client_id);
    }
    if (success_filter == 0 || success_filter == 1) {
        sqlite3_bind_int(stmt, (*index)++, success_filter);
    }
    if (from != NULL && *from != '\0') {
        sqlite3_bind_text(stmt, (*index)++, from, -1, SQLITE_TRANSIENT);
    }
    if (to != NULL && *to != '\0') {
        sqlite3_bind_text(stmt, (*index)++, to, -1, SQLITE_TRANSIENT);
    }
    return 0;
}

static int build_connection_where(char *where,
                                  size_t where_len,
                                  long long client_id,
                                  int success_filter,
                                  const char *from,
                                  const char *to)
{
    int written = snprintf(where, where_len, " WHERE 1=1");
    if (written < 0 || (size_t)written >= where_len) {
        return -1;
    }
    if (client_id > 0) {
        strncat(where, " AND client_id = ?", where_len - strlen(where) - 1U);
    }
    if (success_filter == 0 || success_filter == 1) {
        strncat(where, " AND success = ?", where_len - strlen(where) - 1U);
    }
    if (from != NULL && *from != '\0') {
        strncat(where, " AND connected_at >= ?", where_len - strlen(where) - 1U);
    }
    if (to != NULL && *to != '\0') {
        strncat(where, " AND connected_at <= ?", where_len - strlen(where) - 1U);
    }
    return 0;
}

static const char *normalize_tenant_id(const char *tenant_id)
{
    return tenant_id == NULL || *tenant_id == '\0' ? "default" : tenant_id;
}

static const char *normalize_owner_username(const char *owner_username)
{
    return owner_username == NULL || *owner_username == '\0' ? "" : owner_username;
}

static int append_visible_connection_filters(sqlite3_stmt *stmt,
                                             const char *tenant_id,
                                             const char *owner_username,
                                             int include_all_clients,
                                             long long client_id,
                                             int success_filter,
                                             const char *from,
                                             const char *to,
                                             int *index)
{
    sqlite3_bind_text(stmt, (*index)++, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
    if (!include_all_clients) {
        sqlite3_bind_text(stmt, (*index)++, normalize_owner_username(owner_username), -1, SQLITE_TRANSIENT);
    }
    if (client_id > 0) {
        sqlite3_bind_int64(stmt, (*index)++, client_id);
    }
    if (success_filter == 0 || success_filter == 1) {
        sqlite3_bind_int(stmt, (*index)++, success_filter);
    }
    if (from != NULL && *from != '\0') {
        sqlite3_bind_text(stmt, (*index)++, from, -1, SQLITE_TRANSIENT);
    }
    if (to != NULL && *to != '\0') {
        sqlite3_bind_text(stmt, (*index)++, to, -1, SQLITE_TRANSIENT);
    }
    return 0;
}

static int build_visible_connection_where(char *where,
                                          size_t where_len,
                                          const char *record_alias,
                                          int include_all_clients,
                                          long long client_id,
                                          int success_filter,
                                          const char *from,
                                          const char *to)
{
    int written = snprintf(where,
                           where_len,
                           " WHERE COALESCE(NULLIF(%s.tenant_id, ''), c.tenant_id, 'default') = ?%s",
                           record_alias,
                           include_all_clients ? "" : " AND c.owner_username = ?");
    if (written < 0 || (size_t)written >= where_len) {
        return -1;
    }
    if (client_id > 0) {
        strncat(where, " AND ", where_len - strlen(where) - 1U);
        strncat(where, record_alias, where_len - strlen(where) - 1U);
        strncat(where, ".client_id = ?", where_len - strlen(where) - 1U);
    }
    if (success_filter == 0 || success_filter == 1) {
        strncat(where, " AND ", where_len - strlen(where) - 1U);
        strncat(where, record_alias, where_len - strlen(where) - 1U);
        strncat(where, ".success = ?", where_len - strlen(where) - 1U);
    }
    if (from != NULL && *from != '\0') {
        strncat(where, " AND ", where_len - strlen(where) - 1U);
        strncat(where, record_alias, where_len - strlen(where) - 1U);
        strncat(where, ".connected_at >= ?", where_len - strlen(where) - 1U);
    }
    if (to != NULL && *to != '\0') {
        strncat(where, " AND ", where_len - strlen(where) - 1U);
        strncat(where, record_alias, where_len - strlen(where) - 1U);
        strncat(where, ".connected_at <= ?", where_len - strlen(where) - 1U);
    }
    return 0;
}

int st_storage_list_connections(const char *path,
                                long long client_id,
                                int success_filter,
                                const char *from,
                                const char *to,
                                int page,
                                int size,
                                st_storage_connection *connections,
                                size_t max_connections,
                                size_t *connection_count,
                                long long *total_count)
{
    *connection_count = 0;
    *total_count = 0;
    if (page < 0) {
        page = 0;
    }
    if (size <= 0) {
        size = 100;
    }
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    char where[256];
    if (build_connection_where(where, sizeof(where), client_id, success_filter, from, to) != 0) {
        sqlite3_close(db);
        return -1;
    }
    char sql[768];
    int written = snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM connection_record%s", where);
    if (written < 0 || (size_t)written >= sizeof(sql)) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    int bind_index = 1;
    append_connection_filters(db, stmt, client_id, success_filter, from, to, &bind_index);
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *total_count = sqlite3_column_int64(stmt, 0);
        rc = SQLITE_DONE;
    }
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        sqlite3_close(db);
        return -1;
    }

    written = snprintf(sql,
                       sizeof(sql),
                       "SELECT id, COALESCE(NULLIF(tenant_id, ''), 'default'), client_id, client_name, channel_id, remote_address, success, reason, "
                       "disconnect_reason, connected_at, disconnected_at FROM connection_record%s "
                       "ORDER BY id DESC LIMIT ? OFFSET ?",
                       where);
    if (written < 0 || (size_t)written >= sizeof(sql)) {
        sqlite3_close(db);
        return -1;
    }
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    bind_index = 1;
    append_connection_filters(db, stmt, client_id, success_filter, from, to, &bind_index);
    sqlite3_bind_int(stmt, bind_index++, size);
    sqlite3_bind_int(stmt, bind_index, page * size);
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (*connection_count >= max_connections || scan_connection(stmt, &connections[*connection_count]) != 0) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return -1;
        }
        ++*connection_count;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == SQLITE_DONE ? 0 : -1;
}

int st_storage_list_connections_visible(const char *path,
                                        long long client_id,
                                        int success_filter,
                                        const char *from,
                                        const char *to,
                                        const char *tenant_id,
                                        const char *owner_username,
                                        int include_all_clients,
                                        int page,
                                        int size,
                                        st_storage_connection *connections,
                                        size_t max_connections,
                                        size_t *connection_count,
                                        long long *total_count)
{
    *connection_count = 0;
    *total_count = 0;
    if (page < 0) {
        page = 0;
    }
    if (size <= 0) {
        size = 100;
    }
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    char where[384];
    if (build_visible_connection_where(where,
                                       sizeof(where),
                                       "r",
                                       include_all_clients,
                                       client_id,
                                       success_filter,
                                       from,
                                       to) != 0) {
        sqlite3_close(db);
        return -1;
    }
    char sql[1024];
    int written = snprintf(sql,
                           sizeof(sql),
                           "SELECT COUNT(*) FROM connection_record r "
                           "JOIN client_account c ON c.rowid = r.client_id OR "
                           "(r.client_id IS NULL AND c.client_name = r.client_name "
                           "AND c.tenant_id = COALESCE(NULLIF(r.tenant_id, ''), c.tenant_id, 'default'))%s",
                           where);
    if (written < 0 || (size_t)written >= sizeof(sql)) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    int bind_index = 1;
    append_visible_connection_filters(stmt,
                                      tenant_id,
                                      owner_username,
                                      include_all_clients,
                                      client_id,
                                      success_filter,
                                      from,
                                      to,
                                      &bind_index);
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *total_count = sqlite3_column_int64(stmt, 0);
        rc = SQLITE_DONE;
    }
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        sqlite3_close(db);
        return -1;
    }

    written = snprintf(sql,
                       sizeof(sql),
                       "SELECT r.id, COALESCE(NULLIF(r.tenant_id, ''), c.tenant_id, 'default'), "
                       "r.client_id, r.client_name, r.channel_id, r.remote_address, "
                       "r.success, r.reason, r.disconnect_reason, r.connected_at, r.disconnected_at "
                       "FROM connection_record r "
                       "JOIN client_account c ON c.rowid = r.client_id OR "
                       "(r.client_id IS NULL AND c.client_name = r.client_name "
                       "AND c.tenant_id = COALESCE(NULLIF(r.tenant_id, ''), c.tenant_id, 'default'))%s "
                       "ORDER BY r.id DESC LIMIT ? OFFSET ?",
                       where);
    if (written < 0 || (size_t)written >= sizeof(sql)) {
        sqlite3_close(db);
        return -1;
    }
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    bind_index = 1;
    append_visible_connection_filters(stmt,
                                      tenant_id,
                                      owner_username,
                                      include_all_clients,
                                      client_id,
                                      success_filter,
                                      from,
                                      to,
                                      &bind_index);
    sqlite3_bind_int(stmt, bind_index++, size);
    sqlite3_bind_int(stmt, bind_index, page * size);
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (*connection_count >= max_connections || scan_connection(stmt, &connections[*connection_count]) != 0) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return -1;
        }
        ++*connection_count;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == SQLITE_DONE ? 0 : -1;
}

int st_storage_archive_connections(const char *path, const char *before_timestamp)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT INTO connection_stat(client_id, client_name, stat_date, success_count, failure_count, updated_at) "
        "SELECT MAX(client_id), client_name, substr(connected_at, 1, 10), "
        "SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END), "
        "SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END), "
        "CURRENT_TIMESTAMP "
        "FROM connection_record WHERE connected_at < ? "
        "GROUP BY client_name, substr(connected_at, 1, 10) "
        "ON CONFLICT(client_name, stat_date) DO UPDATE SET "
        "client_id = COALESCE(connection_stat.client_id, excluded.client_id), "
        "success_count = success_count + excluded.success_count, "
        "failure_count = failure_count + excluded.failure_count, "
        "updated_at = excluded.updated_at",
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

int st_storage_list_connection_stats(const char *path,
                                     const char *client_name,
                                     int limit,
                                     st_storage_connection_stat *stats,
                                     size_t max_stats,
                                     size_t *stat_count)
{
    *stat_count = 0;
    if (limit <= 0) {
        limit = 100;
    } else if (limit > 500) {
        limit = 500;
    }
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    int has_client_filter = client_name != NULL && *client_name != '\0';
    const char *sql = has_client_filter
        ? "SELECT id, client_id, client_name, stat_date, success_count, failure_count, "
          "(success_count + failure_count), updated_at FROM connection_stat "
          "WHERE client_name = ? ORDER BY stat_date DESC, client_name ASC LIMIT ?"
        : "SELECT id, client_id, client_name, stat_date, success_count, failure_count, "
          "(success_count + failure_count), updated_at FROM connection_stat "
          "ORDER BY stat_date DESC, client_name ASC LIMIT ?";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    int bind_index = 1;
    if (has_client_filter) {
        sqlite3_bind_text(stmt, bind_index++, client_name, -1, SQLITE_TRANSIENT);
    }
    sqlite3_bind_int(stmt, bind_index, limit);
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (*stat_count >= max_stats || scan_connection_stat(stmt, &stats[*stat_count]) != 0) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return -1;
        }
        ++*stat_count;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == SQLITE_DONE ? 0 : -1;
}

int st_storage_list_connection_stats_visible(const char *path,
                                             const char *client_name,
                                             const char *tenant_id,
                                             const char *owner_username,
                                             int include_all_clients,
                                             int limit,
                                             st_storage_connection_stat *stats,
                                             size_t max_stats,
                                             size_t *stat_count)
{
    *stat_count = 0;
    if (limit <= 0) {
        limit = 100;
    } else if (limit > 500) {
        limit = 500;
    }
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    int has_client_filter = client_name != NULL && *client_name != '\0';
    char sql[1024];
    int written = snprintf(sql,
                           sizeof(sql),
                           "SELECT s.id, s.client_id, s.client_name, s.stat_date, s.success_count, "
                           "s.failure_count, (s.success_count + s.failure_count), s.updated_at "
                           "FROM connection_stat s "
                           "JOIN client_account c ON c.rowid = s.client_id OR "
                           "(s.client_id IS NULL AND c.client_name = s.client_name) "
                           "WHERE c.tenant_id = ?%s%s "
                           "ORDER BY s.stat_date DESC, s.client_name ASC LIMIT ?",
                           include_all_clients ? "" : " AND c.owner_username = ?",
                           has_client_filter ? " AND s.client_name = ?" : "");
    if (written < 0 || (size_t)written >= sizeof(sql)) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    int bind_index = 1;
    sqlite3_bind_text(stmt, bind_index++, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
    if (!include_all_clients) {
        sqlite3_bind_text(stmt, bind_index++, normalize_owner_username(owner_username), -1, SQLITE_TRANSIENT);
    }
    if (has_client_filter) {
        sqlite3_bind_text(stmt, bind_index++, client_name, -1, SQLITE_TRANSIENT);
    }
    sqlite3_bind_int(stmt, bind_index, limit);
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (*stat_count >= max_stats || scan_connection_stat(stmt, &stats[*stat_count]) != 0) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return -1;
        }
        ++*stat_count;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == SQLITE_DONE ? 0 : -1;
}

int st_storage_record_traffic_usage(const char *path,
                                    long long client_id,
                                    const char *client_name,
                                    const char *usage_date,
                                    long long upload_bytes,
                                    long long download_bytes)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT INTO traffic_usage(client_id, client_name, usage_date, upload_bytes, download_bytes, updated_at) "
        "VALUES(?,?,?,?,?,CURRENT_TIMESTAMP) "
        "ON CONFLICT(client_name, usage_date) DO UPDATE SET "
        "client_id = COALESCE(traffic_usage.client_id, excluded.client_id), "
        "upload_bytes = upload_bytes + excluded.upload_bytes, "
        "download_bytes = download_bytes + excluded.download_bytes, "
        "updated_at = excluded.updated_at",
        -1,
        &stmt,
        NULL);
    if (rc == SQLITE_OK) {
        if (client_id > 0) {
            sqlite3_bind_int64(stmt, 1, client_id);
        } else {
            sqlite3_bind_null(stmt, 1);
        }
        sqlite3_bind_text(stmt, 2, client_name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, usage_date, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 4, upload_bytes);
        sqlite3_bind_int64(stmt, 5, download_bytes);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == 0 ? 0 : -1;
}

int st_storage_list_traffic_usage(const char *path,
                                  long long client_id,
                                  int limit,
                                  st_storage_traffic_usage *items,
                                  size_t max_items,
                                  size_t *item_count)
{
    *item_count = 0;
    if (limit <= 0) {
        limit = 100;
    } else if (limit > 1000) {
        limit = 100;
    }
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    const char *sql = client_id > 0
        ? "SELECT id, client_id, client_name, usage_date, upload_bytes, download_bytes, updated_at "
          "FROM traffic_usage WHERE client_id = ? ORDER BY usage_date DESC, id DESC LIMIT ?"
        : "SELECT id, client_id, client_name, usage_date, upload_bytes, download_bytes, updated_at "
          "FROM traffic_usage ORDER BY usage_date DESC, id DESC LIMIT ?";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    int bind_index = 1;
    if (client_id > 0) {
        sqlite3_bind_int64(stmt, bind_index++, client_id);
    }
    sqlite3_bind_int(stmt, bind_index, limit);
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (*item_count >= max_items || scan_traffic_usage(stmt, &items[*item_count]) != 0) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return -1;
        }
        ++*item_count;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == SQLITE_DONE ? 0 : -1;
}

int st_storage_list_traffic_usage_visible(const char *path,
                                          long long client_id,
                                          const char *tenant_id,
                                          const char *owner_username,
                                          int include_all_clients,
                                          int limit,
                                          st_storage_traffic_usage *items,
                                          size_t max_items,
                                          size_t *item_count)
{
    *item_count = 0;
    if (limit <= 0) {
        limit = 100;
    } else if (limit > 1000) {
        limit = 100;
    }
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    char sql[1024];
    int written = snprintf(sql,
                           sizeof(sql),
                           "SELECT t.id, t.client_id, t.client_name, t.usage_date, "
                           "t.upload_bytes, t.download_bytes, t.updated_at "
                           "FROM traffic_usage t "
                           "JOIN client_account c ON c.rowid = t.client_id OR "
                           "(t.client_id IS NULL AND c.client_name = t.client_name) "
                           "WHERE c.tenant_id = ?%s%s "
                           "ORDER BY t.usage_date DESC, t.id DESC LIMIT ?",
                           include_all_clients ? "" : " AND c.owner_username = ?",
                           client_id > 0 ? " AND t.client_id = ?" : "");
    if (written < 0 || (size_t)written >= sizeof(sql)) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    int bind_index = 1;
    sqlite3_bind_text(stmt, bind_index++, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
    if (!include_all_clients) {
        sqlite3_bind_text(stmt, bind_index++, normalize_owner_username(owner_username), -1, SQLITE_TRANSIENT);
    }
    if (client_id > 0) {
        sqlite3_bind_int64(stmt, bind_index++, client_id);
    }
    sqlite3_bind_int(stmt, bind_index, limit);
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (*item_count >= max_items || scan_traffic_usage(stmt, &items[*item_count]) != 0) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return -1;
        }
        ++*item_count;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == SQLITE_DONE ? 0 : -1;
}

int st_storage_record_resource_traffic_usage(const char *path,
                                             long long client_id,
                                             const char *client_name,
                                             const char *resource_type,
                                             const char *resource_key,
                                             long long resource_id,
                                             const char *resource_name,
                                             const char *usage_date,
                                             long long upload_bytes,
                                             long long download_bytes)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT INTO resource_traffic_usage(client_id, client_name, resource_type, resource_key, resource_id, "
        "resource_name, usage_date, upload_bytes, download_bytes, updated_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP) "
        "ON CONFLICT(client_name, resource_type, resource_key, usage_date) DO UPDATE SET "
        "client_id = COALESCE(resource_traffic_usage.client_id, excluded.client_id), "
        "resource_id = COALESCE(resource_traffic_usage.resource_id, excluded.resource_id), "
        "resource_name = excluded.resource_name, "
        "upload_bytes = upload_bytes + excluded.upload_bytes, "
        "download_bytes = download_bytes + excluded.download_bytes, "
        "updated_at = excluded.updated_at",
        -1,
        &stmt,
        NULL);
    if (rc == SQLITE_OK) {
        if (client_id > 0) {
            sqlite3_bind_int64(stmt, 1, client_id);
        } else {
            sqlite3_bind_null(stmt, 1);
        }
        sqlite3_bind_text(stmt, 2, client_name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, resource_type, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, resource_key, -1, SQLITE_TRANSIENT);
        if (resource_id > 0) {
            sqlite3_bind_int64(stmt, 5, resource_id);
        } else {
            sqlite3_bind_null(stmt, 5);
        }
        if (resource_name == NULL) {
            sqlite3_bind_null(stmt, 6);
        } else {
            sqlite3_bind_text(stmt, 6, resource_name, -1, SQLITE_TRANSIENT);
        }
        sqlite3_bind_text(stmt, 7, usage_date, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 8, upload_bytes);
        sqlite3_bind_int64(stmt, 9, download_bytes);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == 0 ? 0 : -1;
}

int st_storage_list_resource_traffic_usage(const char *path,
                                           const char *resource_type,
                                           long long client_id,
                                           int limit,
                                           st_storage_resource_traffic_usage *items,
                                           size_t max_items,
                                           size_t *item_count)
{
    *item_count = 0;
    if (limit <= 0) {
        limit = 200;
    } else if (limit > 1000) {
        limit = 200;
    }
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    char sql[512];
    int written = snprintf(sql,
                           sizeof(sql),
                           "SELECT id, client_id, client_name, resource_type, resource_key, resource_id, "
                           "resource_name, usage_date, upload_bytes, download_bytes, updated_at "
                           "FROM resource_traffic_usage WHERE 1=1%s%s "
                           "ORDER BY usage_date DESC, id DESC LIMIT ?",
                           client_id > 0 ? " AND client_id = ?" : "",
                           resource_type != NULL && *resource_type != '\0' ? " AND resource_type = ?" : "");
    if (written < 0 || (size_t)written >= sizeof(sql)) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    int bind_index = 1;
    if (client_id > 0) {
        sqlite3_bind_int64(stmt, bind_index++, client_id);
    }
    if (resource_type != NULL && *resource_type != '\0') {
        sqlite3_bind_text(stmt, bind_index++, resource_type, -1, SQLITE_TRANSIENT);
    }
    sqlite3_bind_int(stmt, bind_index, limit);
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (*item_count >= max_items || scan_resource_traffic_usage(stmt, &items[*item_count]) != 0) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return -1;
        }
        ++*item_count;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == SQLITE_DONE ? 0 : -1;
}

int st_storage_list_resource_traffic_usage_visible(const char *path,
                                                   const char *resource_type,
                                                   long long client_id,
                                                   const char *tenant_id,
                                                   const char *owner_username,
                                                   int include_all_clients,
                                                   int limit,
                                                   st_storage_resource_traffic_usage *items,
                                                   size_t max_items,
                                                   size_t *item_count)
{
    *item_count = 0;
    if (limit <= 0) {
        limit = 200;
    } else if (limit > 1000) {
        limit = 200;
    }
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    int has_type_filter = resource_type != NULL && *resource_type != '\0';
    char sql[1200];
    int written = snprintf(sql,
                           sizeof(sql),
                           "SELECT r.id, r.client_id, r.client_name, r.resource_type, r.resource_key, "
                           "r.resource_id, r.resource_name, r.usage_date, r.upload_bytes, "
                           "r.download_bytes, r.updated_at "
                           "FROM resource_traffic_usage r "
                           "JOIN client_account c ON c.rowid = r.client_id OR "
                           "(r.client_id IS NULL AND c.client_name = r.client_name) "
                           "WHERE c.tenant_id = ?%s%s%s "
                           "ORDER BY r.usage_date DESC, r.id DESC LIMIT ?",
                           include_all_clients ? "" : " AND c.owner_username = ?",
                           client_id > 0 ? " AND r.client_id = ?" : "",
                           has_type_filter ? " AND r.resource_type = ?" : "");
    if (written < 0 || (size_t)written >= sizeof(sql)) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    int bind_index = 1;
    sqlite3_bind_text(stmt, bind_index++, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
    if (!include_all_clients) {
        sqlite3_bind_text(stmt, bind_index++, normalize_owner_username(owner_username), -1, SQLITE_TRANSIENT);
    }
    if (client_id > 0) {
        sqlite3_bind_int64(stmt, bind_index++, client_id);
    }
    if (has_type_filter) {
        sqlite3_bind_text(stmt, bind_index++, resource_type, -1, SQLITE_TRANSIENT);
    }
    sqlite3_bind_int(stmt, bind_index, limit);
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (*item_count >= max_items || scan_resource_traffic_usage(stmt, &items[*item_count]) != 0) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return -1;
        }
        ++*item_count;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == SQLITE_DONE ? 0 : -1;
}

int st_storage_list_peer_mesh_acls_visible(const char *path,
                                           const char *tenant_id,
                                           const char *owner_username,
                                           int include_all_clients,
                                           st_storage_peer_mesh_acl *acls,
                                           size_t max_acls,
                                           size_t *acl_count)
{
    *acl_count = 0;
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    char sql[512];
    int written = snprintf(sql,
                           sizeof(sql),
                           "SELECT id, tenant_id, owner_username, source_client_id, source_client_name, "
                            "target_client_id, target_client_name, allowed, direction, created_at, updated_at "
                           "FROM peer_mesh_acl WHERE tenant_id COLLATE BINARY = ?%s ORDER BY id DESC",
                           include_all_clients ? "" : " AND owner_username COLLATE BINARY = ?");
    if (written < 0 || (size_t)written >= sizeof(sql)) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
    if (!include_all_clients) {
        sqlite3_bind_text(stmt, 2, normalize_owner_username(owner_username), -1, SQLITE_TRANSIENT);
    }
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (*acl_count >= max_acls || scan_peer_mesh_acl(stmt, &acls[*acl_count]) != 0) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return -1;
        }
        ++*acl_count;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int read_peer_mesh_device(sqlite3 *db,
                                 const char *tenant_id,
                                 long long client_id,
                                 st_storage_peer_mesh_device *device)
{
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
                                "SELECT id, tenant_id, owner_username, client_id, client_name, enabled, "
                                "virtual_ip, public_key, nat_type, last_endpoint, virtual_device_mode, "
                                "virtual_device_name, virtual_device_status, virtual_device_error, "
                                "virtual_device_updated_at, last_seen_at, updated_at "
                                "FROM peer_mesh_device WHERE tenant_id = ? AND client_id = ?",
                                -1,
                                &stmt,
                                NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, client_id);
    rc = sqlite3_step(stmt);
    int ok = rc == SQLITE_ROW && device != NULL && scan_peer_mesh_device(stmt, device) == 0;
    sqlite3_finalize(stmt);
    return ok ? 0 : -1;
}

int st_storage_ensure_peer_mesh_device(const char *path,
                                       const st_storage_client *client,
                                       st_storage_peer_mesh_device *out_device)
{
    if (client == NULL || client->id <= 0) {
        return -1;
    }
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(
        db,
        "INSERT INTO peer_mesh_device(tenant_id, owner_username, client_id, client_name, enabled, "
        "nat_type, virtual_device_mode, virtual_device_status, virtual_device_error, updated_at) "
        "VALUES (?, ?, ?, ?, 0, 'UNKNOWN', 'UNSUPPORTED', 'UNSUPPORTED', "
        "'C server does not implement Peer Mesh data plane', CURRENT_TIMESTAMP) "
        "ON CONFLICT(tenant_id, client_id) DO UPDATE SET "
        "owner_username = excluded.owner_username, client_name = excluded.client_name, updated_at = CURRENT_TIMESTAMP",
        -1,
        &stmt,
        NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, normalize_tenant_id(client->tenant_id), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, normalize_owner_username(client->owner_username), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 3, client->id);
        sqlite3_bind_text(stmt, 4, client->client_name, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    if (rc == 0 && out_device != NULL) {
        rc = read_peer_mesh_device(db, client->tenant_id, client->id, out_device);
        if (rc == 0) {
            out_device->message_send_capable = client->message_send_capable;
            out_device->message_receive_capable = client->message_receive_capable;
            out_device->message_attachments_capable = client->message_attachments_capable;
            out_device->message_media_preview_capable = client->message_media_preview_capable;
            out_device->message_max_attachment_bytes = client->message_max_attachment_bytes;
        }
    }
    sqlite3_close(db);
    return rc == 0 ? 0 : -1;
}

int st_storage_update_peer_mesh_device_enabled(const char *path,
                                               const st_storage_client *client,
                                               int enabled,
                                               st_storage_peer_mesh_device *out_device)
{
    if (client == NULL || client->id <= 0) {
        return -1;
    }
    if (st_storage_ensure_peer_mesh_device(path, client, NULL) != 0) {
        return -1;
    }
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
                                "UPDATE peer_mesh_device SET enabled = ?, owner_username = ?, "
                                "client_name = ?, updated_at = CURRENT_TIMESTAMP "
                                "WHERE tenant_id = ? AND client_id = ?",
                                -1,
                                &stmt,
                                NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, enabled ? 1 : 0);
        sqlite3_bind_text(stmt, 2, normalize_owner_username(client->owner_username), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, client->client_name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, normalize_tenant_id(client->tenant_id), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 5, client->id);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    if (rc == 0 && out_device != NULL) {
        rc = read_peer_mesh_device(db, client->tenant_id, client->id, out_device);
        if (rc == 0) {
            out_device->message_send_capable = client->message_send_capable;
            out_device->message_receive_capable = client->message_receive_capable;
            out_device->message_attachments_capable = client->message_attachments_capable;
            out_device->message_media_preview_capable = client->message_media_preview_capable;
            out_device->message_max_attachment_bytes = client->message_max_attachment_bytes;
        }
    }
    sqlite3_close(db);
    return rc == 0 ? 0 : -1;
}

int st_storage_get_peer_mesh_acl(const char *path, long long id, st_storage_peer_mesh_acl *acl)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT id, tenant_id, owner_username, source_client_id, source_client_name, "
        "target_client_id, target_client_name, allowed, direction, created_at, updated_at "
        "FROM peer_mesh_acl WHERE id = ?",
        -1,
        &stmt,
        NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, id);
    rc = sqlite3_step(stmt);
    int ok = rc == SQLITE_ROW && scan_peer_mesh_acl(stmt, acl) == 0;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return ok ? 0 : -1;
}

int st_storage_upsert_peer_mesh_acl(const char *path,
                                    const char *tenant_id,
                                    const char *owner_username,
                                    const st_storage_client *source,
                                    const st_storage_client *target,
                                    int allowed,
                                    const char *direction,
                                    st_storage_peer_mesh_acl *out_acl)
{
    const char *normalized_tenant_id = normalize_tenant_id(tenant_id);
    if (source == NULL || target == NULL || source->id <= 0 || target->id <= 0 || source->id == target->id) {
        return -1;
    }
    if (strcmp(source->tenant_id, normalized_tenant_id) != 0
        || strcmp(target->tenant_id, normalized_tenant_id) != 0) {
        return -1;
    }
    if (direction != NULL
        && strcmp(direction, "OUTBOUND") != 0
        && strcmp(direction, "INBOUND") != 0
        && strcmp(direction, "BOTH") != 0) {
        return -1;
    }
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT INTO peer_mesh_acl(tenant_id, owner_username, source_client_id, source_client_name, "
        "target_client_id, target_client_name, allowed, direction, created_at, updated_at) "
        "VALUES(?,?,?,?,?,?,?,COALESCE(?, 'OUTBOUND'),CURRENT_TIMESTAMP,CURRENT_TIMESTAMP) "
        "ON CONFLICT(tenant_id, source_client_id, target_client_id) DO UPDATE SET "
        "owner_username=excluded.owner_username, "
        "source_client_name=excluded.source_client_name, "
        "target_client_name=excluded.target_client_name, "
        "allowed=excluded.allowed, "
        "direction=COALESCE(?, peer_mesh_acl.direction), "
        "updated_at=CURRENT_TIMESTAMP",
        -1,
        &stmt,
        NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, normalized_tenant_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, normalize_owner_username(owner_username), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, source->id);
    sqlite3_bind_text(stmt, 4, source->client_name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 5, target->id);
    sqlite3_bind_text(stmt, 6, target->client_name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 7, allowed ? 1 : 0);
    if (direction == NULL) {
        sqlite3_bind_null(stmt, 8);
        sqlite3_bind_null(stmt, 9);
    } else {
        sqlite3_bind_text(stmt, 8, direction, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 9, direction, -1, SQLITE_TRANSIENT);
    }
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    if (rc != SQLITE_DONE) {
        return -1;
    }
    if (out_acl == NULL) {
        return 0;
    }
    sqlite3 *read_db = NULL;
    if (open_db(path, &read_db) != 0) {
        return -1;
    }
    sqlite3_stmt *read_stmt = NULL;
    rc = sqlite3_prepare_v2(read_db,
        "SELECT id, tenant_id, owner_username, source_client_id, source_client_name, "
        "target_client_id, target_client_name, allowed, direction, created_at, updated_at "
        "FROM peer_mesh_acl WHERE tenant_id COLLATE BINARY = ? AND source_client_id = ? AND target_client_id = ?",
        -1,
        &read_stmt,
        NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(read_db);
        return -1;
    }
    sqlite3_bind_text(read_stmt, 1, normalized_tenant_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(read_stmt, 2, source->id);
    sqlite3_bind_int64(read_stmt, 3, target->id);
    rc = sqlite3_step(read_stmt);
    int ok = rc == SQLITE_ROW && scan_peer_mesh_acl(read_stmt, out_acl) == 0;
    sqlite3_finalize(read_stmt);
    sqlite3_close(read_db);
    return ok ? 0 : -1;
}

int st_storage_delete_peer_mesh_acl_visible(const char *path,
                                            long long id,
                                            const char *tenant_id,
                                            const char *owner_username,
                                            int include_all_clients)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    char sql[256];
    int written = snprintf(sql,
                           sizeof(sql),
                           "DELETE FROM peer_mesh_acl WHERE id = ? AND tenant_id COLLATE BINARY = ?%s",
                           include_all_clients ? "" : " AND owner_username COLLATE BINARY = ?");
    if (written < 0 || (size_t)written >= sizeof(sql)) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, id);
    sqlite3_bind_text(stmt, 2, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
    if (!include_all_clients) {
        sqlite3_bind_text(stmt, 3, normalize_owner_username(owner_username), -1, SQLITE_TRANSIENT);
    }
    rc = sqlite3_step(stmt);
    int changed = sqlite3_changes(db);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == SQLITE_DONE && changed > 0 ? 0 : -1;
}

static int append_peer_mesh_session_visible_where(char *out,
                                                  size_t out_len,
                                                  int include_all_clients,
                                                  int include_closed,
                                                  const char *prefix)
{
    const char *alias = prefix == NULL ? "s" : prefix;
    int written = snprintf(out,
                           out_len,
                           " WHERE %s.tenant_id = ?%s%s",
                           alias,
                           include_all_clients
                               ? ""
                               : " AND EXISTS (SELECT 1 FROM client_account c "
                                 "WHERE c.tenant_id = s.tenant_id AND c.owner_username = ? "
                                 "AND (c.rowid = s.source_client_id OR c.rowid = s.target_client_id))",
                           include_closed ? "" : " AND s.status <> 'CLOSED'");
    return written < 0 || (size_t)written >= out_len ? -1 : 0;
}

static void bind_peer_mesh_session_visible(sqlite3_stmt *stmt,
                                           const char *tenant_id,
                                           const char *owner_username,
                                           int include_all_clients,
                                           int *bind_index)
{
    sqlite3_bind_text(stmt, (*bind_index)++, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
    if (!include_all_clients) {
        sqlite3_bind_text(stmt, (*bind_index)++, normalize_owner_username(owner_username), -1, SQLITE_TRANSIENT);
    }
}

static int read_peer_mesh_session_visible(sqlite3 *db,
                                          long long id,
                                          const char *tenant_id,
                                          const char *owner_username,
                                          int include_all_clients,
                                          st_storage_peer_mesh_session *session)
{
    char where[512];
    if (append_peer_mesh_session_visible_where(where, sizeof(where), include_all_clients, 1, "s") != 0) {
        return -1;
    }
    char sql[1024];
    int written = snprintf(sql,
                           sizeof(sql),
                           "SELECT s.id, s.tenant_id, s.source_client_id, s.source_client_name, "
                           "s.target_client_id, s.target_client_name, s.path_type, s.status, "
                           "s.started_at, s.updated_at, s.expires_at, s.closed_at, s.rtt_millis, "
                           "s.local_endpoint, s.remote_endpoint, s.direct_bytes, s.relay_bytes, "
                           "s.last_traffic_at FROM peer_mesh_session s%s AND s.id = ?",
                           where);
    if (written < 0 || (size_t)written >= sizeof(sql)) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }
    int bind_index = 1;
    bind_peer_mesh_session_visible(stmt, tenant_id, owner_username, include_all_clients, &bind_index);
    sqlite3_bind_int64(stmt, bind_index, id);
    rc = sqlite3_step(stmt);
    int ok = rc == SQLITE_ROW && session != NULL && scan_peer_mesh_session(stmt, session) == 0;
    sqlite3_finalize(stmt);
    return ok ? 0 : -1;
}

int st_storage_list_peer_mesh_sessions_visible(const char *path,
                                               const char *tenant_id,
                                               const char *owner_username,
                                               int include_all_clients,
                                               int include_closed,
                                               int limit,
                                               st_storage_peer_mesh_session *sessions,
                                               size_t max_sessions,
                                               size_t *session_count)
{
    if (session_count == NULL || sessions == NULL) {
        return -1;
    }
    *session_count = 0;
    if (limit <= 0 || limit > 200) {
        limit = 100;
    }
    if ((size_t)limit > max_sessions) {
        limit = (int)max_sessions;
    }
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    char where[512];
    if (append_peer_mesh_session_visible_where(where, sizeof(where), include_all_clients, include_closed, "s") != 0) {
        sqlite3_close(db);
        return -1;
    }
    char sql[1024];
    int written = snprintf(sql,
                           sizeof(sql),
                           "SELECT s.id, s.tenant_id, s.source_client_id, s.source_client_name, "
                           "s.target_client_id, s.target_client_name, s.path_type, s.status, "
                           "s.started_at, s.updated_at, s.expires_at, s.closed_at, s.rtt_millis, "
                           "s.local_endpoint, s.remote_endpoint, s.direct_bytes, s.relay_bytes, "
                           "s.last_traffic_at FROM peer_mesh_session s%s "
                           "ORDER BY s.updated_at DESC, s.id DESC LIMIT ?",
                           where);
    if (written < 0 || (size_t)written >= sizeof(sql)) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    int bind_index = 1;
    bind_peer_mesh_session_visible(stmt, tenant_id, owner_username, include_all_clients, &bind_index);
    sqlite3_bind_int(stmt, bind_index, limit);
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (*session_count >= max_sessions || scan_peer_mesh_session(stmt, &sessions[*session_count]) != 0) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return -1;
        }
        ++*session_count;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == SQLITE_DONE ? 0 : -1;
}

int st_storage_close_peer_mesh_session_visible(const char *path,
                                               long long id,
                                               const char *tenant_id,
                                               const char *owner_username,
                                               int include_all_clients,
                                               st_storage_peer_mesh_session *out_session)
{
    if (id <= 0 || out_session == NULL) {
        return -1;
    }
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    if (read_peer_mesh_session_visible(db, id, tenant_id, owner_username, include_all_clients, out_session) != 0) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(
        db,
        "UPDATE peer_mesh_session SET status = 'CLOSED', "
        "closed_at = COALESCE(NULLIF(closed_at, ''), CURRENT_TIMESTAMP), "
        "updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        -1,
        &stmt,
        NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, id);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    if (rc == 0) {
        rc = read_peer_mesh_session_visible(db, id, tenant_id, owner_username, include_all_clients, out_session);
    }
    sqlite3_close(db);
    return rc == 0 ? 0 : -1;
}

int st_storage_close_open_peer_mesh_sessions_visible(const char *path,
                                                     const char *tenant_id,
                                                     const char *owner_username,
                                                     int include_all_clients,
                                                     st_storage_peer_mesh_session *sessions,
                                                     size_t max_sessions,
                                                     size_t *session_count)
{
    if (sessions == NULL || session_count == NULL) {
        return -1;
    }
    if (st_storage_list_peer_mesh_sessions_visible(path,
                                                   tenant_id,
                                                   owner_username,
                                                   include_all_clients,
                                                   0,
                                                   (int)max_sessions,
                                                   sessions,
                                                   max_sessions,
                                                   session_count) != 0) {
        return -1;
    }
    for (size_t i = 0; i < *session_count; ++i) {
        st_storage_peer_mesh_session closed;
        if (st_storage_close_peer_mesh_session_visible(path,
                                                       sessions[i].id,
                                                       tenant_id,
                                                       owner_username,
                                                       include_all_clients,
                                                       &closed) != 0) {
            return -1;
        }
        sessions[i] = closed;
    }
    return 0;
}

int st_storage_record_http_exchange(const char *path, const st_storage_http_exchange_record *record)
{
    if (record == NULL || record->client_id <= 0 || record->client_name == NULL || record->route == NULL) {
        return -1;
    }
    char request_hex[4096];
    char request_text[8192];
    char response_hex[4096];
    char response_text[8192];
    build_hex_preview(record->request_body, record->request_body_len, request_hex, sizeof(request_hex));
    build_text_preview(record->request_body, record->request_body_len, request_text, sizeof(request_text));
    build_hex_preview(record->response_body, record->response_body_len, response_hex, sizeof(response_hex));
    build_text_preview(record->response_body, record->response_body_len, response_text, sizeof(response_text));
    const char *body_type = record->response_body_type != NULL && *record->response_body_type != '\0'
        ? record->response_body_type
        : classify_body_type(record->response_content_type);
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT INTO specus_http_traffic_exchange("
        "tenant_id, client_id, client_name, route, resource_id, resource_name, method, relative_path, raw_query, "
        "status_code, success, error, remote_address, request_bytes, response_bytes, elapsed_ms, "
        "request_content_type, response_content_type, response_body_type, request_headers, response_headers, "
        "request_preview_hex, request_preview_text, response_preview_hex, response_preview_text, "
        "request_truncated, response_truncated, captured_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        -1,
        &stmt,
        NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, normalize_tenant_id(record->tenant_id), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 2, record->client_id);
        sqlite3_bind_text(stmt, 3, record->client_name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, record->route, -1, SQLITE_TRANSIENT);
        if (record->resource_id > 0) {
            sqlite3_bind_int64(stmt, 5, record->resource_id);
        } else {
            sqlite3_bind_null(stmt, 5);
        }
        bind_nullable_text_limit(stmt, 6, record->resource_name == NULL ? record->route : record->resource_name, 511);
        bind_nullable_text_limit(stmt, 7, record->method == NULL ? "" : record->method, 15);
        bind_nullable_text_limit(stmt, 8, record->relative_path == NULL ? "/" : record->relative_path, 1023);
        bind_nullable_text_limit(stmt, 9, record->raw_query, 2047);
        sqlite3_bind_int(stmt, 10, record->status_code);
        sqlite3_bind_int(stmt, 11, record->success ? 1 : 0);
        bind_nullable_text_limit(stmt, 12, record->error, 2047);
        bind_nullable_text_limit(stmt, 13, record->remote_address, 255);
        sqlite3_bind_int64(stmt, 14, record->request_bytes);
        sqlite3_bind_int64(stmt, 15, record->response_bytes);
        sqlite3_bind_int64(stmt, 16, record->elapsed_ms);
        bind_nullable_text_limit(stmt, 17, record->request_content_type, 255);
        bind_nullable_text_limit(stmt, 18, record->response_content_type, 255);
        bind_nullable_text_limit(stmt, 19, body_type, 31);
        bind_nullable_text_limit(stmt, 20, record->request_headers, 8191);
        bind_nullable_text_limit(stmt, 21, record->response_headers, 8191);
        bind_nullable_text(stmt, 22, request_hex);
        bind_nullable_text(stmt, 23, request_text);
        bind_nullable_text(stmt, 24, response_hex);
        bind_nullable_text(stmt, 25, response_text);
        sqlite3_bind_int(stmt, 26, record->request_body_len > ST_STORAGE_PREVIEW_BYTES ? 1 : 0);
        sqlite3_bind_int(stmt, 27, record->response_body_len > ST_STORAGE_PREVIEW_BYTES ? 1 : 0);
        sqlite3_bind_text(stmt, 28, record->captured_at == NULL ? "" : record->captured_at, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == 0 ? 0 : -1;
}

static void copy_lower(const char *input, char *out, size_t out_len)
{
    if (out_len == 0U) {
        return;
    }
    size_t pos = 0U;
    const unsigned char *p = (const unsigned char *)(input == NULL ? "" : input);
    while (*p != '\0' && pos + 1U < out_len) {
        out[pos++] = (char)tolower(*p++);
    }
    out[pos] = '\0';
}

static void normalize_http_search_field(const char *field, char *out, size_t out_len)
{
    if (out_len == 0U) {
        return;
    }
    size_t pos = 0U;
    const unsigned char *p = (const unsigned char *)(field == NULL ? "" : field);
    while (*p != '\0' && pos + 1U < out_len) {
        if (*p != '_' && *p != '-') {
            out[pos++] = (char)tolower(*p);
        }
        ++p;
    }
    out[pos] = '\0';
}

static char *storage_dup_text(const char *text)
{
    const char *value = text == NULL ? "" : text;
    size_t len = strlen(value);
    char *copy = (char *)malloc(len + 1U);
    if (copy == NULL) {
        return NULL;
    }
    memcpy(copy, value, len + 1U);
    return copy;
}

static char *next_search_token(char **cursor)
{
    if (cursor == NULL || *cursor == NULL) {
        return NULL;
    }
    char *p = *cursor;
    while (*p != '\0' && isspace((unsigned char)*p)) {
        ++p;
    }
    if (*p == '\0') {
        *cursor = p;
        return NULL;
    }
    char *token = p;
    while (*p != '\0' && !isspace((unsigned char)*p)) {
        ++p;
    }
    if (*p != '\0') {
        *p++ = '\0';
    }
    *cursor = p;
    return token;
}

static int append_http_search_filters(char *where, size_t where_len, const char *field, const char *query);

static void append_http_search_filter(char *where, size_t where_len, const char *field)
{
    char normalized[64];
    normalize_http_search_field(field, normalized, sizeof(normalized));
    if (normalized[0] == '\0' || strcmp(normalized, "summary") == 0) {
        strncat(where,
                " AND (LOWER(COALESCE(h.client_name,'')) LIKE ? OR LOWER(COALESCE(h.route,'')) LIKE ? OR "
                "LOWER(COALESCE(h.resource_name,'')) LIKE ? OR LOWER(COALESCE(h.method,'')) LIKE ? OR "
                "LOWER(COALESCE(h.relative_path,'')) LIKE ? OR LOWER(COALESCE(h.raw_query,'')) LIKE ? OR "
                "LOWER(COALESCE(h.error,'')) LIKE ? OR LOWER(COALESCE(h.remote_address,'')) LIKE ? OR "
                "LOWER(COALESCE(h.request_content_type,'')) LIKE ? OR LOWER(COALESCE(h.response_content_type,'')) LIKE ? OR "
                "LOWER(COALESCE(h.response_body_type,'')) LIKE ? OR LOWER(COALESCE(h.captured_at,'')) LIKE ? OR "
                "CAST(h.id AS TEXT) = ? OR CAST(h.client_id AS TEXT) = ? OR CAST(h.status_code AS TEXT) = ? OR "
                "CAST(COALESCE(h.resource_id, -1) AS TEXT) = ?)",
                where_len - strlen(where) - 1U);
        return;
    }
    if (strcmp(normalized, "all") == 0) {
        strncat(where,
                " AND (LOWER(COALESCE(h.client_name,'')) LIKE ? OR LOWER(COALESCE(h.route,'')) LIKE ? OR "
                "LOWER(COALESCE(h.resource_name,'')) LIKE ? OR LOWER(COALESCE(h.method,'')) LIKE ? OR "
                "LOWER(COALESCE(h.relative_path,'')) LIKE ? OR LOWER(COALESCE(h.raw_query,'')) LIKE ? OR "
                "LOWER(COALESCE(h.error,'')) LIKE ? OR LOWER(COALESCE(h.remote_address,'')) LIKE ? OR "
                "LOWER(COALESCE(h.request_content_type,'')) LIKE ? OR LOWER(COALESCE(h.response_content_type,'')) LIKE ? OR "
                "LOWER(COALESCE(h.response_body_type,'')) LIKE ? OR LOWER(COALESCE(h.request_headers,'')) LIKE ? OR "
                "LOWER(COALESCE(h.response_headers,'')) LIKE ? OR LOWER(COALESCE(h.request_preview_text,'')) LIKE ? OR "
                "LOWER(COALESCE(h.response_preview_text,'')) LIKE ? OR LOWER(COALESCE(h.captured_at,'')) LIKE ? OR "
                "CAST(h.id AS TEXT) = ? OR CAST(h.client_id AS TEXT) = ? OR CAST(h.status_code AS TEXT) = ? OR "
                "CAST(COALESCE(h.resource_id, -1) AS TEXT) = ?)",
                where_len - strlen(where) - 1U);
        return;
    }
    if (strcmp(normalized, "method") == 0) {
        strncat(where, " AND LOWER(COALESCE(h.method,'')) = LOWER(?)", where_len - strlen(where) - 1U);
    } else if (strcmp(normalized, "id") == 0) {
        strncat(where, " AND CAST(h.id AS TEXT) = ?", where_len - strlen(where) - 1U);
    } else if (strcmp(normalized, "status") == 0 || strcmp(normalized, "statuscode") == 0) {
        strncat(where, " AND CAST(h.status_code AS TEXT) = ?", where_len - strlen(where) - 1U);
    } else if (strcmp(normalized, "route") == 0) {
        strncat(where, " AND LOWER(COALESCE(h.route,'')) LIKE ?", where_len - strlen(where) - 1U);
    } else if (strcmp(normalized, "path") == 0 || strcmp(normalized, "relativepath") == 0) {
        strncat(where,
                " AND (LOWER(COALESCE(h.relative_path,'')) LIKE ? OR LOWER(COALESCE(h.raw_query,'')) LIKE ?)",
                where_len - strlen(where) - 1U);
    } else if (strcmp(normalized, "query") == 0 || strcmp(normalized, "rawquery") == 0) {
        strncat(where, " AND LOWER(COALESCE(h.raw_query,'')) LIKE ?", where_len - strlen(where) - 1U);
    } else if (strcmp(normalized, "client") == 0 || strcmp(normalized, "clientid") == 0
               || strcmp(normalized, "clientname") == 0) {
        strncat(where,
                " AND (LOWER(COALESCE(h.client_name,'')) LIKE ? OR CAST(h.client_id AS TEXT) = ?)",
                where_len - strlen(where) - 1U);
    } else if (strcmp(normalized, "resource") == 0 || strcmp(normalized, "resourceid") == 0
               || strcmp(normalized, "resourcename") == 0) {
        strncat(where,
                " AND (LOWER(COALESCE(h.resource_name,'')) LIKE ? OR CAST(COALESCE(h.resource_id, -1) AS TEXT) = ?)",
                where_len - strlen(where) - 1U);
    } else if (strcmp(normalized, "remote") == 0 || strcmp(normalized, "remoteaddress") == 0) {
        strncat(where, " AND LOWER(COALESCE(h.remote_address,'')) LIKE ?", where_len - strlen(where) - 1U);
    } else if (strcmp(normalized, "contenttype") == 0) {
        strncat(where,
                " AND (LOWER(COALESCE(h.request_content_type,'')) LIKE ? OR "
                "LOWER(COALESCE(h.response_content_type,'')) LIKE ? OR LOWER(COALESCE(h.response_body_type,'')) = LOWER(?))",
                where_len - strlen(where) - 1U);
    } else if (strcmp(normalized, "error") == 0) {
        strncat(where, " AND LOWER(COALESCE(h.error,'')) LIKE ?", where_len - strlen(where) - 1U);
    } else if (strcmp(normalized, "requestheaders") == 0) {
        strncat(where, " AND LOWER(COALESCE(h.request_headers,'')) LIKE ?", where_len - strlen(where) - 1U);
    } else if (strcmp(normalized, "responseheaders") == 0) {
        strncat(where, " AND LOWER(COALESCE(h.response_headers,'')) LIKE ?", where_len - strlen(where) - 1U);
    } else if (strcmp(normalized, "headers") == 0) {
        strncat(where,
                " AND (LOWER(COALESCE(h.request_headers,'')) LIKE ? OR LOWER(COALESCE(h.response_headers,'')) LIKE ?)",
                where_len - strlen(where) - 1U);
    } else if (strcmp(normalized, "requestbody") == 0) {
        strncat(where, " AND LOWER(COALESCE(h.request_preview_text,'')) LIKE ?", where_len - strlen(where) - 1U);
    } else if (strcmp(normalized, "responsebody") == 0) {
        strncat(where, " AND LOWER(COALESCE(h.response_preview_text,'')) LIKE ?", where_len - strlen(where) - 1U);
    } else if (strcmp(normalized, "body") == 0) {
        strncat(where,
                " AND (LOWER(COALESCE(h.request_preview_text,'')) LIKE ? OR LOWER(COALESCE(h.response_preview_text,'')) LIKE ?)",
                where_len - strlen(where) - 1U);
    } else if (strcmp(normalized, "responsebodytype") == 0 || strcmp(normalized, "responsedatatype") == 0) {
        strncat(where, " AND LOWER(COALESCE(h.response_body_type,'')) = LOWER(?)", where_len - strlen(where) - 1U);
    } else {
        strncat(where, " AND LOWER(COALESCE(h.response_preview_text,'')) LIKE ?", where_len - strlen(where) - 1U);
    }
}

static int append_http_search_filters(char *where, size_t where_len, const char *field, const char *query)
{
    char *copy = storage_dup_text(query);
    if (copy == NULL) {
        return -1;
    }
    char *cursor = copy;
    char *token = NULL;
    int appended = 0;
    while ((token = next_search_token(&cursor)) != NULL) {
        (void)token;
        append_http_search_filter(where, where_len, field);
        appended = 1;
    }
    free(copy);
    (void)appended;
    return 0;
}

static void bind_like(sqlite3_stmt *stmt, int *index, const char *query)
{
    char like[512];
    char lower[480];
    copy_lower(query == NULL ? "" : query, lower, sizeof(lower));
    snprintf(like, sizeof(like), "%%%s%%", lower);
    sqlite3_bind_text(stmt, (*index)++, like, -1, SQLITE_TRANSIENT);
}

static void bind_exact(sqlite3_stmt *stmt, int *index, const char *query)
{
    sqlite3_bind_text(stmt, (*index)++, query == NULL ? "" : query, -1, SQLITE_TRANSIENT);
}

static void bind_http_search_token(sqlite3_stmt *stmt, int *index, const char *field, const char *token)
{
    char normalized[64];
    normalize_http_search_field(field, normalized, sizeof(normalized));
    if (normalized[0] == '\0' || strcmp(normalized, "summary") == 0) {
        for (int i = 0; i < 12; ++i) {
            bind_like(stmt, index, token);
        }
        for (int i = 0; i < 4; ++i) {
            bind_exact(stmt, index, token);
        }
    } else if (strcmp(normalized, "all") == 0) {
        for (int i = 0; i < 16; ++i) {
            bind_like(stmt, index, token);
        }
        for (int i = 0; i < 4; ++i) {
            bind_exact(stmt, index, token);
        }
    } else if (strcmp(normalized, "path") == 0 || strcmp(normalized, "relativepath") == 0
               || strcmp(normalized, "headers") == 0 || strcmp(normalized, "body") == 0) {
        bind_like(stmt, index, token);
        bind_like(stmt, index, token);
    } else if (strcmp(normalized, "client") == 0 || strcmp(normalized, "clientid") == 0
               || strcmp(normalized, "clientname") == 0 || strcmp(normalized, "resource") == 0
               || strcmp(normalized, "resourceid") == 0 || strcmp(normalized, "resourcename") == 0) {
        bind_like(stmt, index, token);
        bind_exact(stmt, index, token);
    } else if (strcmp(normalized, "contenttype") == 0) {
        bind_like(stmt, index, token);
        bind_like(stmt, index, token);
        bind_exact(stmt, index, token);
    } else if (strcmp(normalized, "method") == 0 || strcmp(normalized, "id") == 0
               || strcmp(normalized, "status") == 0 || strcmp(normalized, "statuscode") == 0
               || strcmp(normalized, "responsebodytype") == 0 || strcmp(normalized, "responsedatatype") == 0) {
        bind_exact(stmt, index, token);
    } else {
        bind_like(stmt, index, token);
    }
}

static void bind_http_filters(sqlite3_stmt *stmt,
                              const char *tenant_id,
                              const char *owner_username,
                              int include_all_clients,
                              long long client_id,
                              const char *route,
                              const char *response_body_type,
                              const char *field,
                              const char *query,
                              int *index)
{
    sqlite3_bind_text(stmt, (*index)++, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
    if (!include_all_clients) {
        sqlite3_bind_text(stmt, (*index)++, normalize_owner_username(owner_username), -1, SQLITE_TRANSIENT);
    }
    if (client_id > 0) {
        sqlite3_bind_int64(stmt, (*index)++, client_id);
    }
    if (route != NULL && *route != '\0') {
        sqlite3_bind_text(stmt, (*index)++, route, -1, SQLITE_TRANSIENT);
    }
    if (response_body_type != NULL && *response_body_type != '\0') {
        sqlite3_bind_text(stmt, (*index)++, response_body_type, -1, SQLITE_TRANSIENT);
    }
    if (query != NULL && *query != '\0') {
        char *copy = storage_dup_text(query);
        if (copy == NULL) {
            return;
        }
        char *cursor = copy;
        char *token = NULL;
        while ((token = next_search_token(&cursor)) != NULL) {
            bind_http_search_token(stmt, index, field, token);
        }
        free(copy);
    }
}

int st_storage_list_http_exchanges_visible(const char *path,
                                           long long client_id,
                                           const char *route,
                                           const char *response_body_type,
                                           const char *field,
                                           const char *query,
                                           const char *tenant_id,
                                           const char *owner_username,
                                           int include_all_clients,
                                           int page,
                                           int size,
                                           st_storage_http_exchange *items,
                                           size_t max_items,
                                           size_t *item_count,
                                           long long *total_count)
{
    *item_count = 0;
    *total_count = 0;
    if (page < 0) {
        page = 0;
    }
    if (size <= 0) {
        size = 50;
    } else if (size > 500) {
        size = 500;
    }
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    char where[4096];
    int written = snprintf(where,
                           sizeof(where),
                           " WHERE c.tenant_id = ?%s",
                           include_all_clients ? "" : " AND c.owner_username = ?");
    if (written < 0 || (size_t)written >= sizeof(where)) {
        sqlite3_close(db);
        return -1;
    }
    if (client_id > 0) {
        strncat(where, " AND h.client_id = ?", sizeof(where) - strlen(where) - 1U);
    }
    if (route != NULL && *route != '\0') {
        strncat(where, " AND h.route = ?", sizeof(where) - strlen(where) - 1U);
    }
    if (response_body_type != NULL && *response_body_type != '\0') {
        strncat(where, " AND h.response_body_type = ?", sizeof(where) - strlen(where) - 1U);
    }
    if (query != NULL && *query != '\0') {
        if (append_http_search_filters(where, sizeof(where), field, query) != 0) {
            sqlite3_close(db);
            return -1;
        }
    }
    char sql[8192];
    written = snprintf(sql,
                       sizeof(sql),
                       "SELECT COUNT(*) FROM specus_http_traffic_exchange h "
                       "JOIN client_account c ON c.rowid = h.client_id%s",
                       where);
    if (written < 0 || (size_t)written >= sizeof(sql)) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    int bind_index = 1;
    bind_http_filters(stmt, tenant_id, owner_username, include_all_clients, client_id, route,
                      response_body_type, field, query, &bind_index);
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *total_count = sqlite3_column_int64(stmt, 0);
        rc = SQLITE_DONE;
    }
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        sqlite3_close(db);
        return -1;
    }
    written = snprintf(sql,
                       sizeof(sql),
                       "SELECT h.id, h.tenant_id, h.client_id, h.client_name, h.route, h.resource_id, "
                       "h.resource_name, h.method, h.relative_path, h.raw_query, h.status_code, h.success, "
                       "h.error, h.remote_address, h.request_bytes, h.response_bytes, h.elapsed_ms, "
                       "h.request_content_type, h.response_content_type, h.response_body_type, "
                       "h.request_headers, h.response_headers, h.request_preview_hex, h.request_preview_text, "
                       "h.response_preview_hex, h.response_preview_text, h.request_truncated, "
                       "h.response_truncated, h.captured_at "
                       "FROM specus_http_traffic_exchange h JOIN client_account c ON c.rowid = h.client_id%s "
                       "ORDER BY h.id DESC LIMIT ? OFFSET ?",
                       where);
    if (written < 0 || (size_t)written >= sizeof(sql)) {
        sqlite3_close(db);
        return -1;
    }
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    bind_index = 1;
    bind_http_filters(stmt, tenant_id, owner_username, include_all_clients, client_id, route,
                      response_body_type, field, query, &bind_index);
    sqlite3_bind_int(stmt, bind_index++, size);
    sqlite3_bind_int(stmt, bind_index, page * size);
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (*item_count >= max_items || scan_http_exchange(stmt, &items[*item_count]) != 0) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return -1;
        }
        ++*item_count;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == SQLITE_DONE ? 0 : -1;
}

int st_storage_record_tcp_frame(const char *path, const st_storage_tcp_frame_record *record)
{
    if (record == NULL || record->client_id <= 0 || record->client_name == NULL
        || record->channel_id == NULL || record->direction == NULL) {
        return -1;
    }
    char payload_hex[4096];
    char payload_text[4096];
    build_hex_preview(record->payload_data, record->payload_data_len, payload_hex, sizeof(payload_hex));
    build_text_preview(record->payload_data, record->payload_data_len, payload_text, sizeof(payload_text));
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT INTO specus_tcp_traffic_frame("
        "tenant_id, client_id, client_name, listen_port, resource_id, resource_name, channel_id, "
        "frame_direction, remote_address, source_address, source_port, destination_address, destination_port, "
        "stream_offset, stream_end_offset, frame_index, payload_bytes, payload_data, payload_preview_hex, "
        "payload_preview_text, truncated, frame_time) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        -1,
        &stmt,
        NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, normalize_tenant_id(record->tenant_id), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 2, record->client_id);
        sqlite3_bind_text(stmt, 3, record->client_name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 4, record->listen_port);
        if (record->resource_id > 0) {
            sqlite3_bind_int64(stmt, 5, record->resource_id);
        } else {
            sqlite3_bind_null(stmt, 5);
        }
        sqlite3_bind_text(stmt, 6, record->resource_name == NULL ? "" : record->resource_name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 7, record->channel_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 8, record->direction, -1, SQLITE_TRANSIENT);
        bind_nullable_text(stmt, 9, record->remote_address);
        bind_nullable_text(stmt, 10, record->source_address);
        if (record->source_port > 0) {
            sqlite3_bind_int(stmt, 11, record->source_port);
        } else {
            sqlite3_bind_null(stmt, 11);
        }
        bind_nullable_text(stmt, 12, record->destination_address);
        if (record->destination_port > 0) {
            sqlite3_bind_int(stmt, 13, record->destination_port);
        } else {
            sqlite3_bind_null(stmt, 13);
        }
        sqlite3_bind_int64(stmt, 14, record->stream_offset);
        sqlite3_bind_int64(stmt, 15, record->stream_offset + (long long)record->payload_data_len);
        sqlite3_bind_int64(stmt, 16, record->frame_index);
        sqlite3_bind_int64(stmt, 17, (long long)record->payload_data_len);
        if (record->payload_data != NULL && record->payload_data_len > 0) {
            sqlite3_bind_blob(stmt, 18, record->payload_data, (int)record->payload_data_len, SQLITE_TRANSIENT);
        } else {
            sqlite3_bind_null(stmt, 18);
        }
        bind_nullable_text(stmt, 19, payload_hex);
        bind_nullable_text(stmt, 20, payload_text);
        sqlite3_bind_int(stmt, 21, 0);
        sqlite3_bind_text(stmt, 22, record->frame_time == NULL ? "" : record->frame_time, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == 0 ? 0 : -1;
}

static void bind_tcp_visible_filters(sqlite3_stmt *stmt,
                                     const char *tenant_id,
                                     const char *owner_username,
                                     int include_all_clients,
                                     long long client_id,
                                     int listen_port,
                                     const char *channel_id,
                                     int *index)
{
    sqlite3_bind_text(stmt, (*index)++, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
    if (!include_all_clients) {
        sqlite3_bind_text(stmt, (*index)++, normalize_owner_username(owner_username), -1, SQLITE_TRANSIENT);
    }
    if (client_id > 0) {
        sqlite3_bind_int64(stmt, (*index)++, client_id);
    }
    if (listen_port > 0) {
        sqlite3_bind_int(stmt, (*index)++, listen_port);
    }
    if (channel_id != NULL && *channel_id != '\0') {
        sqlite3_bind_text(stmt, (*index)++, channel_id, -1, SQLITE_TRANSIENT);
    }
}

static int build_tcp_visible_where(char *where,
                                   size_t where_len,
                                   int include_all_clients,
                                   long long client_id,
                                   int listen_port,
                                   const char *channel_id)
{
    int written = snprintf(where,
                           where_len,
                           " WHERE c.tenant_id = ?%s",
                           include_all_clients ? "" : " AND c.owner_username = ?");
    if (written < 0 || (size_t)written >= where_len) {
        return -1;
    }
    if (client_id > 0) {
        strncat(where, " AND f.client_id = ?", where_len - strlen(where) - 1U);
    }
    if (listen_port > 0) {
        strncat(where, " AND f.listen_port = ?", where_len - strlen(where) - 1U);
    }
    if (channel_id != NULL && *channel_id != '\0') {
        strncat(where, " AND f.channel_id = ?", where_len - strlen(where) - 1U);
    }
    return 0;
}

static int list_tcp_frames_internal(const char *path,
                                    long long client_id,
                                    int listen_port,
                                    const char *channel_id,
                                    const char *tenant_id,
                                    const char *owner_username,
                                    int include_all_clients,
                                    int page,
                                    int size,
                                    int include_payload,
                                    st_storage_tcp_frame *items,
                                    size_t max_items,
                                    size_t *item_count,
                                    long long *total_count)
{
    *item_count = 0;
    if (total_count != NULL) {
        *total_count = 0;
    }
    if (page < 0) {
        page = 0;
    }
    if (size <= 0) {
        size = 50;
    } else if (size > 1000) {
        size = 1000;
    }
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    char where[512];
    if (build_tcp_visible_where(where, sizeof(where), include_all_clients, client_id, listen_port, channel_id) != 0) {
        sqlite3_close(db);
        return -1;
    }
    char sql[2048];
    int written = snprintf(sql,
                           sizeof(sql),
                           "SELECT COUNT(*) FROM specus_tcp_traffic_frame f "
                           "JOIN client_account c ON c.rowid = f.client_id%s",
                           where);
    if (written < 0 || (size_t)written >= sizeof(sql)) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    int bind_index = 1;
    bind_tcp_visible_filters(stmt, tenant_id, owner_username, include_all_clients, client_id, listen_port, channel_id, &bind_index);
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW && total_count != NULL) {
        *total_count = sqlite3_column_int64(stmt, 0);
        rc = SQLITE_DONE;
    }
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        sqlite3_close(db);
        return -1;
    }
    written = snprintf(sql,
                       sizeof(sql),
                       "SELECT f.id, f.tenant_id, f.client_id, f.client_name, f.listen_port, f.resource_id, "
                       "f.resource_name, f.channel_id, f.frame_direction, f.remote_address, f.source_address, "
                       "f.source_port, f.destination_address, f.destination_port, f.stream_offset, "
                       "f.stream_end_offset, f.frame_index, f.payload_bytes, %s, f.payload_preview_hex, "
                       "f.payload_preview_text, f.truncated, f.frame_time "
                       "FROM specus_tcp_traffic_frame f JOIN client_account c ON c.rowid = f.client_id%s "
                       "ORDER BY %s LIMIT ? OFFSET ?",
                       include_payload ? "f.payload_data" : "NULL",
                       where,
                       channel_id != NULL && *channel_id != '\0'
                           ? "f.frame_index ASC, f.id ASC"
                           : "f.id DESC");
    if (written < 0 || (size_t)written >= sizeof(sql)) {
        sqlite3_close(db);
        return -1;
    }
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    bind_index = 1;
    bind_tcp_visible_filters(stmt, tenant_id, owner_username, include_all_clients, client_id, listen_port, channel_id, &bind_index);
    sqlite3_bind_int(stmt, bind_index++, size);
    sqlite3_bind_int(stmt, bind_index, page * size);
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (*item_count >= max_items || scan_tcp_frame(stmt, &items[*item_count], include_payload) != 0) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return -1;
        }
        ++*item_count;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == SQLITE_DONE ? 0 : -1;
}

int st_storage_list_tcp_frames_visible(const char *path,
                                       long long client_id,
                                       int listen_port,
                                       const char *tenant_id,
                                       const char *owner_username,
                                       int include_all_clients,
                                       int page,
                                       int size,
                                       st_storage_tcp_frame *items,
                                       size_t max_items,
                                       size_t *item_count,
                                       long long *total_count)
{
    return list_tcp_frames_internal(path,
                                    client_id,
                                    listen_port,
                                    NULL,
                                    tenant_id,
                                    owner_username,
                                    include_all_clients,
                                    page,
                                    size,
                                    0,
                                    items,
                                    max_items,
                                    item_count,
                                    total_count);
}

int st_storage_get_tcp_frame_visible(const char *path,
                                     long long id,
                                     const char *tenant_id,
                                     const char *owner_username,
                                     int include_all_clients,
                                     st_storage_tcp_frame *frame)
{
    if (frame == NULL || id <= 0) {
        return -1;
    }
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    char sql[2048];
    int written = snprintf(sql,
                           sizeof(sql),
                           "SELECT f.id, f.tenant_id, f.client_id, f.client_name, f.listen_port, f.resource_id, "
                           "f.resource_name, f.channel_id, f.frame_direction, f.remote_address, f.source_address, "
                           "f.source_port, f.destination_address, f.destination_port, f.stream_offset, "
                           "f.stream_end_offset, f.frame_index, f.payload_bytes, f.payload_data, "
                           "f.payload_preview_hex, f.payload_preview_text, f.truncated, f.frame_time "
                           "FROM specus_tcp_traffic_frame f JOIN client_account c ON c.rowid = f.client_id "
                           "WHERE f.id = ? AND c.tenant_id = ?%s",
                           include_all_clients ? "" : " AND c.owner_username = ?");
    if (written < 0 || (size_t)written >= sizeof(sql)) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    int bind_index = 1;
    sqlite3_bind_int64(stmt, bind_index++, id);
    sqlite3_bind_text(stmt, bind_index++, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
    if (!include_all_clients) {
        sqlite3_bind_text(stmt, bind_index++, normalize_owner_username(owner_username), -1, SQLITE_TRANSIENT);
    }
    rc = sqlite3_step(stmt);
    int ok = rc == SQLITE_ROW && scan_tcp_frame(stmt, frame, 1) == 0;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return ok ? 0 : -1;
}

int st_storage_list_tcp_stream_visible(const char *path,
                                       const char *channel_id,
                                       const char *tenant_id,
                                       const char *owner_username,
                                       int include_all_clients,
                                       int limit,
                                       st_storage_tcp_frame *items,
                                       size_t max_items,
                                       size_t *item_count)
{
    long long total_count = 0;
    if (channel_id == NULL || *channel_id == '\0') {
        *item_count = 0;
        return -1;
    }
    return list_tcp_frames_internal(path,
                                    0,
                                    0,
                                    channel_id,
                                    tenant_id,
                                    owner_username,
                                    include_all_clients,
                                    0,
                                    limit,
                                    1,
                                    items,
                                    max_items,
                                    item_count,
                                    &total_count);
}

void st_storage_tcp_frame_free(st_storage_tcp_frame *frame)
{
    if (frame != NULL) {
        free(frame->payload_data);
        frame->payload_data = NULL;
        frame->payload_data_len = 0;
    }
}
