#include "storage.h"

#include "crypto.h"
#include "elasticsearch_traffic.h"
#include "http_share.h"
#include "json.h"
#include "traffic_capture.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <limits.h>
#include <sqlite3.h>
#include <stdatomic.h>
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
        const char *error = *db == NULL ? "sqlite handle allocation failed" : sqlite3_errmsg(*db);
        fprintf(stderr, "failed to open sqlite database %s: %s\n", path, error);
        if (*db != NULL) {
            sqlite3_close(*db);
        }
        *db = NULL;
        return -1;
    }
    if (sqlite3_busy_timeout(*db, 5000) != SQLITE_OK) {
        fprintf(stderr, "failed to configure sqlite busy timeout for %s: %s\n",
                path,
                sqlite3_errmsg(*db));
        sqlite3_close(*db);
        *db = NULL;
        return -1;
    }
    return 0;
}

static const char *normalize_tenant_id(const char *tenant_id);

/*
 * Deletes every identity's workbench references to one object, whatever their tenant: no
 * reference may outlive its object, so an id handed out again never inherits one. Runs inside the
 * caller's transaction, next to the deletion of the object itself.
 */
static int workbench_delete_object_refs(sqlite3 *db, const char *kind, long long object_id)
{
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "DELETE FROM management_workbench_item WHERE kind = ? AND object_id = ?",
        -1,
        &stmt,
        NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, kind, -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 2, object_id);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    return rc;
}

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
        "CREATE TABLE IF NOT EXISTS specus_management_user_email ("
        "username TEXT PRIMARY KEY,"
        "email TEXT NOT NULL COLLATE NOCASE UNIQUE,"
        "verified_at TEXT NOT NULL,"
        "created_at TEXT NOT NULL,"
        "updated_at TEXT NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS specus_management_registration_challenge ("
        "registration_id TEXT PRIMARY KEY,"
        "username TEXT NOT NULL COLLATE NOCASE UNIQUE,"
        "email TEXT NOT NULL COLLATE NOCASE UNIQUE,"
        "password_hash TEXT NOT NULL,"
        "code_hash TEXT NOT NULL,"
        "attempts_remaining INTEGER NOT NULL,"
        "expires_at TEXT NOT NULL,"
        "resend_available_at TEXT NOT NULL,"
        "created_at TEXT NOT NULL,"
        "updated_at TEXT NOT NULL"
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
        "version TEXT,"
        "sha256 TEXT,"
        "file_size INTEGER NOT NULL DEFAULT 0,"
        "is_latest INTEGER NOT NULL DEFAULT 0,"
        "changelog_url TEXT,"
        "min_supported_version TEXT,"
        "hosted INTEGER NOT NULL DEFAULT 0,"
        "package_path TEXT,"
        "package_file_name TEXT,"
        "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ");"
        "CREATE TABLE IF NOT EXISTS user_diagram_document ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "tenant_id TEXT NOT NULL,"
        "owner_username TEXT NOT NULL,"
        "name TEXT NOT NULL,"
        "snapshot_data BLOB NOT NULL,"
        "size_bytes INTEGER NOT NULL,"
        "revision INTEGER NOT NULL DEFAULT 0,"
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
        ");");
    if (rc == 0) {
        rc = exec_sql(db,
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
        "peer_service_discovery_version INTEGER NOT NULL DEFAULT 0,"
        "peer_service_applications TEXT,"
        "http_login_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "netty_connected_at TEXT,"
        "disconnected_at TEXT,"
        "expires_at TEXT NOT NULL,"
        "channel_id TEXT,"
        "remote_address TEXT,"
        "client_egress_version INTEGER NOT NULL DEFAULT 0,"
        "client_egress_domain_targets INTEGER NOT NULL DEFAULT 0,"
        "client_http_route_version INTEGER NOT NULL DEFAULT 0"
        ");");
    }
    if (rc == 0) {
        rc = exec_sql(db,
        "CREATE TABLE IF NOT EXISTS public_transfer_room ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "room_name TEXT NOT NULL,"
        "owner_token_hash TEXT NOT NULL,"
        "created_by_peer_id TEXT NOT NULL,"
        "created_at TEXT NOT NULL,"
        "updated_at TEXT NOT NULL,"
        "UNIQUE(room_name, owner_token_hash)"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_public_transfer_room_name "
        "ON public_transfer_room(room_name);"
        "CREATE TABLE IF NOT EXISTS public_transfer_room_access ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "room_id INTEGER NOT NULL,"
        "token_hash TEXT NOT NULL UNIQUE,"
        "role TEXT NOT NULL,"
        "label TEXT NOT NULL,"
        "created_at TEXT NOT NULL,"
        "expires_at TEXT,"
        "revoked_at TEXT"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_public_transfer_access_room "
        "ON public_transfer_room_access(room_id);"
        "CREATE TABLE IF NOT EXISTS public_transfer_room_pairing_code ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "room_id INTEGER NOT NULL,"
        "code_hash TEXT NOT NULL UNIQUE,"
        "role TEXT NOT NULL,"
        "label TEXT NOT NULL,"
        "created_at TEXT NOT NULL,"
        "expires_at TEXT NOT NULL,"
        "max_uses INTEGER NOT NULL,"
        "used_count INTEGER NOT NULL DEFAULT 0,"
        "revoked_at TEXT"
        ");"
        "CREATE TABLE IF NOT EXISTS public_transfer_diagram_version ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "room_id INTEGER NOT NULL,"
        "name TEXT NOT NULL,"
        "author_peer_id TEXT NOT NULL,"
        "snapshot_data BLOB NOT NULL,"
        "size_bytes INTEGER NOT NULL,"
        "created_at TEXT NOT NULL"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_public_transfer_version_room "
        "ON public_transfer_diagram_version(room_id);"
        "CREATE INDEX IF NOT EXISTS idx_public_transfer_version_created "
        "ON public_transfer_diagram_version(created_at);");
    }
    if (rc == 0) {
        rc = exec_sql(db,
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
        "media_capture_enabled INTEGER NOT NULL DEFAULT 0,"
        "path_rewrite_enabled INTEGER NOT NULL DEFAULT 0,"
        "insecure_skip_verify INTEGER NOT NULL DEFAULT 0,"
        "auth_enabled INTEGER NOT NULL DEFAULT 0,"
        "auth_username TEXT NOT NULL DEFAULT '',"
        "auth_password_hash TEXT NOT NULL DEFAULT '',"
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
        "cidr TEXT NOT NULL DEFAULT '100.96.0.0/11',"
        "public_key TEXT,"
        "nat_type TEXT NOT NULL DEFAULT 'UNKNOWN',"
        "nat_mapping_behavior TEXT,"
        "nat_filtering_behavior TEXT,"
        "nat_behavior_discovery TEXT,"
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
        ");");
    }
    if (rc == 0) {
        rc = exec_sql(db,
        "CREATE TABLE IF NOT EXISTS peer_mesh_service_sharing ("
        "tenant_id TEXT NOT NULL PRIMARY KEY,enabled INTEGER NOT NULL DEFAULT 0,"
        "mdns_import_enabled INTEGER NOT NULL DEFAULT 0,updated_by TEXT,"
        "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);"
        "CREATE TABLE IF NOT EXISTS peer_mesh_shared_service ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,tenant_id TEXT NOT NULL,client_id INTEGER NOT NULL,"
        "client_name TEXT NOT NULL,service_id TEXT NOT NULL,name TEXT NOT NULL,description TEXT,"
        "transport TEXT NOT NULL,application TEXT NOT NULL,target_host TEXT NOT NULL,"
        "target_port INTEGER NOT NULL,published_port INTEGER NOT NULL,path TEXT,"
        "enabled INTEGER NOT NULL DEFAULT 0,visibility TEXT NOT NULL DEFAULT 'OWNER',"
        "allowed_client_ids TEXT,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,UNIQUE(tenant_id,client_id,service_id));"
        "CREATE TABLE IF NOT EXISTS peer_mesh_service_audit ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "action TEXT NOT NULL,tenant_id TEXT NOT NULL,client_id INTEGER,session_id INTEGER,"
        "service_id TEXT,reason TEXT);"
        "CREATE INDEX IF NOT EXISTS idx_peer_shared_service_tenant_client "
        "ON peer_mesh_shared_service(tenant_id,client_id);"
        "CREATE INDEX IF NOT EXISTS idx_peer_service_audit_tenant_id "
        "ON peer_mesh_service_audit(tenant_id,id DESC);"
        "CREATE TABLE IF NOT EXISTS peer_mesh_egress_policy ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,tenant_id TEXT NOT NULL,owner_username TEXT NOT NULL,"
        "egress_client_id INTEGER NOT NULL,egress_client_name TEXT NOT NULL,"
        "enabled INTEGER NOT NULL DEFAULT 0,scope TEXT NOT NULL DEFAULT 'PUBLIC',"
        "allowed_consumer_client_ids TEXT,destination_rules TEXT,"
        "domain_rules TEXT NOT NULL DEFAULT '[]',"
        "max_concurrent_flows INTEGER NOT NULL DEFAULT 256,"
        "max_flows_per_consumer INTEGER NOT NULL DEFAULT 64,"
        "idle_timeout_seconds INTEGER NOT NULL DEFAULT 60,"
        "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "UNIQUE(tenant_id,egress_client_id));"
        "CREATE INDEX IF NOT EXISTS idx_peer_egress_policy_enabled "
        "ON peer_mesh_egress_policy(tenant_id,enabled);"
        "CREATE TABLE IF NOT EXISTS peer_mesh_egress_activity ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,tenant_id TEXT NOT NULL,egress_client_id INTEGER NOT NULL,"
        "egress_client_name TEXT NOT NULL,session_id INTEGER NOT NULL DEFAULT 0,"
        "revision INTEGER NOT NULL DEFAULT 0,active_flows INTEGER NOT NULL DEFAULT 0,"
        "total_flows INTEGER NOT NULL DEFAULT 0,rejected_flows TEXT,"
        "bytes_in INTEGER NOT NULL DEFAULT 0,bytes_out INTEGER NOT NULL DEFAULT 0,"
        "reported_at TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "UNIQUE(tenant_id,egress_client_id));"
        "CREATE TABLE IF NOT EXISTS peer_mesh_egress_switch ("
        "tenant_id TEXT NOT NULL PRIMARY KEY,enabled INTEGER NOT NULL DEFAULT 0,"
        "updated_by TEXT,updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);"
        );
    }
    if (rc == 0) {
        rc = exec_sql(db,
        "CREATE TABLE IF NOT EXISTS specus_http_media_capture ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "tenant_id TEXT NOT NULL,"
        "client_id INTEGER NOT NULL,"
        "client_name TEXT NOT NULL,"
        "route TEXT NOT NULL,"
        "resource_id INTEGER,"
        "source_url TEXT NOT NULL,"
        "resource_key TEXT NOT NULL,"
        "deduplication_key TEXT UNIQUE,"
        "method TEXT NOT NULL,"
        "status_code INTEGER NOT NULL,"
        "content_type TEXT,"
        "content_encoding TEXT,"
        "media_kind TEXT NOT NULL,"
        "entity_tag TEXT,"
        "last_modified TEXT,"
        "content_range_start INTEGER,"
        "content_range_end INTEGER,"
        "total_bytes INTEGER,"
        "captured_bytes INTEGER NOT NULL DEFAULT 0,"
        "segment_sequence INTEGER,"
        "initialization_segment INTEGER NOT NULL DEFAULT 0,"
        "live_stream INTEGER NOT NULL DEFAULT 0,"
        "object_key TEXT NOT NULL,"
        "upload_id TEXT,"
        "object_etag TEXT,"
        "state TEXT NOT NULL,"
        "failure_reason TEXT,"
        "response_headers TEXT,"
        "captured_at TEXT NOT NULL,"
        "completed_at TEXT,"
        "expires_at TEXT NOT NULL"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_http_media_tenant_id ON specus_http_media_capture(tenant_id,id);"
        "CREATE INDEX IF NOT EXISTS idx_http_media_tenant_client_id ON specus_http_media_capture(tenant_id,client_id,id);"
        "CREATE INDEX IF NOT EXISTS idx_http_media_resource ON specus_http_media_capture(tenant_id,resource_key,id);"
        "CREATE INDEX IF NOT EXISTS idx_http_media_source ON specus_http_media_capture(tenant_id,client_id,route,id);"
        "CREATE INDEX IF NOT EXISTS idx_http_media_expiry ON specus_http_media_capture(state,expires_at);"
        "CREATE TABLE IF NOT EXISTS specus_http_media_reference ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "tenant_id TEXT NOT NULL,"
        "manifest_capture_id INTEGER NOT NULL,"
        "relation_type TEXT NOT NULL,"
        "sequence_index INTEGER,"
        "original_uri TEXT NOT NULL,"
        "resolved_source_url TEXT NOT NULL,"
        "created_at TEXT NOT NULL"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_http_media_ref_manifest ON specus_http_media_reference(tenant_id,manifest_capture_id,sequence_index);"
        "CREATE INDEX IF NOT EXISTS idx_http_media_ref_source ON specus_http_media_reference(tenant_id,manifest_capture_id);"
        );
    }
    if (rc == 0) {
        rc = exec_sql(db,
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
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "client_account", "tenant_id", "TEXT NOT NULL DEFAULT 'default'");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "client_account", "owner_username", "TEXT NOT NULL DEFAULT 'admin'");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "client_download_link", "version", "TEXT");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "client_download_link", "sha256", "TEXT");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "client_download_link", "file_size", "INTEGER NOT NULL DEFAULT 0");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "client_download_link", "is_latest", "INTEGER NOT NULL DEFAULT 0");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "client_download_link", "changelog_url", "TEXT");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "client_download_link", "min_supported_version", "TEXT");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "client_download_link", "hosted", "INTEGER NOT NULL DEFAULT 0");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "client_download_link", "package_path", "TEXT");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "client_download_link", "package_file_name", "TEXT");
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
        rc = add_column_if_missing(db, "http_route_mapping", "media_capture_enabled", "INTEGER NOT NULL DEFAULT 0");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "http_route_mapping", "path_rewrite_enabled", "INTEGER NOT NULL DEFAULT 0");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "http_route_mapping", "insecure_skip_verify", "INTEGER NOT NULL DEFAULT 0");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "http_route_mapping", "auth_enabled", "INTEGER NOT NULL DEFAULT 0");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "http_route_mapping", "auth_username", "TEXT NOT NULL DEFAULT ''");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "http_route_mapping", "auth_password_hash", "TEXT NOT NULL DEFAULT ''");
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
        rc = add_column_if_missing(db, "specus_client_session", "peer_service_discovery_version", "INTEGER NOT NULL DEFAULT 0");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "specus_client_session", "peer_service_applications", "TEXT");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "specus_client_session", "client_egress_version", "INTEGER NOT NULL DEFAULT 0");
    }
    if (rc == 0) {
        /* Sessions stored before the catalog carried it never declared domain targets. */
        rc = add_column_if_missing(db, "specus_client_session", "client_egress_domain_targets",
                                   "INTEGER NOT NULL DEFAULT 0");
    }
    if (rc == 0) {
        /* Sessions stored before the connectivity check are older clients: their RSTs stay unclassified. */
        rc = add_column_if_missing(db, "specus_client_session", "client_http_route_version",
                                   "INTEGER NOT NULL DEFAULT 0");
    }
    if (rc == 0) {
        /* Policies saved before domain rules grant no name. */
        rc = add_column_if_missing(db, "peer_mesh_egress_policy", "domain_rules",
                                   "TEXT NOT NULL DEFAULT '[]'");
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
        rc = add_column_if_missing(db, "peer_mesh_device", "cidr", "TEXT NOT NULL DEFAULT '100.96.0.0/11'");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "peer_mesh_device", "nat_mapping_behavior", "TEXT");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "peer_mesh_device", "nat_filtering_behavior", "TEXT");
    }
    if (rc == 0) {
        rc = add_column_if_missing(db, "peer_mesh_device", "nat_behavior_discovery", "TEXT");
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
            "CREATE INDEX IF NOT EXISTS idx_user_diagram_owner ON user_diagram_document(tenant_id,owner_username);"
            "CREATE INDEX IF NOT EXISTS idx_user_diagram_updated ON user_diagram_document(updated_at);"
            "CREATE INDEX IF NOT EXISTS idx_registration_challenge_expiry "
            "ON specus_management_registration_challenge(expires_at);"
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
    if (rc == 0) {
        /*
         * Service workbench: one row per (identity, list, reference), nothing but the reference
         * and an epoch-millisecond time. No foreign keys, like every other table: the deletions
         * of routes, mappings, Peer services, clients and accounts remove their rows themselves.
         */
        rc = exec_sql(db,
            "CREATE TABLE IF NOT EXISTS management_workbench_item ("
            "tenant_id TEXT NOT NULL,"
            "username TEXT NOT NULL,"
            "list TEXT NOT NULL,"
            "kind TEXT NOT NULL,"
            "object_id INTEGER NOT NULL,"
            "at_ms INTEGER NOT NULL,"
            "PRIMARY KEY(tenant_id, username, list, kind, object_id)"
            ");"
            "CREATE INDEX IF NOT EXISTS idx_mwi_object ON management_workbench_item(tenant_id, kind, object_id);"
            "CREATE INDEX IF NOT EXISTS idx_mwi_list_at ON management_workbench_item(list, at_ms);");
    }
    if (rc == 0) {
        /*
         * Temporary HTTP shares and the audit of who changed access to a route
         * (protocol/spec/temporary-http-share.md). The names and columns are shared by every
         * server; times are integer epoch seconds and only the token's SHA-256 is stored.
         */
        rc = exec_sql(db,
            "CREATE TABLE IF NOT EXISTS http_share ("
            "share_id VARCHAR(16) PRIMARY KEY,"
            "tenant_id VARCHAR(80) NOT NULL,"
            "route_id BIGINT NOT NULL,"
            "token_sha256 VARCHAR(64) NOT NULL,"
            "access VARCHAR(8) NOT NULL,"
            "path_prefix VARCHAR(256) NOT NULL,"
            "label VARCHAR(255),"
            "created_by VARCHAR(120) NOT NULL,"
            "created_at BIGINT NOT NULL,"
            "expires_at BIGINT NOT NULL,"
            "revoked_at BIGINT,"
            "revoked_by VARCHAR(120),"
            "revoke_reason VARCHAR(40),"
            "expiry_recorded INTEGER NOT NULL DEFAULT 0"
            ");"
            "CREATE INDEX IF NOT EXISTS idx_http_share_route ON http_share(route_id);"
            "CREATE INDEX IF NOT EXISTS idx_http_share_creator ON http_share(tenant_id, created_by);"
            "CREATE INDEX IF NOT EXISTS idx_http_share_expires ON http_share(expires_at);"
            "CREATE TABLE IF NOT EXISTS http_access_audit ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "tenant_id VARCHAR(80) NOT NULL,"
            "occurred_at BIGINT NOT NULL,"
            "actor VARCHAR(120),"
            "action VARCHAR(40) NOT NULL,"
            "route_id BIGINT NOT NULL,"
            "share_id VARCHAR(16),"
            "detail_json VARCHAR(512) NOT NULL"
            ");"
            "CREATE INDEX IF NOT EXISTS idx_http_access_audit_at ON http_access_audit(occurred_at);"
            "CREATE INDEX IF NOT EXISTS idx_http_access_audit_route ON http_access_audit(tenant_id, route_id, id);");
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
    client->peer_service_discovery_version = sqlite3_column_int(stmt, 13);
    if (copy_text_column(stmt, 14, client->peer_service_applications, sizeof(client->peer_service_applications)) != 0
        || copy_text_column(stmt, 15, client->client_version, sizeof(client->client_version)) != 0) {
        return -1;
    }
    client->upload_bytes = sqlite3_column_int64(stmt, 16);
    client->download_bytes = sqlite3_column_int64(stmt, 17);
    client->client_egress_version = sqlite3_column_int(stmt, 18);
    client->client_egress_domain_targets = sqlite3_column_int(stmt, 19) != 0;
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
        || copy_text_column(stmt, 9, link->version, sizeof(link->version)) != 0
        || copy_text_column(stmt, 10, link->sha256, sizeof(link->sha256)) != 0
        || copy_text_column(stmt, 13, link->changelog_url, sizeof(link->changelog_url)) != 0
        || copy_text_column(stmt, 14, link->min_supported_version, sizeof(link->min_supported_version)) != 0
        || copy_text_column(stmt, 16, link->package_path, sizeof(link->package_path)) != 0
        || copy_text_column(stmt, 17, link->package_file_name, sizeof(link->package_file_name)) != 0
        || copy_text_column(stmt, 18, link->created_at, sizeof(link->created_at)) != 0
        || copy_text_column(stmt, 19, link->updated_at, sizeof(link->updated_at)) != 0) {
        return -1;
    }
    link->display_order = sqlite3_column_int(stmt, 7);
    link->enabled = sqlite3_column_int(stmt, 8) != 0;
    link->file_size = sqlite3_column_int64(stmt, 11);
    link->is_latest = sqlite3_column_int(stmt, 12) != 0;
    link->hosted = sqlite3_column_int(stmt, 15) != 0;
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
        || copy_text_column(stmt, 23, session->peer_service_applications, sizeof(session->peer_service_applications)) != 0
        || copy_text_column(stmt, 24, session->http_login_at, sizeof(session->http_login_at)) != 0
        || copy_text_column(stmt, 25, session->netty_connected_at, sizeof(session->netty_connected_at)) != 0
        || copy_text_column(stmt, 26, session->disconnected_at, sizeof(session->disconnected_at)) != 0
        || copy_text_column(stmt, 27, session->expires_at, sizeof(session->expires_at)) != 0
        || copy_text_column(stmt, 28, session->channel_id, sizeof(session->channel_id)) != 0
        || copy_text_column(stmt, 29, session->remote_address, sizeof(session->remote_address)) != 0) {
        return -1;
    }
    session->message_send_capable = sqlite3_column_int(stmt, 17) != 0;
    session->message_receive_capable = sqlite3_column_int(stmt, 18) != 0;
    session->message_attachments_capable = sqlite3_column_int(stmt, 19) != 0;
    session->message_media_preview_capable = sqlite3_column_int(stmt, 20) != 0;
    session->message_max_attachment_bytes = sqlite3_column_int64(stmt, 21);
    session->peer_service_discovery_version = sqlite3_column_int(stmt, 22);
    session->client_egress_version = sqlite3_column_int(stmt, 30);
    session->client_egress_domain_targets = sqlite3_column_int(stmt, 31) != 0;
    session->client_http_route_version = sqlite3_column_int(stmt, 32);
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
        || copy_text_column(stmt, 11, route->auth_username, sizeof(route->auth_username)) != 0
        || copy_text_column(stmt, 12, route->auth_password_hash, sizeof(route->auth_password_hash)) != 0
        || copy_text_column(stmt, 13, route->created_at, sizeof(route->created_at)) != 0
        || copy_text_column(stmt, 14, route->updated_at, sizeof(route->updated_at)) != 0) {
        return -1;
    }
    route->enabled = sqlite3_column_int(stmt, 5) != 0;
    route->detail_capture_enabled = sqlite3_column_int(stmt, 6) != 0;
    route->media_capture_enabled = sqlite3_column_int(stmt, 7) != 0;
    route->path_rewrite_enabled = sqlite3_column_int(stmt, 8) != 0;
    route->insecure_skip_verify = sqlite3_column_int(stmt, 9) != 0;
    route->auth_enabled = sqlite3_column_int(stmt, 10) != 0;
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
        || copy_text_column(stmt, 7, device->cidr, sizeof(device->cidr)) != 0
        || copy_text_column(stmt, 8, device->public_key, sizeof(device->public_key)) != 0
        || copy_text_column(stmt, 9, device->nat_type, sizeof(device->nat_type)) != 0
        || copy_text_column(stmt, 10, device->nat_mapping_behavior, sizeof(device->nat_mapping_behavior)) != 0
        || copy_text_column(stmt, 11, device->nat_filtering_behavior, sizeof(device->nat_filtering_behavior)) != 0
        || copy_text_column(stmt, 12, device->nat_behavior_discovery, sizeof(device->nat_behavior_discovery)) != 0
        || copy_text_column(stmt, 13, device->last_endpoint, sizeof(device->last_endpoint)) != 0
        || copy_text_column(stmt, 14, device->virtual_device_mode, sizeof(device->virtual_device_mode)) != 0
        || copy_text_column(stmt, 15, device->virtual_device_name, sizeof(device->virtual_device_name)) != 0
        || copy_text_column(stmt, 16, device->virtual_device_status, sizeof(device->virtual_device_status)) != 0
        || copy_text_column(stmt, 17, device->virtual_device_error, sizeof(device->virtual_device_error)) != 0
        || copy_text_column(stmt, 18, device->virtual_device_updated_at, sizeof(device->virtual_device_updated_at)) != 0
        || copy_text_column(stmt, 19, device->last_seen_at, sizeof(device->last_seen_at)) != 0
        || copy_text_column(stmt, 20, device->updated_at, sizeof(device->updated_at)) != 0) {
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
        "COALESCE((SELECT message_send_capable FROM specus_client_session s WHERE s.client_id = client_account.rowid AND s.status = 'NETTY_ONLINE' ORDER BY s.id DESC LIMIT 1), 0), "
        "COALESCE((SELECT message_receive_capable FROM specus_client_session s WHERE s.client_id = client_account.rowid AND s.status = 'NETTY_ONLINE' ORDER BY s.id DESC LIMIT 1), 0), "
        "COALESCE((SELECT message_attachments_capable FROM specus_client_session s WHERE s.client_id = client_account.rowid AND s.status = 'NETTY_ONLINE' ORDER BY s.id DESC LIMIT 1), 0), "
        "COALESCE((SELECT message_media_preview_capable FROM specus_client_session s WHERE s.client_id = client_account.rowid AND s.status = 'NETTY_ONLINE' ORDER BY s.id DESC LIMIT 1), 0), "
        "COALESCE((SELECT message_max_attachment_bytes FROM specus_client_session s WHERE s.client_id = client_account.rowid AND s.status = 'NETTY_ONLINE' ORDER BY s.id DESC LIMIT 1), 0), "
        "COALESCE((SELECT peer_service_discovery_version FROM specus_client_session s WHERE s.client_id = client_account.rowid AND s.status = 'NETTY_ONLINE' ORDER BY s.id DESC LIMIT 1), 0), "
        "COALESCE((SELECT peer_service_applications FROM specus_client_session s WHERE s.client_id = client_account.rowid AND s.status = 'NETTY_ONLINE' ORDER BY s.id DESC LIMIT 1), ''), "
        "COALESCE((SELECT client_version FROM specus_client_session s WHERE s.client_id = client_account.rowid AND s.status = 'NETTY_ONLINE' ORDER BY s.id DESC LIMIT 1), ''), "
        "COALESCE((SELECT SUM(upload_bytes) FROM traffic_usage t WHERE t.client_id = client_account.rowid), 0), "
        "COALESCE((SELECT SUM(download_bytes) FROM traffic_usage t WHERE t.client_id = client_account.rowid), 0), "
        "COALESCE((SELECT client_egress_version FROM specus_client_session s WHERE s.client_id = client_account.rowid AND s.status = 'NETTY_ONLINE' ORDER BY s.id DESC LIMIT 1), 0), "
        "COALESCE((SELECT client_egress_domain_targets FROM specus_client_session s WHERE s.client_id = client_account.rowid AND s.status = 'NETTY_ONLINE' ORDER BY s.id DESC LIMIT 1), 0) "
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
        "COALESCE((SELECT message_send_capable FROM specus_client_session s WHERE s.client_id = client_account.rowid AND s.status = 'NETTY_ONLINE' ORDER BY s.id DESC LIMIT 1), 0), "
        "COALESCE((SELECT message_receive_capable FROM specus_client_session s WHERE s.client_id = client_account.rowid AND s.status = 'NETTY_ONLINE' ORDER BY s.id DESC LIMIT 1), 0), "
        "COALESCE((SELECT message_attachments_capable FROM specus_client_session s WHERE s.client_id = client_account.rowid AND s.status = 'NETTY_ONLINE' ORDER BY s.id DESC LIMIT 1), 0), "
        "COALESCE((SELECT message_media_preview_capable FROM specus_client_session s WHERE s.client_id = client_account.rowid AND s.status = 'NETTY_ONLINE' ORDER BY s.id DESC LIMIT 1), 0), "
        "COALESCE((SELECT message_max_attachment_bytes FROM specus_client_session s WHERE s.client_id = client_account.rowid AND s.status = 'NETTY_ONLINE' ORDER BY s.id DESC LIMIT 1), 0), "
        "COALESCE((SELECT peer_service_discovery_version FROM specus_client_session s WHERE s.client_id = client_account.rowid AND s.status = 'NETTY_ONLINE' ORDER BY s.id DESC LIMIT 1), 0), "
        "COALESCE((SELECT peer_service_applications FROM specus_client_session s WHERE s.client_id = client_account.rowid AND s.status = 'NETTY_ONLINE' ORDER BY s.id DESC LIMIT 1), ''), "
        "COALESCE((SELECT client_version FROM specus_client_session s WHERE s.client_id = client_account.rowid AND s.status = 'NETTY_ONLINE' ORDER BY s.id DESC LIMIT 1), ''), "
        "COALESCE((SELECT SUM(upload_bytes) FROM traffic_usage t WHERE t.client_id = client_account.rowid), 0), "
        "COALESCE((SELECT SUM(download_bytes) FROM traffic_usage t WHERE t.client_id = client_account.rowid), 0), "
        "COALESCE((SELECT client_egress_version FROM specus_client_session s WHERE s.client_id = client_account.rowid AND s.status = 'NETTY_ONLINE' ORDER BY s.id DESC LIMIT 1), 0), "
        "COALESCE((SELECT client_egress_domain_targets FROM specus_client_session s WHERE s.client_id = client_account.rowid AND s.status = 'NETTY_ONLINE' ORDER BY s.id DESC LIMIT 1), 0) "
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
        "COALESCE((SELECT message_send_capable FROM specus_client_session s WHERE s.client_id = client_account.rowid AND s.status = 'NETTY_ONLINE' ORDER BY s.id DESC LIMIT 1), 0), "
        "COALESCE((SELECT message_receive_capable FROM specus_client_session s WHERE s.client_id = client_account.rowid AND s.status = 'NETTY_ONLINE' ORDER BY s.id DESC LIMIT 1), 0), "
        "COALESCE((SELECT message_attachments_capable FROM specus_client_session s WHERE s.client_id = client_account.rowid AND s.status = 'NETTY_ONLINE' ORDER BY s.id DESC LIMIT 1), 0), "
        "COALESCE((SELECT message_media_preview_capable FROM specus_client_session s WHERE s.client_id = client_account.rowid AND s.status = 'NETTY_ONLINE' ORDER BY s.id DESC LIMIT 1), 0), "
        "COALESCE((SELECT message_max_attachment_bytes FROM specus_client_session s WHERE s.client_id = client_account.rowid AND s.status = 'NETTY_ONLINE' ORDER BY s.id DESC LIMIT 1), 0), "
        "COALESCE((SELECT peer_service_discovery_version FROM specus_client_session s WHERE s.client_id = client_account.rowid AND s.status = 'NETTY_ONLINE' ORDER BY s.id DESC LIMIT 1), 0), "
        "COALESCE((SELECT peer_service_applications FROM specus_client_session s WHERE s.client_id = client_account.rowid AND s.status = 'NETTY_ONLINE' ORDER BY s.id DESC LIMIT 1), ''), "
        "COALESCE((SELECT client_version FROM specus_client_session s WHERE s.client_id = client_account.rowid AND s.status = 'NETTY_ONLINE' ORDER BY s.id DESC LIMIT 1), ''), "
        "COALESCE((SELECT SUM(upload_bytes) FROM traffic_usage t WHERE t.client_id = client_account.rowid), 0), "
        "COALESCE((SELECT SUM(download_bytes) FROM traffic_usage t WHERE t.client_id = client_account.rowid), 0), "
        "COALESCE((SELECT client_egress_version FROM specus_client_session s WHERE s.client_id = client_account.rowid AND s.status = 'NETTY_ONLINE' ORDER BY s.id DESC LIMIT 1), 0), "
        "COALESCE((SELECT client_egress_domain_targets FROM specus_client_session s WHERE s.client_id = client_account.rowid AND s.status = 'NETTY_ONLINE' ORDER BY s.id DESC LIMIT 1), 0) "
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

int st_storage_client_has_online_receive_capability(const char *path,
                                                    long long client_id,
                                                    int *capable)
{
    if (client_id <= 0 || capable == NULL) {
        return -1;
    }
    *capable = 0;
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(
        db,
        "SELECT EXISTS(SELECT 1 FROM specus_client_session "
        "WHERE client_id = ? AND status = 'NETTY_ONLINE' AND message_receive_capable = 1)",
        -1,
        &stmt,
        NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, client_id);
        rc = sqlite3_step(stmt);
        if (rc == SQLITE_ROW) {
            *capable = sqlite3_column_int(stmt, 0) != 0;
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == SQLITE_ROW ? 0 : -1;
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
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT username, tenant_id, password_hash, role, enabled, created_at, updated_at "
        "FROM specus_management_user WHERE tenant_id = ? ORDER BY lower(username)",
        -1,
        &stmt,
        NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
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

int st_storage_get_management_user_in_tenant(const char *path,
                                             const char *tenant_id,
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
        "FROM specus_management_user WHERE tenant_id = ? AND lower(username) = lower(?)",
        -1,
        &stmt,
        NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, username, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);
    int ok = rc == SQLITE_ROW && scan_management_user(stmt, user) == 0;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return ok ? 0 : -1;
}

int st_storage_find_management_user(const char *path,
                                    const char *username,
                                    st_storage_management_user *user)
{
    /* Read-only: a lookup on every authenticated request must never create or migrate the file. */
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_busy_timeout(db, 5000);
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
    int result = rc == SQLITE_ROW ? (scan_management_user(stmt, user) == 0 ? 0 : -1)
        : rc == SQLITE_DONE ? 1 : -1;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return result;
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

static int update_management_user_on_db(sqlite3 *db,
                                        const char *tenant_id,
                                        const char *username,
                                        const char *password_hash,
                                        const char *role,
                                        int enabled)
{
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "UPDATE specus_management_user SET "
        "password_hash = COALESCE(?, password_hash), "
        "role = COALESCE(?, role), "
        "enabled = ?, updated_at = CURRENT_TIMESTAMP "
        "WHERE tenant_id = ? AND lower(username) = lower(?)",
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
        sqlite3_bind_text(stmt, 4, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, username, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db) == 1 ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    return rc;
}

int st_storage_update_management_user(const char *path,
                                      const char *tenant_id,
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
    int rc = update_management_user_on_db(db, tenant_id, username, password_hash, role, enabled);
    sqlite3_close(db);
    if (rc != 0) {
        return -1;
    }
    return out_user == NULL ? 0 : st_storage_get_management_user_in_tenant(path, tenant_id, username, out_user);
}

static int delete_management_user_on_db(sqlite3 *db, const char *tenant_id, const char *username)
{
    /*
     * The account's workbench rows go in the caller's transaction: favourites and recent opens are
     * personal history, and an account created later under the same name must start empty.
     */
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "DELETE FROM management_workbench_item WHERE (tenant_id, username) IN ("
        "SELECT tenant_id, username FROM specus_management_user "
        "WHERE tenant_id = ? AND lower(username) = lower(?))",
        -1,
        &stmt,
        NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, username, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    stmt = NULL;
    if (rc == 0) {
        rc = sqlite3_prepare_v2(db,
            "DELETE FROM specus_management_user WHERE tenant_id = ? AND lower(username) = lower(?)",
            -1,
            &stmt,
            NULL);
        if (rc == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, username, -1, SQLITE_TRANSIENT);
            rc = sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db) == 1 ? 0 : -1;
        } else {
            rc = -1;
        }
        sqlite3_finalize(stmt);
    }
    return rc;
}

int st_storage_delete_management_user(const char *path, const char *tenant_id, const char *username)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    if (exec_sql(db, "BEGIN IMMEDIATE") != 0) {
        sqlite3_close(db);
        return -1;
    }
    int rc = delete_management_user_on_db(db, tenant_id, username);
    if (rc == 0) {
        rc = exec_sql(db, "COMMIT");
    } else {
        (void)exec_sql(db, "ROLLBACK");
    }
    sqlite3_close(db);
    return rc == 0 ? 0 : -1;
}

static int scan_registration_challenge(sqlite3_stmt *stmt,
                                       st_storage_registration_challenge *challenge)
{
    memset(challenge, 0, sizeof(*challenge));
    return copy_text_column(stmt, 0, challenge->registration_id, sizeof(challenge->registration_id))
        || copy_text_column(stmt, 1, challenge->username, sizeof(challenge->username))
        || copy_text_column(stmt, 2, challenge->email, sizeof(challenge->email))
        || copy_text_column(stmt, 3, challenge->password_hash, sizeof(challenge->password_hash))
        || copy_text_column(stmt, 4, challenge->code_hash, sizeof(challenge->code_hash))
        || ((challenge->attempts_remaining = sqlite3_column_int(stmt, 5)), 0)
        || copy_text_column(stmt, 6, challenge->expires_at, sizeof(challenge->expires_at))
        || copy_text_column(stmt, 7, challenge->resend_available_at, sizeof(challenge->resend_available_at))
        || copy_text_column(stmt, 8, challenge->created_at, sizeof(challenge->created_at))
        || copy_text_column(stmt, 9, challenge->updated_at, sizeof(challenge->updated_at));
}

int st_storage_management_email_exists(const char *path, const char *email)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) return -1;
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT 1 FROM specus_management_user_email WHERE email = ? COLLATE NOCASE LIMIT 1",
        -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, email, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt);
    }
    int result = rc == SQLITE_ROW ? 1 : (rc == SQLITE_DONE ? 0 : -1);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return result;
}

static int get_registration_challenge_with_sql(const char *path,
                                               const char *sql,
                                               const char *first,
                                               const char *second,
                                               st_storage_registration_challenge *challenge)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) return -1;
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, first, -1, SQLITE_TRANSIENT);
        if (second != NULL) sqlite3_bind_text(stmt, 2, second, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt);
    }
    int result = rc == SQLITE_ROW && scan_registration_challenge(stmt, challenge) == 0 ? 0 : -1;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return result;
}

int st_storage_get_registration_challenge(const char *path,
                                          const char *registration_id,
                                          st_storage_registration_challenge *challenge)
{
    return get_registration_challenge_with_sql(path,
        "SELECT registration_id,username,email,password_hash,code_hash,attempts_remaining,"
        "expires_at,resend_available_at,created_at,updated_at "
        "FROM specus_management_registration_challenge WHERE registration_id = ?",
        registration_id, NULL, challenge);
}

int st_storage_find_registration_challenge(const char *path,
                                           const char *username,
                                           const char *email,
                                           st_storage_registration_challenge *challenge)
{
    return get_registration_challenge_with_sql(path,
        "SELECT registration_id,username,email,password_hash,code_hash,attempts_remaining,"
        "expires_at,resend_available_at,created_at,updated_at "
        "FROM specus_management_registration_challenge "
        "WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE LIMIT 1",
        username, email, challenge);
}

int st_storage_create_registration_challenge(const char *path,
                                             const st_storage_registration_challenge *challenge)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) return -1;
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT INTO specus_management_registration_challenge("
        "registration_id,username,email,password_hash,code_hash,attempts_remaining,"
        "expires_at,resend_available_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
        -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, challenge->registration_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, challenge->username, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, challenge->email, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, challenge->password_hash, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, challenge->code_hash, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 6, challenge->attempts_remaining);
        sqlite3_bind_text(stmt, 7, challenge->expires_at, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 8, challenge->resend_available_at, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 9, challenge->created_at, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 10, challenge->updated_at, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    } else rc = -1;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc;
}

int st_storage_update_registration_attempts(const char *path,
                                            const char *registration_id,
                                            int attempts_remaining,
                                            const char *updated_at)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) return -1;
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "UPDATE specus_management_registration_challenge SET attempts_remaining=?,updated_at=? "
        "WHERE registration_id=?", -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, attempts_remaining);
        sqlite3_bind_text(stmt, 2, updated_at, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, registration_id, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db) == 1 ? 0 : -1;
    } else rc = -1;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc;
}

int st_storage_delete_registration_challenge(const char *path, const char *registration_id)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) return -1;
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "DELETE FROM specus_management_registration_challenge WHERE registration_id=?",
        -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, registration_id, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    } else rc = -1;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc;
}

int st_storage_delete_expired_registration_challenges(const char *path, const char *expires_before)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) return -1;
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "DELETE FROM specus_management_registration_challenge WHERE expires_at < ?",
        -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, expires_before, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    } else rc = -1;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc;
}

int st_storage_complete_registration(const char *path,
                                     const st_storage_registration_challenge *challenge,
                                     const char *tenant_id,
                                     st_storage_management_user *out_user)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0 || exec_sql(db, "BEGIN IMMEDIATE") != 0) {
        if (db != NULL) sqlite3_close(db);
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT INTO specus_management_user(username,tenant_id,password_hash,role,enabled,created_at,updated_at) "
        "VALUES(?,?,?,'USER',1,?,?)", -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, challenge->username, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, challenge->password_hash, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, challenge->updated_at, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, challenge->updated_at, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    } else rc = -1;
    sqlite3_finalize(stmt);
    if (rc == 0) rc = sqlite3_prepare_v2(db,
        "INSERT INTO specus_management_user_email(username,email,verified_at,created_at,updated_at) "
        "VALUES(?,?,?,?,?)", -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, challenge->username, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, challenge->email, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, challenge->updated_at, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, challenge->updated_at, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, challenge->updated_at, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    } else if (rc != 0) rc = -1;
    sqlite3_finalize(stmt);
    if (rc == 0) rc = sqlite3_prepare_v2(db,
        "DELETE FROM specus_management_registration_challenge "
        "WHERE registration_id=? AND code_hash=?", -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, challenge->registration_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, challenge->code_hash, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db) == 1 ? 0 : -1;
    } else if (rc != 0) rc = -1;
    sqlite3_finalize(stmt);
    if (rc == 0) rc = exec_sql(db, "COMMIT"); else (void)exec_sql(db, "ROLLBACK");
    sqlite3_close(db);
    if (rc != 0) return -1;
    return out_user == NULL ? 0 : st_storage_get_management_user(path, challenge->username, out_user);
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
        "display_order, enabled, version, sha256, file_size, is_latest, changelog_url, "
        "min_supported_version, hosted, package_path, package_file_name, created_at, updated_at "
        "FROM client_download_link ORDER BY display_order ASC, id ASC";
    const char *sql_public =
        "SELECT id, implementation, platform, arch, display_name, download_url, description, "
        "display_order, enabled, version, sha256, file_size, is_latest, changelog_url, "
        "min_supported_version, hosted, package_path, package_file_name, created_at, updated_at "
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
        "display_order, enabled, version, sha256, file_size, is_latest, changelog_url, "
        "min_supported_version, hosted, package_path, package_file_name, created_at, updated_at "
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
    st_storage_client_download_link existing;
    memset(&existing, 0, sizeof(existing));
    if (id > 0) (void)st_storage_get_client_download_link(path, id, &existing);
    return st_storage_upsert_client_download_link_extended(path, id, implementation, platform, arch,
        display_name, download_url, description, display_order, enabled, existing.version,
        existing.sha256, existing.file_size, existing.is_latest, existing.changelog_url,
        existing.min_supported_version, existing.hosted, existing.package_path,
        existing.package_file_name, out_link);
}

int st_storage_upsert_client_download_link_extended(const char *path,
                                                    long long id,
                                                    const char *implementation,
                                                    const char *platform,
                                                    const char *arch,
                                                    const char *display_name,
                                                    const char *download_url,
                                                    const char *description,
                                                    int display_order,
                                                    int enabled,
                                                    const char *version,
                                                    const char *sha256,
                                                    long long file_size,
                                                    int is_latest,
                                                    const char *changelog_url,
                                                    const char *min_supported_version,
                                                    int hosted,
                                                    const char *package_path,
                                                    const char *package_file_name,
                                                    st_storage_client_download_link *out_link)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    if (exec_sql(db, "BEGIN IMMEDIATE") != 0) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    const char *sql_insert =
        "INSERT INTO client_download_link(implementation, platform, arch, display_name, download_url, "
        "description, display_order, enabled, version, sha256, file_size, is_latest, changelog_url, "
        "min_supported_version, hosted, package_path, package_file_name, created_at, updated_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)";
    const char *sql_update =
        "UPDATE client_download_link SET implementation = ?, platform = ?, arch = ?, display_name = ?, "
        "download_url = ?, description = ?, display_order = ?, enabled = ?, version = ?, sha256 = ?, "
        "file_size = ?, is_latest = ?, changelog_url = ?, min_supported_version = ?, hosted = ?, "
        "package_path = ?, package_file_name = ?, updated_at = CURRENT_TIMESTAMP "
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
        bind_nullable_text_limit(stmt, 9, version, 80);
        bind_nullable_text_limit(stmt, 10, sha256, 64);
        sqlite3_bind_int64(stmt, 11, file_size < 0 ? 0 : file_size);
        sqlite3_bind_int(stmt, 12, is_latest ? 1 : 0);
        bind_nullable_text_limit(stmt, 13, changelog_url, 1024);
        bind_nullable_text_limit(stmt, 14, min_supported_version, 80);
        sqlite3_bind_int(stmt, 15, hosted ? 1 : 0);
        bind_nullable_text_limit(stmt, 16, package_path, 1024);
        bind_nullable_text_limit(stmt, 17, package_file_name, 255);
        if (id > 0) {
            sqlite3_bind_int64(stmt, 18, id);
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
    if (rc == 0 && is_latest) {
        rc = sqlite3_prepare_v2(db,
            "UPDATE client_download_link SET is_latest = 0, updated_at = CURRENT_TIMESTAMP "
            "WHERE implementation = ? AND platform = ? AND arch = ? AND id <> ?",
            -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, implementation, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, platform, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 3, arch, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(stmt, 4, written_id);
            rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
        } else {
            rc = -1;
        }
        sqlite3_finalize(stmt);
    }
    if (rc == 0) rc = exec_sql(db, "COMMIT");
    else (void)exec_sql(db, "ROLLBACK");
    sqlite3_close(db);
    if (rc != 0) {
        return -1;
    }
    return out_link == NULL ? 0 : st_storage_get_client_download_link(path, written_id, out_link);
}

int st_storage_mark_client_download_latest(const char *path,
                                           long long id,
                                           st_storage_client_download_link *out_link)
{
    st_storage_client_download_link link;
    if (st_storage_get_client_download_link(path, id, &link) != 0) return -1;
    return st_storage_upsert_client_download_link_extended(path, id, link.implementation,
        link.platform, link.arch, link.display_name, link.download_url, link.description,
        link.display_order, link.enabled, link.version, link.sha256, link.file_size, 1,
        link.changelog_url, link.min_supported_version, link.hosted, link.package_path,
        link.package_file_name, out_link);
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

static int scan_user_diagram(sqlite3_stmt *stmt,
                             st_storage_user_diagram *diagram,
                             int include_snapshot)
{
    memset(diagram, 0, sizeof(*diagram));
    diagram->id = sqlite3_column_int64(stmt, 0);
    if (copy_text_column(stmt, 1, diagram->tenant_id, sizeof(diagram->tenant_id)) != 0
        || copy_text_column(stmt, 2, diagram->owner_username, sizeof(diagram->owner_username)) != 0
        || copy_text_column(stmt, 3, diagram->name, sizeof(diagram->name)) != 0
        || copy_text_column(stmt, include_snapshot ? 7 : 6, diagram->created_at,
                            sizeof(diagram->created_at)) != 0
        || copy_text_column(stmt, include_snapshot ? 8 : 7, diagram->updated_at,
                            sizeof(diagram->updated_at)) != 0) return -1;
    if (include_snapshot) {
        const void *blob = sqlite3_column_blob(stmt, 4);
        int bytes = sqlite3_column_bytes(stmt, 4);
        if (blob == NULL || bytes <= 0) return -1;
        diagram->snapshot_data = (uint8_t *)malloc((size_t)bytes);
        if (diagram->snapshot_data == NULL) return -1;
        memcpy(diagram->snapshot_data, blob, (size_t)bytes);
        diagram->snapshot_len = (size_t)bytes;
        diagram->size_bytes = sqlite3_column_int64(stmt, 5);
        diagram->revision = sqlite3_column_int64(stmt, 6);
    } else {
        diagram->size_bytes = sqlite3_column_int64(stmt, 4);
        diagram->revision = sqlite3_column_int64(stmt, 5);
    }
    return 0;
}

int st_storage_list_user_diagrams(const char *path,
                                  const char *tenant_id,
                                  const char *owner_username,
                                  st_storage_user_diagram *items,
                                  size_t capacity,
                                  size_t *out_count)
{
    if (items == NULL || out_count == NULL) return -1;
    *out_count = 0U;
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) return -1;
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT id,tenant_id,owner_username,name,size_bytes,revision,created_at,updated_at "
        "FROM user_diagram_document WHERE tenant_id=? AND owner_username=? "
        "ORDER BY updated_at DESC,id DESC", -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, owner_username, -1, SQLITE_TRANSIENT);
        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW && *out_count < capacity) {
            if (scan_user_diagram(stmt, &items[*out_count], 0) != 0) {
                rc = SQLITE_ERROR;
                break;
            }
            ++(*out_count);
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == SQLITE_DONE || (*out_count == capacity && capacity > 0U) ? 0 : -1;
}

int st_storage_get_user_diagram(const char *path,
                                long long id,
                                const char *tenant_id,
                                const char *owner_username,
                                st_storage_user_diagram *out)
{
    sqlite3 *db = NULL;
    if (out == NULL || open_db(path, &db) != 0) return -1;
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT id,tenant_id,owner_username,name,snapshot_data,size_bytes,revision,created_at,updated_at "
        "FROM user_diagram_document WHERE id=? AND tenant_id=? AND owner_username=?",
        -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, id);
        sqlite3_bind_text(stmt, 2, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, owner_username, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt);
    }
    int ok = rc == SQLITE_ROW && scan_user_diagram(stmt, out, 1) == 0;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return ok ? 0 : -1;
}

int st_storage_create_user_diagram(const char *path,
                                   const char *tenant_id,
                                   const char *owner_username,
                                   const char *name,
                                   const uint8_t *snapshot,
                                   size_t snapshot_len,
                                   st_storage_user_diagram *out)
{
    if (snapshot == NULL || snapshot_len == 0U || snapshot_len > (size_t)INT_MAX) return -1;
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0 || exec_sql(db, "BEGIN IMMEDIATE") != 0) {
        if (db != NULL) sqlite3_close(db);
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT COUNT(*) FROM user_diagram_document WHERE tenant_id=? AND owner_username=?",
        -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, owner_username, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt);
    }
    long long count = rc == SQLITE_ROW ? sqlite3_column_int64(stmt, 0) : 100;
    sqlite3_finalize(stmt);
    if (count >= 100) {
        (void)exec_sql(db, "ROLLBACK");
        sqlite3_close(db);
        return 1;
    }
    rc = sqlite3_prepare_v2(db,
        "INSERT INTO user_diagram_document(tenant_id,owner_username,name,snapshot_data,size_bytes,"
        "revision,created_at,updated_at) VALUES(?,?,?,?,?,0,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)",
        -1, &stmt, NULL);
    long long id = 0;
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, owner_username, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_blob(stmt, 4, snapshot, (int)snapshot_len, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 5, (long long)snapshot_len);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
        if (rc == 0) id = sqlite3_last_insert_rowid(db);
    } else rc = -1;
    sqlite3_finalize(stmt);
    if (rc == 0) rc = exec_sql(db, "COMMIT"); else (void)exec_sql(db, "ROLLBACK");
    sqlite3_close(db);
    if (rc != 0) return -1;
    return out == NULL ? 0 : st_storage_get_user_diagram(path, id, tenant_id, owner_username, out);
}

int st_storage_update_user_diagram(const char *path,
                                   long long id,
                                   const char *tenant_id,
                                   const char *owner_username,
                                   long long expected_revision,
                                   const char *name,
                                   const uint8_t *snapshot,
                                   size_t snapshot_len,
                                   st_storage_user_diagram *out)
{
    if (snapshot == NULL || snapshot_len == 0U || snapshot_len > (size_t)INT_MAX) return -1;
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) return -1;
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "UPDATE user_diagram_document SET name=?,snapshot_data=?,size_bytes=?,revision=revision+1,"
        "updated_at=CURRENT_TIMESTAMP WHERE id=? AND tenant_id=? AND owner_username=? AND revision=?",
        -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_blob(stmt, 2, snapshot, (int)snapshot_len, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 3, (long long)snapshot_len);
        sqlite3_bind_int64(stmt, 4, id);
        sqlite3_bind_text(stmt, 5, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 6, owner_username, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 7, expected_revision);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
        if (rc == 0 && sqlite3_changes(db) != 1) rc = 1;
    } else rc = -1;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    if (rc != 0) return rc;
    return out == NULL ? 0 : st_storage_get_user_diagram(path, id, tenant_id, owner_username, out);
}

int st_storage_delete_user_diagram(const char *path,
                                   long long id,
                                   const char *tenant_id,
                                   const char *owner_username)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) return -1;
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "DELETE FROM user_diagram_document WHERE id=? AND tenant_id=? AND owner_username=?",
        -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, id);
        sqlite3_bind_text(stmt, 2, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, owner_username, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db) == 1 ? 0 : -1;
    } else rc = -1;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc;
}

void st_storage_user_diagram_free(st_storage_user_diagram *diagram)
{
    if (diagram == NULL) return;
    free(diagram->snapshot_data);
    diagram->snapshot_data = NULL;
    diagram->snapshot_len = 0U;
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
    for (unsigned int i = 1U; i < 1000U; ++i) {
        if (i == 1U) {
            snprintf(out, out_len, "%s", base);
        } else {
            snprintf(out, out_len, "%.112s-%u", base, i);
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
        "message_media_preview_capable, message_max_attachment_bytes, peer_service_discovery_version, "
        "peer_service_applications, http_login_at, netty_connected_at, "
        "disconnected_at, expires_at, channel_id, remote_address, client_egress_version, "
        "client_egress_domain_targets, client_http_route_version "
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
        "message_max_attachment_bytes, peer_service_discovery_version, peer_service_applications, "
        "http_login_at, expires_at, client_egress_version, client_egress_domain_targets, client_http_route_version) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
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
        sqlite3_bind_int(stmt, 22, session->peer_service_discovery_version);
        bind_nullable_text_limit(stmt, 23, session->peer_service_applications, 127);
        sqlite3_bind_text(stmt, 24, session->http_login_at, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 25, session->expires_at, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 26, session->client_egress_version);
        sqlite3_bind_int(stmt, 27, session->client_egress_domain_targets ? 1 : 0);
        sqlite3_bind_int(stmt, 28, session->client_http_route_version < 0 ? 0 : session->client_http_route_version);
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
        "message_media_preview_capable, message_max_attachment_bytes, peer_service_discovery_version, "
        "peer_service_applications, http_login_at, netty_connected_at, "
        "disconnected_at, expires_at, channel_id, remote_address, client_egress_version, "
        "client_egress_domain_targets, client_http_route_version "
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
    int result = rc == SQLITE_ROW
        ? (scan_client_session(stmt, session) == 0 ? 0 : -1)
        : (rc == SQLITE_DONE ? 1 : -1);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return result;
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

int st_storage_client_session_superseded(const char *path,
                                         long long credential_id,
                                         const char *machine_fingerprint,
                                         const char *os_user,
                                         long long session_id,
                                         int *superseded)
{
    /* Session ids are AUTOINCREMENT, so a larger id for the same machine user is a later HTTP login. */
    int newer = 0;
    int rc = count_online_client_sessions(path,
        "SELECT COUNT(*) FROM specus_client_session "
        "WHERE credential_id = ? AND machine_fingerprint = ? AND os_user = ? AND id > ?",
        credential_id,
        machine_fingerprint == NULL ? "" : machine_fingerprint,
        os_user == NULL ? "" : os_user,
        session_id,
        &newer);
    *superseded = rc == 0 && newer > 0;
    return rc;
}

int st_storage_list_online_session_ids_by_credential(const char *path,
                                                     long long credential_id,
                                                     long long *ids,
                                                     size_t max_ids,
                                                     size_t *id_count)
{
    *id_count = 0U;
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT id FROM specus_client_session WHERE credential_id = ? AND status = 'NETTY_ONLINE' "
        "ORDER BY id",
        -1,
        &stmt,
        NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, credential_id);
        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
            if (*id_count < max_ids) {
                ids[(*id_count)++] = sqlite3_column_int64(stmt, 0);
            }
        }
        rc = rc == SQLITE_DONE ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == 0 ? 0 : -1;
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

/* Updates client rowid id; previous_name (NULL when unknown) moves its mappings and routes along. */
static int update_client_on_db(sqlite3 *db,
                               long long id,
                               const char *previous_name,
                               const char *tenant_id,
                               const char *client_name,
                               const char *owner_username,
                               int enabled,
                               int connection_rate_limit_per_minute)
{
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
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
    if (rc == 0 && previous_name != NULL && strcmp(previous_name, client_name) != 0) {
        rc = sqlite3_prepare_v2(db,
            "UPDATE specus_mapping SET client_name = ?, updated_at = CURRENT_TIMESTAMP WHERE client_name = ?",
            -1,
            &stmt,
            NULL);
        if (rc == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, client_name, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, previous_name, -1, SQLITE_TRANSIENT);
            rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
        } else {
            rc = -1;
        }
        sqlite3_finalize(stmt);
    }
    if (rc == 0 && previous_name != NULL && strcmp(previous_name, client_name) != 0) {
        rc = sqlite3_prepare_v2(db,
            "UPDATE http_route_mapping SET client_name = ?, updated_at = CURRENT_TIMESTAMP WHERE client_name = ?",
            -1,
            &stmt,
            NULL);
        if (rc == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, client_name, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, previous_name, -1, SQLITE_TRANSIENT);
            rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
        } else {
            rc = -1;
        }
        sqlite3_finalize(stmt);
    }
    return rc;
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
    int rc;
    if (id > 0) {
        rc = update_client_on_db(db, id, has_existing ? existing.client_name : NULL, tenant_id, client_name,
                                 owner_username, enabled, connection_rate_limit_per_minute);
    } else {
        sqlite3_stmt *stmt = NULL;
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

/* Deletes the client with its mappings and HTTP routes. */
static int delete_client_on_db(sqlite3 *db, long long id, const char *client_name)
{
    /*
     * Workbench references to everything the client carries go first, in the caller's transaction:
     * its routes and mappings below, and its Peer services, whose rows this deletion leaves in
     * place but which no longer resolve to a client.
     */
    static const char *const workbench_refs_sql[] = {
        "DELETE FROM management_workbench_item WHERE kind = 'http-route' AND object_id IN ("
        "SELECT id FROM http_route_mapping WHERE client_name = ?)",
        "DELETE FROM management_workbench_item WHERE kind = 'tcp-mapping' AND object_id IN ("
        "SELECT id FROM specus_mapping WHERE client_name = ?)",
        "DELETE FROM management_workbench_item WHERE kind = 'peer-service' AND object_id IN ("
        "SELECT id FROM peer_mesh_shared_service WHERE client_id = ?)"
    };
    sqlite3_stmt *stmt = NULL;
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < sizeof(workbench_refs_sql) / sizeof(workbench_refs_sql[0]); ++i) {
        if (sqlite3_prepare_v2(db, workbench_refs_sql[i], -1, &stmt, NULL) != SQLITE_OK) {
            rc = -1;
        } else {
            if (i < 2U) {
                sqlite3_bind_text(stmt, 1, client_name, -1, SQLITE_TRANSIENT);
            } else {
                sqlite3_bind_int64(stmt, 1, id);
            }
            rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
        }
        sqlite3_finalize(stmt);
        stmt = NULL;
    }
    if (rc == 0) {
        rc = sqlite3_prepare_v2(db, "DELETE FROM specus_mapping WHERE client_name = ?", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, client_name, -1, SQLITE_TRANSIENT);
            rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
        } else {
            rc = -1;
        }
        sqlite3_finalize(stmt);
    }
    if (rc == 0) {
        rc = sqlite3_prepare_v2(db, "DELETE FROM http_route_mapping WHERE client_name = ?", -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, client_name, -1, SQLITE_TRANSIENT);
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
    return rc;
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
    if (exec_sql(db, "BEGIN IMMEDIATE") != 0) {
        sqlite3_close(db);
        return -1;
    }
    int rc = delete_client_on_db(db, id, client.client_name);
    if (rc == 0) {
        rc = exec_sql(db, "COMMIT");
    } else {
        (void)exec_sql(db, "ROLLBACK");
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

/* Deletes one route or mapping by id together with every workbench reference to it. */
static int delete_object_by_id_with_workbench_refs(const char *path,
                                                   const char *delete_sql,
                                                   const char *workbench_kind,
                                                   long long id)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    if (exec_sql(db, "BEGIN IMMEDIATE") != 0) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, delete_sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, id);
        rc = sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db) == 1 ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    if (rc == 0) {
        rc = workbench_delete_object_refs(db, workbench_kind, id);
    }
    if (rc == 0) {
        rc = exec_sql(db, "COMMIT");
    } else {
        (void)exec_sql(db, "ROLLBACK");
    }
    sqlite3_close(db);
    return rc == 0 ? 0 : -1;
}

int st_storage_delete_mapping_by_id(const char *path, long long id)
{
    return delete_object_by_id_with_workbench_refs(path,
                                                   "DELETE FROM specus_mapping WHERE id = ?",
                                                   "tcp-mapping",
                                                   id);
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
        "r.enabled, r.detail_capture_enabled, r.media_capture_enabled, r.path_rewrite_enabled, r.insecure_skip_verify, r.auth_enabled, "
        "r.auth_username, r.auth_password_hash, r.created_at, r.updated_at "
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
        "r.enabled, r.detail_capture_enabled, r.media_capture_enabled, r.path_rewrite_enabled, r.insecure_skip_verify, r.auth_enabled, "
        "r.auth_username, r.auth_password_hash, r.created_at, r.updated_at "
        "FROM http_route_mapping r JOIN client_account c ON c.client_name = r.client_name "
        "ORDER BY r.id DESC";
    const char *sql_filtered =
        "SELECT r.id, c.rowid, r.client_name, r.route, r.target_base_url, "
        "r.enabled, r.detail_capture_enabled, r.media_capture_enabled, r.path_rewrite_enabled, r.insecure_skip_verify, r.auth_enabled, "
        "r.auth_username, r.auth_password_hash, r.created_at, r.updated_at "
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

/* Returns -1 when the row could not be read, otherwise 0 with *found telling whether it exists. */
static int find_http_route_by_id(const char *path, long long id, st_storage_http_route *route, int *found)
{
    *found = 0;
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT r.id, c.rowid, r.client_name, r.route, r.target_base_url, "
        "r.enabled, r.detail_capture_enabled, r.media_capture_enabled, r.path_rewrite_enabled, r.insecure_skip_verify, r.auth_enabled, "
        "r.auth_username, r.auth_password_hash, r.created_at, r.updated_at "
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
    int result = 0;
    if (rc == SQLITE_ROW) {
        result = scan_http_route(stmt, route) == 0 ? 0 : -1;
        *found = result == 0;
    } else if (rc != SQLITE_DONE) {
        result = -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return result;
}

static int load_http_route_by_id(const char *path, long long id, st_storage_http_route *route)
{
    int found = 0;
    return find_http_route_by_id(path, id, route, &found) == 0 && found ? 0 : -1;
}

int st_storage_find_http_route_by_id(const char *path, long long id, st_storage_http_route *route, int *found)
{
    if (route == NULL || found == NULL) {
        return -1;
    }
    return find_http_route_by_id(path, id, route, found);
}

int st_storage_get_http_route(const char *path, long long id, st_storage_http_route *route)
{
    return load_http_route_by_id(path, id, route);
}

int st_storage_find_http_route_by_client_route(const char *path,
                                               const char *client_name,
                                               const char *route_name,
                                               st_storage_http_route *route,
                                               int *found)
{
    if (route == NULL || found == NULL) {
        return -1;
    }
    *found = 0;
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT r.id, c.rowid, r.client_name, r.route, r.target_base_url, "
        "r.enabled, r.detail_capture_enabled, r.media_capture_enabled, r.path_rewrite_enabled, r.insecure_skip_verify, r.auth_enabled, "
        "r.auth_username, r.auth_password_hash, r.created_at, r.updated_at "
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
    int result = 0;
    if (rc == SQLITE_ROW) {
        result = scan_http_route(stmt, route);
        *found = result == 0;
    } else if (rc != SQLITE_DONE) {
        result = -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return result;
}

int st_storage_get_http_route_by_client_route(const char *path,
                                              const char *client_name,
                                              const char *route_name,
                                              st_storage_http_route *route)
{
    int found = 0;
    return st_storage_find_http_route_by_client_route(path,
                                                      client_name,
                                                      route_name,
                                                      route,
                                                      &found) == 0 && found
        ? 0
        : -1;
}

/* Creates the route, or updates it when the client already has a route of that name. */
static int upsert_http_route_on_db(sqlite3 *db,
                                   const char *client_name,
                                   const char *route,
                                   const char *target_base_url,
                                   int enabled,
                                   int detail_capture_enabled,
                                   int media_capture_enabled,
                                   int path_rewrite_enabled,
                                   int insecure_skip_verify,
                                   int auth_enabled,
                                   const char *auth_username,
                                   const char *auth_password_hash)
{
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT INTO http_route_mapping(client_name, route, target_base_url, enabled, detail_capture_enabled, media_capture_enabled, "
        "path_rewrite_enabled, insecure_skip_verify, auth_enabled, auth_username, auth_password_hash) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(client_name, route) DO UPDATE SET "
        "target_base_url = excluded.target_base_url,"
        "enabled = excluded.enabled,"
        "detail_capture_enabled = excluded.detail_capture_enabled,"
        "media_capture_enabled = excluded.media_capture_enabled,"
        "path_rewrite_enabled = excluded.path_rewrite_enabled,"
        "insecure_skip_verify = excluded.insecure_skip_verify,"
        "auth_enabled = excluded.auth_enabled,"
        "auth_username = excluded.auth_username,"
        "auth_password_hash = excluded.auth_password_hash,"
        "updated_at = CURRENT_TIMESTAMP",
        -1,
        &stmt,
        NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, client_name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, route, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, target_base_url, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 4, enabled ? 1 : 0);
        sqlite3_bind_int(stmt, 5, detail_capture_enabled ? 1 : 0);
        sqlite3_bind_int(stmt, 6, media_capture_enabled ? 1 : 0);
        sqlite3_bind_int(stmt, 7, path_rewrite_enabled ? 1 : 0);
        sqlite3_bind_int(stmt, 8, insecure_skip_verify ? 1 : 0);
        sqlite3_bind_int(stmt, 9, auth_enabled ? 1 : 0);
        sqlite3_bind_text(stmt, 10, auth_username == NULL ? "" : auth_username, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 11, auth_password_hash == NULL ? "" : auth_password_hash, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    return rc;
}

int st_storage_create_http_route_for_client(const char *path,
                                            long long client_id,
                                            const char *route,
                                            const char *target_base_url,
                                            int enabled,
                                            int detail_capture_enabled,
                                            int media_capture_enabled,
                                            int path_rewrite_enabled,
                                            int insecure_skip_verify,
                                            int auth_enabled,
                                            const char *auth_username,
                                            const char *auth_password_hash,
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
    int rc = upsert_http_route_on_db(db, client.client_name, route, target_base_url, enabled,
                                     detail_capture_enabled, media_capture_enabled, path_rewrite_enabled,
                                     insecure_skip_verify, auth_enabled, auth_username, auth_password_hash);
    sqlite3_close(db);
    if (rc != 0) {
        return -1;
    }
    return out_route == NULL
        ? 0
        : st_storage_get_http_route_by_client_route(path, client.client_name, route, out_route);
}

static int update_http_route_on_db(sqlite3 *db,
                                   long long id,
                                   const char *route,
                                   const char *target_base_url,
                                   int enabled,
                                   int detail_capture_enabled,
                                   int media_capture_enabled,
                                   int path_rewrite_enabled,
                                   int insecure_skip_verify,
                                   int auth_enabled,
                                   const char *auth_username,
                                   const char *auth_password_hash)
{
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "UPDATE http_route_mapping SET route = ?, target_base_url = ?, enabled = ?, "
        "detail_capture_enabled = ?, media_capture_enabled = ?, path_rewrite_enabled = ?, insecure_skip_verify = ?, auth_enabled = ?, "
        "auth_username = ?, auth_password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        -1,
        &stmt,
        NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, route, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, target_base_url, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 3, enabled ? 1 : 0);
        sqlite3_bind_int(stmt, 4, detail_capture_enabled ? 1 : 0);
        sqlite3_bind_int(stmt, 5, media_capture_enabled ? 1 : 0);
        sqlite3_bind_int(stmt, 6, path_rewrite_enabled ? 1 : 0);
        sqlite3_bind_int(stmt, 7, insecure_skip_verify ? 1 : 0);
        sqlite3_bind_int(stmt, 8, auth_enabled ? 1 : 0);
        sqlite3_bind_text(stmt, 9, auth_username == NULL ? "" : auth_username, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 10, auth_password_hash == NULL ? "" : auth_password_hash, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 11, id);
        rc = sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db) == 1 ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    return rc;
}

int st_storage_update_http_route_by_id(const char *path,
                                       long long id,
                                       const char *route,
                                       const char *target_base_url,
                                       int enabled,
                                       int detail_capture_enabled,
                                       int media_capture_enabled,
                                       int path_rewrite_enabled,
                                       int insecure_skip_verify,
                                       int auth_enabled,
                                       const char *auth_username,
                                       const char *auth_password_hash,
                                       st_storage_http_route *out_route)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    int rc = update_http_route_on_db(db, id, route, target_base_url, enabled, detail_capture_enabled,
                                     media_capture_enabled, path_rewrite_enabled, insecure_skip_verify,
                                     auth_enabled, auth_username, auth_password_hash);
    sqlite3_close(db);
    if (rc != 0) {
        return -1;
    }
    return out_route == NULL ? 0 : load_http_route_by_id(path, id, out_route);
}

static int delete_http_route_on_db(sqlite3 *db, long long id)
{
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, "DELETE FROM http_route_mapping WHERE id = ?", -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, id);
        rc = sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db) == 1 ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    /* Every workbench reference to the route goes with it, in the caller's transaction. */
    if (rc == 0) {
        rc = workbench_delete_object_refs(db, "http-route", id);
    }
    return rc;
}

int st_storage_delete_http_route_by_id(const char *path, long long id)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    if (exec_sql(db, "BEGIN IMMEDIATE") != 0) {
        sqlite3_close(db);
        return -1;
    }
    int rc = delete_http_route_on_db(db, id);
    if (rc == 0) {
        rc = exec_sql(db, "COMMIT");
    } else {
        (void)exec_sql(db, "ROLLBACK");
    }
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

int st_storage_close_open_connections(const char *path,
                                      const char *disconnect_reason,
                                      const char *disconnected_at,
                                      int *closed_count)
{
    if (closed_count != NULL) {
        *closed_count = 0;
    }
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    /* A reason already stamped on an open row is kept, as Java and Go do; only the end time is missing. */
    int rc = sqlite3_prepare_v2(db,
        "UPDATE connection_record SET disconnected_at = ?, "
        "disconnect_reason = COALESCE(NULLIF(disconnect_reason, ''), ?) "
        "WHERE disconnected_at IS NULL OR disconnected_at = ''",
        -1,
        &stmt,
        NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, disconnected_at == NULL ? "" : disconnected_at, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, disconnect_reason == NULL ? "" : disconnect_reason, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
        if (rc == 0 && closed_count != NULL) {
            *closed_count = sqlite3_changes(db);
        }
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
                                "virtual_ip, cidr, public_key, nat_type, nat_mapping_behavior, "
                                "nat_filtering_behavior, nat_behavior_discovery, last_endpoint, virtual_device_mode, "
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

static uint32_t peer_mesh_java_string_hash(const char *value)
{
    uint32_t hash = 0U;
    const unsigned char *cursor = (const unsigned char *)(value == NULL ? "" : value);
    while (*cursor != '\0') {
        uint32_t codepoint;
        if (*cursor < 0x80U) {
            codepoint = *cursor++;
        } else if ((*cursor & 0xe0U) == 0xc0U && cursor[1] != '\0') {
            codepoint = ((uint32_t)(cursor[0] & 0x1fU) << 6U) | (uint32_t)(cursor[1] & 0x3fU);
            cursor += 2;
        } else if ((*cursor & 0xf0U) == 0xe0U && cursor[1] != '\0' && cursor[2] != '\0') {
            codepoint = ((uint32_t)(cursor[0] & 0x0fU) << 12U)
                | ((uint32_t)(cursor[1] & 0x3fU) << 6U) | (uint32_t)(cursor[2] & 0x3fU);
            cursor += 3;
        } else if ((*cursor & 0xf8U) == 0xf0U
                   && cursor[1] != '\0' && cursor[2] != '\0' && cursor[3] != '\0') {
            codepoint = ((uint32_t)(cursor[0] & 0x07U) << 18U)
                | ((uint32_t)(cursor[1] & 0x3fU) << 12U)
                | ((uint32_t)(cursor[2] & 0x3fU) << 6U) | (uint32_t)(cursor[3] & 0x3fU);
            cursor += 4;
        } else {
            codepoint = *cursor++;
        }
        if (codepoint <= 0xffffU) {
            hash = hash * 31U + codepoint;
        } else {
            codepoint -= 0x10000U;
            hash = hash * 31U + (0xd800U + (codepoint >> 10U));
            hash = hash * 31U + (0xdc00U + (codepoint & 0x3ffU));
        }
    }
    return hash;
}

static int peer_mesh_allocate_virtual_ip(sqlite3 *db,
                                         const st_storage_client *client,
                                         const char *cidr,
                                         char out[64])
{
    char cidr_copy[64];
    if (db == NULL || client == NULL || cidr == NULL || strlen(cidr) >= sizeof(cidr_copy)) return -1;
    strcpy(cidr_copy, cidr);
    char *slash = strrchr(cidr_copy, '/');
    if (slash == NULL) return -1;
    *slash++ = '\0';
    char *end = NULL;
    long prefix = strtol(slash, &end, 10);
    struct in_addr address;
    if (end == slash || *end != '\0' || prefix < 1 || prefix > 30
        || inet_pton(AF_INET, cidr_copy, &address) != 1) return -1;
    uint64_t capacity = 1ULL << (32U - (unsigned int)prefix);
    uint32_t mask = UINT32_MAX << (32U - (unsigned int)prefix);
    uint32_t base = ntohl(address.s_addr) & mask;
    uint64_t usable = capacity - 2U;

    char identity[512];
    int written = snprintf(identity, sizeof(identity), "%s:%s:%lld",
                           normalize_tenant_id(client->tenant_id),
                           normalize_owner_username(client->owner_username), client->id);
    if (written < 0 || (size_t)written >= sizeof(identity)) return -1;
    uint32_t raw_hash = peer_mesh_java_string_hash(identity);
    uint64_t seed = (raw_hash & 0x80000000U) != 0U
        ? (uint64_t)(0U - raw_hash) : (uint64_t)raw_hash;

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT 1 FROM peer_mesh_device WHERE tenant_id=? AND virtual_ip=? LIMIT 1",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;
    for (uint64_t i = 1U; i <= usable; ++i) {
        uint64_t host = ((seed + i) % usable) + 1U;
        struct in_addr candidate;
        candidate.s_addr = htonl(base + (uint32_t)host);
        if (inet_ntop(AF_INET, &candidate, out, 64) == NULL) break;
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);
        sqlite3_bind_text(stmt, 1, normalize_tenant_id(client->tenant_id), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, out, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE) {
            sqlite3_finalize(stmt);
            return 0;
        }
        if (rc != SQLITE_ROW) break;
    }
    sqlite3_finalize(stmt);
    return -1;
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
    const char *cidr = getenv("SPECUS_PEER_MESH_CIDR");
    if (cidr == NULL || *cidr == '\0') cidr = "100.96.0.0/11";
    char virtual_ip[64];
    st_storage_peer_mesh_device existing;
    if (read_peer_mesh_device(db, client->tenant_id, client->id, &existing) == 0
        && existing.virtual_ip[0] != '\0') {
        snprintf(virtual_ip, sizeof(virtual_ip), "%s", existing.virtual_ip);
    } else if (peer_mesh_allocate_virtual_ip(db, client, cidr, virtual_ip) != 0) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(
        db,
        "INSERT INTO peer_mesh_device(tenant_id, owner_username, client_id, client_name, enabled, "
        "virtual_ip, cidr, nat_type, virtual_device_mode, virtual_device_status, updated_at) "
        "VALUES (?, ?, ?, ?, 0, ?, ?, 'UNKNOWN', 'AUTO', 'DOWN', CURRENT_TIMESTAMP) "
        "ON CONFLICT(tenant_id, client_id) DO UPDATE SET "
        "owner_username = excluded.owner_username, client_name = excluded.client_name, "
        "virtual_ip = CASE WHEN peer_mesh_device.virtual_ip IS NULL OR peer_mesh_device.virtual_ip='' "
        "THEN excluded.virtual_ip ELSE peer_mesh_device.virtual_ip END, "
        "cidr=excluded.cidr, updated_at=CURRENT_TIMESTAMP",
        -1,
        &stmt,
        NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, normalize_tenant_id(client->tenant_id), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, normalize_owner_username(client->owner_username), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 3, client->id);
        sqlite3_bind_text(stmt, 4, client->client_name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, virtual_ip, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 6, cidr, -1, SQLITE_TRANSIENT);
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

int st_storage_get_peer_mesh_device_by_client(const char *path,
                                              const char *tenant_id,
                                              long long client_id,
                                              st_storage_peer_mesh_device *out_device)
{
    sqlite3 *db = NULL;
    if (out_device == NULL || open_db(path, &db) != 0) return -1;
    int rc = read_peer_mesh_device(db, tenant_id, client_id, out_device);
    sqlite3_close(db);
    return rc;
}

int st_storage_update_peer_mesh_device_report(const char *path,
                                              const st_storage_client *client,
                                              const char *public_key,
                                              const char *nat_type,
                                              const char *nat_mapping_behavior,
                                              const char *nat_filtering_behavior,
                                              const char *nat_behavior_discovery,
                                              const char *last_endpoint,
                                              const char *virtual_device_mode,
                                              const char *virtual_device_name,
                                              const char *virtual_device_status,
                                              const char *virtual_device_error,
                                              st_storage_peer_mesh_device *out_device)
{
    if (client == NULL || st_storage_ensure_peer_mesh_device(path, client, NULL) != 0) return -1;
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) return -1;
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "UPDATE peer_mesh_device SET public_key=COALESCE(?,public_key),nat_type=COALESCE(?,nat_type),"
        "nat_mapping_behavior=COALESCE(?,nat_mapping_behavior),"
        "nat_filtering_behavior=COALESCE(?,nat_filtering_behavior),"
        "nat_behavior_discovery=COALESCE(?,nat_behavior_discovery),"
        "last_endpoint=COALESCE(?,last_endpoint),virtual_device_mode=COALESCE(?,virtual_device_mode),"
        "virtual_device_name=COALESCE(?,virtual_device_name),virtual_device_status=COALESCE(?,virtual_device_status),"
        "virtual_device_error=COALESCE(?,virtual_device_error),virtual_device_updated_at=CASE WHEN ? IS NULL AND ? IS NULL AND ? IS NULL AND ? IS NULL THEN virtual_device_updated_at ELSE CURRENT_TIMESTAMP END,"
        "last_seen_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=? AND client_id=?",
        -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        bind_nullable_text_limit(stmt, 1, public_key, 256);
        bind_nullable_text_limit(stmt, 2, nat_type, 63);
        bind_nullable_text_limit(stmt, 3, nat_mapping_behavior, 63);
        bind_nullable_text_limit(stmt, 4, nat_filtering_behavior, 63);
        bind_nullable_text_limit(stmt, 5, nat_behavior_discovery, 40);
        bind_nullable_text_limit(stmt, 6, last_endpoint, 127);
        bind_nullable_text_limit(stmt, 7, virtual_device_mode, 31);
        bind_nullable_text_limit(stmt, 8, virtual_device_name, 127);
        bind_nullable_text_limit(stmt, 9, virtual_device_status, 31);
        bind_nullable_text_limit(stmt, 10, virtual_device_error, 255);
        bind_nullable_text_limit(stmt, 11, virtual_device_mode, 31);
        bind_nullable_text_limit(stmt, 12, virtual_device_name, 127);
        bind_nullable_text_limit(stmt, 13, virtual_device_status, 31);
        bind_nullable_text_limit(stmt, 14, virtual_device_error, 255);
        sqlite3_bind_text(stmt, 15, normalize_tenant_id(client->tenant_id), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 16, client->id);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    } else rc = -1;
    sqlite3_finalize(stmt);
    if (rc == 0 && out_device != NULL) rc = read_peer_mesh_device(db, client->tenant_id, client->id, out_device);
    sqlite3_close(db);
    return rc;
}

int st_storage_can_peer(const char *path,
                        const st_storage_client *source,
                        const st_storage_client *target,
                        int *allowed)
{
    if (source == NULL || target == NULL || allowed == NULL
        || source->id <= 0 || target->id <= 0 || source->id == target->id) {
        return -1;
    }
    *allowed = 0;
    if (!source->enabled || !target->enabled
        || strcmp(source->tenant_id, target->tenant_id) != 0) {
        return 0;
    }
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(
        db,
        "SELECT COUNT(*) FROM peer_mesh_device "
        "WHERE tenant_id COLLATE BINARY = ? AND enabled = 1 AND client_id IN (?, ?)",
        -1,
        &stmt,
        NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, source->tenant_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, source->id);
    sqlite3_bind_int64(stmt, 3, target->id);
    rc = sqlite3_step(stmt);
    int enabled_devices = rc == SQLITE_ROW ? sqlite3_column_int(stmt, 0) : 0;
    sqlite3_finalize(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_close(db);
        return -1;
    }
    if (enabled_devices != 2) {
        sqlite3_close(db);
        return 0;
    }
    if (strcmp(normalize_owner_username(source->owner_username),
               normalize_owner_username(target->owner_username)) == 0) {
        *allowed = 1;
        sqlite3_close(db);
        return 0;
    }

    rc = sqlite3_prepare_v2(
        db,
        "SELECT 1 FROM peer_mesh_acl WHERE tenant_id COLLATE BINARY = ? AND allowed = 1 AND ("
        "(source_client_id = ? AND target_client_id = ? AND direction IN ('OUTBOUND','BOTH')) OR "
        "(source_client_id = ? AND target_client_id = ? AND direction IN ('INBOUND','BOTH'))) LIMIT 1",
        -1,
        &stmt,
        NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, source->tenant_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, source->id);
    sqlite3_bind_int64(stmt, 3, target->id);
    sqlite3_bind_int64(stmt, 4, target->id);
    sqlite3_bind_int64(stmt, 5, source->id);
    rc = sqlite3_step(stmt);
    *allowed = rc == SQLITE_ROW;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == SQLITE_ROW || rc == SQLITE_DONE ? 0 : -1;
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
    if (st_elasticsearch_traffic_enabled_current()) {
        return st_elasticsearch_record_http(record);
    }
    if (record == NULL || record->client_id <= 0 || record->client_name == NULL || record->route == NULL) {
        return -1;
    }
    /* Previews as Java TrafficInspectionService builds them (traffic_capture.c). */
    size_t preview_bytes = st_traffic_preview_bytes();
    char request_hex[ST_TRAFFIC_PREVIEW_HEX_CAP];
    char request_text[ST_TRAFFIC_PREVIEW_TEXT_CAP];
    char response_hex[ST_TRAFFIC_PREVIEW_HEX_CAP];
    char response_text[ST_TRAFFIC_PREVIEW_TEXT_CAP];
    st_traffic_hex_preview(record->request_body, record->request_body_len, preview_bytes,
                           request_hex, sizeof(request_hex));
    st_traffic_http_text_preview(record->request_body, record->request_body_len, record->request_content_type,
                                 record->request_content_encoding, preview_bytes,
                                 request_text, sizeof(request_text));
    st_traffic_hex_preview(record->response_body, record->response_body_len, preview_bytes,
                           response_hex, sizeof(response_hex));
    st_traffic_http_text_preview(record->response_body, record->response_body_len, record->response_content_type,
                                 record->response_content_encoding, preview_bytes,
                                 response_text, sizeof(response_text));
    const char *body_type = st_traffic_body_type_or_classify(record->response_body_type,
                                                             record->response_content_type,
                                                             record->response_bytes);
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
        /* C keeps previews, not bodies: truncated says the preview holds less than the body. */
        sqlite3_bind_int(stmt, 26, record->request_body_len > preview_bytes ? 1 : 0);
        sqlite3_bind_int(stmt, 27, record->response_body_len > preview_bytes ? 1 : 0);
        sqlite3_bind_text(stmt, 28, record->captured_at == NULL ? "" : record->captured_at, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == 0 ? 0 : -1;
}

static int read_peer_mesh_session(sqlite3 *db,
                                  const char *tenant_id,
                                  long long id,
                                  st_storage_peer_mesh_session *session)
{
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT id,tenant_id,source_client_id,source_client_name,target_client_id,target_client_name,"
        "path_type,status,started_at,updated_at,expires_at,closed_at,rtt_millis,local_endpoint,"
        "remote_endpoint,direct_bytes,relay_bytes,last_traffic_at FROM peer_mesh_session "
        "WHERE tenant_id=? AND id=?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;
    sqlite3_bind_text(stmt, 1, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, id);
    rc = sqlite3_step(stmt);
    int ok = rc == SQLITE_ROW && session != NULL && scan_peer_mesh_session(stmt, session) == 0;
    sqlite3_finalize(stmt);
    return ok ? 0 : -1;
}

int st_storage_create_peer_mesh_session(const char *path,
                                        const st_storage_client *source,
                                        const st_storage_client *target,
                                        const char *path_type,
                                        const char *token_hash,
                                        long long ttl_seconds,
                                        st_storage_peer_mesh_session *out_session)
{
    if (source == NULL || target == NULL || token_hash == NULL || ttl_seconds <= 0) return -1;
    int allowed = 0;
    if (st_storage_can_peer(path, source, target, &allowed) != 0 || !allowed) return -1;
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) return -1;
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT INTO peer_mesh_session(tenant_id,source_client_id,source_client_name,target_client_id,"
        "target_client_name,path_type,status,token_hash,started_at,updated_at,expires_at) "
        "VALUES(?,?,?,?,?,?, 'NEGOTIATING',?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,datetime('now',?))",
        -1, &stmt, NULL);
    char ttl[64];
    snprintf(ttl, sizeof(ttl), "+%lld seconds", ttl_seconds);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, source->tenant_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 2, source->id);
        sqlite3_bind_text(stmt, 3, source->client_name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 4, target->id);
        sqlite3_bind_text(stmt, 5, target->client_name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 6, path_type == NULL || *path_type == '\0' ? "DIRECT" : path_type, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 7, token_hash, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 8, ttl, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    } else rc = -1;
    sqlite3_finalize(stmt);
    long long id = rc == 0 ? sqlite3_last_insert_rowid(db) : 0;
    if (rc == 0 && out_session != NULL) rc = read_peer_mesh_session(db, source->tenant_id, id, out_session);
    sqlite3_close(db);
    return rc;
}

int st_storage_get_peer_mesh_session(const char *path,
                                     const char *tenant_id,
                                     long long id,
                                     st_storage_peer_mesh_session *out_session)
{
    sqlite3 *db = NULL;
    if (out_session == NULL || open_db(path, &db) != 0) return -1;
    int rc = read_peer_mesh_session(db, tenant_id, id, out_session);
    sqlite3_close(db);
    return rc;
}

int st_storage_report_peer_mesh_session(const char *path,
                                        const st_storage_client *reporter,
                                        long long id,
                                        const char *path_type,
                                        const char *status,
                                        long long rtt_millis,
                                        const char *local_endpoint,
                                        const char *remote_endpoint,
                                        long long direct_bytes,
                                        long long relay_bytes,
                                        int close_session,
                                        st_storage_peer_mesh_session *out_session)
{
    if (reporter == NULL || id <= 0) return -1;
    if (direct_bytes < 0) direct_bytes = 0;
    if (relay_bytes < 0) relay_bytes = 0;
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) return -1;
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "UPDATE peer_mesh_session SET path_type=CASE WHEN ?='' THEN path_type ELSE ? END,"
        "status=CASE WHEN ? THEN 'CLOSED' WHEN ?='' THEN status ELSE ? END,"
        "rtt_millis=CASE WHEN ?<0 THEN rtt_millis ELSE ? END,"
        "local_endpoint=COALESCE(?,local_endpoint),remote_endpoint=COALESCE(?,remote_endpoint),"
        "direct_bytes=direct_bytes+?,relay_bytes=relay_bytes+?,"
        "last_traffic_at=CASE WHEN ?>0 OR ?>0 THEN CURRENT_TIMESTAMP ELSE last_traffic_at END,"
        "closed_at=CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE closed_at END,updated_at=CURRENT_TIMESTAMP "
        "WHERE id=? AND tenant_id=? AND (source_client_id=? OR target_client_id=?)",
        -1, &stmt, NULL);
    const char *next_path = path_type == NULL ? "" : path_type;
    const char *next_status = status == NULL ? "" : status;
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, next_path, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, next_path, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 3, close_session ? 1 : 0);
        sqlite3_bind_text(stmt, 4, next_status, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, next_status, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 6, rtt_millis);
        sqlite3_bind_int64(stmt, 7, rtt_millis);
        bind_nullable_text_limit(stmt, 8, local_endpoint, 255);
        bind_nullable_text_limit(stmt, 9, remote_endpoint, 255);
        sqlite3_bind_int64(stmt, 10, direct_bytes);
        sqlite3_bind_int64(stmt, 11, relay_bytes);
        sqlite3_bind_int64(stmt, 12, direct_bytes);
        sqlite3_bind_int64(stmt, 13, relay_bytes);
        sqlite3_bind_int(stmt, 14, close_session ? 1 : 0);
        sqlite3_bind_int64(stmt, 15, id);
        sqlite3_bind_text(stmt, 16, reporter->tenant_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 17, reporter->id);
        sqlite3_bind_int64(stmt, 18, reporter->id);
        rc = sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db) == 1 ? 0 : -1;
    } else rc = -1;
    sqlite3_finalize(stmt);
    if (rc == 0 && out_session != NULL) rc = read_peer_mesh_session(db, reporter->tenant_id, id, out_session);
    sqlite3_close(db);
    return rc;
}

static int peer_mesh_session_authorized(sqlite3 *db,
                                        long long session_id,
                                        long long from_client_id,
                                        long long to_client_id,
                                        char *token_hash,
                                        size_t token_hash_len)
{
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT token_hash FROM peer_mesh_session WHERE id=? AND status<>'CLOSED' "
        "AND datetime(expires_at)>CURRENT_TIMESTAMP AND ((source_client_id=? AND target_client_id=?) "
        "OR (source_client_id=? AND target_client_id=?))",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;
    sqlite3_bind_int64(stmt, 1, session_id);
    sqlite3_bind_int64(stmt, 2, from_client_id);
    sqlite3_bind_int64(stmt, 3, to_client_id);
    sqlite3_bind_int64(stmt, 4, to_client_id);
    sqlite3_bind_int64(stmt, 5, from_client_id);
    rc = sqlite3_step(stmt);
    int allowed = rc == SQLITE_ROW;
    if (allowed && token_hash != NULL && token_hash_len > 0U) {
        const unsigned char *value = sqlite3_column_text(stmt, 0);
        snprintf(token_hash, token_hash_len, "%s", value == NULL ? "" : (const char *)value);
    }
    sqlite3_finalize(stmt);
    return allowed ? 1 : (rc == SQLITE_DONE ? 0 : -1);
}

int st_storage_authorize_peer_mesh_relay(const char *path,
                                         long long session_id,
                                         long long from_client_id,
                                         long long to_client_id,
                                         long long relay_bytes,
                                         int account_traffic)
{
    if (session_id <= 0 || from_client_id <= 0 || to_client_id <= 0
        || from_client_id == to_client_id || relay_bytes < 0) return 0;
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) return -1;
    int allowed = peer_mesh_session_authorized(db, session_id, from_client_id,
                                               to_client_id, NULL, 0U);
    if (allowed == 1 && account_traffic) {
        sqlite3_stmt *stmt = NULL;
        int rc = sqlite3_prepare_v2(db,
            "UPDATE peer_mesh_session SET status='ACTIVE',path_type='RELAY',"
            "relay_bytes=CASE WHEN relay_bytes>? THEN 9223372036854775807 ELSE relay_bytes+? END,"
            "last_traffic_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=?",
            -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, 9223372036854775807LL - relay_bytes);
            sqlite3_bind_int64(stmt, 2, relay_bytes);
            sqlite3_bind_int64(stmt, 3, session_id);
            rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
        } else rc = -1;
        sqlite3_finalize(stmt);
        if (rc != 0) allowed = -1;
    }
    sqlite3_close(db);
    return allowed;
}

int st_storage_verify_peer_mesh_probe(const char *path,
                                      long long session_id,
                                      long long from_client_id,
                                      long long to_client_id,
                                      const char *token)
{
    if (token == NULL || *token == '\0') return 0;
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) return -1;
    char expected_hex[ST_SHA256_HEX_LEN + 1U];
    int allowed = peer_mesh_session_authorized(db, session_id, from_client_id,
                                               to_client_id, expected_hex, sizeof(expected_hex));
    sqlite3_close(db);
    if (allowed != 1 || strlen(expected_hex) != ST_SHA256_HEX_LEN) return allowed < 0 ? -1 : 0;
    uint8_t actual[ST_SHA256_LEN];
    uint8_t expected[ST_SHA256_LEN];
    st_sha256((const uint8_t *)token, strlen(token), actual);
    if (st_hex_decode_32(expected_hex, expected) != 0) return 0;
    return st_constant_time_eq(actual, expected, sizeof(actual)) ? 1 : 0;
}

int st_storage_get_peer_mesh_service_sharing(const char *path,
                                             const char *tenant_id,
                                             st_storage_peer_mesh_service_sharing *out_sharing)
{
    if (out_sharing == NULL) return -1;
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) return -1;
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT enabled,mdns_import_enabled,updated_by,updated_at FROM peer_mesh_service_sharing WHERE tenant_id=?",
        -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt);
        if (rc == SQLITE_ROW) {
            memset(out_sharing, 0, sizeof(*out_sharing));
            out_sharing->enabled = sqlite3_column_int(stmt, 0) != 0;
            out_sharing->mdns_import_enabled = sqlite3_column_int(stmt, 1) != 0;
            if (copy_text_column(stmt, 2, out_sharing->updated_by, sizeof(out_sharing->updated_by)) != 0
                || copy_text_column(stmt, 3, out_sharing->updated_at, sizeof(out_sharing->updated_at)) != 0) rc = SQLITE_ERROR;
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == SQLITE_ROW ? 0 : (rc == SQLITE_DONE ? 1 : -1);
}

int st_storage_upsert_peer_mesh_service_sharing(const char *path,
                                                const char *tenant_id,
                                                int enabled,
                                                int mdns_import_enabled,
                                                const char *updated_by,
                                                st_storage_peer_mesh_service_sharing *out_sharing)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) return -1;
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT INTO peer_mesh_service_sharing(tenant_id,enabled,mdns_import_enabled,updated_by,updated_at) "
        "VALUES(?,?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(tenant_id) DO UPDATE SET enabled=excluded.enabled,"
        "mdns_import_enabled=excluded.mdns_import_enabled,updated_by=excluded.updated_by,updated_at=CURRENT_TIMESTAMP",
        -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 2, enabled ? 1 : 0);
        sqlite3_bind_int(stmt, 3, mdns_import_enabled ? 1 : 0);
        bind_nullable_text_limit(stmt, 4, updated_by, 127);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    } else rc = -1;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == 0 && out_sharing != NULL
        ? st_storage_get_peer_mesh_service_sharing(path, tenant_id, out_sharing) : rc;
}

static int scan_peer_mesh_service(sqlite3_stmt *stmt, st_storage_peer_mesh_service *service)
{
    memset(service, 0, sizeof(*service));
    service->id = sqlite3_column_int64(stmt, 0);
    service->client_id = sqlite3_column_int64(stmt, 2);
    service->target_port = sqlite3_column_int(stmt, 10);
    service->published_port = sqlite3_column_int(stmt, 11);
    service->enabled = sqlite3_column_int(stmt, 13) != 0;
    return copy_text_column(stmt, 1, service->tenant_id, sizeof(service->tenant_id)) == 0
        && copy_text_column(stmt, 3, service->client_name, sizeof(service->client_name)) == 0
        && copy_text_column(stmt, 4, service->service_id, sizeof(service->service_id)) == 0
        && copy_text_column(stmt, 5, service->name, sizeof(service->name)) == 0
        && copy_text_column(stmt, 6, service->description, sizeof(service->description)) == 0
        && copy_text_column(stmt, 7, service->transport, sizeof(service->transport)) == 0
        && copy_text_column(stmt, 8, service->application, sizeof(service->application)) == 0
        && copy_text_column(stmt, 9, service->target_host, sizeof(service->target_host)) == 0
        && copy_text_column(stmt, 12, service->path, sizeof(service->path)) == 0
        && copy_text_column(stmt, 14, service->visibility, sizeof(service->visibility)) == 0
        && copy_text_column(stmt, 15, service->allowed_client_ids, sizeof(service->allowed_client_ids)) == 0
        && copy_text_column(stmt, 16, service->created_at, sizeof(service->created_at)) == 0
        && copy_text_column(stmt, 17, service->updated_at, sizeof(service->updated_at)) == 0 ? 0 : -1;
}

static const char *peer_mesh_service_select(void)
{
    return "SELECT s.id,s.tenant_id,s.client_id,s.client_name,s.service_id,s.name,s.description,"
        "s.transport,s.application,s.target_host,s.target_port,s.published_port,s.path,s.enabled,"
        "s.visibility,s.allowed_client_ids,s.created_at,s.updated_at FROM peer_mesh_shared_service s";
}

int st_storage_list_peer_mesh_services_visible(const char *path,
                                               const char *tenant_id,
                                               const char *owner_username,
                                               int include_all_clients,
                                               st_storage_peer_mesh_service *services,
                                               size_t max_services,
                                               size_t *service_count)
{
    if (services == NULL || service_count == NULL) return -1;
    *service_count = 0U;
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) return -1;
    char sql[1024];
    int written = snprintf(sql, sizeof(sql), "%s %s WHERE s.tenant_id=?%s ORDER BY s.client_name,s.name",
        peer_mesh_service_select(), include_all_clients ? "" : "JOIN client_account c ON c.rowid=s.client_id",
        include_all_clients ? "" : " AND c.owner_username=?");
    sqlite3_stmt *stmt = NULL;
    int rc = written > 0 && (size_t)written < sizeof(sql)
        ? sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) : SQLITE_ERROR;
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
        if (!include_all_clients) sqlite3_bind_text(stmt, 2, normalize_owner_username(owner_username), -1, SQLITE_TRANSIENT);
        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
            if (*service_count >= max_services
                || scan_peer_mesh_service(stmt, &services[*service_count]) != 0) { rc = SQLITE_ERROR; break; }
            ++*service_count;
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == SQLITE_DONE ? 0 : -1;
}

int st_storage_get_peer_mesh_service_visible(const char *path,
                                             long long id,
                                             const char *tenant_id,
                                             const char *owner_username,
                                             int include_all_clients,
                                             st_storage_peer_mesh_service *out_service)
{
    if (out_service == NULL || id <= 0) return -1;
    st_storage_peer_mesh_service items[256];
    size_t count = 0U;
    if (st_storage_list_peer_mesh_services_visible(path, tenant_id, owner_username,
                                                   include_all_clients, items, 256, &count) != 0) return -1;
    for (size_t i = 0; i < count; ++i) {
        if (items[i].id == id) { *out_service = items[i]; return 0; }
    }
    return 1;
}

int st_storage_upsert_peer_mesh_service(const char *path,
                                        const st_storage_peer_mesh_service *service,
                                        st_storage_peer_mesh_service *out_service)
{
    if (service == NULL || service->client_id <= 0) return -1;
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) return -1;
    sqlite3_stmt *stmt = NULL;
    const char *sql = service->id > 0
        ? "UPDATE peer_mesh_shared_service SET name=?,description=?,transport=?,application=?,target_host=?,"
          "target_port=?,published_port=?,path=?,enabled=?,visibility=?,allowed_client_ids=?,updated_at=CURRENT_TIMESTAMP "
          "WHERE id=? AND tenant_id=?"
        : "INSERT INTO peer_mesh_shared_service(tenant_id,client_id,client_name,service_id,name,description,transport,"
          "application,target_host,target_port,published_port,path,enabled,visibility,allowed_client_ids,created_at,updated_at) "
          "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)";
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK && service->id > 0) {
        sqlite3_bind_text(stmt, 1, service->name, -1, SQLITE_TRANSIENT);
        bind_nullable_text_limit(stmt, 2, service->description, 200);
        sqlite3_bind_text(stmt, 3, service->transport, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, service->application, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, service->target_host, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 6, service->target_port);
        sqlite3_bind_int(stmt, 7, service->published_port);
        bind_nullable_text_limit(stmt, 8, service->path, 255);
        sqlite3_bind_int(stmt, 9, service->enabled ? 1 : 0);
        sqlite3_bind_text(stmt, 10, service->visibility, -1, SQLITE_TRANSIENT);
        bind_nullable_text_limit(stmt, 11, service->allowed_client_ids, 511);
        sqlite3_bind_int64(stmt, 12, service->id);
        sqlite3_bind_text(stmt, 13, normalize_tenant_id(service->tenant_id), -1, SQLITE_TRANSIENT);
    } else if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, normalize_tenant_id(service->tenant_id), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 2, service->client_id);
        sqlite3_bind_text(stmt, 3, service->client_name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, service->service_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, service->name, -1, SQLITE_TRANSIENT);
        bind_nullable_text_limit(stmt, 6, service->description, 200);
        sqlite3_bind_text(stmt, 7, service->transport, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 8, service->application, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 9, service->target_host, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 10, service->target_port);
        sqlite3_bind_int(stmt, 11, service->published_port);
        bind_nullable_text_limit(stmt, 12, service->path, 255);
        sqlite3_bind_int(stmt, 13, service->enabled ? 1 : 0);
        sqlite3_bind_text(stmt, 14, service->visibility, -1, SQLITE_TRANSIENT);
        bind_nullable_text_limit(stmt, 15, service->allowed_client_ids, 511);
    }
    if (rc == SQLITE_OK) rc = sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db) == 1 ? 0 : -1;
    else rc = -1;
    sqlite3_finalize(stmt);
    long long id = service->id > 0 ? service->id : sqlite3_last_insert_rowid(db);
    sqlite3_close(db);
    return rc == 0 && out_service != NULL
        ? st_storage_get_peer_mesh_service_visible(path, id, service->tenant_id, "", 1, out_service) : rc;
}

int st_storage_delete_peer_mesh_service(const char *path,
                                        long long id,
                                        const char *tenant_id)
{
    sqlite3 *db = NULL;
    if (id <= 0 || open_db(path, &db) != 0) return -1;
    if (exec_sql(db, "BEGIN IMMEDIATE") != 0) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "DELETE FROM peer_mesh_shared_service WHERE id=? AND tenant_id=?", -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, id);
        sqlite3_bind_text(stmt, 2, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) != SQLITE_DONE) rc = -1;
        else rc = sqlite3_changes(db) == 1 ? 0 : 1;
    } else rc = -1;
    sqlite3_finalize(stmt);
    /* The service's workbench references go with it, in the same transaction. */
    if (rc == 0 && workbench_delete_object_refs(db, "peer-service", id) != 0) rc = -1;
    if (rc == 0) {
        if (exec_sql(db, "COMMIT") != 0) rc = -1;
    }
    if (rc != 0) (void)exec_sql(db, "ROLLBACK");
    sqlite3_close(db);
    return rc;
}

static const char *peer_mesh_egress_policy_select(void)
{
    return "SELECT id,tenant_id,owner_username,egress_client_id,egress_client_name,enabled,scope,"
        "allowed_consumer_client_ids,destination_rules,max_concurrent_flows,max_flows_per_consumer,"
        "idle_timeout_seconds,created_at,updated_at,domain_rules FROM peer_mesh_egress_policy";
}

static int scan_peer_mesh_egress_policy(sqlite3_stmt *stmt, st_storage_peer_mesh_egress_policy *policy)
{
    memset(policy, 0, sizeof(*policy));
    policy->id = sqlite3_column_int64(stmt, 0);
    policy->egress_client_id = sqlite3_column_int64(stmt, 3);
    policy->enabled = sqlite3_column_int(stmt, 5) != 0;
    policy->max_concurrent_flows = sqlite3_column_int(stmt, 9);
    policy->max_flows_per_consumer = sqlite3_column_int(stmt, 10);
    policy->idle_timeout_seconds = sqlite3_column_int(stmt, 11);
    return copy_text_column(stmt, 1, policy->tenant_id, sizeof(policy->tenant_id)) == 0
        && copy_text_column(stmt, 2, policy->owner_username, sizeof(policy->owner_username)) == 0
        && copy_text_column(stmt, 4, policy->egress_client_name, sizeof(policy->egress_client_name)) == 0
        && copy_text_column(stmt, 6, policy->scope, sizeof(policy->scope)) == 0
        && copy_text_column(stmt, 7, policy->allowed_consumer_client_ids,
                            sizeof(policy->allowed_consumer_client_ids)) == 0
        && copy_text_column(stmt, 8, policy->destination_rules, sizeof(policy->destination_rules)) == 0
        && copy_text_column(stmt, 12, policy->created_at, sizeof(policy->created_at)) == 0
        && copy_text_column(stmt, 13, policy->updated_at, sizeof(policy->updated_at)) == 0
        && copy_text_column(stmt, 14, policy->domain_rules, sizeof(policy->domain_rules)) == 0 ? 0 : -1;
}

int st_storage_list_peer_mesh_egress_policies(const char *path,
                                              const char *tenant_id,
                                              int enabled_only,
                                              st_storage_peer_mesh_egress_policy *policies,
                                              size_t max_policies,
                                              size_t *policy_count)
{
    if (policies == NULL || policy_count == NULL) return -1;
    *policy_count = 0U;
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) return -1;
    char sql[768];
    int written = snprintf(sql, sizeof(sql), "%s WHERE tenant_id=?%s ORDER BY egress_client_name",
        peer_mesh_egress_policy_select(), enabled_only ? " AND enabled=1" : "");
    sqlite3_stmt *stmt = NULL;
    int rc = written > 0 && (size_t)written < sizeof(sql)
        ? sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) : SQLITE_ERROR;
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
            if (*policy_count >= max_policies
                || scan_peer_mesh_egress_policy(stmt, &policies[*policy_count]) != 0) {
                rc = SQLITE_ERROR;
                break;
            }
            ++*policy_count;
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* Returns 0 on a hit, 1 when the row is absent, -1 on a storage failure. */
static int peer_mesh_egress_policy_lookup(const char *path,
                                          const char *column,
                                          long long key,
                                          const char *tenant_id,
                                          st_storage_peer_mesh_egress_policy *out_policy)
{
    if (out_policy == NULL || key <= 0) return -1;
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) return -1;
    char sql[768];
    int written = snprintf(sql, sizeof(sql), "%s WHERE tenant_id=? AND %s=?",
        peer_mesh_egress_policy_select(), column);
    sqlite3_stmt *stmt = NULL;
    int rc = written > 0 && (size_t)written < sizeof(sql)
        ? sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) : SQLITE_ERROR;
    int result = -1;
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 2, key);
        rc = sqlite3_step(stmt);
        if (rc == SQLITE_ROW) result = scan_peer_mesh_egress_policy(stmt, out_policy) == 0 ? 0 : -1;
        else if (rc == SQLITE_DONE) result = 1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return result;
}

int st_storage_get_peer_mesh_egress_policy(const char *path,
                                           long long id,
                                           const char *tenant_id,
                                           st_storage_peer_mesh_egress_policy *out_policy)
{
    return peer_mesh_egress_policy_lookup(path, "id", id, tenant_id, out_policy);
}

int st_storage_find_peer_mesh_egress_policy_by_client(const char *path,
                                                      const char *tenant_id,
                                                      long long egress_client_id,
                                                      st_storage_peer_mesh_egress_policy *out_policy)
{
    return peer_mesh_egress_policy_lookup(path, "egress_client_id", egress_client_id, tenant_id, out_policy);
}

int st_storage_upsert_peer_mesh_egress_policy(const char *path,
                                              const st_storage_peer_mesh_egress_policy *policy,
                                              st_storage_peer_mesh_egress_policy *out_policy)
{
    if (policy == NULL || policy->egress_client_id <= 0) return -1;
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) return -1;
    sqlite3_stmt *stmt = NULL;
    const char *sql = policy->id > 0
        ? "UPDATE peer_mesh_egress_policy SET owner_username=?,egress_client_name=?,enabled=?,scope=?,"
          "allowed_consumer_client_ids=?,destination_rules=?,max_concurrent_flows=?,"
          "max_flows_per_consumer=?,idle_timeout_seconds=?,domain_rules=?,updated_at=CURRENT_TIMESTAMP "
          "WHERE id=? AND tenant_id=?"
        : "INSERT INTO peer_mesh_egress_policy(tenant_id,owner_username,egress_client_id,egress_client_name,"
          "enabled,scope,allowed_consumer_client_ids,destination_rules,max_concurrent_flows,"
          "max_flows_per_consumer,idle_timeout_seconds,domain_rules,created_at,updated_at) "
          "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)";
    /* The column is NOT NULL: a caller that left the rules unset stores none. */
    const char *domain_rules = policy->domain_rules[0] == '\0' ? "[]" : policy->domain_rules;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK && policy->id > 0) {
        sqlite3_bind_text(stmt, 1, normalize_owner_username(policy->owner_username), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, policy->egress_client_name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 3, policy->enabled ? 1 : 0);
        sqlite3_bind_text(stmt, 4, policy->scope, -1, SQLITE_TRANSIENT);
        bind_nullable_text_limit(stmt, 5, policy->allowed_consumer_client_ids, 511);
        bind_nullable_text_limit(stmt, 6, policy->destination_rules, 4096);
        sqlite3_bind_int(stmt, 7, policy->max_concurrent_flows);
        sqlite3_bind_int(stmt, 8, policy->max_flows_per_consumer);
        sqlite3_bind_int(stmt, 9, policy->idle_timeout_seconds);
        sqlite3_bind_text(stmt, 10, domain_rules, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 11, policy->id);
        sqlite3_bind_text(stmt, 12, normalize_tenant_id(policy->tenant_id), -1, SQLITE_TRANSIENT);
    } else if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, normalize_tenant_id(policy->tenant_id), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, normalize_owner_username(policy->owner_username), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 3, policy->egress_client_id);
        sqlite3_bind_text(stmt, 4, policy->egress_client_name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 5, policy->enabled ? 1 : 0);
        sqlite3_bind_text(stmt, 6, policy->scope, -1, SQLITE_TRANSIENT);
        bind_nullable_text_limit(stmt, 7, policy->allowed_consumer_client_ids, 511);
        bind_nullable_text_limit(stmt, 8, policy->destination_rules, 4096);
        sqlite3_bind_int(stmt, 9, policy->max_concurrent_flows);
        sqlite3_bind_int(stmt, 10, policy->max_flows_per_consumer);
        sqlite3_bind_int(stmt, 11, policy->idle_timeout_seconds);
        sqlite3_bind_text(stmt, 12, domain_rules, -1, SQLITE_TRANSIENT);
    }
    if (rc == SQLITE_OK) rc = sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db) == 1 ? 0 : -1;
    else rc = -1;
    sqlite3_finalize(stmt);
    long long id = policy->id > 0 ? policy->id : sqlite3_last_insert_rowid(db);
    sqlite3_close(db);
    return rc == 0 && out_policy != NULL
        ? st_storage_get_peer_mesh_egress_policy(path, id, policy->tenant_id, out_policy) : rc;
}

int st_storage_delete_peer_mesh_egress_policy(const char *path,
                                              long long id,
                                              const char *tenant_id)
{
    sqlite3 *db = NULL;
    if (id <= 0 || open_db(path, &db) != 0) return -1;
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "DELETE FROM peer_mesh_egress_policy WHERE id=? AND tenant_id=?", -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, id);
        sqlite3_bind_text(stmt, 2, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db) == 1 ? 0 : 1;
    } else rc = -1;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc;
}

static const char *peer_mesh_egress_activity_select(void)
{
    return "SELECT id,tenant_id,egress_client_id,egress_client_name,session_id,revision,active_flows,"
        "total_flows,rejected_flows,bytes_in,bytes_out,reported_at,created_at,updated_at "
        "FROM peer_mesh_egress_activity";
}

static int scan_peer_mesh_egress_activity(sqlite3_stmt *stmt, st_storage_peer_mesh_egress_activity *row)
{
    memset(row, 0, sizeof(*row));
    row->id = sqlite3_column_int64(stmt, 0);
    row->egress_client_id = sqlite3_column_int64(stmt, 2);
    row->session_id = sqlite3_column_int64(stmt, 4);
    row->revision = sqlite3_column_int64(stmt, 5);
    row->active_flows = sqlite3_column_int64(stmt, 6);
    row->total_flows = sqlite3_column_int64(stmt, 7);
    row->bytes_in = sqlite3_column_int64(stmt, 9);
    row->bytes_out = sqlite3_column_int64(stmt, 10);
    return copy_text_column(stmt, 1, row->tenant_id, sizeof(row->tenant_id)) == 0
        && copy_text_column(stmt, 3, row->egress_client_name, sizeof(row->egress_client_name)) == 0
        && copy_text_column(stmt, 8, row->rejected_flows, sizeof(row->rejected_flows)) == 0
        && copy_text_column(stmt, 11, row->reported_at, sizeof(row->reported_at)) == 0
        && copy_text_column(stmt, 12, row->created_at, sizeof(row->created_at)) == 0
        && copy_text_column(stmt, 13, row->updated_at, sizeof(row->updated_at)) == 0 ? 0 : -1;
}

int st_storage_list_peer_mesh_egress_activity(const char *path,
                                              const char *tenant_id,
                                              st_storage_peer_mesh_egress_activity *rows,
                                              size_t max_rows,
                                              size_t *row_count)
{
    if (rows == NULL || row_count == NULL) return -1;
    *row_count = 0U;
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) return -1;
    char sql[768];
    int written = snprintf(sql, sizeof(sql), "%s WHERE tenant_id=? ORDER BY egress_client_name",
        peer_mesh_egress_activity_select());
    sqlite3_stmt *stmt = NULL;
    int rc = written > 0 && (size_t)written < sizeof(sql)
        ? sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) : SQLITE_ERROR;
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
            if (*row_count >= max_rows
                || scan_peer_mesh_egress_activity(stmt, &rows[*row_count]) != 0) {
                rc = SQLITE_ERROR;
                break;
            }
            ++*row_count;
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* Returns 0 on a hit, 1 when the device has never reported, -1 on a storage failure. */
int st_storage_find_peer_mesh_egress_activity(const char *path,
                                              const char *tenant_id,
                                              long long egress_client_id,
                                              st_storage_peer_mesh_egress_activity *out_row)
{
    if (out_row == NULL || egress_client_id <= 0) return -1;
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) return -1;
    char sql[768];
    int written = snprintf(sql, sizeof(sql), "%s WHERE tenant_id=? AND egress_client_id=?",
        peer_mesh_egress_activity_select());
    sqlite3_stmt *stmt = NULL;
    int rc = written > 0 && (size_t)written < sizeof(sql)
        ? sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) : SQLITE_ERROR;
    int result = -1;
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 2, egress_client_id);
        rc = sqlite3_step(stmt);
        if (rc == SQLITE_ROW) result = scan_peer_mesh_egress_activity(stmt, out_row) == 0 ? 0 : -1;
        else if (rc == SQLITE_DONE) result = 1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return result;
}

int st_storage_upsert_peer_mesh_egress_activity(const char *path,
                                                const st_storage_peer_mesh_egress_activity *row)
{
    if (row == NULL || row->egress_client_id <= 0) return -1;
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) return -1;
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT INTO peer_mesh_egress_activity(tenant_id,egress_client_id,egress_client_name,session_id,"
        "revision,active_flows,total_flows,rejected_flows,bytes_in,bytes_out,reported_at,created_at,updated_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP) "
        "ON CONFLICT(tenant_id,egress_client_id) DO UPDATE SET egress_client_name=excluded.egress_client_name,"
        "session_id=excluded.session_id,revision=excluded.revision,active_flows=excluded.active_flows,"
        "total_flows=excluded.total_flows,rejected_flows=excluded.rejected_flows,bytes_in=excluded.bytes_in,"
        "bytes_out=excluded.bytes_out,reported_at=excluded.reported_at,updated_at=CURRENT_TIMESTAMP",
        -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, normalize_tenant_id(row->tenant_id), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 2, row->egress_client_id);
        sqlite3_bind_text(stmt, 3, row->egress_client_name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 4, row->session_id);
        sqlite3_bind_int64(stmt, 5, row->revision);
        sqlite3_bind_int64(stmt, 6, row->active_flows);
        sqlite3_bind_int64(stmt, 7, row->total_flows);
        bind_nullable_text_limit(stmt, 8, row->rejected_flows, 1023);
        sqlite3_bind_int64(stmt, 9, row->bytes_in);
        sqlite3_bind_int64(stmt, 10, row->bytes_out);
        sqlite3_bind_text(stmt, 11, row->reported_at, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    } else rc = -1;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc;
}

int st_storage_get_peer_mesh_egress_switch(const char *path,
                                           const char *tenant_id,
                                           st_storage_peer_mesh_egress_switch *out_row)
{
    if (out_row == NULL) return -1;
    memset(out_row, 0, sizeof(*out_row));
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) return -1;
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT tenant_id,enabled,updated_by,updated_at FROM peer_mesh_egress_switch WHERE tenant_id=?",
        -1, &stmt, NULL);
    int result = -1;
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt);
        if (rc == SQLITE_ROW) {
            out_row->enabled = sqlite3_column_int(stmt, 1) != 0;
            result = copy_text_column(stmt, 0, out_row->tenant_id, sizeof(out_row->tenant_id)) == 0
                && copy_text_column(stmt, 2, out_row->updated_by, sizeof(out_row->updated_by)) == 0
                && copy_text_column(stmt, 3, out_row->updated_at, sizeof(out_row->updated_at)) == 0 ? 0 : -1;
        } else if (rc == SQLITE_DONE) {
            result = 1;
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return result;
}

int st_storage_upsert_peer_mesh_egress_switch(const char *path,
                                              const st_storage_peer_mesh_egress_switch *row)
{
    if (row == NULL) return -1;
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) return -1;
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT INTO peer_mesh_egress_switch(tenant_id,enabled,updated_by,updated_at) "
        "VALUES(?,?,?,CURRENT_TIMESTAMP) "
        "ON CONFLICT(tenant_id) DO UPDATE SET enabled=excluded.enabled,"
        "updated_by=excluded.updated_by,updated_at=CURRENT_TIMESTAMP",
        -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, normalize_tenant_id(row->tenant_id), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 2, row->enabled ? 1 : 0);
        bind_nullable_text_limit(stmt, 3, row->updated_by, 127);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    } else rc = -1;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc;
}

int st_storage_record_peer_mesh_service_audit(const char *path,
                                              const char *action,
                                              const char *tenant_id,
                                              long long client_id,
                                              long long session_id,
                                              const char *service_id,
                                              const char *reason)
{
    if (action == NULL || *action == '\0') return -1;
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) return -1;
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT INTO peer_mesh_service_audit(action,tenant_id,client_id,session_id,service_id,reason) "
        "VALUES(?,?,?,?,?,?)", -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, action, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
        if (client_id > 0) sqlite3_bind_int64(stmt, 3, client_id); else sqlite3_bind_null(stmt, 3);
        if (session_id > 0) sqlite3_bind_int64(stmt, 4, session_id); else sqlite3_bind_null(stmt, 4);
        bind_nullable_text_limit(stmt, 5, service_id, 64);
        bind_nullable_text_limit(stmt, 6, reason, 255);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    } else rc = -1;
    sqlite3_finalize(stmt);
    if (rc == 0) {
        rc = sqlite3_prepare_v2(db,
            "DELETE FROM peer_mesh_service_audit WHERE tenant_id=? AND id NOT IN "
            "(SELECT id FROM peer_mesh_service_audit WHERE tenant_id=? ORDER BY id DESC LIMIT 80)",
            -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
            rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
        } else rc = -1;
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    return rc;
}

int st_storage_list_peer_mesh_service_audits(const char *path,
                                             const char *tenant_id,
                                             st_storage_peer_mesh_service_audit *events,
                                             size_t max_events,
                                             size_t *event_count)
{
    if (events == NULL || event_count == NULL) return -1;
    *event_count = 0U;
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) return -1;
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT at,action,tenant_id,client_id,session_id,service_id,reason "
        "FROM peer_mesh_service_audit WHERE tenant_id=? ORDER BY id DESC LIMIT ?",
        -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 2, (sqlite3_int64)max_events);
        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
            if (*event_count >= max_events) { rc = SQLITE_ERROR; break; }
            st_storage_peer_mesh_service_audit *event = &events[(*event_count)++];
            memset(event, 0, sizeof(*event));
            event->client_id = sqlite3_column_type(stmt, 3) == SQLITE_NULL ? 0 : sqlite3_column_int64(stmt, 3);
            event->session_id = sqlite3_column_type(stmt, 4) == SQLITE_NULL ? 0 : sqlite3_column_int64(stmt, 4);
            if (copy_text_column(stmt, 0, event->at, sizeof(event->at)) != 0
                || copy_text_column(stmt, 1, event->action, sizeof(event->action)) != 0
                || copy_text_column(stmt, 2, event->tenant_id, sizeof(event->tenant_id)) != 0
                || copy_text_column(stmt, 5, event->service_id, sizeof(event->service_id)) != 0
                || copy_text_column(stmt, 6, event->reason, sizeof(event->reason)) != 0) {
                rc = SQLITE_ERROR;
                break;
            }
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == SQLITE_DONE ? 0 : -1;
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
    if (st_elasticsearch_traffic_enabled_current()) {
        return st_elasticsearch_list_http(path,
                                          client_id,
                                          route,
                                          response_body_type,
                                          field,
                                          query,
                                          tenant_id,
                                          owner_username,
                                          include_all_clients,
                                          page,
                                          size,
                                          items,
                                          max_items,
                                          item_count,
                                          total_count);
    }
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
    /* Summary projection: the headers and previews stay unread (Java summarySourceFilter). */
    written = snprintf(sql,
                       sizeof(sql),
                       "SELECT h.id, h.tenant_id, h.client_id, h.client_name, h.route, h.resource_id, "
                       "h.resource_name, h.method, h.relative_path, h.raw_query, h.status_code, h.success, "
                       "h.error, h.remote_address, h.request_bytes, h.response_bytes, h.elapsed_ms, "
                       "h.request_content_type, h.response_content_type, h.response_body_type, "
                       "NULL, NULL, NULL, NULL, NULL, NULL, h.request_truncated, "
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

int st_storage_get_http_exchange_visible(const char *path,
                                         long long exchange_id,
                                         const char *tenant_id,
                                         const char *owner_username,
                                         int include_all_clients,
                                         st_storage_http_exchange *item,
                                         int *found)
{
    if (st_elasticsearch_traffic_enabled_current()) {
        return st_elasticsearch_get_http(path, exchange_id, tenant_id, owner_username, include_all_clients,
                                         item, found);
    }
    *found = 0;
    if (exchange_id <= 0) {
        return 0;
    }
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        include_all_clients
            ? "SELECT h.id, h.tenant_id, h.client_id, h.client_name, h.route, h.resource_id, "
              "h.resource_name, h.method, h.relative_path, h.raw_query, h.status_code, h.success, "
              "h.error, h.remote_address, h.request_bytes, h.response_bytes, h.elapsed_ms, "
              "h.request_content_type, h.response_content_type, h.response_body_type, "
              "h.request_headers, h.response_headers, h.request_preview_hex, h.request_preview_text, "
              "h.response_preview_hex, h.response_preview_text, h.request_truncated, "
              "h.response_truncated, h.captured_at "
              "FROM specus_http_traffic_exchange h JOIN client_account c ON c.rowid = h.client_id "
              "WHERE h.id = ? AND c.tenant_id = ?"
            : "SELECT h.id, h.tenant_id, h.client_id, h.client_name, h.route, h.resource_id, "
              "h.resource_name, h.method, h.relative_path, h.raw_query, h.status_code, h.success, "
              "h.error, h.remote_address, h.request_bytes, h.response_bytes, h.elapsed_ms, "
              "h.request_content_type, h.response_content_type, h.response_body_type, "
              "h.request_headers, h.response_headers, h.request_preview_hex, h.request_preview_text, "
              "h.response_preview_hex, h.response_preview_text, h.request_truncated, "
              "h.response_truncated, h.captured_at "
              "FROM specus_http_traffic_exchange h JOIN client_account c ON c.rowid = h.client_id "
              "WHERE h.id = ? AND c.tenant_id = ? AND c.owner_username = ?",
        -1,
        &stmt,
        NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, exchange_id);
    sqlite3_bind_text(stmt, 2, normalize_tenant_id(tenant_id), -1, SQLITE_TRANSIENT);
    if (!include_all_clients) {
        sqlite3_bind_text(stmt, 3, normalize_owner_username(owner_username), -1, SQLITE_TRANSIENT);
    }
    rc = sqlite3_step(stmt);
    int result = 0;
    if (rc == SQLITE_ROW) {
        result = scan_http_exchange(stmt, item) == 0 ? 0 : -1;
        *found = result == 0;
    } else if (rc != SQLITE_DONE) {
        result = -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return result;
}

int st_storage_record_tcp_frame(const char *path, const st_storage_tcp_frame_record *record)
{
    if (st_elasticsearch_traffic_enabled_current()) {
        return st_elasticsearch_record_tcp(record);
    }
    if (record == NULL || record->client_id <= 0 || record->client_name == NULL
        || record->channel_id == NULL || record->direction == NULL) {
        return -1;
    }
    size_t preview_bytes = st_traffic_preview_bytes();
    char payload_hex[ST_TRAFFIC_PREVIEW_HEX_CAP];
    char payload_text[ST_TRAFFIC_PREVIEW_TEXT_CAP];
    st_traffic_hex_preview(record->payload_data, record->payload_data_len, preview_bytes,
                           payload_hex, sizeof(payload_hex));
    st_traffic_tcp_text_preview(record->payload_data, record->payload_data_len, preview_bytes,
                                payload_text, sizeof(payload_text));
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
    if (st_elasticsearch_traffic_enabled_current()) {
        return st_elasticsearch_list_tcp(path,
                                         client_id,
                                         listen_port,
                                         tenant_id,
                                         owner_username,
                                         include_all_clients,
                                         page,
                                         size,
                                         items,
                                         max_items,
                                         item_count,
                                         total_count);
    }
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
    if (st_elasticsearch_traffic_enabled_current()) {
        return st_elasticsearch_get_tcp(path,
                                        id,
                                        tenant_id,
                                        owner_username,
                                        include_all_clients,
                                        frame);
    }
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
    if (st_elasticsearch_traffic_enabled_current()) {
        return st_elasticsearch_list_tcp_stream(path,
                                                channel_id,
                                                tenant_id,
                                                owner_username,
                                                include_all_clients,
                                                limit,
                                                items,
                                                max_items,
                                                item_count);
    }
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

/* ---- Service workbench --------------------------------------------------------------------- */

/* The fixed kind order that breaks ties: http-route, tcp-mapping, peer-service. */
#define ST_WORKBENCH_KIND_ORDER_SQL \
    "CASE kind WHEN 'http-route' THEN 0 WHEN 'tcp-mapping' THEN 1 ELSE 2 END"

void st_storage_workbench_document_free(st_storage_workbench_document *doc)
{
    if (doc == NULL) {
        return;
    }
    free(doc->favorites);
    memset(doc, 0, sizeof(*doc));
}

static int workbench_scan_entry(sqlite3_stmt *stmt, st_storage_workbench_entry *entry)
{
    memset(entry, 0, sizeof(*entry));
    entry->object_id = sqlite3_column_int64(stmt, 1);
    entry->at_ms = sqlite3_column_int64(stmt, 2);
    return copy_text_column(stmt, 0, entry->kind, sizeof(entry->kind));
}

/* Prepares sql and binds the identity to ?1 (tenant_id) and ?2 (username). */
static int workbench_prepare(sqlite3 *db,
                             const char *sql,
                             const char *tenant_id,
                             const char *username,
                             sqlite3_stmt **stmt)
{
    *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, stmt, NULL) != SQLITE_OK
        || sqlite3_bind_text(*stmt, 1, tenant_id, -1, SQLITE_TRANSIENT) != SQLITE_OK
        || sqlite3_bind_text(*stmt, 2, username, -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        sqlite3_finalize(*stmt);
        *stmt = NULL;
        return -1;
    }
    return 0;
}

static int workbench_read_document(sqlite3 *db,
                                   const char *tenant_id,
                                   const char *username,
                                   long long now_ms,
                                   st_storage_workbench_document *doc)
{
    memset(doc, 0, sizeof(*doc));
    sqlite3_stmt *stmt = NULL;
    if (workbench_prepare(db,
            "SELECT kind, object_id, at_ms FROM management_workbench_item "
            "WHERE tenant_id = ?1 AND username = ?2 AND list = 'favorite' "
            "ORDER BY at_ms ASC, " ST_WORKBENCH_KIND_ORDER_SQL " ASC, object_id ASC",
            tenant_id, username, &stmt) != 0) {
        return -1;
    }
    size_t capacity = 0U;
    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (doc->favorites_len == capacity) {
            size_t next = capacity == 0U ? 16U : capacity * 2U;
            st_storage_workbench_entry *grown = (st_storage_workbench_entry *)realloc(
                doc->favorites, next * sizeof(st_storage_workbench_entry));
            if (grown == NULL) {
                rc = SQLITE_NOMEM;
                break;
            }
            doc->favorites = grown;
            capacity = next;
        }
        if (workbench_scan_entry(stmt, &doc->favorites[doc->favorites_len]) != 0) {
            rc = SQLITE_ERROR;
            break;
        }
        ++doc->favorites_len;
    }
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        st_storage_workbench_document_free(doc);
        return -1;
    }
    /* A recent entry is visible while now - visitedAt < 30 days, i.e. visitedAt > now - 30 days. */
    if (workbench_prepare(db,
            "SELECT kind, object_id, at_ms FROM management_workbench_item "
            "WHERE tenant_id = ?1 AND username = ?2 AND list = 'recent' AND at_ms > ?3 "
            "ORDER BY at_ms DESC, " ST_WORKBENCH_KIND_ORDER_SQL " ASC, object_id ASC LIMIT ?4",
            tenant_id, username, &stmt) != 0
        || sqlite3_bind_int64(stmt, 3, now_ms - ST_STORAGE_WORKBENCH_RECENT_RETENTION_MS) != SQLITE_OK
        || sqlite3_bind_int(stmt, 4, ST_STORAGE_WORKBENCH_MAX_RECENTS) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        st_storage_workbench_document_free(doc);
        return -1;
    }
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (doc->recents_len >= ST_STORAGE_WORKBENCH_MAX_RECENTS
            || workbench_scan_entry(stmt, &doc->recents[doc->recents_len]) != 0) {
            rc = SQLITE_ERROR;
            break;
        }
        ++doc->recents_len;
    }
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        st_storage_workbench_document_free(doc);
        return -1;
    }
    return 0;
}

int st_storage_workbench_read(const char *path,
                              const char *tenant_id,
                              const char *username,
                              long long now_ms,
                              st_storage_workbench_document *doc)
{
    if (doc == NULL) {
        return -1;
    }
    memset(doc, 0, sizeof(*doc));
    if (path == NULL || tenant_id == NULL || username == NULL) {
        return -1;
    }
    /* Read-only, like the account lookup: reading the workbench never creates or changes anything. */
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_busy_timeout(db, 5000);
    /* One read transaction, so both lists come from the same snapshot. */
    int rc = exec_sql(db, "BEGIN");
    if (rc == 0) {
        rc = workbench_read_document(db, tenant_id, username, now_ms, doc);
        if (rc == 0) {
            rc = exec_sql(db, "COMMIT");
        } else {
            (void)exec_sql(db, "ROLLBACK");
        }
    }
    sqlite3_close(db);
    if (rc != 0) {
        st_storage_workbench_document_free(doc);
        return -1;
    }
    return 0;
}

/*
 * The client that carries the object, as the kind's list endpoint sees it: 0 when found, 1 when
 * there is no such object (or its route or mapping has no client), -1 when the store failed.
 */
static int workbench_object_client(sqlite3 *db, const char *kind, long long object_id, st_storage_client *client)
{
    const char *sql = NULL;
    if (strcmp(kind, "http-route") == 0) {
        sql = "SELECT c.rowid, c.tenant_id, c.owner_username FROM http_route_mapping r "
              "JOIN client_account c ON c.client_name = r.client_name WHERE r.id = ?";
    } else if (strcmp(kind, "tcp-mapping") == 0) {
        sql = "SELECT c.rowid, c.tenant_id, c.owner_username FROM specus_mapping m "
              "JOIN client_account c ON c.client_name = m.client_name WHERE m.id = ?";
    } else if (strcmp(kind, "peer-service") == 0) {
        /* Peer services are listed by their own tenant; the owner is that of the client. */
        sql = "SELECT COALESCE(c.rowid, 0), s.tenant_id, COALESCE(c.owner_username, '') "
              "FROM peer_mesh_shared_service s LEFT JOIN client_account c ON c.rowid = s.client_id "
              "WHERE s.id = ?";
    } else {
        return 1;
    }
    memset(client, 0, sizeof(*client));
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, object_id);
    int rc = sqlite3_step(stmt);
    int result;
    if (rc == SQLITE_ROW) {
        client->id = sqlite3_column_int64(stmt, 0);
        result = copy_text_column(stmt, 1, client->tenant_id, sizeof(client->tenant_id)) == 0
                && copy_text_column(stmt, 2, client->owner_username, sizeof(client->owner_username)) == 0
            ? 0 : -1;
    } else {
        result = rc == SQLITE_DONE ? 1 : -1;
    }
    sqlite3_finalize(stmt);
    return result;
}

static int workbench_count_favorites(sqlite3 *db, const char *tenant_id, const char *username, long long *count)
{
    sqlite3_stmt *stmt = NULL;
    if (workbench_prepare(db,
            "SELECT COUNT(*) FROM management_workbench_item "
            "WHERE tenant_id = ?1 AND username = ?2 AND list = 'favorite'",
            tenant_id, username, &stmt) != 0) {
        return -1;
    }
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *count = sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return rc == SQLITE_ROW ? 0 : -1;
}

static int workbench_favorite_exists(sqlite3 *db,
                                     const st_storage_workbench_write_request *request,
                                     int *exists)
{
    sqlite3_stmt *stmt = NULL;
    if (workbench_prepare(db,
            "SELECT 1 FROM management_workbench_item WHERE tenant_id = ?1 AND username = ?2 "
            "AND list = 'favorite' AND kind = ?3 AND object_id = ?4",
            request->tenant_id, request->username, &stmt) != 0
        || sqlite3_bind_text(stmt, 3, request->kind, -1, SQLITE_TRANSIENT) != SQLITE_OK
        || sqlite3_bind_int64(stmt, 4, request->object_id) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return -1;
    }
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    *exists = rc == SQLITE_ROW;
    return rc == SQLITE_ROW || rc == SQLITE_DONE ? 0 : -1;
}

/*
 * Writes one reference at now. A row that is already there keeps the later of the two times, so
 * an instance whose clock is behind never moves a recent entry back.
 */
static int workbench_upsert(sqlite3 *db, const st_storage_workbench_write_request *request, const char *list)
{
    sqlite3_stmt *stmt = NULL;
    if (workbench_prepare(db,
            "INSERT INTO management_workbench_item(tenant_id, username, list, kind, object_id, at_ms) "
            "VALUES(?1, ?2, ?3, ?4, ?5, ?6) "
            "ON CONFLICT(tenant_id, username, list, kind, object_id) "
            "DO UPDATE SET at_ms = max(at_ms, excluded.at_ms)",
            request->tenant_id, request->username, &stmt) != 0
        || sqlite3_bind_text(stmt, 3, list, -1, SQLITE_STATIC) != SQLITE_OK
        || sqlite3_bind_text(stmt, 4, request->kind, -1, SQLITE_TRANSIENT) != SQLITE_OK
        || sqlite3_bind_int64(stmt, 5, request->object_id) != SQLITE_OK
        || sqlite3_bind_int64(stmt, 6, request->now_ms) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return -1;
    }
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* Deletes one reference of a list, or the whole list when request->kind is NULL. */
static int workbench_delete(sqlite3 *db, const st_storage_workbench_write_request *request, const char *list)
{
    sqlite3_stmt *stmt = NULL;
    int single = request->kind != NULL;
    if (workbench_prepare(db,
            single
                ? "DELETE FROM management_workbench_item WHERE tenant_id = ?1 AND username = ?2 "
                  "AND list = ?3 AND kind = ?4 AND object_id = ?5"
                : "DELETE FROM management_workbench_item WHERE tenant_id = ?1 AND username = ?2 "
                  "AND list = ?3",
            request->tenant_id, request->username, &stmt) != 0
        || sqlite3_bind_text(stmt, 3, list, -1, SQLITE_STATIC) != SQLITE_OK
        || (single && sqlite3_bind_text(stmt, 4, request->kind, -1, SQLITE_TRANSIENT) != SQLITE_OK)
        || (single && sqlite3_bind_int64(stmt, 5, request->object_id) != SQLITE_OK)) {
        sqlite3_finalize(stmt);
        return -1;
    }
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 0 : -1;
}

/*
 * After every successful write the identity's recents are kept within the contract: expired rows
 * (now - at >= 30 days) are deleted, then every row ranked after the 20th. Deleted, not hidden.
 */
static int workbench_normalize_recents(sqlite3 *db, const st_storage_workbench_write_request *request)
{
    sqlite3_stmt *stmt = NULL;
    if (workbench_prepare(db,
            "DELETE FROM management_workbench_item WHERE tenant_id = ?1 AND username = ?2 "
            "AND list = 'recent' AND at_ms <= ?3",
            request->tenant_id, request->username, &stmt) != 0
        || sqlite3_bind_int64(stmt, 3, request->now_ms - ST_STORAGE_WORKBENCH_RECENT_RETENTION_MS)
            != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return -1;
    }
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        return -1;
    }
    if (workbench_prepare(db,
            "DELETE FROM management_workbench_item WHERE tenant_id = ?1 AND username = ?2 "
            "AND list = 'recent' AND rowid NOT IN ("
            "SELECT rowid FROM management_workbench_item WHERE tenant_id = ?1 AND username = ?2 "
            "AND list = 'recent' "
            "ORDER BY at_ms DESC, " ST_WORKBENCH_KIND_ORDER_SQL " ASC, object_id ASC LIMIT ?3)",
            request->tenant_id, request->username, &stmt) != 0
        || sqlite3_bind_int(stmt, 3, ST_STORAGE_WORKBENCH_MAX_RECENTS) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return -1;
    }
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 0 : -1;
}

int st_storage_workbench_write(const char *path,
                               const st_storage_workbench_write_request *request,
                               st_storage_workbench_document *doc)
{
    if (doc == NULL) {
        return -1;
    }
    memset(doc, 0, sizeof(*doc));
    if (path == NULL || request == NULL || request->tenant_id == NULL || request->username == NULL) {
        return -1;
    }
    st_storage_workbench_write_op op = request->op;
    int growth = op == ST_STORAGE_WORKBENCH_ADD_FAVORITE || op == ST_STORAGE_WORKBENCH_RECORD_VISIT;
    int clearing = op == ST_STORAGE_WORKBENCH_CLEAR_FAVORITES || op == ST_STORAGE_WORKBENCH_CLEAR_RECENTS;
    if ((!clearing && request->kind == NULL) || (clearing && request->kind != NULL)
        || (growth && request->visible == NULL)) {
        return -1;
    }
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    /* IMMEDIATE serialises writers, so the favourite bound holds under concurrent adds. */
    if (exec_sql(db, "BEGIN IMMEDIATE") != 0) {
        sqlite3_close(db);
        return -1;
    }
    /*
     * The identity's rows are read first: a store that cannot be read fails here, before the
     * visibility of the target is looked at, so it answers as unavailable even for an object
     * that does not exist.
     */
    long long favorites = 0;
    int result = workbench_count_favorites(db, request->tenant_id, request->username, &favorites);
    if (result == 0 && growth) {
        st_storage_client client;
        int found = workbench_object_client(db, request->kind, request->object_id, &client);
        if (found < 0) {
            result = -1;
        } else if (found > 0 || !request->visible(request->visible_ctx, &client)) {
            result = ST_STORAGE_WORKBENCH_TARGET_NOT_FOUND;
        }
    }
    if (result == 0) {
        switch (op) {
        case ST_STORAGE_WORKBENCH_ADD_FAVORITE: {
            /* Adding one that is there changes nothing, its addedAt included, even at the bound. */
            int exists = 0;
            result = workbench_favorite_exists(db, request, &exists);
            if (result == 0 && !exists) {
                result = favorites >= ST_STORAGE_WORKBENCH_MAX_FAVORITES
                    ? ST_STORAGE_WORKBENCH_FAVORITES_FULL
                    : workbench_upsert(db, request, "favorite");
            }
            break;
        }
        case ST_STORAGE_WORKBENCH_RECORD_VISIT:
            result = workbench_upsert(db, request, "recent");
            break;
        case ST_STORAGE_WORKBENCH_REMOVE_FAVORITE:
        case ST_STORAGE_WORKBENCH_CLEAR_FAVORITES:
            result = workbench_delete(db, request, "favorite");
            break;
        case ST_STORAGE_WORKBENCH_REMOVE_RECENT:
        case ST_STORAGE_WORKBENCH_CLEAR_RECENTS:
            result = workbench_delete(db, request, "recent");
            break;
        default:
            result = -1;
            break;
        }
    }
    if (result == 0) {
        result = workbench_normalize_recents(db, request);
    }
    if (result == 0) {
        result = workbench_read_document(db, request->tenant_id, request->username, request->now_ms, doc);
    }
    if (result == 0 && exec_sql(db, "COMMIT") != 0) {
        result = -1;
    }
    if (result != 0) {
        (void)exec_sql(db, "ROLLBACK");
        st_storage_workbench_document_free(doc);
    }
    sqlite3_close(db);
    return result;
}

int st_storage_workbench_sweep(const char *path, long long now_ms)
{
    sqlite3 *db = NULL;
    if (path == NULL || open_db(path, &db) != 0) {
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "DELETE FROM management_workbench_item WHERE list = 'recent' AND at_ms <= ?",
        -1,
        &stmt,
        NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, now_ms - ST_STORAGE_WORKBENCH_RECENT_RETENTION_MS);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc;
}

/* ------------------------------------------------------------------------------------------------
 * Temporary HTTP shares (protocol/spec/temporary-http-share.md): share rows and the access audit.
 * "now" arrives in epoch milliseconds so expiry (now >= expires_at) is exact at full precision;
 * rows keep whole seconds. Every decision reads the share, route, client and creator afresh.
 */

#define ST_SHARE_COLUMNS \
    "share_id, tenant_id, route_id, token_sha256, access, path_prefix, label, created_by, " \
    "created_at, expires_at, revoked_at, revoked_by, revoke_reason, expiry_recorded"

static atomic_int share_store_failing;

void st_storage_http_share_fail_for_testing(int failing)
{
    atomic_store(&share_store_failing, failing ? 1 : 0);
}

static int share_open_db(const char *path, sqlite3 **db)
{
    *db = NULL;
    if (path == NULL || atomic_load(&share_store_failing)) {
        return -1;
    }
    return open_db(path, db);
}

static int share_begin(sqlite3 *db)
{
    return exec_sql(db, "BEGIN IMMEDIATE");
}

/* Commits when rc is 0 and rolls back otherwise; a failed commit turns into -1. */
static int share_end(sqlite3 *db, int rc)
{
    if (rc == 0) {
        if (exec_sql(db, "COMMIT") == 0) {
            return 0;
        }
        rc = -1;
    }
    (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    return rc;
}

int st_storage_share_ids_add(st_storage_share_ids *ids, const char *share_id)
{
    if (ids == NULL) {
        return 0;
    }
    if (ids->len == ids->cap) {
        size_t next = ids->cap == 0U ? 8U : ids->cap * 2U;
        char (*grown)[17] = realloc(ids->ids, next * sizeof(*grown));
        if (grown == NULL) {
            return -1;
        }
        ids->ids = grown;
        ids->cap = next;
    }
    snprintf(ids->ids[ids->len], sizeof(ids->ids[ids->len]), "%s", share_id);
    ++ids->len;
    return 0;
}

void st_storage_share_ids_free(st_storage_share_ids *ids)
{
    if (ids == NULL) {
        return;
    }
    free(ids->ids);
    ids->ids = NULL;
    ids->len = 0U;
    ids->cap = 0U;
}

static const char *share_exposure(int enabled, int auth_enabled)
{
    return !enabled ? "disabled" : (auth_enabled ? "protected" : "public");
}

/* One audit row (spec 8); it never carries a token, hash, label, credential or visitor data. */
static int share_audit(sqlite3 *db,
                       const char *tenant_id,
                       long long at,
                       const char *actor,
                       const char *action,
                       long long route_id,
                       const char *share_id,
                       const char *detail_json)
{
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT INTO http_access_audit(tenant_id, occurred_at, actor, action, route_id, share_id, detail_json) "
        "VALUES(?,?,?,?,?,?,?)",
        -1,
        &stmt,
        NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, tenant_id == NULL ? "" : tenant_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 2, at);
        bind_nullable_text(stmt, 3, actor);
        sqlite3_bind_text(stmt, 4, action, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 5, route_id);
        bind_nullable_text(stmt, 6, share_id);
        sqlite3_bind_text(stmt, 7, detail_json, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    } else {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    return rc;
}

static int share_scan(sqlite3_stmt *stmt, st_storage_http_share *share)
{
    memset(share, 0, sizeof(*share));
    if (copy_text_column(stmt, 0, share->share_id, sizeof(share->share_id)) != 0
        || copy_text_column(stmt, 1, share->tenant_id, sizeof(share->tenant_id)) != 0
        || copy_text_column(stmt, 3, share->token_sha256, sizeof(share->token_sha256)) != 0
        || copy_text_column(stmt, 4, share->access, sizeof(share->access)) != 0
        || copy_text_column(stmt, 5, share->path_prefix, sizeof(share->path_prefix)) != 0
        || copy_text_column(stmt, 7, share->created_by, sizeof(share->created_by)) != 0) {
        return -1;
    }
    share->route_id = sqlite3_column_int64(stmt, 2);
    if (sqlite3_column_type(stmt, 6) != SQLITE_NULL) {
        if (copy_text_column(stmt, 6, share->label, sizeof(share->label)) != 0) {
            return -1;
        }
        share->has_label = share->label[0] != '\0';
    }
    share->created_at = sqlite3_column_int64(stmt, 8);
    share->expires_at = sqlite3_column_int64(stmt, 9);
    if (sqlite3_column_type(stmt, 10) != SQLITE_NULL) {
        share->revoked = 1;
        share->revoked_at = sqlite3_column_int64(stmt, 10);
    }
    if (sqlite3_column_type(stmt, 11) != SQLITE_NULL) {
        if (copy_text_column(stmt, 11, share->revoked_by, sizeof(share->revoked_by)) != 0) {
            return -1;
        }
        share->has_revoked_by = 1;
    }
    if (sqlite3_column_type(stmt, 12) != SQLITE_NULL
        && copy_text_column(stmt, 12, share->revoke_reason, sizeof(share->revoke_reason)) != 0) {
        return -1;
    }
    share->expiry_recorded = sqlite3_column_int(stmt, 13) != 0;
    return 0;
}

/* Steps a prepared share query into a malloc'd array and finalizes it. */
static int share_collect(sqlite3_stmt *stmt, st_storage_http_share **shares, size_t *count)
{
    *shares = NULL;
    *count = 0U;
    size_t capacity = 0U;
    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (*count == capacity) {
            size_t next = capacity == 0U ? 8U : capacity * 2U;
            st_storage_http_share *grown = realloc(*shares, next * sizeof(*grown));
            if (grown == NULL) {
                rc = SQLITE_NOMEM;
                break;
            }
            *shares = grown;
            capacity = next;
        }
        if (share_scan(stmt, &(*shares)[*count]) != 0) {
            rc = SQLITE_ERROR;
            break;
        }
        ++*count;
    }
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        free(*shares);
        *shares = NULL;
        *count = 0U;
        return -1;
    }
    return 0;
}

/* 0 found, 1 missing, -1 on error. */
static int share_load(sqlite3 *db, const char *share_id, st_storage_http_share *share)
{
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "SELECT " ST_SHARE_COLUMNS " FROM http_share WHERE share_id = ?",
                           -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, share_id, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    int result = rc == SQLITE_ROW ? (share_scan(stmt, share) == 0 ? 0 : -1) : (rc == SQLITE_DONE ? 1 : -1);
    sqlite3_finalize(stmt);
    return result;
}

static int share_is_active(const st_storage_http_share *share, long long now_ms)
{
    return !share->revoked && share->expires_at * 1000LL > now_ms;
}

/* Active shares selected by one bound value (route id or client name), oldest first. */
static int share_select_active(sqlite3 *db,
                               const char *sql,
                               long long route_id,
                               const char *text,
                               const char *text2,
                               long long now_ms,
                               st_storage_http_share **shares,
                               size_t *count)
{
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return -1;
    }
    int index = 1;
    if (text != NULL) {
        sqlite3_bind_text(stmt, index++, text, -1, SQLITE_TRANSIENT);
    }
    if (text2 != NULL) {
        sqlite3_bind_text(stmt, index++, text2, -1, SQLITE_TRANSIENT);
    }
    if (route_id > 0) {
        sqlite3_bind_int64(stmt, index++, route_id);
    }
    sqlite3_bind_int64(stmt, index, now_ms);
    return share_collect(stmt, shares, count);
}

static int share_active_of_route(sqlite3 *db, long long route_id, long long now_ms,
                                 st_storage_http_share **shares, size_t *count)
{
    return share_select_active(db,
        "SELECT " ST_SHARE_COLUMNS " FROM http_share WHERE route_id = ? "
        "AND revoked_at IS NULL AND expires_at * 1000 > ? ORDER BY created_at, share_id",
        route_id, NULL, NULL, now_ms, shares, count);
}

static int share_active_of_client(sqlite3 *db, const char *client_name, long long now_ms,
                                  st_storage_http_share **shares, size_t *count)
{
    return share_select_active(db,
        "SELECT " ST_SHARE_COLUMNS " FROM http_share "
        "WHERE route_id IN (SELECT id FROM http_route_mapping WHERE client_name = ?) "
        "AND revoked_at IS NULL AND expires_at * 1000 > ? ORDER BY created_at, share_id",
        0, client_name, NULL, now_ms, shares, count);
}

typedef struct {
    int route_found;
    int client_found;
    long long route_id;
    char route_name[128];
    char client_name[256];
    int route_enabled;
    int auth_enabled;
    int path_rewrite_enabled;
    long long client_id;
    char tenant_id[128];
    char owner_username[128];
    int client_enabled;
    char target_base_url[512];
} share_target;

/* The route by id with its client, which a route reaches by name and may have lost. */
static int share_load_target(sqlite3 *db, long long route_id, share_target *target)
{
    memset(target, 0, sizeof(*target));
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT r.id, r.route, r.client_name, r.enabled, r.auth_enabled, r.path_rewrite_enabled, "
            "c.rowid, c.tenant_id, c.owner_username, c.enabled, r.target_base_url "
            "FROM http_route_mapping r LEFT JOIN client_account c ON c.client_name = r.client_name "
            "WHERE r.id = ?",
            -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, route_id);
    int rc = sqlite3_step(stmt);
    int result = 0;
    if (rc == SQLITE_ROW) {
        target->route_found = 1;
        target->route_id = sqlite3_column_int64(stmt, 0);
        if (copy_text_column(stmt, 1, target->route_name, sizeof(target->route_name)) != 0
            || copy_text_column(stmt, 2, target->client_name, sizeof(target->client_name)) != 0
            || copy_text_column(stmt, 10, target->target_base_url, sizeof(target->target_base_url)) != 0) {
            result = -1;
        }
        target->route_enabled = sqlite3_column_int(stmt, 3) != 0;
        target->auth_enabled = sqlite3_column_int(stmt, 4) != 0;
        target->path_rewrite_enabled = sqlite3_column_int(stmt, 5) != 0;
        if (sqlite3_column_type(stmt, 6) != SQLITE_NULL) {
            target->client_found = 1;
            target->client_id = sqlite3_column_int64(stmt, 6);
            if (copy_text_column(stmt, 7, target->tenant_id, sizeof(target->tenant_id)) != 0
                || copy_text_column(stmt, 8, target->owner_username, sizeof(target->owner_username)) != 0) {
                result = -1;
            }
            target->client_enabled = sqlite3_column_int(stmt, 9) != 0;
        }
    } else if (rc != SQLITE_DONE) {
        result = -1;
    }
    sqlite3_finalize(stmt);
    return result;
}

typedef struct {
    int exists;
    int enabled;
    int admin;
    char username[128];
    char tenant_id[128];
} share_principal;

static int share_ascii_casecmp(const char *left, const char *right)
{
    while (*left != '\0' && *right != '\0') {
        int a = tolower((unsigned char)*left++);
        int b = tolower((unsigned char)*right++);
        if (a != b) {
            return a - b;
        }
    }
    return tolower((unsigned char)*left) - tolower((unsigned char)*right);
}

static int share_role_is_admin(const char *role)
{
    while (*role == ' ' || *role == '\t') {
        ++role;
    }
    size_t len = strlen(role);
    while (len > 0U && (role[len - 1U] == ' ' || role[len - 1U] == '\t')) {
        --len;
    }
    char trimmed[16];
    if (len >= sizeof(trimmed)) {
        return 0;
    }
    memcpy(trimmed, role, len);
    trimmed[len] = '\0';
    return share_ascii_casecmp(trimmed, "ADMIN") == 0;
}

/*
 * A user as the management API sees it now. The built-in admin has no row: under its configured
 * tenant it is an ADMIN that is enabled while it may sign in, as admin_resolve_token_user treats it.
 */
static int share_load_principal(sqlite3 *db,
                                const st_storage_share_builtin_admin *builtin,
                                const char *username,
                                const char *tenant_hint,
                                share_principal *principal)
{
    memset(principal, 0, sizeof(*principal));
    if (username == NULL || *username == '\0') {
        return 0;
    }
    if (builtin != NULL && builtin->username != NULL && builtin->username[0] != '\0'
        && builtin->tenant_id != NULL && share_ascii_casecmp(username, builtin->username) == 0
        && (tenant_hint == NULL || tenant_hint[0] == '\0'
            || share_ascii_casecmp(tenant_hint, builtin->tenant_id) == 0)) {
        principal->exists = 1;
        principal->enabled = builtin->accepted != 0;
        principal->admin = 1;
        snprintf(principal->username, sizeof(principal->username), "%s", builtin->username);
        snprintf(principal->tenant_id, sizeof(principal->tenant_id), "%s", builtin->tenant_id);
        return 0;
    }
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT username, tenant_id, role, enabled FROM specus_management_user "
            "WHERE lower(username) = lower(?)",
            -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    int result = 0;
    if (rc == SQLITE_ROW) {
        char role[32];
        if (copy_text_column(stmt, 0, principal->username, sizeof(principal->username)) != 0
            || copy_text_column(stmt, 1, principal->tenant_id, sizeof(principal->tenant_id)) != 0
            || copy_text_column(stmt, 2, role, sizeof(role)) != 0) {
            result = -1;
        } else {
            principal->exists = 1;
            principal->admin = share_role_is_admin(role);
            principal->enabled = sqlite3_column_int(stmt, 3) != 0;
        }
    } else if (rc != SQLITE_DONE) {
        result = -1;
    }
    sqlite3_finalize(stmt);
    return result;
}

/* The route management rule, evaluated now: same tenant, and an admin or the client's owner. */
static int share_can_manage(const share_principal *principal, const share_target *target)
{
    return principal->exists && principal->enabled && target->route_found && target->client_found
        && strcmp(principal->tenant_id, target->tenant_id) == 0
        && (principal->admin || strcmp(target->owner_username, principal->username) == 0);
}

/* Spec 7.2: why an active share can no longer be honoured, first match wins; NULL when it can. */
static int share_lapse_reason(sqlite3 *db,
                              const st_storage_share_builtin_admin *builtin,
                              const st_storage_http_share *share,
                              const share_target *target,
                              const char **reason)
{
    *reason = NULL;
    if (!target->route_found || (target->client_found && strcmp(target->tenant_id, share->tenant_id) != 0)) {
        *reason = "route-deleted";
    } else if (!target->client_found) {
        *reason = "client-deleted";
    } else if (!target->client_enabled) {
        *reason = "client-disabled";
    } else if (!target->route_enabled) {
        *reason = "route-disabled";
    } else if (!target->auth_enabled) {
        *reason = "route-made-public";
    } else {
        share_principal creator;
        if (share_load_principal(db, builtin, share->created_by, share->tenant_id, &creator) != 0) {
            return -1;
        }
        if (!share_can_manage(&creator, target)) {
            *reason = "creator-lost-access";
        }
    }
    return 0;
}

/*
 * The conditional revoke of spec 7.4: only a share that is neither revoked nor expired changes,
 * so concurrent instances write one audit row. 1 when this call ended it, 0 when it had already
 * ended, -1 on error. Runs inside the caller's transaction.
 */
static int share_revoke_row(sqlite3 *db,
                            const st_storage_http_share *share,
                            const char *actor,
                            const char *reason,
                            long long now_ms)
{
    long long now_s = now_ms / 1000LL;
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "UPDATE http_share SET revoked_at = ?, revoked_by = ?, revoke_reason = ? "
        "WHERE share_id = ? AND revoked_at IS NULL AND expires_at * 1000 > ?",
        -1,
        &stmt,
        NULL);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, now_s);
    bind_nullable_text(stmt, 2, actor);
    sqlite3_bind_text(stmt, 3, reason, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, share->share_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 5, now_ms);
    rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    int changed = rc == 0 && sqlite3_changes(db) == 1;
    sqlite3_finalize(stmt);
    if (rc != 0) {
        return -1;
    }
    if (!changed) {
        return 0;
    }
    char detail[96];
    snprintf(detail, sizeof(detail), "{\"reason\":\"%s\"}", reason);
    return share_audit(db, share->tenant_id, now_s, actor, "share.revoked", share->route_id,
                       share->share_id, detail) == 0 ? 1 : -1;
}

static int share_revoke_each(sqlite3 *db,
                             const st_storage_http_share *shares,
                             size_t count,
                             const char *actor,
                             const char *reason,
                             long long now_ms,
                             st_storage_share_ids *revoked)
{
    for (size_t i = 0U; i < count; ++i) {
        int changed = share_revoke_row(db, &shares[i], actor, reason, now_ms);
        if (changed < 0 || (changed == 1 && st_storage_share_ids_add(revoked, shares[i].share_id) != 0)) {
            return -1;
        }
    }
    return 0;
}

/* Revokes in place, each in its own transaction, the given active shares that have lapsed. */
static int share_revoke_lapsed_list(sqlite3 *db,
                                    const st_storage_share_builtin_admin *builtin,
                                    const st_storage_http_share *shares,
                                    size_t count,
                                    long long now_ms,
                                    st_storage_share_ids *revoked)
{
    for (size_t i = 0U; i < count; ++i) {
        share_target target;
        const char *reason = NULL;
        if (share_load_target(db, shares[i].route_id, &target) != 0
            || share_lapse_reason(db, builtin, &shares[i], &target, &reason) != 0) {
            return -1;
        }
        if (reason == NULL) {
            continue;
        }
        int rc = share_begin(db);
        int changed = rc == 0 ? share_revoke_row(db, &shares[i], NULL, reason, now_ms) : -1;
        if (share_end(db, changed < 0 ? -1 : 0) != 0) {
            return -1;
        }
        if (changed == 1 && st_storage_share_ids_add(revoked, shares[i].share_id) != 0) {
            return -1;
        }
    }
    return 0;
}

int st_storage_http_share_caller_can_manage(const char *path,
                                            const st_storage_share_builtin_admin *builtin,
                                            const char *caller,
                                            const char *caller_tenant,
                                            long long route_id,
                                            int *allowed)
{
    *allowed = 0;
    sqlite3 *db = NULL;
    if (share_open_db(path, &db) != 0) {
        return -1;
    }
    share_target target;
    share_principal principal;
    int rc = share_load_target(db, route_id, &target);
    if (rc == 0) {
        rc = share_load_principal(db, builtin, caller, caller_tenant, &principal);
    }
    if (rc == 0) {
        *allowed = share_can_manage(&principal, &target);
    }
    sqlite3_close(db);
    return rc;
}

int st_storage_http_share_caller_is_admin(const char *path,
                                          const st_storage_share_builtin_admin *builtin,
                                          const char *caller,
                                          const char *caller_tenant,
                                          int *admin,
                                          char tenant_id[128])
{
    *admin = 0;
    tenant_id[0] = '\0';
    sqlite3 *db = NULL;
    if (share_open_db(path, &db) != 0) {
        return -1;
    }
    share_principal principal;
    int rc = share_load_principal(db, builtin, caller, caller_tenant, &principal);
    if (rc == 0 && principal.exists && principal.enabled) {
        *admin = principal.admin;
        snprintf(tenant_id, 128U, "%s", principal.tenant_id);
    }
    sqlite3_close(db);
    return rc;
}

int st_storage_http_share_create(const char *path,
                                 const st_storage_share_builtin_admin *builtin,
                                 const char *caller,
                                 const char *caller_tenant,
                                 long long route_id,
                                 const st_storage_http_share *draft,
                                 int max_active,
                                 long long now_ms,
                                 st_storage_http_share *out)
{
    sqlite3 *db = NULL;
    if (share_open_db(path, &db) != 0) {
        return -1;
    }
    share_target target;
    share_principal principal;
    st_storage_http_share row = *draft;
    int rc = share_begin(db);
    if (rc == 0) {
        rc = share_load_target(db, route_id, &target);
    }
    if (rc == 0) {
        rc = share_load_principal(db, builtin, caller, caller_tenant, &principal);
    }
    if (rc == 0) {
        if (!share_can_manage(&principal, &target)) {
            rc = ST_STORAGE_SHARE_ROUTE_NOT_FOUND;
        } else if (!target.route_enabled) {
            rc = ST_STORAGE_SHARE_ROUTE_DISABLED;
        } else if (!target.client_enabled) {
            rc = ST_STORAGE_SHARE_CLIENT_DISABLED;
        } else if (!target.auth_enabled) {
            rc = ST_STORAGE_SHARE_ROUTE_PUBLIC;
        }
    }
    if (rc == 0) {
        /* Only active shares count; the count and the insert share one transaction. */
        sqlite3_stmt *stmt = NULL;
        rc = sqlite3_prepare_v2(db,
            "SELECT COUNT(*) FROM http_share WHERE route_id = ? AND revoked_at IS NULL AND expires_at * 1000 > ?",
            -1, &stmt, NULL) == SQLITE_OK ? 0 : -1;
        if (rc == 0) {
            sqlite3_bind_int64(stmt, 1, target.route_id);
            sqlite3_bind_int64(stmt, 2, now_ms);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                rc = sqlite3_column_int64(stmt, 0) >= max_active ? ST_STORAGE_SHARE_LIMIT_REACHED : 0;
            } else {
                rc = -1;
            }
        }
        sqlite3_finalize(stmt);
    }
    if (rc == 0) {
        snprintf(row.tenant_id, sizeof(row.tenant_id), "%s", target.tenant_id);
        snprintf(row.created_by, sizeof(row.created_by), "%s", principal.username);
        row.route_id = target.route_id;
        row.revoked = 0;
        row.has_revoked_by = 0;
        row.revoke_reason[0] = '\0';
        row.expiry_recorded = 0;
        sqlite3_stmt *stmt = NULL;
        rc = sqlite3_prepare_v2(db,
            "INSERT INTO http_share(share_id, tenant_id, route_id, token_sha256, access, path_prefix, label, "
            "created_by, created_at, expires_at, expiry_recorded) VALUES(?,?,?,?,?,?,?,?,?,?,0)",
            -1, &stmt, NULL) == SQLITE_OK ? 0 : -1;
        if (rc == 0) {
            sqlite3_bind_text(stmt, 1, row.share_id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, row.tenant_id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(stmt, 3, row.route_id);
            sqlite3_bind_text(stmt, 4, row.token_sha256, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 5, row.access, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 6, row.path_prefix, -1, SQLITE_TRANSIENT);
            bind_nullable_text(stmt, 7, row.has_label ? row.label : NULL);
            sqlite3_bind_text(stmt, 8, row.created_by, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(stmt, 9, row.created_at);
            sqlite3_bind_int64(stmt, 10, row.expires_at);
            int step = sqlite3_step(stmt);
            rc = step == SQLITE_DONE ? 0 : (step == SQLITE_CONSTRAINT ? ST_STORAGE_SHARE_ID_TAKEN : -1);
        }
        sqlite3_finalize(stmt);
    }
    if (rc == 0) {
        char expires[32];
        st_http_share_format_time(row.expires_at, expires);
        char *prefix = st_json_escape(row.path_prefix);
        char detail[512];
        int written = prefix == NULL ? -1 : snprintf(detail, sizeof(detail),
                                                     "{\"access\":\"%s\",\"pathPrefix\":\"%s\",\"expiresAt\":\"%s\"}",
                                                     row.access, prefix, expires);
        free(prefix);
        rc = written > 0 && (size_t)written < sizeof(detail)
            ? share_audit(db, row.tenant_id, now_ms / 1000LL, row.created_by, "share.created",
                          row.route_id, row.share_id, detail)
            : -1;
    }
    rc = share_end(db, rc);
    sqlite3_close(db);
    if (rc == 0 && out != NULL) {
        *out = row;
    }
    return rc;
}

int st_storage_http_share_list(const char *path,
                               const st_storage_share_builtin_admin *builtin,
                               long long route_id,
                               const char *share_id,
                               long long now_ms,
                               st_storage_http_share **shares,
                               size_t *count,
                               st_storage_share_ids *revoked)
{
    *shares = NULL;
    *count = 0U;
    sqlite3 *db = NULL;
    if (share_open_db(path, &db) != 0) {
        return -1;
    }
    /* Read-time revoke first, so a share that cannot be used is never listed as active. */
    st_storage_http_share *active = NULL;
    size_t active_count = 0U;
    int rc = share_id == NULL
        ? share_active_of_route(db, route_id, now_ms, &active, &active_count)
        : share_select_active(db,
                              "SELECT " ST_SHARE_COLUMNS " FROM http_share WHERE share_id = ? AND route_id = ? "
                              "AND revoked_at IS NULL AND expires_at * 1000 > ? ORDER BY created_at, share_id",
                              route_id, share_id, NULL, now_ms, &active, &active_count);
    if (rc == 0) {
        rc = share_revoke_lapsed_list(db, builtin, active, active_count, now_ms, revoked);
    }
    free(active);
    if (rc == 0) {
        sqlite3_stmt *stmt = NULL;
        rc = sqlite3_prepare_v2(db,
            share_id == NULL
                ? "SELECT " ST_SHARE_COLUMNS " FROM http_share WHERE route_id = ? ORDER BY created_at DESC, share_id DESC"
                : "SELECT " ST_SHARE_COLUMNS " FROM http_share WHERE route_id = ? AND share_id = ?",
            -1, &stmt, NULL) == SQLITE_OK ? 0 : -1;
        if (rc == 0) {
            sqlite3_bind_int64(stmt, 1, route_id);
            if (share_id != NULL) {
                sqlite3_bind_text(stmt, 2, share_id, -1, SQLITE_TRANSIENT);
            }
            rc = share_collect(stmt, shares, count);
        } else {
            sqlite3_finalize(stmt);
        }
    }
    sqlite3_close(db);
    return rc;
}

int st_storage_http_share_revoke(const char *path,
                                 const st_storage_share_builtin_admin *builtin,
                                 const char *caller,
                                 const char *caller_tenant,
                                 long long route_id,
                                 const char *share_id,
                                 long long now_ms,
                                 st_storage_http_share *out,
                                 int *changed)
{
    *changed = 0;
    sqlite3 *db = NULL;
    if (share_open_db(path, &db) != 0) {
        return -1;
    }
    share_target target;
    share_principal principal;
    st_storage_http_share share;
    int rc = share_begin(db);
    if (rc == 0) {
        rc = share_load_target(db, route_id, &target);
    }
    if (rc == 0) {
        rc = share_load_principal(db, builtin, caller, caller_tenant, &principal);
    }
    if (rc == 0 && !share_can_manage(&principal, &target)) {
        rc = ST_STORAGE_SHARE_ROUTE_NOT_FOUND;
    }
    if (rc == 0) {
        int loaded = share_load(db, share_id, &share);
        rc = loaded < 0 ? -1 : (loaded == 1 || share.route_id != route_id ? ST_STORAGE_SHARE_NOT_FOUND : 0);
    }
    /* Idempotent: an ended share is answered as it is, nothing is written. */
    if (rc == 0 && share_is_active(&share, now_ms)) {
        int revoked = share_revoke_row(db, &share, principal.username, "revoked-by-user", now_ms);
        rc = revoked < 0 ? -1 : 0;
        *changed = revoked == 1;
        if (rc == 0 && revoked == 1) {
            rc = share_load(db, share_id, &share) == 0 ? 0 : -1;
        }
    }
    rc = share_end(db, rc);
    sqlite3_close(db);
    if (rc != 0) {
        *changed = 0;
    } else if (out != NULL) {
        *out = share;
    }
    return rc;
}

int st_storage_http_share_resolve(const char *path,
                                  const st_storage_share_builtin_admin *builtin,
                                  const char *share_id,
                                  long long now_ms,
                                  st_storage_http_share_resolution *out)
{
    memset(out, 0, sizeof(*out));
    sqlite3 *db = NULL;
    if (share_open_db(path, &db) != 0) {
        return -1;
    }
    int loaded = share_load(db, share_id, &out->share);
    int rc = loaded < 0 ? -1 : 0;
    if (loaded == 0) {
        out->found = 1;
        share_target target;
        rc = share_load_target(db, out->share.route_id, &target);
        if (rc == 0) {
            out->route_found = target.route_found;
            out->client_found = target.client_found;
            out->client_id = target.client_id;
            out->path_rewrite_enabled = target.path_rewrite_enabled;
            snprintf(out->client_name, sizeof(out->client_name), "%s", target.client_name);
            snprintf(out->route_name, sizeof(out->route_name), "%s", target.route_name);
            snprintf(out->target_base_url, sizeof(out->target_base_url), "%s", target.target_base_url);
            if (share_is_active(&out->share, now_ms)) {
                rc = share_lapse_reason(db, builtin, &out->share, &target, &out->lapse_reason);
            }
        }
    }
    sqlite3_close(db);
    return rc;
}

int st_storage_http_share_revoke_lapsed(const char *path,
                                        const char *share_id,
                                        const char *reason,
                                        long long now_ms,
                                        int *changed)
{
    *changed = 0;
    sqlite3 *db = NULL;
    if (share_open_db(path, &db) != 0) {
        return -1;
    }
    st_storage_http_share share;
    int rc = share_begin(db);
    int loaded = rc == 0 ? share_load(db, share_id, &share) : -1;
    int revoked = 0;
    if (loaded < 0) {
        rc = -1;
    } else if (loaded == 0) {
        revoked = share_revoke_row(db, &share, NULL, reason, now_ms);
        rc = revoked < 0 ? -1 : 0;
    }
    rc = share_end(db, rc);
    sqlite3_close(db);
    *changed = rc == 0 && revoked == 1;
    return rc;
}

int st_storage_http_share_sweep(const char *path,
                                const st_storage_share_builtin_admin *builtin,
                                long long now_ms,
                                st_storage_share_ids *revoked)
{
    sqlite3 *db = NULL;
    if (share_open_db(path, &db) != 0) {
        return -1;
    }
    /* 1. Each expiry is recorded once, stamped with expiresAt, in expiry order. */
    st_storage_http_share *expired = NULL;
    size_t expired_count = 0U;
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT " ST_SHARE_COLUMNS " FROM http_share WHERE revoked_at IS NULL AND expiry_recorded = 0 "
        "AND expires_at * 1000 <= ? ORDER BY expires_at, share_id",
        -1, &stmt, NULL) == SQLITE_OK ? 0 : -1;
    if (rc == 0) {
        sqlite3_bind_int64(stmt, 1, now_ms);
        rc = share_collect(stmt, &expired, &expired_count);
    } else {
        sqlite3_finalize(stmt);
    }
    for (size_t i = 0U; rc == 0 && i < expired_count; ++i) {
        rc = share_begin(db);
        int changed = 0;
        if (rc == 0) {
            stmt = NULL;
            rc = sqlite3_prepare_v2(db,
                "UPDATE http_share SET expiry_recorded = 1 "
                "WHERE share_id = ? AND revoked_at IS NULL AND expiry_recorded = 0",
                -1, &stmt, NULL) == SQLITE_OK ? 0 : -1;
            if (rc == 0) {
                sqlite3_bind_text(stmt, 1, expired[i].share_id, -1, SQLITE_TRANSIENT);
                rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
                changed = rc == 0 && sqlite3_changes(db) == 1;
            }
            sqlite3_finalize(stmt);
        }
        if (rc == 0 && changed) {
            rc = share_audit(db, expired[i].tenant_id, expired[i].expires_at, NULL, "share.expired",
                             expired[i].route_id, expired[i].share_id, "{}");
        }
        rc = share_end(db, rc);
    }
    free(expired);
    /* 2. The safety net: active shares whose route, client or creator no longer allows them. */
    if (rc == 0) {
        st_storage_http_share *active = NULL;
        size_t active_count = 0U;
        stmt = NULL;
        rc = sqlite3_prepare_v2(db,
            "SELECT " ST_SHARE_COLUMNS " FROM http_share WHERE revoked_at IS NULL AND expires_at * 1000 > ? "
            "ORDER BY created_at, share_id",
            -1, &stmt, NULL) == SQLITE_OK ? 0 : -1;
        if (rc == 0) {
            sqlite3_bind_int64(stmt, 1, now_ms);
            rc = share_collect(stmt, &active, &active_count);
        } else {
            sqlite3_finalize(stmt);
        }
        if (rc == 0) {
            rc = share_revoke_lapsed_list(db, builtin, active, active_count, now_ms, revoked);
        }
        free(active);
    }
    /* 3. Retention: ended shares for 30 days, audit for 180 days. */
    if (rc == 0) {
        long long now_s = now_ms / 1000LL;
        long long share_horizon = now_s - ST_HTTP_SHARE_RETENTION_DAYS * 86400LL;
        long long audit_horizon = now_s - ST_HTTP_SHARE_AUDIT_RETENTION_DAYS * 86400LL;
        stmt = NULL;
        rc = sqlite3_prepare_v2(db,
            "DELETE FROM http_share WHERE (revoked_at IS NOT NULL AND revoked_at < ?1) "
            "OR (revoked_at IS NULL AND expires_at < ?1)",
            -1, &stmt, NULL) == SQLITE_OK ? 0 : -1;
        if (rc == 0) {
            sqlite3_bind_int64(stmt, 1, share_horizon);
            rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
        }
        sqlite3_finalize(stmt);
        if (rc == 0) {
            stmt = NULL;
            rc = sqlite3_prepare_v2(db, "DELETE FROM http_access_audit WHERE occurred_at < ?",
                                    -1, &stmt, NULL) == SQLITE_OK ? 0 : -1;
            if (rc == 0) {
                sqlite3_bind_int64(stmt, 1, audit_horizon);
                rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
            }
            sqlite3_finalize(stmt);
        }
    }
    sqlite3_close(db);
    return rc;
}

int st_storage_http_access_audit_list(const char *path,
                                      const char *tenant_id,
                                      long long route_id,
                                      long long before,
                                      int limit,
                                      st_storage_http_access_audit **entries,
                                      size_t *count,
                                      int *more)
{
    *entries = NULL;
    *count = 0U;
    *more = 0;
    if (limit <= 0) {
        return -1;
    }
    sqlite3 *db = NULL;
    if (share_open_db(path, &db) != 0) {
        return -1;
    }
    char sql[384];
    snprintf(sql, sizeof(sql),
             "SELECT id, occurred_at, actor, action, route_id, share_id, detail_json FROM http_access_audit "
             "WHERE tenant_id = ?%s%s ORDER BY id DESC LIMIT ?",
             route_id > 0 ? " AND route_id = ?" : "",
             before > 0 ? " AND id < ?" : "");
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    int index = 1;
    sqlite3_bind_text(stmt, index++, tenant_id, -1, SQLITE_TRANSIENT);
    if (route_id > 0) {
        sqlite3_bind_int64(stmt, index++, route_id);
    }
    if (before > 0) {
        sqlite3_bind_int64(stmt, index++, before);
    }
    sqlite3_bind_int(stmt, index, limit + 1);
    st_storage_http_access_audit *items = calloc((size_t)limit, sizeof(*items));
    int rc = items == NULL ? SQLITE_NOMEM : SQLITE_OK;
    size_t got = 0U;
    while (items != NULL && (rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (got == (size_t)limit) {
            *more = 1;
            continue;
        }
        st_storage_http_access_audit *item = &items[got];
        item->id = sqlite3_column_int64(stmt, 0);
        item->occurred_at = sqlite3_column_int64(stmt, 1);
        if (sqlite3_column_type(stmt, 2) != SQLITE_NULL) {
            item->has_actor = copy_text_column(stmt, 2, item->actor, sizeof(item->actor)) == 0;
        }
        item->route_id = sqlite3_column_int64(stmt, 4);
        if (sqlite3_column_type(stmt, 5) != SQLITE_NULL) {
            item->has_share_id = copy_text_column(stmt, 5, item->share_id, sizeof(item->share_id)) == 0;
        }
        if (copy_text_column(stmt, 3, item->action, sizeof(item->action)) != 0
            || copy_text_column(stmt, 6, item->detail_json, sizeof(item->detail_json)) != 0) {
            rc = SQLITE_ERROR;
            break;
        }
        ++got;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    if (rc != SQLITE_DONE) {
        free(items);
        *more = 0;
        return -1;
    }
    *entries = items;
    *count = got;
    return 0;
}

/* Spec 7.3 and 8 after a route change: exposure and credentials audit, then the share hooks. */
static int share_route_changed(sqlite3 *db,
                               const char *tenant_id,
                               long long route_id,
                               const char *before,
                               const char *after,
                               int credentials_changed,
                               const char *actor,
                               long long now_ms,
                               st_storage_share_ids *revoked)
{
    long long at = now_ms / 1000LL;
    int rc = 0;
    if (strcmp(before, after) != 0) {
        char detail[96];
        snprintf(detail, sizeof(detail), "{\"from\":\"%s\",\"to\":\"%s\"}", before, after);
        rc = share_audit(db, tenant_id, at, actor, "route.exposure-changed", route_id, NULL, detail);
    }
    if (rc == 0 && credentials_changed) {
        rc = share_audit(db, tenant_id, at, actor, "route.credentials-changed", route_id, NULL, "{}");
    }
    if (rc == 0 && strcmp(after, "protected") != 0) {
        st_storage_http_share *shares = NULL;
        size_t count = 0U;
        rc = share_active_of_route(db, route_id, now_ms, &shares, &count);
        if (rc == 0) {
            rc = share_revoke_each(db, shares, count, actor,
                                   strcmp(after, "disabled") == 0 ? "route-disabled" : "route-made-public",
                                   now_ms, revoked);
        }
        free(shares);
    }
    return rc;
}

typedef struct {
    int found;
    long long id;
    int enabled;
    int auth_enabled;
    char auth_username[121];
    char tenant_id[128];
} share_route_state;

static int share_load_route_state(sqlite3 *db, const char *sql, long long id, const char *client_name,
                                  const char *route, share_route_state *state)
{
    memset(state, 0, sizeof(*state));
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return -1;
    }
    if (id > 0) {
        sqlite3_bind_int64(stmt, 1, id);
    } else {
        sqlite3_bind_text(stmt, 1, client_name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, route, -1, SQLITE_TRANSIENT);
    }
    int rc = sqlite3_step(stmt);
    int result = 0;
    if (rc == SQLITE_ROW) {
        state->found = 1;
        state->id = sqlite3_column_int64(stmt, 0);
        state->enabled = sqlite3_column_int(stmt, 1) != 0;
        state->auth_enabled = sqlite3_column_int(stmt, 2) != 0;
        if (copy_text_column(stmt, 3, state->auth_username, sizeof(state->auth_username)) != 0
            || copy_text_column(stmt, 4, state->tenant_id, sizeof(state->tenant_id)) != 0) {
            result = -1;
        }
    } else if (rc != SQLITE_DONE) {
        result = -1;
    }
    sqlite3_finalize(stmt);
    return result;
}

#define ST_SHARE_ROUTE_STATE_COLUMNS \
    "SELECT r.id, r.enabled, r.auth_enabled, r.auth_username, COALESCE(c.tenant_id, '') " \
    "FROM http_route_mapping r LEFT JOIN client_account c ON c.client_name = r.client_name "

int st_storage_create_http_route_audited(const char *path,
                                         long long client_id,
                                         const char *route,
                                         const char *target_base_url,
                                         int enabled,
                                         int detail_capture_enabled,
                                         int media_capture_enabled,
                                         int path_rewrite_enabled,
                                         int insecure_skip_verify,
                                         int auth_enabled,
                                         const char *auth_username,
                                         const char *auth_password_hash,
                                         int password_set,
                                         const char *actor,
                                         long long now_ms,
                                         st_storage_http_route *out_route,
                                         st_storage_share_ids *revoked)
{
    st_storage_client client;
    if (st_storage_get_client(path, client_id, &client) != 0) {
        return -1;
    }
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    share_route_state existing;
    share_route_state created;
    int rc = share_begin(db);
    if (rc == 0) {
        rc = share_load_route_state(db, ST_SHARE_ROUTE_STATE_COLUMNS "WHERE r.client_name = ? AND r.route = ?",
                                    0, client.client_name, route, &existing);
    }
    if (rc == 0) {
        rc = upsert_http_route_on_db(db, client.client_name, route, target_base_url, enabled,
                                     detail_capture_enabled, media_capture_enabled, path_rewrite_enabled,
                                     insecure_skip_verify, auth_enabled, auth_username, auth_password_hash);
    }
    if (rc == 0) {
        rc = share_load_route_state(db, ST_SHARE_ROUTE_STATE_COLUMNS "WHERE r.client_name = ? AND r.route = ?",
                                    0, client.client_name, route, &created);
        if (rc == 0 && !created.found) {
            rc = -1;
        }
    }
    const char *after = share_exposure(enabled, auth_enabled);
    if (rc == 0 && !existing.found) {
        char detail[64];
        snprintf(detail, sizeof(detail), "{\"exposure\":\"%s\"}", after);
        rc = share_audit(db, client.tenant_id, now_ms / 1000LL, actor, "route.created", created.id, NULL, detail);
    } else if (rc == 0) {
        /* Creating a route that already exists updates it, with the update's audit and hooks. */
        const char *username = auth_username == NULL ? "" : auth_username;
        int credentials_changed = auth_enabled && (strcmp(username, existing.auth_username) != 0 || password_set);
        rc = share_route_changed(db, client.tenant_id, existing.id,
                                 share_exposure(existing.enabled, existing.auth_enabled), after,
                                 credentials_changed, actor, now_ms, revoked);
    }
    rc = share_end(db, rc);
    sqlite3_close(db);
    if (rc != 0) {
        return -1;
    }
    return out_route == NULL
        ? 0
        : st_storage_get_http_route_by_client_route(path, client.client_name, route, out_route);
}

int st_storage_update_http_route_audited(const char *path,
                                         long long id,
                                         const char *route,
                                         const char *target_base_url,
                                         int enabled,
                                         int detail_capture_enabled,
                                         int media_capture_enabled,
                                         int path_rewrite_enabled,
                                         int insecure_skip_verify,
                                         int auth_enabled,
                                         const char *auth_username,
                                         const char *auth_password_hash,
                                         int password_set,
                                         const char *actor,
                                         long long now_ms,
                                         st_storage_http_route *out_route,
                                         st_storage_share_ids *revoked)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    share_route_state before;
    int rc = share_begin(db);
    if (rc == 0) {
        rc = share_load_route_state(db, ST_SHARE_ROUTE_STATE_COLUMNS "WHERE r.id = ?", id, NULL, NULL, &before);
        if (rc == 0 && !before.found) {
            rc = -1;
        }
    }
    if (rc == 0) {
        rc = update_http_route_on_db(db, id, route, target_base_url, enabled, detail_capture_enabled,
                                     media_capture_enabled, path_rewrite_enabled, insecure_skip_verify,
                                     auth_enabled, auth_username, auth_password_hash);
    }
    if (rc == 0) {
        /* A new Basic username, or a new password, while the route asks for Basic. */
        const char *username = auth_username == NULL ? "" : auth_username;
        int credentials_changed = auth_enabled && (strcmp(username, before.auth_username) != 0 || password_set);
        rc = share_route_changed(db, before.tenant_id, id, share_exposure(before.enabled, before.auth_enabled),
                                 share_exposure(enabled, auth_enabled), credentials_changed, actor, now_ms,
                                 revoked);
    }
    rc = share_end(db, rc);
    sqlite3_close(db);
    if (rc != 0) {
        return -1;
    }
    return out_route == NULL ? 0 : load_http_route_by_id(path, id, out_route);
}

int st_storage_delete_http_route_audited(const char *path,
                                         long long id,
                                         const char *actor,
                                         long long now_ms,
                                         st_storage_share_ids *revoked)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    share_route_state before;
    st_storage_http_share *shares = NULL;
    size_t count = 0U;
    int rc = share_begin(db);
    if (rc == 0) {
        rc = share_load_route_state(db, ST_SHARE_ROUTE_STATE_COLUMNS "WHERE r.id = ?", id, NULL, NULL, &before);
        if (rc == 0 && !before.found) {
            rc = -1;
        }
    }
    if (rc == 0) {
        rc = share_active_of_route(db, id, now_ms, &shares, &count);
    }
    if (rc == 0) {
        rc = delete_http_route_on_db(db, id);
    }
    if (rc == 0) {
        char detail[64];
        snprintf(detail, sizeof(detail), "{\"exposure\":\"%s\"}", share_exposure(before.enabled, before.auth_enabled));
        rc = share_audit(db, before.tenant_id, now_ms / 1000LL, actor, "route.deleted", id, NULL, detail);
    }
    if (rc == 0) {
        rc = share_revoke_each(db, shares, count, actor, "route-deleted", now_ms, revoked);
    }
    free(shares);
    rc = share_end(db, rc);
    sqlite3_close(db);
    return rc == 0 ? 0 : -1;
}

typedef struct {
    char tenant_id[128];
    char client_name[256];
    char owner_username[128];
    int enabled;
} share_client_state;

static int share_load_client_state(sqlite3 *db, long long id, share_client_state *state)
{
    memset(state, 0, sizeof(*state));
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT tenant_id, client_name, owner_username, enabled FROM client_account WHERE rowid = ?",
            -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, id);
    int result = sqlite3_step(stmt) == SQLITE_ROW
        && copy_text_column(stmt, 0, state->tenant_id, sizeof(state->tenant_id)) == 0
        && copy_text_column(stmt, 1, state->client_name, sizeof(state->client_name)) == 0
        && copy_text_column(stmt, 2, state->owner_username, sizeof(state->owner_username)) == 0
        ? 0 : -1;
    if (result == 0) {
        state->enabled = sqlite3_column_int(stmt, 3) != 0;
    }
    sqlite3_finalize(stmt);
    return result;
}

int st_storage_update_client_audited(const char *path,
                                     long long id,
                                     const char *client_name,
                                     int enabled,
                                     int connection_rate_limit_per_minute,
                                     const char *actor,
                                     long long now_ms,
                                     st_storage_client *out_client,
                                     st_storage_share_ids *revoked)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    if (connection_rate_limit_per_minute <= 0) {
        connection_rate_limit_per_minute = 30;
    }
    share_client_state before;
    int rc = share_begin(db);
    if (rc == 0) {
        rc = share_load_client_state(db, id, &before);
    }
    if (rc == 0) {
        rc = update_client_on_db(db, id, before.client_name, before.tenant_id, client_name,
                                 before.owner_username, enabled, connection_rate_limit_per_minute);
    }
    if (rc == 0 && before.enabled && !enabled) {
        st_storage_http_share *shares = NULL;
        size_t count = 0U;
        rc = share_active_of_client(db, client_name, now_ms, &shares, &count);
        if (rc == 0) {
            rc = share_revoke_each(db, shares, count, actor, "client-disabled", now_ms, revoked);
        }
        free(shares);
    }
    rc = share_end(db, rc);
    sqlite3_close(db);
    if (rc != 0) {
        return -1;
    }
    return out_client == NULL ? 0 : st_storage_get_client(path, id, out_client);
}

int st_storage_delete_client_audited(const char *path,
                                     long long id,
                                     const char *actor,
                                     long long now_ms,
                                     st_storage_share_ids *revoked)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    share_client_state client;
    long long *route_ids = NULL;
    char (*exposures)[16] = NULL;
    size_t route_count = 0U;
    st_storage_http_share *shares = NULL;
    size_t share_count = 0U;
    int rc = share_begin(db);
    if (rc == 0) {
        rc = share_load_client_state(db, id, &client);
    }
    if (rc == 0) {
        /* Its routes go with it; each gets route.deleted, in ascending id, before the shares end. */
        sqlite3_stmt *stmt = NULL;
        rc = sqlite3_prepare_v2(db,
            "SELECT id, enabled, auth_enabled FROM http_route_mapping WHERE client_name = ? ORDER BY id",
            -1, &stmt, NULL) == SQLITE_OK ? 0 : -1;
        if (rc == 0) {
            sqlite3_bind_text(stmt, 1, client.client_name, -1, SQLITE_TRANSIENT);
            size_t capacity = 0U;
            int step;
            while ((step = sqlite3_step(stmt)) == SQLITE_ROW) {
                if (route_count == capacity) {
                    size_t next = capacity == 0U ? 8U : capacity * 2U;
                    long long *grown_ids = realloc(route_ids, next * sizeof(*grown_ids));
                    if (grown_ids == NULL) {
                        step = SQLITE_NOMEM;
                        break;
                    }
                    route_ids = grown_ids;
                    char (*grown_exposures)[16] = realloc(exposures, next * sizeof(*grown_exposures));
                    if (grown_exposures == NULL) {
                        step = SQLITE_NOMEM;
                        break;
                    }
                    exposures = grown_exposures;
                    capacity = next;
                }
                route_ids[route_count] = sqlite3_column_int64(stmt, 0);
                snprintf(exposures[route_count], sizeof(exposures[route_count]), "%s",
                         share_exposure(sqlite3_column_int(stmt, 1) != 0, sqlite3_column_int(stmt, 2) != 0));
                ++route_count;
            }
            rc = step == SQLITE_DONE ? 0 : -1;
        }
        sqlite3_finalize(stmt);
    }
    if (rc == 0) {
        rc = share_active_of_client(db, client.client_name, now_ms, &shares, &share_count);
    }
    if (rc == 0) {
        rc = delete_client_on_db(db, id, client.client_name);
    }
    for (size_t i = 0U; rc == 0 && i < route_count; ++i) {
        char detail[64];
        snprintf(detail, sizeof(detail), "{\"exposure\":\"%s\"}", exposures[i]);
        rc = share_audit(db, client.tenant_id, now_ms / 1000LL, actor, "route.deleted", route_ids[i], NULL, detail);
    }
    if (rc == 0) {
        rc = share_revoke_each(db, shares, share_count, actor, "client-deleted", now_ms, revoked);
    }
    free(route_ids);
    free(exposures);
    free(shares);
    rc = share_end(db, rc);
    sqlite3_close(db);
    return rc == 0 ? 0 : -1;
}

typedef struct {
    char username[128];
    char tenant_id[128];
    char role[32];
    int enabled;
} share_user_state;

/* 0 found, 1 missing, -1 on error. */
static int share_load_user_state(sqlite3 *db, const char *username, share_user_state *state)
{
    memset(state, 0, sizeof(*state));
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT username, tenant_id, role, enabled FROM specus_management_user WHERE lower(username) = lower(?)",
            -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    int result = rc == SQLITE_DONE ? 1 : -1;
    if (rc == SQLITE_ROW) {
        result = copy_text_column(stmt, 0, state->username, sizeof(state->username)) == 0
            && copy_text_column(stmt, 1, state->tenant_id, sizeof(state->tenant_id)) == 0
            && copy_text_column(stmt, 2, state->role, sizeof(state->role)) == 0
            ? 0 : -1;
        state->enabled = sqlite3_column_int(stmt, 3) != 0;
    }
    sqlite3_finalize(stmt);
    return result;
}

/* The user's own active shares whose creator may no longer manage their route (spec 7.3). */
static int share_revoke_lost_creator(sqlite3 *db,
                                     const st_storage_share_builtin_admin *builtin,
                                     const char *tenant_id,
                                     const char *username,
                                     const char *actor,
                                     long long now_ms,
                                     st_storage_share_ids *revoked)
{
    st_storage_http_share *shares = NULL;
    size_t count = 0U;
    int rc = share_select_active(db,
                                 "SELECT " ST_SHARE_COLUMNS " FROM http_share WHERE tenant_id = ? "
                                 "AND lower(created_by) = lower(?) AND revoked_at IS NULL AND expires_at * 1000 > ? "
                                 "ORDER BY created_at, share_id",
                                 0, tenant_id, username, now_ms, &shares, &count);
    for (size_t i = 0U; rc == 0 && i < count; ++i) {
        share_target target;
        const char *reason = NULL;
        rc = share_load_target(db, shares[i].route_id, &target);
        if (rc == 0) {
            rc = share_lapse_reason(db, builtin, &shares[i], &target, &reason);
        }
        if (rc == 0 && reason != NULL && strcmp(reason, "creator-lost-access") == 0) {
            rc = share_revoke_each(db, &shares[i], 1U, actor, reason, now_ms, revoked);
        }
    }
    free(shares);
    return rc;
}

int st_storage_update_management_user_audited(const char *path,
                                              const st_storage_share_builtin_admin *builtin,
                                              const char *tenant_id,
                                              const char *username,
                                              const char *password_hash,
                                              const char *role,
                                              int enabled,
                                              const char *actor,
                                              long long now_ms,
                                              st_storage_management_user *out_user,
                                              st_storage_share_ids *revoked)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    share_user_state before;
    share_user_state after;
    int rc = share_begin(db);
    if (rc == 0) {
        rc = share_load_user_state(db, username, &before) == 0 ? 0 : -1;
    }
    if (rc == 0) {
        rc = update_management_user_on_db(db, tenant_id, username, password_hash, role, enabled);
    }
    if (rc == 0) {
        rc = share_load_user_state(db, username, &after) == 0 ? 0 : -1;
    }
    /* Disabling a user or changing its role may end the shares it created. */
    if (rc == 0 && (before.enabled != after.enabled || strcmp(before.role, after.role) != 0)) {
        rc = share_revoke_lost_creator(db, builtin, before.tenant_id, before.username, actor, now_ms, revoked);
    }
    rc = share_end(db, rc);
    sqlite3_close(db);
    if (rc != 0) {
        return -1;
    }
    return out_user == NULL ? 0 : st_storage_get_management_user_in_tenant(path, tenant_id, username, out_user);
}

int st_storage_delete_management_user_audited(const char *path,
                                              const st_storage_share_builtin_admin *builtin,
                                              const char *tenant_id,
                                              const char *username,
                                              const char *actor,
                                              long long now_ms,
                                              st_storage_share_ids *revoked)
{
    sqlite3 *db = NULL;
    if (open_db(path, &db) != 0) {
        return -1;
    }
    share_user_state before;
    int rc = share_begin(db);
    if (rc == 0) {
        rc = share_load_user_state(db, username, &before) == 0 ? 0 : -1;
    }
    if (rc == 0) {
        rc = delete_management_user_on_db(db, tenant_id, username);
    }
    if (rc == 0) {
        rc = share_revoke_lost_creator(db, builtin, before.tenant_id, before.username, actor, now_ms, revoked);
    }
    rc = share_end(db, rc);
    sqlite3_close(db);
    return rc == 0 ? 0 : -1;
}
