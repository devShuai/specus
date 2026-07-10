#include "storage.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int test_peer_mesh_acl_direction_migration(void)
{
    char path[256];
    snprintf(path, sizeof(path), "/tmp/shuai-tunnel-c-acl-migration-%ld.db", (long)getpid());
    unlink(path);
    sqlite3 *db = NULL;
    char *error = NULL;
    const char *legacy_schema =
        "CREATE TABLE peer_mesh_acl ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "tenant_id TEXT NOT NULL DEFAULT 'default',"
        "owner_username TEXT NOT NULL DEFAULT 'admin',"
        "source_client_id INTEGER NOT NULL,"
        "source_client_name TEXT NOT NULL,"
        "target_client_id INTEGER NOT NULL,"
        "target_client_name TEXT NOT NULL,"
        "allowed INTEGER NOT NULL DEFAULT 1,"
        "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "UNIQUE(tenant_id, source_client_id, target_client_id));"
        "INSERT INTO peer_mesh_acl(tenant_id, owner_username, source_client_id, source_client_name, "
        "target_client_id, target_client_name, allowed) "
        "VALUES('tenant-migration','OwnerCase',1,'source',2,'target',1);";
    if (sqlite3_open(path, &db) != SQLITE_OK
        || sqlite3_exec(db, legacy_schema, NULL, NULL, &error) != SQLITE_OK) {
        fprintf(stderr, "peer mesh acl legacy schema setup failed: %s\n", error == NULL ? "sqlite error" : error);
        sqlite3_free(error);
        sqlite3_close(db);
        unlink(path);
        return 1;
    }
    sqlite3_close(db);
    if (st_storage_init(path, 0) != 0) {
        fprintf(stderr, "peer mesh acl direction migration failed\n");
        unlink(path);
        return 1;
    }
    st_storage_peer_mesh_acl acl;
    if (st_storage_get_peer_mesh_acl(path, 1, &acl) != 0
        || strcmp(acl.direction, "OUTBOUND") != 0) {
        fprintf(stderr, "peer mesh acl migrated direction default mismatch\n");
        unlink(path);
        return 1;
    }
    unlink(path);
    return 0;
}

int main(void)
{
    if (test_peer_mesh_acl_direction_migration() != 0) {
        return 1;
    }
    char path[256];
    snprintf(path, sizeof(path), "/tmp/shuai-tunnel-c-storage-%ld.db", (long)getpid());
    unlink(path);

    if (st_storage_init(path, 1) != 0) {
        fprintf(stderr, "storage init failed\n");
        unlink(path);
        return 1;
    }

    if (st_storage_client_enabled(path, "Demo client") != 0) {
        fprintf(stderr, "seeded client enabled check failed\n");
        unlink(path);
        return 1;
    }
    st_storage_client seeded_by_name;
    if (st_storage_get_client_by_name(path, "Demo client", &seeded_by_name) != 0
        || strcmp(seeded_by_name.client_name, "Demo client") != 0
        || seeded_by_name.enabled != 1) {
        fprintf(stderr, "seeded client lookup mismatch\n");
        unlink(path);
        return 1;
    }
    st_storage_client clients[4];
    size_t client_count = 0;
    if (st_storage_list_clients(path, clients, 4, &client_count) != 0
        || client_count != 1U
        || clients[0].id <= 0
        || strcmp(clients[0].tenant_id, "default") != 0
        || strcmp(clients[0].owner_username, "admin") != 0
        || strcmp(clients[0].client_name, "Demo client") != 0
        || clients[0].connection_rate_limit_per_minute != 30) {
        fprintf(stderr, "seeded client list mismatch\n");
        unlink(path);
        return 1;
    }

    st_storage_management_user created_user;
    if (st_storage_create_management_user(path,
                                          "alice",
                                          "default",
                                          "hash-value",
                                          "USER",
                                          1,
                                          &created_user) != 0
        || strcmp(created_user.username, "alice") != 0
        || strcmp(created_user.tenant_id, "default") != 0
        || strcmp(created_user.password_hash, "hash-value") != 0
        || strcmp(created_user.role, "USER") != 0
        || created_user.enabled != 1) {
        fprintf(stderr, "management user create mismatch\n");
        unlink(path);
        return 1;
    }
    st_storage_management_user users[4];
    size_t user_count = 0;
    if (st_storage_list_management_users(path, "default", users, 4, &user_count) != 0
        || user_count != 1U
        || strcmp(users[0].username, "alice") != 0) {
        fprintf(stderr, "management user list mismatch\n");
        unlink(path);
        return 1;
    }
    if (st_storage_update_management_user(path, "ALICE", NULL, "ADMIN", 0, &created_user) != 0
        || strcmp(created_user.role, "ADMIN") != 0
        || strcmp(created_user.password_hash, "hash-value") != 0
        || created_user.enabled != 0) {
        fprintf(stderr, "management user update mismatch\n");
        unlink(path);
        return 1;
    }
    if (st_storage_get_management_user(path, "alice", &created_user) != 0
        || strcmp(created_user.username, "alice") != 0
        || created_user.enabled != 0) {
        fprintf(stderr, "management user lookup mismatch\n");
        unlink(path);
        return 1;
    }
    if (st_storage_delete_management_user(path, "alice") != 0
        || st_storage_get_management_user(path, "alice", &created_user) == 0) {
        fprintf(stderr, "management user delete mismatch\n");
        unlink(path);
        return 1;
    }

    st_storage_client_credential credential;
    if (st_storage_upsert_client_credential(path,
                                            0,
                                            "tenant-c",
                                            "owner1",
                                            "api-c",
                                            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                                            1,
                                            3,
                                            &credential) != 0
        || credential.id <= 0
        || strcmp(credential.tenant_id, "tenant-c") != 0
        || strcmp(credential.owner_username, "owner1") != 0
        || strcmp(credential.api_key, "api-c") != 0
        || credential.enabled != 1
        || credential.max_online_instances != 3) {
        fprintf(stderr, "client credential create mismatch\n");
        unlink(path);
        return 1;
    }
    if (st_storage_get_client_credential_by_api_key(path, "api-c", &credential) != 0
        || strcmp(credential.secret_hash, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") != 0) {
        fprintf(stderr, "client credential lookup mismatch\n");
        unlink(path);
        return 1;
    }
    if (st_storage_get_client_credential(path, credential.id, &credential) != 0
        || strcmp(credential.api_key, "api-c") != 0) {
        fprintf(stderr, "client credential lookup by id mismatch\n");
        unlink(path);
        return 1;
    }
    st_storage_client_credential credential_two;
    if (st_storage_upsert_client_credential(path,
                                            0,
                                            "tenant-c",
                                            "owner2",
                                            "api-c2",
                                            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                                            1,
                                            2,
                                            &credential_two) != 0) {
        fprintf(stderr, "second client credential create mismatch\n");
        unlink(path);
        return 1;
    }
    st_storage_client_credential listed_credentials[4];
    size_t listed_credential_count = 0;
    if (st_storage_list_client_credentials(path,
                                           "tenant-c",
                                           listed_credentials,
                                           4,
                                           &listed_credential_count) != 0
        || listed_credential_count < 2U
        || st_storage_delete_client_credential(path, credential_two.id) != 0
        || st_storage_get_client_credential(path, credential_two.id, &credential_two) == 0) {
        fprintf(stderr, "client credential list/delete mismatch\n");
        unlink(path);
        return 1;
    }
    st_storage_client_download_link disabled_download;
    if (st_storage_upsert_client_download_link(path,
                                               0,
                                               "java",
                                               "any",
                                               "any",
                                               "Java exec jar",
                                               "https://example.com/shuai-tunnel.jar",
                                               "cross platform",
                                               20,
                                               0,
                                               &disabled_download) != 0
        || disabled_download.id <= 0
        || disabled_download.enabled != 0
        || strcmp(disabled_download.description, "cross platform") != 0) {
        fprintf(stderr, "client download disabled create mismatch\n");
        unlink(path);
        return 1;
    }
    st_storage_client_download_link enabled_download;
    if (st_storage_upsert_client_download_link(path,
                                               0,
                                               "go",
                                               "linux",
                                               "x64",
                                               "Linux x64",
                                               "https://example.com/shuai-tunnel-linux-amd64",
                                               NULL,
                                               10,
                                               1,
                                               &enabled_download) != 0
        || enabled_download.id <= 0
        || enabled_download.enabled != 1
        || enabled_download.description[0] != '\0') {
        fprintf(stderr, "client download enabled create mismatch\n");
        unlink(path);
        return 1;
    }
    st_storage_client_download_link public_downloads[4];
    size_t public_download_count = 0;
    if (st_storage_list_client_download_links(path,
                                              1,
                                              public_downloads,
                                              4,
                                              &public_download_count) != 0
        || public_download_count != 1U
        || public_downloads[0].id != enabled_download.id) {
        fprintf(stderr, "client download public list mismatch\n");
        unlink(path);
        return 1;
    }
    if (st_storage_upsert_client_download_link(path,
                                               enabled_download.id,
                                               "csharp",
                                               "windows",
                                               "x64",
                                               "Windows x64",
                                               "https://example.com/shuai-tunnel-win-x64.zip",
                                               "windows package",
                                               10,
                                               1,
                                               &enabled_download) != 0
        || strcmp(enabled_download.implementation, "csharp") != 0
        || strcmp(enabled_download.platform, "windows") != 0
        || strcmp(enabled_download.display_name, "Windows x64") != 0) {
        fprintf(stderr, "client download update mismatch\n");
        unlink(path);
        return 1;
    }
    st_storage_client_download_link all_downloads[4];
    size_t all_download_count = 0;
    if (st_storage_list_client_download_links(path,
                                              0,
                                              all_downloads,
                                              4,
                                              &all_download_count) != 0
        || all_download_count != 2U
        || all_downloads[0].id != enabled_download.id
        || all_downloads[1].id != disabled_download.id
        || st_storage_delete_client_download_link(path, disabled_download.id) != 0
        || st_storage_get_client_download_link(path, disabled_download.id, &disabled_download) == 0) {
        fprintf(stderr, "client download admin list/delete mismatch\n");
        unlink(path);
        return 1;
    }
    st_storage_client_identity identity;
    if (st_storage_find_or_create_client_identity(path,
                                                  &credential,
                                                  "machine-1",
                                                  "tester",
                                                  "host-one",
                                                  &identity) != 0
        || identity.id <= 0
        || identity.client_id <= 0
        || strcmp(identity.tenant_id, "tenant-c") != 0
        || strcmp(identity.machine_fingerprint, "machine-1") != 0
        || strcmp(identity.os_user, "tester") != 0
        || strstr(identity.client_name, "host-one-tester-") == NULL) {
        fprintf(stderr, "client identity create mismatch\n");
        unlink(path);
        return 1;
    }
    st_storage_client_identity identity_again;
    if (st_storage_find_or_create_client_identity(path,
                                                  &credential,
                                                  "machine-1",
                                                  "tester",
                                                  "host-two",
                                                  &identity_again) != 0
        || identity_again.id != identity.id
        || strcmp(identity_again.hostname, "host-two") != 0) {
        fprintf(stderr, "client identity update mismatch\n");
        unlink(path);
        return 1;
    }
    st_storage_client_session session;
    memset(&session, 0, sizeof(session));
    snprintf(session.tenant_id, sizeof(session.tenant_id), "%s", identity.tenant_id);
    session.credential_id = credential.id;
    session.identity_id = identity.id;
    session.client_id = identity.client_id;
    snprintf(session.client_name, sizeof(session.client_name), "%s", identity.client_name);
    snprintf(session.token_hash, sizeof(session.token_hash), "%s", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    snprintf(session.status, sizeof(session.status), "%s", "HTTP_AUTHENTICATED");
    snprintf(session.machine_fingerprint, sizeof(session.machine_fingerprint), "%s", "machine-1");
    snprintf(session.os_user, sizeof(session.os_user), "%s", "tester");
    snprintf(session.hostname, sizeof(session.hostname), "%s", "host-two");
    session.message_send_capable = 1;
    session.message_receive_capable = 1;
    session.message_attachments_capable = 1;
    session.message_media_preview_capable = 1;
    session.message_max_attachment_bytes = 16777216;
    snprintf(session.http_login_at, sizeof(session.http_login_at), "%s", "2026-06-25T00:00:00Z");
    snprintf(session.expires_at, sizeof(session.expires_at), "%s", "2026-06-25T08:00:00Z");
    if (st_storage_create_client_session(path, &session, &session) != 0
        || session.id <= 0
        || strcmp(session.status, "HTTP_AUTHENTICATED") != 0
        || strcmp(session.client_name, identity.client_name) != 0
        || !session.message_send_capable
        || !session.message_receive_capable
        || !session.message_attachments_capable
        || !session.message_media_preview_capable
        || session.message_max_attachment_bytes != 16777216) {
        fprintf(stderr, "client session create mismatch\n");
        unlink(path);
        return 1;
    }
    st_storage_client_session login_session;
    int online_count = -1;
    if (st_storage_get_client_session_for_login(path,
                                                session.id,
                                                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                                                &login_session) != 0
        || login_session.id != session.id
        || !login_session.message_send_capable
        || !login_session.message_receive_capable
        || !login_session.message_attachments_capable
        || !login_session.message_media_preview_capable
        || login_session.message_max_attachment_bytes != 16777216
        || st_storage_count_online_sessions_by_machine(path,
                                                       credential.id,
                                                       "machine-1",
                                                       "tester",
                                                       session.id,
                                                       &online_count) != 0
        || online_count != 0
        || st_storage_mark_client_session_online(path,
                                                 session.id,
                                                 "channel-1",
                                                 "127.0.0.1:7010",
                                                 "2026-06-25T00:02:00Z") != 0
        || st_storage_count_online_sessions_by_credential(path,
                                                          credential.id,
                                                          0,
                                                          &online_count) != 0
        || online_count != 1
        || st_storage_mark_client_session_disconnected(path,
                                                       session.id,
                                                       "2026-06-25T00:03:00Z") != 0) {
        fprintf(stderr, "client session runtime state mismatch\n");
        unlink(path);
        return 1;
    }
    st_storage_client capability_client;
    st_storage_peer_mesh_device capability_device;
    if (st_storage_get_client(path, identity.client_id, &capability_client) != 0
        || !capability_client.message_send_capable
        || !capability_client.message_receive_capable
        || !capability_client.message_attachments_capable
        || !capability_client.message_media_preview_capable
        || capability_client.message_max_attachment_bytes != 16777216
        || st_storage_ensure_peer_mesh_device(path, &capability_client, &capability_device) != 0
        || !capability_device.message_attachments_capable
        || capability_device.message_max_attachment_bytes != 16777216) {
        fprintf(stderr, "client message capability projection mismatch\n");
        unlink(path);
        return 1;
    }
    if (st_storage_close_http_authenticated_sessions(path,
                                                     credential.id,
                                                     "machine-1",
                                                     "tester",
                                                     "2026-06-25T00:01:00Z") != 0) {
        fprintf(stderr, "client session close mismatch\n");
        unlink(path);
        return 1;
    }

    st_storage_client created_client;
    if (st_storage_upsert_client(path, 0, "tenant-c", "Managed C", "owner1", 1, 45, &created_client) != 0
        || created_client.id <= 0
        || strcmp(created_client.tenant_id, "tenant-c") != 0
        || strcmp(created_client.client_name, "Managed C") != 0
        || strcmp(created_client.owner_username, "owner1") != 0
        || created_client.connection_rate_limit_per_minute != 45) {
        fprintf(stderr, "client create mismatch\n");
        unlink(path);
        return 1;
    }
    if (st_storage_upsert_client(path, created_client.id, "tenant-c", "Managed C Renamed", "owner2", 0, 12, &created_client) != 0
        || created_client.enabled != 0
        || strcmp(created_client.client_name, "Managed C Renamed") != 0
        || strcmp(created_client.owner_username, "owner2") != 0
        || created_client.connection_rate_limit_per_minute != 12) {
        fprintf(stderr, "client update mismatch\n");
        unlink(path);
        return 1;
    }

    st_storage_client acl_target;
    if (st_storage_upsert_client(path, 0, "tenant-c", "ACL target", "owner2", 1, 30, &acl_target) != 0) {
        fprintf(stderr, "peer mesh acl target create mismatch\n");
        unlink(path);
        return 1;
    }
    st_storage_peer_mesh_acl acl;
    if (st_storage_upsert_peer_mesh_acl(path,
                                        "tenant-c",
                                        "OwnerCase",
                                        &created_client,
                                        &acl_target,
                                        1,
                                        NULL,
                                        &acl) != 0
        || strcmp(acl.direction, "OUTBOUND") != 0) {
        fprintf(stderr, "peer mesh acl default direction mismatch\n");
        unlink(path);
        return 1;
    }
    long long acl_id = acl.id;
    if (st_storage_upsert_peer_mesh_acl(path,
                                        "tenant-c",
                                        "OwnerCase",
                                        &created_client,
                                        &acl_target,
                                        0,
                                        "INBOUND",
                                        &acl) != 0
        || acl.id != acl_id
        || strcmp(acl.direction, "INBOUND") != 0
        || acl.allowed) {
        fprintf(stderr, "peer mesh acl explicit direction update mismatch\n");
        unlink(path);
        return 1;
    }
    if (st_storage_upsert_peer_mesh_acl(path,
                                        "tenant-c",
                                        "OwnerCase",
                                        &created_client,
                                        &acl_target,
                                        1,
                                        NULL,
                                        &acl) != 0
        || acl.id != acl_id
        || strcmp(acl.direction, "INBOUND") != 0
        || !acl.allowed) {
        fprintf(stderr, "peer mesh acl omitted direction should preserve existing value\n");
        unlink(path);
        return 1;
    }
    if (st_storage_upsert_peer_mesh_acl(path,
                                        "tenant-c",
                                        "OwnerCase",
                                        &created_client,
                                        &acl_target,
                                        1,
                                        "SIDEWAYS",
                                        NULL) == 0) {
        fprintf(stderr, "peer mesh acl invalid storage direction should be rejected\n");
        unlink(path);
        return 1;
    }
    st_storage_peer_mesh_acl visible_acls[4];
    size_t visible_acl_count = 0;
    if (st_storage_list_peer_mesh_acls_visible(path,
                                               "tenant-c",
                                               "OwnerCase",
                                               0,
                                               visible_acls,
                                               4,
                                               &visible_acl_count) != 0
        || visible_acl_count != 1U
        || visible_acls[0].id != acl_id
        || st_storage_list_peer_mesh_acls_visible(path,
                                                  "tenant-c",
                                                  "ownercase",
                                                  0,
                                                  visible_acls,
                                                  4,
                                                  &visible_acl_count) != 0
        || visible_acl_count != 0U
        || st_storage_list_peer_mesh_acls_visible(path,
                                                  "TENANT-C",
                                                  "OwnerCase",
                                                  1,
                                                  visible_acls,
                                                  4,
                                                  &visible_acl_count) != 0
        || visible_acl_count != 0U) {
        fprintf(stderr, "peer mesh acl tenant/owner visibility must be case-sensitive\n");
        unlink(path);
        return 1;
    }
    st_storage_client case_variant_target;
    if (st_storage_upsert_client(path, 0, "TENANT-C", "ACL case target", "owner2", 1, 30, &case_variant_target) != 0
        || st_storage_upsert_peer_mesh_acl(path,
                                           "tenant-c",
                                           "OwnerCase",
                                           &created_client,
                                           &case_variant_target,
                                           1,
                                           "OUTBOUND",
                                           NULL) == 0) {
        fprintf(stderr, "peer mesh acl cross-tenant case variant should be rejected\n");
        unlink(path);
        return 1;
    }
    if (st_storage_delete_peer_mesh_acl_visible(path, acl_id, "TENANT-C", "OwnerCase", 1) == 0
        || st_storage_delete_peer_mesh_acl_visible(path, acl_id, "tenant-c", "ownercase", 0) == 0
        || st_storage_delete_peer_mesh_acl_visible(path, acl_id, "tenant-c", "OwnerCase", 0) != 0) {
        fprintf(stderr, "peer mesh acl delete visibility must be case-sensitive\n");
        unlink(path);
        return 1;
    }

    if (st_storage_upsert_mapping(path, "Demo client", 18080, "127.0.0.1", 8080, 1) != 0) {
        fprintf(stderr, "mapping upsert failed\n");
        unlink(path);
        return 1;
    }
    st_storage_mapping mappings[4];
    size_t count = 0;
    if (st_storage_load_mappings(path, "Demo client", mappings, 4, &count) != 0
        || count != 1U
        || mappings[0].listen_port != 18080
        || strcmp(mappings[0].target_address, "127.0.0.1") != 0
        || mappings[0].target_port != 8080
        || mappings[0].enabled != 1
        || mappings[0].detail_capture_enabled != 0) {
        fprintf(stderr, "mapping load mismatch\n");
        unlink(path);
        return 1;
    }
    st_storage_mapping mapping_by_port;
    if (st_storage_get_mapping_by_client_port(path, "Demo client", 18080, &mapping_by_port) != 0
        || mapping_by_port.listen_port != 18080
        || strcmp(mapping_by_port.target_address, "127.0.0.1") != 0) {
        fprintf(stderr, "mapping lookup by client/port mismatch\n");
        unlink(path);
        return 1;
    }
    st_storage_mapping created_mapping;
    if (st_storage_create_mapping_for_client(path, clients[0].id, 19090, "192.168.1.10", 9090, 1, 1, &created_mapping) != 0
        || created_mapping.id <= 0
        || created_mapping.client_id != clients[0].id
        || created_mapping.listen_port != 19090
        || strcmp(created_mapping.target_address, "192.168.1.10") != 0
        || created_mapping.target_port != 9090
        || created_mapping.detail_capture_enabled != 1) {
        fprintf(stderr, "mapping create mismatch\n");
        unlink(path);
        return 1;
    }
    if (st_storage_update_mapping_by_id(path, created_mapping.id, 19091, "192.168.1.11", 9091, 0, 0, &created_mapping) != 0
        || created_mapping.listen_port != 19091
        || strcmp(created_mapping.target_address, "192.168.1.11") != 0
        || created_mapping.target_port != 9091
        || created_mapping.enabled != 0
        || created_mapping.detail_capture_enabled != 0) {
        fprintf(stderr, "mapping update mismatch\n");
        unlink(path);
        return 1;
    }
    count = 0;
    if (st_storage_list_mappings(path, clients[0].id, mappings, 4, &count) != 0 || count != 2U) {
        fprintf(stderr, "mapping list mismatch\n");
        unlink(path);
        return 1;
    }
    if (st_storage_delete_mapping_by_id(path, created_mapping.id) != 0) {
        fprintf(stderr, "mapping delete failed\n");
        unlink(path);
        return 1;
    }
    st_storage_http_route created_route;
    if (st_storage_create_http_route_for_client(path,
                                                clients[0].id,
                                                "api",
                                                "https://example.com/base",
                                                1,
                                                1,
                                                1,
                                                &created_route) != 0
        || created_route.id <= 0
        || created_route.client_id != clients[0].id
        || strcmp(created_route.route, "api") != 0
        || strcmp(created_route.target_base_url, "https://example.com/base") != 0
        || created_route.detail_capture_enabled != 1
        || created_route.path_rewrite_enabled != 1) {
        fprintf(stderr, "http route create mismatch\n");
        unlink(path);
        return 1;
    }
    if (st_storage_update_http_route_by_id(path,
                                           created_route.id,
                                           "web",
                                           "http://127.0.0.1:8088",
                                           0,
                                           0,
                                           0,
                                           &created_route) != 0
        || strcmp(created_route.route, "web") != 0
        || strcmp(created_route.target_base_url, "http://127.0.0.1:8088") != 0
        || created_route.enabled != 0
        || created_route.detail_capture_enabled != 0
        || created_route.path_rewrite_enabled != 0) {
        fprintf(stderr, "http route update mismatch\n");
        unlink(path);
        return 1;
    }
    st_storage_http_route route_by_name;
    if (st_storage_get_http_route_by_client_route(path, "Demo client", "web", &route_by_name) != 0
        || route_by_name.id != created_route.id
        || strcmp(route_by_name.target_base_url, "http://127.0.0.1:8088") != 0) {
        fprintf(stderr, "http route lookup by client/route mismatch\n");
        unlink(path);
        return 1;
    }
    st_storage_http_route routes[4];
    size_t route_count = 0;
    if (st_storage_list_http_routes(path, clients[0].id, routes, 4, &route_count) != 0 || route_count != 1U) {
        fprintf(stderr, "http route list mismatch\n");
        unlink(path);
        return 1;
    }
    if (st_storage_delete_http_route_by_id(path, created_route.id) != 0) {
        fprintf(stderr, "http route delete failed\n");
        unlink(path);
        return 1;
    }
    if (st_storage_delete_client(path, created_client.id) != 0
        || st_storage_get_client(path, created_client.id, &created_client) == 0) {
        fprintf(stderr, "client delete mismatch\n");
        unlink(path);
        return 1;
    }

    if (st_storage_record_connection_detail(path,
                                            clients[0].id,
                                            "Demo client",
                                            "chan-1",
                                            "127.0.0.1:61234",
                                            1,
                                            NULL,
                                            "CLIENT_CLOSED",
                                            "2026-06-22T00:00:00Z",
                                            "2026-06-22T00:05:00Z") != 0) {
        fprintf(stderr, "connection detail record failed\n");
        unlink(path);
        return 1;
    }
    st_storage_connection connections[4];
    size_t connection_count = 0;
    long long total_count = 0;
    if (st_storage_list_connections(path,
                                    clients[0].id,
                                    1,
                                    "2026-06-22T00:00:00Z",
                                    "2026-06-23T00:00:00Z",
                                    0,
                                    10,
                                    connections,
                                    4,
                                    &connection_count,
                                    &total_count) != 0
        || connection_count != 1U
        || total_count != 1
        || strcmp(connections[0].tenant_id, "default") != 0
        || connections[0].client_id != clients[0].id
        || strcmp(connections[0].channel_id, "chan-1") != 0
        || strcmp(connections[0].remote_address, "127.0.0.1:61234") != 0
        || strcmp(connections[0].disconnect_reason, "CLIENT_CLOSED") != 0) {
        fprintf(stderr, "connection list mismatch\n");
        unlink(path);
        return 1;
    }

    long long live_record_id = 0;
    if (st_storage_record_connection_detail_with_id(path,
                                                    clients[0].id,
                                                    "Demo client",
                                                    NULL,
                                                    "127.0.0.1:61235",
                                                    1,
                                                    NULL,
                                                    NULL,
                                                    "2026-06-24T00:00:00Z",
                                                    NULL,
                                                    &live_record_id) != 0
        || live_record_id <= 0
        || st_storage_mark_connection_disconnected(path,
                                                   live_record_id,
                                                   "CLIENT_CLOSED",
                                                   "2026-06-24T00:10:00Z") != 0) {
        fprintf(stderr, "connection update setup failed\n");
        unlink(path);
        return 1;
    }
    connection_count = 0;
    total_count = 0;
    if (st_storage_list_connections(path,
                                    clients[0].id,
                                    1,
                                    "2026-06-24T00:00:00Z",
                                    "2026-06-25T00:00:00Z",
                                    0,
                                    10,
                                    connections,
                                    4,
                                    &connection_count,
                                    &total_count) != 0
        || connection_count != 1U
        || total_count != 1
        || connections[0].id != live_record_id
        || strcmp(connections[0].tenant_id, "default") != 0
        || strcmp(connections[0].disconnect_reason, "CLIENT_CLOSED") != 0
        || strcmp(connections[0].disconnected_at, "2026-06-24T00:10:00Z") != 0) {
        fprintf(stderr, "connection update mismatch\n");
        unlink(path);
        return 1;
    }

    if (st_storage_record_connection(path, "Demo client", 1, NULL, "2026-06-20T00:00:00Z") != 0
        || st_storage_record_connection(path, "Demo client", 0, "LOGIN_FAILURE", "2026-06-20T01:00:00Z") != 0
        || st_storage_archive_connections(path, "2026-06-21T00:00:00Z") != 0) {
        fprintf(stderr, "connection archive setup failed\n");
        unlink(path);
        return 1;
    }
    int successes = 0;
    int failures = 0;
    if (st_storage_load_connection_stat(path, "Demo client", "2026-06-20", &successes, &failures) != 0
        || successes != 1
        || failures != 1) {
        fprintf(stderr, "connection archive mismatch\n");
        unlink(path);
        return 1;
    }
    st_storage_connection_stat stats[4];
    size_t stat_count = 0;
    if (st_storage_list_connection_stats(path, "Demo client", 10, stats, 4, &stat_count) != 0
        || stat_count != 1U
        || strcmp(stats[0].client_name, "Demo client") != 0
        || strcmp(stats[0].month, "2026-06-20") != 0
        || stats[0].total != 2
        || stats[0].success != 1
        || stats[0].failure != 1) {
        fprintf(stderr, "connection stat list mismatch\n");
        unlink(path);
        return 1;
    }
    if (st_storage_record_traffic_usage(path, clients[0].id, "Demo client", "2026-06-22", 123, 456) != 0
        || st_storage_record_traffic_usage(path, clients[0].id, "Demo client", "2026-06-22", 7, 8) != 0) {
        fprintf(stderr, "traffic usage record failed\n");
        unlink(path);
        return 1;
    }
    st_storage_traffic_usage traffic_items[4];
    size_t traffic_count = 0;
    if (st_storage_list_traffic_usage(path, clients[0].id, 10, traffic_items, 4, &traffic_count) != 0
        || traffic_count != 1U
        || traffic_items[0].client_id != clients[0].id
        || strcmp(traffic_items[0].client_name, "Demo client") != 0
        || strcmp(traffic_items[0].usage_date, "2026-06-22") != 0
        || traffic_items[0].upload_bytes != 130
        || traffic_items[0].download_bytes != 464) {
        fprintf(stderr, "traffic usage list mismatch\n");
        unlink(path);
        return 1;
    }
    if (st_storage_record_resource_traffic_usage(path,
                                                 clients[0].id,
                                                 "Demo client",
                                                 "HTTP_ROUTE",
                                                 "http:api",
                                                 12,
                                                 "api -> http://127.0.0.1:8080",
                                                 "2026-06-22",
                                                 321,
                                                 654) != 0) {
        fprintf(stderr, "resource traffic record failed\n");
        unlink(path);
        return 1;
    }
    st_storage_resource_traffic_usage resource_items[4];
    size_t resource_count = 0;
    if (st_storage_list_resource_traffic_usage(path, "HTTP_ROUTE", clients[0].id, 10, resource_items, 4, &resource_count) != 0
        || resource_count != 1U
        || resource_items[0].client_id != clients[0].id
        || strcmp(resource_items[0].resource_type, "HTTP_ROUTE") != 0
        || strcmp(resource_items[0].resource_key, "http:api") != 0
        || resource_items[0].resource_id != 12
        || strcmp(resource_items[0].resource_name, "api -> http://127.0.0.1:8080") != 0
        || resource_items[0].upload_bytes != 321
        || resource_items[0].download_bytes != 654) {
        fprintf(stderr, "resource traffic list mismatch\n");
        unlink(path);
        return 1;
    }

    unlink(path);
    return 0;
}
