#include "storage.h"

#include "peer_egress.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int test_peer_mesh_acl_direction_migration(void)
{
    char path[256];
    snprintf(path, sizeof(path), "/tmp/specus-c-acl-migration-%ld.db", (long)getpid());
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

static int test_http_route_auth_migration(void)
{
    char path[256];
    snprintf(path, sizeof(path), "/tmp/specus-c-http-route-auth-migration-%ld.db", (long)getpid());
    unlink(path);
    sqlite3 *db = NULL;
    char *error = NULL;
    const char *legacy_schema =
        "CREATE TABLE http_route_mapping ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "client_name TEXT NOT NULL,"
        "route TEXT NOT NULL,"
        "target_base_url TEXT NOT NULL,"
        "enabled INTEGER NOT NULL DEFAULT 1,"
        "detail_capture_enabled INTEGER NOT NULL DEFAULT 0,"
        "path_rewrite_enabled INTEGER NOT NULL DEFAULT 0,"
        "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "UNIQUE(client_name, route));"
        "INSERT INTO http_route_mapping(client_name, route, target_base_url) "
        "VALUES('legacy-client','legacy','http://127.0.0.1:8080');";
    if (sqlite3_open(path, &db) != SQLITE_OK
        || sqlite3_exec(db, legacy_schema, NULL, NULL, &error) != SQLITE_OK) {
        fprintf(stderr, "http route auth legacy schema setup failed: %s\n",
                error == NULL ? "sqlite error" : error);
        sqlite3_free(error);
        sqlite3_close(db);
        unlink(path);
        return 1;
    }
    sqlite3_close(db);
    if (st_storage_init(path, 0) != 0) {
        fprintf(stderr, "http route auth migration failed\n");
        unlink(path);
        return 1;
    }
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK
        || sqlite3_prepare_v2(db,
                              "SELECT insecure_skip_verify, auth_enabled, auth_username, auth_password_hash "
                              "FROM http_route_mapping WHERE route = 'legacy'",
                              -1,
                              &stmt,
                              NULL) != SQLITE_OK
        || sqlite3_step(stmt) != SQLITE_ROW
        || sqlite3_column_int(stmt, 0) != 0
        || sqlite3_column_int(stmt, 1) != 0
        || strcmp((const char *)sqlite3_column_text(stmt, 2), "") != 0
        || strcmp((const char *)sqlite3_column_text(stmt, 3), "") != 0) {
        fprintf(stderr, "http route auth migrated defaults mismatch\n");
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        unlink(path);
        return 1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    unlink(path);
    return 0;
}

/*
 * A session table from before the egress-catalog carried domainTargetCapable. Startup must add the
 * column rather than fail on the new SELECT/INSERT lists, and rows already there must read as not
 * having declared it: the catalogue only offers name resolution a device actually announced.
 */
static int test_client_session_domain_targets_migration(void)
{
    char path[256];
    snprintf(path, sizeof(path), "/tmp/specus-c-session-domain-migration-%ld.db", (long)getpid());
    unlink(path);
    sqlite3 *db = NULL;
    char *error = NULL;
    const char *legacy_schema =
        "CREATE TABLE specus_client_session ("
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
        "client_egress_version INTEGER NOT NULL DEFAULT 0);"
        "INSERT INTO specus_client_session(tenant_id, credential_id, identity_id, client_id, client_name, "
        "token_hash, status, machine_fingerprint, os_user, expires_at, client_egress_version) "
        "VALUES('tenant-migration',1,1,7,'legacy-egress','legacy-token','NETTY_ONLINE','machine','user',"
        "'2026-06-25T08:00:00Z',1);";
    if (sqlite3_open(path, &db) != SQLITE_OK
        || sqlite3_exec(db, legacy_schema, NULL, NULL, &error) != SQLITE_OK) {
        fprintf(stderr, "client session legacy schema setup failed: %s\n",
                error == NULL ? "sqlite error" : error);
        sqlite3_free(error);
        sqlite3_close(db);
        unlink(path);
        return 1;
    }
    sqlite3_close(db);
    if (st_storage_init(path, 0) != 0) {
        fprintf(stderr, "client session domain targets migration failed\n");
        unlink(path);
        return 1;
    }
    st_storage_client_session legacy;
    if (st_storage_get_client_session_for_login(path, 1, "legacy-token", &legacy) != 0
        || legacy.client_egress_version != 1
        || legacy.client_egress_domain_targets != 0) {
        fprintf(stderr, "client session migrated domain targets default mismatch\n");
        unlink(path);
        return 1;
    }

    /* The added column is written by new logins like any other. */
    st_storage_client_session fresh = legacy;
    snprintf(fresh.token_hash, sizeof(fresh.token_hash), "%s", "fresh-token");
    snprintf(fresh.status, sizeof(fresh.status), "%s", "HTTP_AUTHENTICATED");
    snprintf(fresh.http_login_at, sizeof(fresh.http_login_at), "%s", "2026-06-25T00:00:00Z");
    fresh.client_egress_domain_targets = 1;
    if (st_storage_create_client_session(path, &fresh, &fresh) != 0
        || fresh.id == legacy.id
        || fresh.client_egress_version != 1
        || !fresh.client_egress_domain_targets) {
        fprintf(stderr, "client session domain targets after migration mismatch\n");
        unlink(path);
        return 1;
    }
    unlink(path);
    return 0;
}

/*
 * Egress policy storage. The judgment layer itself is covered by the shared vectors in
 * peer_egress_tests; what is checked here is that a policy survives a round trip and that a
 * disabled one leaves the enabled-only listing that catalogue building reads.
 */
static int test_peer_mesh_egress_policy_round_trip(void)
{
    char path[256];
    snprintf(path, sizeof(path), "/tmp/specus-c-egress-%ld.db", (long)getpid());
    unlink(path);
    if (st_storage_init(path, 0) != 0) {
        fprintf(stderr, "storage init failed\n");
        return 1;
    }

    int failures = 0;
    st_storage_peer_mesh_egress_policy policy;
    memset(&policy, 0, sizeof(policy));
    snprintf(policy.tenant_id, sizeof(policy.tenant_id), "default");
    snprintf(policy.owner_username, sizeof(policy.owner_username), "owner");
    policy.egress_client_id = 2002;
    snprintf(policy.egress_client_name, sizeof(policy.egress_client_name), "office-gateway");
    policy.enabled = 1;
    snprintf(policy.scope, sizeof(policy.scope), "%s", ST_EGRESS_SCOPE_PUBLIC);
    snprintf(policy.allowed_consumer_client_ids, sizeof(policy.allowed_consumer_client_ids), "1001");
    snprintf(policy.destination_rules, sizeof(policy.destination_rules),
             "[{\"cidr\":\"203.0.113.0/24\",\"protocols\":[\"tcp\"],\"portRanges\":[[443,443]]}]");
    policy.max_concurrent_flows = 256;
    policy.max_flows_per_consumer = 64;
    policy.idle_timeout_seconds = 60;

    st_storage_peer_mesh_egress_policy saved;
    if (st_storage_upsert_peer_mesh_egress_policy(path, &policy, &saved) != 0) {
        fprintf(stderr, "egress policy insert failed\n");
        unlink(path);
        return failures + 1;
    }
    if (saved.id <= 0 || saved.egress_client_id != 2002 || !saved.enabled
        || strcmp(saved.scope, ST_EGRESS_SCOPE_PUBLIC) != 0
        || strcmp(saved.destination_rules, policy.destination_rules) != 0
        || strcmp(saved.domain_rules, "[]") != 0
        || saved.max_flows_per_consumer != 64) {
        fprintf(stderr, "egress policy did not round trip\n");
        failures++;
    }
    snprintf(saved.domain_rules, sizeof(saved.domain_rules),
             "[{\"match\":\"*.cdn.example\",\"protocols\":[\"tcp\"],\"portRanges\":[[443,443]]}]");
    st_storage_peer_mesh_egress_policy with_names;
    if (st_storage_upsert_peer_mesh_egress_policy(path, &saved, &with_names) != 0
        || strcmp(with_names.domain_rules, saved.domain_rules) != 0
        || strcmp(with_names.destination_rules, policy.destination_rules) != 0) {
        fprintf(stderr, "egress policy domain rules did not round trip\n");
        failures++;
    }

    st_storage_peer_mesh_egress_policy found;
    if (st_storage_find_peer_mesh_egress_policy_by_client(path, "default", 2002, &found) != 0
        || found.id != saved.id) {
        fprintf(stderr, "egress policy lookup by client failed\n");
        failures++;
    }
    /* A tenant that has never configured egress must read as absent rather than as an error. */
    if (st_storage_find_peer_mesh_egress_policy_by_client(path, "default", 4242, &found) != 1) {
        fprintf(stderr, "a missing policy must read as absent\n");
        failures++;
    }

    /*
     * A disabled policy must disappear from the enabled-only listing, which is what catalogue
     * building reads: switching the device off has to stop it being offered, not merely stop new
     * flows at the far end.
     */
    saved.enabled = 0;
    snprintf(saved.allowed_consumer_client_ids, sizeof(saved.allowed_consumer_client_ids), "1001,1002");
    if (st_storage_upsert_peer_mesh_egress_policy(path, &saved, NULL) != 0) {
        fprintf(stderr, "egress policy update failed\n");
        failures++;
    }
    st_storage_peer_mesh_egress_policy listed[8];
    size_t count = 0U;
    if (st_storage_list_peer_mesh_egress_policies(path, "default", 1, listed, 8U, &count) != 0
        || count != 0U) {
        fprintf(stderr, "a disabled policy is still listed as enabled\n");
        failures++;
    }
    if (st_storage_list_peer_mesh_egress_policies(path, "default", 0, listed, 8U, &count) != 0
        || count != 1U
        || strcmp(listed[0].allowed_consumer_client_ids, "1001,1002") != 0) {
        fprintf(stderr, "the update did not persist\n");
        failures++;
    }

    if (st_storage_delete_peer_mesh_egress_policy(path, saved.id, "default") != 0
        || st_storage_get_peer_mesh_egress_policy(path, saved.id, "default", &found) != 1) {
        fprintf(stderr, "egress policy delete failed\n");
        failures++;
    }
    unlink(path);
    return failures;
}

/*
 * An egress policy table from before domain rules. Startup must add the column rather than fail on
 * the new SELECT/INSERT lists, and a policy already there must read as granting no name.
 */
static int test_peer_mesh_egress_domain_rules_migration(void)
{
    char path[256];
    snprintf(path, sizeof(path), "/tmp/specus-c-egress-domain-migration-%ld.db", (long)getpid());
    unlink(path);
    sqlite3 *db = NULL;
    char *error = NULL;
    const char *legacy_schema =
        "CREATE TABLE peer_mesh_egress_policy ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,tenant_id TEXT NOT NULL,owner_username TEXT NOT NULL,"
        "egress_client_id INTEGER NOT NULL,egress_client_name TEXT NOT NULL,"
        "enabled INTEGER NOT NULL DEFAULT 0,scope TEXT NOT NULL DEFAULT 'PUBLIC',"
        "allowed_consumer_client_ids TEXT,destination_rules TEXT,"
        "max_concurrent_flows INTEGER NOT NULL DEFAULT 256,"
        "max_flows_per_consumer INTEGER NOT NULL DEFAULT 64,"
        "idle_timeout_seconds INTEGER NOT NULL DEFAULT 60,"
        "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "UNIQUE(tenant_id,egress_client_id));"
        "INSERT INTO peer_mesh_egress_policy(tenant_id,owner_username,egress_client_id,egress_client_name,"
        "enabled,scope,allowed_consumer_client_ids,destination_rules) "
        "VALUES('default','owner',2002,'office-gateway',1,'PUBLIC','1001',"
        "'[{\"cidr\":\"203.0.113.0/24\",\"protocols\":[\"tcp\"],\"portRanges\":[[443,443]]}]');";
    if (sqlite3_open(path, &db) != SQLITE_OK
        || sqlite3_exec(db, legacy_schema, NULL, NULL, &error) != SQLITE_OK) {
        fprintf(stderr, "egress policy legacy schema setup failed: %s\n",
                error == NULL ? "sqlite error" : error);
        sqlite3_free(error);
        sqlite3_close(db);
        unlink(path);
        return 1;
    }
    sqlite3_close(db);
    if (st_storage_init(path, 0) != 0) {
        fprintf(stderr, "egress policy domain rules migration failed\n");
        unlink(path);
        return 1;
    }
    st_storage_peer_mesh_egress_policy legacy;
    if (st_storage_find_peer_mesh_egress_policy_by_client(path, "default", 2002, &legacy) != 0
        || strcmp(legacy.domain_rules, "[]") != 0
        || strstr(legacy.destination_rules, "203.0.113.0/24") == NULL) {
        fprintf(stderr, "a migrated egress policy did not read as granting no name\n");
        unlink(path);
        return 1;
    }
    snprintf(legacy.domain_rules, sizeof(legacy.domain_rules),
             "[{\"match\":\"example.com\",\"protocols\":[\"tcp\"],\"portRanges\":[[443,443]]}]");
    st_storage_peer_mesh_egress_policy saved;
    if (st_storage_upsert_peer_mesh_egress_policy(path, &legacy, &saved) != 0
        || strcmp(saved.domain_rules, legacy.domain_rules) != 0) {
        fprintf(stderr, "domain rules could not be saved after the migration\n");
        unlink(path);
        return 1;
    }
    unlink(path);
    return 0;
}

/*
 * Egress activity storage. The report ingest itself lives in peer_mesh.c behind a control channel;
 * what is checked here is that a snapshot round-trips and that the refusal map keeps its shape.
 */
static int test_peer_mesh_egress_activity_round_trip(void)
{
    char path[256];
    snprintf(path, sizeof(path), "/tmp/specus-c-egress-activity-%ld.db", (long)getpid());
    unlink(path);
    if (st_storage_init(path, 0) != 0) {
        fprintf(stderr, "storage init failed\n");
        return 1;
    }

    int failures = 0;
    st_storage_peer_mesh_egress_activity row;
    memset(&row, 0, sizeof(row));
    snprintf(row.tenant_id, sizeof(row.tenant_id), "default");
    row.egress_client_id = 2002;
    snprintf(row.egress_client_name, sizeof(row.egress_client_name), "office-gateway");
    row.session_id = 4201;
    row.revision = 12;
    row.active_flows = 18;
    row.total_flows = 2140;
    row.bytes_in = 10485760;
    row.bytes_out = 2097152;
    snprintf(row.rejected_flows, sizeof(row.rejected_flows), "{\"EGRESS_DEST_DENIED\":4}");
    snprintf(row.reported_at, sizeof(row.reported_at), "2026-09-08T12:00:00Z");

    if (st_storage_upsert_peer_mesh_egress_activity(path, &row) != 0) {
        fprintf(stderr, "egress activity insert failed\n");
        unlink(path);
        return failures + 1;
    }

    st_storage_peer_mesh_egress_activity found;
    if (st_storage_find_peer_mesh_egress_activity(path, "default", 2002, &found) != 0
        || found.active_flows != 18 || found.total_flows != 2140
        || found.session_id != 4201 || found.revision != 12
        || strcmp(found.rejected_flows, "{\"EGRESS_DEST_DENIED\":4}") != 0) {
        fprintf(stderr, "egress activity did not round trip\n");
        failures++;
    }
    /* A device that has never reported must read as absent rather than as an error. */
    if (st_storage_find_peer_mesh_egress_activity(path, "default", 4242, &found) != 1) {
        fprintf(stderr, "a missing activity row must read as absent\n");
        failures++;
    }

    /* A second report replaces the row rather than accumulating history. */
    row.revision = 13;
    row.active_flows = 21;
    if (st_storage_upsert_peer_mesh_egress_activity(path, &row) != 0) {
        fprintf(stderr, "egress activity update failed\n");
        failures++;
    }
    st_storage_peer_mesh_egress_activity rows[8];
    size_t count = 0U;
    if (st_storage_list_peer_mesh_egress_activity(path, "default", rows, 8U, &count) != 0
        || count != 1U || rows[0].active_flows != 21 || rows[0].revision != 13) {
        fprintf(stderr, "egress activity list mismatch: count=%zu\n", count);
        failures++;
    }
    unlink(path);
    return failures;
}

/* Refusal counters are aggregated by result code; anything else must not be storable. */
static int test_peer_egress_known_codes(void)
{
    int failures = 0;
    if (!st_egress_is_known_code(ST_EGRESS_CODE_DEST_DENIED)
        || !st_egress_is_known_code(ST_EGRESS_CODE_PORT_DENIED)
        || !st_egress_is_known_code(ST_EGRESS_CODE_ALLOWED)) {
        fprintf(stderr, "a defined result code was not recognised\n");
        failures++;
    }
    if (st_egress_is_known_code("EGRESS_MADE_UP") || st_egress_is_known_code("")
        || st_egress_is_known_code(NULL)) {
        fprintf(stderr, "an undefined result code was accepted\n");
        failures++;
    }
    if (!st_egress_is_known_code(ST_EGRESS_CODE_NAME_UNRESOLVED)) {
        fprintf(stderr, "a phase-two refusal code was not recognised\n");
        failures++;
    }
    if (ST_EGRESS_ALL_CODES_LEN != 33U) {
        fprintf(stderr, "expected 33 result codes, got %zu\n", ST_EGRESS_ALL_CODES_LEN);
        failures++;
    }
    return failures;
}

static int create_lifecycle_session(const char *path,
                                    const st_storage_client_credential *credential,
                                    const st_storage_client_identity *identity,
                                    const char *token_hash,
                                    st_storage_client_session *out)
{
    memset(out, 0, sizeof(*out));
    snprintf(out->tenant_id, sizeof(out->tenant_id), "%s", identity->tenant_id);
    out->credential_id = credential->id;
    out->identity_id = identity->id;
    out->client_id = identity->client_id;
    snprintf(out->client_name, sizeof(out->client_name), "%s", identity->client_name);
    snprintf(out->token_hash, sizeof(out->token_hash), "%s", token_hash);
    snprintf(out->status, sizeof(out->status), "%s", "HTTP_AUTHENTICATED");
    snprintf(out->machine_fingerprint, sizeof(out->machine_fingerprint), "%s", identity->machine_fingerprint);
    snprintf(out->os_user, sizeof(out->os_user), "%s", identity->os_user);
    snprintf(out->http_login_at, sizeof(out->http_login_at), "%s", "2026-06-25T00:00:00Z");
    snprintf(out->expires_at, sizeof(out->expires_at), "%s", "2026-06-25T08:00:00Z");
    return st_storage_create_client_session(path, out, out);
}

/*
 * The queries the control login and the shutdown path rely on: a later HTTP login of the same
 * machine user supersedes a session, the NETTY_ONLINE ids of a credential feed the stale-row
 * cleanup, and the open-record sweep ends only rows that are still open.
 */
static int test_client_session_lifecycle_queries(void)
{
    char path[256];
    snprintf(path, sizeof(path), "/tmp/specus-c-session-lifecycle-%ld.db", (long)getpid());
    unlink(path);
    if (st_storage_init(path, 0) != 0) {
        fprintf(stderr, "storage init failed\n");
        return 1;
    }
    int failures = 0;
    st_storage_client_credential credential;
    st_storage_client_identity machine_one;
    st_storage_client_identity machine_two;
    st_storage_client_session older;
    st_storage_client_session newer;
    st_storage_client_session other_machine;
    if (st_storage_upsert_client_credential(path, 0, "default", "owner", "ck_lifecycle",
                                            "0000000000000000000000000000000000000000000000000000000000000000",
                                            1, 3, &credential) != 0
        || st_storage_find_or_create_client_identity(path, &credential, "machine-1", "tester", "host",
                                                     &machine_one) != 0
        || st_storage_find_or_create_client_identity(path, &credential, "machine-2", "tester", "host",
                                                     &machine_two) != 0
        || create_lifecycle_session(path, &credential, &machine_one,
                                    "1111111111111111111111111111111111111111111111111111111111111111", &older) != 0
        || create_lifecycle_session(path, &credential, &machine_one,
                                    "2222222222222222222222222222222222222222222222222222222222222222", &newer) != 0
        || create_lifecycle_session(path, &credential, &machine_two,
                                    "3333333333333333333333333333333333333333333333333333333333333333",
                                    &other_machine) != 0) {
        fprintf(stderr, "lifecycle fixture setup failed\n");
        unlink(path);
        return 1;
    }

    int superseded = -1;
    if (st_storage_client_session_superseded(path, credential.id, "machine-1", "tester", older.id, &superseded) != 0
        || superseded != 1) {
        fprintf(stderr, "a session followed by a later login of the same machine user must be superseded\n");
        failures++;
    }
    if (st_storage_client_session_superseded(path, credential.id, "machine-1", "tester", newer.id, &superseded) != 0
        || superseded != 0) {
        fprintf(stderr, "the newest session of a machine user must not be superseded\n");
        failures++;
    }
    /* other_machine was created after newer, but for a different machine user. */
    if (st_storage_client_session_superseded(path, credential.id, "machine-2", "tester",
                                             other_machine.id, &superseded) != 0
        || superseded != 0) {
        fprintf(stderr, "another machine's login must not supersede a session\n");
        failures++;
    }

    long long ids[4];
    size_t id_count = 99U;
    if (st_storage_list_online_session_ids_by_credential(path, credential.id, ids, 4U, &id_count) != 0
        || id_count != 0U) {
        fprintf(stderr, "no session is online yet, got %zu\n", id_count);
        failures++;
    }
    if (st_storage_mark_client_session_online(path, other_machine.id, "c2", "127.0.0.1:2", "2026-06-25T00:01:00Z") != 0
        || st_storage_mark_client_session_online(path, older.id, "c1", "127.0.0.1:1", "2026-06-25T00:01:00Z") != 0
        || st_storage_list_online_session_ids_by_credential(path, credential.id, ids, 4U, &id_count) != 0
        || id_count != 2U || ids[0] != older.id || ids[1] != other_machine.id) {
        fprintf(stderr, "online session ids mismatch: count=%zu\n", id_count);
        failures++;
    }
    if (st_storage_list_online_session_ids_by_credential(path, credential.id, ids, 1U, &id_count) != 0
        || id_count != 1U || ids[0] != older.id) {
        fprintf(stderr, "online session ids must respect the caller's capacity\n");
        failures++;
    }

    long long open_id = 0;
    long long stamped_open_id = 0;
    long long closed_id = 0;
    if (st_storage_record_connection_detail_with_tenant_and_id(path, "default", machine_one.client_id,
                                                               machine_one.client_name, NULL, "127.0.0.1:1", 1,
                                                               NULL, NULL, "2026-06-25T00:01:00Z", NULL,
                                                               &open_id) != 0
        || st_storage_record_connection_detail_with_tenant_and_id(path, "default", machine_one.client_id,
                                                                  machine_one.client_name, NULL, "127.0.0.1:1", 1,
                                                                  NULL, "IDLE_TIMEOUT", "2026-06-25T00:01:00Z",
                                                                  NULL, &stamped_open_id) != 0
        || st_storage_record_connection_detail_with_tenant_and_id(path, "default", machine_one.client_id,
                                                                  machine_one.client_name, NULL, "127.0.0.1:1", 1,
                                                                  NULL, "CLIENT_CLOSED", "2026-06-25T00:01:00Z",
                                                                  "2026-06-25T00:02:00Z", &closed_id) != 0) {
        fprintf(stderr, "connection record fixture failed\n");
        unlink(path);
        return failures + 1;
    }
    int closed = -1;
    if (st_storage_close_open_connections(path, "SERVER_SHUTDOWN", "2026-06-25T00:03:00Z", &closed) != 0
        || closed != 2) {
        fprintf(stderr, "open-record sweep closed %d row(s), expected 2\n", closed);
        failures++;
    }
    st_storage_connection connections[4];
    size_t connection_count = 0U;
    long long total_count = 0;
    if (st_storage_list_connections(path, machine_one.client_id, -1, NULL, NULL, 0, 10,
                                    connections, 4U, &connection_count, &total_count) != 0
        || connection_count != 3U) {
        fprintf(stderr, "connection list after sweep mismatch: %zu\n", connection_count);
        failures++;
    } else {
        for (size_t i = 0; i < connection_count; ++i) {
            const st_storage_connection *row = &connections[i];
            const char *expected_reason = row->id == open_id ? "SERVER_SHUTDOWN"
                : row->id == stamped_open_id ? "IDLE_TIMEOUT" : "CLIENT_CLOSED";
            const char *expected_end = row->id == closed_id ? "2026-06-25T00:02:00Z" : "2026-06-25T00:03:00Z";
            if (strcmp(row->disconnect_reason, expected_reason) != 0
                || strcmp(row->disconnected_at, expected_end) != 0) {
                fprintf(stderr, "record %lld swept to %s/%s, expected %s/%s\n", row->id,
                        row->disconnect_reason, row->disconnected_at, expected_reason, expected_end);
                failures++;
            }
        }
    }
    if (st_storage_close_open_connections(path, "SERVER_SHUTDOWN", "2026-06-25T00:04:00Z", &closed) != 0
        || closed != 0) {
        fprintf(stderr, "a second sweep must find nothing open, closed %d\n", closed);
        failures++;
    }
    unlink(path);
    return failures;
}

/* A scratch database path on /dev/shm when it is writable (much faster), otherwise TMPDIR or /tmp. */
static void scratch_db_path(char *path, size_t path_len, const char *name)
{
    const char *tmp = getenv("TMPDIR");
    const char *dir = access("/dev/shm", W_OK) == 0 ? "/dev/shm" : (tmp != NULL && *tmp != '\0' ? tmp : "/tmp");
    snprintf(path, path_len, "%s/specus-c-%s-%ld.db", dir, name, (long)getpid());
    unlink(path);
}

/* First column of the first row as an integer; -1000 when there is no row, -2000 on error. */
static long long query_int(const char *path, const char *sql)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    long long value = -2000;
    if (sqlite3_open(path, &db) == SQLITE_OK && sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        int step = sqlite3_step(stmt);
        if (step == SQLITE_ROW) {
            value = sqlite3_column_type(stmt, 0) == SQLITE_NULL ? -3000 : sqlite3_column_int64(stmt, 0);
        } else if (step == SQLITE_DONE) {
            value = -1000;
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return value;
}

static int exec_script(const char *path, const char *sql)
{
    sqlite3 *db = NULL;
    char *error = NULL;
    int rc = sqlite3_open(path, &db) == SQLITE_OK
        && sqlite3_exec(db, sql, NULL, NULL, &error) == SQLITE_OK ? 0 : -1;
    if (rc != 0) fprintf(stderr, "sql failed: %s\n", error == NULL ? "sqlite error" : error);
    sqlite3_free(error);
    sqlite3_close(db);
    return rc;
}

/*
 * Java PeerServiceDiscoverySchemaMigratorTests, createsTablesDisabledByDefaultAndAddsSessionCapabilityColumns.
 * A session table from before peer service discovery and peer egress gains the four capability
 * columns, and a row already there as well as a new row that does not set them announce nothing.
 * Sharing tables from before mDNS import and the allow list gain both columns switched off, a
 * NULL enabled flag is forced off, and a fresh database creates both tables disabled by default.
 * Startup runs the migration twice to show it is idempotent.
 */
static int test_peer_service_discovery_migration(void)
{
    char path[256];
    scratch_db_path(path, sizeof(path), "peer-service-migration");
    const char *legacy_schema =
        "CREATE TABLE specus_client_session ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,tenant_id TEXT NOT NULL DEFAULT 'default',"
        "credential_id INTEGER NOT NULL,identity_id INTEGER NOT NULL,client_id INTEGER NOT NULL,"
        "client_name TEXT NOT NULL,token_hash TEXT NOT NULL,status TEXT NOT NULL,"
        "machine_fingerprint TEXT NOT NULL,os_user TEXT NOT NULL,hostname TEXT,os_name TEXT,"
        "os_version TEXT,os_arch TEXT,client_version TEXT,java_version TEXT,local_addresses TEXT,"
        "message_send_capable INTEGER NOT NULL DEFAULT 0,message_receive_capable INTEGER NOT NULL DEFAULT 0,"
        "message_attachments_capable INTEGER NOT NULL DEFAULT 0,"
        "message_media_preview_capable INTEGER NOT NULL DEFAULT 0,"
        "message_max_attachment_bytes INTEGER NOT NULL DEFAULT 0,"
        "http_login_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,netty_connected_at TEXT,"
        "disconnected_at TEXT,expires_at TEXT NOT NULL,channel_id TEXT,remote_address TEXT);"
        "INSERT INTO specus_client_session(id,credential_id,identity_id,client_id,client_name,token_hash,"
        "status,machine_fingerprint,os_user,expires_at) VALUES(2,1,1,7,'legacy','legacy-token',"
        "'DISCONNECTED','machine','user','2026-06-25T08:00:00Z');"
        "CREATE TABLE peer_mesh_service_sharing (tenant_id TEXT NOT NULL PRIMARY KEY,enabled INTEGER,"
        "updated_by TEXT,updated_at TEXT NOT NULL);"
        "INSERT INTO peer_mesh_service_sharing(tenant_id,enabled,updated_at) VALUES('legacy-tenant',NULL,'then');"
        "CREATE TABLE peer_mesh_shared_service (id INTEGER PRIMARY KEY AUTOINCREMENT,tenant_id TEXT NOT NULL,"
        "client_id INTEGER NOT NULL,client_name TEXT NOT NULL,service_id TEXT NOT NULL,name TEXT NOT NULL,"
        "description TEXT,transport TEXT NOT NULL,application TEXT NOT NULL,target_host TEXT NOT NULL,"
        "target_port INTEGER NOT NULL,published_port INTEGER NOT NULL,path TEXT,enabled INTEGER,"
        "visibility TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,"
        "UNIQUE(tenant_id,client_id,service_id));"
        "INSERT INTO peer_mesh_shared_service(id,tenant_id,client_id,client_name,service_id,name,transport,"
        "application,target_host,target_port,published_port,enabled,visibility,created_at,updated_at) "
        "VALUES(9,'legacy-tenant',1,'a','svc-legacy','ssh','tcp','ssh','127.0.0.1',22,2222,NULL,'OWNER','then','then');";
    int failures = 0;
    if (exec_script(path, legacy_schema) != 0
        || st_storage_init(path, 0) != 0 || st_storage_init(path, 0) != 0) {
        fprintf(stderr, "peer service discovery migration of a legacy database failed\n");
        unlink(path);
        return 1;
    }
    if (exec_script(path,
            "INSERT INTO specus_client_session(id,credential_id,identity_id,client_id,client_name,token_hash,"
            "status,machine_fingerprint,os_user,expires_at) VALUES(1,1,1,7,'legacy','fresh-token',"
            "'HTTP_AUTHENTICATED','machine','user','2026-06-25T08:00:00Z');") != 0) {
        failures++;
    }
    for (int id = 1; id <= 2; ++id) {
        char sql[256];
        snprintf(sql, sizeof(sql),
                 "SELECT peer_service_discovery_version + client_egress_version * 10 "
                 "+ client_egress_domain_targets * 100 FROM specus_client_session WHERE id=%d", id);
        long long announced = query_int(path, sql);
        snprintf(sql, sizeof(sql), "SELECT peer_service_applications FROM specus_client_session WHERE id=%d", id);
        long long applications = query_int(path, sql);
        if (announced != 0 || applications != -3000) {
            fprintf(stderr, "session %d after the migration announced %lld (applications %lld)\n",
                    id, announced, applications);
            failures++;
        }
    }
    if (query_int(path, "SELECT enabled FROM peer_mesh_service_sharing WHERE tenant_id='legacy-tenant'") != 0
        || query_int(path, "SELECT mdns_import_enabled FROM peer_mesh_service_sharing "
                           "WHERE tenant_id='legacy-tenant'") != 0
        || query_int(path, "SELECT enabled FROM peer_mesh_shared_service WHERE id=9") != 0
        || query_int(path, "SELECT allowed_client_ids FROM peer_mesh_shared_service WHERE id=9") != -3000) {
        fprintf(stderr, "legacy sharing rows were not switched off with the new columns\n");
        failures++;
    }
    unlink(path);

    /* A fresh database: both tables exist and a row that does not say otherwise is off. */
    if (st_storage_init(path, 0) != 0 || st_storage_init(path, 0) != 0
        || exec_script(path,
               "INSERT INTO peer_mesh_service_sharing(tenant_id) VALUES('default');"
               "INSERT INTO peer_mesh_shared_service(id,tenant_id,client_id,client_name,service_id,name,"
               "transport,application,target_host,target_port,published_port) VALUES(1,'default',1,'a',"
               "'svc-ssh001','ssh','tcp','ssh','127.0.0.1',22,2222);") != 0) {
        fprintf(stderr, "fresh peer service discovery tables could not take a row\n");
        unlink(path);
        return 1;
    }
    if (query_int(path, "SELECT enabled FROM peer_mesh_service_sharing WHERE tenant_id='default'") != 0
        || query_int(path, "SELECT mdns_import_enabled FROM peer_mesh_service_sharing WHERE tenant_id='default'") != 0
        || query_int(path, "SELECT enabled FROM peer_mesh_shared_service WHERE id=1") != 0
        || query_int(path, "SELECT allowed_client_ids FROM peer_mesh_shared_service WHERE id=1") != -3000) {
        fprintf(stderr, "fresh peer service discovery tables are not disabled by default\n");
        failures++;
    }
    unlink(path);
    return failures;
}

/*
 * Java ConnectionArchiveServiceTests at the storage level, with the clock fixed at
 * 2026-10-07T12:00:00Z: the cutoff is the UTC date 60 days earlier, detail before it is rolled into
 * per-month totals and deleted, detail from the cutoff day on stays, and a later run adds to a
 * month that was already archived. The scheduled run through a real server is in
 * connection_archive_tests.
 */
static int test_connection_archive_window(void)
{
    const long long now = 1791374400LL; /* 2026-10-07T12:00:00Z */
    char cutoff[11];
    if (st_storage_connection_archive_cutoff(60, now, cutoff) != 0 || strcmp(cutoff, "2026-08-08") != 0
        || st_storage_connection_archive_cutoff(0, now, cutoff) != -1
        || st_storage_connection_archive_cutoff(1, 1767225600LL, cutoff) != 0
        || strcmp(cutoff, "2025-12-31") != 0
        || st_storage_connection_archive_cutoff(366, 1772323200LL, cutoff) != 0
        || strcmp(cutoff, "2025-02-28") != 0) {
        fprintf(stderr, "connection archive cutoff mismatch: %s\n", cutoff);
        return 1;
    }
    char path[256];
    scratch_db_path(path, sizeof(path), "connection-archive");
    static const struct {
        const char *at;
        int success;
    } records[] = {
        {"2026-06-03T08:00:00.000Z", 1}, {"2026-06-17T08:00:00.000Z", 1}, {"2026-06-30T23:59:59.000Z", 0},
        {"2026-07-12T08:00:00.000Z", 1},
        {"2026-08-07T23:59:59.999Z", 1}, /* the last moment before the cutoff day */
        {"2026-08-08T00:00:00.000Z", 0}, /* the cutoff day itself stays */
        {"2026-10-02T08:00:00.000Z", 1}, {"2026-10-02T09:00:00.000Z", 0},
    };
    int failures = 0;
    if (st_storage_init(path, 0) != 0) {
        unlink(path);
        return 1;
    }
    for (size_t i = 0; i < sizeof(records) / sizeof(records[0]); ++i) {
        if (st_storage_record_connection(path, "ArchiveClient", records[i].success,
                                         records[i].success ? NULL : "LOGIN_FAILURE", records[i].at) != 0) {
            failures++;
        }
    }
    /* Retention 0 turns the archive off: nothing moves. */
    if (st_storage_archive_expired_connections(path, 0, now) != 0
        || query_int(path, "SELECT COUNT(*) FROM connection_stat") != 0
        || query_int(path, "SELECT COUNT(*) FROM connection_record") != 8) {
        fprintf(stderr, "a retention of 0 still archived connection detail\n");
        failures++;
    }
    if (st_storage_archive_expired_connections(path, 60, now) != 0
        || st_storage_archive_expired_connections(path, 60, now) != 0) {
        fprintf(stderr, "connection archive run failed\n");
        unlink(path);
        return 1;
    }
    int successes = 0;
    int failures_count = 0;
    if (query_int(path, "SELECT COUNT(*) FROM connection_record") != 3
        || query_int(path, "SELECT COUNT(*) FROM connection_record WHERE connected_at < '2026-08-08'") != 0) {
        fprintf(stderr, "connection detail inside the 60-day window was not kept as it was\n");
        failures++;
    }
    if (st_storage_load_connection_stat(path, "ArchiveClient", "2026-06", &successes, &failures_count) != 0
        || successes != 2 || failures_count != 1) {
        fprintf(stderr, "June total mismatch: %d/%d\n", successes, failures_count);
        failures++;
    }
    if (st_storage_load_connection_stat(path, "ArchiveClient", "2026-08", &successes, &failures_count) != 0
        || successes != 1 || failures_count != 0) {
        fprintf(stderr, "the month straddling the cutoff was not archived up to the cutoff\n");
        failures++;
    }
    if (st_storage_load_connection_stat(path, "ArchiveClient", "2026-10", &successes, &failures_count) != -1) {
        fprintf(stderr, "the recent month was archived\n");
        failures++;
    }
    st_storage_connection_stat stats[8];
    size_t stat_count = 0;
    if (st_storage_list_connection_stats(path, "ArchiveClient", 100, stats, 8, &stat_count) != 0
        || stat_count != 3U
        || strcmp(stats[0].month, "2026-08") != 0 || strcmp(stats[1].month, "2026-07") != 0
        || strcmp(stats[2].month, "2026-06") != 0
        || stats[2].total != 3 || stats[2].success != 2 || stats[2].failure != 1
        || stats[1].total != 1 || stats[1].success != 1 || stats[1].failure != 0) {
        fprintf(stderr, "archived months mismatch (%zu rows)\n", stat_count);
        failures++;
    }
    /* Two months later the rest of August ages out and is added to the August total. */
    if (st_storage_archive_expired_connections(path, 60, now + 61LL * 86400LL) != 0
        || st_storage_load_connection_stat(path, "ArchiveClient", "2026-08", &successes, &failures_count) != 0
        || successes != 1 || failures_count != 1
        || query_int(path, "SELECT COUNT(*) FROM connection_record") != 0) {
        fprintf(stderr, "a later run did not add to the month already archived\n");
        failures++;
    }
    unlink(path);
    return failures;
}

/* The first column of the first row of sql as text ("" when there is none). */
static void query_text(const char *path, const char *sql, char *out, size_t out_len)
{
    out[0] = '\0';
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_open(path, &db) == SQLITE_OK && sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK
        && sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_text(stmt, 0) != NULL) {
        snprintf(out, out_len, "%s", (const char *)sqlite3_column_text(stmt, 0));
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

/*
 * client_account used to be keyed by client_name with the rowid as account id, and SQLite gives a
 * freed newest rowid to the next account. The migration keeps every id, retires the ids other
 * tables still refer to, and from then on no id is handed out twice. A rename carries the account's
 * identity and session names along; a delete ends its runtime tokens.
 */
static int test_client_account_id_migration(void)
{
    char path[256];
    snprintf(path, sizeof(path), "/tmp/specus-c-client-account-ids-%ld.db", (long)getpid());
    unlink(path);
    if (st_storage_init(path, 0) != 0) {
        fprintf(stderr, "client account id: init failed\n");
        unlink(path);
        return 1;
    }
    sqlite3 *db = NULL;
    char *error = NULL;
    const char *legacy =
        "DROP TABLE client_account;"
        "DELETE FROM sqlite_sequence WHERE name = 'client_account';"
        "CREATE TABLE client_account ("
        "tenant_id TEXT NOT NULL DEFAULT 'default',"
        "client_name TEXT PRIMARY KEY,"
        "owner_username TEXT NOT NULL DEFAULT 'admin',"
        "enabled INTEGER NOT NULL DEFAULT 1,"
        "connection_limit_per_minute INTEGER NOT NULL DEFAULT 30,"
        "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);"
        "INSERT INTO client_account(client_name) VALUES('alpha'),('beta'),('gamma'),('delta'),('epsilon');"
        /* epsilon (5) is gone, but an identity still names it; gamma (3) is gone without a trace. */
        "DELETE FROM client_account WHERE client_name IN ('gamma', 'epsilon');"
        "INSERT INTO specus_client_identity(credential_id, client_id, client_name, machine_fingerprint, os_user) "
        "VALUES(1, 5, 'epsilon', 'machine-epsilon', 'user');"
        "INSERT INTO specus_client_identity(credential_id, client_id, client_name, machine_fingerprint, os_user) "
        "VALUES(1, 2, 'beta', 'machine-beta', 'user');"
        "INSERT INTO specus_client_session(credential_id, identity_id, client_id, client_name, token_hash, status, "
        "machine_fingerprint, os_user, expires_at) "
        "VALUES(1, 2, 2, 'beta', 'hash', 'NETTY_ONLINE', 'machine-beta', 'user', '2999-01-01T00:00:00Z');";
    if (sqlite3_open(path, &db) != SQLITE_OK || sqlite3_exec(db, legacy, NULL, NULL, &error) != SQLITE_OK) {
        fprintf(stderr, "client account id: legacy schema setup failed: %s\n", error == NULL ? "sqlite error" : error);
        sqlite3_free(error);
        sqlite3_close(db);
        unlink(path);
        return 1;
    }
    sqlite3_close(db);

    int failures = 0;
    char text[256];
    for (int pass = 0; pass < 2; ++pass) {
        /* The second init finds the migrated table and leaves it alone. */
        if (st_storage_init(path, 0) != 0) {
            fprintf(stderr, "client account id: migration %d failed\n", pass);
            unlink(path);
            return 1;
        }
    }
    query_text(path, "SELECT group_concat(id || ':' || client_name, ',') FROM "
                     "(SELECT id, client_name FROM client_account ORDER BY id)", text, sizeof(text));
    if (strcmp(text, "1:alpha,2:beta,4:delta") != 0) {
        fprintf(stderr, "client account id: migrated accounts %s, expected their old rowids\n", text);
        ++failures;
    }
    st_storage_client created;
    if (st_storage_upsert_client(path, 0, "default", "zeta", "admin", 1, 30, &created) != 0 || created.id != 6) {
        fprintf(stderr, "client account id: first new account got id %lld, expected 6 (5 is still referenced)\n",
                created.id);
        ++failures;
    }
    st_storage_client again;
    if (st_storage_delete_client(path, created.id) != 0
        || st_storage_upsert_client(path, 0, "default", "zeta", "admin", 1, 30, &again) != 0
        || again.id != 7) {
        fprintf(stderr, "client account id: re-created newest account got id %lld, expected 7, not the deleted 6\n",
                again.id);
        ++failures;
    }
    if (st_storage_upsert_client(path, 0, "default", "alpha", "admin", 1, 30, &created) == 0) {
        fprintf(stderr, "client account id: a second account named alpha was created\n");
        ++failures;
    }

    st_storage_client renamed;
    if (st_storage_upsert_client(path, 2, "default", "beta-renamed", "admin", 1, 30, &renamed) != 0) {
        fprintf(stderr, "client account id: rename failed\n");
        ++failures;
    }
    query_text(path, "SELECT (SELECT client_name FROM specus_client_identity WHERE client_id = 2) || '|' || "
                     "(SELECT client_name FROM specus_client_session WHERE client_id = 2) || '|' || "
                     "(SELECT client_name FROM specus_client_identity WHERE client_id = 5)", text, sizeof(text));
    if (strcmp(text, "beta-renamed|beta-renamed|epsilon") != 0) {
        fprintf(stderr, "client account id: identity|session|other names after the rename: %s\n", text);
        ++failures;
    }
    if (st_storage_delete_client(path, 2) != 0) {
        fprintf(stderr, "client account id: delete failed\n");
        ++failures;
    }
    query_text(path, "SELECT status || '|' || (expires_at <= strftime('%Y-%m-%dT%H:%M:%SZ', 'now')) "
                     "FROM specus_client_session WHERE client_id = 2", text, sizeof(text));
    if (strcmp(text, "DISCONNECTED|1") != 0) {
        fprintf(stderr, "client account id: session of the deleted account is %s, expected DISCONNECTED|1 "
                        "(status|expired)\n", text);
        ++failures;
    }
    unlink(path);
    return failures == 0 ? 0 : 1;
}

int main(void)
{
    if (test_client_account_id_migration() != 0) {
        return 1;
    }
    if (test_peer_mesh_acl_direction_migration() != 0) {
        return 1;
    }
    if (test_peer_service_discovery_migration() != 0) {
        return 1;
    }
    if (test_connection_archive_window() != 0) {
        return 1;
    }
    if (test_client_session_lifecycle_queries() != 0) {
        return 1;
    }
    if (test_http_route_auth_migration() != 0) {
        return 1;
    }
    if (test_client_session_domain_targets_migration() != 0) {
        return 1;
    }
    if (test_peer_mesh_egress_policy_round_trip() != 0) {
        return 1;
    }
    if (test_peer_mesh_egress_domain_rules_migration() != 0) {
        return 1;
    }
    if (test_peer_mesh_egress_activity_round_trip() != 0) {
        return 1;
    }
    if (test_peer_egress_known_codes() != 0) {
        return 1;
    }
    char path[256];
    snprintf(path, sizeof(path), "/tmp/specus-c-storage-%ld.db", (long)getpid());
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
    /* Another tenant neither lists, reads, updates nor deletes alice, under any spelling. */
    st_storage_management_user foreign_view;
    if (st_storage_list_management_users(path, "tenant-other", users, 4, &user_count) != 0
        || user_count != 0U
        || st_storage_get_management_user_in_tenant(path, "tenant-other", "alice", &foreign_view) == 0
        || st_storage_update_management_user(path, "tenant-other", "ALICE", "taken-over", "ADMIN", 0,
                                             &foreign_view) == 0
        || st_storage_delete_management_user(path, "tenant-other", "alice") == 0
        || st_storage_get_management_user(path, "alice", &created_user) != 0
        || strcmp(created_user.tenant_id, "default") != 0
        || strcmp(created_user.password_hash, "hash-value") != 0
        || strcmp(created_user.role, "USER") != 0
        || created_user.enabled != 1) {
        fprintf(stderr, "management user crossed its tenant\n");
        unlink(path);
        return 1;
    }
    /* No tenant is the default tenant, never "every tenant". */
    if (st_storage_list_management_users(path, NULL, users, 4, &user_count) != 0
        || user_count != 1U
        || st_storage_get_management_user_in_tenant(path, "", "ALICE", &created_user) != 0
        || strcmp(created_user.username, "alice") != 0) {
        fprintf(stderr, "management user default tenant scope mismatch\n");
        unlink(path);
        return 1;
    }
    if (st_storage_update_management_user(path, "default", "ALICE", NULL, "ADMIN", 0, &created_user) != 0
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
    if (st_storage_delete_management_user(path, "default", "alice") != 0
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
                                               "https://example.com/specus.jar",
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
                                               "https://example.com/specus-linux-amd64",
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
                                               "https://example.com/specus-win-x64.zip",
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
    session.client_egress_version = 1;
    session.client_egress_domain_targets = 1;
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
        || session.message_max_attachment_bytes != 16777216
        || session.client_egress_version != 1
        || !session.client_egress_domain_targets) {
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
        || st_storage_get_client_session_for_login(path,
                                                   session.id,
                                                   "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                                                   &login_session) != 1
        || login_session.id != session.id
        || !login_session.message_send_capable
        || !login_session.message_receive_capable
        || !login_session.message_attachments_capable
        || !login_session.message_media_preview_capable
        || login_session.message_max_attachment_bytes != 16777216
        || login_session.client_egress_version != 1
        || !login_session.client_egress_domain_targets
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
        || online_count != 1) {
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
        || capability_client.client_egress_version != 1
        || !capability_client.client_egress_domain_targets
        || st_storage_ensure_peer_mesh_device(path, &capability_client, &capability_device) != 0
        || !capability_device.message_attachments_capable
        || capability_device.message_max_attachment_bytes != 16777216) {
        fprintf(stderr, "client message capability projection mismatch\n");
        unlink(path);
        return 1;
    }
    if (st_storage_mark_client_session_disconnected(path,
                                                    session.id,
                                                    "2026-06-25T00:03:00Z") != 0
        || st_storage_get_client(path, identity.client_id, &capability_client) != 0
        || capability_client.message_send_capable
        || capability_client.message_receive_capable
        || capability_client.message_attachments_capable
        || capability_client.message_media_preview_capable
        || capability_client.message_max_attachment_bytes != 0
        || capability_client.client_egress_version != 0
        || capability_client.client_egress_domain_targets
        || st_storage_ensure_peer_mesh_device(path, &capability_client, &capability_device) != 0
        || capability_device.message_attachments_capable
        || capability_device.message_max_attachment_bytes != 0) {
        fprintf(stderr, "offline client message capability projection mismatch\n");
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
    if (st_storage_upsert_client(path, 0, "tenant-c", "ACL target", "owner3", 1, 30, &acl_target) != 0) {
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
    st_storage_peer_mesh_device peer_device;
    int can_peer = -1;
    if (st_storage_upsert_client(path,
                                 created_client.id,
                                 "tenant-c",
                                 created_client.client_name,
                                 created_client.owner_username,
                                 1,
                                 created_client.connection_rate_limit_per_minute,
                                 &created_client) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &created_client, 1, &peer_device) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &acl_target, 1, &peer_device) != 0
        || st_storage_can_peer(path, &created_client, &acl_target, &can_peer) != 0
        || can_peer
        || st_storage_can_peer(path, &acl_target, &created_client, &can_peer) != 0
        || can_peer) {
        fprintf(stderr, "disabled peer mesh ACL fallback permission mismatch\n");
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
    if (st_storage_can_peer(path, &created_client, &acl_target, &can_peer) != 0
        || can_peer
        || st_storage_can_peer(path, &acl_target, &created_client, &can_peer) != 0
        || !can_peer
        || st_storage_update_peer_mesh_device_enabled(path, &acl_target, 0, &peer_device) != 0
        || st_storage_can_peer(path, &acl_target, &created_client, &can_peer) != 0
        || can_peer) {
        fprintf(stderr, "directional peer mesh fallback permission mismatch\n");
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
    const char *route_password_hash =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const char *updated_route_password_hash =
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    if (st_storage_create_http_route_for_client(path,
                                                clients[0].id,
                                                "api",
                                                "https://example.com/base",
                                                1,
                                                1,
                                                1,
                                                1,
                                                1,
                                                1,
                                                "visitor",
                                                route_password_hash,
                                                &created_route) != 0
        || created_route.id <= 0
        || created_route.client_id != clients[0].id
        || strcmp(created_route.route, "api") != 0
        || strcmp(created_route.target_base_url, "https://example.com/base") != 0
        || created_route.detail_capture_enabled != 1
        || created_route.media_capture_enabled != 1
        || created_route.path_rewrite_enabled != 1
        || created_route.insecure_skip_verify != 1
        || created_route.auth_enabled != 1
        || strcmp(created_route.auth_username, "visitor") != 0
        || strcmp(created_route.auth_password_hash, route_password_hash) != 0) {
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
                                           0,
                                           0,
                                           0,
                                           "viewer",
                                           updated_route_password_hash,
                                           &created_route) != 0
        || strcmp(created_route.route, "web") != 0
        || strcmp(created_route.target_base_url, "http://127.0.0.1:8088") != 0
        || created_route.enabled != 0
        || created_route.detail_capture_enabled != 0
        || created_route.media_capture_enabled != 0
        || created_route.path_rewrite_enabled != 0
        || created_route.insecure_skip_verify != 0
        || created_route.auth_enabled != 0
        || strcmp(created_route.auth_username, "viewer") != 0
        || strcmp(created_route.auth_password_hash, updated_route_password_hash) != 0) {
        fprintf(stderr, "http route update mismatch\n");
        unlink(path);
        return 1;
    }
    st_storage_http_route route_by_name;
    if (st_storage_get_http_route_by_client_route(path, "Demo client", "web", &route_by_name) != 0
        || route_by_name.id != created_route.id
        || strcmp(route_by_name.target_base_url, "http://127.0.0.1:8088") != 0
        || strcmp(route_by_name.auth_username, "viewer") != 0
        || strcmp(route_by_name.auth_password_hash, updated_route_password_hash) != 0) {
        fprintf(stderr, "http route lookup by client/route mismatch\n");
        unlink(path);
        return 1;
    }
    int route_found = 0;
    if (st_storage_find_http_route_by_client_route(path,
                                                   "Demo client",
                                                   "web",
                                                   &route_by_name,
                                                   &route_found) != 0
        || !route_found
        || st_storage_find_http_route_by_client_route(path,
                                                      "Demo client",
                                                      "missing",
                                                      &route_by_name,
                                                      &route_found) != 0
        || route_found) {
        fprintf(stderr, "http route presence-aware lookup mismatch\n");
        unlink(path);
        return 1;
    }
    st_storage_http_route routes[4];
    size_t route_count = 0;
    if (st_storage_list_http_routes(path, clients[0].id, routes, 4, &route_count) != 0
        || route_count != 1U
        || strcmp(routes[0].auth_username, "viewer") != 0
        || strcmp(routes[0].auth_password_hash, updated_route_password_hash) != 0) {
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
    if (st_storage_load_connection_stat(path, "Demo client", "2026-06", &successes, &failures) != 0
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
        || strcmp(stats[0].month, "2026-06") != 0
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
