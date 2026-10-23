#define _POSIX_C_SOURCE 200809L
#include "storage.h"

#include "client_auth_nonce.h"
#include "crypto.h"
#include "instant.h"
#include "object_storage.h"
#include "peer_egress.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int exec_script(const char *path, const char *sql);
static void query_text(const char *path, const char *sql, char *out, size_t out_len);

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
        || legacy.client_egress_domain_targets != 0
        || legacy.client_egress_ipv6_targets != 0
        || legacy.client_egress_ipv6_packets != 0) {
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
    fresh.client_egress_ipv6_targets = 1;
    fresh.client_egress_ipv6_packets = 1;
    if (st_storage_create_client_session(path, &fresh, &fresh) != 0
        || fresh.id == legacy.id
        || fresh.client_egress_version != 1
        || !fresh.client_egress_domain_targets
        || !fresh.client_egress_ipv6_targets
        || !fresh.client_egress_ipv6_packets) {
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
    st_storage_peer_mesh_egress_policy *listed = NULL;
    size_t count = 0U;
    if (st_storage_list_peer_mesh_egress_policies(path, "default", 1, &listed, &count) != 0
        || count != 0U) {
        fprintf(stderr, "a disabled policy is still listed as enabled\n");
        failures++;
    }
    free(listed);
    listed = NULL;
    if (st_storage_list_peer_mesh_egress_policies(path, "default", 0, &listed, &count) != 0
        || count != 1U
        || strcmp(listed[0].allowed_consumer_client_ids, "1001,1002") != 0) {
        fprintf(stderr, "the update did not persist\n");
        failures++;
    }
    free(listed);

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
    if (st_storage_init(path, 0) != 0 || st_storage_init(path, 0) != 0) {
        fprintf(stderr, "egress policy domain rules migration failed\n");
        unlink(path);
        return 1;
    }
    /* Java: a row written without domain rules after the migration reads the same empty list. */
    char domain_rules[64];
    if (exec_script(path, "INSERT INTO peer_mesh_egress_policy(tenant_id,owner_username,egress_client_id,"
                          "egress_client_name) VALUES('default','owner',2004,'new-gateway');") != 0) {
        unlink(path);
        return 1;
    }
    query_text(path, "SELECT domain_rules FROM peer_mesh_egress_policy WHERE egress_client_id=2004",
               domain_rules, sizeof(domain_rules));
    if (strcmp(domain_rules, "[]") != 0) {
        fprintf(stderr, "a policy written without domain rules reads '%s', expected []\n", domain_rules);
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
    st_storage_peer_mesh_egress_activity *rows = NULL;
    size_t count = 0U;
    if (st_storage_list_peer_mesh_egress_activity(path, "default", &rows, &count) != 0
        || count != 1U || rows[0].active_flows != 21 || rows[0].revision != 13) {
        fprintf(stderr, "egress activity list mismatch: count=%zu\n", count);
        failures++;
    }
    free(rows);
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
 * Java ClientAuthNonceServiceIntegrationTests on the stored form: each (api key, nonce) pair is
 * consumed once, under Java's id and with Java's text expiry; a row still answers at its exact
 * expiry instant (Java deletes rows with expiresAt < now) and is gone a millisecond later, and
 * every consume sweeps what has expired.
 */
static int test_client_auth_nonce_store(void)
{
    char path[256];
    scratch_db_path(path, sizeof(path), "client-auth-nonce");
    if (st_storage_init(path, 0) != 0) {
        unlink(path);
        return 1;
    }
    const long long now = 1791374400000LL; /* 2026-10-07T12:00:00.000Z */
    int failures = 0;
    if (st_client_auth_nonce_consume_stored(path, "api-key-a", "nonce", now) != ST_CLIENT_AUTH_NONCE_ACCEPTED
        || st_client_auth_nonce_consume_stored(path, "api-key-a", "nonce", now) != ST_CLIENT_AUTH_NONCE_REPLAYED
        || st_client_auth_nonce_consume_stored(path, "api-key-b", "nonce", now) != ST_CLIENT_AUTH_NONCE_ACCEPTED) {
        fprintf(stderr, "stored nonce: each api key and nonce pair must be consumed exactly once\n");
        failures = 1;
    }
    uint8_t digest[ST_SHA256_LEN];
    char api_key_hash[ST_SHA256_HEX_LEN + 1];
    char material[ST_SHA256_HEX_LEN + 16];
    char nonce_id[ST_SHA256_HEX_LEN + 1];
    st_sha256((const uint8_t *)"api-key-a", strlen("api-key-a"), digest);
    st_hex_encode(digest, sizeof(digest), api_key_hash);
    snprintf(material, sizeof(material), "%s\nnonce", api_key_hash);
    st_sha256((const uint8_t *)material, strlen(material), digest);
    st_hex_encode(digest, sizeof(digest), nonce_id);
    char sql[512];
    snprintf(sql, sizeof(sql),
             "SELECT COUNT(*) FROM specus_client_auth_nonce WHERE id = '%s' AND api_key_hash = '%s' "
             "AND expires_at = '2026-10-07T12:02:00.0000000Z'", nonce_id, api_key_hash);
    if (!failures && query_int(path, sql) != 1) {
        fprintf(stderr, "stored nonce row is not Java's id, api key hash and expiry\n");
        failures = 1;
    }
    if (!failures
        && (st_client_auth_nonce_consume_stored(path, "api-key-a", "nonce", now + 120000LL)
                != ST_CLIENT_AUTH_NONCE_REPLAYED
            || st_client_auth_nonce_consume_stored(path, "api-key-a", "nonce", now + 120001LL)
                != ST_CLIENT_AUTH_NONCE_ACCEPTED
            || query_int(path, "SELECT COUNT(*) FROM specus_client_auth_nonce") != 1)) {
        fprintf(stderr, "stored nonce expiry boundary or sweep mismatch\n");
        failures = 1;
    }
    if (!failures
        && (st_client_auth_nonce_consume_stored(path, "api-key-c", "other", now + 300000LL)
                != ST_CLIENT_AUTH_NONCE_ACCEPTED
            || query_int(path, "SELECT COUNT(*) FROM specus_client_auth_nonce WHERE expires_at = "
                               "'2026-10-07T12:07:00.0000000Z'") != 1
            || query_int(path, "SELECT COUNT(*) FROM specus_client_auth_nonce") != 1)) {
        fprintf(stderr, "stored nonce sweep of expired rows mismatch\n");
        failures = 1;
    }
    unlink(path);
    /* A database that cannot be opened fails closed. */
    if (!failures && st_client_auth_nonce_consume_stored("/nonexistent-dir/specus.db", "api-key-a", "nonce", now)
                         != ST_CLIENT_AUTH_NONCE_UNAVAILABLE) {
        fprintf(stderr, "stored nonce on a broken database did not fail closed\n");
        failures = 1;
    }
    return failures;
}

/* specus_client_session as releases before peer service discovery and peer egress created it. */
#define LEGACY_CLIENT_SESSION_TABLE                                                                         \
    "CREATE TABLE specus_client_session ("                                                                  \
    "id INTEGER PRIMARY KEY AUTOINCREMENT,tenant_id TEXT NOT NULL DEFAULT 'default',"                       \
    "credential_id INTEGER NOT NULL,identity_id INTEGER NOT NULL,client_id INTEGER NOT NULL,"               \
    "client_name TEXT NOT NULL,token_hash TEXT NOT NULL,status TEXT NOT NULL,"                              \
    "machine_fingerprint TEXT NOT NULL,os_user TEXT NOT NULL,hostname TEXT,os_name TEXT,"                   \
    "os_version TEXT,os_arch TEXT,client_version TEXT,java_version TEXT,local_addresses TEXT,"              \
    "message_send_capable INTEGER NOT NULL DEFAULT 0,message_receive_capable INTEGER NOT NULL DEFAULT 0,"   \
    "message_attachments_capable INTEGER NOT NULL DEFAULT 0,"                                               \
    "message_media_preview_capable INTEGER NOT NULL DEFAULT 0,"                                             \
    "message_max_attachment_bytes INTEGER NOT NULL DEFAULT 0,"                                              \
    "http_login_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,netty_connected_at TEXT,"                        \
    "disconnected_at TEXT,expires_at TEXT NOT NULL,channel_id TEXT,remote_address TEXT);"

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
        LEGACY_CLIENT_SESSION_TABLE
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
        /* Java: neither an upgraded session nor a new row that does not set them announces IPv6. */
        snprintf(sql, sizeof(sql),
                 "SELECT client_egress_ipv6_targets + client_egress_ipv6_packets * 10 "
                 "FROM specus_client_session WHERE id=%d", id);
        long long ipv6 = query_int(path, sql);
        if (ipv6 != 0) {
            fprintf(stderr, "session %d after the migration announced IPv6 egress (%lld)\n", id, ipv6);
            failures++;
        }
    }
    /* Another startup keeps the IPv6 capabilities a session announced since. */
    if (exec_script(path, "UPDATE specus_client_session SET client_egress_version=1, "
                          "client_egress_ipv6_targets=1 WHERE id=2;") != 0
        || st_storage_init(path, 0) != 0
        || query_int(path, "SELECT client_egress_ipv6_targets FROM specus_client_session WHERE id=2") != 1
        || query_int(path, "SELECT client_egress_ipv6_packets FROM specus_client_session WHERE id=2") != 0
        || exec_script(path, "UPDATE specus_client_session SET client_egress_ipv6_packets=1 WHERE id=1;") != 0
        || st_storage_init(path, 0) != 0
        || query_int(path, "SELECT client_egress_ipv6_packets FROM specus_client_session WHERE id=1") != 1) {
        fprintf(stderr, "a later startup reset the IPv6 egress capabilities of a session\n");
        failures++;
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

/* The file change counter of the database header: one up for every transaction that wrote. */
static long file_change_counter(const char *path)
{
    unsigned char header[28];
    FILE *file = fopen(path, "rb");
    size_t got = file == NULL ? 0U : fread(header, 1U, sizeof(header), file);
    if (file != NULL) {
        fclose(file);
    }
    return got == sizeof(header)
        ? (long)(((unsigned long)header[24] << 24) | ((unsigned long)header[25] << 16)
                 | ((unsigned long)header[26] << 8) | (unsigned long)header[27])
        : -1L;
}

/*
 * st_storage_init runs before many requests, every Direct HTTP one among them, and each write it
 * makes waits for its journal syncs. A new database is therefore created in one transaction, and a
 * current one is not written at all: the seeded demo client draws no id from the AUTOINCREMENT
 * sequence, and a connection record whose tenant is right is not rewritten. One whose tenant is
 * not, as recorded by name before its client was known, is still moved to its client's tenant.
 */
static int test_init_writes_nothing_on_a_current_database(void)
{
    char path[256];
    scratch_db_path(path, sizeof(path), "init-writes");
    int failed = st_storage_init(path, 1) != 0;
    long counter = failed ? -1L : file_change_counter(path);
    if (!failed && counter != 1L) {
        fprintf(stderr, "a new database took %ld write transactions, expected 1\n", counter);
        failed = 1;
    }
    st_storage_client acme;
    failed = failed || st_storage_upsert_client(path, 0, "acme", "acme-client", "admin", 1, 60, &acme) != 0
        || st_storage_record_connection(path, "Demo client", 1, NULL, "2026-10-08T00:00:00.000Z") != 0
        || st_storage_record_connection(path, "acme-client", 1, NULL, "2026-10-08T00:00:01.000Z") != 0
        || st_storage_init(path, 1) != 0;
    char tenant[64];
    query_text(path, "SELECT tenant_id FROM connection_record WHERE client_name = 'acme-client'", tenant,
               sizeof(tenant));
    if (!failed && strcmp(tenant, "acme") != 0) {
        fprintf(stderr, "a record stored under the default tenant was not moved to acme, got '%s'\n", tenant);
        failed = 1;
    }
    counter = file_change_counter(path);
    long long sequence = query_int(path, "SELECT seq FROM sqlite_sequence WHERE name = 'client_account'");
    for (int i = 0; !failed && i < 3; ++i) {
        failed = st_storage_init(path, 1) != 0;
    }
    long after = file_change_counter(path);
    long long sequence_after = query_int(path, "SELECT seq FROM sqlite_sequence WHERE name = 'client_account'");
    if (!failed && (after != counter || sequence_after != sequence)) {
        fprintf(stderr, "init wrote to a current database: change counter %ld -> %ld, id sequence %lld -> %lld\n",
                counter, after, sequence, sequence_after);
        failed = 1;
    }
    if (!failed && (query_int(path, "SELECT COUNT(*) FROM client_account WHERE client_name = 'Demo client'") != 1
                    || query_int(path, "SELECT COUNT(*) FROM connection_record WHERE tenant_id = 'default'") != 1)) {
        fprintf(stderr, "the demo client or its default-tenant record changed\n");
        failed = 1;
    }
    unlink(path);
    return failed ? 1 : 0;
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

/* specus_management_user as releases before tenant-scoped login names created it. */
static const char legacy_management_user_table[] =
    "CREATE TABLE specus_management_user ("
    "username TEXT PRIMARY KEY,"
    "tenant_id TEXT NOT NULL DEFAULT 'default',"
    "password_hash TEXT NOT NULL DEFAULT 'hash',"
    "role TEXT NOT NULL DEFAULT 'USER',"
    "enabled INTEGER NOT NULL DEFAULT 1,"
    "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
    "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
    "oidc_issuer TEXT,"
    "oidc_subject TEXT,"
    "oidc_identity_key TEXT);";

static int login_name_exec(const char *path, const char *sql)
{
    sqlite3 *db = NULL;
    char *error = NULL;
    int rc = sqlite3_open(path, &db) == SQLITE_OK ? sqlite3_exec(db, sql, NULL, NULL, &error) : SQLITE_ERROR;
    sqlite3_free(error);
    sqlite3_close(db);
    return rc == SQLITE_OK ? 0 : -1;
}

/* A fresh file holding only the legacy account table and the given rows. */
static int legacy_login_name_database(const char *path, const char *rows)
{
    unlink(path);
    char sql[1024];
    snprintf(sql, sizeof(sql), "%s%s", legacy_management_user_table, rows);
    if (login_name_exec(path, sql) != 0) {
        fprintf(stderr, "legacy account table setup failed\n");
        return -1;
    }
    return 0;
}

static int login_name_query_text(const char *path, const char *sql, char *out, size_t out_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int rc = -1;
    out[0] = '\0';
    if (sqlite3_open(path, &db) == SQLITE_OK && sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK
        && sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *text = sqlite3_column_text(stmt, 0);
        snprintf(out, out_len, "%s", text == NULL ? "(null)" : (const char *)text);
        rc = 0;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc;
}

/* Java ManagementUserSchemaMigratorTests.backfillsLegacyRowsAndEnforcesTenantScopedUniqueness. */
static int test_login_name_migration_backfills_legacy_rows(void)
{
    char path[256];
    char text[128];
    snprintf(path, sizeof(path), "/tmp/specus-c-login-name-backfill-%ld.db", (long)getpid());
    if (legacy_login_name_database(path, "INSERT INTO specus_management_user(username, tenant_id) "
                                         "VALUES('Alice','tenant-a'),('alice','tenant-b');") != 0) {
        return 1;
    }
    int failed = st_storage_init(path, 0) != 0 || st_storage_init(path, 0) != 0;
    char error[160];
    failed = failed || st_storage_migrate_management_login_names(path, error, sizeof(error)) != 0;
    if (failed) fprintf(stderr, "login-name migration of legacy rows failed\n");
    if (!failed) {
        failed = login_name_query_text(path, "SELECT login_name || '/' || login_name_normalized "
                                             "FROM specus_management_user WHERE username = 'Alice'",
                                       text, sizeof(text)) != 0
            || strcmp(text, "Alice/alice") != 0;
        if (failed) fprintf(stderr, "legacy row backfill mismatch: %s\n", text);
    }
    if (!failed && login_name_exec(path, "INSERT INTO specus_management_user(username, tenant_id, login_name, "
                                         "login_name_normalized, password_hash) "
                                         "VALUES('new-key','tenant-a','ALICE','alice','hash');") == 0) {
        fprintf(stderr, "a second alice of tenant-a was stored\n");
        failed = 1;
    }
    static const char *const tenants[][2] = {{"tenant-a", "Alice"}, {"tenant-b", "alice"}};
    for (size_t i = 0; !failed && i < 2U; ++i) {
        st_storage_management_user user;
        failed = st_storage_get_management_user_in_tenant(path, tenants[i][0], "ALICE", &user) != 0
            || strcmp(user.account_key, tenants[i][1]) != 0 || strcmp(user.username, tenants[i][1]) != 0
            || strcmp(user.tenant_id, tenants[i][0]) != 0;
        if (failed) fprintf(stderr, "%s's alice is not found in its own tenant\n", tenants[i][0]);
    }
    st_storage_management_user nobody;
    if (!failed && st_storage_get_management_user_in_tenant(path, "default", "alice", &nobody) == 0) {
        fprintf(stderr, "the default tenant found another tenant's alice\n");
        failed = 1;
    }
    unlink(path);
    return failed ? 1 : 0;
}

/* Java ManagementUserSchemaMigratorTests.failsBeforeBackfillWhenLegacyRowsCollideInsideTenant. */
static int test_login_name_migration_refuses_duplicates_inside_a_tenant(void)
{
    char path[256];
    char text[128];
    char error[160];
    snprintf(path, sizeof(path), "/tmp/specus-c-login-name-duplicate-%ld.db", (long)getpid());
    if (legacy_login_name_database(path, "INSERT INTO specus_management_user(username, tenant_id) "
                                         "VALUES('Alice','tenant-a'),('alice','tenant-a');") != 0) {
        return 1;
    }
    int failed = st_storage_init(path, 0) == 0;
    if (failed) fprintf(stderr, "storage opened with two alices in one tenant\n");
    if (!failed) {
        failed = st_storage_migrate_management_login_names(path, error, sizeof(error)) == 0
            || strstr(error, "duplicate management login name") == NULL || strstr(error, "tenant-a") == NULL;
        if (failed) fprintf(stderr, "duplicate login name error mismatch: %s\n", error);
    }
    if (!failed) {
        failed = login_name_query_text(path, "SELECT COUNT(*) FROM specus_management_user "
                                             "WHERE login_name IS NOT NULL", text, sizeof(text)) != 0
            || strcmp(text, "0") != 0;
        if (failed) fprintf(stderr, "%s rows were backfilled before the failure\n", text);
    }
    unlink(path);
    return failed ? 1 : 0;
}

/* Java ManagementUserSchemaMigratorTests.rejectsAnExistingIndexWithTheExpectedNameButWrongDefinition. */
static int test_login_name_migration_rejects_a_wrong_index(void)
{
    char path[256];
    char error[160];
    snprintf(path, sizeof(path), "/tmp/specus-c-login-name-index-%ld.db", (long)getpid());
    if (legacy_login_name_database(path, "CREATE UNIQUE INDEX uq_management_user_tenant_login_name "
                                         "ON specus_management_user(username);") != 0) {
        return 1;
    }
    int failed = st_storage_init(path, 0) == 0
        || st_storage_migrate_management_login_names(path, error, sizeof(error)) == 0
        || strstr(error, "must be unique on (tenant_id, login_name_normalized)") == NULL;
    if (failed) fprintf(stderr, "a wrong login-name index was accepted: %s\n", error);
    unlink(path);
    return failed ? 1 : 0;
}

/*
 * ManagementUserServiceTests.createsSameLoginNameInDifferentTenantWithoutGlobalLookup at the store:
 * a new account gets a random key rather than its name, so tenants share login names, and the
 * legacy key lookup finds only accounts that predate login names, and only an unambiguous one.
 */
static int test_login_names_are_unique_per_tenant(void)
{
    char path[256];
    snprintf(path, sizeof(path), "/tmp/specus-c-login-name-tenants-%ld.db", (long)getpid());
    if (legacy_login_name_database(path, "INSERT INTO specus_management_user(username, tenant_id) "
                                         "VALUES('Carol','tenant-c'),('carol','tenant-d'),('erin','tenant-e');") != 0) {
        return 1;
    }
    st_storage_management_user a;
    st_storage_management_user b;
    st_storage_management_user other;
    int failed = st_storage_init(path, 0) != 0
        || st_storage_create_management_user(path, "Bob", "tenant-a", "hash", "USER", 1, &a) != 0
        || st_storage_create_management_user(path, "bob", "tenant-b", "hash", "USER", 1, &b) != 0;
    if (failed) fprintf(stderr, "same login name in two tenants was refused\n");
    if (!failed) {
        failed = strlen(a.account_key) != 36U || a.account_key[8] != '-' || a.account_key[14] != '4'
            || strcmp(a.account_key, b.account_key) == 0 || strcmp(a.username, "Bob") != 0
            || strcmp(b.username, "bob") != 0;
        if (failed) fprintf(stderr, "new accounts did not get random keys: %s %s\n", a.account_key, b.account_key);
    }
    if (!failed && st_storage_create_management_user(path, " BOB ", "tenant-a", "hash", "USER", 1, &other) == 0) {
        fprintf(stderr, "a second bob of tenant-a was created\n");
        failed = 1;
    }
    if (!failed && st_storage_find_legacy_management_user(path, "bob", &other) != 1) {
        fprintf(stderr, "a new account was found by its login name as a legacy key\n");
        failed = 1;
    }
    if (!failed && st_storage_find_legacy_management_user(path, "CAROL", &other) != 1) {
        fprintf(stderr, "an ambiguous legacy key resolved\n");
        failed = 1;
    }
    if (!failed) {
        failed = st_storage_find_legacy_management_user(path, "Erin", &other) != 0
            || strcmp(other.account_key, "erin") != 0 || strcmp(other.tenant_id, "tenant-e") != 0;
        if (failed) fprintf(stderr, "a unique legacy key did not resolve\n");
    }
    if (!failed) {
        failed = st_storage_find_management_user_by_account_key(path, a.account_key, &other) != 0
            || strcmp(other.tenant_id, "tenant-a") != 0
            || st_storage_find_management_user_by_account_key(path, "ERIN", &other) != 1
            || st_storage_find_management_user_in_tenant(path, "tenant-b", "BOB", &other) != 0
            || strcmp(other.account_key, b.account_key) != 0
            || st_storage_find_management_user_in_tenant(path, "tenant-c", "bob", &other) != 1;
        if (failed) fprintf(stderr, "account key or tenant lookups mismatch\n");
    }
    unlink(path);
    return failed ? 1 : 0;
}

/*
 * Whether table has a unique index on exactly these comma-separated columns, in any order and under
 * any name, as a table constraint or CREATE UNIQUE INDEX makes one: 1 a full one, 2 only a partial
 * one, 0 none, -1 on error. With name set, only the index of that name counts.
 */
static int unique_index_on(const char *path, const char *table, const char *columns, const char *name)
{
    char wanted[8][64];
    size_t wanted_count = 0U;
    for (const char *cursor = columns; *cursor != '\0' && wanted_count < 8U;) {
        size_t len = strcspn(cursor, ",");
        snprintf(wanted[wanted_count++], sizeof(wanted[0]), "%.*s", (int)len, cursor);
        cursor += len;
        if (*cursor == ',') {
            ++cursor;
        }
    }
    sqlite3 *db = NULL;
    sqlite3_stmt *indexes = NULL;
    int result = -1;
    if (sqlite3_open(path, &db) == SQLITE_OK
        && sqlite3_prepare_v2(db, "SELECT name, \"unique\", partial FROM pragma_index_list(?1)", -1, &indexes,
                              NULL) == SQLITE_OK) {
        sqlite3_bind_text(indexes, 1, table, -1, SQLITE_STATIC);
        result = 0;
        while (result >= 0 && result != 1 && sqlite3_step(indexes) == SQLITE_ROW) {
            const char *index = (const char *)sqlite3_column_text(indexes, 0);
            if (index == NULL || sqlite3_column_int(indexes, 1) == 0 || (name != NULL && strcmp(index, name) != 0)) {
                continue;
            }
            sqlite3_stmt *info = NULL;
            size_t total = 0U;
            size_t matched = 0U;
            if (sqlite3_prepare_v2(db, "SELECT name FROM pragma_index_info(?1)", -1, &info, NULL) != SQLITE_OK) {
                result = -1;
            } else {
                sqlite3_bind_text(info, 1, index, -1, SQLITE_TRANSIENT);
                while (sqlite3_step(info) == SQLITE_ROW) {
                    const char *column = (const char *)sqlite3_column_text(info, 0);
                    ++total;
                    for (size_t i = 0U; column != NULL && i < wanted_count; ++i) {
                        if (strcmp(column, wanted[i]) == 0) {
                            ++matched;
                            break;
                        }
                    }
                }
            }
            sqlite3_finalize(info);
            if (result >= 0 && total == wanted_count && matched == wanted_count) {
                result = sqlite3_column_int(indexes, 2) == 0 ? 1 : 2;
            }
        }
    }
    sqlite3_finalize(indexes);
    sqlite3_close(db);
    return result;
}

/* Every table, index and trigger with its SQL, as one string the caller frees; NULL on error. */
static char *schema_snapshot(const char *path)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    char *snapshot = NULL;
    if (sqlite3_open(path, &db) == SQLITE_OK
        && sqlite3_prepare_v2(db,
               "SELECT group_concat(type || ' ' || name || ' ' || tbl_name || ' ' || COALESCE(sql, ''), char(10)) "
               "FROM (SELECT * FROM sqlite_master ORDER BY type, name)",
               -1, &stmt, NULL) == SQLITE_OK
        && sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_text(stmt, 0) != NULL) {
        snapshot = strdup((const char *)sqlite3_column_text(stmt, 0));
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return snapshot;
}

/* Runs sql on its own connection: the SQLite result code, with the error message in message. */
static int exec_status(const char *path, const char *sql, char *message, size_t message_len)
{
    sqlite3 *db = NULL;
    char *error = NULL;
    int rc = sqlite3_open(path, &db);
    if (rc == SQLITE_OK) {
        rc = sqlite3_exec(db, sql, NULL, NULL, &error);
    }
    snprintf(message, message_len, "%s", error == NULL ? "" : error);
    sqlite3_free(error);
    sqlite3_close(db);
    return rc;
}

/*
 * A new database as the server leaves it: st_storage_init, then the attachment tables, which
 * object_storage.c creates when attachments are first used (here through the expiry sweep, which
 * opens SPECUS_DATABASE_PATH with object storage switched off).
 */
static int init_full_schema(const char *path)
{
    if (st_storage_init(path, 0) != 0 || setenv("SPECUS_DATABASE_PATH", path, 1) != 0
        || unsetenv("SPECUS_OBJECT_STORAGE_PROVIDER") != 0) {
        return -1;
    }
    int rc = st_object_storage_cleanup_expired();
    unsetenv("SPECUS_DATABASE_PATH");
    return rc;
}

/*
 * Java ClientDownloadSchemaMigratorTests.upgradesLegacyRowsWithoutInventingVisibleVersionsAndEnforcesPortableSlots
 * on the C table from before the version columns: legacy rows get no visible version and distinct
 * legacy keys; duplicate version and latest declarations keep one version (the newest row's) and one
 * latest; catalog_key is enforced by a unique index; a disabled row loses its latest slot; and a
 * further startup changes nothing and does not write.
 */
static int test_client_download_catalog_migration(void)
{
    char path[256];
    scratch_db_path(path, sizeof(path), "client-download-catalog");
    int failed = exec_script(path,
        "CREATE TABLE client_download_link (id INTEGER PRIMARY KEY AUTOINCREMENT,implementation TEXT NOT NULL,"
        "platform TEXT NOT NULL,arch TEXT NOT NULL,display_name TEXT NOT NULL,download_url TEXT NOT NULL,"
        "description TEXT,display_order INTEGER NOT NULL DEFAULT 0,enabled INTEGER NOT NULL DEFAULT 1,"
        "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);"
        "INSERT INTO client_download_link(id,implementation,platform,arch,display_name,download_url) "
        "VALUES(1,'go','windows','x64','one','https://example.test/1'),"
        "(2,'go','windows','x64','two','https://example.test/2');") != 0
        || st_storage_init(path, 0) != 0;
    if (!failed
        && (query_int(path, "SELECT COUNT(*) FROM client_download_link WHERE version IS NULL AND is_latest = 0 "
                            "AND hosted = 0 AND latest_slot IS NULL") != 2
            || query_int(path, "SELECT COUNT(DISTINCT catalog_key) FROM client_download_link") != 2
            || query_int(path, "SELECT COUNT(*) FROM client_download_link WHERE catalog_key = "
                               "'go|windows|x64|legacy:' || id") != 2)) {
        fprintf(stderr, "legacy client downloads gained a version, a latest slot or a shared key\n");
        failed = 1;
    }

    /* A partially upgraded database with duplicate version and latest declarations. */
    failed = failed
        || exec_script(path, "UPDATE client_download_link SET version='v1.2.3', min_supported_version='v1.0.0', "
                             "is_latest=1;") != 0
        || st_storage_init(path, 0) != 0;
    if (!failed
        && (query_int(path, "SELECT COUNT(*) FROM client_download_link WHERE version IS NOT NULL") != 1
            || query_int(path, "SELECT COUNT(*) FROM client_download_link WHERE version IS NULL "
                               "AND min_supported_version IS NOT NULL") != 0
            || query_int(path, "SELECT COUNT(*) FROM client_download_link WHERE id = 2 AND version = '1.2.3' "
                               "AND min_supported_version = '1.0.0' AND catalog_key = 'go|windows|x64|1.2.3'") != 1
            || query_int(path, "SELECT COUNT(*) FROM client_download_link WHERE is_latest = 1") != 1
            || query_int(path, "SELECT COUNT(DISTINCT catalog_key) FROM client_download_link") != 2)) {
        fprintf(stderr, "duplicate legacy versions or latest flags survived the migration\n");
        failed = 1;
    }
    char occupied[96];
    char message[256];
    query_text(path, "SELECT catalog_key FROM client_download_link ORDER BY id DESC LIMIT 1", occupied,
               sizeof(occupied));
    char insert[384];
    snprintf(insert, sizeof(insert),
             "INSERT INTO client_download_link(id,implementation,platform,arch,display_name,download_url,catalog_key) "
             "VALUES(3,'go','windows','x64','three','https://example.test/3','%s')", occupied);
    int rc = failed ? SQLITE_OK : exec_status(path, insert, message, sizeof(message));
    if (!failed && (rc != SQLITE_CONSTRAINT
                    || strcmp(message, "UNIQUE constraint failed: client_download_link.catalog_key") != 0)) {
        fprintf(stderr, "an occupied catalog key was accepted: %d %s\n", rc, message);
        failed = 1;
    }

    /* A disabled row cannot hold the latest slot. */
    failed = failed
        || exec_script(path, "UPDATE client_download_link SET enabled=0, is_latest=1, "
                             "latest_slot='go|windows|x64' WHERE id=2;") != 0
        || st_storage_init(path, 0) != 0;
    if (!failed
        && query_int(path, "SELECT COUNT(*) FROM client_download_link WHERE id = 2 AND is_latest = 0 "
                           "AND latest_slot IS NULL") != 1) {
        fprintf(stderr, "a disabled client download kept the latest slot\n");
        failed = 1;
    }

    /* A third run is a no-op, which every restart relies on. */
    long counter = failed ? -1L : file_change_counter(path);
    failed = failed || st_storage_init(path, 0) != 0;
    if (!failed && (query_int(path, "SELECT COUNT(*) FROM client_download_link") != 2
                    || file_change_counter(path) != counter
                    || unique_index_on(path, "client_download_link", "catalog_key",
                                       "ux_client_download_catalog_key") != 1
                    || unique_index_on(path, "client_download_link", "latest_slot",
                                       "ux_client_download_latest_slot") != 1)) {
        fprintf(stderr, "a further startup changed the client download catalogue or lost its unique keys\n");
        failed = 1;
    }
    unlink(path);
    return failed ? 1 : 0;
}

/*
 * Java SqliteUniqueIndexStartupTests.startupEnforcesEveryUniqueKeyOfTheMapping over the 22
 * table-level unique keys that SqliteUniqueIndexMigratorTests.listsEveryTableLevelUniqueKeyOfTheMapping
 * counts (SqliteUniqueIndexMigrator.UNIQUE_KEYS): on a new database each is enforced by a full unique
 * index or table constraint on the C table and columns listed here. Where C's table or key columns
 * differ from Java's, the comment says why the key is the same. The two keys C used to lack and the
 * two traffic keys it used to put on the client name carry Java's index names, as the migrator
 * creates them.
 */
static int test_schema_enforces_java_unique_keys(void)
{
    static const struct {
        const char *java_key;
        const char *table;
        const char *columns;
        const char *index_name; /* when the index must carry Java's name */
    } keys[] = {
        {"uk_client_credential_api_key", "specus_client_credential", "api_key", NULL},
        {"uk_client_identity_machine_user", "specus_client_identity", "credential_id,machine_fingerprint,os_user",
         NULL},
        {"uq_management_user_tenant_login_name", "specus_management_user", "tenant_id,login_name_normalized",
         "uq_management_user_tenant_login_name"},
        /* Both declared COLLATE NOCASE in C, so the key also refuses a value differing only in ASCII case. */
        {"uq_registration_challenge_username", "specus_management_registration_challenge", "username", NULL},
        {"uq_registration_challenge_email", "specus_management_registration_challenge", "email", NULL},
        {"uk_specus_mapping_listen_port", "specus_mapping", "listen_port", "uk_specus_mapping_listen_port"},
        /*
         * Java (client_id, route). C's routes name their client instead of numbering it:
         * client_account.client_name is unique across all tenants and a rename rewrites it here,
         * and a deleted client's routes go with it, so one name is one client of one tenant.
         */
        {"uk_http_route_client_route", "http_route_mapping", "client_name,route", NULL},
        {"uk_peer_mesh_acl_pair", "peer_mesh_acl", "tenant_id,source_client_id,target_client_id", NULL},
        {"uk_peer_mesh_device_client", "peer_mesh_device", "tenant_id,client_id", NULL},
        {"uk_peer_mesh_device_ip", "peer_mesh_device", "tenant_id,virtual_ip", "uk_peer_mesh_device_ip"},
        {"uk_peer_egress_policy_client", "peer_mesh_egress_policy", "tenant_id,egress_client_id", NULL},
        {"uk_peer_egress_activity_client", "peer_mesh_egress_activity", "tenant_id,egress_client_id", NULL},
        {"uk_peer_shared_service_id", "peer_mesh_shared_service", "tenant_id,client_id,service_id", NULL},
        {"uk_public_transfer_room_key", "public_transfer_room", "room_name,owner_token_hash", NULL},
        {"uk_public_transfer_access_token", "public_transfer_room_access", "token_hash", NULL},
        {"uk_public_transfer_pairing_code_hash", "public_transfer_room_pairing_code", "code_hash", NULL},
        {"uk_attachment_download_grant_token", "transfer_attachment_download_grant", "token_hash", NULL},
        /*
         * Java's two traffic counters, by account: a deleted client's rows outlive it, so a name
         * can stand for two clients of two tenants there (C keyed them by name until #35 item 45).
         */
        {"uk_specus_traffic_client_date", "traffic_usage", "client_id,usage_date", "uk_specus_traffic_client_date"},
        {"uk_resource_traffic_resource_date", "resource_traffic_usage",
         "tenant_id,client_id,resource_type,resource_key,usage_date", "uk_resource_traffic_resource_date"},
        /*
         * Java specus_connection_stat (tenant_id, client_name, stat_month): C's connection_stat keeps
         * the same "yyyy-MM" month in stat_date (st_storage_archive_connections), and the name fixes
         * the tenant.
         */
        {"uk_specus_connection_stat", "connection_stat", "client_name,stat_date", NULL},
        {"uk_http_media_deduplication", "specus_http_media_capture", "deduplication_key", NULL},
    };
    const size_t key_count = sizeof(keys) / sizeof(keys[0]);
    char path[256];
    scratch_db_path(path, sizeof(path), "unique-keys");
    if (init_full_schema(path) != 0) {
        fprintf(stderr, "unique keys: schema setup failed\n");
        unlink(path);
        return 1;
    }
    int failures = 0;
    /* The keys above and the OIDC identity key below. */
    if (key_count + 1U != 22U) {
        fprintf(stderr, "unique keys: %zu keys listed, Java's mapping has 22\n", key_count + 1U);
        ++failures;
    }
    for (size_t i = 0U; i < key_count; ++i) {
        int state = unique_index_on(path, keys[i].table, keys[i].columns, keys[i].index_name);
        if (state != 1) {
            fprintf(stderr, "unique keys: %s is not enforced on %s (%s)%s%s, state %d\n", keys[i].java_key,
                    keys[i].table, keys[i].columns, keys[i].index_name == NULL ? "" : " by an index named ",
                    keys[i].index_name == NULL ? "" : keys[i].index_name, state);
            ++failures;
        }
    }
    /*
     * Java uq_management_user_oidc_identity_key is a full unique index on oidc_identity_key. C's is
     * partial, WHERE oidc_identity_key IS NOT NULL AND oidc_identity_key <> ''. NULLs never collide in
     * either, so the two differ only for '': accounts without an OIDC identity store NULL, and an
     * identity key is never empty, so no row C writes is treated differently.
     */
    if (unique_index_on(path, "specus_management_user", "oidc_identity_key", "uq_management_user_oidc_identity_key")
            != 2
        || unique_index_on(path, "specus_management_user", "oidc_identity_key", NULL) != 2) {
        fprintf(stderr, "unique keys: the OIDC identity key is not C's partial unique index\n");
        ++failures;
    }
    unlink(path);
    return failures == 0 ? 0 : 1;
}

/*
 * Java SqliteIdentityKeySchemaTests.everyIdentityIdAliasesTheRowid: every table keyed by an id the
 * database numbers has that id as its only key column, declared INTEGER, so it is the rowid and
 * holds what sqlite3_last_insert_rowid() reports. Java checks its IDENTITY entities, among them the
 * three tables its SqliteIdentityKeyMigrator repairs; C checks every table whose key is id.
 * specus_client_auth_nonce is the exception, as in Java: its id is computed (a SHA-256 in hex,
 * Java's String id without @GeneratedValue), not numbered.
 */
static int test_every_identity_id_aliases_the_rowid(void)
{
    char path[256];
    scratch_db_path(path, sizeof(path), "identity-ids");
    sqlite3 *db = NULL;
    sqlite3_stmt *tables = NULL;
    if (init_full_schema(path) != 0 || sqlite3_open(path, &db) != SQLITE_OK
        || sqlite3_prepare_v2(db,
               "SELECT m.name, (SELECT COUNT(*) FROM pragma_table_info(m.name) WHERE pk > 0), "
               "(SELECT upper(type) FROM pragma_table_info(m.name) WHERE name = 'id' AND pk > 0) "
               "FROM sqlite_master m WHERE m.type = 'table' AND m.name NOT LIKE 'sqlite\\_%' ESCAPE '\\' "
               "AND EXISTS (SELECT 1 FROM pragma_table_info(m.name) WHERE name = 'id' AND pk > 0) "
               "ORDER BY m.name",
               -1, &tables, NULL) != SQLITE_OK) {
        fprintf(stderr, "identity ids: schema setup failed\n");
        sqlite3_finalize(tables);
        sqlite3_close(db);
        unlink(path);
        return 1;
    }
    int failures = 0;
    int checked = 0;
    int repaired_by_java = 0;
    while (sqlite3_step(tables) == SQLITE_ROW) {
        const char *table = (const char *)sqlite3_column_text(tables, 0);
        const char *type = (const char *)sqlite3_column_text(tables, 2);
        const char *expected = strcmp(table, "specus_client_auth_nonce") == 0 ? "VARCHAR(64)" : "INTEGER";
        ++checked;
        if (strcmp(table, "specus_http_media_capture") == 0 || strcmp(table, "specus_http_traffic_exchange") == 0
            || strcmp(table, "specus_tcp_traffic_frame") == 0) {
            ++repaired_by_java;
        }
        if (sqlite3_column_int(tables, 1) != 1 || type == NULL || strcmp(type, expected) != 0) {
            fprintf(stderr, "identity ids: %s has %d key column(s), id typed %s, expected id alone as %s\n", table,
                    sqlite3_column_int(tables, 1), type == NULL ? "(none)" : type, expected);
            ++failures;
        }
    }
    sqlite3_finalize(tables);
    sqlite3_close(db);
    if (checked <= 3 || repaired_by_java != 3) {
        fprintf(stderr, "identity ids: %d tables checked, %d of Java's three repaired ones\n", checked,
                repaired_by_java);
        ++failures;
    }
    unlink(path);
    return failures == 0 ? 0 : 1;
}

/*
 * Java SqliteSchemaUpdateRestartTests.serverRestartsOnAnExistingSqliteDatabase and
 * SqliteIdentityKeySchemaTests.theRepairLeavesACreatedSchemaAlone: later starts on a database
 * the server created leave every table, index and constraint as the first start made them.
 */
static int test_restart_keeps_the_schema(void)
{
    char path[256];
    scratch_db_path(path, sizeof(path), "restart-schema");
    char *first = init_full_schema(path) == 0 ? schema_snapshot(path) : NULL;
    char *second = first != NULL && init_full_schema(path) == 0 && st_storage_init(path, 1) == 0
        ? schema_snapshot(path) : NULL;
    int failed = first == NULL || second == NULL || strcmp(first, second) != 0;
    if (failed) {
        fprintf(stderr, "restart changed the schema\n--- first\n%s\n--- second\n%s\n", first == NULL ? "" : first,
                second == NULL ? "" : second);
    }
    free(first);
    free(second);
    unlink(path);
    return failed ? 1 : 0;
}

/*
 * Java PostgresSchemaMigrationTests.managementUserMigrationAcceptsTheIndexHibernateCreated on
 * SQLite: the login-name columns and a correct uq_management_user_tenant_login_name are already
 * there, the row's login names are not. Startup backfills them and keeps the index as it was.
 */
static int test_login_name_migration_accepts_an_existing_index(void)
{
    char path[256];
    char text[512];
    char index_before[512];
    snprintf(path, sizeof(path), "/tmp/specus-c-login-name-existing-index-%ld.db", (long)getpid());
    if (legacy_login_name_database(path,
            "ALTER TABLE specus_management_user ADD COLUMN login_name TEXT;"
            "ALTER TABLE specus_management_user ADD COLUMN login_name_normalized TEXT;"
            "CREATE UNIQUE INDEX uq_management_user_tenant_login_name "
            "ON specus_management_user (tenant_id, login_name_normalized);"
            "INSERT INTO specus_management_user(username, tenant_id) VALUES('Alice', 'tenant-a');") != 0) {
        return 1;
    }
    query_text(path, "SELECT sql FROM sqlite_master WHERE name = 'uq_management_user_tenant_login_name'",
               index_before, sizeof(index_before));
    int failed = st_storage_init(path, 0) != 0 || st_storage_init(path, 0) != 0;
    if (failed) fprintf(stderr, "login-name migration refused its own index\n");
    if (!failed) {
        failed = login_name_query_text(path, "SELECT login_name || '/' || login_name_normalized "
                                             "FROM specus_management_user WHERE username = 'Alice'",
                                       text, sizeof(text)) != 0
            || strcmp(text, "Alice/alice") != 0;
        if (failed) fprintf(stderr, "login names under an existing index: %s, expected Alice/alice\n", text);
    }
    if (!failed) {
        query_text(path, "SELECT sql FROM sqlite_master WHERE name = 'uq_management_user_tenant_login_name'",
                   text, sizeof(text));
        failed = strcmp(text, index_before) != 0
            || unique_index_on(path, "specus_management_user", "tenant_id,login_name_normalized",
                               "uq_management_user_tenant_login_name") != 1;
        if (failed) fprintf(stderr, "the existing login-name index changed: %s\n", text);
    }
    unlink(path);
    return failed ? 1 : 0;
}

/*
 * Java PostgresSchemaMigrationTests.peerServiceMigrationAddsColumnsToALegacySessionTable on SQLite:
 * a database from before peer service discovery, with a session row and no shared-service table,
 * gains the session capability columns (0 on the old row) and the shared-service table with its
 * unique key on (tenant_id, client_id, service_id), Java's uk_peer_shared_service_id (a table
 * constraint in C), and idx_peer_shared_service_tenant_client. Startup runs twice.
 */
static int test_peer_service_migration_creates_the_shared_service_keys(void)
{
    char path[256];
    scratch_db_path(path, sizeof(path), "peer-service-keys");
    if (exec_script(path,
            LEGACY_CLIENT_SESSION_TABLE
            "INSERT INTO specus_client_session(id,credential_id,identity_id,client_id,client_name,token_hash,"
            "status,machine_fingerprint,os_user,expires_at) VALUES(1,1,1,7,'legacy','legacy-token',"
            "'DISCONNECTED','machine','user','2026-06-25T08:00:00Z');") != 0
        || query_int(path, "SELECT COUNT(*) FROM sqlite_master WHERE tbl_name = 'peer_mesh_shared_service'") != 0
        || st_storage_init(path, 0) != 0 || st_storage_init(path, 0) != 0) {
        fprintf(stderr, "peer service migration of a database without shared services failed\n");
        unlink(path);
        return 1;
    }
    int failures = 0;
    if (query_int(path, "SELECT peer_service_discovery_version + client_egress_version * 10 "
                        "+ client_egress_domain_targets * 100 FROM specus_client_session WHERE id = 1") != 0) {
        fprintf(stderr, "the legacy session announces peer services or egress after the migration\n");
        ++failures;
    }
    if (unique_index_on(path, "peer_mesh_shared_service", "tenant_id,client_id,service_id", NULL) != 1) {
        fprintf(stderr, "peer_mesh_shared_service lacks its unique (tenant_id, client_id, service_id)\n");
        ++failures;
    }
    char columns[128];
    query_text(path, "SELECT group_concat(name, ',') FROM (SELECT name FROM "
                     "pragma_index_info('idx_peer_shared_service_tenant_client') ORDER BY seqno)",
               columns, sizeof(columns));
    if (query_int(path, "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' "
                        "AND name = 'idx_peer_shared_service_tenant_client' "
                        "AND tbl_name = 'peer_mesh_shared_service'") != 1
        || strcmp(columns, "tenant_id,client_id") != 0) {
        fprintf(stderr, "idx_peer_shared_service_tenant_client missing or on (%s)\n", columns);
        ++failures;
    }
    unlink(path);
    return failures == 0 ? 0 : 1;
}

/* Lets every child pass the gate at once and waits for them: 0 when each exited 0. */
static int run_gated_children(int gate[2], const pid_t *children, size_t started, size_t wanted)
{
    close(gate[0]);
    close(gate[1]);
    int failed = started != wanted;
    for (size_t i = 0U; i < started; ++i) {
        int status = 0;
        if (waitpid(children[i], &status, 0) != children[i] || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            failed = 1;
        }
    }
    return failed ? -1 : 0;
}

/* Enrols each client from a process of its own, all released together. */
static int race_peer_mesh_enrolments(const char *path, const st_storage_client *clients, size_t count)
{
    int gate[2];
    pid_t children[8];
    if (count > 8U || pipe(gate) != 0) {
        return -1;
    }
    fflush(NULL);
    size_t started = 0U;
    for (; started < count; ++started) {
        pid_t pid = fork();
        if (pid < 0) {
            break;
        }
        if (pid == 0) {
            close(gate[1]);
            char byte;
            /* Returns at end of file, when the parent closes its end of the gate. */
            ssize_t got = read(gate[0], &byte, 1U);
            st_storage_peer_mesh_device device;
            int rc = got >= 0 ? st_storage_ensure_peer_mesh_device(path, &clients[started], &device) : -1;
            _exit(rc == 0 ? 0 : 1);
        }
        children[started] = pid;
    }
    return run_gated_children(gate, children, started, count);
}

/*
 * Java uk_peer_mesh_device_ip: one device per virtual address in a tenant. A second row on an
 * address is refused, the same address in another tenant and devices without one are not. Clients
 * enrolling at the same time each get an address of their own (PeerMeshService.allocateVirtualIp
 * under Java's transaction and unique key): a /29 has six, and six enrolments race for them.
 */
static int test_peer_mesh_device_ip_is_unique(void)
{
    char path[256];
    char message[256];
    scratch_db_path(path, sizeof(path), "peer-device-ip");
    if (st_storage_init(path, 0) != 0) {
        unlink(path);
        return 1;
    }
    int failures = 0;
    if (exec_status(path, "INSERT INTO peer_mesh_device(tenant_id, client_id, client_name, virtual_ip) "
                          "VALUES('t-ip', 1001, 'ip-a', '100.96.0.5')", message, sizeof(message)) != SQLITE_OK
        || exec_status(path, "INSERT INTO peer_mesh_device(tenant_id, client_id, client_name, virtual_ip) "
                             "VALUES('t-ip', 1002, 'ip-b', '100.96.0.5')", message, sizeof(message))
               != SQLITE_CONSTRAINT
        || strstr(message, "UNIQUE constraint failed: peer_mesh_device.tenant_id, peer_mesh_device.virtual_ip")
               == NULL) {
        fprintf(stderr, "a second device on one virtual address was not refused: %s\n", message);
        ++failures;
    }
    if (exec_status(path, "INSERT INTO peer_mesh_device(tenant_id, client_id, client_name, virtual_ip) "
                          "VALUES('t-other', 1002, 'ip-b', '100.96.0.5');"
                          "INSERT INTO peer_mesh_device(tenant_id, client_id, client_name) "
                          "VALUES('t-ip', 1003, 'ip-c'), ('t-ip', 1004, 'ip-d');",
                    message, sizeof(message)) != SQLITE_OK) {
        fprintf(stderr, "another tenant's address or devices without one were refused: %s\n", message);
        ++failures;
    }

    if (setenv("SPECUS_PEER_MESH_CIDR", "10.200.0.0/29", 1) != 0) {
        unlink(path);
        return 1;
    }
    st_storage_client clients[7];
    for (int i = 0; i < 7; ++i) {
        char name[32];
        snprintf(name, sizeof(name), "race-client-%d", i);
        if (st_storage_upsert_client(path, 0, "t-race", name, "admin", 1, 30, &clients[i]) != 0) {
            fprintf(stderr, "race client %d could not be created\n", i);
            ++failures;
        }
    }
    for (int round = 0; failures == 0 && round < 5; ++round) {
        if (exec_script(path, "DELETE FROM peer_mesh_device WHERE tenant_id = 't-race'") != 0
            || race_peer_mesh_enrolments(path, clients, 6U) != 0) {
            fprintf(stderr, "round %d: a racing enrolment failed\n", round);
            ++failures;
        } else if (query_int(path, "SELECT COUNT(*) FROM peer_mesh_device WHERE tenant_id = 't-race'") != 6
                   || query_int(path, "SELECT COUNT(DISTINCT virtual_ip) FROM peer_mesh_device "
                                      "WHERE tenant_id = 't-race' AND virtual_ip LIKE '10.200.0.%'") != 6) {
            fprintf(stderr, "round %d: racing enrolments shared a virtual address\n", round);
            ++failures;
        }
    }
    st_storage_peer_mesh_device device;
    if (failures == 0
        && (st_storage_ensure_peer_mesh_device(path, &clients[6], &device) == 0
            || query_int(path, "SELECT COUNT(*) FROM peer_mesh_device WHERE tenant_id = 't-race'") != 6)) {
        fprintf(stderr, "a seventh device was enrolled in a pool of six addresses\n");
        ++failures;
    }
    unsetenv("SPECUS_PEER_MESH_CIDR");
    unlink(path);
    return failures == 0 ? 0 : 1;
}

/*
 * Java SqliteUniqueIndexMigratorTests.leavesConflictingRowsAloneAndCreatesTheIndexOnceTheyAreResolved
 * and rowsWithANullKeyColumnDoNotCollide, for the two keys C databases ran without: rows that
 * already share a key keep the index out and are left exactly as they are, at every start, until
 * they are resolved; rows whose key column is NULL never collide. An index of that name on other
 * columns is left alone as well.
 */
static int test_reported_unique_keys_wait_for_their_rows(void)
{
    static const char mapping_rows[] =
        "SELECT group_concat(id || '|' || client_name || '|' || listen_port || '|' || target_port, ';') "
        "FROM (SELECT * FROM specus_mapping ORDER BY id)";
    static const char device_rows[] =
        "SELECT group_concat(id || '|' || client_id || '|' || COALESCE(virtual_ip, 'NULL'), ';') "
        "FROM (SELECT * FROM peer_mesh_device ORDER BY id)";
    static const char mapping_index[] =
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'uk_specus_mapping_listen_port'";
    static const char device_index[] =
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'uk_peer_mesh_device_ip'";
    char path[256];
    char text[256];
    scratch_db_path(path, sizeof(path), "reported-unique-keys");
    if (st_storage_init(path, 0) != 0
        || exec_script(path,
               "DROP INDEX uk_specus_mapping_listen_port;"
               "DROP INDEX uk_peer_mesh_device_ip;"
               "INSERT INTO specus_mapping(id, client_name, listen_port, target_address, target_port) "
               "VALUES(1, 'legacy-a', 2222, '127.0.0.1', 22), (2, 'legacy-b', 2222, '127.0.0.1', 2022);"
               "INSERT INTO peer_mesh_device(id, tenant_id, client_id, client_name, virtual_ip) "
               "VALUES(1, 'default', 11, 'legacy-a', '100.96.0.7'), (2, 'default', 12, 'legacy-b', '100.96.0.7'),"
               "(3, 'default', 13, 'legacy-c', NULL), (4, 'default', 14, 'legacy-d', NULL);") != 0) {
        fprintf(stderr, "reported unique keys: legacy rows setup failed\n");
        unlink(path);
        return 1;
    }
    int failures = 0;
    for (int start = 0; start < 2; ++start) {
        if (st_storage_init(path, 0) != 0) {
            fprintf(stderr, "reported unique keys: start %d failed on conflicting rows\n", start);
            ++failures;
        }
        if (query_int(path, mapping_index) != 0 || query_int(path, device_index) != 0
            || unique_index_on(path, "specus_mapping", "listen_port", NULL) != 0
            || unique_index_on(path, "peer_mesh_device", "tenant_id,virtual_ip", NULL) != 0) {
            fprintf(stderr, "reported unique keys: start %d created an index over conflicting rows\n", start);
            ++failures;
        }
        query_text(path, mapping_rows, text, sizeof(text));
        if (strcmp(text, "1|legacy-a|2222|22;2|legacy-b|2222|2022") != 0) {
            fprintf(stderr, "reported unique keys: start %d changed the mappings: %s\n", start, text);
            ++failures;
        }
        query_text(path, device_rows, text, sizeof(text));
        if (strcmp(text, "1|11|100.96.0.7;2|12|100.96.0.7;3|13|NULL;4|14|NULL") != 0) {
            fprintf(stderr, "reported unique keys: start %d changed the devices: %s\n", start, text);
            ++failures;
        }
    }
    if (exec_script(path, "UPDATE specus_mapping SET listen_port = 2223 WHERE id = 2") != 0
        || st_storage_init(path, 0) != 0
        || unique_index_on(path, "specus_mapping", "listen_port", "uk_specus_mapping_listen_port") != 1
        || query_int(path, device_index) != 0) {
        fprintf(stderr, "reported unique keys: the mapping index did not follow its resolved rows alone\n");
        ++failures;
    }
    /* The two devices without an address stay: NULLs never collide. */
    if (exec_script(path, "UPDATE peer_mesh_device SET virtual_ip = '100.96.0.8' WHERE id = 2") != 0
        || st_storage_init(path, 0) != 0
        || unique_index_on(path, "peer_mesh_device", "tenant_id,virtual_ip", "uk_peer_mesh_device_ip") != 1
        || query_int(path, "SELECT COUNT(*) FROM peer_mesh_device") != 4) {
        fprintf(stderr, "reported unique keys: the device index did not follow its resolved rows\n");
        ++failures;
    }
    if (exec_script(path, "DROP INDEX uk_specus_mapping_listen_port;"
                          "CREATE INDEX uk_specus_mapping_listen_port ON specus_mapping(target_port);") != 0
        || st_storage_init(path, 0) != 0
        || unique_index_on(path, "specus_mapping", "listen_port", NULL) != 0
        || query_int(path, "SELECT COUNT(*) FROM sqlite_master WHERE name = 'uk_specus_mapping_listen_port' "
                           "AND sql LIKE '%(target_port)'") != 1) {
        fprintf(stderr, "reported unique keys: an index of that name on other columns was replaced\n");
        ++failures;
    }
    unlink(path);
    return failures == 0 ? 0 : 1;
}

/*
 * Java uk_specus_mapping_listen_port: a public port belongs to one mapping of any client. The
 * management API refuses a taken port before writing (management_crud_tests); here every storage
 * write path meets the key itself. The upsert still replaces the target of the client's own mapping
 * on the port and refuses another client's; a create or a move onto a taken port fails, the move
 * telling the caller so (-2) apart from a mapping that is gone (-1).
 */
static int test_mapping_listen_port_is_unique(void)
{
    char path[256];
    char message[256];
    scratch_db_path(path, sizeof(path), "mapping-port");
    st_storage_client a;
    st_storage_client b;
    st_storage_mapping mapping_a;
    st_storage_mapping mapping_b;
    st_storage_mapping refused;
    if (st_storage_init(path, 0) != 0
        || st_storage_upsert_client(path, 0, "default", "map-a", "admin", 1, 30, &a) != 0
        || st_storage_upsert_client(path, 0, "default", "map-b", "admin", 1, 30, &b) != 0
        || st_storage_create_mapping_for_client(path, a.id, 18080, "127.0.0.1", 8080, 1, 0, &mapping_a) != 0) {
        fprintf(stderr, "mapping port: setup failed\n");
        unlink(path);
        return 1;
    }
    int failures = 0;
    if (st_storage_upsert_mapping(path, "map-b", 18080, "127.0.0.1", 9, 1) != -1
        || query_int(path, "SELECT COUNT(*) FROM specus_mapping WHERE listen_port = 18080") != 1) {
        fprintf(stderr, "mapping port: the upsert gave another client's port a second mapping\n");
        ++failures;
    }
    char sql[160];
    char text[128];
    snprintf(sql, sizeof(sql), "SELECT target_address || ':' || target_port || ':' || enabled "
                               "FROM specus_mapping WHERE id = %lld", mapping_a.id);
    int upserted = st_storage_upsert_mapping(path, "map-a", 18080, "10.0.0.1", 9090, 0);
    query_text(path, sql, text, sizeof(text));
    if (upserted != 0 || strcmp(text, "10.0.0.1:9090:0") != 0
        || query_int(path, "SELECT COUNT(*) FROM specus_mapping") != 1) {
        fprintf(stderr, "mapping port: the upsert no longer replaces the client's own mapping (%s)\n", text);
        ++failures;
    }
    if (st_storage_create_mapping_for_client(path, b.id, 18080, "127.0.0.1", 9, 1, 0, &refused) != -1
        || st_storage_create_mapping_for_client(path, b.id, 18081, "127.0.0.1", 9, 1, 0, &mapping_b) != 0) {
        fprintf(stderr, "mapping port: create on a taken or a free port answered wrongly\n");
        ++failures;
    }
    snprintf(sql, sizeof(sql), "SELECT listen_port FROM specus_mapping WHERE id = %lld", mapping_b.id);
    if (st_storage_update_mapping_by_id(path, mapping_b.id, 18080, "127.0.0.1", 9, 1, 0, &refused) != -2
        || query_int(path, sql) != 18081
        || st_storage_update_mapping_by_id(path, mapping_b.id + 1000, 18082, "127.0.0.1", 9, 1, 0, &refused) != -1) {
        fprintf(stderr, "mapping port: a move onto a taken port or of a missing mapping answered wrongly\n");
        ++failures;
    }
    if (exec_status(path, "INSERT INTO specus_mapping(client_name, listen_port, target_address, target_port) "
                          "VALUES('map-c', 18081, '127.0.0.1', 9)", message, sizeof(message)) != SQLITE_CONSTRAINT
        || strcmp(message, "UNIQUE constraint failed: specus_mapping.listen_port") != 0) {
        fprintf(stderr, "mapping port: a raw second mapping on a port was not refused: %s\n", message);
        ++failures;
    }
    unlink(path);
    return failures == 0 ? 0 : 1;
}

/* Java Instant.toString with a fraction: "YYYY-MM-DDTHH:MM:SS." then 3, 6 or 9 digits and "Z". */
static int is_fractional_instant(const char *text)
{
    static const char pattern[] = "dddd-dd-ddTdd:dd:dd.";
    size_t len = strlen(text);
    if (len != 24U && len != 27U && len != 30U) return 0;
    for (size_t i = 0U; i + 1U < len; ++i) {
        char expected = i < sizeof(pattern) - 1U ? pattern[i] : 'd';
        if (expected == 'd' ? text[i] < '0' || text[i] > '9' : text[i] != expected) return 0;
    }
    return text[len - 1U] == 'Z';
}

/*
 * The values TrafficUsageService writes on every flush. updated_at is Instant.now().toString(), so
 * it carries the fraction of a second (C wrote SQLite's whole-second CURRENT_TIMESTAMP). A
 * resource row takes the id and name the resource has at that moment: the mapping on port 9000
 * deleted is a NULL id with "端口 9000", the one created on it later its new id. C kept the first
 * id it had stored.
 */
static int test_traffic_usage_rows(void)
{
    char path[256];
    scratch_db_path(path, sizeof(path), "traffic-rows");
    st_storage_client client;
    if (st_storage_init(path, 0) != 0
        || st_storage_upsert_client(path, 0, "tenant-rows", "rows-client", "owner", 1, 30, &client) != 0) {
        fprintf(stderr, "traffic rows: setup failed\n");
        unlink(path);
        return 1;
    }
    char before[ST_INSTANT_CAPACITY];
    char after[ST_INSTANT_CAPACITY];
    char stored[ST_INSTANT_CAPACITY];
    st_storage_traffic_usage day[2];
    size_t day_count = 0U;
    int failed = st_instant_now(before) != 0
        || st_storage_record_traffic_usage(path, client.id, "rows-client", "2026-10-20", 1, 2) != 0
        || st_instant_now(after) != 0
        || st_storage_list_traffic_usage(path, client.id, 10, day, 2U, &day_count) != 0 || day_count != 1U;
    if (!failed && (!is_fractional_instant(day[0].updated_at) || st_instant_normalize(day[0].updated_at, stored) != 0
                    || strcmp(stored, before) < 0 || strcmp(stored, after) > 0)) {
        fprintf(stderr, "traffic rows: updatedAt %s is not Instant.toString between %s and %s\n",
                day[0].updated_at, before, after);
        failed = 1;
    }
    static const long long ids[] = {3, 0, 7};
    static const char *const names[] = {"9000 -> 10.0.0.1:22", "端口 9000", "9000 -> 10.0.0.2:2222"};
    for (size_t i = 0U; !failed && i < sizeof(ids) / sizeof(ids[0]); ++i) {
        st_storage_resource_traffic_usage rows[2];
        size_t row_count = 0U;
        failed = st_storage_record_resource_traffic_usage(path, client.id, "rows-client", "TCP_SPECUS", "tcp:9000",
                                                          ids[i], names[i], "2026-10-20", 10, 20) != 0
            || st_storage_list_resource_traffic_usage(path, "TCP_SPECUS", client.id, 10, rows, 2U, &row_count) != 0
            || row_count != 1U || rows[0].resource_id != ids[i] || strcmp(rows[0].resource_name, names[i]) != 0
            || rows[0].upload_bytes != 10 * (long long)(i + 1U) || rows[0].download_bytes != 20 * (long long)(i + 1U)
            || !is_fractional_instant(rows[0].updated_at);
        if (failed) {
            fprintf(stderr, "traffic rows: after write %zu the resource row is id %lld, %s, %lld/%lld, %s; "
                            "expected id %lld, %s\n", i, row_count == 1U ? rows[0].resource_id : -1,
                    row_count == 1U ? rows[0].resource_name : "-", row_count == 1U ? rows[0].upload_bytes : -1,
                    row_count == 1U ? rows[0].download_bytes : -1, row_count == 1U ? rows[0].updated_at : "-",
                    ids[i], names[i]);
        }
    }
    unlink(path);
    return failed ? 1 : 0;
}

static long long query_count(const char *path, const char *format, long long id)
{
    char sql[512];
    snprintf(sql, sizeof(sql), format, id);
    return query_int(path, sql);
}

/*
 * Java keys a client's traffic by its account (TrafficUsageService's upserts, by client_id), and
 * a deleted client's rows stay. "keyed" counts 100 bytes on 2026-10-20 and is deleted; a new
 * client of the same name in another tenant counts 50 that day: each has its own row in its own
 * tenant, where C added the 50 to the deleted client's row, in the first tenant. "bar", renamed
 * to the name of a deleted client that has rows on two of bar's days, keeps its rows and the
 * deleted client keeps its own (C's UPDATE OR REPLACE deleted those), and bar's next bytes land on
 * bar's row.
 */
static int test_traffic_usage_keys(void)
{
    char path[256];
    scratch_db_path(path, sizeof(path), "traffic-keys");
    st_storage_client first;
    st_storage_client second;
    int failed = st_storage_init(path, 0) != 0
        || st_storage_upsert_client(path, 0, "tenant-a", "keyed", "owner", 1, 30, &first) != 0
        || st_storage_record_traffic_usage(path, first.id, "keyed", "2026-10-20", 100, 101) != 0
        || st_storage_record_resource_traffic_usage(path, first.id, "keyed", "HTTP_ROUTE", "http:web", 0, "web",
                                                    "2026-10-20", 100, 101) != 0
        || st_storage_delete_client(path, first.id) != 0
        || st_storage_upsert_client(path, 0, "tenant-b", "keyed", "owner", 1, 30, &second) != 0
        || second.id == first.id
        || st_storage_record_traffic_usage(path, second.id, "keyed", "2026-10-20", 50, 51) != 0
        || st_storage_record_resource_traffic_usage(path, second.id, "keyed", "HTTP_ROUTE", "http:web", 0, "web",
                                                    "2026-10-20", 50, 51) != 0;
    if (failed) {
        fprintf(stderr, "traffic keys: setup failed\n");
    }
    for (int resource = 0; !failed && resource < 2; ++resource) {
        const char *table = resource ? "resource_traffic_usage" : "traffic_usage";
        char format[256];
        snprintf(format, sizeof(format),
                 "SELECT upload_bytes * 1000 + download_bytes FROM %s WHERE client_id = %%lld AND tenant_id = 'tenant-a'",
                 table);
        long long old_row = query_count(path, format, first.id);
        snprintf(format, sizeof(format),
                 "SELECT upload_bytes * 1000 + download_bytes FROM %s WHERE client_id = %%lld AND tenant_id = 'tenant-b'",
                 table);
        long long new_row = query_count(path, format, second.id);
        snprintf(format, sizeof(format), "SELECT COUNT(*) FROM %s WHERE client_name = 'keyed'", table);
        long long rows = query_int(path, format);
        if (old_row != 100101 || new_row != 50051 || rows != 2) {
            fprintf(stderr, "traffic keys: %s holds %lld for the deleted client in tenant-a, %lld for the new one in "
                            "tenant-b, %lld row(s) named keyed; expected 100101, 50051 and 2\n",
                    table, old_row, new_row, rows);
            failed = 1;
        }
    }
    st_storage_traffic_usage visible[4];
    size_t visible_count = 0U;
    if (!failed && (st_storage_list_traffic_usage_visible(path, 0, "tenant-b", NULL, 1, 10, visible, 4U,
                                                          &visible_count) != 0
                    || visible_count != 1U || visible[0].client_id != second.id || visible[0].upload_bytes != 50)) {
        fprintf(stderr, "traffic keys: tenant-b's administrator does not see the new client's 50 bytes alone\n");
        failed = 1;
    }

    st_storage_client gone;
    st_storage_client bar;
    failed = failed
        || st_storage_upsert_client(path, 0, "tenant-a", "gone", "owner", 1, 30, &gone) != 0
        || st_storage_record_traffic_usage(path, gone.id, "gone", "2026-10-19", 7, 7) != 0
        || st_storage_record_traffic_usage(path, gone.id, "gone", "2026-10-20", 8, 8) != 0
        || st_storage_record_resource_traffic_usage(path, gone.id, "gone", "TCP_SPECUS", "tcp:9100", 0, "端口 9100",
                                                    "2026-10-19", 7, 7) != 0
        || st_storage_delete_client(path, gone.id) != 0
        || st_storage_upsert_client(path, 0, "tenant-a", "bar", "owner", 1, 30, &bar) != 0
        || st_storage_record_traffic_usage(path, bar.id, "bar", "2026-10-19", 1, 1) != 0
        || st_storage_record_traffic_usage(path, bar.id, "bar", "2026-10-20", 2, 2) != 0
        || st_storage_record_resource_traffic_usage(path, bar.id, "bar", "TCP_SPECUS", "tcp:9100", 0, "端口 9100",
                                                    "2026-10-19", 1, 1) != 0
        || st_storage_upsert_client(path, bar.id, "tenant-a", "gone", "owner", 1, 30, &bar) != 0
        || st_storage_record_traffic_usage(path, bar.id, "gone", "2026-10-20", 5, 5) != 0;
    if (!failed) {
        long long gone_days = query_count(path, "SELECT COUNT(*) FROM traffic_usage WHERE client_id = %lld", gone.id);
        long long gone_sum = query_count(path, "SELECT SUM(upload_bytes) FROM traffic_usage WHERE client_id = %lld",
                                         gone.id);
        long long bar_sum = query_count(path, "SELECT SUM(upload_bytes) FROM traffic_usage WHERE client_id = %lld "
                                              "AND client_name = 'gone'", bar.id);
        long long bar_today = query_count(path, "SELECT upload_bytes FROM traffic_usage WHERE client_id = %lld "
                                                "AND usage_date = '2026-10-20'", bar.id);
        long long resource_rows = query_count(path, "SELECT COUNT(*) FROM resource_traffic_usage "
                                                    "WHERE resource_key = 'tcp:9100' AND client_id = %lld", gone.id)
            + query_count(path, "SELECT COUNT(*) FROM resource_traffic_usage WHERE resource_key = 'tcp:9100' "
                                "AND client_id = %lld AND client_name = 'gone'", bar.id);
        if (gone_days != 2 || gone_sum != 15 || bar_sum != 8 || bar_today != 7 || resource_rows != 2) {
            fprintf(stderr, "traffic keys after the rename: deleted client %lld day(s) %lld bytes, renamed client "
                            "%lld bytes (%lld today), %lld resource row(s); expected 2, 15, 8 (7), 2\n",
                    gone_days, gone_sum, bar_sum, bar_today, resource_rows);
            failed = 1;
        }
    }
    unlink(path);
    return failed ? 1 : 0;
}

/*
 * Java SqliteUniqueIndexMigratorTests.mergesSplitTrafficCountersIntoTheNewestRowAndEnablesTheUpsert
 * on a database C keyed by client name: client 7's 2026-10-01 counted under its old and its new
 * name is summed into the newest row (30/300, the later updated_at), its other day and the rows
 * without a client id stay, the resource table likewise (keeping the newest row's resource id and
 * name), every id and the id sequence survive the rebuild, Java's two indexes replace the inline
 * ones, a second start changes nothing, and a count for client 7 now adds to the merged row.
 */
static int test_traffic_usage_key_migration(void)
{
    char path[256];
    scratch_db_path(path, sizeof(path), "traffic-key-migration");
    int failed = exec_script(path,
        "CREATE TABLE traffic_usage (id INTEGER PRIMARY KEY AUTOINCREMENT, client_id INTEGER, "
        "client_name TEXT NOT NULL, usage_date TEXT NOT NULL, upload_bytes INTEGER NOT NULL DEFAULT 0, "
        "download_bytes INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, "
        "UNIQUE(client_name, usage_date));"
        "ALTER TABLE traffic_usage ADD COLUMN tenant_id TEXT;"
        "CREATE TABLE resource_traffic_usage (id INTEGER PRIMARY KEY AUTOINCREMENT, client_id INTEGER, "
        "client_name TEXT NOT NULL, resource_type TEXT NOT NULL, resource_key TEXT NOT NULL, resource_id INTEGER, "
        "resource_name TEXT, usage_date TEXT NOT NULL, upload_bytes INTEGER NOT NULL DEFAULT 0, "
        "download_bytes INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, "
        "UNIQUE(client_name, resource_type, resource_key, usage_date));"
        "ALTER TABLE resource_traffic_usage ADD COLUMN tenant_id TEXT;"
        "INSERT INTO traffic_usage(id, tenant_id, client_id, client_name, usage_date, upload_bytes, download_bytes, "
        "updated_at) VALUES"
        "(1, 'default', 7, 'old-name', '2026-10-01', 10, 100, '2026-10-01T10:00:00Z'),"
        "(2, 'default', 7, 'new-name', '2026-10-01', 20, 200, '2026-10-01T09:00:00Z'),"
        "(4, 'default', 7, 'new-name', '2026-10-02', 1, 2, '2026-10-02T08:00:00Z'),"
        "(5, NULL, NULL, 'legacy-a', '2026-10-01', 3, 4, '2026-10-01 00:00:00'),"
        "(6, NULL, NULL, 'legacy-b', '2026-10-01', 5, 6, '2026-10-01 00:00:00');"
        "UPDATE sqlite_sequence SET seq = 50 WHERE name = 'traffic_usage';"
        "INSERT INTO resource_traffic_usage(id, tenant_id, client_id, client_name, resource_type, resource_key, "
        "resource_id, resource_name, usage_date, upload_bytes, download_bytes, updated_at) VALUES"
        "(1, 'default', 7, 'old-name', 'TCP_SPECUS', 'tcp:9000', 3, '9000 -> a:1', '2026-10-01', 10, 100, "
        "'2026-10-01T10:00:00Z'),"
        "(2, 'default', 7, 'new-name', 'TCP_SPECUS', 'tcp:9000', 4, '9000 -> b:2', '2026-10-01', 20, 200, "
        "'2026-10-01T09:00:00Z'),"
        "(3, 'default', 7, 'new-name', 'HTTP_ROUTE', 'http:web', NULL, 'web', '2026-10-01', 1, 2, "
        "'2026-10-01T08:00:00Z');") != 0
        || st_storage_init(path, 0) != 0;
    char rows[1024] = "";
    const char *expected_rows =
        "2:7:new-name:2026-10-01:30/300:2026-10-01T10:00:00Z|4:7:new-name:2026-10-02:1/2:2026-10-02T08:00:00Z|"
        "5:-:legacy-a:2026-10-01:3/4:2026-10-01 00:00:00|6:-:legacy-b:2026-10-01:5/6:2026-10-01 00:00:00";
    if (!failed) {
        query_text(path, "SELECT group_concat(id || ':' || COALESCE(client_id, '-') || ':' || client_name || ':' || "
                         "usage_date || ':' || upload_bytes || '/' || download_bytes || ':' || updated_at, '|') "
                         "FROM (SELECT * FROM traffic_usage ORDER BY id)", rows, sizeof(rows));
        failed = strcmp(rows, expected_rows) != 0;
        if (failed) fprintf(stderr, "traffic key migration: daily rows\n%s\nexpected\n%s\n", rows, expected_rows);
    }
    const char *expected_resources =
        "2:7:tcp:9000:4:9000 -> b:2:30/300:2026-10-01T10:00:00Z|3:7:http:web:-:web:1/2:2026-10-01T08:00:00Z";
    if (!failed) {
        query_text(path, "SELECT group_concat(id || ':' || client_id || ':' || resource_key || ':' || "
                         "COALESCE(resource_id, '-') || ':' || resource_name || ':' || upload_bytes || '/' || "
                         "download_bytes || ':' || updated_at, '|') FROM (SELECT * FROM resource_traffic_usage "
                         "ORDER BY id)", rows, sizeof(rows));
        failed = strcmp(rows, expected_resources) != 0;
        if (failed) fprintf(stderr, "traffic key migration: resource rows\n%s\nexpected\n%s\n", rows,
                            expected_resources);
    }
    if (!failed
        && (unique_index_on(path, "traffic_usage", "client_id,usage_date", "uk_specus_traffic_client_date") != 1
            || unique_index_on(path, "traffic_usage", "client_name,usage_date", NULL) != 0
            || unique_index_on(path, "resource_traffic_usage", "tenant_id,client_id,resource_type,resource_key,usage_date",
                               "uk_resource_traffic_resource_date") != 1
            || unique_index_on(path, "resource_traffic_usage", "client_name,resource_type,resource_key,usage_date",
                               NULL) != 0)) {
        fprintf(stderr, "traffic key migration: the keys are not Java's\n");
        failed = 1;
    }
    long counter = failed ? -1L : file_change_counter(path);
    if (!failed && (st_storage_init(path, 0) != 0 || file_change_counter(path) != counter)) {
        fprintf(stderr, "traffic key migration: a second start wrote to the database\n");
        failed = 1;
    }
    failed = failed
        || exec_script(path, "INSERT INTO client_account(id, tenant_id, client_name) VALUES(7, 'default', 'new-name')") != 0
        || st_storage_record_traffic_usage(path, 7, "new-name", "2026-10-01", 5, 50) != 0
        || st_storage_record_traffic_usage(path, 7, "new-name", "2026-10-03", 1, 1) != 0;
    long long merged = failed ? -1 : query_int(path, "SELECT upload_bytes * 1000 + download_bytes FROM traffic_usage "
                                                     "WHERE id = 2");
    long long next_id = failed ? -1 : query_int(path, "SELECT id FROM traffic_usage WHERE usage_date = '2026-10-03'");
    /* An upsert that updates still draws an AUTOINCREMENT number, so the new row is 51 or later. */
    if (!failed && (merged != 35350 || next_id <= 50)) {
        fprintf(stderr, "traffic key migration: the merged row holds %lld (35350 expected) and the next row got "
                        "id %lld (above the sequence's 50 expected)\n", merged, next_id);
        failed = 1;
    }
    unlink(path);
    return failed ? 1 : 0;
}

int main(void)
{
    if (test_client_account_id_migration() != 0) {
        return 1;
    }
    if (test_traffic_usage_rows() != 0 || test_traffic_usage_keys() != 0 || test_traffic_usage_key_migration() != 0) {
        return 1;
    }
    if (test_login_name_migration_backfills_legacy_rows() != 0
        || test_login_name_migration_refuses_duplicates_inside_a_tenant() != 0
        || test_login_name_migration_rejects_a_wrong_index() != 0
        || test_login_names_are_unique_per_tenant() != 0) {
        return 1;
    }
    if (test_peer_mesh_acl_direction_migration() != 0) {
        return 1;
    }
    if (test_client_auth_nonce_store() != 0) {
        return 1;
    }
    if (test_peer_service_discovery_migration() != 0) {
        return 1;
    }
    if (test_client_download_catalog_migration() != 0) {
        return 1;
    }
    if (test_connection_archive_window() != 0) {
        return 1;
    }
    if (test_init_writes_nothing_on_a_current_database() != 0) {
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
    /* Run all of them: each names what it found, and the schema checks are independent. */
    int schema_failures = test_schema_enforces_java_unique_keys()
        + test_every_identity_id_aliases_the_rowid()
        + test_restart_keeps_the_schema()
        + test_login_name_migration_accepts_an_existing_index()
        + test_peer_service_migration_creates_the_shared_service_keys()
        + test_peer_mesh_device_ip_is_unique()
        + test_reported_unique_keys_wait_for_their_rows()
        + test_mapping_listen_port_is_unique();
    if (schema_failures != 0) {
        fprintf(stderr, "%d schema test(s) failed\n", schema_failures);
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
        || st_storage_delete_management_user(path, "tenant-other", "alice", "admin") == 0
        || st_storage_get_management_user_in_tenant(path, "default", "alice", &created_user) != 0
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
    if (st_storage_get_management_user_in_tenant(path, "default", "alice", &created_user) != 0
        || strcmp(created_user.username, "alice") != 0
        || created_user.enabled != 0) {
        fprintf(stderr, "management user lookup mismatch\n");
        unlink(path);
        return 1;
    }
    if (st_storage_delete_management_user(path, "default", "alice", "admin") != 0
        || st_storage_get_management_user_in_tenant(path, "default", "alice", &created_user) == 0) {
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
    session.client_egress_ipv6_targets = 1;
    session.client_egress_ipv6_packets = 1;
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
        || !session.client_egress_domain_targets
        || !session.client_egress_ipv6_targets
        || !session.client_egress_ipv6_packets) {
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
        || !login_session.client_egress_ipv6_targets
        || !login_session.client_egress_ipv6_packets
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
        || !capability_client.client_egress_ipv6_targets
        || !capability_client.client_egress_ipv6_packets
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
        || capability_client.client_egress_ipv6_targets
        || capability_client.client_egress_ipv6_packets
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
    st_storage_peer_mesh_acl *visible_acls = NULL;
    size_t visible_acl_count = 0;
    int owner_ok = st_storage_list_peer_mesh_acls_visible(path,
                                                          "tenant-c",
                                                          "OwnerCase",
                                                          0,
                                                          &visible_acls,
                                                          &visible_acl_count) == 0
        && visible_acl_count == 1U
        && visible_acls[0].id == acl_id;
    free(visible_acls);
    visible_acls = NULL;
    int other_case_owner_ok = st_storage_list_peer_mesh_acls_visible(path,
                                                                     "tenant-c",
                                                                     "ownercase",
                                                                     0,
                                                                     &visible_acls,
                                                                     &visible_acl_count) == 0
        && visible_acl_count == 0U;
    free(visible_acls);
    visible_acls = NULL;
    int other_case_tenant_ok = st_storage_list_peer_mesh_acls_visible(path,
                                                                      "TENANT-C",
                                                                      "OwnerCase",
                                                                      1,
                                                                      &visible_acls,
                                                                      &visible_acl_count) == 0
        && visible_acl_count == 0U;
    free(visible_acls);
    if (!owner_ok || !other_case_owner_ok || !other_case_tenant_ok) {
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
    st_storage_mapping *mappings = NULL;
    size_t count = 0;
    if (st_storage_load_mappings(path, "Demo client", &mappings, &count) != 0
        || count != 1U
        || mappings[0].listen_port != 18080
        || strcmp(mappings[0].target_address, "127.0.0.1") != 0
        || mappings[0].target_port != 8080
        || mappings[0].enabled != 1
        || mappings[0].detail_capture_enabled != 0) {
        fprintf(stderr, "mapping load mismatch\n");
        free(mappings);
        unlink(path);
        return 1;
    }
    free(mappings);
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
    if (st_storage_list_mappings(path, clients[0].id, &mappings, &count) != 0 || count != 2U) {
        fprintf(stderr, "mapping list mismatch\n");
        free(mappings);
        unlink(path);
        return 1;
    }
    free(mappings);
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
    st_storage_http_route *routes = NULL;
    size_t route_count = 0;
    if (st_storage_list_http_routes(path, clients[0].id, &routes, &route_count) != 0
        || route_count != 1U
        || strcmp(routes[0].auth_username, "viewer") != 0
        || strcmp(routes[0].auth_password_hash, updated_route_password_hash) != 0) {
        fprintf(stderr, "http route list mismatch\n");
        free(routes);
        unlink(path);
        return 1;
    }
    free(routes);
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
