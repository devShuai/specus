#define _POSIX_C_SOURCE 200809L

#include "json.h"
#include "peer_egress.h"
#include "peer_mesh.h"
#include "storage.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef ST_EGRESS_VECTOR_DIR
#define ST_EGRESS_VECTOR_DIR "../../../protocol/test-vectors/"
#endif

typedef struct {
    char target[128];
    char source[128];
    char message[8192];
} captured_signal;

typedef struct {
    captured_signal signals[32];
    size_t count;
    int target_online;
} peer_test_context;

static int capture_signal(void *raw,
                          const char *target,
                          const char *source,
                          const char *message)
{
    peer_test_context *ctx = (peer_test_context *)raw;
    if (ctx->count >= sizeof(ctx->signals) / sizeof(ctx->signals[0])
        || strlen(target) >= sizeof(ctx->signals[0].target)
        || strlen(source) >= sizeof(ctx->signals[0].source)
        || strlen(message) >= sizeof(ctx->signals[0].message)) return -1;
    captured_signal *signal = &ctx->signals[ctx->count++];
    strcpy(signal->target, target);
    strcpy(signal->source, source);
    strcpy(signal->message, message);
    return 0;
}

static int is_online(void *raw, long long client_id, const char *client_name)
{
    (void)client_id;
    peer_test_context *ctx = (peer_test_context *)raw;
    return strcmp(client_name, "peer-source") == 0
        || (ctx->target_online && strcmp(client_name, "peer-target") == 0);
}

static int contains(const char *value, const char *needle)
{
    return value != NULL && strstr(value, needle) != NULL;
}

static int exec_sql_on(const char *path, const char *sql);

/* Public Instant strings use UTC Z and zero, three, six or nine fractional digits.
 * The fixed seven-digit database representation must not escape into a signal. */
static int has_wire_expiry(const char *message)
{
    char *value = message == NULL ? NULL : st_json_get_top_level_string(message, "expiresAt");
    if (value == NULL) return 0;
    size_t length = strlen(value);
    int valid = length == 20U || length == 24U || length == 27U || length == 30U;
    static const char shape[] = "dddd-dd-ddTdd:dd:dd";
    for (size_t i = 0; valid && shape[i] != '\0'; ++i) {
        valid = shape[i] == 'd' ? (value[i] >= '0' && value[i] <= '9') : value[i] == shape[i];
    }
    if (valid) valid = value[length - 1U] == 'Z' && (length == 20U || value[19] == '.');
    for (size_t i = 20U; valid && i + 1U < length; ++i) {
        valid = value[i] >= '0' && value[i] <= '9';
    }
    free(value);
    return valid;
}

static int test_wire_expiry_format(void)
{
    static const struct { const char *value; int valid; } cases[] = {
        {"2026-10-19T10:00:00Z", 1},
        {"2026-10-19T10:00:00.123Z", 1},
        {"2026-10-19T10:00:00.123456Z", 1},
        {"2026-10-19T10:00:00.123456700Z", 1},
        {"2026-10-19 10:00:00Z", 0},
        {"2026-10-19T10:00:00.1234567Z", 0},
        {"2026-10-19T10:00:00.1234567890Z", 0},
        {"2026-10-19T10:00:00.12xZ", 0},
        {"2026-10-19T10:00:00.123+00:00", 0},
        {"2026-10-19T10:00:00z", 0},
        {"2026-10-19T10:00:00", 0},
        {"2026-10-19T10:00:00Zextra", 0},
        {"", 0}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        char message[160];
        snprintf(message, sizeof(message), "{\"expiresAt\":\"%s\"}", cases[i].value);
        if (has_wire_expiry(message) != cases[i].valid) {
            fprintf(stderr, "wire expiry format assertion mismatch: %s\n", cases[i].value);
            return 1;
        }
    }
    return has_wire_expiry(NULL) || has_wire_expiry("{}")
        || has_wire_expiry("{\"expiresAt\":null}");
}

/* The catalogue fixture: the consumer and the plain egress stay up, the DNS egress comes and goes. */
typedef struct {
    peer_test_context capture;
    int dns_egress_online;
} egress_test_context;

static int capture_egress_signal(void *raw,
                                 const char *target,
                                 const char *source,
                                 const char *message)
{
    return capture_signal(&((egress_test_context *)raw)->capture, target, source, message);
}

static int egress_is_online(void *raw, long long client_id, const char *client_name)
{
    (void)client_id;
    egress_test_context *ctx = (egress_test_context *)raw;
    return strcmp(client_name, "egress-consumer") == 0
        || strcmp(client_name, "egress-plain") == 0
        || (ctx->dns_egress_online && strcmp(client_name, "egress-dns") == 0);
}

/* Logs a client in the way the HTTP login and the control connection leave its session row. */
static int open_egress_session_announcing(const char *path,
                                          const st_storage_client *client,
                                          int egress_version,
                                          int domain_targets,
                                          long long *session_id)
{
    static int logins;
    st_storage_client_session session;
    memset(&session, 0, sizeof(session));
    snprintf(session.tenant_id, sizeof(session.tenant_id), "%s", client->tenant_id);
    session.credential_id = 1;
    session.identity_id = client->id;
    session.client_id = client->id;
    snprintf(session.client_name, sizeof(session.client_name), "%s", client->client_name);
    snprintf(session.token_hash, sizeof(session.token_hash), "token-%d", ++logins);
    snprintf(session.status, sizeof(session.status), "%s", "HTTP_AUTHENTICATED");
    snprintf(session.machine_fingerprint, sizeof(session.machine_fingerprint), "machine-%lld", client->id);
    snprintf(session.os_user, sizeof(session.os_user), "%s", "tester");
    snprintf(session.http_login_at, sizeof(session.http_login_at), "%s", "2026-06-25T00:00:00Z");
    snprintf(session.expires_at, sizeof(session.expires_at), "%s", "2099-06-25T08:00:00Z");
    session.client_egress_version = egress_version;
    session.client_egress_domain_targets = domain_targets;
    if (st_storage_create_client_session(path, &session, &session) != 0
        || st_storage_mark_client_session_online(path, session.id, "channel", "127.0.0.1:7000",
                                                 "2026-06-25T00:01:00Z") != 0) return -1;
    *session_id = session.id;
    return 0;
}

static int open_egress_session(const char *path,
                               const st_storage_client *client,
                               int domain_targets,
                               long long *session_id)
{
    return open_egress_session_announcing(path, client, 1, domain_targets, session_id);
}

static int add_egress_policy(const char *path, const st_storage_client *egress, long long consumer_id)
{
    st_storage_peer_mesh_egress_policy policy;
    memset(&policy, 0, sizeof(policy));
    snprintf(policy.tenant_id, sizeof(policy.tenant_id), "%s", egress->tenant_id);
    snprintf(policy.owner_username, sizeof(policy.owner_username), "%s", egress->owner_username);
    policy.egress_client_id = egress->id;
    snprintf(policy.egress_client_name, sizeof(policy.egress_client_name), "%s", egress->client_name);
    policy.enabled = 1;
    snprintf(policy.scope, sizeof(policy.scope), "%s", ST_EGRESS_SCOPE_PUBLIC);
    snprintf(policy.allowed_consumer_client_ids, sizeof(policy.allowed_consumer_client_ids), "%lld",
             consumer_id);
    snprintf(policy.destination_rules, sizeof(policy.destination_rules),
             "[{\"cidr\":\"203.0.113.0/24\",\"protocols\":[\"tcp\"],\"portRanges\":[[443,443]]}]");
    policy.max_concurrent_flows = 16;
    policy.max_flows_per_consumer = 8;
    policy.idle_timeout_seconds = 60;
    return st_storage_upsert_peer_mesh_egress_policy(path, &policy, NULL);
}

/* The most recent egress-catalog pushed to the named device, or NULL. */
static const char *last_egress_catalog(const peer_test_context *ctx, const char *target)
{
    const char *found = NULL;
    for (size_t i = 0; i < ctx->count; ++i) {
        if (strcmp(ctx->signals[i].target, target) == 0
            && contains(ctx->signals[i].message, "\"type\":\"egress-catalog\"")) {
            found = ctx->signals[i].message;
        }
    }
    return found;
}

/* A boolean field of one catalogue entry: 1, 0, or -1 when the entry or field is missing. */
static int catalog_entry_flag(const char *message, const char *client_name, const char *field)
{
    char needle[160];
    char key[64];
    snprintf(needle, sizeof(needle), "\"clientName\":\"%s\"", client_name);
    snprintf(key, sizeof(key), "\"%s\":", field);
    const char *entry = message == NULL ? NULL : strstr(message, needle);
    /* Entries hold no nested objects, so the first closing brace ends this one. */
    const char *end = entry == NULL ? NULL : strchr(entry, '}');
    const char *value = entry == NULL ? NULL : strstr(entry, key);
    if (end == NULL || value == NULL || value > end) return -1;
    value += strlen(key);
    if (strncmp(value, "true", 4) == 0) return 1;
    if (strncmp(value, "false", 5) == 0) return 0;
    return -1;
}

/* A non-negative integer field of one catalogue entry, or -1 when the entry or field is missing. */
static long catalog_entry_int(const char *message, const char *client_name, const char *field)
{
    char needle[160];
    char key[64];
    snprintf(needle, sizeof(needle), "\"clientName\":\"%s\"", client_name);
    snprintf(key, sizeof(key), "\"%s\":", field);
    const char *entry = message == NULL ? NULL : strstr(message, needle);
    const char *end = entry == NULL ? NULL : strchr(entry, '}');
    const char *value = entry == NULL ? NULL : strstr(entry, key);
    if (end == NULL || value == NULL || value > end) return -1;
    value += strlen(key);
    char *parsed_end = NULL;
    long parsed = strtol(value, &parsed_end, 10);
    return parsed_end == value || parsed < 0 ? -1 : parsed;
}

/*
 * domainTargetCapable in the egress-catalog follows what each egress declared on its current
 * online session. It used to be written as false for every entry, which left consumers unable to
 * tell which egress could take a domain rule.
 */
static int test_egress_catalog_ipv6_targets(void)
{
    char path[] = "/tmp/specus_c_peer_egress_ipv6_targets.XXXXXX";
    int temp_fd = mkstemp(path);
    if (temp_fd < 0) return 1;
    close(temp_fd);
    unlink(path);
    if (st_storage_init(path, 0) != 0) return 1;
    sqlite3 *db = NULL;
    sqlite3_stmt *probe = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK) { unlink(path); return 1; }
    int has_column = sqlite3_prepare_v2(db,
        "SELECT client_egress_ipv6_targets FROM specus_client_session LIMIT 0", -1, &probe, NULL) == SQLITE_OK;
    sqlite3_finalize(probe);
    /* Test-only legacy scaffolding: the declaration is present in SQL even on
     * the old model, isolating the old catalog's failure to carry it. The HTTP
     * login and migration regressions independently require production storage. */
    if (!has_column && sqlite3_exec(db,
        "ALTER TABLE specus_client_session ADD COLUMN client_egress_ipv6_targets INTEGER NOT NULL DEFAULT 0",
        NULL, NULL, NULL) != SQLITE_OK) { sqlite3_close(db); unlink(path); return 1; }

    st_storage_client consumer, egress;
    st_storage_peer_mesh_device device;
    long long consumer_session = 0, egress_session = 0;
    st_storage_peer_mesh_egress_switch egress_switch;
    memset(&egress_switch, 0, sizeof(egress_switch));
    snprintf(egress_switch.tenant_id, sizeof(egress_switch.tenant_id), "%s", "tenant-egress");
    egress_switch.enabled = 1;
    snprintf(egress_switch.updated_by, sizeof(egress_switch.updated_by), "%s", "admin");
    if (st_storage_upsert_client(path, 0, "tenant-egress", "egress-consumer", "owner", 1, 60, &consumer) != 0
        || st_storage_upsert_client(path, 0, "tenant-egress", "egress-dns", "owner", 1, 60, &egress) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &consumer, 1, &device) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &egress, 1, &device) != 0
        || st_storage_upsert_peer_mesh_egress_switch(path, &egress_switch) != 0
        || add_egress_policy(path, &egress, consumer.id) != 0
        || open_egress_session(path, &consumer, 0, &consumer_session) != 0
        || open_egress_session(path, &egress, 1, &egress_session) != 0) {
        sqlite3_close(db); unlink(path); return 1;
    }
    egress_test_context context;
    memset(&context, 0, sizeof(context));
    context.dns_egress_online = 1;
    st_peer_mesh_runtime runtime = {path, capture_egress_signal, egress_is_online, &context, 0, 2};
    int failed = 0;
    const int expected[] = {1, 0, 0, 0};
    for (size_t i = 0; i < sizeof(expected) / sizeof(expected[0]); ++i) {
        char sql[512];
        if (i == 1 && open_egress_session(path, &egress, 0, &egress_session) != 0) { failed = 1; break; }
        if (i == 0) snprintf(sql, sizeof(sql),
            "UPDATE specus_client_session SET client_egress_ipv6_targets=1 WHERE id=%lld", egress_session);
        else if (i == 1) snprintf(sql, sizeof(sql),
            "UPDATE specus_client_session SET client_egress_ipv6_targets=0 WHERE id=%lld", egress_session);
        else if (i == 2) snprintf(sql, sizeof(sql),
            "UPDATE specus_client_session SET client_egress_version=0,client_egress_ipv6_targets=1 WHERE id=%lld",
            egress_session);
        else {
            snprintf(sql, sizeof(sql), "UPDATE specus_client_session SET status='DISCONNECTED' WHERE client_id=%lld", egress.id);
            context.dns_egress_online = 0;
        }
        if (sqlite3_exec(db, sql, NULL, NULL, NULL) != SQLITE_OK) { failed = 1; break; }
        context.capture.count = 0;
        if (st_peer_mesh_refresh_tenant(&runtime, "tenant-egress") != 0) { failed = 1; break; }
        const char *catalog = last_egress_catalog(&context.capture, "egress-consumer");
        int actual = catalog_entry_flag(catalog, "egress-dns", "ipv6TargetCapable");
        if (actual != expected[i]) {
            fprintf(stderr, "IPv6 target catalog scenario %zu: got %d, expected %d\n", i, actual, expected[i]);
            failed = 1;
        }
    }
    sqlite3_close(db);
    unlink(path);
    return failed;
}

/*
 * ipv6PacketCapable follows the same current online session as ipv6TargetCapable, right after it in
 * each entry, and the two declarations never stand in for each other.
 */
static int test_egress_catalog_ipv6_packets(void)
{
    char path[] = "/tmp/specus_c_peer_egress_ipv6_packets.XXXXXX";
    int temp_fd = mkstemp(path);
    if (temp_fd < 0) return 1;
    close(temp_fd);
    unlink(path);
    if (st_storage_init(path, 0) != 0) return 1;
    sqlite3 *db = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK) { unlink(path); return 1; }

    st_storage_client consumer, egress;
    st_storage_peer_mesh_device device;
    long long consumer_session = 0, egress_session = 0;
    st_storage_peer_mesh_egress_switch egress_switch;
    memset(&egress_switch, 0, sizeof(egress_switch));
    snprintf(egress_switch.tenant_id, sizeof(egress_switch.tenant_id), "%s", "tenant-egress");
    egress_switch.enabled = 1;
    snprintf(egress_switch.updated_by, sizeof(egress_switch.updated_by), "%s", "admin");
    if (st_storage_upsert_client(path, 0, "tenant-egress", "egress-consumer", "owner", 1, 60, &consumer) != 0
        || st_storage_upsert_client(path, 0, "tenant-egress", "egress-dns", "owner", 1, 60, &egress) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &consumer, 1, &device) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &egress, 1, &device) != 0
        || st_storage_upsert_peer_mesh_egress_switch(path, &egress_switch) != 0
        || add_egress_policy(path, &egress, consumer.id) != 0
        || open_egress_session(path, &consumer, 0, &consumer_session) != 0
        || open_egress_session(path, &egress, 1, &egress_session) != 0) {
        sqlite3_close(db); unlink(path); return 1;
    }
    egress_test_context context;
    memset(&context, 0, sizeof(context));
    context.dns_egress_online = 1;
    st_peer_mesh_runtime runtime = {path, capture_egress_signal, egress_is_online, &context, 0, 2};
    int failed = 0;
    const int expected_packets[] = {1, 0, 0, 0};
    const int expected_targets[] = {0, 1, 0, 0};
    for (size_t i = 0; i < sizeof(expected_packets) / sizeof(expected_packets[0]); ++i) {
        char sql[512];
        if (i == 1 && open_egress_session(path, &egress, 0, &egress_session) != 0) { failed = 1; break; }
        if (i == 0) snprintf(sql, sizeof(sql),
            "UPDATE specus_client_session SET client_egress_ipv6_packets=1,client_egress_ipv6_targets=0 "
            "WHERE id=%lld", egress_session);
        else if (i == 1) snprintf(sql, sizeof(sql),
            "UPDATE specus_client_session SET client_egress_ipv6_packets=0,client_egress_ipv6_targets=1 "
            "WHERE id=%lld", egress_session);
        else if (i == 2) snprintf(sql, sizeof(sql),
            "UPDATE specus_client_session SET client_egress_version=0,client_egress_ipv6_packets=1,"
            "client_egress_ipv6_targets=1 WHERE id=%lld", egress_session);
        else {
            snprintf(sql, sizeof(sql), "UPDATE specus_client_session SET status='DISCONNECTED' WHERE client_id=%lld", egress.id);
            context.dns_egress_online = 0;
        }
        if (sqlite3_exec(db, sql, NULL, NULL, NULL) != SQLITE_OK) { failed = 1; break; }
        context.capture.count = 0;
        if (st_peer_mesh_refresh_tenant(&runtime, "tenant-egress") != 0) { failed = 1; break; }
        const char *catalog = last_egress_catalog(&context.capture, "egress-consumer");
        int packets = catalog_entry_flag(catalog, "egress-dns", "ipv6PacketCapable");
        int targets = catalog_entry_flag(catalog, "egress-dns", "ipv6TargetCapable");
        if (packets != expected_packets[i] || targets != expected_targets[i]) {
            fprintf(stderr, "IPv6 packet catalog scenario %zu: got packets %d targets %d, expected %d %d\n",
                    i, packets, targets, expected_packets[i], expected_targets[i]);
            failed = 1;
        }
        if (i == 0 && (catalog == NULL || strstr(catalog,
                "\"ipv6TargetCapable\":false,\"ipv6PacketCapable\":true,\"egressVersion\":1}") == NULL)) {
            fprintf(stderr, "ipv6PacketCapable is not right after ipv6TargetCapable\n");
            failed = 1;
        }
    }
    sqlite3_close(db);
    unlink(path);
    return failed;
}

static int test_egress_catalog_domain_targets(void)
{
    char path[] = "/tmp/specus_c_peer_egress_catalog_tests.XXXXXX";
    int temp_fd = mkstemp(path);
    if (temp_fd < 0) return 1;
    close(temp_fd);
    unlink(path);
    if (st_storage_init(path, 0) != 0) return 1;

    st_storage_client consumer;
    st_storage_client dns_egress;
    st_storage_client plain_egress;
    st_storage_peer_mesh_device device;
    long long consumer_session = 0;
    long long dns_session = 0;
    long long plain_session = 0;
    st_storage_peer_mesh_egress_switch egress_switch;
    memset(&egress_switch, 0, sizeof(egress_switch));
    snprintf(egress_switch.tenant_id, sizeof(egress_switch.tenant_id), "%s", "tenant-egress");
    egress_switch.enabled = 1;
    snprintf(egress_switch.updated_by, sizeof(egress_switch.updated_by), "%s", "admin");
    if (st_storage_upsert_client(path, 0, "tenant-egress", "egress-consumer", "owner", 1, 60, &consumer) != 0
        || st_storage_upsert_client(path, 0, "tenant-egress", "egress-dns", "owner", 1, 60, &dns_egress) != 0
        || st_storage_upsert_client(path, 0, "tenant-egress", "egress-plain", "owner", 1, 60, &plain_egress) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &consumer, 1, &device) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &dns_egress, 1, &device) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &plain_egress, 1, &device) != 0
        || st_storage_upsert_peer_mesh_egress_switch(path, &egress_switch) != 0
        || add_egress_policy(path, &dns_egress, consumer.id) != 0
        || add_egress_policy(path, &plain_egress, consumer.id) != 0
        || open_egress_session(path, &consumer, 0, &consumer_session) != 0
        || open_egress_session(path, &dns_egress, 1, &dns_session) != 0
        || open_egress_session(path, &plain_egress, 0, &plain_session) != 0) {
        fprintf(stderr, "egress catalog fixture setup failed\n");
        unlink(path);
        return 1;
    }

    egress_test_context context;
    memset(&context, 0, sizeof(context));
    context.dns_egress_online = 1;
    st_peer_mesh_runtime runtime = {path, capture_egress_signal, egress_is_online, &context, 0, 2};
    if (st_peer_mesh_refresh_tenant(&runtime, "tenant-egress") != 0) {
        fprintf(stderr, "egress catalog refresh failed\n");
        unlink(path);
        return 1;
    }
    const char *catalog = last_egress_catalog(&context.capture, "egress-consumer");
    if (catalog_entry_flag(catalog, "egress-dns", "domainTargetCapable") != 1
        || catalog_entry_flag(catalog, "egress-plain", "domainTargetCapable") != 0
        || catalog_entry_flag(catalog, "egress-dns", "ipv6TargetCapable") != 0
        || catalog_entry_flag(catalog, "egress-plain", "ipv6TargetCapable") != 0) {
        fprintf(stderr, "egress catalog did not carry the announced domainTargetCapable: %s\n",
                catalog == NULL ? "(none)" : catalog);
        unlink(path);
        return 1;
    }

    /*
     * The departure push runs before the session row is marked disconnected, so the row still says
     * it declared domain targets. The catalogue must follow the live connection, not that row.
     */
    context.capture.count = 0;
    context.dns_egress_online = 0;
    if (st_peer_mesh_push_on_logout(&runtime, "egress-dns") != 0) {
        fprintf(stderr, "egress catalog departure push failed\n");
        unlink(path);
        return 1;
    }
    catalog = last_egress_catalog(&context.capture, "egress-consumer");
    if (catalog_entry_flag(catalog, "egress-dns", "domainTargetCapable") != 0) {
        fprintf(stderr, "egress catalog kept domainTargetCapable for a departed egress: %s\n",
                catalog == NULL ? "(none)" : catalog);
        unlink(path);
        return 1;
    }

    /* Back on a session that did not declare it: the new session wins over the old declaration. */
    context.capture.count = 0;
    context.dns_egress_online = 1;
    if (st_storage_mark_client_session_disconnected(path, dns_session, "2026-06-25T00:02:00Z") != 0
        || open_egress_session(path, &dns_egress, 0, &dns_session) != 0
        || st_peer_mesh_push_on_login(&runtime, "egress-dns") != 0) {
        fprintf(stderr, "egress catalog relogin fixture failed\n");
        unlink(path);
        return 1;
    }
    catalog = last_egress_catalog(&context.capture, "egress-consumer");
    if (catalog_entry_flag(catalog, "egress-dns", "domainTargetCapable") != 0) {
        fprintf(stderr, "egress catalog did not follow the current session's declaration: %s\n",
                catalog == NULL ? "(none)" : catalog);
        unlink(path);
        return 1;
    }

    /* No online session at all reads as not declared, whatever an earlier one said. */
    context.capture.count = 0;
    if (st_storage_mark_client_session_disconnected(path, dns_session, "2026-06-25T00:03:00Z") != 0
        || open_egress_session(path, &dns_egress, 1, &dns_session) != 0
        || st_storage_mark_client_session_disconnected(path, dns_session, "2026-06-25T00:04:00Z") != 0
        || st_peer_mesh_refresh_tenant(&runtime, "tenant-egress") != 0) {
        fprintf(stderr, "egress catalog offline fixture failed\n");
        unlink(path);
        return 1;
    }
    catalog = last_egress_catalog(&context.capture, "egress-consumer");
    if (catalog_entry_flag(catalog, "egress-dns", "domainTargetCapable") != 0
        || catalog_entry_flag(catalog, "egress-plain", "domainTargetCapable") != 0) {
        fprintf(stderr, "egress catalog advertised domain targets without an online session: %s\n",
                catalog == NULL ? "(none)" : catalog);
        unlink(path);
        return 1;
    }
    unlink(path);
    return 0;
}

/* The most recent egress-config pushed to the named device, or NULL. */
static const char *last_egress_config(const peer_test_context *ctx, const char *target)
{
    const char *found = NULL;
    for (size_t i = 0; i < ctx->count; ++i) {
        if (strcmp(ctx->signals[i].target, target) == 0
            && contains(ctx->signals[i].message, "\"type\":\"egress-config\"")) {
            found = ctx->signals[i].message;
        }
    }
    return found;
}

/*
 * The egress-config an enabled egress receives carries the saved domain rules next to the
 * destination rules, and [] when there are none. The disabling push keeps its shape.
 */
static int test_egress_config_domain_rules(void)
{
    char path[] = "/tmp/specus_c_peer_egress_domain_tests.XXXXXX";
    int temp_fd = mkstemp(path);
    if (temp_fd < 0) return 1;
    close(temp_fd);
    unlink(path);
    if (st_storage_init(path, 0) != 0) return 1;

    st_storage_client consumer;
    st_storage_client egress;
    st_storage_peer_mesh_device device;
    long long consumer_session = 0;
    long long egress_session = 0;
    st_storage_peer_mesh_egress_switch egress_switch;
    memset(&egress_switch, 0, sizeof(egress_switch));
    snprintf(egress_switch.tenant_id, sizeof(egress_switch.tenant_id), "%s", "tenant-egress");
    egress_switch.enabled = 1;
    snprintf(egress_switch.updated_by, sizeof(egress_switch.updated_by), "%s", "admin");
    if (st_storage_upsert_client(path, 0, "tenant-egress", "egress-consumer", "owner", 1, 60, &consumer) != 0
        || st_storage_upsert_client(path, 0, "tenant-egress", "egress-plain", "owner", 1, 60, &egress) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &consumer, 1, &device) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &egress, 1, &device) != 0
        || st_storage_upsert_peer_mesh_egress_switch(path, &egress_switch) != 0
        || add_egress_policy(path, &egress, consumer.id) != 0
        || open_egress_session(path, &consumer, 0, &consumer_session) != 0
        || open_egress_session(path, &egress, 1, &egress_session) != 0) {
        fprintf(stderr, "egress domain rules fixture setup failed\n");
        unlink(path);
        return 1;
    }

    egress_test_context context;
    memset(&context, 0, sizeof(context));
    st_peer_mesh_runtime runtime = {path, capture_egress_signal, egress_is_online, &context, 0, 2};
    const char *config = NULL;
    if (st_peer_mesh_refresh_tenant(&runtime, "tenant-egress") != 0
        || (config = last_egress_config(&context.capture, "egress-plain")) == NULL
        || !contains(config, "\"enabled\":true")
        || !contains(config, "\"portRanges\":[[443,443]]}],\"domainRules\":[],\"limits\":")) {
        fprintf(stderr, "an enabled egress-config without domain rules lacked domainRules: []: %s\n",
                config == NULL ? "(none)" : config);
        unlink(path);
        return 1;
    }

    st_storage_peer_mesh_egress_policy policy;
    if (st_storage_find_peer_mesh_egress_policy_by_client(path, "tenant-egress", egress.id, &policy) != 0) {
        unlink(path);
        return 1;
    }
    snprintf(policy.domain_rules, sizeof(policy.domain_rules),
             "[{\"match\":\"*.cdn.example\",\"protocols\":[\"tcp\",\"udp\"],\"portRanges\":[[443,443]]}]");
    context.capture.count = 0;
    if (st_storage_upsert_peer_mesh_egress_policy(path, &policy, NULL) != 0
        || st_peer_mesh_refresh_tenant(&runtime, "tenant-egress") != 0
        || (config = last_egress_config(&context.capture, "egress-plain")) == NULL
        || !contains(config, "\"domainRules\":[{\"match\":\"*.cdn.example\",\"protocols\":[\"tcp\",\"udp\"],"
                             "\"portRanges\":[[443,443]]}]")) {
        fprintf(stderr, "egress-config did not carry the saved domain rules: %s\n",
                config == NULL ? "(none)" : config);
        unlink(path);
        return 1;
    }
    const char *catalog = last_egress_catalog(&context.capture, "egress-consumer");
    if (catalog == NULL || contains(catalog, "domainRules") || contains(catalog, "cdn.example")) {
        fprintf(stderr, "egress-catalog leaked the domain rules: %s\n", catalog == NULL ? "(none)" : catalog);
        unlink(path);
        return 1;
    }

    /*
     * PeerEgressServiceTests unreadableStoredDomainRulesGrantNothing: a stored list that cannot be
     * read, or an empty one, is pushed as no name at all, and the push itself still goes out.
     */
    static const char *const unreadable[] = { "{not json", "" };
    for (size_t i = 0; i < sizeof(unreadable) / sizeof(unreadable[0]); ++i) {
        char sql[256];
        snprintf(sql, sizeof(sql), "UPDATE peer_mesh_egress_policy SET domain_rules='%s' WHERE egress_client_id=%lld",
                 unreadable[i], egress.id);
        context.capture.count = 0;
        if (exec_sql_on(path, sql) != 0
            || st_peer_mesh_refresh_tenant(&runtime, "tenant-egress") != 0
            || (config = last_egress_config(&context.capture, "egress-plain")) == NULL
            || !contains(config, "\"enabled\":true")
            || !contains(config, "\"portRanges\":[[443,443]]}],\"domainRules\":[],\"limits\":")) {
            fprintf(stderr, "stored domain rules '%s' did not push as []: %s\n", unreadable[i],
                    config == NULL ? "(none)" : config);
            unlink(path);
            return 1;
        }
    }

    policy.enabled = 0;
    context.capture.count = 0;
    if (st_storage_upsert_peer_mesh_egress_policy(path, &policy, NULL) != 0
        || st_peer_mesh_refresh_tenant(&runtime, "tenant-egress") != 0
        || (config = last_egress_config(&context.capture, "egress-plain")) == NULL
        || !contains(config, "\"enabled\":false,\"allowedConsumerClientIds\":[],\"destinationRules\":[],")
        || contains(config, "domainRules")) {
        fprintf(stderr, "the disabling egress-config changed shape: %s\n", config == NULL ? "(none)" : config);
        unlink(path);
        return 1;
    }
    unlink(path);
    return 0;
}

static int any_signal_of_type(const peer_test_context *ctx, const char *target, const char *type)
{
    char needle[64];
    snprintf(needle, sizeof(needle), "\"type\":\"%s\"", type);
    for (size_t i = 0; i < ctx->count; ++i) {
        if (strcmp(ctx->signals[i].target, target) == 0 && contains(ctx->signals[i].message, needle)) return 1;
    }
    return 0;
}

static int gates_online(void *raw, long long client_id, const char *client_name)
{
    (void)raw;
    (void)client_id;
    (void)client_name;
    return 1;
}

/*
 * PeerEgressServiceTests theTenantSwitchGatesEveryPolicy, aConsumerOutsideTheAllowlistDoesNotSeeTheEgress
 * and clientsThatCannotDoEgressAreNeverPushedAPolicy, as the pushes leave the server: the tenant
 * switch is off by default and gates an enabled policy; a consumer missing from the allowlist does
 * not see the egress in its catalogue; a client that announced no egress capability is sent neither
 * an egress-config nor an egress-catalog.
 */
static int test_egress_pushes_are_gated(void)
{
    char path[] = "/tmp/specus_c_peer_egress_gates.XXXXXX";
    int temp_fd = mkstemp(path);
    if (temp_fd < 0) return 1;
    close(temp_fd);
    unlink(path);
    if (st_storage_init(path, 0) != 0) return 1;
    st_storage_client consumer, outsider, egress, legacy;
    st_storage_peer_mesh_device device;
    long long session_id = 0;
    int failed = st_storage_upsert_client(path, 0, "tenant-gates", "gates-consumer", "owner", 1, 60, &consumer) != 0
        || st_storage_upsert_client(path, 0, "tenant-gates", "gates-outsider", "owner", 1, 60, &outsider) != 0
        || st_storage_upsert_client(path, 0, "tenant-gates", "gates-egress", "owner", 1, 60, &egress) != 0
        || st_storage_upsert_client(path, 0, "tenant-gates", "gates-legacy", "owner", 1, 60, &legacy) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &consumer, 1, &device) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &outsider, 1, &device) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &egress, 1, &device) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &legacy, 1, &device) != 0
        || add_egress_policy(path, &egress, consumer.id) != 0
        || add_egress_policy(path, &legacy, consumer.id) != 0
        || open_egress_session_announcing(path, &consumer, 1, 0, &session_id) != 0
        || open_egress_session_announcing(path, &outsider, 1, 0, &session_id) != 0
        || open_egress_session_announcing(path, &egress, 1, 0, &session_id) != 0
        || open_egress_session_announcing(path, &legacy, 0, 0, &session_id) != 0;
    if (failed) {
        fprintf(stderr, "egress gate fixture setup failed\n");
        unlink(path);
        return 1;
    }
    peer_test_context capture;
    memset(&capture, 0, sizeof(capture));
    st_peer_mesh_runtime runtime = {path, capture_signal, gates_online, &capture, 0, 2};
    char allowed[64];
    snprintf(allowed, sizeof(allowed), "\"allowedConsumerClientIds\":[%lld]", consumer.id);

    /* No switch row: off by default, so the enabled policy grants nothing. */
    const char *config = NULL;
    if (st_peer_mesh_refresh_tenant(&runtime, "tenant-gates") != 0
        || (config = last_egress_config(&capture, "gates-egress")) == NULL
        || !contains(config, "\"enabled\":false,\"allowedConsumerClientIds\":[]")) {
        fprintf(stderr, "an unset tenant switch did not gate the policy: %s\n", config == NULL ? "(none)" : config);
        failed = 1;
    }
    st_storage_peer_mesh_egress_switch egress_switch;
    memset(&egress_switch, 0, sizeof(egress_switch));
    snprintf(egress_switch.tenant_id, sizeof(egress_switch.tenant_id), "%s", "tenant-gates");
    egress_switch.enabled = 1;
    snprintf(egress_switch.updated_by, sizeof(egress_switch.updated_by), "%s", "admin");
    capture.count = 0;
    const char *catalog = NULL;
    if (!failed && (st_storage_upsert_peer_mesh_egress_switch(path, &egress_switch) != 0
                    || st_peer_mesh_refresh_tenant(&runtime, "tenant-gates") != 0
                    || (config = last_egress_config(&capture, "gates-egress")) == NULL
                    || !contains(config, "\"enabled\":true") || !contains(config, allowed))) {
        fprintf(stderr, "the tenant switch did not let the policy through: %s\n", config == NULL ? "(none)" : config);
        failed = 1;
    }
    if (!failed && ((catalog = last_egress_catalog(&capture, "gates-consumer")) == NULL
                    || !contains(catalog, "\"clientName\":\"gates-egress\""))) {
        fprintf(stderr, "an allowlisted consumer did not see the egress: %s\n", catalog == NULL ? "(none)" : catalog);
        failed = 1;
    }
    if (!failed && ((catalog = last_egress_catalog(&capture, "gates-outsider")) == NULL
                    || contains(catalog, "gates-egress"))) {
        fprintf(stderr, "a consumer outside the allowlist saw the egress: %s\n", catalog == NULL ? "(none)" : catalog);
        failed = 1;
    }
    if (!failed && (any_signal_of_type(&capture, "gates-legacy", "egress-config")
                    || any_signal_of_type(&capture, "gates-legacy", "egress-catalog"))) {
        fprintf(stderr, "a client without egress capability was pushed egress state\n");
        failed = 1;
    }
    unlink(path);
    return failed;
}

/* The version fixture: every device is connected except the two whose egress has gone away. */
static int version_egress_is_online(void *raw, long long client_id, const char *client_name)
{
    (void)raw;
    (void)client_id;
    return strcmp(client_name, "egress-gone") != 0 && strcmp(client_name, "egress-departing") != 0;
}

/*
 * egressVersion in the egress-catalog is the version each egress announced on its current online
 * session, and 0 for an old client or an egress with no live session. It is always written: a
 * consumer reads 0 as an egress that cannot take a flow, but an absent field as an old server.
 */
static int test_egress_catalog_egress_version(void)
{
    char path[] = "/tmp/specus_c_peer_egress_version_tests.XXXXXX";
    int temp_fd = mkstemp(path);
    if (temp_fd < 0) return 1;
    close(temp_fd);
    unlink(path);
    if (st_storage_init(path, 0) != 0) return 1;

    static const char *const names[] = {
        "egress-current", "egress-old", "egress-gone", "egress-departing", "egress-disabled"
    };
    st_storage_client consumer;
    st_storage_client egresses[5];
    st_storage_peer_mesh_device device;
    long long session_id = 0;
    st_storage_peer_mesh_egress_switch egress_switch;
    memset(&egress_switch, 0, sizeof(egress_switch));
    snprintf(egress_switch.tenant_id, sizeof(egress_switch.tenant_id), "%s", "tenant-egress-version");
    egress_switch.enabled = 1;
    snprintf(egress_switch.updated_by, sizeof(egress_switch.updated_by), "%s", "admin");
    int failed = st_storage_upsert_client(path, 0, "tenant-egress-version", "egress-consumer", "owner", 1, 60,
                                          &consumer) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &consumer, 1, &device) != 0
        || st_storage_upsert_peer_mesh_egress_switch(path, &egress_switch) != 0
        || open_egress_session(path, &consumer, 0, &session_id) != 0;
    for (size_t i = 0; !failed && i < 5U; ++i) {
        failed = st_storage_upsert_client(path, 0, "tenant-egress-version", names[i], "owner", 1, 60,
                                          &egresses[i]) != 0
            || st_storage_update_peer_mesh_device_enabled(path, &egresses[i], 1, &device) != 0
            || add_egress_policy(path, &egresses[i], consumer.id) != 0;
    }
    /*
     * egress-current announced version 1. egress-old is an old client that announced none.
     * egress-gone announced 1 on a session that has since ended. egress-departing still has its
     * session row online, as during the logout push, but its connection is already gone.
     * egress-disabled is online on a session that announced version 1, domain targets and both IPv6
     * declarations, but its device has been switched off.
     */
    char disabled_sql[256];
    failed = failed
        || open_egress_session_announcing(path, &egresses[0], 1, 0, &session_id) != 0
        || open_egress_session_announcing(path, &egresses[1], 0, 0, &session_id) != 0
        || open_egress_session_announcing(path, &egresses[2], 1, 0, &session_id) != 0
        || st_storage_mark_client_session_disconnected(path, session_id, "2026-06-25T00:02:00Z") != 0
        || open_egress_session_announcing(path, &egresses[3], 1, 0, &session_id) != 0
        || open_egress_session_announcing(path, &egresses[4], 1, 1, &session_id) != 0
        || snprintf(disabled_sql, sizeof(disabled_sql), "UPDATE specus_client_session SET "
                    "client_egress_ipv6_targets=1,client_egress_ipv6_packets=1 WHERE id=%lld", session_id) <= 0
        || exec_sql_on(path, disabled_sql) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &egresses[4], 0, &device) != 0;
    if (failed) {
        fprintf(stderr, "egress version fixture setup failed\n");
        unlink(path);
        return 1;
    }

    peer_test_context capture;
    memset(&capture, 0, sizeof(capture));
    st_peer_mesh_runtime runtime = {path, capture_signal, version_egress_is_online, &capture, 0, 2};
    if (st_peer_mesh_refresh_tenant(&runtime, "tenant-egress-version") != 0) {
        fprintf(stderr, "egress version catalog refresh failed\n");
        unlink(path);
        return 1;
    }
    const char *catalog = last_egress_catalog(&capture, "egress-consumer");
    /* -1 would mean the field is missing, so each 0 below also proves it was written. */
    if (catalog_entry_int(catalog, "egress-current", "egressVersion") != 1
        || catalog_entry_int(catalog, "egress-old", "egressVersion") != 0
        || catalog_entry_int(catalog, "egress-gone", "egressVersion") != 0
        || catalog_entry_int(catalog, "egress-departing", "egressVersion") != 0) {
        fprintf(stderr, "egress catalog did not carry each online egress's announced version: %s\n",
                catalog == NULL ? "(none)" : catalog);
        unlink(path);
        return 1;
    }
    /*
     * Java's mocked canPeer lists the disabled device with every capability false and version 0.
     * Its real canPeer, like st_storage_can_peer, needs both devices enabled, so the entry is
     * dropped altogether: none of the four announcements can reach the consumer either way.
     */
    if (contains(catalog, "egress-disabled")
        || catalog_entry_flag(catalog, "egress-disabled", "domainTargetCapable") != -1
        || catalog_entry_flag(catalog, "egress-disabled", "ipv6TargetCapable") != -1
        || catalog_entry_flag(catalog, "egress-disabled", "ipv6PacketCapable") != -1
        || catalog_entry_int(catalog, "egress-disabled", "egressVersion") != -1) {
        fprintf(stderr, "egress catalog offered a disabled device's announcements: %s\n", catalog);
        unlink(path);
        return 1;
    }
    unlink(path);
    return 0;
}

static int always_online(void *raw, long long client_id, const char *client_name)
{
    (void)raw;
    (void)client_id;
    (void)client_name;
    return 1;
}

static int temp_database(char path[64], const char *name)
{
    snprintf(path, 64U, "/tmp/specus_c_%s.XXXXXX", name);
    int temp_fd = mkstemp(path);
    if (temp_fd < 0) return -1;
    close(temp_fd);
    unlink(path);
    return st_storage_init(path, 0);
}

static int exec_sql_on(const char *path, const char *sql)
{
    sqlite3 *db = NULL;
    int rc = sqlite3_open(path, &db) == SQLITE_OK
        && sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
    sqlite3_close(db);
    return rc;
}

static char *read_text_file(const char *path)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        perror(path);
        return NULL;
    }
    char *text = NULL;
    long len = fseek(file, 0, SEEK_END) == 0 ? ftell(file) : -1;
    if (len >= 0 && fseek(file, 0, SEEK_SET) == 0 && (text = (char *)malloc((size_t)len + 1U)) != NULL) {
        if (fread(text, 1, (size_t)len, file) == (size_t)len) text[len] = '\0';
        else {
            free(text);
            text = NULL;
        }
    }
    fclose(file);
    return text;
}

/* ---- egress-report (Java PeerEgressServiceTests, protocol/spec/peer-egress.md) ------------- */

static int egress_activity(const char *path, const st_storage_client *egress,
                           st_storage_peer_mesh_egress_activity *row)
{
    memset(row, 0, sizeof(*row));
    return st_storage_find_peer_mesh_egress_activity(path, egress->tenant_id, egress->id, row);
}

/* The stored report equals the one sent: the counters, and the refusal map code by code. */
static int activity_matches(const st_storage_peer_mesh_egress_activity *row, const char *report,
                            long long session_id, const char *label)
{
    long long revision = 0, active = 0, total = 0, bytes_in = 0, bytes_out = 0;
    char *refused = st_json_get_top_level_raw(report, "rejectedFlows");
    int ok = st_json_get_i64(report, "revision", &revision) == 0
        && st_json_get_i64(report, "activeFlows", &active) == 0
        && st_json_get_i64(report, "totalFlows", &total) == 0
        && st_json_get_i64(report, "bytesIn", &bytes_in) == 0
        && st_json_get_i64(report, "bytesOut", &bytes_out) == 0
        && refused != NULL
        && row->revision == revision && row->active_flows == active && row->total_flows == total
        && row->bytes_in == bytes_in && row->bytes_out == bytes_out && row->session_id == session_id;
    for (size_t i = 0U; ok && i < ST_EGRESS_ALL_CODES_LEN; ++i) {
        long long want = -1, got = -1;
        int sent = st_json_get_i64(refused, ST_EGRESS_ALL_CODES[i], &want) == 0;
        int stored = st_json_get_i64(row->rejected_flows, ST_EGRESS_ALL_CODES[i], &got) == 0;
        ok = sent == stored && want == got;
    }
    if (!ok) {
        fprintf(stderr, "%s: stored revision %lld active %lld total %lld in %lld out %lld refused %s session %lld; "
                "sent %s\n", label, row->revision, row->active_flows, row->total_flows, row->bytes_in,
                row->bytes_out, row->rejected_flows, row->session_id, report);
    }
    free(refused);
    return ok ? 0 : -1;
}

static int egress_report_client(const char *path, const char *name, int egress_version,
                                st_storage_client *client, long long *session_id)
{
    st_storage_peer_mesh_device device;
    return st_storage_upsert_client(path, 0, "tenant-report", name, "owner", 1, 60, client) == 0
        && st_storage_update_peer_mesh_device_enabled(path, client, 1, &device) == 0
        && open_egress_session_announcing(path, client, egress_version, 0, session_id) == 0 ? 0 : -1;
}

/*
 * Replays protocol/test-vectors/peer-egress-report-v1.json through the server side: every report an
 * egress sends there (one control session, revisions strictly increasing across a reconnect) is
 * accepted and replaces the stored one whole; sending the first again afterwards changes nothing.
 */
static int test_egress_report_vector(const char *path)
{
    char *vector = read_text_file(ST_EGRESS_VECTOR_DIR "peer-egress-report-v1.json");
    char **events = NULL;
    size_t event_count = 0U;
    if (vector == NULL || st_json_get_raw_array(vector, "events", &events, &event_count) != 0
        || event_count == 0U) {
        fprintf(stderr, "egress report vector unreadable\n");
        free(vector);
        return 1;
    }
    st_storage_client egress;
    long long session_id = 0;
    peer_test_context capture = {0};
    int failed = egress_report_client(path, "report-vector", 1, &egress, &session_id) != 0;
    st_peer_mesh_runtime runtime = {path, capture_signal, always_online, &capture, session_id, 2};
    char *first = NULL;
    size_t reports = 0U;
    for (size_t i = 0U; !failed && i < event_count; ++i) {
        char *report = st_json_get_top_level_raw(events[i], "report");
        if (report != NULL && strcmp(report, "null") != 0) {
            char label[64];
            snprintf(label, sizeof(label), "egress report vector event %zu", i);
            st_storage_peer_mesh_egress_activity row;
            failed = st_peer_mesh_handle_control(&runtime, egress.client_name, NULL, report) != 0
                || egress_activity(path, &egress, &row) != 0
                || activity_matches(&row, report, session_id, label) != 0;
            if (first == NULL) {
                first = report;
                report = NULL;
            }
            ++reports;
        }
        free(report);
    }
    st_storage_peer_mesh_egress_activity before;
    st_storage_peer_mesh_egress_activity after;
    if (!failed && (reports < 2U
                    || egress_activity(path, &egress, &before) != 0
                    || st_peer_mesh_handle_control(&runtime, egress.client_name, NULL, first) != 0
                    || egress_activity(path, &egress, &after) != 0
                    || after.revision != before.revision || after.active_flows != before.active_flows
                    || strcmp(after.rejected_flows, before.rejected_flows) != 0)) {
        fprintf(stderr, "a replayed older egress report overwrote the newer one\n");
        failed = 1;
    }
    free(first);
    st_json_free_string_array(events, event_count);
    free(vector);
    return failed;
}

static int test_egress_report(void)
{
    char path[64];
    if (temp_database(path, "peer_egress_report") != 0) return 1;
    st_storage_client egress;
    st_storage_client legacy;
    long long session_id = 0;
    long long legacy_session = 0;
    int failed = egress_report_client(path, "report-egress", 1, &egress, &session_id) != 0
        || egress_report_client(path, "report-legacy", 0, &legacy, &legacy_session) != 0;
    if (failed) {
        fprintf(stderr, "egress report fixture setup failed\n");
        unlink(path);
        return 1;
    }
    peer_test_context capture = {0};
    st_peer_mesh_runtime runtime = {path, capture_signal, always_online, &capture, session_id, 2};
    st_storage_peer_mesh_egress_activity row;

    /* The reporter and its session come from the connection; unknown refusal codes are dropped. */
    const char *report =
        "{\"type\":\"egress-report\",\"revision\":12,\"activeFlows\":18,\"totalFlows\":2140,"
        "\"rejectedFlows\":{\"EGRESS_DEST_DENIED\":4,\"EGRESS_MADE_UP\":9,\"EGRESS_PORT_DENIED\":1},"
        "\"bytesIn\":10485760,\"bytesOut\":2097152}";
    if (st_peer_mesh_handle_control(&runtime, egress.client_name, NULL, report) != 0
        || egress_activity(path, &egress, &row) != 0
        || strcmp(row.egress_client_name, "report-egress") != 0
        || strstr(row.rejected_flows, "EGRESS_MADE_UP") != NULL
        || activity_matches(&row, report, session_id, "accepted egress report") != 0) {
        fprintf(stderr, "an identity-free egress report was not stored as sent\n");
        failed = 1;
    }

    /* Routing and identity are server-bound: a report naming any of them is refused, even as null. */
    static const char *const server_bound[] = {
        "sourceClientId", "sourceClientName", "sourceVirtualIp", "sourcePublicKey", "sourceKeyEpoch",
        "targetClientId", "targetClientName", "targetVirtualIp", "targetPublicKey", "sessionId", "token",
    };
    char message[10240];
    for (size_t i = 0U; !failed && i < sizeof(server_bound) / sizeof(server_bound[0]); ++i) {
        snprintf(message, sizeof(message),
                 "{\"type\":\"egress-report\",\"revision\":90,\"activeFlows\":1,\"%s\":null}", server_bound[i]);
        if (st_peer_mesh_handle_control(&runtime, egress.client_name, NULL, message) == 0) {
            fprintf(stderr, "egress-report with %s was accepted\n", server_bound[i]);
            failed = 1;
        }
    }
    /* So is one addressed to a peer, and one over 8 KiB. */
    snprintf(message, sizeof(message), "{\"type\":\"egress-report\",\"revision\":91,\"padding\":\"");
    size_t used = strlen(message);
    memset(message + used, 'x', 9000U);
    snprintf(message + used + 9000U, sizeof(message) - used - 9000U, "\"}");
    if (!failed && (st_peer_mesh_handle_control(&runtime, egress.client_name, "report-legacy",
                                                "{\"type\":\"egress-report\",\"revision\":92}") == 0
                    || st_peer_mesh_handle_control(&runtime, egress.client_name, NULL, message) == 0)) {
        fprintf(stderr, "an addressed or oversized egress-report was accepted\n");
        failed = 1;
    }
    if (!failed && (egress_activity(path, &egress, &row) != 0 || row.revision != 12 || row.active_flows != 18)) {
        fprintf(stderr, "a refused egress-report changed the stored one: revision %lld\n", row.revision);
        failed = 1;
    }

    /* An older snapshot does not roll the counters back; a newer one replaces the stored one whole. */
    const char *fresh =
        "{\"type\":\"egress-report\",\"revision\":13,\"activeFlows\":21,\"totalFlows\":2150,"
        "\"rejectedFlows\":{\"EGRESS_PORT_DENIED\":2},\"bytesIn\":10485761,\"bytesOut\":2097153}";
    if (!failed && (st_peer_mesh_handle_control(&runtime, egress.client_name, NULL,
                        "{\"type\":\"egress-report\",\"revision\":5,\"activeFlows\":1}") != 0
                    || egress_activity(path, &egress, &row) != 0 || row.revision != 12 || row.active_flows != 18
                    || st_peer_mesh_handle_control(&runtime, egress.client_name, NULL, fresh) != 0
                    || egress_activity(path, &egress, &row) != 0
                    || activity_matches(&row, fresh, session_id, "newer egress report") != 0)) {
        fprintf(stderr, "egress-report revision ordering mismatch\n");
        failed = 1;
    }
    /* A negative counter is clamped rather than stored. */
    if (!failed && (st_peer_mesh_handle_control(&runtime, egress.client_name, NULL,
                        "{\"type\":\"egress-report\",\"revision\":14,\"activeFlows\":-3,"
                        "\"rejectedFlows\":{\"EGRESS_PORT_DENIED\":-1}}") != 0
                    || egress_activity(path, &egress, &row) != 0
                    || row.active_flows != 0 || strcmp(row.rejected_flows, "{}") != 0)) {
        fprintf(stderr, "negative egress counters were stored: %lld %s\n", row.active_flows, row.rejected_flows);
        failed = 1;
    }

    /* A client that did not announce egress capability, or a connection without a session, cannot report. */
    st_peer_mesh_runtime legacy_runtime = {path, capture_signal, always_online, &capture, legacy_session, 2};
    st_peer_mesh_runtime sessionless = {path, capture_signal, always_online, &capture, 0, 2};
    if (!failed && (st_peer_mesh_handle_control(&legacy_runtime, legacy.client_name, NULL,
                                                "{\"type\":\"egress-report\",\"revision\":1}") == 0
                    || egress_activity(path, &legacy, &row) != 1
                    || st_peer_mesh_handle_control(&sessionless, egress.client_name, NULL,
                                                   "{\"type\":\"egress-report\",\"revision\":99}") == 0)) {
        fprintf(stderr, "an egress-report without egress capability or session was accepted\n");
        failed = 1;
    }

    if (!failed) failed = test_egress_report_vector(path);

    /* At most 20 reports per control session per minute; another session has its own budget. */
    st_storage_client limited;
    long long limited_session = 0;
    if (!failed && egress_report_client(path, "report-limited", 1, &limited, &limited_session) != 0) failed = 1;
    st_peer_mesh_runtime limited_runtime = {path, capture_signal, always_online, &capture, limited_session, 2};
    for (int revision = 1; !failed && revision <= 20; ++revision) {
        snprintf(message, sizeof(message), "{\"type\":\"egress-report\",\"revision\":%d}", revision);
        if (st_peer_mesh_handle_control(&limited_runtime, limited.client_name, NULL, message) != 0) {
            fprintf(stderr, "egress-report %d within the rate limit was refused\n", revision);
            failed = 1;
        }
    }
    if (!failed && (st_peer_mesh_handle_control(&limited_runtime, limited.client_name, NULL,
                                                "{\"type\":\"egress-report\",\"revision\":21}") == 0
                    || egress_activity(path, &limited, &row) != 0 || row.revision != 20)) {
        fprintf(stderr, "the 21st egress-report within a minute was accepted\n");
        failed = 1;
    }

    /*
     * The rate table is keyed by client-driven session ids, so it is bounded: once it is full a new
     * session's report is refused, while sessions already tracked keep their own budget.
     */
    st_storage_client newcomer;
    long long newcomer_session = 0;
    if (!failed && egress_report_client(path, "report-newcomer", 1, &newcomer, &newcomer_session) != 0) failed = 1;
    st_peer_mesh_runtime newcomer_runtime = {path, capture_signal, always_online, &capture, newcomer_session, 2};
    if (!failed) {
        size_t used_sessions = st_peer_mesh_egress_report_rate_sessions_for_testing();
        failed = used_sessions >= 4096U
            || st_peer_mesh_egress_report_rate_occupy_for_testing(4096U - used_sessions) != 0
            || st_peer_mesh_egress_report_rate_occupy_for_testing(1U) == 0;
        if (failed) fprintf(stderr, "egress report rate table did not stop at 4096 sessions\n");
    }
    if (!failed && (st_peer_mesh_handle_control(&newcomer_runtime, newcomer.client_name, NULL,
                                                "{\"type\":\"egress-report\",\"revision\":1}") == 0
                    || st_peer_mesh_handle_control(&runtime, egress.client_name, NULL,
                                                   "{\"type\":\"egress-report\",\"revision\":15}") != 0)) {
        fprintf(stderr, "a full egress report rate table admitted a new session or refused a tracked one\n");
        failed = 1;
    }
    st_peer_mesh_egress_report_rate_release_for_testing();
    if (!failed && st_peer_mesh_handle_control(&newcomer_runtime, newcomer.client_name, NULL,
                                               "{\"type\":\"egress-report\",\"revision\":1}") != 0) {
        fprintf(stderr, "a new session's egress-report was refused after the rate table drained\n");
        failed = 1;
    }
    unlink(path);
    return failed;
}

/* ---- peer sessions (Java PeerMeshServiceTests) --------------------------------------------- */

/* The sessionId and token of the last session-grant sent to client_name. */
static int last_grant(const peer_test_context *ctx, const char *client_name, long long *session_id, char token[64])
{
    const char *grant = NULL;
    for (size_t i = 0; i < ctx->count; ++i) {
        if (strcmp(ctx->signals[i].target, client_name) == 0
            && contains(ctx->signals[i].message, "\"type\":\"session-grant\"")) grant = ctx->signals[i].message;
    }
    char *value = grant == NULL ? NULL : st_json_get_top_level_string(grant, "token");
    int ok = value != NULL && strlen(value) < 64U && st_json_get_i64(grant, "sessionId", session_id) == 0;
    if (ok) snprintf(token, 64U, "%s", value);
    free(value);
    return ok ? 0 : -1;
}

static int open_offer(const st_peer_mesh_runtime *runtime, peer_test_context *ctx, const char *from,
                      const char *to, long long *session_id, char token[64])
{
    ctx->count = 0;
    return st_peer_mesh_handle_control(runtime, from, to, "{\"type\":\"offer\",\"sdp\":\"x\"}") == 0
        ? last_grant(ctx, from, session_id, token) : -1;
}

static int expire_session(const char *path, long long id)
{
    char sql[160];
    snprintf(sql, sizeof(sql),
             "UPDATE peer_mesh_session SET expires_at=datetime('now','-5 seconds') WHERE id=%lld", id);
    return exec_sql_on(path, sql);
}

static int session_report(const st_peer_mesh_runtime *runtime, const char *client, const char *format, long long id)
{
    char message[256];
    snprintf(message, sizeof(message), format, id);
    return st_peer_mesh_handle_control(runtime, client, NULL, message);
}

/*
 * createSessionReusesCachedOpenSessionForSamePeerPair: a second offer between the same pair, either
 * way round, is granted the open session and its token again; after a close or expiry there is
 * none to reuse and a new one opens (the expired one is closed on the way).
 */
static int test_session_reuse(void)
{
    char path[64];
    if (temp_database(path, "peer_session_reuse") != 0) return 1;
    st_storage_client a, b;
    st_storage_peer_mesh_device device;
    if (st_storage_upsert_client(path, 0, "tenant-reuse", "reuse-a", "owner", 1, 60, &a) != 0
        || st_storage_upsert_client(path, 0, "tenant-reuse", "reuse-b", "owner", 1, 60, &b) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &a, 1, &device) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &b, 1, &device) != 0) {
        fprintf(stderr, "session reuse fixture setup failed\n");
        unlink(path);
        return 1;
    }
    peer_test_context ctx = {0};
    st_peer_mesh_runtime runtime = {path, capture_signal, always_online, &ctx, 0, 2};
    long long first = 0, again = 0, reverse = 0, after_close = 0, after_expiry = 0;
    char first_token[64], again_token[64], reverse_token[64], close_token[64], expiry_token[64];
    int failed = open_offer(&runtime, &ctx, "reuse-a", "reuse-b", &first, first_token) != 0
        || open_offer(&runtime, &ctx, "reuse-a", "reuse-b", &again, again_token) != 0
        || again != first || strcmp(again_token, first_token) != 0;
    if (failed) fprintf(stderr, "a second offer did not reuse the open session\n");
    /* The other side's offer gets the same session and token, and its peer is told that token. */
    if (!failed && (open_offer(&runtime, &ctx, "reuse-b", "reuse-a", &reverse, reverse_token) != 0
                    || reverse != first || strcmp(reverse_token, first_token) != 0
                    || ctx.count != 2 || strcmp(ctx.signals[1].target, "reuse-a") != 0
                    || !contains(ctx.signals[1].message, first_token))) {
        fprintf(stderr, "a reverse offer did not reuse the open session\n");
        failed = 1;
    }
    st_storage_peer_mesh_session sessions[8];
    size_t count = 0U;
    if (!failed && (st_storage_list_peer_mesh_sessions_visible(path, "tenant-reuse", "owner", 1, 1, 8,
                                                               sessions, 8, &count) != 0 || count != 1U)) {
        fprintf(stderr, "reused offers opened %zu sessions\n", count);
        failed = 1;
    }
    if (!failed && (session_report(&runtime, "reuse-a", "{\"type\":\"close\",\"sessionId\":%lld}", first) != 0
                    || open_offer(&runtime, &ctx, "reuse-a", "reuse-b", &after_close, close_token) != 0
                    || after_close == first || strcmp(close_token, first_token) == 0)) {
        fprintf(stderr, "a closed session was granted again\n");
        failed = 1;
    }
    st_storage_peer_mesh_session expired;
    if (!failed && (expire_session(path, after_close) != 0
                    || open_offer(&runtime, &ctx, "reuse-b", "reuse-a", &after_expiry, expiry_token) != 0
                    || after_expiry == after_close
                    || st_storage_get_peer_mesh_session(path, "tenant-reuse", after_close, &expired) != 0
                    || strcmp(expired.status, "CLOSED") != 0 || expired.closed_at[0] == '\0')) {
        fprintf(stderr, "an expired session was granted again or left open\n");
        failed = 1;
    }
    unlink(path);
    return failed;
}

static int session_state_is(const char *path, long long id, const char *status, const char *path_type,
                            long long direct, long long relay, const char *label)
{
    st_storage_peer_mesh_session session;
    if (st_storage_get_peer_mesh_session(path, "tenant-reports", id, &session) == 0
        && strcmp(session.status, status) == 0 && strcmp(session.path_type, path_type) == 0
        && session.direct_bytes == direct && session.relay_bytes == relay) return 0;
    fprintf(stderr, "%s: session is %s/%s %lld/%lld, want %s/%s %lld/%lld\n", label, session.status,
            session.path_type, session.direct_bytes, session.relay_bytes, status, path_type, direct, relay);
    return -1;
}

/*
 * trafficReportAccumulatesDirectAndRelayBytes, expiredTrafficReportClosesSessionWithoutAddingBytes
 * and the path rules of reportPath: counters accumulate and set the effective path; a closed or
 * expired session records nothing more (an expired one is closed), and a path-report cannot
 * reopen a closed session.
 */
static int test_session_reports(void)
{
    char path[64];
    if (temp_database(path, "peer_session_reports") != 0) return 1;
    st_storage_client a, b, other;
    st_storage_peer_mesh_device device;
    if (st_storage_upsert_client(path, 0, "tenant-reports", "reports-a", "owner", 1, 60, &a) != 0
        || st_storage_upsert_client(path, 0, "tenant-reports", "reports-b", "owner", 1, 60, &b) != 0
        || st_storage_upsert_client(path, 0, "tenant-reports", "reports-other", "owner", 1, 60, &other) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &a, 1, &device) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &b, 1, &device) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &other, 1, &device) != 0) {
        fprintf(stderr, "session report fixture setup failed\n");
        unlink(path);
        return 1;
    }
    peer_test_context ctx = {0};
    st_peer_mesh_runtime runtime = {path, capture_signal, always_online, &ctx, 0, 2};
    long long id = 0;
    char token[64];
    int failed = open_offer(&runtime, &ctx, "reports-a", "reports-b", &id, token) != 0
        || session_report(&runtime, "reports-a",
                          "{\"type\":\"path-report\",\"sessionId\":%lld,\"pathType\":\"DIRECT\",\"rttMillis\":9}", id) != 0
        || session_state_is(path, id, "ACTIVE", "DIRECT", 0, 0, "path-report") != 0;
    if (!failed && (session_report(&runtime, "reports-b",
                                   "{\"type\":\"traffic-report\",\"sessionId\":%lld,\"directBytes\":120,"
                                   "\"relayBytes\":30}", id) != 0
                    || session_state_is(path, id, "ACTIVE", "DIRECT", 120, 30, "traffic-report") != 0)) failed = 1;
    st_storage_peer_mesh_session session;
    if (!failed && (st_storage_get_peer_mesh_session(path, "tenant-reports", id, &session) != 0
                    || session.last_traffic_at[0] == '\0')) {
        fprintf(stderr, "a traffic report did not record lastTrafficAt\n");
        failed = 1;
    }
    /*
     * Java applyTraffic returns before it sets updatedAt when neither count is above 0 (negative
     * counts are 0, a missing one too), so such a report leaves updatedAt, and the session's place
     * in the lists ordered by it, as they were; one that counts a byte moves it.
     */
    char marked[64] = "";
    if (!failed) {
        char sql[128];
        snprintf(sql, sizeof(sql), "UPDATE peer_mesh_session SET updated_at='2020-01-01 00:00:00' WHERE id=%lld", id);
        failed = exec_sql_on(path, sql) != 0
            || st_storage_get_peer_mesh_session(path, "tenant-reports", id, &session) != 0;
        snprintf(marked, sizeof(marked), "%s", session.updated_at);
        const char *const empty_reports[] = {
            "{\"type\":\"traffic-report\",\"sessionId\":%lld,\"directBytes\":0,\"relayBytes\":0}",
            "{\"type\":\"traffic-report\",\"sessionId\":%lld,\"directBytes\":-5,\"relayBytes\":-1}",
            "{\"type\":\"traffic-report\",\"sessionId\":%lld}",
        };
        for (size_t i = 0U; !failed && i < sizeof(empty_reports) / sizeof(empty_reports[0]); ++i) {
            failed = session_report(&runtime, i == 1U ? "reports-b" : "reports-a", empty_reports[i], id) != 0
                || st_storage_get_peer_mesh_session(path, "tenant-reports", id, &session) != 0
                || strcmp(session.updated_at, marked) != 0
                || session_state_is(path, id, "ACTIVE", "DIRECT", 120, 30, "traffic report without bytes") != 0;
            if (failed) fprintf(stderr, "traffic report %zu without bytes moved updatedAt: %s, was %s\n", i,
                                session.updated_at, marked);
        }
    }
    /* More relay than direct traffic makes the session a relayed one... */
    if (!failed && (session_report(&runtime, "reports-a",
                                   "{\"type\":\"traffic-report\",\"sessionId\":%lld,\"relayBytes\":200}", id) != 0
                    || session_state_is(path, id, "ACTIVE", "RELAY", 120, 230, "relay traffic") != 0)) failed = 1;
    if (!failed && (st_storage_get_peer_mesh_session(path, "tenant-reports", id, &session) != 0
                    || strcmp(session.updated_at, marked) == 0)) {
        fprintf(stderr, "a traffic report that counts bytes did not move updatedAt from %s\n", marked);
        failed = 1;
    }
    /* ...which a later path-report does not override, and whose bytes it does not add to. */
    if (!failed && (session_report(&runtime, "reports-a",
                                   "{\"type\":\"path-report\",\"sessionId\":%lld,\"pathType\":\"DIRECT\","
                                   "\"directBytes\":999}", id) != 0
                    || session_state_is(path, id, "ACTIVE", "RELAY", 120, 230, "path-report after traffic") != 0)) {
        failed = 1;
    }
    /* A client outside the session cannot report on it. */
    if (!failed && session_report(&runtime, "reports-other",
                                  "{\"type\":\"traffic-report\",\"sessionId\":%lld,\"directBytes\":5}", id) == 0) {
        fprintf(stderr, "a client outside the session reported traffic on it\n");
        failed = 1;
    }
    /* An expired session: the report closes it and adds nothing. */
    if (!failed && (expire_session(path, id) != 0
                    || session_report(&runtime, "reports-b",
                                      "{\"type\":\"traffic-report\",\"sessionId\":%lld,\"directBytes\":120}", id) != 0
                    || session_state_is(path, id, "CLOSED", "RELAY", 120, 230, "expired traffic report") != 0
                    || st_storage_get_peer_mesh_session(path, "tenant-reports", id, &session) != 0
                    || session.closed_at[0] == '\0')) {
        fprintf(stderr, "an expired traffic report did not close the session without counting\n");
        failed = 1;
    }
    /* A closed session stays closed whatever is reported on it. */
    long long closed = 0;
    if (!failed && (open_offer(&runtime, &ctx, "reports-a", "reports-b", &closed, token) != 0
                    || closed == id
                    || session_report(&runtime, "reports-a",
                                      "{\"type\":\"close\",\"sessionId\":%lld,\"directBytes\":50}", closed) != 0
                    || session_state_is(path, closed, "CLOSED", "DIRECT", 0, 0, "close with bytes") != 0
                    || session_report(&runtime, "reports-a",
                                      "{\"type\":\"path-report\",\"sessionId\":%lld,\"pathType\":\"RELAY\","
                                      "\"status\":\"ACTIVE\"}", closed) != 0
                    || session_report(&runtime, "reports-b",
                                      "{\"type\":\"traffic-report\",\"sessionId\":%lld,\"relayBytes\":7}", closed) != 0
                    || session_state_is(path, closed, "CLOSED", "DIRECT", 0, 0, "reports on a closed session") != 0)) {
        fprintf(stderr, "a closed session was reopened or counted\n");
        failed = 1;
    }
    unlink(path);
    return failed;
}

/* ---- login configuration (Java loginConfig* tests) ----------------------------------------- */

static void clear_stun_settings(void)
{
    static const char *const names[] = {
        "SPECUS_PEER_MESH_PUBLIC_ADDRESS", "SPECUS_PEER_MESH_STUN_TURN_PORT",
        "SPECUS_PEER_MESH_STANDALONE_STUN_ADDRESS", "SPECUS_PEER_MESH_STANDALONE_STUN_PORT",
        "SPECUS_PEER_MESH_STANDALONE_STUN_ALTERNATE_ADDRESS", "SPECUS_PEER_MESH_PUBLIC_STUN_SERVERS",
    };
    for (size_t i = 0U; i < sizeof(names) / sizeof(names[0]); ++i) unsetenv(names[i]);
}

static int login_config_has(const char *path, const char *client, const char *needle, const char *label)
{
    char *config = st_peer_mesh_build_login_config(path, client, 2);
    int ok = contains(config, needle);
    if (!ok) fprintf(stderr, "%s: %s lacks %s\n", label, config == NULL ? "(none)" : config, needle);
    free(config);
    return ok ? 0 : -1;
}

/*
 * loginConfigAllocatesVirtualIpButLeavesDeviceDisabledByDefault,
 * loginConfigCanAdvertiseStandaloneStunSeparatelyFromTurn and
 * incompleteStandaloneStunFallsBackToEmbeddedEndpoint.
 */
static int test_login_config_stun(void)
{
    char path[64];
    if (temp_database(path, "peer_login_config") != 0) return 1;
    st_storage_client client;
    if (st_storage_upsert_client(path, 0, "tenant-config", "config-device", "owner", 1, 60, &client) != 0) {
        unlink(path);
        return 1;
    }
    char ice_subject[64];
    snprintf(ice_subject, sizeof(ice_subject), ":pm-%lld:", client.id);
    clear_stun_settings();
    /* A new device gets a virtual IP but stays off; it is still told the endpoints and a TURN credential. */
    int failed = login_config_has(path, "config-device", "{\"enabled\":false,", "new device") != 0
        || login_config_has(path, "config-device", "\"virtualIp\":\"100.", "new device") != 0
        || login_config_has(path, "config-device", "\"cidr\":\"100.96.0.0/11\"", "new device") != 0
        || login_config_has(path, "config-device", "\"stunPort\":3478", "new device") != 0
        || login_config_has(path, "config-device", ice_subject, "new device") != 0
        || login_config_has(path, "config-device", "\"peerServiceDiscoveryVersion\":2", "new device") != 0
        || login_config_has(path, "config-device",
                            "\"serviceSharing\":{\"deploymentEnabled\":true,\"configuredEnabled\":false,"
                            "\"effectiveEnabled\":false", "new device") != 0;

    setenv("SPECUS_PEER_MESH_PUBLIC_ADDRESS", "turn.example.com", 1);
    setenv("SPECUS_PEER_MESH_STANDALONE_STUN_ADDRESS", "stun.example.com", 1);
    setenv("SPECUS_PEER_MESH_STANDALONE_STUN_PORT", "5349", 1);
    setenv("SPECUS_PEER_MESH_STANDALONE_STUN_ALTERNATE_ADDRESS", "stun-backup.example.com", 1);
    failed = failed || login_config_has(path, "config-device",
        "\"stunHost\":\"stun.example.com\",\"stunPort\":5349,\"turnHost\":\"turn.example.com\",\"turnPort\":3478,"
        "\"publicStunServers\":[\"stun:stun-backup.example.com:5349\"]", "standalone STUN") != 0;
    /* Configured public servers follow, trimmed and without repeats. */
    setenv("SPECUS_PEER_MESH_PUBLIC_STUN_SERVERS",
           " stun:extra.example.com:3478 ,stun:stun-backup.example.com:5349, stun:extra.example.com:3478", 1);
    failed = failed || login_config_has(path, "config-device",
        "\"publicStunServers\":[\"stun:stun-backup.example.com:5349\",\"stun:extra.example.com:3478\"]",
        "standalone STUN with public servers") != 0;

    clear_stun_settings();
    setenv("SPECUS_PEER_MESH_PUBLIC_ADDRESS", "relay.example.com", 1);
    setenv("SPECUS_PEER_MESH_STUN_TURN_PORT", "4444", 1);
    setenv("SPECUS_PEER_MESH_STANDALONE_STUN_ADDRESS", "stun.example.com", 1);
    setenv("SPECUS_PEER_MESH_STANDALONE_STUN_PORT", "0", 1);
    failed = failed || login_config_has(path, "config-device",
        "\"stunHost\":\"relay.example.com\",\"stunPort\":4444,\"turnHost\":\"relay.example.com\",\"turnPort\":4444",
        "incomplete standalone STUN") != 0;
    clear_stun_settings();
    unlink(path);
    return failed;
}

/*
 * aclVisibilityHidesServiceFromClientsNotOnAllowList: an ACL-visible service reaches only the
 * clients on its allowlist, here as the peers the publisher's data plane lets in.
 */
static int test_acl_visibility(void)
{
    char path[64];
    if (temp_database(path, "peer_acl_visibility") != 0) return 1;
    st_storage_client publisher, allowed, other;
    st_storage_peer_mesh_device publisher_device, allowed_device, other_device;
    st_storage_peer_mesh_service service;
    memset(&service, 0, sizeof(service));
    int failed = st_storage_upsert_client(path, 0, "tenant-acl", "acl-publisher", "owner", 1, 60, &publisher) != 0
        || st_storage_upsert_client(path, 0, "tenant-acl", "acl-allowed", "owner", 1, 60, &allowed) != 0
        || st_storage_upsert_client(path, 0, "tenant-acl", "acl-other", "owner", 1, 60, &other) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &publisher, 1, &publisher_device) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &allowed, 1, &allowed_device) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &other, 1, &other_device) != 0;
    snprintf(service.tenant_id, sizeof(service.tenant_id), "%s", publisher.tenant_id);
    service.client_id = publisher.id;
    snprintf(service.client_name, sizeof(service.client_name), "%s", publisher.client_name);
    snprintf(service.service_id, sizeof(service.service_id), "svc-acl0001");
    snprintf(service.name, sizeof(service.name), "acl ssh");
    snprintf(service.transport, sizeof(service.transport), "tcp");
    snprintf(service.application, sizeof(service.application), "ssh");
    snprintf(service.target_host, sizeof(service.target_host), "127.0.0.1");
    service.target_port = 22;
    service.published_port = 2222;
    service.enabled = 1;
    snprintf(service.visibility, sizeof(service.visibility), "ACL");
    snprintf(service.allowed_client_ids, sizeof(service.allowed_client_ids), "%lld", allowed.id);
    failed = failed
        || st_storage_upsert_peer_mesh_service_sharing(path, publisher.tenant_id, 1, 0, "admin", NULL) != 0
        || st_storage_upsert_peer_mesh_service(path, &service, NULL) != 0;
    char *config = failed ? NULL : st_peer_mesh_build_login_config(path, publisher.client_name, 2);
    char expected[128];
    snprintf(expected, sizeof(expected), "\"allowedPeerVirtualIps\":[\"%s\"]", allowed_device.virtual_ip);
    if (failed || !contains(config, "\"serviceId\":\"svc-acl0001\"") || !contains(config, expected)
        || contains(config, other_device.virtual_ip)) {
        fprintf(stderr, "an ACL service reached clients off its allowlist: %s\n", config == NULL ? "(none)" : config);
        failed = 1;
    }
    free(config);
    unlink(path);
    return failed;
}

/* The service-catalog the peer was sent by the last call, or NULL. */
static const char *catalog_for(const peer_test_context *ctx, const char *recipient)
{
    for (size_t i = 0; i < ctx->count; ++i) {
        if (strcmp(ctx->signals[i].target, recipient) == 0
            && contains(ctx->signals[i].message, "\"type\":\"service-catalog\"")) return ctx->signals[i].message;
    }
    return NULL;
}

/*
 * PeerServiceDiscoveryServiceTests reportIsIgnoredWhenSharingOffAndDoesNotAdvertiseTargetHost and
 * withdrawalKeepsRevisionTombstoneAndServerBoundsClientTtl: with sharing off a report advertises
 * nothing; the catalogue's expiry is the server's, whatever the client claims; a withdrawal keeps
 * the revision, so the earlier report replayed is ignored; a disconnect withdraws the catalogue and
 * forgets the session's revisions.
 */
static int test_service_report_lifecycle(void)
{
    char path[64];
    if (temp_database(path, "peer_service_lifecycle") != 0) return 1;
    st_storage_client publisher, peer;
    st_storage_peer_mesh_device device;
    st_storage_peer_mesh_service service;
    memset(&service, 0, sizeof(service));
    int failed = st_storage_upsert_client(path, 0, "tenant-lifecycle", "life-publisher", "owner", 1, 60,
                                          &publisher) != 0
        || st_storage_upsert_client(path, 0, "tenant-lifecycle", "life-peer", "owner", 1, 60, &peer) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &publisher, 1, &device) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &peer, 1, &device) != 0;
    snprintf(service.tenant_id, sizeof(service.tenant_id), "%s", publisher.tenant_id);
    service.client_id = publisher.id;
    snprintf(service.client_name, sizeof(service.client_name), "%s", publisher.client_name);
    snprintf(service.service_id, sizeof(service.service_id), "svc-life0001");
    snprintf(service.name, sizeof(service.name), "local-ssh");
    snprintf(service.transport, sizeof(service.transport), "tcp");
    snprintf(service.application, sizeof(service.application), "ssh");
    snprintf(service.target_host, sizeof(service.target_host), "127.0.0.1");
    service.target_port = 22;
    service.published_port = 2222;
    service.enabled = 1;
    snprintf(service.visibility, sizeof(service.visibility), "OWNER");
    failed = failed || st_storage_upsert_peer_mesh_service(path, &service, NULL) != 0;
    if (failed) {
        fprintf(stderr, "service report lifecycle fixture setup failed\n");
        unlink(path);
        return 1;
    }
    peer_test_context ctx = {0};
    st_peer_mesh_runtime runtime = {path, capture_signal, always_online, &ctx, 8201, 2};
    static const char *const report_format =
        "{\"type\":\"service-report\",\"enabled\":%s,\"revision\":%d,"
        "\"generatedAt\":\"2099-01-01T00:00:00Z\",\"expiresAt\":\"2099-01-01T01:00:00Z\","
        "\"services\":[{\"serviceId\":\"svc-life0001\",\"name\":\"client-supplied-name\","
        "\"transport\":\"tcp\",\"application\":\"ssh\",\"publishedPort\":2222}]}";
    char report[1024];
    const char *catalog = NULL;

    /* Sharing has never been switched on: the peer is told of no service. */
    snprintf(report, sizeof(report), report_format, "true", 1);
    ctx.count = 0;
    if (st_peer_mesh_handle_control(&runtime, publisher.client_name, NULL, report) != 0
        || ((catalog = catalog_for(&ctx, "life-peer")) != NULL
            && (!contains(catalog, "\"services\":[]") || contains(catalog, "svc-life0001")))) {
        fprintf(stderr, "a report advertised services with sharing off: %s\n", catalog == NULL ? "(none)" : catalog);
        failed = 1;
    }
    /* Sharing on: published from the stored definition, on the server's expiry. */
    snprintf(report, sizeof(report), report_format, "true", 2);
    ctx.count = 0;
    if (!failed && (st_storage_upsert_peer_mesh_service_sharing(path, publisher.tenant_id, 1, 0, "admin", NULL) != 0
                    || st_peer_mesh_handle_control(&runtime, publisher.client_name, NULL, report) != 0
                    || (catalog = catalog_for(&ctx, "life-peer")) == NULL
                    || !contains(catalog, "\"serviceId\":\"svc-life0001\"") || !contains(catalog, "\"revision\":2")
                    || !contains(catalog, "\"name\":\"local-ssh\"") || contains(catalog, "client-supplied-name")
                    || contains(catalog, "targetHost") || contains(catalog, "2099-"))) {
        fprintf(stderr, "a published catalogue did not follow the definition and the server's expiry: %s\n",
                catalog == NULL ? "(none)" : catalog);
        failed = 1;
    }
    /* A withdrawal goes out with its own revision; replaying the earlier report changes nothing. */
    snprintf(report, sizeof(report), report_format, "false", 3);
    ctx.count = 0;
    if (!failed && (st_peer_mesh_handle_control(&runtime, publisher.client_name, NULL, report) != 0
                    || (catalog = catalog_for(&ctx, "life-peer")) == NULL
                    || !contains(catalog, "\"revision\":3") || !contains(catalog, "\"services\":[]"))) {
        fprintf(stderr, "a withdrawal did not reach the peer: %s\n", catalog == NULL ? "(none)" : catalog);
        failed = 1;
    }
    snprintf(report, sizeof(report), report_format, "true", 2);
    ctx.count = 0;
    if (!failed && (st_peer_mesh_handle_control(&runtime, publisher.client_name, NULL, report) != 0
                    || ctx.count != 0)) {
        fprintf(stderr, "the report before a withdrawal was published again\n");
        failed = 1;
    }
    /* The disconnect withdraws the catalogue and forgets the session's revisions. */
    ctx.count = 0;
    if (!failed && (st_peer_mesh_handle_disconnect(&runtime, publisher.client_name) != 0
                    || (catalog = catalog_for(&ctx, "life-peer")) == NULL
                    || !contains(catalog, "\"publisherSessionId\":8201") || !contains(catalog, "\"services\":[]"))) {
        fprintf(stderr, "a disconnect did not withdraw the catalogue: %s\n", catalog == NULL ? "(none)" : catalog);
        failed = 1;
    }
    snprintf(report, sizeof(report), report_format, "true", 1);
    ctx.count = 0;
    if (!failed && (st_peer_mesh_handle_control(&runtime, publisher.client_name, NULL, report) != 0
                    || (catalog = catalog_for(&ctx, "life-peer")) == NULL
                    || !contains(catalog, "\"serviceId\":\"svc-life0001\""))) {
        fprintf(stderr, "a disconnected session's revisions were still tracked: %s\n",
                catalog == NULL ? "(none)" : catalog);
        failed = 1;
    }
    (void)st_peer_mesh_handle_disconnect(&runtime, publisher.client_name);
    unlink(path);
    return failed;
}

/* ---- service-report bounds (PeerServiceDiscoveryServiceTests, PeerSignalServiceEnvelopeTests) -- */

static int service_report(const char *path, peer_test_context *ctx, long long session_id, const char *client,
                          const char *message)
{
    st_peer_mesh_runtime runtime = {path, capture_signal, always_online, ctx, session_id, 2};
    ctx->count = 0;
    return st_peer_mesh_handle_control(&runtime, client, NULL, message);
}

static int test_service_report_bounds(void)
{
    char path[64];
    if (temp_database(path, "peer_service_bounds") != 0) return 1;
    st_storage_client publisher;
    st_storage_peer_mesh_device device;
    if (st_storage_upsert_client(path, 0, "tenant-bounds", "bounds-publisher", "owner", 1, 60, &publisher) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &publisher, 1, &device) != 0) {
        unlink(path);
        return 1;
    }
    peer_test_context ctx = {0};
    char message[20480];
    int failed = 0;
    /* 20 reports per control session per minute; the 21st is refused and audited. */
    for (int revision = 1; !failed && revision <= 20; ++revision) {
        snprintf(message, sizeof(message),
                 "{\"type\":\"service-report\",\"enabled\":false,\"revision\":%d,\"services\":[]}", revision);
        if (service_report(path, &ctx, 8101, "bounds-publisher", message) != 0) {
            fprintf(stderr, "service-report %d within the rate limit was refused\n", revision);
            failed = 1;
        }
    }
    for (int attempt = 0; !failed && attempt < 5; ++attempt) {
        if (service_report(path, &ctx, 8101, "bounds-publisher",
                           "{\"type\":\"service-report\",\"enabled\":false,\"revision\":99,\"services\":[]}") == 0) {
            fprintf(stderr, "a service-report over the rate limit was accepted\n");
            failed = 1;
        }
    }
    st_storage_peer_mesh_service_audit audits[100];
    size_t audit_count = 0U;
    int rate_audited = 0;
    if (!failed && st_storage_list_peer_mesh_service_audits(path, "tenant-bounds", audits, 100U, &audit_count) == 0) {
        for (size_t i = 0U; i < audit_count; ++i) {
            if (strcmp(audits[i].reason, "rate-limited") == 0 && audits[i].session_id == 8101) rate_audited = 1;
        }
    }
    if (!failed && !rate_audited) {
        fprintf(stderr, "a rate-limited service-report was not audited\n");
        failed = 1;
    }
    /* Another session has its own budget. */
    if (!failed && service_report(path, &ctx, 8102, "bounds-publisher",
                                  "{\"type\":\"service-report\",\"enabled\":false,\"revision\":1,\"services\":[]}") != 0) {
        fprintf(stderr, "another session's service-report was refused\n");
        failed = 1;
    }

    /*
     * PeerSignalServiceEnvelopeTests: the server binds the publisher, so a report addressed to a
     * peer, or naming any identity or routing field even as null, is refused.
     */
    static const char *const server_bound[] = {
        "sourceClientId", "sourceClientName", "sourceVirtualIp", "sourcePublicKey", "sourceKeyEpoch",
        "targetClientId", "targetClientName", "targetVirtualIp", "targetPublicKey", "sessionId", "token",
        "publisherClientId", "publisherClientName", "publisherSessionId",
    };
    st_peer_mesh_runtime envelope_runtime = {path, capture_signal, always_online, &ctx, 8105, 2};
    if (!failed && st_peer_mesh_handle_control(&envelope_runtime, "bounds-publisher", "peer-b",
            "{\"type\":\"service-report\",\"enabled\":true,\"revision\":1,\"services\":[]}") == 0) {
        fprintf(stderr, "a service-report addressed to a peer was accepted\n");
        failed = 1;
    }
    for (size_t i = 0U; !failed && i < sizeof(server_bound) / sizeof(server_bound[0]); ++i) {
        snprintf(message, sizeof(message),
                 "{\"type\":\"service-report\",\"enabled\":true,\"revision\":1,\"services\":[],\"%s\":null}",
                 server_bound[i]);
        if (st_peer_mesh_handle_control(&envelope_runtime, "bounds-publisher", NULL, message) == 0) {
            fprintf(stderr, "a service-report naming %s was accepted\n", server_bound[i]);
            failed = 1;
        }
    }
    /* With none of them it is accepted. */
    if (!failed && st_peer_mesh_handle_control(&envelope_runtime, "bounds-publisher", NULL,
            "{\"type\":\"service-report\",\"enabled\":true,\"revision\":1,\"services\":[]}") != 0) {
        fprintf(stderr, "an identity-free service-report was refused\n");
        failed = 1;
    }

    /* The raw message is bounded before it is read, and so is every collection after. */
    snprintf(message, sizeof(message), "{\"type\":\"service-report\",\"revision\":2,\"padding\":\"");
    size_t used = strlen(message);
    memset(message + used, 'x', 16U * 1024U);
    snprintf(message + used + 16U * 1024U, sizeof(message) - used - 16U * 1024U, "\"}");
    if (!failed && service_report(path, &ctx, 8103, "bounds-publisher", message) == 0) {
        fprintf(stderr, "an oversized service-report was accepted\n");
        failed = 1;
    }
    for (int stats = 32; !failed && stats <= 33; ++stats) {
        snprintf(message, sizeof(message), "{\"type\":\"service-report\",\"enabled\":false,\"revision\":%d,"
                 "\"services\":[],\"stats\":[", stats);
        for (int i = 0; i < stats; ++i) {
            used = strlen(message);
            snprintf(message + used, sizeof(message) - used, "%s{\"serviceId\":\"svc-stat%02d\"}", i == 0 ? "" : ",", i);
        }
        used = strlen(message);
        snprintf(message + used, sizeof(message) - used, "]}");
        int rc = service_report(path, &ctx, 8103, "bounds-publisher", message);
        if ((stats == 32) != (rc == 0)) {
            fprintf(stderr, "a service-report with %d stats was %s\n", stats, rc == 0 ? "accepted" : "refused");
            failed = 1;
        }
    }
    static const char *const bad_instances[] = {
        "{\"type\":\"service-report\",\"revision\":40,\"services\":[],\"instanceId\":\"bad/instance\"}",
        "{\"type\":\"service-report\",\"revision\":41,\"services\":[],"
        "\"instanceId\":\"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"}",
    };
    for (size_t i = 0U; !failed && i < sizeof(bad_instances) / sizeof(bad_instances[0]); ++i) {
        if (service_report(path, &ctx, 8103, "bounds-publisher", bad_instances[i]) == 0) {
            fprintf(stderr, "a service-report with an invalid instanceId was accepted: %s\n", bad_instances[i]);
            failed = 1;
        }
    }

    /*
     * The catalogue table is keyed by client-driven session ids and has a fixed size: when every
     * slot holds a live catalogue a new session's report is refused, while a session that already
     * has one keeps reporting.
     */
    (void)st_peer_mesh_catalogs_occupy_for_testing(4096U);
    if (!failed && (service_report(path, &ctx, 8104, "bounds-publisher",
                                   "{\"type\":\"service-report\",\"enabled\":false,\"revision\":1,\"services\":[]}") == 0
                    || service_report(path, &ctx, 8102, "bounds-publisher",
                                      "{\"type\":\"service-report\",\"enabled\":false,\"revision\":2,\"services\":[]}") != 0)) {
        fprintf(stderr, "a full catalogue table admitted a new session or refused a tracked one\n");
        failed = 1;
    }
    st_peer_mesh_catalogs_release_for_testing();
    if (!failed && service_report(path, &ctx, 8104, "bounds-publisher",
                                  "{\"type\":\"service-report\",\"enabled\":false,\"revision\":1,\"services\":[]}") != 0) {
        fprintf(stderr, "a new session's service-report was refused after the catalogue table drained\n");
        failed = 1;
    }
    unlink(path);
    return failed;
}

/* ---- egress policy and catalogue (Java PeerEgressServiceTests) ----------------------------- */

static int egress_switch_on(const char *path, const char *tenant_id)
{
    st_storage_peer_mesh_egress_switch egress_switch;
    memset(&egress_switch, 0, sizeof(egress_switch));
    snprintf(egress_switch.tenant_id, sizeof(egress_switch.tenant_id), "%s", tenant_id);
    egress_switch.enabled = 1;
    snprintf(egress_switch.updated_by, sizeof(egress_switch.updated_by), "%s", "admin");
    return st_storage_upsert_peer_mesh_egress_switch(path, &egress_switch);
}

/* Refreshes the tenant; the egress-config the egress and the egress-catalog the consumer got. */
static int egress_refresh(const st_peer_mesh_runtime *runtime, peer_test_context *capture, const char *tenant_id,
                          const char *egress, const char *consumer, const char **config, const char **catalog)
{
    capture->count = 0;
    if (st_peer_mesh_refresh_tenant(runtime, tenant_id) != 0) return -1;
    *config = last_egress_config(capture, egress);
    *catalog = last_egress_catalog(capture, consumer);
    return *config != NULL && *catalog != NULL ? 0 : -1;
}

/*
 * PeerEgressServiceTests baseMeshAccessIsRequiredOnTopOfTheEgressAllowlist and
 * anEmptyConsumerAllowlistGrantsNothing, as the pushes leave the server. The consumer is on the
 * egress allowlist but has another owner, so the base mesh ACL decides: with no ACL row, or one
 * with allowed=0, the enabled config lists no consumer and the consumer's catalogue has no egress;
 * an allowed ACL lets it in. An empty allowlist then grants nothing although the ACL allows the pair.
 */
static int test_egress_allowlist_needs_base_access(void)
{
    char path[64];
    if (temp_database(path, "peer_egress_base_access") != 0) return 1;
    st_storage_client consumer, egress;
    st_storage_peer_mesh_device device;
    long long session_id = 0;
    int failed = st_storage_upsert_client(path, 0, "tenant-base", "base-consumer", "bob", 1, 60, &consumer) != 0
        || st_storage_upsert_client(path, 0, "tenant-base", "base-egress", "alice", 1, 60, &egress) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &consumer, 1, &device) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &egress, 1, &device) != 0
        || egress_switch_on(path, "tenant-base") != 0
        || add_egress_policy(path, &egress, consumer.id) != 0
        || open_egress_session(path, &consumer, 0, &session_id) != 0
        || open_egress_session(path, &egress, 0, &session_id) != 0;
    if (failed) {
        fprintf(stderr, "egress base access fixture setup failed\n");
        unlink(path);
        return 1;
    }
    peer_test_context capture;
    memset(&capture, 0, sizeof(capture));
    st_peer_mesh_runtime runtime = {path, capture_signal, gates_online, &capture, 0, 2};
    char granted[64];
    snprintf(granted, sizeof(granted), "\"allowedConsumerClientIds\":[%lld]", consumer.id);
    static const char *const steps[] = {
        "no ACL row", "an ACL with allowed=0", "an allowed ACL", "an empty allowlist under an allowed ACL"
    };
    st_storage_peer_mesh_acl acl;
    for (int step = 0; !failed && step < 4; ++step) {
        if ((step == 1 || step == 2)
            && st_storage_upsert_peer_mesh_acl(path, "tenant-base", "admin", &consumer, &egress, step == 2,
                                               "BOTH", &acl) != 0) failed = 1;
        if (step == 3 && exec_sql_on(path, "UPDATE peer_mesh_egress_policy SET allowed_consumer_client_ids=''") != 0) {
            failed = 1;
        }
        int granted_expected = step == 2;
        const char *config = NULL;
        const char *catalog = NULL;
        if (failed
            || egress_refresh(&runtime, &capture, "tenant-base", "base-egress", "base-consumer", &config, &catalog) != 0
            || !contains(config, "\"enabled\":true,")
            || contains(config, granted) != granted_expected
            || (!granted_expected && !contains(config, "\"allowedConsumerClientIds\":[]"))
            || contains(catalog, "\"clientName\":\"base-egress\"") != granted_expected) {
            fprintf(stderr, "egress allowlist with %s: config %s | catalog %s\n", steps[step],
                    config == NULL ? "(none)" : config, catalog == NULL ? "(none)" : catalog);
            failed = 1;
        }
    }
    unlink(path);
    return failed;
}

/*
 * PeerEgressServiceTests anEnabledPolicyPushesRulesAndLimits and theCatalogueCarriesNoDestinationAllowlist.
 * The policy row is written with the columns Java's fixture sets, so the limits are the defaults
 * Java's entity carries (256, 64, 60). The config names the scope, the allowlisted consumer, the one
 * rule and the limits under a positive revision; the consumer's catalogue lists the egress by id with
 * the protocols of its rules and no rule, CIDR or port at all.
 */
static int test_egress_policy_defaults_and_catalog_shape(void)
{
    char path[64];
    if (temp_database(path, "peer_egress_limits") != 0) return 1;
    st_storage_client consumer, egress;
    st_storage_peer_mesh_device device;
    long long session_id = 0;
    char sql[640];
    int failed = st_storage_upsert_client(path, 0, "tenant-limits", "limits-consumer", "owner", 1, 60, &consumer) != 0
        || st_storage_upsert_client(path, 0, "tenant-limits", "limits-egress", "owner", 1, 60, &egress) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &consumer, 1, &device) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &egress, 1, &device) != 0
        || egress_switch_on(path, "tenant-limits") != 0
        || open_egress_session(path, &consumer, 0, &session_id) != 0
        || open_egress_session(path, &egress, 0, &session_id) != 0
        || snprintf(sql, sizeof(sql),
                    "INSERT INTO peer_mesh_egress_policy(tenant_id,owner_username,egress_client_id,egress_client_name,"
                    "enabled,scope,allowed_consumer_client_ids,destination_rules) VALUES('tenant-limits','admin',%lld,"
                    "'limits-egress',1,'%s','%lld','[{\"cidr\":\"203.0.113.0/24\",\"protocols\":[\"tcp\"],"
                    "\"portRanges\":[[443,443]]}]')", egress.id, ST_EGRESS_SCOPE_PUBLIC, consumer.id) <= 0
        || exec_sql_on(path, sql) != 0;
    if (failed) {
        fprintf(stderr, "egress limits fixture setup failed\n");
        unlink(path);
        return 1;
    }
    peer_test_context capture;
    memset(&capture, 0, sizeof(capture));
    st_peer_mesh_runtime runtime = {path, capture_signal, gates_online, &capture, 0, 2};
    const char *config = NULL;
    const char *catalog = NULL;
    char enabled[128];
    snprintf(enabled, sizeof(enabled), "\"enabled\":true,\"scope\":\"%s\",\"allowedConsumerClientIds\":[%lld],",
             ST_EGRESS_SCOPE_PUBLIC, consumer.id);
    long long revision = 0;
    if (egress_refresh(&runtime, &capture, "tenant-limits", "limits-egress", "limits-consumer", &config, &catalog) != 0
        || st_json_get_i64(config, "revision", &revision) != 0 || revision <= 0
        || !contains(config, enabled)
        || !contains(config, "\"destinationRules\":[{\"cidr\":\"203.0.113.0/24\",\"protocols\":[\"tcp\"],"
                             "\"portRanges\":[[443,443]]}],")
        || !contains(config, "\"limits\":{\"maxConcurrentFlows\":256,\"maxFlowsPerConsumer\":64,"
                             "\"idleTimeoutSeconds\":60}")) {
        fprintf(stderr, "an enabled policy did not push its scope, rule and limits: %s\n",
                config == NULL ? "(none)" : config);
        unlink(path);
        return 1;
    }
    char entry[128];
    snprintf(entry, sizeof(entry), "\"egresses\":[{\"clientId\":%lld,\"clientName\":\"limits-egress\",", egress.id);
    const char *second = catalog == NULL ? NULL : strstr(catalog, "\"clientId\":");
    if (second != NULL) second = strstr(second + 1, "\"clientId\":");
    if (!contains(catalog, entry) || second != NULL
        || !contains(catalog, "\"protocols\":[\"tcp\"],")
        || catalog_entry_flag(catalog, "limits-egress", "domainTargetCapable") != 0
        || contains(catalog, "destinationRules") || contains(catalog, "domainRules") || contains(catalog, "cidr")
        || contains(catalog, "203.0.113") || contains(catalog, "portRanges")) {
        fprintf(stderr, "the egress catalogue entry was not the egress alone without its allowlist: %s\n",
                catalog == NULL ? "(none)" : catalog);
        unlink(path);
        return 1;
    }
    unlink(path);
    return 0;
}

/* One vector session row of the egress, as the login and the control connection would leave it. */
static int insert_vector_session(const char *path, const char *row, const char *tenant_id, long long client_id)
{
    long long id = 0;
    int version = 0;
    int value = 0;
    int targets = 0;
    int packets = 0;
    char *row_tenant = st_json_get_top_level_string(row, "tenantId");
    char *status = st_json_get_top_level_string(row, "status");
    char *connected = st_json_get_top_level_string(row, "connectedAt");
    if (st_json_get_bool(row, "ipv6TargetCapable", &value) == 0) targets = value;
    if (st_json_get_bool(row, "ipv6PacketCapable", &value) == 0) packets = value;
    int rc = row_tenant != NULL && status != NULL && connected != NULL
        && st_json_get_i64(row, "id", &id) == 0 && st_json_get_int(row, "version", &version) == 0 ? 0 : -1;
    sqlite3 *db = NULL;
    sqlite3_stmt *statement = NULL;
    if (rc == 0 && (sqlite3_open(path, &db) != SQLITE_OK || sqlite3_prepare_v2(db,
        "INSERT INTO specus_client_session (id,tenant_id,credential_id,identity_id,client_id,client_name,token_hash,"
        "status,machine_fingerprint,os_user,http_login_at,netty_connected_at,expires_at,client_egress_version,"
        "client_egress_ipv6_targets,client_egress_ipv6_packets) VALUES(?1,?2,1,?3,?3,'vector-egress',?4,?5,"
        "'vector-machine','tester',?6,?6,'2099-06-25T08:00:00Z',?7,?8,?9)", -1, &statement, NULL) != SQLITE_OK)) {
        rc = -1;
    }
    if (rc == 0) {
        char token[64];
        snprintf(token, sizeof(token), "vector-session-%lld", id);
        /* The vector's tenant-a is the egress's own tenant; any other tenant is kept as written. */
        sqlite3_bind_int64(statement, 1, id);
        sqlite3_bind_text(statement, 2, strcmp(row_tenant, "tenant-a") == 0 ? tenant_id : row_tenant, -1,
                          SQLITE_TRANSIENT);
        sqlite3_bind_int64(statement, 3, client_id);
        sqlite3_bind_text(statement, 4, token, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 5, status, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 6, connected, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(statement, 7, version);
        sqlite3_bind_int(statement, 8, targets);
        sqlite3_bind_int(statement, 9, packets);
        if (sqlite3_step(statement) != SQLITE_DONE) rc = -1;
    }
    if (rc != 0) fprintf(stderr, "vector session insert failed: %s\n", db == NULL ? "(no db)" : sqlite3_errmsg(db));
    sqlite3_finalize(statement);
    sqlite3_close(db);
    free(row_tenant);
    free(status);
    free(connected);
    return rc;
}

/*
 * PeerEgressServiceTests theCatalogReflectsTheNewestOnlineIPv6PacketAnnouncement: replays the ten
 * "catalog" cases of protocol/test-vectors/peer-egress-ipv6-packet-announcement-v1.json. Each case's
 * session rows are the egress's only rows; ipv6PacketCapable in the consumer's catalogue must be the
 * case's expectation: the newest online session by connection time in the egress's own tenant,
 * never an older row, another tenant's row, a version-0 row or the separate ipv6TargetCapable.
 * The connection callback says every client is up, so only the stored rows decide.
 */
static int test_egress_catalog_ipv6_packet_vector(void)
{
    char *vector = read_text_file(ST_EGRESS_VECTOR_DIR "peer-egress-ipv6-packet-announcement-v1.json");
    char **cases = NULL;
    size_t case_count = 0U;
    if (vector == NULL || st_json_get_raw_array(vector, "catalog", &cases, &case_count) != 0 || case_count != 10U) {
        fprintf(stderr, "IPv6 packet announcement vector missing or not ten catalogue cases (%zu)\n", case_count);
        st_json_free_string_array(cases, case_count);
        free(vector);
        return 1;
    }
    char path[64];
    st_storage_client consumer, egress;
    st_storage_peer_mesh_device device;
    long long session_id = 0;
    int failed = temp_database(path, "peer_egress_ipv6_vector") != 0;
    failed = failed
        || st_storage_upsert_client(path, 0, "tenant-ipv6-vector", "vector-consumer", "owner", 1, 60, &consumer) != 0
        || st_storage_upsert_client(path, 0, "tenant-ipv6-vector", "vector-egress", "owner", 1, 60, &egress) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &consumer, 1, &device) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &egress, 1, &device) != 0
        || egress_switch_on(path, "tenant-ipv6-vector") != 0
        || add_egress_policy(path, &egress, consumer.id) != 0
        || open_egress_session(path, &consumer, 0, &session_id) != 0;
    if (failed) fprintf(stderr, "IPv6 packet vector fixture setup failed\n");
    peer_test_context capture;
    memset(&capture, 0, sizeof(capture));
    st_peer_mesh_runtime runtime = {path, capture_signal, always_online, &capture, 0, 2};
    size_t replayed = 0U;
    for (size_t i = 0U; !failed && i < case_count; ++i) {
        char *name = st_json_get_top_level_string(cases[i], "name");
        char **rows = NULL;
        size_t row_count = 0U;
        int expected = -1;
        char sql[128];
        snprintf(sql, sizeof(sql), "DELETE FROM specus_client_session WHERE client_id=%lld", egress.id);
        int ok = name != NULL && st_json_get_bool(cases[i], "expected", &expected) == 0
            && st_json_get_raw_array(cases[i], "sessions", &rows, &row_count) == 0 && row_count > 0U
            && exec_sql_on(path, sql) == 0;
        for (size_t r = 0U; ok && r < row_count; ++r) {
            ok = insert_vector_session(path, rows[r], egress.tenant_id, egress.id) == 0;
        }
        capture.count = 0;
        const char *catalog = NULL;
        int packets = -2;
        int targets = -2;
        if (ok && st_peer_mesh_refresh_tenant(&runtime, "tenant-ipv6-vector") == 0
            && (catalog = last_egress_catalog(&capture, "vector-consumer")) != NULL) {
            packets = catalog_entry_flag(catalog, "vector-egress", "ipv6PacketCapable");
            targets = catalog_entry_flag(catalog, "vector-egress", "ipv6TargetCapable");
        }
        if (packets != expected
            || (name != NULL && strcmp(name, "target-flag-is-not-packet-flag") == 0 && targets != 1)) {
            fprintf(stderr, "IPv6 packet vector case %s: packets %d (want %d), targets %d: %s\n",
                    name == NULL ? "(unnamed)" : name, packets, expected, targets,
                    catalog == NULL ? "(none)" : catalog);
            failed = 1;
        } else {
            ++replayed;
        }
        st_json_free_string_array(rows, row_count);
        free(name);
    }
    if (!failed && replayed != 10U) failed = 1;
    st_json_free_string_array(cases, case_count);
    free(vector);
    unlink(path);
    return failed;
}

/*
 * PeerEgressServiceTests refusalCountersKeepOnlyCodesThisBuildDefines, the cases test_egress_report
 * does not reach: a report without rejectedFlows, with only codes this build does not define, with
 * null, or with a negative count of a known code stores {}.
 */
static int test_egress_refusal_codes_unknown_only(void)
{
    char path[64];
    if (temp_database(path, "peer_egress_refusals") != 0) return 1;
    st_storage_client egress;
    long long session_id = 0;
    if (egress_report_client(path, "refusal-egress", 1, &egress, &session_id) != 0) {
        fprintf(stderr, "egress refusal fixture setup failed\n");
        unlink(path);
        return 1;
    }
    peer_test_context capture;
    memset(&capture, 0, sizeof(capture));
    /* A control session id of its own, so the earlier reports' rate windows do not count here. */
    st_peer_mesh_runtime runtime = {path, capture_signal, always_online, &capture, 9301, 2};
    static const char *const reports[] = {
        "{\"type\":\"egress-report\",\"revision\":1,\"activeFlows\":1}",
        "{\"type\":\"egress-report\",\"revision\":2,\"rejectedFlows\":{\"EGRESS_MADE_UP\":9}}",
        "{\"type\":\"egress-report\",\"revision\":3,\"rejectedFlows\":null}",
        "{\"type\":\"egress-report\",\"revision\":4,\"rejectedFlows\":{\"EGRESS_PORT_DENIED\":-3}}",
    };
    int failed = 0;
    for (size_t i = 0U; !failed && i < sizeof(reports) / sizeof(reports[0]); ++i) {
        st_storage_peer_mesh_egress_activity row;
        if (st_peer_mesh_handle_control(&runtime, egress.client_name, NULL, reports[i]) != 0
            || egress_activity(path, &egress, &row) != 0
            || row.revision != (long long)i + 1 || strcmp(row.rejected_flows, "{}") != 0) {
            fprintf(stderr, "egress report %s stored refusals %s\n", reports[i], row.rejected_flows);
            failed = 1;
        }
    }
    unlink(path);
    return failed;
}

/* ---- peer ACL and session close (Java PeerMeshServiceTests) -------------------------------- */

/*
 * crossOwnerDeniedWithoutAcl, crossOwnerAllowedWithExplicitAcl and closeSessionMarksSessionClosed:
 * two enabled devices of different owners cannot peer while there is no ACL row or only one with
 * allowed=0, so an offer or candidates between them is refused and nothing is sent; an allowed ACL
 * opens a session, and a close from the target side marks it CLOSED with closedAt set.
 */
static int test_session_owner_acl_and_close(void)
{
    char path[64];
    if (temp_database(path, "peer_owner_acl") != 0) return 1;
    st_storage_client alice, bob;
    st_storage_peer_mesh_device device;
    if (st_storage_upsert_client(path, 0, "tenant-owner", "owner-alice", "alice", 1, 60, &alice) != 0
        || st_storage_upsert_client(path, 0, "tenant-owner", "owner-bob", "bob", 1, 60, &bob) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &alice, 1, &device) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &bob, 1, &device) != 0) {
        fprintf(stderr, "cross-owner fixture setup failed\n");
        unlink(path);
        return 1;
    }
    peer_test_context ctx;
    memset(&ctx, 0, sizeof(ctx));
    st_peer_mesh_runtime runtime = {path, capture_signal, always_online, &ctx, 0, 2};
    st_storage_peer_mesh_acl acl;
    int failed = 0;
    for (int step = 0; !failed && step < 2; ++step) {
        int forward = -1;
        int reverse = -1;
        if (step == 1 && st_storage_upsert_peer_mesh_acl(path, "tenant-owner", "admin", &alice, &bob, 0, "BOTH",
                                                         &acl) != 0) failed = 1;
        ctx.count = 0;
        if (failed
            || st_storage_can_peer(path, &alice, &bob, &forward) != 0 || forward != 0
            || st_storage_can_peer(path, &bob, &alice, &reverse) != 0 || reverse != 0
            || st_peer_mesh_handle_control(&runtime, "owner-alice", "owner-bob",
                                           "{\"type\":\"offer\",\"sdp\":\"x\"}") == 0
            || st_peer_mesh_handle_control(&runtime, "owner-bob", "owner-alice",
                                           "{\"type\":\"candidates\",\"candidates\":[]}") == 0
            || ctx.count != 0) {
            fprintf(stderr, "cross-owner peers %s: can_peer %d/%d, %zu signals sent\n",
                    step == 0 ? "without an ACL" : "under a denying ACL", forward, reverse, ctx.count);
            failed = 1;
        }
    }
    long long id = 0;
    char token[64];
    int allowed = 0;
    st_storage_peer_mesh_session session;
    if (!failed && (st_storage_upsert_peer_mesh_acl(path, "tenant-owner", "admin", &alice, &bob, 1, "BOTH", &acl) != 0
                    || st_storage_can_peer(path, &alice, &bob, &allowed) != 0 || !allowed
                    || open_offer(&runtime, &ctx, "owner-alice", "owner-bob", &id, token) != 0)) {
        fprintf(stderr, "an allowed cross-owner ACL did not open a session\n");
        failed = 1;
    }
    if (!failed && (session_report(&runtime, "owner-bob", "{\"type\":\"close\",\"sessionId\":%lld}", id) != 0
                    || st_storage_get_peer_mesh_session(path, "tenant-owner", id, &session) != 0
                    || strcmp(session.status, "CLOSED") != 0 || session.closed_at[0] == '\0')) {
        fprintf(stderr, "the target side's close did not close the session\n");
        failed = 1;
    }
    unlink(path);
    return failed;
}

/* ---- three peers, two publisher sessions (Java PeerServiceDiscoveryServiceTests) ------------ */

/* The recipient got one service-catalog per publisher session, 101 and 102, each with or without the service. */
static int sync_catalogs_are(const peer_test_context *ctx, const char *recipient, int with_service, const char *label)
{
    int total = 0;
    int session_101 = 0;
    int session_102 = 0;
    int shaped = 1;
    for (size_t i = 0; i < ctx->count; ++i) {
        const char *message = ctx->signals[i].message;
        if (strcmp(ctx->signals[i].target, recipient) != 0 || !contains(message, "\"type\":\"service-catalog\"")) {
            continue;
        }
        ++total;
        session_101 += contains(message, "\"publisherSessionId\":101,");
        session_102 += contains(message, "\"publisherSessionId\":102,");
        if (contains(message, "\"serviceId\":\"svc-sync0001\"") != with_service
            || (!with_service && !contains(message, "\"services\":[]"))) shaped = 0;
    }
    if (shaped && total == 2 && session_101 == 1 && session_102 == 1) return 0;
    fprintf(stderr, "%s: %s got %d catalogues (101: %d, 102: %d), want one per session %s\n", label, recipient,
            total, session_101, session_102, with_service ? "with the service" : "without services");
    return -1;
}

/* The catalogue revision a publisher session currently holds, or -1. */
static long long sync_revision(long long publisher_id, long long session_id)
{
    st_peer_mesh_service_instance instances[8];
    size_t count = 0U;
    if (st_peer_mesh_list_service_instances("tenant-sync", publisher_id, "svc-sync0001", instances, 8U, &count) != 0) {
        return -1;
    }
    for (size_t i = 0U; i < count; ++i) {
        if (instances[i].publisher_session_id == session_id) return instances[i].revision;
    }
    return -1;
}

/*
 * authorizationChangesLoginAndDisconnectSynchronizeThreePeersAndPublisherSessions. A publisher with
 * two control sessions (101, 102) shares an ACL-visible service with peers B and C, each of another
 * owner and let in by a mesh ACL. Narrowing the service allowlist to B sends B both sessions'
 * catalogues with the service and C both without it. Revoking B's mesh ACL sends B both empty while
 * C keeps the service, and so does B's next login; with the ACL back B's login replays both with
 * the service. A later report advances the revision past the authorisation change, and the
 * disconnect of session 101 withdraws only that session's catalogue.
 */
static int test_service_three_peer_sync(void)
{
    char path[64];
    if (temp_database(path, "peer_service_sync") != 0) return 1;
    st_storage_client publisher, peer_b, peer_c;
    st_storage_peer_mesh_device device;
    st_storage_peer_mesh_acl acl;
    st_storage_peer_mesh_service service, saved;
    memset(&service, 0, sizeof(service));
    int failed = st_storage_upsert_client(path, 0, "tenant-sync", "sync-publisher", "alice", 1, 60, &publisher) != 0
        || st_storage_upsert_client(path, 0, "tenant-sync", "sync-peer-b", "bob", 1, 60, &peer_b) != 0
        || st_storage_upsert_client(path, 0, "tenant-sync", "sync-peer-c", "carol", 1, 60, &peer_c) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &publisher, 1, &device) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &peer_b, 1, &device) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &peer_c, 1, &device) != 0
        || st_storage_upsert_peer_mesh_acl(path, "tenant-sync", "admin", &publisher, &peer_b, 1, "BOTH", &acl) != 0
        || st_storage_upsert_peer_mesh_acl(path, "tenant-sync", "admin", &publisher, &peer_c, 1, "BOTH", &acl) != 0
        || st_storage_upsert_peer_mesh_service_sharing(path, "tenant-sync", 1, 0, "admin", NULL) != 0;
    snprintf(service.tenant_id, sizeof(service.tenant_id), "%s", publisher.tenant_id);
    service.client_id = publisher.id;
    snprintf(service.client_name, sizeof(service.client_name), "%s", publisher.client_name);
    snprintf(service.service_id, sizeof(service.service_id), "svc-sync0001");
    snprintf(service.name, sizeof(service.name), "local-ssh");
    snprintf(service.transport, sizeof(service.transport), "tcp");
    snprintf(service.application, sizeof(service.application), "ssh");
    snprintf(service.target_host, sizeof(service.target_host), "127.0.0.1");
    service.target_port = 22;
    service.published_port = 2222;
    service.enabled = 1;
    snprintf(service.visibility, sizeof(service.visibility), "ACL");
    snprintf(service.allowed_client_ids, sizeof(service.allowed_client_ids), "%lld,%lld", peer_b.id, peer_c.id);
    failed = failed || st_storage_upsert_peer_mesh_service(path, &service, &saved) != 0;
    if (failed) {
        fprintf(stderr, "three-peer sync fixture setup failed\n");
        unlink(path);
        return 1;
    }
    peer_test_context ctx;
    memset(&ctx, 0, sizeof(ctx));
    st_peer_mesh_runtime session_101 = {path, capture_signal, always_online, &ctx, 101, 2};
    st_peer_mesh_runtime session_102 = {path, capture_signal, always_online, &ctx, 102, 2};
    static const char *const report_format =
        "{\"type\":\"service-report\",\"enabled\":true,\"revision\":%d,\"services\":[{\"serviceId\":\"svc-sync0001\","
        "\"name\":\"client-supplied-name\",\"transport\":\"tcp\",\"application\":\"ssh\",\"publishedPort\":2222}]}";
    char report[512];
    snprintf(report, sizeof(report), report_format, 1);
    failed = st_peer_mesh_handle_control(&session_101, publisher.client_name, NULL, report) != 0
        || st_peer_mesh_handle_control(&session_102, publisher.client_name, NULL, report) != 0;
    if (failed) fprintf(stderr, "the two publisher sessions' reports were refused\n");

    /* The allowlist narrowed to B: an admin service update refreshes the tenant. */
    snprintf(saved.allowed_client_ids, sizeof(saved.allowed_client_ids), "%lld", peer_b.id);
    ctx.count = 0;
    if (!failed && (st_storage_upsert_peer_mesh_service(path, &saved, &saved) != 0
                    || st_peer_mesh_refresh_tenant(&session_101, "tenant-sync") != 0
                    || sync_catalogs_are(&ctx, "sync-peer-b", 1, "allowlist narrowed to B") != 0
                    || sync_catalogs_are(&ctx, "sync-peer-c", 0, "allowlist narrowed to B") != 0)) failed = 1;
    snprintf(saved.allowed_client_ids, sizeof(saved.allowed_client_ids), "%lld,%lld", peer_b.id, peer_c.id);
    if (!failed && (st_storage_upsert_peer_mesh_service(path, &saved, &saved) != 0
                    || st_peer_mesh_refresh_tenant(&session_101, "tenant-sync") != 0)) failed = 1;

    /* B's mesh access revoked: B loses the service on both sessions, C keeps it, and B's login agrees. */
    ctx.count = 0;
    if (!failed && (st_storage_upsert_peer_mesh_acl(path, "tenant-sync", "admin", &publisher, &peer_b, 0, "BOTH",
                                                    &acl) != 0
                    || st_peer_mesh_refresh_tenant(&session_101, "tenant-sync") != 0
                    || sync_catalogs_are(&ctx, "sync-peer-b", 0, "B revoked") != 0
                    || sync_catalogs_are(&ctx, "sync-peer-c", 1, "B revoked") != 0)) failed = 1;
    ctx.count = 0;
    if (!failed && (st_peer_mesh_push_on_login(&session_101, "sync-peer-b") != 0
                    || sync_catalogs_are(&ctx, "sync-peer-b", 0, "revoked B's login") != 0)) failed = 1;
    ctx.count = 0;
    if (!failed && (st_storage_upsert_peer_mesh_acl(path, "tenant-sync", "admin", &publisher, &peer_b, 1, "BOTH",
                                                    &acl) != 0
                    || st_peer_mesh_push_on_login(&session_101, "sync-peer-b") != 0
                    || sync_catalogs_are(&ctx, "sync-peer-b", 1, "re-allowed B's login") != 0)) failed = 1;

    /* A later report on 101 goes out under a revision above the authorisation change's. */
    long long authorization_revision = failed ? -1 : sync_revision(publisher.id, 101);
    snprintf(report, sizeof(report), report_format, 2);
    ctx.count = 0;
    if (!failed && (authorization_revision < 1
                    || st_peer_mesh_handle_control(&session_101, publisher.client_name, NULL, report) != 0
                    || ctx.count == 0 || sync_revision(publisher.id, 101) <= authorization_revision)) {
        fprintf(stderr, "a report after the authorisation change did not advance the revision past %lld (%lld)\n",
                authorization_revision, sync_revision(publisher.id, 101));
        failed = 1;
    }

    /* Session 101 disconnects: only its catalogue is withdrawn, 102's stays. */
    ctx.count = 0;
    int withdrawn = 1;
    if (!failed && st_peer_mesh_handle_disconnect(&session_101, publisher.client_name) != 0) withdrawn = 0;
    for (size_t i = 0; !failed && i < ctx.count; ++i) {
        if (!contains(ctx.signals[i].message, "\"publisherSessionId\":101,")
            || !contains(ctx.signals[i].message, "\"services\":[]")) withdrawn = 0;
    }
    if (!failed && (!withdrawn || ctx.count == 0 || sync_revision(publisher.id, 101) != -1
                    || sync_revision(publisher.id, 102) < 1)) {
        fprintf(stderr, "disconnecting session 101 did not withdraw only its catalogue\n");
        failed = 1;
    }
    (void)st_peer_mesh_handle_disconnect(&session_102, publisher.client_name);
    unlink(path);
    return failed;
}

int main(void)
{
    if (test_wire_expiry_format() != 0) return 1;
    char path[] = "/tmp/specus_c_peer_mesh_tests.XXXXXX";
    int temp_fd = mkstemp(path);
    if (temp_fd < 0) return 1;
    close(temp_fd);
    unlink(path);
    setenv("SPECUS_PEER_MESH_ENABLED", "true", 1);
    setenv("SPECUS_PEER_MESH_CIDR", "100.96.0.0/11", 1);
    setenv("SPECUS_PEER_MESH_SESSION_TTL_SECONDS", "3600", 1);
    if (st_storage_init(path, 0) != 0) return 1;

    st_storage_client source;
    st_storage_client target;
    st_storage_client denied;
    st_storage_peer_mesh_device source_device;
    st_storage_peer_mesh_device target_device;
    if (st_storage_upsert_client(path, 0, "tenant-peer", "peer-source", "owner", 1, 60, &source) != 0
        || st_storage_upsert_client(path, 0, "tenant-peer", "peer-target", "owner", 1, 60, &target) != 0
        || st_storage_upsert_client(path, 0, "tenant-peer", "peer-denied", "other", 1, 60, &denied) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &source, 1, &source_device) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &target, 1, &target_device) != 0) {
        fprintf(stderr, "peer mesh fixture setup failed\n");
        return 1;
    }
    if (source_device.virtual_ip[0] == '\0' || target_device.virtual_ip[0] == '\0'
        || strcmp(source_device.virtual_ip, target_device.virtual_ip) == 0
        || strcmp(source_device.cidr, "100.96.0.0/11") != 0) {
        fprintf(stderr, "peer mesh virtual IP allocation mismatch\n");
        return 1;
    }
    st_storage_peer_mesh_service service;
    memset(&service, 0, sizeof(service));
    snprintf(service.tenant_id, sizeof(service.tenant_id), "%s", source.tenant_id);
    service.client_id = source.id;
    snprintf(service.client_name, sizeof(service.client_name), "%s", source.client_name);
    snprintf(service.service_id, sizeof(service.service_id), "service-http-1");
    snprintf(service.name, sizeof(service.name), "Local HTTP");
    snprintf(service.description, sizeof(service.description), "Peer-only test service");
    snprintf(service.transport, sizeof(service.transport), "tcp");
    snprintf(service.application, sizeof(service.application), "http");
    snprintf(service.target_host, sizeof(service.target_host), "127.0.0.1");
    service.target_port = 8080;
    service.published_port = 18080;
    snprintf(service.path, sizeof(service.path), "/");
    service.enabled = 1;
    snprintf(service.visibility, sizeof(service.visibility), "OWNER");
    if (st_storage_upsert_peer_mesh_service_sharing(path, source.tenant_id, 1, 1, "admin", NULL) != 0
        || st_storage_upsert_peer_mesh_service(path, &service, NULL) != 0) {
        fprintf(stderr, "peer service fixture setup failed\n");
        return 1;
    }

    peer_test_context context = {0};
    context.target_online = 1;
    st_peer_mesh_runtime runtime = {path, capture_signal, is_online, &context, 7001, 2};
    if (st_peer_mesh_push_on_login(&runtime, source.client_name) != 0
        || context.count < 2
        || !contains(context.signals[0].message, "\"type\":\"peer-config\"")
        || !contains(context.signals[0].message, "\"peerServiceDiscoveryVersion\":2")
        || !contains(context.signals[0].message, "\"configuredEnabled\":true")
        || !contains(context.signals[0].message, "\"serviceId\":\"service-http-1\"")
        || !contains(context.signals[0].message, target_device.virtual_ip)) {
        fprintf(stderr, "peer mesh login config/roster push mismatch\n");
        return 1;
    }
    /*
     * loginConfigOnlyPublishesServicesToAclCapableClientAndIncludesAuthorizedPeerIps: a v1 client
     * gets no local services; a v2 one gets them with exactly the authorised peers' virtual IPs
     * (peer-denied belongs to another owner and the service is OWNER-visible).
     */
    char allowed_ips[128];
    snprintf(allowed_ips, sizeof(allowed_ips), "\"allowedPeerVirtualIps\":[\"%s\"]", target_device.virtual_ip);
    char *v1_config = st_peer_mesh_build_login_config(path, source.client_name, 1);
    char *v2_config = st_peer_mesh_build_login_config(path, source.client_name, 2);
    int services_ok = contains(v1_config, "\"localServices\":[]")
        && contains(v2_config, "\"serviceId\":\"service-http-1\"") && contains(v2_config, allowed_ips);
    if (!services_ok) {
        fprintf(stderr, "login config local services mismatch: v1 %s | v2 %s\n",
                v1_config == NULL ? "(none)" : v1_config, v2_config == NULL ? "(none)" : v2_config);
    }
    free(v1_config);
    free(v2_config);
    if (!services_ok) return 1;

    context.count = 0;
    const char *service_report =
        "{\"type\":\"service-report\",\"enabled\":true,\"revision\":1,"
        "\"instanceId\":\"instance-a\",\"services\":[{\"serviceId\":\"service-http-1\","
        "\"name\":\"Local HTTP\",\"description\":\"Peer-only test service\","
        "\"transport\":\"tcp\",\"application\":\"http\",\"publishedPort\":18080,\"path\":\"/\"}],"
        "\"stats\":[{\"serviceId\":\"service-http-1\",\"bytesIn\":12,\"bytesOut\":34,"
        "\"activeConnections\":2,\"totalConnections\":5}],"
        "\"mdnsCandidates\":[{\"name\":\"Local Web\",\"application\":\"http\","
        "\"targetHost\":\"localhost\",\"targetPort\":8080},"
        "{\"name\":\"Public Web\",\"transport\":\"tcp\",\"application\":\"http\","
        "\"targetHost\":\"198.51.100.9\",\"targetPort\":8081}]}";
    if (st_peer_mesh_handle_control(&runtime, source.client_name, NULL, service_report) != 0
        || context.count != 1 || strcmp(context.signals[0].target, target.client_name) != 0
        || !contains(context.signals[0].message, "\"type\":\"service-catalog\"")
        || !contains(context.signals[0].message, "\"publisherSessionId\":7001")
        || !contains(context.signals[0].message, "\"serviceId\":\"service-http-1\"")
        || contains(context.signals[0].message, "targetHost")) {
        fprintf(stderr, "peer service catalog fanout mismatch\n");
        return 1;
    }
    st_peer_mesh_mdns_candidate mdns[8];
    size_t mdns_count = 0U;
    st_peer_mesh_service_instance instances[8];
    size_t instance_count = 0U;
    if (st_peer_mesh_list_mdns_candidates(source.tenant_id, source.id, mdns, 8U, &mdns_count) != 0
        || mdns_count != 1 || strcmp(mdns[0].target_host, "127.0.0.1") != 0
        || strcmp(mdns[0].transport, "tcp") != 0
        || st_peer_mesh_list_service_instances(source.tenant_id, source.id, service.service_id,
                                               instances, 8U, &instance_count) != 0
        || instance_count != 1 || !instances[0].advertised || !instances[0].online
        || instances[0].bytes_in != 12 || instances[0].bytes_out != 34
        || instances[0].active_connections != 2 || instances[0].total_connections != 5) {
        fprintf(stderr, "peer service mDNS/stat catalog mismatch\n");
        return 1;
    }
    context.count = 0;
    if (st_peer_mesh_handle_control(&runtime, source.client_name, NULL, service_report) != 0
        || context.count != 0
        || st_peer_mesh_handle_control(&runtime, source.client_name, NULL,
            "{\"type\":\"service-report\",\"sourceClientId\":999,\"revision\":2,\"services\":[]}") == 0) {
        fprintf(stderr, "peer service report revision/envelope validation mismatch\n");
        return 1;
    }
    if (st_peer_mesh_handle_control(&runtime, source.client_name, NULL,
            "{\"type\":\"service-report\",\"enabled\":false,\"revision\":2,\"services\":[]}") != 0
        || context.count != 1 || !contains(context.signals[0].message, "\"services\":[]")) {
        fprintf(stderr, "peer service catalog withdrawal mismatch\n");
        return 1;
    }
    context.count = 0;
    if (st_peer_mesh_handle_control(&runtime, source.client_name, NULL,
            "{\"type\":\"service-report\",\"enabled\":true,\"revision\":3,"
            "\"instanceId\":\"instance-a\",\"services\":[{\"serviceId\":\"service-http-1\","
            "\"name\":\"Local HTTP\",\"description\":\"Peer-only test service\","
            "\"transport\":\"tcp\",\"application\":\"http\",\"publishedPort\":18080,\"path\":\"/\"}]}") != 0
        || context.count != 1) {
        fprintf(stderr, "peer service refresh fixture mismatch\n");
        return 1;
    }
    context.count = 0;
    if (st_storage_update_peer_mesh_device_enabled(path, &target, 0, &target_device) != 0
        || st_peer_mesh_refresh_tenant(&runtime, source.tenant_id) != 0) {
        fprintf(stderr, "peer service tenant refresh failed\n");
        return 1;
    }
    int saw_revoked_catalog = 0;
    for (size_t i = 0; i < context.count; ++i) {
        if (strcmp(context.signals[i].target, target.client_name) == 0
            && contains(context.signals[i].message, "\"type\":\"service-catalog\"")
            && contains(context.signals[i].message, "\"services\":[]")) {
            saw_revoked_catalog = 1;
        }
    }
    if (!saw_revoked_catalog
        || st_storage_update_peer_mesh_device_enabled(path, &target, 1, &target_device) != 0
        || st_peer_mesh_refresh_tenant(&runtime, source.tenant_id) != 0) {
        fprintf(stderr, "peer service permission revocation refresh mismatch\n");
        return 1;
    }
    context.count = 0;
    if (st_peer_mesh_handle_disconnect(&runtime, source.client_name) != 0
        || context.count != 1
        || !contains(context.signals[0].message, "\"publisherSessionId\":7001")
        || !contains(context.signals[0].message, "\"services\":[]")) {
        fprintf(stderr, "peer service disconnect withdrawal mismatch\n");
        return 1;
    }
    setenv("SPECUS_PEER_MESH_CATALOG_TTL_SECONDS", "1", 1);
    context.count = 0;
    if (st_peer_mesh_handle_control(&runtime, source.client_name, NULL,
            "{\"type\":\"service-report\",\"enabled\":true,\"revision\":4,"
            "\"instanceId\":\"instance-a\",\"services\":[{\"serviceId\":\"service-http-1\","
            "\"name\":\"Local HTTP\",\"description\":\"Peer-only test service\","
            "\"transport\":\"tcp\",\"application\":\"http\",\"publishedPort\":18080,\"path\":\"/\"}]}") != 0
        || context.count != 1) {
        fprintf(stderr, "peer service expiry fixture mismatch\n");
        return 1;
    }
    context.count = 0;
    sleep(1);
    if (st_peer_mesh_expire_catalogs(&runtime) != 0
        || context.count != 1
        || !contains(context.signals[0].message, "\"services\":[]")) {
        fprintf(stderr, "peer service catalog expiry mismatch\n");
        return 1;
    }
    unsetenv("SPECUS_PEER_MESH_CATALOG_TTL_SECONDS");

    context.count = 0;
    const char *candidates =
        "{\"type\":\"candidates\",\"sourceClientId\":999,\"sourceClientName\":\"spoof\","
        "\"sourceKeyEpoch\":\"epoch-a\",\"candidates\":[{\"type\":\"host\","
        "\"address\":\"192.0.2.10\",\"port\":40000}],\"dataFrameVersion\":2}";
    if (st_peer_mesh_handle_control(&runtime, source.client_name, target.client_name, candidates) != 0
        || context.count != 2
        || strcmp(context.signals[0].target, source.client_name) != 0
        || !contains(context.signals[0].message, "\"type\":\"session-grant\"")
        || !contains(context.signals[0].message, "\"token\":")
        || strcmp(context.signals[1].target, target.client_name) != 0
        || !contains(context.signals[1].message, "\"sourceClientName\":\"peer-source\"")
        || contains(context.signals[1].message, "spoof")
        || !contains(context.signals[1].message, "\"candidates\":[")
        || !contains(context.signals[1].message, "\"sourceKeyEpoch\":\"epoch-a\"")) {
        fprintf(stderr, "peer mesh candidate/session forwarding mismatch\n");
        return 1;
    }
    if (!has_wire_expiry(context.signals[0].message) || !has_wire_expiry(context.signals[1].message)) {
        fprintf(stderr, "peer mesh session expiry is not an RFC 3339 UTC instant: %s | %s\n",
                context.signals[0].message, context.signals[1].message);
        return 1;
    }

    st_storage_peer_mesh_session sessions[8];
    size_t session_count = 0;
    if (st_storage_list_peer_mesh_sessions_visible(path, "tenant-peer", "owner", 1, 1, 8,
                                                   sessions, 8, &session_count) != 0
        || session_count != 1 || strcmp(sessions[0].status, "NEGOTIATING") != 0) {
        fprintf(stderr, "peer mesh session creation mismatch\n");
        return 1;
    }
    char report[512];
    snprintf(report, sizeof(report),
             "{\"type\":\"path-report\",\"sessionId\":%lld,\"pathType\":\"DIRECT\","
             "\"rttMillis\":12,\"localEndpoint\":\"10.0.0.1:1\",\"remoteEndpoint\":\"10.0.0.2:2\"}",
             sessions[0].id);
    if (st_peer_mesh_handle_control(&runtime, source.client_name, NULL, report) != 0
        || st_storage_get_peer_mesh_session(path, "tenant-peer", sessions[0].id, &sessions[0]) != 0
        || strcmp(sessions[0].status, "ACTIVE") != 0 || sessions[0].rtt_millis != 12) {
        fprintf(stderr, "peer mesh path report mismatch\n");
        return 1;
    }
    snprintf(report, sizeof(report),
             "{\"type\":\"traffic-report\",\"sessionId\":%lld,\"directBytes\":123}",
             sessions[0].id);
    if (st_peer_mesh_handle_control(&runtime, target.client_name, NULL, report) != 0
        || st_storage_get_peer_mesh_session(path, "tenant-peer", sessions[0].id, &sessions[0]) != 0
        || sessions[0].direct_bytes != 123 || strcmp(sessions[0].path_type, "DIRECT") != 0) {
        fprintf(stderr, "peer mesh traffic report mismatch\n");
        return 1;
    }
    if (st_peer_mesh_handle_control(&runtime, source.client_name, NULL,
            "{\"type\":\"device-report\",\"natType\":\"PORT_RESTRICTED\","
            "\"natMappingBehavior\":\"ENDPOINT_INDEPENDENT\","
            "\"natFilteringBehavior\":\"ADDRESS_AND_PORT_DEPENDENT\","
            "\"natBehaviorDiscovery\":\"RFC5780\","
            "\"lastEndpoint\":\"198.51.100.1:50000\",\"virtualDeviceStatus\":\"UP\"}") != 0
        || st_storage_get_peer_mesh_device_by_client(path, "tenant-peer", source.id, &source_device) != 0
        || strcmp(source_device.nat_type, "PORT_RESTRICTED") != 0
        || strcmp(source_device.nat_mapping_behavior, "ENDPOINT_INDEPENDENT") != 0
        || strcmp(source_device.nat_filtering_behavior, "ADDRESS_AND_PORT_DEPENDENT") != 0
        || strcmp(source_device.nat_behavior_discovery, "RFC5780") != 0
        || strcmp(source_device.last_endpoint, "198.51.100.1:50000") != 0
        || strcmp(source_device.virtual_device_status, "UP") != 0) {
        fprintf(stderr, "peer mesh device report mismatch\n");
        return 1;
    }
    if (st_peer_mesh_handle_control(&runtime, source.client_name, denied.client_name,
                                    "{\"type\":\"offer\"}") == 0) {
        fprintf(stderr, "peer mesh denied target was accepted\n");
        return 1;
    }
    context.target_online = 0;
    if (st_peer_mesh_handle_control(&runtime, source.client_name, target.client_name,
                                    "{\"type\":\"offer\"}") == 0) {
        fprintf(stderr, "peer mesh offline target was accepted\n");
        return 1;
    }

    snprintf(report, sizeof(report), "{\"type\":\"close\",\"sessionId\":%lld}", sessions[0].id);
    if (st_peer_mesh_handle_control(&runtime, source.client_name, NULL, report) != 0
        || st_storage_get_peer_mesh_session(path, "tenant-peer", sessions[0].id, &sessions[0]) != 0
        || strcmp(sessions[0].status, "CLOSED") != 0) {
        fprintf(stderr, "peer mesh close mismatch\n");
        return 1;
    }

    /* A device that leaves is announced to its online peers, with itself offline. Rosters used to
     * be pushed on login only, so a consumer kept a stopped egress as online. */
    context.count = 0;
    context.target_online = 0;
    if (st_peer_mesh_push_on_logout(&runtime, target.client_name) != 0) {
        fprintf(stderr, "peer mesh logout push failed\n");
        return 1;
    }
    int announced = 0;
    for (size_t i = 0; i < context.count; ++i) {
        if (strcmp(context.signals[i].target, source.client_name) == 0
            && contains(context.signals[i].message, "\"type\":\"roster\"")) {
            const char *entry = strstr(context.signals[i].message, "\"clientName\":\"peer-target\"");
            const char *online = entry == NULL ? NULL : strstr(entry, "\"online\":");
            announced = online != NULL && strncmp(online, "\"online\":false", 14) == 0;
        }
        if (strcmp(context.signals[i].target, target.client_name) == 0) {
            fprintf(stderr, "peer mesh logout push reached the departed client\n");
            return 1;
        }
    }
    if (!announced) {
        fprintf(stderr, "peer mesh logout did not tell the peer the device is offline\n");
        return 1;
    }

    /* A device already back on a newer session was announced by that login. */
    context.count = 0;
    context.target_online = 1;
    if (st_peer_mesh_push_on_logout(&runtime, target.client_name) != 0 || context.count != 0) {
        fprintf(stderr, "peer mesh logout announced a device that is still online\n");
        return 1;
    }

    /*
     * The login config, rosters and catalogues read every client of the database, which used to be
     * cut at 256 or 1024 rows: past that, a client's local services and every Peer Mesh push failed,
     * whatever tenant the other clients were in. Their names sort before these clients'.
     */
    sqlite3 *bulk_db = NULL;
    int bulk_ok = sqlite3_open(path, &bulk_db) == SQLITE_OK
        && sqlite3_exec(bulk_db,
                        "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < 1099) "
                        "INSERT INTO client_account(tenant_id, client_name, owner_username) "
                        "SELECT 'tenant-bulk', printf('bulk-client-%04d', i), 'bulk-owner' FROM n",
                        NULL, NULL, NULL) == SQLITE_OK;
    sqlite3_close(bulk_db);
    char *bulk_config = bulk_ok ? st_peer_mesh_build_login_config(path, source.client_name, 2) : NULL;
    int bulk_config_ok = contains(bulk_config, "\"serviceId\":\"service-http-1\"") && contains(bulk_config, allowed_ips);
    free(bulk_config);
    context.count = 0;
    context.target_online = 1;
    if (!bulk_ok || !bulk_config_ok || st_peer_mesh_push_on_login(&runtime, source.client_name) != 0
        || context.count < 2 || !contains(context.signals[0].message, "\"type\":\"peer-config\"")) {
        fprintf(stderr, "peer mesh login config or push failed with 1100 more clients in the database\n");
        return 1;
    }

    unlink(path);
    if (test_egress_catalog_domain_targets() != 0) return 1;
    if (test_egress_catalog_ipv6_targets() != 0) return 1;
    if (test_egress_catalog_ipv6_packets() != 0) return 1;
    if (test_egress_catalog_egress_version() != 0) return 1;
    if (test_egress_config_domain_rules() != 0) return 1;
    if (test_egress_pushes_are_gated() != 0) return 1;
    if (test_egress_report() != 0) return 1;
    if (test_egress_allowlist_needs_base_access() != 0) return 1;
    if (test_egress_policy_defaults_and_catalog_shape() != 0) return 1;
    if (test_egress_catalog_ipv6_packet_vector() != 0) return 1;
    if (test_egress_refusal_codes_unknown_only() != 0) return 1;
    if (test_session_owner_acl_and_close() != 0) return 1;
    if (test_service_three_peer_sync() != 0) return 1;
    if (test_session_reuse() != 0) return 1;
    if (test_session_reports() != 0) return 1;
    if (test_login_config_stun() != 0) return 1;
    if (test_service_report_bounds() != 0) return 1;
    if (test_acl_visibility() != 0) return 1;
    if (test_service_report_lifecycle() != 0) return 1;
    printf("peer mesh tests passed\n");
    return 0;
}
