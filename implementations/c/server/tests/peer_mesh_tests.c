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

/* The session expiry is an RFC 3339 UTC instant on the wire, "YYYY-MM-DDTHH:MM:SSZ", whatever
 * format the database keeps it in. */
static int has_wire_expiry(const char *message)
{
    const char *value = message == NULL ? NULL : strstr(message, "\"expiresAt\":\"");
    if (value == NULL) return 0;
    value += strlen("\"expiresAt\":\"");
    static const char shape[] = "dddd-dd-ddTdd:dd:ddZ\"";
    for (size_t i = 0; shape[i] != '\0'; ++i) {
        if (shape[i] == 'd' ? (value[i] < '0' || value[i] > '9') : value[i] != shape[i]) return 0;
    }
    return 1;
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

    static const char *const names[] = { "egress-current", "egress-old", "egress-gone", "egress-departing" };
    st_storage_client consumer;
    st_storage_client egresses[4];
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
    for (size_t i = 0; !failed && i < 4U; ++i) {
        failed = st_storage_upsert_client(path, 0, "tenant-egress-version", names[i], "owner", 1, 60,
                                          &egresses[i]) != 0
            || st_storage_update_peer_mesh_device_enabled(path, &egresses[i], 1, &device) != 0
            || add_egress_policy(path, &egresses[i], consumer.id) != 0;
    }
    /*
     * egress-current announced version 1. egress-old is an old client that announced none.
     * egress-gone announced 1 on a session that has since ended. egress-departing still has its
     * session row online, as during the logout push, but its connection is already gone.
     */
    failed = failed
        || open_egress_session_announcing(path, &egresses[0], 1, 0, &session_id) != 0
        || open_egress_session_announcing(path, &egresses[1], 0, 0, &session_id) != 0
        || open_egress_session_announcing(path, &egresses[2], 1, 0, &session_id) != 0
        || st_storage_mark_client_session_disconnected(path, session_id, "2026-06-25T00:02:00Z") != 0
        || open_egress_session_announcing(path, &egresses[3], 1, 0, &session_id) != 0;
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
    /* More relay than direct traffic makes the session a relayed one... */
    if (!failed && (session_report(&runtime, "reports-a",
                                   "{\"type\":\"traffic-report\",\"sessionId\":%lld,\"relayBytes\":200}", id) != 0
                    || session_state_is(path, id, "ACTIVE", "RELAY", 120, 230, "relay traffic") != 0)) failed = 1;
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

int main(void)
{
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

    unlink(path);
    if (test_egress_catalog_domain_targets() != 0) return 1;
    if (test_egress_catalog_egress_version() != 0) return 1;
    if (test_egress_config_domain_rules() != 0) return 1;
    if (test_egress_pushes_are_gated() != 0) return 1;
    if (test_egress_report() != 0) return 1;
    if (test_session_reuse() != 0) return 1;
    if (test_session_reports() != 0) return 1;
    if (test_login_config_stun() != 0) return 1;
    if (test_service_report_bounds() != 0) return 1;
    if (test_acl_visibility() != 0) return 1;
    if (test_service_report_lifecycle() != 0) return 1;
    printf("peer mesh tests passed\n");
    return 0;
}
