#define _POSIX_C_SOURCE 200809L

#include "peer_egress.h"
#include "peer_mesh.h"
#include "storage.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
    printf("peer mesh tests passed\n");
    return 0;
}
