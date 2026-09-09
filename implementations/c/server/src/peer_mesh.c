#define _POSIX_C_SOURCE 200809L

#include "peer_mesh.h"

#include "crypto.h"
#include "json.h"
#include "peer_egress.h"
#include "storage.h"
#include "turn_auth.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#define ST_PEER_MESH_MAX_CLIENTS 1024U
#define ST_PEER_MESH_MAX_CATALOGS 4096U
#define ST_PEER_MESH_MAX_CATALOG_SERVICES 32U
#define ST_PEER_MESH_CATALOG_TTL_SECONDS 300

typedef struct {
    char service_id[65];
    long long bytes_in;
    long long bytes_out;
    int active_connections;
    long long total_connections;
} pm_service_stats;

typedef struct {
    int in_use;
    int active;
    char tenant_id[64];
    long long publisher_client_id;
    char publisher_client_name[256];
    long long publisher_session_id;
    long long report_revision;
    long long catalog_revision;
    char instance_id[65];
    time_t generated_at;
    time_t expires_at;
    time_t rate_window_started_at;
    unsigned int rate_count;
    char service_ids[ST_PEER_MESH_MAX_CATALOG_SERVICES][65];
    size_t service_count;
    pm_service_stats stats[ST_PEER_MESH_MAX_CATALOG_SERVICES];
    size_t stats_count;
    st_peer_mesh_mdns_candidate *mdns_candidates;
    size_t mdns_count;
} pm_catalog;

static pm_catalog peer_catalogs[ST_PEER_MESH_MAX_CATALOGS];
static pthread_mutex_t peer_catalog_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} pm_builder;

static int pm_reserve(pm_builder *builder, size_t more)
{
    if (builder->len + more + 1U <= builder->cap) return 0;
    size_t next = builder->cap == 0U ? 256U : builder->cap;
    while (next < builder->len + more + 1U) {
        if (next > SIZE_MAX / 2U) return -1;
        next *= 2U;
    }
    char *grown = (char *)realloc(builder->data, next);
    if (grown == NULL) return -1;
    builder->data = grown;
    builder->cap = next;
    return 0;
}

static int pm_append(pm_builder *builder, const char *value)
{
    size_t len = strlen(value);
    if (pm_reserve(builder, len) != 0) return -1;
    memcpy(builder->data + builder->len, value, len + 1U);
    builder->len += len;
    return 0;
}

static int pm_appendf(pm_builder *builder, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    va_list copy;
    va_copy(copy, args);
    int needed = vsnprintf(NULL, 0, format, copy);
    va_end(copy);
    if (needed < 0 || pm_reserve(builder, (size_t)needed) != 0) {
        va_end(args);
        return -1;
    }
    vsnprintf(builder->data + builder->len, builder->cap - builder->len, format, args);
    va_end(args);
    builder->len += (size_t)needed;
    return 0;
}

static int pm_append_json_string(pm_builder *builder, const char *value)
{
    char *escaped = st_json_escape(value == NULL ? "" : value);
    if (escaped == NULL) return -1;
    int rc = pm_appendf(builder, "\"%s\"", escaped);
    free(escaped);
    return rc;
}

static int pm_env_bool(const char *name, int default_value)
{
    const char *value = getenv(name);
    if (value == NULL || *value == '\0') return default_value;
    return strcmp(value, "1") == 0 || strcmp(value, "true") == 0
        || strcmp(value, "TRUE") == 0 || strcmp(value, "yes") == 0;
}

static long long pm_env_i64(const char *name, long long default_value)
{
    const char *value = getenv(name);
    if (value == NULL || *value == '\0') return default_value;
    char *end = NULL;
    long long parsed = strtoll(value, &end, 10);
    return end != value && *end == '\0' ? parsed : default_value;
}

static const char *pm_env_text(const char *name, const char *default_value)
{
    const char *value = getenv(name);
    return value == NULL || *value == '\0' ? default_value : value;
}

static int pm_base64url(const uint8_t *data, size_t len, char *out, size_t out_len)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t needed = (len * 8U + 5U) / 6U;
    if (out_len <= needed) return -1;
    size_t input = 0U;
    size_t output = 0U;
    while (input + 3U <= len) {
        uint32_t value = ((uint32_t)data[input] << 16U)
            | ((uint32_t)data[input + 1U] << 8U) | data[input + 2U];
        out[output++] = alphabet[(value >> 18U) & 63U];
        out[output++] = alphabet[(value >> 12U) & 63U];
        out[output++] = alphabet[(value >> 6U) & 63U];
        out[output++] = alphabet[value & 63U];
        input += 3U;
    }
    if (input < len) {
        uint32_t value = (uint32_t)data[input] << 16U;
        out[output++] = alphabet[(value >> 18U) & 63U];
        if (input + 1U < len) {
            value |= (uint32_t)data[input + 1U] << 8U;
            out[output++] = alphabet[(value >> 12U) & 63U];
            out[output++] = alphabet[(value >> 6U) & 63U];
        } else {
            out[output++] = alphabet[(value >> 12U) & 63U];
        }
    }
    out[output] = '\0';
    return 0;
}

static int pm_generate_token(char out[64])
{
    uint8_t random[32];
    return RAND_bytes(random, sizeof(random)) == 1
        && pm_base64url(random, sizeof(random), out, 64U) == 0 ? 0 : -1;
}

static int pm_has_text(const char *value)
{
    if (value == NULL) return 0;
    while (*value != '\0') {
        if (!isspace((unsigned char)*value)) return 1;
        ++value;
    }
    return 0;
}

static int pm_handle_service_report(const st_peer_mesh_runtime *runtime,
                                    const st_storage_client *source,
                                    const st_storage_peer_mesh_device *source_device,
                                    const char *target_client_name,
                                    const char *message);

static int pm_handle_egress_report(const st_peer_mesh_runtime *runtime,
                                   const st_storage_client *source,
                                   const char *target_client_name,
                                   const char *message);

static int pm_append_named_string(pm_builder *builder,
                                  const char *name,
                                  const char *value)
{
    if (!pm_has_text(value)) return 0;
    if (pm_appendf(builder, ",\"%s\":", name) != 0) return -1;
    return pm_append_json_string(builder, value);
}

static int pm_append_input_string(pm_builder *builder,
                                  const char *input,
                                  const char *name)
{
    char *value = st_json_get_top_level_string(input, name);
    int rc = pm_append_named_string(builder, name, value);
    free(value);
    return rc;
}

static int pm_append_input_i64(pm_builder *builder,
                               const char *input,
                               const char *name)
{
    long long value = 0;
    if (st_json_get_i64(input, name, &value) != 0) return 0;
    return pm_appendf(builder, ",\"%s\":%lld", name, value);
}

static char *pm_build_signal(const char *input,
                             const char *type,
                             const st_storage_client *source,
                             const st_storage_peer_mesh_device *source_device,
                             const st_storage_client *target,
                             const st_storage_peer_mesh_device *target_device,
                             const st_storage_peer_mesh_session *opened_session,
                             const char *opened_token)
{
    pm_builder builder = {0};
    if (pm_append(&builder, "{\"type\":") != 0 || pm_append_json_string(&builder, type) != 0
        || pm_appendf(&builder, ",\"sourceClientId\":%lld,\"sourceClientName\":",
                      source->id) != 0
        || pm_append_json_string(&builder, source->client_name) != 0
        || pm_append_named_string(&builder, "sourceVirtualIp", source_device->virtual_ip) != 0
        || pm_append_named_string(&builder, "sourcePublicKey", source_device->public_key) != 0) goto failed;
    if (target != NULL && (pm_appendf(&builder, ",\"targetClientId\":%lld,\"targetClientName\":",
                                     target->id) != 0
                           || pm_append_json_string(&builder, target->client_name) != 0
                           || pm_append_named_string(&builder, "targetVirtualIp", target_device->virtual_ip) != 0
                           || pm_append_named_string(&builder, "targetPublicKey", target_device->public_key) != 0)) goto failed;

    long long session_id = 0;
    if (opened_session != NULL) session_id = opened_session->id;
    else (void)st_json_get_i64(input, "sessionId", &session_id);
    if (session_id > 0 && pm_appendf(&builder, ",\"sessionId\":%lld", session_id) != 0) goto failed;
    if (opened_token != NULL) {
        if (pm_append_named_string(&builder, "token", opened_token) != 0
            || pm_append_named_string(&builder, "expiresAt", opened_session->expires_at) != 0) goto failed;
    } else if (pm_append_input_string(&builder, input, "token") != 0
               || pm_append_input_string(&builder, input, "expiresAt") != 0) goto failed;

    static const char *string_fields[] = {
        "sourceKeyEpoch", "pathType", "status", "localEndpoint", "remoteEndpoint", "reason",
        "virtualDeviceMode", "virtualDeviceName", "virtualDeviceStatus", "virtualDeviceError",
        "natType", "natMappingBehavior", "natFilteringBehavior", "natBehaviorDiscovery", "lastEndpoint"
    };
    for (size_t i = 0; i < sizeof(string_fields) / sizeof(string_fields[0]); ++i) {
        if (pm_append_input_string(&builder, input, string_fields[i]) != 0) goto failed;
    }
    static const char *integer_fields[] = {"rttMillis", "directBytes", "relayBytes"};
    for (size_t i = 0; i < sizeof(integer_fields) / sizeof(integer_fields[0]); ++i) {
        if (pm_append_input_i64(&builder, input, integer_fields[i]) != 0) goto failed;
    }
    char *candidates = st_json_get_top_level_raw(input, "candidates");
    if (candidates != NULL) {
        int rc = pm_append(&builder, ",\"candidates\":") == 0 ? pm_append(&builder, candidates) : -1;
        free(candidates);
        if (rc != 0) goto failed;
    }
    long long created = 0;
    if (st_json_get_i64(input, "createdAtMillis", &created) != 0 || created <= 0) {
        created = (long long)time(NULL) * 1000LL;
    }
    int data_frame_version = 2;
    (void)st_json_get_int(input, "dataFrameVersion", &data_frame_version);
    if (data_frame_version <= 0) data_frame_version = 2;
    if (pm_appendf(&builder, ",\"dataFrameVersion\":%d,\"createdAtMillis\":%lld}",
                   data_frame_version, created) != 0) goto failed;
    return builder.data;

failed:
    free(builder.data);
    return NULL;
}

static char *pm_build_grant(const st_storage_client *source,
                            const st_storage_peer_mesh_device *source_device,
                            const st_storage_client *target,
                            const st_storage_peer_mesh_device *target_device,
                            const st_storage_peer_mesh_session *session,
                            const char *token)
{
    pm_builder builder = {0};
    if (pm_appendf(&builder,
                   "{\"type\":\"session-grant\",\"sessionId\":%lld,\"sourceClientId\":%lld,\"sourceClientName\":",
                   session->id, source->id) != 0
        || pm_append_json_string(&builder, source->client_name) != 0
        || pm_append_named_string(&builder, "sourceVirtualIp", source_device->virtual_ip) != 0
        || pm_append_named_string(&builder, "sourcePublicKey", source_device->public_key) != 0
        || pm_appendf(&builder, ",\"targetClientId\":%lld,\"targetClientName\":", target->id) != 0
        || pm_append_json_string(&builder, target->client_name) != 0
        || pm_append_named_string(&builder, "targetVirtualIp", target_device->virtual_ip) != 0
        || pm_append_named_string(&builder, "targetPublicKey", target_device->public_key) != 0
        || pm_append_named_string(&builder, "token", token) != 0
        || pm_append_named_string(&builder, "expiresAt", session->expires_at) != 0
        || pm_append_named_string(&builder, "pathType", session->path_type) != 0
        || pm_append_named_string(&builder, "status", session->status) != 0
        || pm_appendf(&builder, ",\"dataFrameVersion\":2,\"createdAtMillis\":%lld}",
                      (long long)time(NULL) * 1000LL) != 0) {
        free(builder.data);
        return NULL;
    }
    return builder.data;
}

static int pm_handle_report(const st_peer_mesh_runtime *runtime,
                            const st_storage_client *source,
                            const char *type,
                            const char *message)
{
    if (strcmp(type, "device-report") == 0) {
        char *nat_type = st_json_get_top_level_string(message, "natType");
        char *nat_mapping = st_json_get_top_level_string(message, "natMappingBehavior");
        char *nat_filtering = st_json_get_top_level_string(message, "natFilteringBehavior");
        char *nat_discovery = st_json_get_top_level_string(message, "natBehaviorDiscovery");
        char *last_endpoint = st_json_get_top_level_string(message, "lastEndpoint");
        char *mode = st_json_get_top_level_string(message, "virtualDeviceMode");
        char *name = st_json_get_top_level_string(message, "virtualDeviceName");
        char *status = st_json_get_top_level_string(message, "virtualDeviceStatus");
        char *error = st_json_get_top_level_string(message, "virtualDeviceError");
        int rc = st_storage_update_peer_mesh_device_report(runtime->database_path, source, NULL,
            nat_type, nat_mapping, nat_filtering, nat_discovery, last_endpoint,
            mode, name, status, error, NULL);
        free(nat_type); free(nat_mapping); free(nat_filtering); free(nat_discovery);
        free(last_endpoint); free(mode); free(name); free(status); free(error);
        return rc;
    }
    long long session_id = 0;
    if (st_json_get_i64(message, "sessionId", &session_id) != 0 || session_id <= 0) return -1;
    char *path_type = st_json_get_top_level_string(message, "pathType");
    char *status = st_json_get_top_level_string(message, "status");
    char *local = st_json_get_top_level_string(message, "localEndpoint");
    char *remote = st_json_get_top_level_string(message, "remoteEndpoint");
    long long rtt = -1;
    long long direct = 0;
    long long relay = 0;
    (void)st_json_get_i64(message, "rttMillis", &rtt);
    (void)st_json_get_i64(message, "directBytes", &direct);
    (void)st_json_get_i64(message, "relayBytes", &relay);
    int close_session = strcmp(type, "close") == 0;
    if (strcmp(type, "path-report") == 0 && !pm_has_text(status)) {
        free(status);
        status = strdup("ACTIVE");
    }
    if (strcmp(type, "traffic-report") == 0) {
        free(path_type);
        path_type = strdup(relay > 0 ? "RELAY" : (direct > 0 ? "DIRECT" : ""));
    }
    int rc = st_storage_report_peer_mesh_session(runtime->database_path, source, session_id,
        path_type, status, rtt, local, remote, direct, relay, close_session, NULL);
    free(path_type); free(status); free(local); free(remote);
    return rc;
}

int st_peer_mesh_handle_control(const st_peer_mesh_runtime *runtime,
                                const char *authenticated_client_name,
                                const char *target_client_name,
                                const char *message)
{
    if (runtime == NULL || runtime->database_path == NULL || runtime->send == NULL
        || !pm_env_bool("SPECUS_PEER_MESH_ENABLED", 0)
        || !pm_has_text(authenticated_client_name) || !st_json_is_valid_object(message)) return -1;
    char *type = st_json_get_top_level_string(message, "type");
    if (!pm_has_text(type) || strcmp(type, "service-catalog") == 0
        || strcmp(type, "egress-config") == 0 || strcmp(type, "egress-catalog") == 0) {
        free(type);
        return -1;
    }
    st_storage_client source;
    st_storage_peer_mesh_device source_device;
    if (st_storage_get_client_by_name(runtime->database_path, authenticated_client_name, &source) != 0
        || !source.enabled
        || st_storage_ensure_peer_mesh_device(runtime->database_path, &source, &source_device) != 0) {
        free(type);
        return -1;
    }
    if (strcmp(type, "service-report") == 0) {
        int rc = pm_handle_service_report(runtime, &source, &source_device,
                                          target_client_name, message);
        free(type);
        return rc;
    }
    if (strcmp(type, "egress-report") == 0) {
        int rc = pm_handle_egress_report(runtime, &source, target_client_name, message);
        free(type);
        return rc;
    }
    if (strcmp(type, "path-report") == 0 || strcmp(type, "traffic-report") == 0
        || strcmp(type, "device-report") == 0) {
        int rc = pm_handle_report(runtime, &source, type, message);
        free(type);
        return rc;
    }
    if (strcmp(type, "close") == 0) {
        if (pm_handle_report(runtime, &source, type, message) != 0) {
            free(type);
            return -1;
        }
        if (!pm_has_text(target_client_name)) {
            free(type);
            return 0;
        }
    }
    if (!pm_has_text(target_client_name)) {
        free(type);
        return -1;
    }
    st_storage_client target;
    st_storage_peer_mesh_device target_device;
    int allowed = 0;
    if (st_storage_get_client_by_name(runtime->database_path, target_client_name, &target) != 0
        || st_storage_can_peer(runtime->database_path, &source, &target, &allowed) != 0 || !allowed
        || st_storage_get_peer_mesh_device_by_client(runtime->database_path, target.tenant_id,
                                                      target.id, &target_device) != 0
        || (runtime->online != NULL && !runtime->online(runtime->ctx, target.id, target.client_name))) {
        free(type);
        return -1;
    }

    st_storage_peer_mesh_session opened;
    st_storage_peer_mesh_session *opened_ptr = NULL;
    char token[64];
    const char *token_ptr = NULL;
    long long existing_session_id = 0;
    int opens = (strcmp(type, "candidates") == 0 || strcmp(type, "offer") == 0)
        && st_json_get_i64(message, "sessionId", &existing_session_id) != 0;
    if (opens) {
        uint8_t token_hash_bytes[ST_SHA256_LEN];
        char token_hash[ST_SHA256_HEX_LEN + 1U];
        long long ttl = pm_env_i64("SPECUS_PEER_MESH_SESSION_TTL_SECONDS", 3600);
        if (ttl <= 0) ttl = 3600;
        if (pm_generate_token(token) != 0) {
            free(type);
            return -1;
        }
        st_sha256((const uint8_t *)token, strlen(token), token_hash_bytes);
        st_hex_encode(token_hash_bytes, sizeof(token_hash_bytes), token_hash);
        if (st_storage_create_peer_mesh_session(runtime->database_path, &source, &target,
                                                "DIRECT", token_hash, ttl, &opened) != 0) {
            free(type);
            return -1;
        }
        opened_ptr = &opened;
        token_ptr = token;
        char *grant = pm_build_grant(&source, &source_device, &target, &target_device, &opened, token);
        if (grant == NULL || runtime->send(runtime->ctx, source.client_name, "server", grant) != 0) {
            free(grant);
            free(type);
            return -1;
        }
        free(grant);
    }
    char *forwarded = pm_build_signal(message, type, &source, &source_device,
                                      &target, &target_device, opened_ptr, token_ptr);
    int rc = forwarded != NULL
        ? runtime->send(runtime->ctx, target.client_name, source.client_name, forwarded) : -1;
    free(forwarded);
    free(type);
    return rc;
}

static int pm_append_public_stun_servers(pm_builder *builder)
{
    const char *configured = getenv("SPECUS_PEER_MESH_PUBLIC_STUN_SERVERS");
    if (pm_append(builder, "[") != 0) return -1;
    if (configured != NULL && *configured != '\0') {
        char *copy = strdup(configured);
        if (copy == NULL) return -1;
        char *save = NULL;
        int first = 1;
        for (char *item = strtok_r(copy, ",", &save); item != NULL; item = strtok_r(NULL, ",", &save)) {
            while (isspace((unsigned char)*item)) ++item;
            if (*item == '\0') continue;
            if ((!first && pm_append(builder, ",") != 0) || pm_append_json_string(builder, item) != 0) {
                free(copy);
                return -1;
            }
            first = 0;
        }
        free(copy);
    }
    return pm_append(builder, "]");
}

static int pm_service_allows_client(const st_storage_peer_mesh_service *service,
                                    long long client_id)
{
    if (service->allowed_client_ids[0] == '\0') return 1;
    char copy[sizeof(service->allowed_client_ids)];
    snprintf(copy, sizeof(copy), "%s", service->allowed_client_ids);
    char *save = NULL;
    for (char *part = strtok_r(copy, ",", &save); part != NULL;
         part = strtok_r(NULL, ",", &save)) {
        char *end = NULL;
        long long value = strtoll(part, &end, 10);
        if (end != part && *end == '\0' && value == client_id) return 1;
    }
    return 0;
}

static int pm_append_allowed_peer_ips(pm_builder *builder,
                                      const char *database_path,
                                      const st_storage_client *publisher,
                                      const st_storage_peer_mesh_service *service)
{
    if (pm_append(builder, "[") != 0) return -1;
    if (!service->enabled) return pm_append(builder, "]");
    st_storage_client clients[256];
    size_t count = 0U;
    if (st_storage_list_clients(database_path, clients, 256U, &count) != 0) return -1;
    int first = 1;
    for (size_t i = 0; i < count; ++i) {
        st_storage_client *recipient = &clients[i];
        int allowed = 0;
        if (recipient->id == publisher->id
            || strcmp(recipient->tenant_id, publisher->tenant_id) != 0
            || !recipient->enabled
            || st_storage_can_peer(database_path, publisher, recipient, &allowed) != 0
            || !allowed
            || (strcmp(service->visibility, "OWNER") == 0
                && strcmp(recipient->owner_username, publisher->owner_username) != 0)
            || (strcmp(service->visibility, "OWNER") != 0
                && !pm_service_allows_client(service, recipient->id))) continue;
        st_storage_peer_mesh_device device;
        if (st_storage_get_peer_mesh_device_by_client(database_path, publisher->tenant_id,
                                                       recipient->id, &device) != 0
            || !device.enabled || device.virtual_ip[0] == '\0') continue;
        if ((!first && pm_append(builder, ",") != 0)
            || pm_append_json_string(builder, device.virtual_ip) != 0) return -1;
        first = 0;
    }
    return pm_append(builder, "]");
}

static int pm_append_local_services(pm_builder *builder,
                                    const char *database_path,
                                    const st_storage_client *client)
{
    if (pm_append(builder, "[") != 0) return -1;
    st_storage_peer_mesh_service services[256];
    size_t count = 0U;
    if (st_storage_list_peer_mesh_services_visible(database_path, client->tenant_id, "", 1,
                                                    services, 256U, &count) != 0) return -1;
    int first = 1;
    for (size_t i = 0; i < count; ++i) {
        const st_storage_peer_mesh_service *service = &services[i];
        if (service->client_id != client->id) continue;
        if ((!first && pm_append(builder, ",") != 0)
            || pm_append(builder, "{\"serviceId\":") != 0
            || pm_append_json_string(builder, service->service_id) != 0
            || pm_append(builder, ",\"name\":") != 0
            || pm_append_json_string(builder, service->name) != 0
            || pm_append(builder, ",\"description\":") != 0
            || pm_append_json_string(builder, service->description) != 0
            || pm_append(builder, ",\"transport\":") != 0
            || pm_append_json_string(builder, service->transport) != 0
            || pm_append(builder, ",\"application\":") != 0
            || pm_append_json_string(builder, service->application) != 0
            || pm_append(builder, ",\"targetHost\":") != 0
            || pm_append_json_string(builder, service->target_host) != 0
            || pm_appendf(builder, ",\"targetPort\":%d,\"publishedPort\":%d,\"path\":",
                          service->target_port, service->published_port) != 0
            || pm_append_json_string(builder, service->path) != 0
            || pm_appendf(builder, ",\"enabled\":%s,\"visibility\":",
                          service->enabled ? "true" : "false") != 0
            || pm_append_json_string(builder, service->visibility) != 0
            || pm_append(builder, ",\"allowedPeerVirtualIps\":") != 0
            || pm_append_allowed_peer_ips(builder, database_path, client, service) != 0
            || pm_append(builder, "}") != 0) return -1;
        first = 0;
    }
    return pm_append(builder, "]");
}

static int pm_top_level_has(const char *json, const char *field)
{
    char *raw = st_json_get_top_level_raw(json, field);
    int present = raw != NULL;
    free(raw);
    return present;
}

static int pm_service_id_valid(const char *value)
{
    size_t len = value == NULL ? 0U : strlen(value);
    if (len < 8U || len > 64U) return 0;
    for (const unsigned char *p = (const unsigned char *)value; *p != '\0'; ++p) {
        if (!isalnum(*p) && *p != '.' && *p != '_' && *p != '-') return 0;
    }
    return 1;
}

static int pm_instance_id_valid(const char *value)
{
    if (!pm_has_text(value)) return 1;
    size_t len = strlen(value);
    if (len > 64U) return 0;
    for (const unsigned char *p = (const unsigned char *)value; *p != '\0'; ++p) {
        if (!isalnum(*p) && *p != '.' && *p != '_' && *p != '-') return 0;
    }
    return 1;
}

static int pm_report_collection_count(const char *message,
                                      const char *field,
                                      size_t limit)
{
    char *raw = st_json_get_top_level_raw(message, field);
    if (raw == NULL) return 0;
    int array = raw[0] == '[';
    free(raw);
    if (!array) return -1;
    char **items = NULL;
    size_t count = 0U;
    int rc = st_json_get_raw_array(message, field, &items, &count) == 0 && count <= limit ? 0 : -1;
    st_json_free_string_array(items, count);
    return rc;
}

static int pm_read_report_services(const char *message, pm_catalog *catalog)
{
    char *raw = st_json_get_top_level_raw(message, "services");
    if (raw == NULL) {
        catalog->service_count = 0U;
        return 0;
    }
    int array = raw[0] == '[';
    free(raw);
    if (!array) return -1;
    char **items = NULL;
    size_t count = 0U;
    if (st_json_get_raw_array(message, "services", &items, &count) != 0
        || count > ST_PEER_MESH_MAX_CATALOG_SERVICES) {
        st_json_free_string_array(items, count);
        return -1;
    }
    int ports[ST_PEER_MESH_MAX_CATALOG_SERVICES];
    for (size_t i = 0; i < count; ++i) {
        char *service_id = st_json_get_top_level_string(items[i], "serviceId");
        char *name = st_json_get_top_level_string(items[i], "name");
        char *description = st_json_get_top_level_string(items[i], "description");
        char *transport = st_json_get_top_level_string(items[i], "transport");
        char *application = st_json_get_top_level_string(items[i], "application");
        char *path = st_json_get_top_level_string(items[i], "path");
        int published_port = 0;
        int app_ok = application != NULL
            && (strcmp(application, "http") == 0 || strcmp(application, "https") == 0
                || strcmp(application, "ssh") == 0 || strcmp(application, "tcp") == 0
                || strcmp(application, "udp") == 0);
        int transport_ok = transport != NULL
            && ((strcmp(application == NULL ? "" : application, "udp") == 0
                 && strcmp(transport, "udp") == 0)
                || (strcmp(application == NULL ? "" : application, "udp") != 0
                    && strcmp(transport, "tcp") == 0));
        int valid = st_json_is_valid_object(items[i]) && pm_service_id_valid(service_id)
            && pm_has_text(name) && strlen(name) <= 80U
            && (description == NULL || strlen(description) <= 200U)
            && app_ok && transport_ok
            && st_json_get_int(items[i], "publishedPort", &published_port) == 0
            && published_port >= 1 && published_port <= 65535
            && (path == NULL || (path[0] == '/' && strlen(path) <= 128U
                                 && strstr(path, "..") == NULL));
        for (size_t j = 0; valid && j < i; ++j) {
            if (strcmp(catalog->service_ids[j], service_id) == 0 || ports[j] == published_port) valid = 0;
        }
        if (valid) {
            snprintf(catalog->service_ids[i], sizeof(catalog->service_ids[i]), "%s", service_id);
            ports[i] = published_port;
        }
        free(service_id); free(name); free(description); free(transport); free(application); free(path);
        if (!valid) {
            st_json_free_string_array(items, count);
            return -1;
        }
    }
    st_json_free_string_array(items, count);
    catalog->service_count = count;
    return 0;
}

static int pm_catalog_has_service(const pm_catalog *catalog, const char *service_id);

static int pm_read_report_stats(const char *message, pm_catalog *catalog)
{
    char **items = NULL;
    size_t count = 0U;
    char *raw = st_json_get_top_level_raw(message, "stats");
    if (raw == NULL) return 0;
    int array = raw[0] == '[';
    free(raw);
    if (!array || st_json_get_raw_array(message, "stats", &items, &count) != 0) return -1;
    for (size_t i = 0; i < count && catalog->stats_count < ST_PEER_MESH_MAX_CATALOG_SERVICES; ++i) {
        char *service_id = st_json_get_top_level_string(items[i], "serviceId");
        if (service_id != NULL && pm_catalog_has_service(catalog, service_id)) {
            pm_service_stats *stats = &catalog->stats[catalog->stats_count++];
            snprintf(stats->service_id, sizeof(stats->service_id), "%s", service_id);
            (void)st_json_get_i64(items[i], "bytesIn", &stats->bytes_in);
            (void)st_json_get_i64(items[i], "bytesOut", &stats->bytes_out);
            (void)st_json_get_int(items[i], "activeConnections", &stats->active_connections);
            (void)st_json_get_i64(items[i], "totalConnections", &stats->total_connections);
            if (stats->bytes_in < 0) stats->bytes_in = 0;
            if (stats->bytes_out < 0) stats->bytes_out = 0;
            if (stats->active_connections < 0) stats->active_connections = 0;
            if (stats->total_connections < 0) stats->total_connections = 0;
        }
        free(service_id);
    }
    st_json_free_string_array(items, count);
    return 0;
}

static void pm_trim_lower(const char *value, char *out, size_t out_len)
{
    if (out_len == 0U) return;
    const char *start = value == NULL ? "" : value;
    while (isspace((unsigned char)*start)) ++start;
    const char *end = start + strlen(start);
    while (end > start && isspace((unsigned char)end[-1])) --end;
    size_t len = (size_t)(end - start);
    if (len >= out_len) len = out_len - 1U;
    for (size_t i = 0; i < len; ++i) out[i] = (char)tolower((unsigned char)start[i]);
    out[len] = '\0';
}

static int pm_normalize_local_host(const char *value, char out[256])
{
    char host[256];
    const char *start = value == NULL ? "" : value;
    while (isspace((unsigned char)*start)) ++start;
    const char *end = start + strlen(start);
    while (end > start && isspace((unsigned char)end[-1])) --end;
    if (end == start || (size_t)(end - start) >= sizeof(host)) return -1;
    memcpy(host, start, (size_t)(end - start));
    host[end - start] = '\0';
    if (host[0] == '[' && end - start > 2 && host[end - start - 1] == ']') {
        memmove(host, host + 1, (size_t)(end - start - 2));
        host[end - start - 2] = '\0';
    }
    if (strcasecmp(host, "localhost") == 0) {
        snprintf(out, 256U, "127.0.0.1");
        return 0;
    }
    struct in_addr ipv4;
    if (inet_pton(AF_INET, host, &ipv4) == 1) {
        uint32_t address = ntohl(ipv4.s_addr);
        int local = (address >> 24U) == 127U || (address >> 24U) == 10U
            || (address >> 20U) == 0xAC1U || (address >> 16U) == 0xC0A8U
            || (address >> 16U) == 0xA9FEU;
        if (!local || address == 0U || (address >> 28U) == 0xEU) return -1;
        return inet_ntop(AF_INET, &ipv4, out, 256U) == NULL ? -1 : 0;
    }
    struct in6_addr ipv6;
    if (inet_pton(AF_INET6, host, &ipv6) != 1) return -1;
    const unsigned char *bytes = ipv6.s6_addr;
    int loopback = IN6_IS_ADDR_LOOPBACK(&ipv6);
    int link_local = bytes[0] == 0xfeU && (bytes[1] & 0xc0U) == 0x80U;
    int unique_local = (bytes[0] & 0xfeU) == 0xfcU;
    if ((!loopback && !link_local && !unique_local) || IN6_IS_ADDR_UNSPECIFIED(&ipv6)
        || IN6_IS_ADDR_MULTICAST(&ipv6)) return -1;
    return inet_ntop(AF_INET6, &ipv6, out, 256U) == NULL ? -1 : 0;
}

static int pm_read_mdns_candidates(const char *message,
                                   st_peer_mesh_mdns_candidate out[32],
                                   size_t *out_count)
{
    *out_count = 0U;
    char *raw = st_json_get_top_level_raw(message, "mdnsCandidates");
    if (raw == NULL) return 0;
    int array = raw[0] == '[';
    free(raw);
    char **items = NULL;
    size_t count = 0U;
    if (!array || st_json_get_raw_array(message, "mdnsCandidates", &items, &count) != 0) return -1;
    for (size_t i = 0; i < count && *out_count < 32U; ++i) {
        char *name = st_json_get_top_level_string(items[i], "name");
        char *transport = st_json_get_top_level_string(items[i], "transport");
        char *application = st_json_get_top_level_string(items[i], "application");
        char *target_host = st_json_get_top_level_string(items[i], "targetHost");
        int target_port = 0;
        char normalized_application[8];
        char normalized_transport[8];
        pm_trim_lower(application, normalized_application, sizeof(normalized_application));
        pm_trim_lower(transport, normalized_transport, sizeof(normalized_transport));
        if (normalized_transport[0] == '\0') {
            snprintf(normalized_transport, sizeof(normalized_transport), "%s",
                     strcmp(normalized_application, "udp") == 0 ? "udp" : "tcp");
        }
        char normalized_host[256];
        int app_ok = strcmp(normalized_application, "http") == 0
            || strcmp(normalized_application, "https") == 0
            || strcmp(normalized_application, "ssh") == 0
            || strcmp(normalized_application, "tcp") == 0
            || strcmp(normalized_application, "udp") == 0;
        int transport_ok = strcmp(normalized_application, "udp") == 0
            ? strcmp(normalized_transport, "udp") == 0
            : strcmp(normalized_transport, "tcp") == 0;
        int name_ok = pm_has_text(name) && strlen(name) <= 80U;
        for (const char *cursor = name; name_ok && cursor != NULL && *cursor != '\0'; ++cursor) {
            if ((unsigned char)*cursor < 32U) name_ok = 0;
        }
        int valid = st_json_is_valid_object(items[i]) && name_ok && app_ok && transport_ok
            && st_json_get_int(items[i], "targetPort", &target_port) == 0
            && target_port >= 1 && target_port <= 65535
            && pm_normalize_local_host(target_host, normalized_host) == 0;
        for (size_t j = 0; valid && j < *out_count; ++j) {
            if (out[j].target_port == target_port
                && strcmp(out[j].target_host, normalized_host) == 0
                && strcmp(out[j].application, normalized_application) == 0) valid = 0;
        }
        if (valid) {
            st_peer_mesh_mdns_candidate *candidate = &out[(*out_count)++];
            snprintf(candidate->name, sizeof(candidate->name), "%s", name);
            snprintf(candidate->transport, sizeof(candidate->transport), "%s", normalized_transport);
            snprintf(candidate->application, sizeof(candidate->application), "%s", normalized_application);
            snprintf(candidate->target_host, sizeof(candidate->target_host), "%s", normalized_host);
            candidate->target_port = target_port;
        }
        free(name); free(transport); free(application); free(target_host);
    }
    st_json_free_string_array(items, count);
    return 0;
}

static int pm_catalog_has_service(const pm_catalog *catalog, const char *service_id)
{
    for (size_t i = 0; i < catalog->service_count; ++i) {
        if (strcmp(catalog->service_ids[i], service_id) == 0) return 1;
    }
    return 0;
}

static int pm_has_authorized_online_peer(const st_peer_mesh_runtime *runtime,
                                         const st_storage_client *publisher)
{
    st_storage_client clients[ST_PEER_MESH_MAX_CLIENTS];
    size_t count = 0U;
    if (st_storage_list_clients(runtime->database_path, clients,
                                ST_PEER_MESH_MAX_CLIENTS, &count) != 0) return 0;
    for (size_t i = 0; i < count; ++i) {
        int allowed = 0;
        if (clients[i].id != publisher->id
            && strcmp(clients[i].tenant_id, publisher->tenant_id) == 0
            && clients[i].enabled
            && st_storage_can_peer(runtime->database_path, publisher, &clients[i], &allowed) == 0
            && allowed
            && runtime->online != NULL
            && runtime->online(runtime->ctx, clients[i].id, clients[i].client_name)) return 1;
    }
    return 0;
}

static int pm_catalog_service_visible(const st_storage_client *publisher,
                                      const st_storage_client *recipient,
                                      const st_storage_peer_mesh_service *service)
{
    return service->enabled
        && (strcmp(service->visibility, "OWNER") == 0
            ? strcmp(publisher->owner_username, recipient->owner_username) == 0
            : pm_service_allows_client(service, recipient->id));
}

static int pm_append_advertised_service(pm_builder *builder,
                                        const st_storage_peer_mesh_service *service)
{
    return pm_append(builder, "{\"serviceId\":") == 0
        && pm_append_json_string(builder, service->service_id) == 0
        && pm_append(builder, ",\"name\":") == 0
        && pm_append_json_string(builder, service->name) == 0
        && pm_append(builder, ",\"description\":") == 0
        && pm_append_json_string(builder, service->description) == 0
        && pm_append(builder, ",\"transport\":") == 0
        && pm_append_json_string(builder, service->transport) == 0
        && pm_append(builder, ",\"application\":") == 0
        && pm_append_json_string(builder, service->application) == 0
        && pm_appendf(builder, ",\"publishedPort\":%d,\"path\":", service->published_port) == 0
        && pm_append_json_string(builder, service->path) == 0
        && pm_append(builder, "}") == 0 ? 0 : -1;
}

static void pm_format_instant(time_t value, char out[32])
{
    struct tm utc;
    if (gmtime_r(&value, &utc) == NULL
        || strftime(out, 32U, "%Y-%m-%dT%H:%M:%SZ", &utc) == 0U) out[0] = '\0';
}

static char *pm_build_catalog_message(const st_peer_mesh_runtime *runtime,
                                      const pm_catalog *catalog,
                                      const st_storage_client *publisher,
                                      const st_storage_client *recipient,
                                      int authorized)
{
    char expires_at[32];
    pm_format_instant(catalog->expires_at, expires_at);
    pm_builder builder = {0};
    if (pm_appendf(&builder,
                   "{\"type\":\"service-catalog\",\"publisherClientId\":%lld,\"publisherClientName\":",
                   catalog->publisher_client_id) != 0
        || pm_append_json_string(&builder, catalog->publisher_client_name) != 0
        || pm_appendf(&builder, ",\"publisherSessionId\":%lld,\"revision\":%lld,\"expiresAt\":",
                      catalog->publisher_session_id, catalog->catalog_revision) != 0
        || pm_append_json_string(&builder, expires_at) != 0
        || pm_append(&builder, ",\"services\":[") != 0) goto failed;
    st_storage_peer_mesh_service definitions[256];
    size_t count = 0U;
    if (authorized && catalog->active
        && st_storage_list_peer_mesh_services_visible(runtime->database_path, publisher->tenant_id,
                                                       "", 1, definitions, 256U, &count) != 0) goto failed;
    int first = 1;
    for (size_t i = 0; authorized && catalog->active && i < count; ++i) {
        st_storage_peer_mesh_service *service = &definitions[i];
        if (service->client_id != publisher->id
            || !pm_catalog_has_service(catalog, service->service_id)
            || !pm_catalog_service_visible(publisher, recipient, service)) continue;
        if ((!first && pm_append(&builder, ",") != 0)
            || pm_append_advertised_service(&builder, service) != 0) goto failed;
        first = 0;
    }
    if (pm_appendf(&builder, "],\"createdAtMillis\":%lld}",
                   (long long)time(NULL) * 1000LL) != 0) goto failed;
    return builder.data;
failed:
    free(builder.data);
    return NULL;
}

static int pm_fanout_catalog(const st_peer_mesh_runtime *runtime,
                             const pm_catalog *catalog,
                             const st_storage_client *publisher)
{
    st_storage_client clients[ST_PEER_MESH_MAX_CLIENTS];
    size_t count = 0U;
    if (st_storage_list_clients(runtime->database_path, clients,
                                ST_PEER_MESH_MAX_CLIENTS, &count) != 0) return -1;
    int rc = 0;
    for (size_t i = 0; i < count; ++i) {
        st_storage_client *recipient = &clients[i];
        if (recipient->id == publisher->id
            || strcmp(recipient->tenant_id, publisher->tenant_id) != 0
            || runtime->online == NULL
            || !runtime->online(runtime->ctx, recipient->id, recipient->client_name)) continue;
        int allowed = 0;
        if (st_storage_can_peer(runtime->database_path, publisher, recipient, &allowed) != 0) {
            rc = -1;
            continue;
        }
        char *message = pm_build_catalog_message(runtime, catalog, publisher, recipient, allowed);
        if (message == NULL
            || runtime->send(runtime->ctx, recipient->client_name, "server", message) != 0) rc = -1;
        free(message);
    }
    return rc;
}

static pm_catalog *pm_find_or_allocate_catalog_locked(const st_storage_client *source,
                                                       long long session_id,
                                                       time_t now)
{
    pm_catalog *free_slot = NULL;
    for (size_t i = 0; i < ST_PEER_MESH_MAX_CATALOGS; ++i) {
        pm_catalog *catalog = &peer_catalogs[i];
        if (catalog->in_use
            && catalog->publisher_client_id == source->id
            && catalog->publisher_session_id == session_id
            && strcmp(catalog->tenant_id, source->tenant_id) == 0) return catalog;
        if (!catalog->in_use || catalog->expires_at < now) free_slot = catalog;
    }
    if (free_slot != NULL) {
        free(free_slot->mdns_candidates);
        memset(free_slot, 0, sizeof(*free_slot));
        free_slot->in_use = 1;
        snprintf(free_slot->tenant_id, sizeof(free_slot->tenant_id), "%s", source->tenant_id);
        free_slot->publisher_client_id = source->id;
        snprintf(free_slot->publisher_client_name, sizeof(free_slot->publisher_client_name),
                 "%s", source->client_name);
        free_slot->publisher_session_id = session_id;
    }
    return free_slot;
}

static int pm_handle_service_report(const st_peer_mesh_runtime *runtime,
                                    const st_storage_client *source,
                                    const st_storage_peer_mesh_device *source_device,
                                    const char *target_client_name,
                                    const char *message)
{
    static const char *server_fields[] = {
        "sourceClientId", "sourceClientName", "sourceVirtualIp", "sourcePublicKey", "sourceKeyEpoch",
        "targetClientId", "targetClientName", "targetVirtualIp", "targetPublicKey", "sessionId", "token",
        "publisherClientId", "publisherClientName", "publisherSessionId"
    };
    if (strlen(message) > 16U * 1024U || pm_has_text(target_client_name)
        || runtime->publisher_session_id <= 0
        || runtime->peer_service_discovery_version < 2) return -1;
    for (size_t i = 0; i < sizeof(server_fields) / sizeof(server_fields[0]); ++i) {
        if (pm_top_level_has(message, server_fields[i])) return -1;
    }
    long long revision = 0;
    int report_enabled = 0;
    char *instance_id = st_json_get_top_level_string(message, "instanceId");
    pm_catalog incoming;
    st_peer_mesh_mdns_candidate incoming_mdns[32];
    size_t incoming_mdns_count = 0U;
    memset(&incoming, 0, sizeof(incoming));
    int valid = st_json_get_i64(message, "revision", &revision) == 0 && revision >= 1
        && (st_json_get_bool(message, "enabled", &report_enabled) == 0 || !pm_top_level_has(message, "enabled"))
        && pm_instance_id_valid(instance_id)
        && pm_read_report_services(message, &incoming) == 0
        && pm_report_collection_count(message, "stats", 32U) == 0
        && pm_report_collection_count(message, "mdnsCandidates", 32U) == 0;
    if (valid && (pm_read_report_stats(message, &incoming) != 0
        || pm_read_mdns_candidates(message, incoming_mdns, &incoming_mdns_count) != 0)) valid = 0;
    if (!valid) {
        free(instance_id);
        return -1;
    }
    st_storage_peer_mesh_service_sharing sharing = {0};
    int sharing_enabled = st_storage_get_peer_mesh_service_sharing(runtime->database_path,
        source->tenant_id, &sharing) == 0 && sharing.enabled && source_device->enabled;
    int active = report_enabled && sharing_enabled && pm_has_authorized_online_peer(runtime, source);
    st_peer_mesh_mdns_candidate *mdns_copy = NULL;
    if (active && sharing.mdns_import_enabled && incoming_mdns_count > 0U) {
        mdns_copy = (st_peer_mesh_mdns_candidate *)calloc(incoming_mdns_count,
                                                           sizeof(*mdns_copy));
        if (mdns_copy == NULL) {
            free(instance_id);
            return -1;
        }
        memcpy(mdns_copy, incoming_mdns, incoming_mdns_count * sizeof(*mdns_copy));
    }
    time_t now = time(NULL);
    pm_catalog snapshot;
    pthread_mutex_lock(&peer_catalog_lock);
    pm_catalog *catalog = pm_find_or_allocate_catalog_locked(source, runtime->publisher_session_id, now);
    if (catalog == NULL) {
        pthread_mutex_unlock(&peer_catalog_lock);
        free(mdns_copy);
        free(instance_id);
        return -1;
    }
    if (catalog->rate_window_started_at == 0 || now - catalog->rate_window_started_at >= 60) {
        catalog->rate_window_started_at = now;
        catalog->rate_count = 0U;
    }
    if (catalog->rate_count >= 20U) {
        pthread_mutex_unlock(&peer_catalog_lock);
        free(mdns_copy);
        free(instance_id);
        (void)st_storage_record_peer_mesh_service_audit(runtime->database_path,
            "service-report", source->tenant_id, source->id,
            runtime->publisher_session_id, NULL, "rate-limited");
        return -1;
    }
    ++catalog->rate_count;
    if (revision <= catalog->report_revision) {
        pthread_mutex_unlock(&peer_catalog_lock);
        free(mdns_copy);
        free(instance_id);
        (void)st_storage_record_peer_mesh_service_audit(runtime->database_path,
            "service-report", source->tenant_id, source->id,
            runtime->publisher_session_id, NULL, "ignored-revision");
        return 0;
    }
    catalog->catalog_revision = revision > catalog->catalog_revision
        ? revision : catalog->catalog_revision + 1LL;
    catalog->report_revision = revision;
    catalog->active = active;
    catalog->generated_at = now;
    long long catalog_ttl = pm_env_i64("SPECUS_PEER_MESH_CATALOG_TTL_SECONDS",
                                       ST_PEER_MESH_CATALOG_TTL_SECONDS);
    if (catalog_ttl < 1 || catalog_ttl > 86400) catalog_ttl = ST_PEER_MESH_CATALOG_TTL_SECONDS;
    catalog->expires_at = now + (time_t)catalog_ttl;
    snprintf(catalog->instance_id, sizeof(catalog->instance_id), "%s", instance_id == NULL ? "" : instance_id);
    catalog->service_count = incoming.service_count;
    memcpy(catalog->service_ids, incoming.service_ids, sizeof(catalog->service_ids));
    catalog->stats_count = incoming.stats_count;
    memcpy(catalog->stats, incoming.stats, sizeof(catalog->stats));
    free(catalog->mdns_candidates);
    catalog->mdns_candidates = mdns_copy;
    catalog->mdns_count = mdns_copy == NULL ? 0U : incoming_mdns_count;
    snapshot = *catalog;
    pthread_mutex_unlock(&peer_catalog_lock);
    free(instance_id);
    const char *reason = active ? (snapshot.service_count == 0U ? "empty" : "published")
        : (!report_enabled || !sharing_enabled ? "withdrawn" : "no-authorized-peer");
    (void)st_storage_record_peer_mesh_service_audit(runtime->database_path,
        "service-report", source->tenant_id, source->id,
        runtime->publisher_session_id, NULL, reason);
    return pm_fanout_catalog(runtime, &snapshot, source);
}

static int pm_replay_catalogs(const st_peer_mesh_runtime *runtime,
                              const st_storage_client *recipient)
{
    pm_catalog *snapshots = (pm_catalog *)calloc(ST_PEER_MESH_MAX_CATALOGS,
                                                 sizeof(*snapshots));
    if (snapshots == NULL) return -1;
    size_t count = 0U;
    time_t now = time(NULL);
    pthread_mutex_lock(&peer_catalog_lock);
    for (size_t i = 0; i < ST_PEER_MESH_MAX_CATALOGS; ++i) {
        pm_catalog *catalog = &peer_catalogs[i];
        if (!catalog->in_use || !catalog->active || catalog->expires_at <= now
            || strcmp(catalog->tenant_id, recipient->tenant_id) != 0
            || catalog->publisher_client_id == recipient->id) continue;
        snapshots[count++] = *catalog;
    }
    pthread_mutex_unlock(&peer_catalog_lock);
    int rc = 0;
    for (size_t i = 0; i < count; ++i) {
        st_storage_client publisher;
        int allowed = 0;
        if (st_storage_get_client_by_name(runtime->database_path,
                                          snapshots[i].publisher_client_name, &publisher) != 0
            || st_storage_can_peer(runtime->database_path, &publisher, recipient, &allowed) != 0
            || !allowed) continue;
        char *message = pm_build_catalog_message(runtime, &snapshots[i], &publisher, recipient, 1);
        if (message == NULL
            || runtime->send(runtime->ctx, recipient->client_name, "server", message) != 0) rc = -1;
        free(message);
    }
    free(snapshots);
    return rc;
}

int st_peer_mesh_expire_catalogs(const st_peer_mesh_runtime *runtime)
{
    if (runtime == NULL || runtime->database_path == NULL || runtime->send == NULL
        || !pm_env_bool("SPECUS_PEER_MESH_ENABLED", 0)) return 0;
    pm_catalog *snapshots = (pm_catalog *)calloc(ST_PEER_MESH_MAX_CATALOGS,
                                                 sizeof(*snapshots));
    if (snapshots == NULL) return -1;
    size_t count = 0U;
    time_t now = time(NULL);
    pthread_mutex_lock(&peer_catalog_lock);
    for (size_t i = 0; i < ST_PEER_MESH_MAX_CATALOGS; ++i) {
        pm_catalog *catalog = &peer_catalogs[i];
        if (!catalog->in_use || !catalog->active || catalog->expires_at > now) continue;
        catalog->active = 0;
        catalog->expires_at = now;
        ++catalog->catalog_revision;
        catalog->service_count = 0U;
        snapshots[count++] = *catalog;
        free(catalog->mdns_candidates);
        catalog->mdns_candidates = NULL;
        catalog->mdns_count = 0U;
    }
    pthread_mutex_unlock(&peer_catalog_lock);
    int rc = 0;
    for (size_t i = 0; i < count; ++i) {
        st_storage_client publisher;
        if (st_storage_get_client_by_name(runtime->database_path,
                                          snapshots[i].publisher_client_name,
                                          &publisher) == 0
            && pm_fanout_catalog(runtime, &snapshots[i], &publisher) != 0) rc = -1;
        (void)st_storage_record_peer_mesh_service_audit(runtime->database_path,
            "catalog-expire", snapshots[i].tenant_id, snapshots[i].publisher_client_id,
            snapshots[i].publisher_session_id, NULL, "ttl");
    }
    free(snapshots);
    return rc;
}

int st_peer_mesh_handle_disconnect(const st_peer_mesh_runtime *runtime,
                                   const char *client_name)
{
    if (runtime == NULL || runtime->database_path == NULL || runtime->send == NULL
        || runtime->publisher_session_id <= 0 || !pm_has_text(client_name)
        || !pm_env_bool("SPECUS_PEER_MESH_ENABLED", 0)) return 0;
    st_storage_client publisher;
    if (st_storage_get_client_by_name(runtime->database_path, client_name, &publisher) != 0) {
        return -1;
    }
    pm_catalog snapshot;
    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.in_use = 1;
    snapshot.publisher_client_id = publisher.id;
    snapshot.publisher_session_id = runtime->publisher_session_id;
    snprintf(snapshot.tenant_id, sizeof(snapshot.tenant_id), "%s", publisher.tenant_id);
    snprintf(snapshot.publisher_client_name, sizeof(snapshot.publisher_client_name), "%s",
             publisher.client_name);
    snapshot.catalog_revision = 1;
    snapshot.expires_at = time(NULL);
    pthread_mutex_lock(&peer_catalog_lock);
    for (size_t i = 0; i < ST_PEER_MESH_MAX_CATALOGS; ++i) {
        pm_catalog *catalog = &peer_catalogs[i];
        if (!catalog->in_use || catalog->publisher_client_id != publisher.id
            || catalog->publisher_session_id != runtime->publisher_session_id
            || strcmp(catalog->tenant_id, publisher.tenant_id) != 0) continue;
        snapshot = *catalog;
        snapshot.active = 0;
        snapshot.expires_at = time(NULL);
        ++snapshot.catalog_revision;
        snapshot.service_count = 0U;
        free(catalog->mdns_candidates);
        memset(catalog, 0, sizeof(*catalog));
        break;
    }
    pthread_mutex_unlock(&peer_catalog_lock);
    (void)st_storage_record_peer_mesh_service_audit(runtime->database_path,
        "publisher-offline", publisher.tenant_id, publisher.id,
        runtime->publisher_session_id, NULL, "disconnected");
    return pm_fanout_catalog(runtime, &snapshot, &publisher);
}

int st_peer_mesh_list_mdns_candidates(const char *tenant_id,
                                      long long client_id,
                                      st_peer_mesh_mdns_candidate *out,
                                      size_t capacity,
                                      size_t *out_count)
{
    if (!pm_has_text(tenant_id) || client_id <= 0 || out_count == NULL
        || (capacity > 0U && out == NULL)) return -1;
    *out_count = 0U;
    time_t now = time(NULL);
    pthread_mutex_lock(&peer_catalog_lock);
    for (size_t i = 0; i < ST_PEER_MESH_MAX_CATALOGS; ++i) {
        pm_catalog *catalog = &peer_catalogs[i];
        if (!catalog->in_use || !catalog->active || catalog->expires_at <= now
            || catalog->publisher_client_id != client_id
            || strcmp(catalog->tenant_id, tenant_id) != 0) continue;
        for (size_t j = 0; j < catalog->mdns_count && *out_count < capacity; ++j) {
            out[(*out_count)++] = catalog->mdns_candidates[j];
        }
    }
    pthread_mutex_unlock(&peer_catalog_lock);
    return 0;
}

int st_peer_mesh_list_service_instances(const char *tenant_id,
                                        long long client_id,
                                        const char *service_id,
                                        st_peer_mesh_service_instance *out,
                                        size_t capacity,
                                        size_t *out_count)
{
    if (!pm_has_text(tenant_id) || client_id <= 0 || !pm_has_text(service_id)
        || out_count == NULL || (capacity > 0U && out == NULL)) return -1;
    *out_count = 0U;
    time_t now = time(NULL);
    pthread_mutex_lock(&peer_catalog_lock);
    for (size_t i = 0; i < ST_PEER_MESH_MAX_CATALOGS && *out_count < capacity; ++i) {
        pm_catalog *catalog = &peer_catalogs[i];
        if (!catalog->in_use || !catalog->active || catalog->expires_at <= now
            || catalog->publisher_client_id != client_id
            || strcmp(catalog->tenant_id, tenant_id) != 0) continue;
        st_peer_mesh_service_instance *instance = &out[(*out_count)++];
        memset(instance, 0, sizeof(*instance));
        instance->publisher_session_id = catalog->publisher_session_id;
        snprintf(instance->instance_id, sizeof(instance->instance_id), "%s", catalog->instance_id);
        instance->online = 1;
        instance->advertised = pm_catalog_has_service(catalog, service_id);
        instance->revision = catalog->catalog_revision;
        pm_format_instant(catalog->generated_at, instance->last_reported_at);
        pm_format_instant(catalog->expires_at, instance->expires_at);
        for (size_t j = 0; j < catalog->stats_count; ++j) {
            if (strcmp(catalog->stats[j].service_id, service_id) != 0) continue;
            instance->bytes_in = catalog->stats[j].bytes_in;
            instance->bytes_out = catalog->stats[j].bytes_out;
            instance->active_connections = catalog->stats[j].active_connections;
            instance->total_connections = catalog->stats[j].total_connections;
            break;
        }
    }
    pthread_mutex_unlock(&peer_catalog_lock);
    return 0;
}

static char *pm_runtime_config(const char *database_path,
                               const st_storage_client *client,
                               const st_storage_peer_mesh_device *device,
                               int client_peer_service_version)
{
    int deployment_enabled = pm_env_bool("SPECUS_PEER_MESH_ENABLED", 0);
    int enabled = deployment_enabled && device != NULL && device->enabled;
    int port = (int)pm_env_i64("SPECUS_PEER_MESH_STUN_TURN_PORT", 3478);
    const char *host = pm_env_text("SPECUS_PEER_MESH_PUBLIC_ADDRESS",
                                   pm_env_text("SPECUS_PUBLIC_ADDRESS", "127.0.0.1"));
    const char *cidr = device != NULL && device->cidr[0] != '\0'
        ? device->cidr : pm_env_text("SPECUS_PEER_MESH_CIDR", "100.96.0.0/11");
    long long ttl = pm_env_i64("SPECUS_PEER_MESH_SESSION_TTL_SECONDS", 3600);
    char ice_username[192] = "";
    char ice_credential[64] = "";
    char subject[64];
    st_storage_peer_mesh_service_sharing sharing = {0};
    (void)st_storage_get_peer_mesh_service_sharing(database_path, client->tenant_id, &sharing);
    int effective_sharing = deployment_enabled && sharing.enabled && enabled;
    snprintf(subject, sizeof(subject), "pm-%lld", client->id);
    if (enabled) (void)st_turn_auth_issue(subject, ice_username, sizeof(ice_username),
                                          ice_credential, sizeof(ice_credential));
    pm_builder builder = {0};
    if (pm_appendf(&builder, "{\"enabled\":%s,\"clientId\":%lld,\"clientName\":",
                   enabled ? "true" : "false", client->id) != 0
        || pm_append_json_string(&builder, client->client_name) != 0
        || pm_append(&builder, ",\"virtualIp\":") != 0
        || pm_append_json_string(&builder, device == NULL ? "" : device->virtual_ip) != 0
        || pm_append(&builder, ",\"cidr\":") != 0 || pm_append_json_string(&builder, cidr) != 0
        || pm_append(&builder, ",\"stunHost\":") != 0 || pm_append_json_string(&builder, enabled ? host : "") != 0
        || pm_appendf(&builder, ",\"stunPort\":%d,\"turnHost\":", enabled ? port : 0) != 0
        || pm_append_json_string(&builder, enabled ? host : "") != 0
        || pm_appendf(&builder, ",\"turnPort\":%d,\"publicStunServers\":", enabled ? port : 0) != 0
        || pm_append_public_stun_servers(&builder) != 0
        || pm_append(&builder, ",\"iceUsername\":") != 0
        || pm_append_json_string(&builder, ice_username) != 0
        || pm_append(&builder, ",\"iceCredential\":") != 0
        || pm_append_json_string(&builder, ice_credential) != 0
        || pm_append(&builder, ",\"iceRealm\":") != 0
        || pm_append_json_string(&builder, st_turn_auth_realm()) != 0
        || pm_append(&builder, ",\"iceNonce\":") != 0
        || pm_append_json_string(&builder, enabled ? st_turn_auth_nonce() : "") != 0
        || pm_append(&builder, ",\"serverPublicKey\":") != 0
        || pm_append_json_string(&builder, pm_env_text("SPECUS_PEER_MESH_SERVER_PUBLIC_KEY", "")) != 0
        || pm_append(&builder, ",\"clientPublicKey\":") != 0
        || pm_append_json_string(&builder, device == NULL ? "" : device->public_key) != 0
        || pm_appendf(&builder,
                      ",\"sessionTtlSeconds\":%lld,\"peerServiceDiscoveryVersion\":2,"
                      "\"serviceSharing\":{\"deploymentEnabled\":%s,\"configuredEnabled\":%s,"
                      "\"effectiveEnabled\":%s,\"mdnsImportEnabled\":%s},\"localServices\":",
                      ttl > 0 ? ttl : 3600, deployment_enabled ? "true" : "false",
                      sharing.enabled ? "true" : "false", effective_sharing ? "true" : "false",
                      effective_sharing && sharing.mdns_import_enabled ? "true" : "false") != 0
        || (client_peer_service_version >= 2
            ? pm_append_local_services(&builder, database_path, client)
            : pm_append(&builder, "[]")) != 0
        || pm_append(&builder, "}") != 0) {
        free(builder.data);
        return NULL;
    }
    return builder.data;
}

char *st_peer_mesh_build_login_config(const char *database_path,
                                      const char *client_name,
                                      int client_peer_service_version)
{
    st_storage_client client;
    st_storage_peer_mesh_device device;
    st_storage_peer_mesh_device *device_ptr = NULL;
    if (database_path == NULL || client_name == NULL
        || st_storage_get_client_by_name(database_path, client_name, &client) != 0) return NULL;
    if (pm_env_bool("SPECUS_PEER_MESH_ENABLED", 0)
        && st_storage_ensure_peer_mesh_device(database_path, &client, &device) == 0) device_ptr = &device;
    return pm_runtime_config(database_path, &client, device_ptr, client_peer_service_version);
}

static int pm_push_config(const st_peer_mesh_runtime *runtime,
                          const st_storage_client *client)
{
    st_storage_peer_mesh_device device;
    if (st_storage_ensure_peer_mesh_device(runtime->database_path, client, &device) != 0) return -1;
    char *config = pm_runtime_config(runtime->database_path, client, &device,
                                     runtime->peer_service_discovery_version);
    if (config == NULL) return -1;
    pm_builder message = {0};
    int rc = pm_appendf(&message,
                        "{\"type\":\"peer-config\",\"sourceClientId\":%lld,\"sourceClientName\":",
                        client->id) == 0
        && pm_append_json_string(&message, client->client_name) == 0
        && pm_appendf(&message, ",\"targetClientId\":%lld,\"targetClientName\":", client->id) == 0
        && pm_append_json_string(&message, client->client_name) == 0
        && pm_append(&message, ",\"peerMesh\":") == 0
        && pm_append(&message, config) == 0
        && pm_appendf(&message, ",\"createdAtMillis\":%lld}", (long long)time(NULL) * 1000LL) == 0
        ? runtime->send(runtime->ctx, client->client_name, "server", message.data) : -1;
    free(config);
    free(message.data);
    return rc;
}

static int pm_append_csv_string_array(pm_builder *builder, const char *csv)
{
    if (pm_append(builder, "[") != 0) return -1;
    if (csv != NULL && *csv != '\0') {
        char copy[128];
        snprintf(copy, sizeof(copy), "%s", csv);
        char *save = NULL;
        int first = 1;
        for (char *part = strtok_r(copy, ",", &save); part != NULL; part = strtok_r(NULL, ",", &save)) {
            if (*part == '\0') continue;
            if ((!first && pm_append(builder, ",") != 0)
                || pm_append_json_string(builder, part) != 0) return -1;
            first = 0;
        }
    }
    return pm_append(builder, "]");
}

static int pm_push_roster(const st_peer_mesh_runtime *runtime,
                          const st_storage_client *source,
                          const st_storage_client *clients,
                          size_t client_count)
{
    pm_builder message = {0};
    if (pm_appendf(&message, "{\"type\":\"roster\",\"clientId\":%lld,\"clientName\":",
                   source->id) != 0
        || pm_append_json_string(&message, source->client_name) != 0
        || pm_append(&message, ",\"peers\":[") != 0) goto failed;
    int first = 1;
    for (size_t i = 0; i < client_count; ++i) {
        if (clients[i].id == source->id || strcmp(clients[i].tenant_id, source->tenant_id) != 0) continue;
        int allowed = 0;
        st_storage_peer_mesh_device device;
        if (st_storage_can_peer(runtime->database_path, source, &clients[i], &allowed) != 0 || !allowed
            || st_storage_get_peer_mesh_device_by_client(runtime->database_path, clients[i].tenant_id,
                                                          clients[i].id, &device) != 0) continue;
        int online = runtime->online != NULL
            && runtime->online(runtime->ctx, clients[i].id, clients[i].client_name);
        if ((!first && pm_append(&message, ",") != 0)
            || pm_appendf(&message, "{\"clientId\":%lld,\"clientName\":", clients[i].id) != 0
            || pm_append_json_string(&message, clients[i].client_name) != 0
            || pm_append(&message, ",\"virtualIp\":") != 0
            || pm_append_json_string(&message, device.virtual_ip) != 0
            || pm_append(&message, ",\"publicKey\":") != 0
            || pm_append_json_string(&message, device.public_key) != 0
            || pm_appendf(&message,
                          ",\"online\":%s,\"messageSendCapable\":%s,\"messageReceiveCapable\":%s,"
                          "\"messageAttachmentsCapable\":%s,\"messageMediaPreviewCapable\":%s,"
                          "\"messageMaxAttachmentBytes\":%lld,\"peerServiceDiscoveryVersion\":%d,"
                          "\"peerServiceApplications\":",
                          online ? "true" : "false",
                          online && clients[i].message_send_capable ? "true" : "false",
                          online && clients[i].message_receive_capable ? "true" : "false",
                          online && clients[i].message_attachments_capable ? "true" : "false",
                          online && clients[i].message_media_preview_capable ? "true" : "false",
                          online ? clients[i].message_max_attachment_bytes : 0LL,
                          online ? clients[i].peer_service_discovery_version : 0) != 0
            || pm_append_csv_string_array(&message,
                online ? clients[i].peer_service_applications : "") != 0
            || pm_append(&message, "}") != 0) goto failed;
        first = 0;
    }
    if (pm_appendf(&message, "],\"createdAtMillis\":%lld}", (long long)time(NULL) * 1000LL) != 0) goto failed;
    int rc = runtime->send(runtime->ctx, source->client_name, "server", message.data);
    free(message.data);
    return rc;
failed:
    free(message.data);
    return -1;
}

/*
 * Peer egress split routing.
 *
 * Kept next to the mesh roster because the two are pushed together, but they answer different
 * questions: the roster and its ACL decide whether two devices may see each other, this decides
 * whether one of them may be used as a way out to the wider network. Effective permission is the
 * intersection, computed in pm_egress_allowed_consumers.
 */

/* Bumped on every push so a client can ignore a snapshot it has already applied. */
static long long peer_egress_revision;
static pthread_mutex_t peer_egress_revision_lock = PTHREAD_MUTEX_INITIALIZER;

static long long pm_next_egress_revision(void)
{
    pthread_mutex_lock(&peer_egress_revision_lock);
    long long revision = ++peer_egress_revision;
    pthread_mutex_unlock(&peer_egress_revision_lock);
    return revision;
}

/*
 * Version 0 or absent means the client cannot take part, and the server must not push egress-config
 * or egress-catalog to it.
 */
static int pm_egress_supported(const st_storage_client *client)
{
    return client != NULL && client->client_egress_version >= 1;
}

/* The tenant switch. Off by default: egress is opt-in for the tenant as well as per device. */
static int pm_tenant_egress_enabled(const char *database_path, const char *tenant_id)
{
    st_storage_peer_mesh_egress_switch row;
    return st_storage_get_peer_mesh_egress_switch(database_path, tenant_id, &row) == 0 && row.enabled;
}

static int pm_egress_id_listed(const char *csv, long long client_id)
{
    if (csv == NULL || *csv == '\0') return 0;
    char copy[512];
    snprintf(copy, sizeof(copy), "%s", csv);
    char *save = NULL;
    for (char *part = strtok_r(copy, ",", &save); part != NULL; part = strtok_r(NULL, ",", &save)) {
        char *end = NULL;
        long long value = strtoll(part, &end, 10);
        if (end != part && *end == '\0' && value == client_id) return 1;
    }
    return 0;
}

static const st_storage_client *pm_find_client_by_id(const st_storage_client *clients,
                                                     size_t client_count,
                                                     long long client_id)
{
    for (size_t i = 0; i < client_count; ++i) {
        if (clients[i].id == client_id) return &clients[i];
    }
    return NULL;
}

/*
 * Intersects the policy allowlist with the base Peer ACL.
 *
 * Taking the intersection here, rather than only on the egress node, keeps the two failure modes
 * aligned: a device that cannot see the egress in its catalogue also cannot reach it on the data
 * plane.
 */
static size_t pm_egress_allowed_consumers(const char *database_path,
                                          const st_storage_client *egress,
                                          const st_storage_peer_mesh_egress_policy *policy,
                                          const st_storage_client *clients,
                                          size_t client_count,
                                          long long *out,
                                          size_t capacity)
{
    if (!policy->enabled || policy->allowed_consumer_client_ids[0] == '\0') {
        /*
         * An empty consumer allowlist grants nothing. Note this is the opposite of the shared
         * service default, where an empty list means "everyone the mesh ACL already allows".
         * Egress has to be chosen on both sides: reading a blank field as "anyone" would turn a
         * device into the whole tenant's way out.
         */
        return 0U;
    }
    size_t count = 0U;
    for (size_t i = 0; i < client_count && count < capacity; ++i) {
        const st_storage_client *candidate = &clients[i];
        int allowed = 0;
        if (candidate->id == egress->id
            || strcmp(candidate->tenant_id, egress->tenant_id) != 0
            || !pm_egress_id_listed(policy->allowed_consumer_client_ids, candidate->id)
            || st_storage_can_peer(database_path, candidate, egress, &allowed) != 0
            || !allowed) continue;
        out[count++] = candidate->id;
    }
    return count;
}

static int pm_append_egress_destination_rules(pm_builder *builder, const char *stored)
{
    st_egress_destination_rule rules[ST_EGRESS_MAX_DESTINATION_RULES];
    size_t rules_len = 0U;
    /*
     * A row that cannot be parsed denies everything rather than falling back to something
     * permissive, so a decode failure still emits an empty allowlist.
     */
    (void)st_egress_parse_destination_rules(stored, rules, ST_EGRESS_MAX_DESTINATION_RULES, &rules_len);
    if (pm_append(builder, "[") != 0) return -1;
    for (size_t i = 0; i < rules_len; ++i) {
        if ((i > 0 && pm_append(builder, ",") != 0)
            || pm_append(builder, "{\"cidr\":") != 0
            || pm_append_json_string(builder, rules[i].cidr) != 0
            || pm_append(builder, ",\"protocols\":[") != 0) return -1;
        for (size_t p = 0; p < rules[i].protocols_len; ++p) {
            if ((p > 0 && pm_append(builder, ",") != 0)
                || pm_append_json_string(builder, rules[i].protocols[p]) != 0) return -1;
        }
        if (pm_append(builder, "],\"portRanges\":[") != 0) return -1;
        for (size_t r = 0; r < rules[i].port_ranges_len; ++r) {
            if (pm_appendf(builder, "%s[%d,%d]", r > 0 ? "," : "",
                           rules[i].port_ranges[r][0], rules[i].port_ranges[r][1]) != 0) return -1;
        }
        if (pm_append(builder, "]}") != 0) return -1;
    }
    return pm_append(builder, "]");
}

static int pm_push_egress_config(const st_peer_mesh_runtime *runtime,
                                 const st_storage_client *client,
                                 const st_storage_client *clients,
                                 size_t client_count)
{
    if (!pm_egress_supported(client)) return 0;

    st_storage_peer_mesh_egress_policy policy;
    int found = st_storage_find_peer_mesh_egress_policy_by_client(runtime->database_path,
                                                                  client->tenant_id,
                                                                  client->id, &policy);
    if (found < 0) return -1;

    pm_builder message = {0};
    int rc = pm_appendf(&message, "{\"type\":\"egress-config\",\"revision\":%lld,",
                        pm_next_egress_revision());
    int tenant_on = pm_tenant_egress_enabled(runtime->database_path, client->tenant_id);
    if (rc == 0 && (found != 0 || !policy.enabled || !tenant_on)) {
        rc = pm_append(&message,
                       "\"enabled\":false,\"allowedConsumerClientIds\":[],\"destinationRules\":[]");
    } else if (rc == 0) {
        long long consumers[ST_EGRESS_MAX_CONSUMERS];
        size_t consumer_count = pm_egress_allowed_consumers(runtime->database_path, client, &policy,
                                                            clients, client_count,
                                                            consumers, ST_EGRESS_MAX_CONSUMERS);
        rc = pm_append(&message, "\"enabled\":true,\"scope\":") == 0
            && pm_append_json_string(&message, policy.scope) == 0
            && pm_append(&message, ",\"allowedConsumerClientIds\":[") == 0 ? 0 : -1;
        for (size_t i = 0; rc == 0 && i < consumer_count; ++i) {
            rc = pm_appendf(&message, "%s%lld", i > 0 ? "," : "", consumers[i]);
        }
        if (rc == 0) {
            rc = pm_append(&message, "],\"destinationRules\":") == 0
                && pm_append_egress_destination_rules(&message, policy.destination_rules) == 0
                && pm_appendf(&message,
                              ",\"limits\":{\"maxConcurrentFlows\":%d,\"maxFlowsPerConsumer\":%d,"
                              "\"idleTimeoutSeconds\":%d}",
                              policy.max_concurrent_flows, policy.max_flows_per_consumer,
                              policy.idle_timeout_seconds) == 0 ? 0 : -1;
        }
    }
    if (rc == 0) {
        rc = pm_appendf(&message, ",\"createdAtMillis\":%lld}", (long long)time(NULL) * 1000LL) == 0
            ? runtime->send(runtime->ctx, client->client_name, "server", message.data) : -1;
    }
    free(message.data);
    return rc;
}

/*
 * The catalogue deliberately omits the egress node's destination allowlist. A consumer does not need
 * it to route, and shipping it would hand every peer a map of that node's reachable network.
 */
static int pm_push_egress_catalog(const st_peer_mesh_runtime *runtime,
                                  const st_storage_client *consumer,
                                  const st_storage_client *clients,
                                  size_t client_count)
{
    if (!pm_egress_supported(consumer)) return 0;

    st_storage_peer_mesh_egress_policy policies[64];
    size_t policy_count = 0U;
    if (!pm_tenant_egress_enabled(runtime->database_path, consumer->tenant_id)) {
        policy_count = 0U;
    } else if (st_storage_list_peer_mesh_egress_policies(runtime->database_path, consumer->tenant_id, 1,
                                                         policies, 64U, &policy_count) != 0) return -1;

    pm_builder message = {0};
    int rc = pm_appendf(&message, "{\"type\":\"egress-catalog\",\"revision\":%lld,\"egresses\":[",
                        pm_next_egress_revision());
    int first = 1;
    for (size_t i = 0; rc == 0 && i < policy_count; ++i) {
        st_storage_peer_mesh_egress_policy *policy = &policies[i];
        if (policy->egress_client_id == consumer->id) continue;

        const st_storage_client *egress = pm_find_client_by_id(clients, client_count,
                                                               policy->egress_client_id);
        int allowed = 0;
        if (egress == NULL
            || st_storage_can_peer(runtime->database_path, consumer, egress, &allowed) != 0
            || !allowed) continue;

        long long consumers[ST_EGRESS_MAX_CONSUMERS];
        size_t consumer_count = pm_egress_allowed_consumers(runtime->database_path, egress, policy,
                                                            clients, client_count,
                                                            consumers, ST_EGRESS_MAX_CONSUMERS);
        int listed = 0;
        for (size_t k = 0; k < consumer_count; ++k) {
            if (consumers[k] == consumer->id) { listed = 1; break; }
        }
        if (!listed) continue;

        st_storage_peer_mesh_device device;
        int online = st_storage_get_peer_mesh_device_by_client(runtime->database_path,
                                                               consumer->tenant_id,
                                                               policy->egress_client_id, &device) == 0
            && device.enabled;

        st_egress_destination_rule rules[ST_EGRESS_MAX_DESTINATION_RULES];
        size_t rules_len = 0U;
        (void)st_egress_parse_destination_rules(policy->destination_rules, rules,
                                                ST_EGRESS_MAX_DESTINATION_RULES, &rules_len);
        char protocols[ST_EGRESS_MAX_PROTOCOLS][8];
        size_t protocol_count = st_egress_collect_protocols(rules, rules_len, protocols,
                                                            ST_EGRESS_MAX_PROTOCOLS);

        if (!first && pm_append(&message, ",") != 0) { rc = -1; break; }
        rc = pm_appendf(&message, "{\"clientId\":%lld,\"clientName\":", policy->egress_client_id) == 0
            && pm_append_json_string(&message, policy->egress_client_name) == 0
            && pm_appendf(&message, ",\"online\":%s,\"scope\":", online ? "true" : "false") == 0
            && pm_append_json_string(&message, policy->scope) == 0
            && pm_append(&message, ",\"protocols\":[") == 0 ? 0 : -1;
        for (size_t p = 0; rc == 0 && p < protocol_count; ++p) {
            rc = ((p > 0 && pm_append(&message, ",") != 0)
                  || pm_append_json_string(&message, protocols[p]) != 0) ? -1 : 0;
        }
        if (rc == 0) {
            /* Both stay false until domain rules and an IPv6 data plane ship. */
            rc = pm_append(&message, "],\"domainTargetCapable\":false,\"ipv6TargetCapable\":false}");
        }
        first = 0;
    }
    if (rc == 0) {
        rc = pm_appendf(&message, "],\"createdAtMillis\":%lld}", (long long)time(NULL) * 1000LL) == 0
            ? runtime->send(runtime->ctx, consumer->client_name, "server", message.data) : -1;
    }
    free(message.data);
    return rc;
}

/*
 * egress-report ingest.
 *
 * The reporter identity and session come from the authenticated control connection the caller
 * already resolved, never from the message body. The report carries counters only: no destination,
 * domain or request content, and refusals aggregated by result code.
 */

/* Cap on one envelope. Counters only, so this is far above what a well-formed report needs. */
#define ST_PEER_EGRESS_MAX_REPORT_BYTES (8U * 1024U)
#define ST_PEER_EGRESS_REPORT_RATE_LIMIT 20U
#define ST_PEER_EGRESS_REPORT_RATE_WINDOW 60
#define ST_PEER_EGRESS_MAX_RATE_SESSIONS 4096U

typedef struct {
    long long session_id;
    time_t window_started_at;
    unsigned int count;
} pm_egress_rate_slot;

static pm_egress_rate_slot peer_egress_rate_slots[ST_PEER_EGRESS_MAX_RATE_SESSIONS];
static size_t peer_egress_rate_used;
static pthread_mutex_t peer_egress_rate_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * Bounds how often one control session may report. The table is keyed by client-driven session ids,
 * so it carries a hard ceiling of its own: refusing at the ceiling is safer than letting an abusive
 * peer grow it without bound.
 */
static int pm_enforce_egress_report_rate(long long session_id)
{
    time_t now = time(NULL);
    int allowed = 0;
    pthread_mutex_lock(&peer_egress_rate_lock);
    pm_egress_rate_slot *slot = NULL;
    for (size_t i = 0; i < peer_egress_rate_used; ++i) {
        if (peer_egress_rate_slots[i].session_id == session_id) {
            slot = &peer_egress_rate_slots[i];
            break;
        }
    }
    if (slot == NULL && peer_egress_rate_used < ST_PEER_EGRESS_MAX_RATE_SESSIONS) {
        slot = &peer_egress_rate_slots[peer_egress_rate_used++];
        slot->session_id = session_id;
        slot->window_started_at = 0;
        slot->count = 0U;
    }
    if (slot != NULL) {
        if (slot->window_started_at == 0
            || now - slot->window_started_at >= ST_PEER_EGRESS_REPORT_RATE_WINDOW) {
            slot->window_started_at = now;
            slot->count = 0U;
        }
        if (slot->count < ST_PEER_EGRESS_REPORT_RATE_LIMIT) {
            ++slot->count;
            allowed = 1;
        }
    }
    pthread_mutex_unlock(&peer_egress_rate_lock);
    return allowed ? 0 : -1;
}

static long long pm_report_counter(const char *message, const char *field)
{
    long long value = 0;
    if (st_json_get_i64(message, field, &value) != 0 || value < 0) {
        return 0;
    }
    return value;
}

/*
 * Keeps only codes this build defines. Without the filter a client could grow the stored map with
 * keys of its own invention.
 */
static void pm_encode_rejected_flows(const char *message, char *out, size_t out_len)
{
    snprintf(out, out_len, "{}");
    char *raw = st_json_get_top_level_raw(message, "rejectedFlows");
    if (raw == NULL) {
        return;
    }
    pm_builder builder = {0};
    int first = 1;
    int rc = pm_append(&builder, "{");
    for (size_t i = 0; rc == 0 && i < ST_EGRESS_ALL_CODES_LEN; ++i) {
        long long count = 0;
        if (st_json_get_i64(raw, ST_EGRESS_ALL_CODES[i], &count) != 0 || count < 0) {
            continue;
        }
        rc = (!first && pm_append(&builder, ",") != 0) ? -1 : 0;
        if (rc == 0) {
            rc = pm_append_json_string(&builder, ST_EGRESS_ALL_CODES[i]) == 0
                && pm_appendf(&builder, ":%lld", count) == 0 ? 0 : -1;
        }
        first = 0;
    }
    if (rc == 0) {
        rc = pm_append(&builder, "}");
    }
    /* Cannot overflow with known codes only; refusing beats storing a truncated map. */
    if (rc == 0 && builder.data != NULL && strlen(builder.data) < out_len) {
        snprintf(out, out_len, "%s", builder.data);
    }
    free(builder.data);
    free(raw);
}

static int pm_handle_egress_report(const st_peer_mesh_runtime *runtime,
                                   const st_storage_client *source,
                                   const char *target_client_name,
                                   const char *message)
{
    static const char *server_fields[] = {
        "sourceClientId", "sourceClientName", "sourceVirtualIp", "sourcePublicKey", "sourceKeyEpoch",
        "targetClientId", "targetClientName", "targetVirtualIp", "targetPublicKey",
        "sessionId", "token"
    };
    if (strlen(message) > ST_PEER_EGRESS_MAX_REPORT_BYTES || pm_has_text(target_client_name)
        || runtime->publisher_session_id <= 0) {
        return -1;
    }
    for (size_t i = 0; i < sizeof(server_fields) / sizeof(server_fields[0]); ++i) {
        if (pm_top_level_has(message, server_fields[i])) return -1;
    }
    if (source->client_egress_version < 1) {
        return -1;
    }
    if (pm_enforce_egress_report_rate(runtime->publisher_session_id) != 0) {
        return -1;
    }

    long long revision = 0;
    (void)st_json_get_i64(message, "revision", &revision);

    st_storage_peer_mesh_egress_activity stored;
    int found = st_storage_find_peer_mesh_egress_activity(runtime->database_path, source->tenant_id,
                                                          source->id, &stored);
    if (found < 0) {
        return -1;
    }
    /* Reports can overtake each other on reconnect; an older snapshot must not overwrite a newer one. */
    if (found == 0 && revision > 0 && revision < stored.revision) {
        return 0;
    }

    st_storage_peer_mesh_egress_activity row;
    memset(&row, 0, sizeof(row));
    snprintf(row.tenant_id, sizeof(row.tenant_id), "%s", source->tenant_id);
    row.egress_client_id = source->id;
    snprintf(row.egress_client_name, sizeof(row.egress_client_name), "%s", source->client_name);
    row.session_id = runtime->publisher_session_id;
    row.revision = revision;
    row.active_flows = pm_report_counter(message, "activeFlows");
    row.total_flows = pm_report_counter(message, "totalFlows");
    row.bytes_in = pm_report_counter(message, "bytesIn");
    row.bytes_out = pm_report_counter(message, "bytesOut");
    pm_encode_rejected_flows(message, row.rejected_flows, sizeof(row.rejected_flows));
    pm_format_instant(time(NULL), row.reported_at);
    return st_storage_upsert_peer_mesh_egress_activity(runtime->database_path, &row);
}

int st_peer_mesh_push_on_login(const st_peer_mesh_runtime *runtime,
                               const char *client_name)
{
    if (runtime == NULL || runtime->database_path == NULL || runtime->send == NULL
        || !pm_env_bool("SPECUS_PEER_MESH_ENABLED", 0)) return 0;
    (void)st_peer_mesh_expire_catalogs(runtime);
    st_storage_client source;
    st_storage_client clients[ST_PEER_MESH_MAX_CLIENTS];
    size_t client_count = 0U;
    if (st_storage_get_client_by_name(runtime->database_path, client_name, &source) != 0
        || st_storage_list_clients(runtime->database_path, clients,
                                   ST_PEER_MESH_MAX_CLIENTS, &client_count) != 0
        || pm_push_config(runtime, &source) != 0) return -1;
    (void)pm_push_egress_config(runtime, &source, clients, client_count);
    for (size_t i = 0; i < client_count; ++i) {
        if (strcmp(clients[i].tenant_id, source.tenant_id) == 0
            && runtime->online != NULL
            && runtime->online(runtime->ctx, clients[i].id, clients[i].client_name)) {
            (void)pm_push_roster(runtime, &clients[i], clients, client_count);
            /* A new egress device changes what its peers may reach, so the catalogue is
             * refreshed for everyone online, not only for the client that just logged in. */
            (void)pm_push_egress_catalog(runtime, &clients[i], clients, client_count);
        }
    }
    (void)pm_replay_catalogs(runtime, &source);
    return 0;
}

int st_peer_mesh_refresh_tenant(const st_peer_mesh_runtime *runtime,
                                const char *tenant_id)
{
    if (runtime == NULL || runtime->database_path == NULL || runtime->send == NULL
        || tenant_id == NULL || *tenant_id == '\0'
        || !pm_env_bool("SPECUS_PEER_MESH_ENABLED", 0)) return 0;

    (void)st_peer_mesh_expire_catalogs(runtime);
    st_storage_client clients[ST_PEER_MESH_MAX_CLIENTS];
    size_t client_count = 0U;
    if (st_storage_list_clients(runtime->database_path, clients,
                                ST_PEER_MESH_MAX_CLIENTS, &client_count) != 0) return -1;

    int rc = 0;
    for (size_t i = 0; i < client_count; ++i) {
        if (strcmp(clients[i].tenant_id, tenant_id) != 0
            || runtime->online == NULL
            || !runtime->online(runtime->ctx, clients[i].id, clients[i].client_name)) continue;
        if (pm_push_config(runtime, &clients[i]) != 0
            || pm_push_roster(runtime, &clients[i], clients, client_count) != 0) rc = -1;
        if (pm_push_egress_config(runtime, &clients[i], clients, client_count) != 0
            || pm_push_egress_catalog(runtime, &clients[i], clients, client_count) != 0) rc = -1;
    }

    pm_catalog *snapshots = (pm_catalog *)calloc(ST_PEER_MESH_MAX_CATALOGS,
                                                 sizeof(*snapshots));
    if (snapshots == NULL) return -1;
    size_t snapshot_count = 0U;
    time_t now = time(NULL);
    pthread_mutex_lock(&peer_catalog_lock);
    for (size_t i = 0; i < ST_PEER_MESH_MAX_CATALOGS; ++i) {
        pm_catalog *catalog = &peer_catalogs[i];
        if (!catalog->in_use || !catalog->active || catalog->expires_at <= now
            || strcmp(catalog->tenant_id, tenant_id) != 0) continue;
        ++catalog->catalog_revision;
        snapshots[snapshot_count++] = *catalog;
    }
    pthread_mutex_unlock(&peer_catalog_lock);
    for (size_t i = 0; i < snapshot_count; ++i) {
        st_storage_client publisher;
        if (st_storage_get_client_by_name(runtime->database_path,
                                          snapshots[i].publisher_client_name,
                                          &publisher) != 0
            || pm_fanout_catalog(runtime, &snapshots[i], &publisher) != 0) rc = -1;
    }
    free(snapshots);
    return rc;
}
