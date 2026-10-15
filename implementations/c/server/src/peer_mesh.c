#define _POSIX_C_SOURCE 200809L

#include "peer_mesh.h"

#include "crypto.h"
#include "json.h"
#include "peer_egress.h"
#include "storage.h"
#include "turn_auth.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <limits.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#define ST_PEER_MESH_MAX_CATALOGS 4096U
#define ST_PEER_MESH_MAX_CATALOG_SERVICES 32U
#define ST_PEER_MESH_CATALOG_TTL_SECONDS 300
/* service-report and egress-report: each at most 20 per control session per minute. */
#define ST_PEER_REPORT_RATE_LIMIT 20U

/*
 * A sliding one-minute window, as Java keeps one per session: a report is admitted while fewer
 * than the limit were admitted in the last window. A window that restarts every minute would let
 * twice the limit through around each restart.
 */
typedef struct {
    long long stamps[ST_PEER_REPORT_RATE_LIMIT];
    unsigned int head;
    unsigned int count;
} pm_rate_window;

static long long pm_monotonic_ms(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (long long)now.tv_sec * 1000LL + now.tv_nsec / 1000000L;
}

static int pm_rate_window_admit(pm_rate_window *window, long long now_ms, unsigned int limit,
                                long long window_ms)
{
    if (limit > ST_PEER_REPORT_RATE_LIMIT) limit = ST_PEER_REPORT_RATE_LIMIT;
    while (window->count > 0U && window->stamps[window->head] < now_ms - window_ms) {
        window->head = (window->head + 1U) % ST_PEER_REPORT_RATE_LIMIT;
        --window->count;
    }
    if (window->count >= limit) return 0;
    window->stamps[(window->head + window->count) % ST_PEER_REPORT_RATE_LIMIT] = now_ms;
    ++window->count;
    return 1;
}

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
    pm_rate_window rate;
    char service_ids[ST_PEER_MESH_MAX_CATALOG_SERVICES][65];
    size_t service_count;
    pm_service_stats stats[ST_PEER_MESH_MAX_CATALOG_SERVICES];
    size_t stats_count;
    st_peer_mesh_mdns_candidate *mdns_candidates;
    size_t mdns_count;
    /* Internal reservation only: readers continue to see the committed cohort. */
    void *pending_report;
    char database_path[512];
    int has_control_source;
    st_storage_control_source control_source;
} pm_catalog;

static pm_catalog peer_catalogs[ST_PEER_MESH_MAX_CATALOGS];
static pthread_mutex_t peer_catalog_lock = PTHREAD_MUTEX_INITIALIZER;
/* Output clock is process-owned, independent of untrusted report counters and retained
 * after per-session cleanup. Called only while peer_catalog_lock is held. */
static long long peer_catalog_sequence;
/* A prepared native admission owns one future output revision, not an already allocated one.
 * Other publications must leave this budget intact until its cache cutover commits or aborts. */
static size_t peer_catalog_reserved_revisions;
static long long pm_next_catalog_revision_locked(long long previous)
{
    long long floor = peer_catalog_sequence > previous ? peer_catalog_sequence : previous;
    if (floor >= LLONG_MAX - (long long)peer_catalog_reserved_revisions) return 0;
    peer_catalog_sequence = floor + 1LL;
    return peer_catalog_sequence;
}
/* Serialize snapshot construction AND delivery, not just database reads. Otherwise
 * an older peer-config/roster may arrive after the committed ownership refresh.
 * Runtime send/online callbacks must not re-enter these dispatch operations. */
static pthread_mutex_t peer_snapshot_dispatch_lock = PTHREAD_MUTEX_INITIALIZER;

struct st_peer_mesh_control_transition {
    char database_path[512];
    char tenant_id[64];
    char publisher_client_name[256];
    long long publisher_client_id;
    long long publisher_session_id;
    long long revision;
    time_t expires_at;
    int audited;
    struct st_peer_mesh_control_transition *next;
};
/* The cap includes reserved, queued AND executing withdrawals. Cache removal and queue insertion
 * share peer_catalog_lock; no database handle or network callback is used while it is held. */
static size_t peer_control_withdrawal_count;
static st_peer_mesh_control_transition *peer_control_withdrawal_head;
static st_peer_mesh_control_transition *peer_control_withdrawal_tail;

typedef struct pm_client_deletion {
    st_storage_client client;
    st_storage_peer_close *closed;
    size_t closed_count;
    pm_catalog *withdrawals;
    size_t withdrawal_count;
    int prepared;
    struct pm_client_deletion *next;
} pm_client_deletion;

static pm_client_deletion *peer_deletion_head = NULL;
static pm_client_deletion *peer_deletion_tail = NULL;
static pthread_mutex_t peer_deletion_queue_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t peer_deletion_dispatch_lock = PTHREAD_MUTEX_INITIALIZER;

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

/*
 * Session tokens this process granted, by session id (Java PeerMeshService.sessionTokenCache).
 * The database keeps only the token's hash, so a session can be handed out again only while its
 * token is held here; a session whose token was evicted, or granted before a restart, is simply
 * not reused and the pair gets a new one.
 */
#define ST_PEER_MESH_TOKEN_CACHE 1024U

typedef struct {
    long long session_id;
    unsigned long long stored;
    char token[64];
} pm_session_token;

static pm_session_token peer_session_tokens[ST_PEER_MESH_TOKEN_CACHE];
static unsigned long long peer_session_token_clock;
static pthread_mutex_t peer_session_token_lock = PTHREAD_MUTEX_INITIALIZER;

static void pm_remember_session_token(long long session_id, const char *token)
{
    pthread_mutex_lock(&peer_session_token_lock);
    pm_session_token *slot = &peer_session_tokens[0];
    for (size_t i = 0U; i < ST_PEER_MESH_TOKEN_CACHE; ++i) {
        pm_session_token *candidate = &peer_session_tokens[i];
        if (candidate->session_id == session_id || candidate->session_id == 0) {
            slot = candidate;
            break;
        }
        if (candidate->stored < slot->stored) slot = candidate;
    }
    slot->session_id = session_id;
    slot->stored = ++peer_session_token_clock;
    snprintf(slot->token, sizeof(slot->token), "%s", token);
    pthread_mutex_unlock(&peer_session_token_lock);
}

static int pm_session_token_for(long long session_id, char out[64])
{
    int found = 0;
    pthread_mutex_lock(&peer_session_token_lock);
    for (size_t i = 0U; i < ST_PEER_MESH_TOKEN_CACHE && !found; ++i) {
        if (peer_session_tokens[i].session_id == session_id && session_id > 0) {
            snprintf(out, 64U, "%s", peer_session_tokens[i].token);
            found = 1;
        }
    }
    pthread_mutex_unlock(&peer_session_token_lock);
    return found;
}

static void pm_forget_session_token(long long session_id)
{
    pthread_mutex_lock(&peer_session_token_lock);
    for (size_t i = 0U; i < ST_PEER_MESH_TOKEN_CACHE; ++i) {
        if (peer_session_tokens[i].session_id == session_id) {
            memset(&peer_session_tokens[i], 0, sizeof(peer_session_tokens[i]));
        }
    }
    pthread_mutex_unlock(&peer_session_token_lock);
}

/*
 * Java reusableSessionGrant: an open, unexpired session between the two clients, in either
 * direction, whose token is still held is granted again with that token. Without it, two peers
 * whose offers cross would each open a session and negotiate on different ones.
 */
static int pm_reusable_session(const st_peer_mesh_runtime *runtime,
                               const st_storage_client *source,
                               const st_storage_client *target,
                               st_storage_peer_mesh_session *session,
                               char token[64])
{
    st_storage_peer_mesh_session open_sessions[16];
    size_t count = 0U;
    if (st_storage_open_peer_mesh_sessions_between(runtime->database_path, source->tenant_id,
                                                   source->id, target->id,
                                                   open_sessions, 16U, &count) != 0) return 0;
    for (size_t i = 0U; i < count; ++i) {
        if (pm_session_token_for(open_sessions[i].id, token)) {
            *session = open_sessions[i];
            return 1;
        }
    }
    return 0;
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

/* A session expiry as the wire carries it: an RFC 3339 UTC instant, which is what Java's
 * Instant.toString() writes and protocol/spec/peer-mesh.md shows. SQLite keeps the expiry as
 * "YYYY-MM-DD HH:MM:SS" in UTC; sent as stored, a .NET client reads it as local time (an expired
 * session east of UTC) and a Go client cannot parse it at all. */
static int pm_append_session_expiry(pm_builder *builder, const char *stored)
{
    int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
    char trailing = '\0';
    char instant[32];
    if (stored != NULL
        && sscanf(stored, "%4d-%2d-%2d %2d:%2d:%2d%c",
                  &year, &month, &day, &hour, &minute, &second, &trailing) == 6) {
        snprintf(instant, sizeof(instant), "%04d-%02d-%02dT%02d:%02d:%02dZ",
                 year, month, day, hour, minute, second);
        stored = instant;
    }
    return pm_append_named_string(builder, "expiresAt", stored);
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
            || pm_append_session_expiry(&builder, opened_session->expires_at) != 0) goto failed;
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
        || pm_append_session_expiry(&builder, session->expires_at) != 0
        || pm_append_named_string(&builder, "pathType", session->path_type) != 0
        || pm_append_named_string(&builder, "status", session->status) != 0
        || pm_appendf(&builder, ",\"dataFrameVersion\":2,\"createdAtMillis\":%lld}",
                      (long long)time(NULL) * 1000LL) != 0) {
        free(builder.data);
        return NULL;
    }
    return builder.data;
}

static int pm_report_session(const st_peer_mesh_runtime *runtime, const st_storage_client *source,
    long long id, const char *path_type, const char *status, long long rtt,
    const char *local, const char *remote, long long direct, long long relay, int close_session)
{
    return runtime->control_source == NULL
        ? st_storage_report_peer_mesh_session(runtime->database_path, source, id, path_type, status, rtt,
                                              local, remote, direct, relay, close_session, NULL)
        : st_storage_report_peer_mesh_session_from_control(runtime->database_path, runtime->control_source,
            source, id, path_type, status, rtt, local, remote, direct, relay, close_session, NULL);
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
        int rc = runtime->control_source == NULL
            ? st_storage_update_peer_mesh_device_report(runtime->database_path, source, NULL, nat_type,
                nat_mapping, nat_filtering, nat_discovery, last_endpoint, mode, name, status, error, NULL)
            : st_storage_update_peer_mesh_device_report_from_control(runtime->database_path,
                runtime->control_source, source, NULL, nat_type, nat_mapping, nat_filtering,
                nat_discovery, last_endpoint, mode, name, status, error, NULL);
        free(nat_type); free(nat_mapping); free(nat_filtering); free(nat_discovery);
        free(last_endpoint); free(mode); free(name); free(status); free(error);
        return rc;
    }
    long long session_id = 0;
    if (st_json_get_i64(message, "sessionId", &session_id) != 0 || session_id <= 0) return -1;
    /*
     * Each type records only its own fields, as Java PeerMeshService does: a close only closes, a
     * traffic report only counts bytes (the storage derives the path type from the counters), and
     * a path-report carries the path but no bytes.
     */
    if (strcmp(type, "close") == 0) {
        int rc = pm_report_session(runtime, source, session_id, NULL, NULL, -1, NULL, NULL, 0, 0, 1);
        if (rc == 0) pm_forget_session_token(session_id);
        return rc;
    }
    if (strcmp(type, "traffic-report") == 0) {
        long long direct = 0;
        long long relay = 0;
        (void)st_json_get_i64(message, "directBytes", &direct);
        (void)st_json_get_i64(message, "relayBytes", &relay);
        return pm_report_session(runtime, source, session_id, NULL, NULL, -1, NULL, NULL, direct, relay, 0);
    }
    char *path_type = st_json_get_top_level_string(message, "pathType");
    char *status = st_json_get_top_level_string(message, "status");
    char *local = st_json_get_top_level_string(message, "localEndpoint");
    char *remote = st_json_get_top_level_string(message, "remoteEndpoint");
    long long rtt = -1;
    (void)st_json_get_i64(message, "rttMillis", &rtt);
    int rc = pm_report_session(runtime, source, session_id, path_type,
                              pm_has_text(status) ? status : "ACTIVE", rtt, local, remote, 0, 0, 0);
    free(path_type); free(status); free(local); free(remote);
    return rc;
}

static int pm_handle_control_impl(const st_peer_mesh_runtime *runtime,
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
        || (runtime->authenticated_client_id > 0 && source.id != runtime->authenticated_client_id)
        || (runtime->authenticated_tenant != NULL && strcmp(source.tenant_id, runtime->authenticated_tenant) != 0)) {
        free(type);
        return -1;
    }
    int device_rc = runtime->control_source == NULL
        ? st_storage_ensure_peer_mesh_device(runtime->database_path, &source, &source_device)
        : st_storage_ensure_peer_mesh_device_from_control(runtime->database_path, runtime->control_source, &source, &source_device);
    if (device_rc != 0) { free(type); return device_rc; }
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
    if (opens && !pm_reusable_session(runtime, &source, &target, &opened, token)) {
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
        int open_rc = runtime->control_source == NULL
            ? st_storage_create_peer_mesh_session(runtime->database_path, &source, &target, "DIRECT", token_hash, ttl, &opened)
            : st_storage_create_peer_mesh_session_from_control(runtime->database_path, runtime->control_source,
                &source, &target, "DIRECT", token_hash, ttl, &opened);
        if (open_rc != 0) {
            free(type);
            return open_rc;
        }
        pm_remember_session_token(opened.id, token);
    }
    if (opens) {
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

/* A port setting as Java binds it: the default when unset; 0 (or anything unusable) turns it off. */
static int pm_env_port(const char *name, int default_value)
{
    const char *value = getenv(name);
    if (value == NULL || *value == '\0') return default_value;
    char *end = NULL;
    long long parsed = strtoll(value, &end, 10);
    return end != value && *end == '\0' && parsed > 0 && parsed <= 65535 ? (int)parsed : 0;
}

/* value with surrounding whitespace removed, or "" when it does not fit. */
static void pm_trim_copy(const char *value, char *out, size_t out_len)
{
    out[0] = '\0';
    if (value == NULL) return;
    while (isspace((unsigned char)*value)) ++value;
    size_t len = strlen(value);
    while (len > 0U && isspace((unsigned char)value[len - 1U])) --len;
    if (len < out_len) {
        memcpy(out, value, len);
        out[len] = '\0';
    }
}

/*
 * The STUN endpoint Peer Mesh clients probe (Java PeerMeshService.resolveStunHost and
 * resolveStunPort): a standalone STUN server when both its address and port are configured,
 * otherwise the embedded STUN/TURN listener at the relay address. An incomplete standalone setting
 * falls back rather than sending clients to a STUN server that is not there.
 */
static int pm_standalone_stun(char host[256], int *port)
{
    pm_trim_copy(getenv("SPECUS_PEER_MESH_STANDALONE_STUN_ADDRESS"), host, 256U);
    *port = pm_env_port("SPECUS_PEER_MESH_STANDALONE_STUN_PORT", 3478);
    return host[0] != '\0' && *port > 0;
}

static int pm_stun_port(void)
{
    char host[256];
    int port = 0;
    return pm_standalone_stun(host, &port) ? port : (int)pm_env_i64("SPECUS_PEER_MESH_STUN_TURN_PORT", 3478);
}

static int pm_append_stun_entry(pm_builder *builder, char seen[][320], size_t *count, const char *entry)
{
    if (*entry == '\0' || *count >= 16U || strlen(entry) >= 320U) return 0;
    for (size_t i = 0U; i < *count; ++i) {
        if (strcmp(seen[i], entry) == 0) return 0;
    }
    snprintf(seen[*count], 320U, "%s", entry);
    if ((*count > 0U && pm_append(builder, ",") != 0) || pm_append_json_string(builder, entry) != 0) return -1;
    ++*count;
    return 0;
}

/*
 * publicStunServers (Java PeerMeshService.publicStunServers): the standalone alternate STUN
 * address on the primary STUN port first, then the configured public servers, trimmed, without
 * repeats and at most 16.
 */
static int pm_append_public_stun_servers(pm_builder *builder)
{
    char seen[16][320];
    size_t count = 0U;
    if (pm_append(builder, "[") != 0) return -1;
    char alternate[256];
    pm_trim_copy(getenv("SPECUS_PEER_MESH_STANDALONE_STUN_ALTERNATE_ADDRESS"), alternate, sizeof(alternate));
    int port = pm_stun_port();
    if (alternate[0] != '\0' && port > 0) {
        char entry[320];
        int bracket = strchr(alternate, ':') != NULL && alternate[0] != '[';
        snprintf(entry, sizeof(entry), "stun:%s%s%s:%d", bracket ? "[" : "", alternate, bracket ? "]" : "", port);
        if (pm_append_stun_entry(builder, seen, &count, entry) != 0) return -1;
    }
    const char *configured = getenv("SPECUS_PEER_MESH_PUBLIC_STUN_SERVERS");
    if (configured != NULL && *configured != '\0') {
        char *copy = strdup(configured);
        if (copy == NULL) return -1;
        char *save = NULL;
        for (char *item = strtok_r(copy, ",", &save); item != NULL; item = strtok_r(NULL, ",", &save)) {
            char entry[320];
            pm_trim_copy(item, entry, sizeof(entry));
            if (pm_append_stun_entry(builder, seen, &count, entry) != 0) {
                free(copy);
                return -1;
            }
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
                                      const st_storage_peer_mesh_config_service *service)
{
    if (pm_append(builder, "[") != 0) return -1;
    for (size_t i = 0; i < service->allowed_peer_count; ++i) {
        if ((i > 0 && pm_append(builder, ",") != 0)
            || pm_append_json_string(builder, service->allowed_peer_ips[i]) != 0) return -1;
    }
    return pm_append(builder, "]");
}

static int pm_append_local_services(pm_builder *builder,
                                    const st_storage_peer_mesh_config *config)
{
    if (pm_append(builder, "[") != 0) return -1;
    int first = 1;
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < config->service_count; ++i) {
        const st_storage_peer_mesh_service *service = &config->services[i].service;
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
            || pm_append_allowed_peer_ips(builder, &config->services[i]) != 0
            || pm_append(builder, "}") != 0) rc = -1;
        first = 0;
    }
    return rc == 0 ? pm_append(builder, "]") : -1;
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

/*
 * Java PeerServiceDiscovery.requireTargetHost, step by step, with the message each refusal carries:
 * a blank value, anything shaped like a URL, a name other than localhost, an address that is not
 * written canonically (Java compares the text with InetAddress.getHostAddress), the wildcard and
 * multicast addresses, and an address that is not loopback, link-local, site-local or unique-local.
 */
const char *st_peer_mesh_local_host_refusal(const char *value, char out[256])
{
    char host[256];
    const char *start = value == NULL ? "" : value;
    while ((unsigned char)*start <= ' ' && *start != '\0') ++start;
    const char *end = start + strlen(start);
    while (end > start && (unsigned char)end[-1] <= ' ') --end;
    if (end == start) return "targetHost is required";
    if ((size_t)(end - start) >= sizeof(host)) return "targetHost must be a unicast IP or localhost";
    memcpy(host, start, (size_t)(end - start));
    host[end - start] = '\0';
    if (strpbrk(host, "/\\@?#") != NULL) return "targetHost must be a local address, not a URL";
    size_t len = strlen(host);
    if (host[0] == '[' && len >= 2U && host[len - 1U] == ']') {
        memmove(host, host + 1, len - 2U);
        host[len - 2U] = '\0';
    }
    if (strcasecmp(host, "localhost") == 0) {
        snprintf(out, 256U, "127.0.0.1");
        return NULL;
    }
    int numeric = strchr(host, ':') != NULL || (host[0] != '\0' && strspn(host, "0123456789.") == strlen(host));
    if (!numeric) return "targetHost must be a numeric local address or localhost";
    struct in_addr ipv4;
    if (strchr(host, ':') == NULL) {
        if (inet_pton(AF_INET, host, &ipv4) != 1 || inet_ntop(AF_INET, &ipv4, out, 256U) == NULL
            || strcmp(out, host) != 0) {
            return "targetHost must be a unicast IP or localhost";
        }
        uint32_t address = ntohl(ipv4.s_addr);
        if (address == 0U || (address >> 28U) == 0xEU) return "targetHost cannot be wildcard or multicast";
        int local = (address >> 24U) == 127U || (address >> 24U) == 10U
            || (address >> 20U) == 0xAC1U || (address >> 16U) == 0xC0A8U
            || (address >> 16U) == 0xA9FEU;
        return local ? NULL : "targetHost must be loopback or a local interface address";
    }
    struct in6_addr ipv6;
    if (inet_pton(AF_INET6, host, &ipv6) != 1) return "targetHost must be a unicast IP or localhost";
    if (IN6_IS_ADDR_UNSPECIFIED(&ipv6) || IN6_IS_ADDR_MULTICAST(&ipv6)) {
        return "targetHost cannot be wildcard or multicast";
    }
    const unsigned char *bytes = ipv6.s6_addr;
    int loopback = IN6_IS_ADDR_LOOPBACK(&ipv6);
    int link_local = bytes[0] == 0xfeU && (bytes[1] & 0xc0U) == 0x80U;
    /* fec0::/10, which Java's isSiteLocalAddress still counts as local. */
    int site_local = bytes[0] == 0xfeU && (bytes[1] & 0xc0U) == 0xc0U;
    int unique_local = (bytes[0] & 0xfeU) == 0xfcU;
    if (!loopback && !link_local && !site_local && !unique_local) {
        return "targetHost must be loopback or a local interface address";
    }
    return inet_ntop(AF_INET6, &ipv6, out, 256U) == NULL ? "targetHost must be a unicast IP or localhost" : NULL;
}

static int pm_normalize_local_host(const char *value, char out[256])
{
    return st_peer_mesh_local_host_refusal(value, out) == NULL ? 0 : -1;
}

int st_peer_mesh_normalize_local_host(const char *value, char out[256])
{
    return pm_normalize_local_host(value, out);
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
    st_storage_client *clients = NULL;
    size_t count = 0U;
    if (st_storage_list_all_clients(runtime->database_path, &clients, &count) != 0) return 0;
    int found = 0;
    for (size_t i = 0; !found && i < count; ++i) {
        int allowed = 0;
        found = clients[i].id != publisher->id
            && strcmp(clients[i].tenant_id, publisher->tenant_id) == 0
            && clients[i].enabled
            && st_storage_can_peer(runtime->database_path, publisher, &clients[i], &allowed) == 0
            && allowed
            && runtime->online != NULL
            && runtime->online(runtime->ctx, clients[i].id, clients[i].client_name);
    }
    free(clients);
    return found;
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
    st_storage_peer_mesh_service_sharing sharing = {0};
    if (authorized && catalog->active
        && (st_storage_get_peer_mesh_service_sharing(runtime->database_path, catalog->tenant_id, &sharing) != 0
            || !sharing.enabled)) authorized = 0;
    char expires_at[32];
    pm_format_instant(catalog->expires_at, expires_at);
    pm_builder builder = {0};
    st_storage_peer_mesh_service *definitions = NULL;
    size_t count = 0U;
    if (pm_appendf(&builder,
                   "{\"type\":\"service-catalog\",\"publisherClientId\":%lld,\"publisherClientName\":",
                   catalog->publisher_client_id) != 0
        || pm_append_json_string(&builder, catalog->publisher_client_name) != 0
        || pm_appendf(&builder, ",\"publisherSessionId\":%lld,\"revision\":%lld,\"expiresAt\":",
                      catalog->publisher_session_id, catalog->catalog_revision) != 0
        || pm_append_json_string(&builder, expires_at) != 0
        || pm_append(&builder, ",\"services\":[") != 0) goto failed;
    if (authorized && catalog->active
        && st_storage_list_peer_mesh_services_visible(runtime->database_path, publisher->tenant_id,
                                                       "", 1, &definitions, &count) != 0) goto failed;
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
    free(definitions);
    return builder.data;
failed:
    free(definitions);
    free(builder.data);
    return NULL;
}

static int pm_fanout_catalog(const st_peer_mesh_runtime *runtime,
                             const pm_catalog *catalog,
                             const st_storage_client *publisher)
{
    if (catalog->catalog_revision < 1) return -1;
    st_storage_client *clients = NULL;
    size_t count = 0U;
    if (st_storage_list_all_clients(runtime->database_path, &clients, &count) != 0) return -1;
    int rc = 0;
    for (size_t i = 0; i < count; ++i) {
        st_storage_client *recipient = &clients[i];
        if (recipient->id == publisher->id
            || strcmp(recipient->tenant_id, publisher->tenant_id) != 0
            || runtime->online == NULL
            || !runtime->online(runtime->ctx, recipient->id, recipient->client_name)) continue;
        int allowed = 0;
        if (catalog->active && st_storage_can_peer(runtime->database_path, publisher, recipient, &allowed) != 0) {
            rc = -1;
            continue;
        }
        char *message = pm_build_catalog_message(runtime, catalog, publisher, recipient, allowed);
        if (message == NULL
            || runtime->send(runtime->ctx, recipient->client_name, "server", message) != 0) rc = -1;
        free(message);
    }
    free(clients);
    return rc;
}

typedef struct {
    const st_peer_mesh_runtime *runtime;
    const pm_catalog *incoming;
    const char *instance_id;
    st_peer_mesh_mdns_candidate *incoming_mdns;
    size_t incoming_mdns_count;
    long long revision, ttl;
    int report_enabled, online_hint, outcome, advances, reserved;
    pm_catalog *slot;
    pm_catalog staged;
} pm_report_lease;

/* Only immutable reservation identity is read here; the SQL callback changes other staged
 * fields without a cache lock. Even a previously empty/expired slot has an owned pending key. */
static int pm_pending_report_for(const pm_catalog *catalog, long long cid, const char *tenant, long long sid)
{
    const pm_report_lease *lease = catalog->pending_report;
    return lease != NULL && lease->staged.publisher_client_id == cid
        && (sid <= 0 || lease->staged.publisher_session_id == sid)
        && strcmp(lease->staged.tenant_id, tenant) == 0;
}

static int pm_same_control_source(const pm_catalog *catalog, const st_storage_control_source *source)
{
    if (catalog->has_control_source != (source != NULL)) return 0;
    if (source == NULL) return 1; /* Explicit trusted service call, not network fallback. */
    const st_storage_control_source *old = &catalog->control_source;
    return old->client_id == source->client_id && old->session_id == source->session_id
        && !strncmp(old->tenant_id, source->tenant_id, sizeof(old->tenant_id))
        && !strncmp(old->client_name, source->client_name, sizeof(old->client_name))
        && !strncmp(old->channel_id, source->channel_id, sizeof(old->channel_id))
        && !strncmp(old->token_hash, source->token_hash, sizeof(old->token_hash));
}

/* Reserve a bounded cell and future output-clock budget BEFORE taking the native writer.
 * A lease is nonblocking: no cache mutex is retained while waiting for SQLite or sockets.
 * Even eviction of an expired other publisher remains private until the native commit. */
static int pm_report_prepare(pm_report_lease *lease, const st_storage_client *source)
{
    const st_peer_mesh_runtime *runtime = lease->runtime;
    if (!pm_has_text(runtime->database_path) || strlen(runtime->database_path) >= 512U) return -1;
    time_t now = time(NULL); pm_catalog *slot = NULL, *unused = NULL; int existing = 0;
    pthread_mutex_lock(&peer_catalog_lock);
    for (size_t i = 0; i < ST_PEER_MESH_MAX_CATALOGS; ++i) {
        pm_catalog *catalog = &peer_catalogs[i];
        if (pm_pending_report_for(catalog, source->id, source->tenant_id, runtime->publisher_session_id)) {
            pthread_mutex_unlock(&peer_catalog_lock); return -1;
        }
        if (catalog->in_use && catalog->publisher_client_id == source->id
            && catalog->publisher_session_id == runtime->publisher_session_id
            && !strcmp(catalog->tenant_id, source->tenant_id)) { slot = catalog; existing = 1; break; }
        if (catalog->pending_report == NULL && (!catalog->in_use || catalog->expires_at < now)) unused = catalog;
    }
    if (slot == NULL) slot = unused;
    if (slot == NULL || slot->pending_report != NULL
        || (existing && *slot->database_path && strcmp(slot->database_path, runtime->database_path))) {
        pthread_mutex_unlock(&peer_catalog_lock); return -1;
    }
    if (existing && pm_same_control_source(slot, runtime->control_source)) lease->staged = *slot;
    else {
        memset(&lease->staged, 0, sizeof(lease->staged));
        if (existing) lease->staged.catalog_revision = slot->catalog_revision;
    }
    pm_catalog *staged = &lease->staged;
    staged->pending_report = NULL; staged->in_use = 1;
    snprintf(staged->database_path, sizeof(staged->database_path), "%s", runtime->database_path);
    snprintf(staged->tenant_id, sizeof(staged->tenant_id), "%s", source->tenant_id);
    snprintf(staged->publisher_client_name, sizeof(staged->publisher_client_name), "%s", source->client_name);
    staged->publisher_client_id = source->id; staged->publisher_session_id = runtime->publisher_session_id;
    staged->has_control_source = runtime->control_source != NULL;
    if (runtime->control_source != NULL) staged->control_source = *runtime->control_source;
    /* Duplicates consume the valid source's rate window, but require no new wire revision. */
    if (lease->revision > staged->report_revision) {
        long long floor = peer_catalog_sequence > staged->catalog_revision ? peer_catalog_sequence : staged->catalog_revision;
        if (floor >= LLONG_MAX - (long long)peer_catalog_reserved_revisions) {
            pthread_mutex_unlock(&peer_catalog_lock); return -1;
        }
        ++peer_catalog_reserved_revisions; lease->reserved = 1;
    }
    slot->pending_report = lease; lease->slot = slot;
    pthread_mutex_unlock(&peer_catalog_lock);
    return 0;
}

static void pm_report_abort(pm_report_lease *lease)
{
    if (lease->slot == NULL) return;
    pthread_mutex_lock(&peer_catalog_lock);
    if (lease->slot->pending_report == lease) lease->slot->pending_report = NULL;
    if (lease->reserved) { --peer_catalog_reserved_revisions; lease->reserved = 0; }
    lease->slot = NULL;
    pthread_mutex_unlock(&peer_catalog_lock);
}

/* Called inside the guarded SQLite writer: private memory and clocks only, no SQL, locks or I/O. */
static int pm_report_stage(void *context, const st_storage_client *current,
    const st_storage_peer_mesh_device *device, const st_storage_peer_mesh_service_sharing *sharing,
    const char **reason)
{
    pm_report_lease *lease = context; pm_catalog *staged = &lease->staged;
    if (!pm_rate_window_admit(&staged->rate, pm_monotonic_ms(), ST_PEER_REPORT_RATE_LIMIT, 60000LL)) {
        lease->outcome = 2; *reason = "rate-limited"; return 0;
    }
    if (lease->revision <= staged->report_revision) {
        lease->outcome = 1; *reason = "ignored-revision"; return 0;
    }
    if (!lease->reserved) return -1;
    int sharing_enabled = sharing->enabled && device->enabled;
    staged->active = lease->report_enabled && sharing_enabled && lease->online_hint;
    staged->report_revision = lease->revision; lease->advances = 1;
    staged->generated_at = time(NULL); staged->expires_at = staged->generated_at + (time_t)lease->ttl;
    snprintf(staged->publisher_client_name, sizeof(staged->publisher_client_name), "%s", current->client_name);
    snprintf(staged->instance_id, sizeof(staged->instance_id), "%s", lease->instance_id == NULL ? "" : lease->instance_id);
    staged->service_count = lease->incoming->service_count;
    memcpy(staged->service_ids, lease->incoming->service_ids, sizeof(staged->service_ids));
    staged->stats_count = lease->incoming->stats_count;
    memcpy(staged->stats, lease->incoming->stats, sizeof(staged->stats));
    staged->mdns_candidates = staged->active && sharing->mdns_import_enabled ? lease->incoming_mdns : NULL;
    staged->mdns_count = staged->mdns_candidates == NULL ? 0U : lease->incoming_mdns_count;
    *reason = staged->active ? (staged->service_count == 0U ? "empty" : "published")
        : (!lease->report_enabled || !sharing_enabled ? "withdrawn" : "no-authorized-peer");
    return 0;
}

static int pm_report_commit(pm_report_lease *lease, pm_catalog *snapshot)
{
    pthread_mutex_lock(&peer_catalog_lock);
    if (lease->slot == NULL || lease->slot->pending_report != lease) {
        pthread_mutex_unlock(&peer_catalog_lock); pm_report_abort(lease); return -1;
    }
    if (lease->reserved) { --peer_catalog_reserved_revisions; lease->reserved = 0; }
    if (lease->advances) {
        lease->staged.catalog_revision = pm_next_catalog_revision_locked(lease->staged.catalog_revision);
        if (lease->staged.catalog_revision == 0) {
            lease->slot->pending_report = NULL; lease->slot = NULL;
            pthread_mutex_unlock(&peer_catalog_lock); return -1;
        }
    }
    st_peer_mesh_mdns_candidate *old_mdns = lease->slot->mdns_candidates;
    lease->staged.pending_report = NULL;
    *lease->slot = lease->staged; *snapshot = lease->staged;
    if (old_mdns != snapshot->mdns_candidates) free(old_mdns);
    if (snapshot->mdns_candidates == lease->incoming_mdns) lease->incoming_mdns = NULL;
    lease->slot = NULL;
    pthread_mutex_unlock(&peer_catalog_lock);
    return 0;
}

static pm_catalog *pm_find_catalog_locked(long long cid, const char *tenant, long long sid)
{
    for (size_t i = 0; i < ST_PEER_MESH_MAX_CATALOGS; ++i) {
        pm_catalog *catalog = &peer_catalogs[i];
        if (pm_pending_report_for(catalog, cid, tenant, sid)) return catalog;
        if (catalog->in_use && catalog->publisher_client_id == cid && catalog->publisher_session_id == sid
            && strcmp(catalog->tenant_id, tenant) == 0) return catalog;
    }
    return NULL;
}

int st_peer_mesh_control_connected_prepare(const st_peer_mesh_runtime *runtime,
                                           const char *client_name, st_peer_mesh_control_transition **out)
{
    if (out == NULL) return -1;
    *out = NULL;
    if (runtime == NULL) return -1;
    if (!pm_env_bool("SPECUS_PEER_MESH_ENABLED", 0) || runtime->publisher_session_id <= 0) return 0;
    if (!pm_has_text(runtime->database_path) || strlen(runtime->database_path) >= 512U
        || runtime->authenticated_client_id <= 0 || !pm_has_text(runtime->authenticated_tenant)
        || strlen(runtime->authenticated_tenant) >= 64U || !pm_has_text(client_name) || strlen(client_name) >= 256U) return -1;
    pthread_mutex_lock(&peer_catalog_lock);
    pm_catalog *found_catalog = pm_find_catalog_locked(runtime->authenticated_client_id, runtime->authenticated_tenant,
                                      runtime->publisher_session_id);
    int found = found_catalog != NULL, busy = found_catalog != NULL && found_catalog->pending_report != NULL;
    pthread_mutex_unlock(&peer_catalog_lock);
    if (busy) return -1;
    if (!found) return 0;
    st_peer_mesh_control_transition *item = calloc(1, sizeof(*item));
    if (item == NULL) return -1;
    snprintf(item->database_path, sizeof(item->database_path), "%s", runtime->database_path);
    snprintf(item->tenant_id, sizeof(item->tenant_id), "%s", runtime->authenticated_tenant);
    snprintf(item->publisher_client_name, sizeof(item->publisher_client_name), "%s", client_name);
    item->publisher_client_id = runtime->authenticated_client_id;
    item->publisher_session_id = runtime->publisher_session_id;
    pthread_mutex_lock(&peer_catalog_lock);
    found_catalog = pm_find_catalog_locked(item->publisher_client_id, item->tenant_id, item->publisher_session_id);
    found = found_catalog != NULL;
    if (!found) { pthread_mutex_unlock(&peer_catalog_lock); free(item); return 0; }
    if (found_catalog->pending_report != NULL || peer_control_withdrawal_count >= ST_PEER_MESH_MAX_CATALOGS
        || peer_catalog_sequence >= LLONG_MAX - (long long)peer_catalog_reserved_revisions) {
        pthread_mutex_unlock(&peer_catalog_lock); free(item); return -1;
    }
    ++peer_control_withdrawal_count;
    ++peer_catalog_reserved_revisions;
    pthread_mutex_unlock(&peer_catalog_lock);
    *out = item;
    return 0;
}

void st_peer_mesh_control_connected_abort(st_peer_mesh_control_transition *item)
{
    if (item == NULL) return;
    pthread_mutex_lock(&peer_catalog_lock);
    --peer_catalog_reserved_revisions;
    --peer_control_withdrawal_count;
    pthread_mutex_unlock(&peer_catalog_lock);
    free(item);
}

int st_peer_mesh_control_connected_commit(st_peer_mesh_control_transition *item)
{
    if (item == NULL) return 0;
    pthread_mutex_lock(&peer_catalog_lock);
    --peer_catalog_reserved_revisions;
    pm_catalog *catalog = pm_find_catalog_locked(item->publisher_client_id, item->tenant_id, item->publisher_session_id);
    if (catalog == NULL || catalog->pending_report != NULL) {
        --peer_control_withdrawal_count;
        int rc = catalog == NULL ? 0 : -1;
        pthread_mutex_unlock(&peer_catalog_lock); free(item); return rc;
    }
    item->revision = pm_next_catalog_revision_locked(catalog->catalog_revision);
    if (item->revision == 0) {
        --peer_control_withdrawal_count;
        pthread_mutex_unlock(&peer_catalog_lock); free(item); return -1;
    }
    item->expires_at = time(NULL);
    free(catalog->mdns_candidates);
    memset(catalog, 0, sizeof(*catalog)); /* Includes the raw cursor, rate window, stats and mDNS. */
    if (peer_control_withdrawal_tail != NULL) peer_control_withdrawal_tail->next = item;
    else peer_control_withdrawal_head = item;
    peer_control_withdrawal_tail = item;
    pthread_mutex_unlock(&peer_catalog_lock);
    return 0;
}

/* Dispatcher ownership is required. A failed item retains its capacity charge and exact wire
 * revision. Different publisher keys can progress while maintenance retries a failing peer. */
static int pm_drain_control_withdrawal(const st_peer_mesh_runtime *runtime, long long cid,
                                      const char *tenant, long long sid)
{
    pthread_mutex_lock(&peer_catalog_lock);
    st_peer_mesh_control_transition *previous = NULL, *item = peer_control_withdrawal_head;
    while (item != NULL && (strcmp(item->database_path, runtime->database_path) != 0
        || (cid > 0 && (item->publisher_client_id != cid || item->publisher_session_id != sid
                        || strcmp(item->tenant_id, tenant) != 0)))) { previous = item; item = item->next; }
    if (item != NULL) {
        if (previous != NULL) previous->next = item->next;
        else peer_control_withdrawal_head = item->next;
        if (peer_control_withdrawal_tail == item) peer_control_withdrawal_tail = previous;
        item->next = NULL;
    }
    pthread_mutex_unlock(&peer_catalog_lock);
    if (item == NULL) return 0;
    int rc = 0;
    if (!item->audited) {
        rc = st_storage_record_peer_mesh_service_audit(runtime->database_path, "publisher-offline", item->tenant_id,
            item->publisher_client_id, item->publisher_session_id, NULL, "control-reconnected");
        if (rc == 0) item->audited = 1;
    }
    if (rc == 0) {
        pm_catalog snapshot = {0};
        st_storage_client publisher = {0};
        snapshot.publisher_client_id = publisher.id = item->publisher_client_id;
        snapshot.publisher_session_id = item->publisher_session_id;
        snapshot.catalog_revision = item->revision;
        snapshot.expires_at = item->expires_at;
        snprintf(snapshot.tenant_id, sizeof(snapshot.tenant_id), "%s", item->tenant_id);
        snprintf(snapshot.publisher_client_name, sizeof(snapshot.publisher_client_name), "%s", item->publisher_client_name);
        snprintf(publisher.tenant_id, sizeof(publisher.tenant_id), "%s", item->tenant_id);
        snprintf(publisher.client_name, sizeof(publisher.client_name), "%s", item->publisher_client_name);
        rc = pm_fanout_catalog(runtime, &snapshot, &publisher);
    }
    pthread_mutex_lock(&peer_catalog_lock);
    if (rc != 0) {
        if (peer_control_withdrawal_tail != NULL) peer_control_withdrawal_tail->next = item;
        else peer_control_withdrawal_head = item;
        peer_control_withdrawal_tail = item;
    } else --peer_control_withdrawal_count;
    pthread_mutex_unlock(&peer_catalog_lock);
    if (rc == 0) free(item);
    return rc == 0 ? 1 : -1;
}

int st_peer_mesh_drain_control_withdrawals(const st_peer_mesh_runtime *runtime)
{
    if (runtime == NULL || !pm_has_text(runtime->database_path) || runtime->send == NULL || runtime->online == NULL) return -1;
    if (pthread_mutex_trylock(&peer_snapshot_dispatch_lock) != 0) return 0;
    int rc = 0;
    for (size_t i = 0; i < 64U; ++i) {
        int drained = pm_drain_control_withdrawal(runtime, 0, NULL, 0);
        if (drained <= 0) { rc = drained; break; }
    }
    pthread_mutex_unlock(&peer_snapshot_dispatch_lock);
    return rc;
}

/*
 * Placeholder catalogues belong to no tenant and no client, and never expire. They take the slots a
 * new session could have: free ones and those whose catalogue has expired.
 */
int st_peer_mesh_catalogs_occupy_for_testing(size_t count)
{
    size_t occupied = 0U;
    time_t now = time(NULL);
    pthread_mutex_lock(&peer_catalog_lock);
    for (size_t i = 0U; i < ST_PEER_MESH_MAX_CATALOGS && occupied < count; ++i) {
        pm_catalog *catalog = &peer_catalogs[i];
        if (catalog->pending_report != NULL || (catalog->in_use && catalog->expires_at >= now)) continue;
        free(catalog->mdns_candidates);
        memset(catalog, 0, sizeof(*catalog));
        catalog->in_use = 1;
        catalog->publisher_client_id = -1;
        catalog->expires_at = (time_t)INT_MAX;
        ++occupied;
    }
    pthread_mutex_unlock(&peer_catalog_lock);
    return occupied == count ? 0 : -1;
}

void st_peer_mesh_catalogs_release_for_testing(void)
{
    pthread_mutex_lock(&peer_catalog_lock);
    for (size_t i = 0U; i < ST_PEER_MESH_MAX_CATALOGS; ++i) {
        if (peer_catalogs[i].in_use && peer_catalogs[i].publisher_client_id == -1) {
            memset(&peer_catalogs[i], 0, sizeof(peer_catalogs[i]));
        }
    }
    pthread_mutex_unlock(&peer_catalog_lock);
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
    (void)source_device; /* Enabled/sharing are reloaded under the guarded native writer. */
    pm_report_lease lease = {.runtime=runtime, .incoming=&incoming, .instance_id=instance_id,
        .revision=revision, .report_enabled=report_enabled, .incoming_mdns_count=incoming_mdns_count};
    lease.online_hint = pm_has_authorized_online_peer(runtime, source); /* Never called under SQL/cache locks. */
    lease.ttl = pm_env_i64("SPECUS_PEER_MESH_CATALOG_TTL_SECONDS", ST_PEER_MESH_CATALOG_TTL_SECONDS);
    if (lease.ttl < 1 || lease.ttl > 86400) lease.ttl = ST_PEER_MESH_CATALOG_TTL_SECONDS;
    if (incoming_mdns_count > 0U) {
        lease.incoming_mdns = calloc(incoming_mdns_count, sizeof(*lease.incoming_mdns));
        if (lease.incoming_mdns == NULL) {
            free(instance_id);
            return -1;
        }
        memcpy(lease.incoming_mdns, incoming_mdns, incoming_mdns_count * sizeof(*lease.incoming_mdns));
    }
    pm_catalog snapshot; st_storage_client committed = {0};
    int rc = pm_report_prepare(&lease, source);
    if (rc == 0) rc = runtime->control_source == NULL
        ? st_storage_commit_peer_service_report(runtime->database_path, source, runtime->publisher_session_id,
            pm_report_stage, &lease, &committed)
        : st_storage_commit_peer_service_report_from_control(runtime->database_path, runtime->control_source,
            source, runtime->publisher_session_id, pm_report_stage, &lease, &committed);
    if (rc == 0) rc = pm_report_commit(&lease, &snapshot);
    if (rc != 0) pm_report_abort(&lease);
    else if (lease.outcome == 2) rc = -1;
    else if (lease.outcome == 0) rc = pm_fanout_catalog(runtime, &snapshot, &committed);
    free(lease.incoming_mdns);
    free(instance_id);
    return rc;
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
    int rc = 0;
    pthread_mutex_lock(&peer_catalog_lock);
    for (size_t i = 0; i < ST_PEER_MESH_MAX_CATALOGS; ++i) {
        pm_catalog *catalog = &peer_catalogs[i];
        if (catalog->pending_report != NULL || !catalog->in_use || !catalog->active || catalog->expires_at > now) continue;
        long long revision = pm_next_catalog_revision_locked(catalog->catalog_revision);
        if (revision == 0) { rc = -1; continue; }
        catalog->active = 0;
        catalog->expires_at = now;
        catalog->catalog_revision = revision;
        catalog->service_count = 0U;
        snapshots[count++] = *catalog;
        free(catalog->mdns_candidates);
        catalog->mdns_candidates = NULL;
        catalog->mdns_count = 0U;
    }
    pthread_mutex_unlock(&peer_catalog_lock);
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
    if ((runtime->authenticated_client_id > 0 && publisher.id != runtime->authenticated_client_id)
        || (runtime->authenticated_tenant != NULL && strcmp(publisher.tenant_id, runtime->authenticated_tenant) != 0)) return -1;
    pm_catalog snapshot;
    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.in_use = 1;
    snapshot.publisher_client_id = publisher.id;
    snapshot.publisher_session_id = runtime->publisher_session_id;
    snprintf(snapshot.tenant_id, sizeof(snapshot.tenant_id), "%s", publisher.tenant_id);
    snprintf(snapshot.publisher_client_name, sizeof(snapshot.publisher_client_name), "%s",
             publisher.client_name);
    snapshot.catalog_revision = 0;
    snapshot.expires_at = time(NULL);
    pthread_mutex_lock(&peer_catalog_lock);
    for (size_t i = 0; i < ST_PEER_MESH_MAX_CATALOGS; ++i) {
        pm_catalog *catalog = &peer_catalogs[i];
        if (pm_pending_report_for(catalog, publisher.id, publisher.tenant_id, runtime->publisher_session_id)) {
            pthread_mutex_unlock(&peer_catalog_lock); return -1;
        }
        if (!catalog->in_use || catalog->publisher_client_id != publisher.id
            || catalog->publisher_session_id != runtime->publisher_session_id
            || strcmp(catalog->tenant_id, publisher.tenant_id) != 0) continue;
        if (catalog->pending_report != NULL) { pthread_mutex_unlock(&peer_catalog_lock); return -1; }
        long long revision = pm_next_catalog_revision_locked(catalog->catalog_revision);
        if (revision == 0) { pthread_mutex_unlock(&peer_catalog_lock); return -1; }
        snapshot = *catalog;
        snapshot.active = 0;
        snapshot.expires_at = time(NULL);
        snapshot.catalog_revision = revision;
        snapshot.service_count = 0U;
        free(catalog->mdns_candidates);
        memset(catalog, 0, sizeof(*catalog));
        break;
    }
    if (snapshot.catalog_revision == 0) snapshot.catalog_revision = pm_next_catalog_revision_locked(0);
    pthread_mutex_unlock(&peer_catalog_lock);
    (void)st_storage_record_peer_mesh_service_audit(runtime->database_path,
        "publisher-offline", publisher.tenant_id, publisher.id,
        runtime->publisher_session_id, NULL, "disconnected");
    return pm_fanout_catalog(runtime, &snapshot, &publisher);
}

static void pm_enqueue_deletion(pm_client_deletion *item)
{
    item->next = NULL;
    pthread_mutex_lock(&peer_deletion_queue_lock);
    if (peer_deletion_tail == NULL) peer_deletion_head = item;
    else peer_deletion_tail->next = item;
    peer_deletion_tail = item;
    pthread_mutex_unlock(&peer_deletion_queue_lock);
}

int st_peer_mesh_queue_client_deleted(const st_storage_client *client,
                                      const st_storage_peer_close *closed, size_t closed_count)
{
    if (client == NULL || client->id <= 0 || !pm_has_text(client->tenant_id)
        || (closed_count != 0U && closed == NULL)
        || closed_count > SIZE_MAX / sizeof(*closed)) return -1;
    if (!pm_env_bool("SPECUS_PEER_MESH_ENABLED", 0)) return 0;
    pm_client_deletion *item = calloc(1U, sizeof(*item));
    if (item == NULL) return -1;
    item->client = *client;
    if (closed_count != 0U) {
        item->closed = malloc(closed_count * sizeof(*closed));
        if (item->closed == NULL) { free(item); return -1; }
        memcpy(item->closed, closed, closed_count * sizeof(*closed));
    }
    item->closed_count = closed_count;
    pm_enqueue_deletion(item);
    return 0;
}

static int pm_prepare_deleted_catalogs(pm_client_deletion *item)
{
    if (item->prepared) return 0;
    pthread_mutex_lock(&peer_catalog_lock);
    size_t count = 0U;
    long long floor = peer_catalog_sequence;
    for (size_t i = 0U; i < ST_PEER_MESH_MAX_CATALOGS; ++i) {
        const pm_catalog *catalog = &peer_catalogs[i];
        if (pm_pending_report_for(catalog, item->client.id, item->client.tenant_id, 0)
            || (catalog->in_use && catalog->publisher_client_id == item->client.id
                && strcmp(catalog->tenant_id, item->client.tenant_id) == 0 && catalog->pending_report != NULL)) {
            pthread_mutex_unlock(&peer_catalog_lock); return -1;
        }
        if (catalog->in_use && catalog->publisher_client_id == item->client.id
            && strcmp(catalog->tenant_id, item->client.tenant_id) == 0) {
            ++count;
            if (catalog->catalog_revision > floor) floor = catalog->catalog_revision;
        }
    }
    if (peer_catalog_reserved_revisions > (unsigned long long)(LLONG_MAX - floor)
        || count > (unsigned long long)(LLONG_MAX - floor) - peer_catalog_reserved_revisions) {
        pthread_mutex_unlock(&peer_catalog_lock);
        return -1;
    }
    pm_catalog *withdrawals = count == 0U ? NULL : calloc(count, sizeof(*withdrawals));
    if (count != 0U && withdrawals == NULL) {
        pthread_mutex_unlock(&peer_catalog_lock);
        return -1;
    }
    peer_catalog_sequence = floor;
    size_t index = 0U;
    for (size_t i = 0U; i < ST_PEER_MESH_MAX_CATALOGS; ++i) {
        pm_catalog *catalog = &peer_catalogs[i];
        if (!catalog->in_use || catalog->publisher_client_id != item->client.id
            || strcmp(catalog->tenant_id, item->client.tenant_id) != 0) continue;
        pm_catalog *snapshot = &withdrawals[index++];
        *snapshot = *catalog;
        snapshot->active = 0;
        snapshot->expires_at = time(NULL);
        snapshot->catalog_revision = pm_next_catalog_revision_locked(snapshot->catalog_revision);
        snapshot->service_count = 0U;
        snapshot->stats_count = 0U;
        snapshot->mdns_candidates = NULL;
        snapshot->mdns_count = 0U;
        free(catalog->mdns_candidates);
        memset(catalog, 0, sizeof(*catalog));
    }
    /* The queue owns the withdrawal identities/revisions before cached state disappears. */
    item->withdrawals = withdrawals;
    item->withdrawal_count = count;
    item->prepared = 1;
    pthread_mutex_unlock(&peer_catalog_lock);
    return 0;
}

static char *pm_closed_session_message(const st_storage_peer_close *closed, const char *reason)
{
    pm_builder builder = {0};
    if (pm_appendf(&builder, "{\"type\":\"close\",\"sessionId\":%lld,\"sourceClientId\":%lld,\"sourceClientName\":",
                   closed->id, closed->source_client_id) != 0
        || pm_append_json_string(&builder, closed->source_client_name) != 0
        || pm_appendf(&builder, ",\"targetClientId\":%lld,\"targetClientName\":", closed->target_client_id) != 0
        || pm_append_json_string(&builder, closed->target_client_name) != 0
        || pm_append(&builder, ",\"status\":\"CLOSED\",\"reason\":") != 0
        || pm_append_json_string(&builder, reason) != 0
        || pm_appendf(&builder, ",\"createdAtMillis\":%lld}",
                      (long long)time(NULL) * 1000LL) != 0) {
        free(builder.data);
        return NULL;
    }
    return builder.data;
}

static int pm_dispatch_deleted_client(const st_peer_mesh_runtime *runtime, pm_client_deletion *item)
{
    if (pm_prepare_deleted_catalogs(item) != 0) return -1;
    st_storage_client *clients = NULL;
    size_t count = 0U;
    if (st_storage_list_all_clients(runtime->database_path, &clients, &count) != 0) return -1;
    int rc = 0;
    for (size_t i = 0U; i < count; ++i) {
        const st_storage_client *recipient = &clients[i];
        if (recipient->id == item->client.id || strcmp(recipient->tenant_id, item->client.tenant_id) != 0
            || !runtime->online(runtime->ctx, recipient->id, recipient->client_name)) continue;
        for (size_t j = 0U; j < item->closed_count; ++j) {
            const st_storage_peer_close *closed = &item->closed[j];
            if (strcmp(closed->tenant_id, recipient->tenant_id) != 0
                || (closed->source_client_id != recipient->id && closed->target_client_id != recipient->id)) continue;
            char *message = pm_closed_session_message(closed, "client-deleted");
            if (message == NULL || runtime->send(runtime->ctx, recipient->client_name, "server", message) != 0) rc = -1;
            free(message);
        }
        for (size_t j = 0U; j < item->withdrawal_count; ++j) {
            char *message = pm_build_catalog_message(runtime, &item->withdrawals[j], &item->client, recipient, 0);
            if (message == NULL || runtime->send(runtime->ctx, recipient->client_name, "server", message) != 0) rc = -1;
            free(message);
        }
    }
    free(clients);
    if (st_peer_mesh_refresh_tenant(runtime, item->client.tenant_id) != 0) rc = -1;
    return rc;
}

int st_peer_mesh_drain_client_deletions(const st_peer_mesh_runtime *runtime)
{
    if (runtime == NULL || runtime->database_path == NULL || runtime->send == NULL || runtime->online == NULL) return -1;
    if (pthread_mutex_trylock(&peer_deletion_dispatch_lock) != 0) return 0;
    int rc = 0;
    for (size_t n = 0U; n < 64U; ++n) {
        pthread_mutex_lock(&peer_deletion_queue_lock);
        pm_client_deletion *item = peer_deletion_head;
        if (item != NULL) {
            peer_deletion_head = item->next;
            if (peer_deletion_head == NULL) peer_deletion_tail = NULL;
        }
        pthread_mutex_unlock(&peer_deletion_queue_lock);
        if (item == NULL) break;
        if (pm_dispatch_deleted_client(runtime, item) != 0) {
            pm_enqueue_deletion(item);
            rc = -1;
            break;
        }
        free(item->closed);
        free(item->withdrawals);
        free(item);
    }
    pthread_mutex_unlock(&peer_deletion_dispatch_lock);
    return rc;
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

static char *pm_runtime_config(const st_storage_peer_mesh_config *config,
                               int client_peer_service_version)
{
    const st_storage_client *client = &config->client;
    const st_storage_peer_mesh_device *device = config->has_device ? &config->device : NULL;
    int deployment_enabled = pm_env_bool("SPECUS_PEER_MESH_ENABLED", 0);
    int enabled = deployment_enabled && device != NULL && device->enabled;
    /*
     * As in Java PeerMeshService.buildConfig, the endpoints and the TURN credential go to every
     * device of an enabled deployment, also one not yet switched on: enabling it later then needs
     * only the peer-config push, not a new login.
     */
    int endpoints = deployment_enabled && device != NULL;
    int turn_port = (int)pm_env_i64("SPECUS_PEER_MESH_STUN_TURN_PORT", 3478);
    const char *turn_host = pm_env_text("SPECUS_PEER_MESH_PUBLIC_ADDRESS",
                                        pm_env_text("SPECUS_PUBLIC_ADDRESS", "127.0.0.1"));
    char stun_host[256];
    int stun_port = 0;
    if (!pm_standalone_stun(stun_host, &stun_port)) {
        snprintf(stun_host, sizeof(stun_host), "%s", turn_host);
        stun_port = turn_port;
    }
    const char *cidr = device != NULL && device->cidr[0] != '\0'
        ? device->cidr : pm_env_text("SPECUS_PEER_MESH_CIDR", "100.96.0.0/11");
    long long ttl = pm_env_i64("SPECUS_PEER_MESH_SESSION_TTL_SECONDS", 3600);
    char ice_username[192] = "";
    char ice_credential[64] = "";
    char subject[64];
    st_storage_peer_mesh_service_sharing sharing = config->sharing;
    int effective_sharing = deployment_enabled && sharing.enabled && enabled;
    snprintf(subject, sizeof(subject), "pm-%lld", client->id);
    if (endpoints) (void)st_turn_auth_issue(subject, ice_username, sizeof(ice_username),
                                            ice_credential, sizeof(ice_credential));
    pm_builder builder = {0};
    if (pm_appendf(&builder, "{\"enabled\":%s,\"clientId\":%lld,\"clientName\":",
                   enabled ? "true" : "false", client->id) != 0
        || pm_append_json_string(&builder, client->client_name) != 0
        || pm_append(&builder, ",\"virtualIp\":") != 0
        || pm_append_json_string(&builder, device == NULL ? "" : device->virtual_ip) != 0
        || pm_append(&builder, ",\"cidr\":") != 0 || pm_append_json_string(&builder, cidr) != 0
        || pm_append(&builder, ",\"stunHost\":") != 0
        || pm_append_json_string(&builder, endpoints ? stun_host : "") != 0
        || pm_appendf(&builder, ",\"stunPort\":%d,\"turnHost\":", endpoints ? stun_port : 0) != 0
        || pm_append_json_string(&builder, endpoints ? turn_host : "") != 0
        || pm_appendf(&builder, ",\"turnPort\":%d,\"publicStunServers\":", endpoints ? turn_port : 0) != 0
        || pm_append_public_stun_servers(&builder) != 0
        || pm_append(&builder, ",\"iceUsername\":") != 0
        || pm_append_json_string(&builder, ice_username) != 0
        || pm_append(&builder, ",\"iceCredential\":") != 0
        || pm_append_json_string(&builder, ice_credential) != 0
        || pm_append(&builder, ",\"iceRealm\":") != 0
        || pm_append_json_string(&builder, st_turn_auth_realm()) != 0
        || pm_append(&builder, ",\"iceNonce\":") != 0
        || pm_append_json_string(&builder, endpoints ? st_turn_auth_nonce() : "") != 0
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
            ? pm_append_local_services(&builder, config)
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
    st_storage_peer_mesh_config snapshot = {0};
    if (database_path == NULL || client_name == NULL
        || st_storage_get_client_by_name(database_path, client_name, &client) != 0) return NULL;
    if (st_storage_load_peer_mesh_config(database_path, &client, pm_env_bool("SPECUS_PEER_MESH_ENABLED", 0),
                                         client_peer_service_version >= 2, &snapshot) != 0) return NULL;
    char *config = pm_runtime_config(&snapshot, client_peer_service_version);
    st_storage_peer_mesh_config_free(&snapshot);
    return config;
}

static int pm_push_config(const st_peer_mesh_runtime *runtime,
                          const st_storage_client *client)
{
    st_storage_peer_mesh_config snapshot = {0};
    if (st_storage_load_peer_mesh_config(runtime->database_path, client, 1,
                                         runtime->peer_service_discovery_version >= 2, &snapshot) != 0) return -1;
    client = &snapshot.client;
    char *config = pm_runtime_config(&snapshot, runtime->peer_service_discovery_version);
    if (config == NULL) { st_storage_peer_mesh_config_free(&snapshot); return -1; }
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
    st_storage_peer_mesh_config_free(&snapshot);
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

/*
 * Always an array, [] when the policy has none. A stored list is canonical and normalises to itself;
 * one that cannot be read grants no name rather than something permissive.
 */
static int pm_append_egress_domain_rules(pm_builder *builder, const char *stored)
{
    char *rules = NULL;
    int rc = pm_append(builder, st_egress_normalize_domain_rules(stored, &rules) == 0 ? rules : "[]");
    free(rules);
    return rc;
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
                && pm_append(&message, ",\"domainRules\":") == 0
                && pm_append_egress_domain_rules(&message, policy.domain_rules) == 0
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

    st_storage_peer_mesh_egress_policy *policies = NULL;
    size_t policy_count = 0U;
    if (pm_tenant_egress_enabled(runtime->database_path, consumer->tenant_id)
        && st_storage_list_peer_mesh_egress_policies(runtime->database_path, consumer->tenant_id, 1,
                                                     &policies, &policy_count) != 0) return -1;

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
        /*
         * egressVersion and domainTargetCapable are what the egress announced on its current online
         * session: the client row carries both from the latest NETTY_ONLINE session, so a device
         * with none reads as 0. The live check covers the departure window, where the logout push
         * runs before that session is marked disconnected and the row would still show the old
         * announcement. A version-0 row has nothing to announce, so it needs no live check; the
         * stored domain flag is already 0 for such a login.
         */
        int announced = online && egress->client_egress_version >= 1
            && runtime->online != NULL
            && runtime->online(runtime->ctx, egress->id, egress->client_name);
        int egress_version = announced ? egress->client_egress_version : 0;
        int domain_targets = announced && egress->client_egress_domain_targets;

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
            /*
             * ipv6TargetCapable stays false: egresses declare it, but no consumer reads it while
             * the consumer data plane carries IPv4 only. egressVersion is written
             * even when 0, because a consumer reads 0 as an egress that cannot take a flow but an
             * absent field as an old server it cannot judge.
             */
            rc = pm_appendf(&message,
                            "],\"domainTargetCapable\":%s,\"ipv6TargetCapable\":false,\"egressVersion\":%d}",
                            domain_targets ? "true" : "false", egress_version);
        }
        first = 0;
    }
    if (rc == 0) {
        rc = pm_appendf(&message, "],\"createdAtMillis\":%lld}", (long long)time(NULL) * 1000LL) == 0
            ? runtime->send(runtime->ctx, consumer->client_name, "server", message.data) : -1;
    }
    free(message.data);
    free(policies);
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
#define ST_PEER_EGRESS_REPORT_RATE_LIMIT ST_PEER_REPORT_RATE_LIMIT
#define ST_PEER_EGRESS_REPORT_RATE_WINDOW 60
#define ST_PEER_EGRESS_MAX_RATE_SESSIONS 4096U

typedef struct {
    long long session_id;
    pm_rate_window window;
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
    long long now = pm_monotonic_ms();
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
        memset(slot, 0, sizeof(*slot));
        slot->session_id = session_id;
    }
    if (slot != NULL) {
        allowed = pm_rate_window_admit(&slot->window, now, ST_PEER_EGRESS_REPORT_RATE_LIMIT,
                                       ST_PEER_EGRESS_REPORT_RATE_WINDOW * 1000LL);
    }
    pthread_mutex_unlock(&peer_egress_rate_lock);
    return allowed ? 0 : -1;
}

/* Placeholder sessions take negative ids, which no control session has. */
int st_peer_mesh_egress_report_rate_occupy_for_testing(size_t count)
{
    int rc = 0;
    pthread_mutex_lock(&peer_egress_rate_lock);
    for (size_t i = 0U; i < count; ++i) {
        if (peer_egress_rate_used >= ST_PEER_EGRESS_MAX_RATE_SESSIONS) {
            rc = -1;
            break;
        }
        pm_egress_rate_slot *slot = &peer_egress_rate_slots[peer_egress_rate_used++];
        memset(slot, 0, sizeof(*slot));
        slot->session_id = -(long long)peer_egress_rate_used;
    }
    pthread_mutex_unlock(&peer_egress_rate_lock);
    return rc;
}

size_t st_peer_mesh_egress_report_rate_sessions_for_testing(void)
{
    pthread_mutex_lock(&peer_egress_rate_lock);
    size_t used = peer_egress_rate_used;
    pthread_mutex_unlock(&peer_egress_rate_lock);
    return used;
}

void st_peer_mesh_egress_report_rate_release_for_testing(void)
{
    pthread_mutex_lock(&peer_egress_rate_lock);
    size_t kept = 0U;
    for (size_t i = 0U; i < peer_egress_rate_used; ++i) {
        if (peer_egress_rate_slots[i].session_id >= 0) peer_egress_rate_slots[kept++] = peer_egress_rate_slots[i];
    }
    peer_egress_rate_used = kept;
    pthread_mutex_unlock(&peer_egress_rate_lock);
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
    return runtime->control_source == NULL
        ? st_storage_upsert_peer_mesh_egress_activity(runtime->database_path, &row)
        : st_storage_upsert_peer_mesh_egress_activity_from_control(runtime->database_path, runtime->control_source, &row);
}

static int pm_push_on_login_impl(const st_peer_mesh_runtime *runtime,
                               const char *client_name)
{
    if (runtime == NULL || runtime->database_path == NULL || runtime->send == NULL
        || !pm_env_bool("SPECUS_PEER_MESH_ENABLED", 0)) return 0;
    (void)st_peer_mesh_expire_catalogs(runtime);
    st_storage_client source;
    st_storage_client *clients = NULL;
    size_t client_count = 0U;
    if (st_storage_get_client_by_name(runtime->database_path, client_name, &source) != 0
        || (runtime->authenticated_client_id > 0 && source.id != runtime->authenticated_client_id)
        || (runtime->authenticated_tenant != NULL && strcmp(source.tenant_id, runtime->authenticated_tenant) != 0)
        || st_storage_list_all_clients(runtime->database_path, &clients, &client_count) != 0) return -1;
    if (pm_push_config(runtime, &source) != 0) {
        free(clients);
        return -1;
    }
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
    free(clients);
    (void)pm_replay_catalogs(runtime, &source);
    return 0;
}

/* Tells a departed client's peers that it is gone.
 *
 * Rosters were pushed when a client arrived and never when it left, so the peers of a device that
 * disconnected kept it as online until something else in the tenant logged in. A consumer whose
 * egress had stopped went on sending flows into a session nobody answered.
 *
 * Called after the session has been removed from the active list, so the rosters built here count
 * the client as offline. A client already back on a newer session was announced by that login and
 * is left alone. */
static int pm_push_on_logout_impl(const st_peer_mesh_runtime *runtime,
                                const char *client_name)
{
    if (runtime == NULL || runtime->database_path == NULL || runtime->send == NULL
        || runtime->online == NULL || !pm_has_text(client_name)
        || !pm_env_bool("SPECUS_PEER_MESH_ENABLED", 0)) return 0;
    st_storage_client departed;
    if (st_storage_get_client_by_name(runtime->database_path, client_name, &departed) != 0) return -1;
    if ((runtime->authenticated_client_id > 0 && departed.id != runtime->authenticated_client_id)
        || (runtime->authenticated_tenant != NULL && strcmp(departed.tenant_id, runtime->authenticated_tenant) != 0)) return -1;
    if (runtime->online(runtime->ctx, departed.id, departed.client_name)) return 0;
    st_storage_client *clients = NULL;
    size_t client_count = 0U;
    if (st_storage_list_all_clients(runtime->database_path, &clients, &client_count) != 0) return -1;
    for (size_t i = 0; i < client_count; ++i) {
        if (clients[i].id == departed.id
            || strcmp(clients[i].tenant_id, departed.tenant_id) != 0
            || !runtime->online(runtime->ctx, clients[i].id, clients[i].client_name)) continue;
        (void)pm_push_roster(runtime, &clients[i], clients, client_count);
        (void)pm_push_egress_catalog(runtime, &clients[i], clients, client_count);
    }
    free(clients);
    return 0;
}

static int pm_refresh_tenant_impl(const st_peer_mesh_runtime *runtime,
                                const char *tenant_id)
{
    if (runtime == NULL || runtime->database_path == NULL || runtime->send == NULL
        || tenant_id == NULL || *tenant_id == '\0'
        || !pm_env_bool("SPECUS_PEER_MESH_ENABLED", 0)) return 0;

    (void)st_peer_mesh_expire_catalogs(runtime);
    st_storage_client *clients = NULL;
    size_t client_count = 0U;
    if (st_storage_list_all_clients(runtime->database_path, &clients, &client_count) != 0) return -1;

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
    free(clients);

    pm_catalog *snapshots = (pm_catalog *)calloc(ST_PEER_MESH_MAX_CATALOGS,
                                                 sizeof(*snapshots));
    if (snapshots == NULL) return -1;
    size_t snapshot_count = 0U;
    time_t now = time(NULL);
    pthread_mutex_lock(&peer_catalog_lock);
    for (size_t i = 0; i < ST_PEER_MESH_MAX_CATALOGS; ++i) {
        pm_catalog *catalog = &peer_catalogs[i];
        if (catalog->pending_report != NULL || !catalog->in_use || !catalog->active || catalog->expires_at <= now
            || strcmp(catalog->tenant_id, tenant_id) != 0) continue;
        long long revision = pm_next_catalog_revision_locked(catalog->catalog_revision);
        if (revision == 0) { rc = -1; continue; }
        catalog->catalog_revision = revision;
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

int st_peer_mesh_owner_changes_init(const char *database_path, st_peer_mesh_owner_cursor *cursor)
{
    if (cursor == NULL) return -1;
    memset(cursor, 0, sizeof(*cursor));
    if (database_path == NULL || *database_path == '\0' || strlen(database_path) >= sizeof(cursor->database_path)
        || st_storage_owner_transfer_last_id(database_path, &cursor->after_id) != 0) return -1;
    strcpy(cursor->database_path, database_path); cursor->initialized = 1; return 0;
}

static int pm_dispatch_owner_change(const st_peer_mesh_runtime *runtime, const st_storage_owner_transfer_event *event)
{
    /* Maintenance must not block behind an in-flight network send. Retain this
     * event and retry after the previous snapshot finishes; never acknowledge it. */
    if (pthread_mutex_trylock(&peer_snapshot_dispatch_lock) != 0) return -1;
    st_storage_client *clients = NULL; size_t count = 0;
    if (st_storage_list_all_clients(runtime->database_path, &clients, &count) != 0) {
        pthread_mutex_unlock(&peer_snapshot_dispatch_lock); return -1;
    }
    int rc = 0;
    for (size_t i = 0; i < event->closed_count; ++i) {
        const st_storage_peer_close *closed = &event->closed[i];
        long long endpoints[] = {closed->source_client_id, closed->target_client_id};
        char *message = pm_closed_session_message(closed, "owner-transferred");
        if (message == NULL) { rc = -1; break; }
        for (size_t n = 0; n < 2; ++n) {
            const st_storage_client *recipient = pm_find_client_by_id(clients, count, endpoints[n]);
            if (recipient == NULL || strcmp(recipient->tenant_id, event->tenant_id) != 0
                || !runtime->online(runtime->ctx, recipient->id, recipient->client_name)) continue;
            if (runtime->send(runtime->ctx, recipient->client_name, "server", message) != 0) rc = -1;
        }
        free(message);
    }
    free(clients);
    if (pm_refresh_tenant_impl(runtime, event->tenant_id) != 0) rc = -1;
    pthread_mutex_unlock(&peer_snapshot_dispatch_lock);
    return rc;
}

int st_peer_mesh_owner_changes_drain(const st_peer_mesh_runtime *runtime, st_peer_mesh_owner_cursor *cursor)
{
    if (runtime == NULL || runtime->database_path == NULL || runtime->send == NULL || runtime->online == NULL
        || cursor == NULL || !cursor->initialized || strcmp(runtime->database_path, cursor->database_path) != 0) return -1;
    if (!pm_env_bool("SPECUS_PEER_MESH_ENABLED", 0)) return 0;
    for (size_t n = 0; n < 64; ++n) {
        st_storage_owner_transfer_event event = {0};
        int found = st_storage_owner_transfer_next(runtime->database_path, cursor->after_id, &event);
        if (found <= 0) return found;
        int rc = pm_dispatch_owner_change(runtime, &event);
        if (rc == 0) cursor->after_id = event.id;
        st_storage_owner_transfer_event_free(&event);
        if (rc != 0) return -1;
    }
    return 0;
}

static int pm_source_dispatch_lock(const st_peer_mesh_runtime *runtime)
{
    if (runtime != NULL && runtime->source_active != NULL) {
        while (pthread_mutex_trylock(&peer_snapshot_dispatch_lock) != 0) {
            if (!runtime->source_active(runtime->ctx)) return -1;
            struct timespec delay = {0, 25L * 1000000L};
            nanosleep(&delay, NULL);
        }
    } else pthread_mutex_lock(&peer_snapshot_dispatch_lock);
    if (runtime != NULL && runtime->source_current != NULL && !runtime->source_current(runtime->ctx)) {
        pthread_mutex_unlock(&peer_snapshot_dispatch_lock);
        return -1;
    }
    int drained = 0;
    if (runtime != NULL && runtime->authenticated_client_id > 0 && pm_has_text(runtime->authenticated_tenant)
        && runtime->publisher_session_id > 0) {
        if (!pm_has_text(runtime->database_path) || runtime->send == NULL || runtime->online == NULL
            || (drained = pm_drain_control_withdrawal(runtime, runtime->authenticated_client_id,
                                                    runtime->authenticated_tenant, runtime->publisher_session_id)) < 0) {
            pthread_mutex_unlock(&peer_snapshot_dispatch_lock);
            return -1;
        }
    }
    /* A queued withdrawal may have waited in real SQL/socket I/O. Do not turn the earlier source
     * check into authority to publish a fresh report after that physical source has retired. */
    if (drained > 0 && runtime != NULL && runtime->source_current != NULL && !runtime->source_current(runtime->ctx)) {
        pthread_mutex_unlock(&peer_snapshot_dispatch_lock);
        return -1;
    }
    return 0;
}

int st_peer_mesh_handle_control(const st_peer_mesh_runtime *runtime, const char *authenticated_client_name,
                                const char *target_client_name, const char *message)
{
    if (pm_source_dispatch_lock(runtime) != 0) return -1;
    int rc = pm_handle_control_impl(runtime, authenticated_client_name, target_client_name, message);
    pthread_mutex_unlock(&peer_snapshot_dispatch_lock); return rc;
}
int st_peer_mesh_push_on_login(const st_peer_mesh_runtime *runtime, const char *client_name)
{
    if (pm_source_dispatch_lock(runtime) != 0) return -1;
    int rc = pm_push_on_login_impl(runtime, client_name);
    pthread_mutex_unlock(&peer_snapshot_dispatch_lock); return rc;
}
int st_peer_mesh_push_on_logout(const st_peer_mesh_runtime *runtime, const char *client_name)
{
    pthread_mutex_lock(&peer_snapshot_dispatch_lock);
    int rc = pm_push_on_logout_impl(runtime, client_name);
    pthread_mutex_unlock(&peer_snapshot_dispatch_lock); return rc;
}
int st_peer_mesh_refresh_tenant(const st_peer_mesh_runtime *runtime, const char *tenant_id)
{
    pthread_mutex_lock(&peer_snapshot_dispatch_lock);
    int rc = pm_refresh_tenant_impl(runtime, tenant_id);
    pthread_mutex_unlock(&peer_snapshot_dispatch_lock); return rc;
}
