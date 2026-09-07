#define _POSIX_C_SOURCE 200809L

#include "public_coordination.h"

#include "crypto.h"
#include "json.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <hiredis/hiredis.h>
#include <limits.h>
#include <utf8proc.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define ST_CLUSTER_EVENT_HEADER_BYTES 26U
#define ST_CLUSTER_EVENT_MAX_GROUP_BYTES 128U
#define ST_CLUSTER_EVENT_MAX_ID_BYTES 512U
#define ST_CLUSTER_EVENT_MAX_PAYLOAD_BYTES (256U * 1024U)
#define ST_CLUSTER_REVISION_TTL_MS 604800000LL

typedef struct {
    char host[256];
    int port;
    char username[256];
    char password[512];
    int database;
    char key_prefix[256];
    long lease_seconds;
    long refresh_interval_ms;
    long command_timeout_ms;
} st_cluster_config;

typedef struct {
    pthread_mutex_t state_lock;
    pthread_mutex_t command_lock;
    redisContext *command;
    redisContext *subscriber;
    pthread_t subscriber_thread;
    int subscriber_started;
    int initialized;
    int available;
    int stopping;
    st_cluster_config config;
    st_public_cluster_event_handler handler;
    void *handler_context;
} st_cluster_state;

static st_cluster_state cluster_state = {
    .state_lock = PTHREAD_MUTEX_INITIALIZER,
    .command_lock = PTHREAD_MUTEX_INITIALIZER
};

static const char cluster_register_script[] =
    "local members = redis.call('SMEMBERS', KEYS[3])\n"
    "local count = 0\n"
    "for _, member in ipairs(members) do\n"
    "  if redis.call('EXISTS', ARGV[6] .. member) == 1 then count = count + 1 "
    "else redis.call('SREM', KEYS[3], member) end\n"
    "end\n"
    "if redis.call('EXISTS', KEYS[1]) == 1 then return {-1, 0} end\n"
    "for _, group in ipairs(redis.call('SMEMBERS', KEYS[6])) do\n"
    "  if redis.call('EXISTS', ARGV[9] .. group .. ':' .. ARGV[3]) == 1 then return {-1, 0} end\n"
    "end\n"
    "if redis.call('EXISTS', KEYS[2]) == 1 then return {-2, 0} end\n"
    "if count >= tonumber(ARGV[5]) then return {-3, 0} end\n"
    "redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[4])\n"
    "redis.call('SET', KEYS[2], ARGV[2], 'PX', ARGV[4])\n"
    "redis.call('SADD', KEYS[3], ARGV[3])\n"
    "redis.call('PEXPIRE', KEYS[3], tonumber(ARGV[4]) * 3)\n"
    "redis.call('SADD', KEYS[6], ARGV[8])\n"
    "redis.call('PEXPIRE', KEYS[6], tonumber(ARGV[4]) * 3)\n"
    "local groupRevision = redis.call('INCR', KEYS[4])\n"
    "redis.call('PEXPIRE', KEYS[4], ARGV[7])\n"
    "local netRevision = redis.call('INCR', KEYS[5])\n"
    "redis.call('PEXPIRE', KEYS[5], ARGV[7])\n"
    "return {1, groupRevision + netRevision}";

static const char cluster_refresh_script[] =
    "if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end\n"
    "if redis.call('GET', KEYS[2]) ~= ARGV[2] then return 0 end\n"
    "redis.call('PEXPIRE', KEYS[1], ARGV[3])\n"
    "redis.call('PEXPIRE', KEYS[2], ARGV[3])\n"
    "redis.call('PEXPIRE', KEYS[3], tonumber(ARGV[3]) * 3)\n"
    "redis.call('PEXPIRE', KEYS[4], tonumber(ARGV[3]) * 3)\n"
    "return 1";

static const char cluster_unregister_script[] =
    "if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end\n"
    "redis.call('DEL', KEYS[1])\n"
    "if redis.call('GET', KEYS[2]) == ARGV[2] then redis.call('DEL', KEYS[2]) end\n"
    "redis.call('SREM', KEYS[3], ARGV[3])\n"
    "if redis.call('SCARD', KEYS[3]) == 0 then redis.call('SREM', KEYS[6], ARGV[5]) end\n"
    "local groupRevision = redis.call('INCR', KEYS[4])\n"
    "redis.call('PEXPIRE', KEYS[4], ARGV[4])\n"
    "local netRevision = redis.call('INCR', KEYS[5])\n"
    "redis.call('PEXPIRE', KEYS[5], ARGV[4])\n"
    "return groupRevision + netRevision";

static const char cluster_cleanup_script[] =
    "local removed = 0\n"
    "local members = redis.call('SMEMBERS', KEYS[1])\n"
    "for _, member in ipairs(members) do\n"
    "  if redis.call('EXISTS', ARGV[1] .. member) == 0 then\n"
    "    redis.call('SREM', KEYS[1], member)\n"
    "    removed = removed + 1\n"
    "  end\n"
    "end\n"
    "if redis.call('SCARD', KEYS[1]) == 0 then redis.call('SREM', KEYS[4], ARGV[3]) end\n"
    "local groupRevision = tonumber(redis.call('GET', KEYS[2]) or '0')\n"
    "local netRevision = tonumber(redis.call('GET', KEYS[3]) or '0')\n"
    "if removed > 0 then\n"
    "  groupRevision = redis.call('INCR', KEYS[2])\n"
    "  redis.call('PEXPIRE', KEYS[2], ARGV[2])\n"
    "  netRevision = redis.call('INCR', KEYS[3])\n"
    "  redis.call('PEXPIRE', KEYS[3], ARGV[2])\n"
    "end\n"
    "return {removed, groupRevision + netRevision}";

static const char cluster_rate_script[] =
    "local count = redis.call('INCR', KEYS[1])\n"
    "if count == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[2]) end\n"
    "if count > tonumber(ARGV[1]) then return 0 end\n"
    "return 1";

static int cluster_env_bool(const char *name, int fallback)
{
    const char *value = getenv(name);
    if (value == NULL || *value == '\0') return fallback;
    return strcmp(value, "0") != 0 && strcasecmp(value, "false") != 0
        && strcasecmp(value, "no") != 0;
}

static long cluster_env_long(const char *name, long fallback)
{
    const char *value = getenv(name);
    if (value == NULL || *value == '\0') return fallback;
    char *end = NULL;
    errno = 0;
    long parsed = strtol(value, &end, 10);
    return errno == 0 && end != value && *end == '\0' && parsed > 0 ? parsed : fallback;
}

int st_public_coordination_enabled(void)
{
    return cluster_env_bool("SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED", 0);
}

static int cluster_percent_decode(const char *source, size_t len, char *out, size_t out_len)
{
    if (len + 1U > out_len) return -1;
    size_t written = 0U;
    for (size_t i = 0U; i < len; ++i) {
        unsigned char value = (unsigned char)source[i];
        if (value == '%') {
            if (i + 2U >= len || !isxdigit((unsigned char)source[i + 1U])
                || !isxdigit((unsigned char)source[i + 2U])) return -1;
            char hex[3] = {source[i + 1U], source[i + 2U], '\0'};
            value = (unsigned char)strtoul(hex, NULL, 16);
            i += 2U;
        }
        if (value == 0U || written + 1U >= out_len) return -1;
        out[written++] = (char)value;
    }
    out[written] = '\0';
    return 0;
}

static int cluster_parse_uri(st_cluster_config *config)
{
    const char *uri = getenv("SPECUS_PUBLIC_TRANSFER_REDIS_URI");
    static const char scheme[] = "redis://";
    if (uri == NULL || strncmp(uri, scheme, sizeof(scheme) - 1U) != 0) {
        fprintf(stderr, "public transfer Redis URI must use redis://\n");
        return -1;
    }
    const char *authority = uri + sizeof(scheme) - 1U;
    const char *path = strchr(authority, '/');
    const char *authority_end = path == NULL ? uri + strlen(uri) : path;
    const char *at = NULL;
    for (const char *cursor = authority; cursor < authority_end; ++cursor) {
        if (*cursor == '@') at = cursor;
    }
    const char *host_start = authority;
    if (at != NULL) {
        const char *colon = memchr(authority, ':', (size_t)(at - authority));
        if (colon == NULL) {
            if (cluster_percent_decode(authority,
                                       (size_t)(at - authority),
                                       config->password,
                                       sizeof(config->password)) != 0) return -1;
        } else {
            if (cluster_percent_decode(authority,
                                       (size_t)(colon - authority),
                                       config->username,
                                       sizeof(config->username)) != 0
                || cluster_percent_decode(colon + 1,
                                          (size_t)(at - colon - 1),
                                          config->password,
                                          sizeof(config->password)) != 0) return -1;
        }
        host_start = at + 1;
    }
    const char *port_start = NULL;
    const char *host_end = authority_end;
    if (host_start < authority_end && *host_start == '[') {
        const char *closing = memchr(host_start, ']', (size_t)(authority_end - host_start));
        if (closing == NULL) return -1;
        host_start++;
        host_end = closing;
        if (closing + 1 < authority_end) {
            if (closing[1] != ':') return -1;
            port_start = closing + 2;
        }
    } else {
        const char *colon = NULL;
        for (const char *cursor = host_start; cursor < authority_end; ++cursor) {
            if (*cursor == ':') colon = cursor;
        }
        if (colon != NULL) {
            host_end = colon;
            port_start = colon + 1;
        }
    }
    if (host_end == host_start || (size_t)(host_end - host_start) >= sizeof(config->host)) return -1;
    memcpy(config->host, host_start, (size_t)(host_end - host_start));
    config->host[host_end - host_start] = '\0';
    config->port = 6379;
    if (port_start != NULL) {
        char port_text[16];
        size_t port_len = (size_t)(authority_end - port_start);
        if (port_len == 0U || port_len >= sizeof(port_text)) return -1;
        memcpy(port_text, port_start, port_len);
        port_text[port_len] = '\0';
        char *end = NULL;
        long parsed = strtol(port_text, &end, 10);
        if (end == port_text || *end != '\0' || parsed < 1 || parsed > 65535) return -1;
        config->port = (int)parsed;
    }
    config->database = 0;
    if (path != NULL && path[1] != '\0') {
        const char *database_text = path + 1;
        if (strchr(database_text, '?') != NULL || strchr(database_text, '#') != NULL) return -1;
        char *end = NULL;
        long parsed = strtol(database_text, &end, 10);
        if (end == database_text || *end != '\0' || parsed < 0 || parsed > 15) return -1;
        config->database = (int)parsed;
    }
    const char *prefix = getenv("SPECUS_PUBLIC_TRANSFER_REDIS_KEY_PREFIX");
    if (prefix == NULL || *prefix == '\0') prefix = "specus:v2:public-transfer";
    while (isspace((unsigned char)*prefix)) ++prefix;
    size_t prefix_len = strlen(prefix);
    while (prefix_len > 0U && (isspace((unsigned char)prefix[prefix_len - 1U])
            || prefix[prefix_len - 1U] == ':')) --prefix_len;
    if (prefix_len == 0U || prefix_len >= sizeof(config->key_prefix)) return -1;
    memcpy(config->key_prefix, prefix, prefix_len);
    config->key_prefix[prefix_len] = '\0';
    config->lease_seconds = cluster_env_long("SPECUS_PUBLIC_TRANSFER_PRESENCE_LEASE_SECONDS", 30L);
    if (config->lease_seconds < 5L) config->lease_seconds = 5L;
    config->refresh_interval_ms = cluster_env_long(
        "SPECUS_PUBLIC_TRANSFER_PRESENCE_REFRESH_INTERVAL_MS", 10000L);
    config->command_timeout_ms = cluster_env_long(
        "SPECUS_PUBLIC_TRANSFER_REDIS_COMMAND_TIMEOUT_MS", 2000L);
    if (config->command_timeout_ms < 100L) config->command_timeout_ms = 100L;
    if (config->lease_seconds > LONG_MAX / 1000L
        || config->refresh_interval_ms > LONG_MAX / 2L
        || config->refresh_interval_ms <= 0L
        || config->refresh_interval_ms * 2L >= config->lease_seconds * 1000L) {
        fprintf(stderr, "public transfer presence refresh must be positive and less than half the lease TTL\n");
        return -1;
    }
    return 0;
}

static int cluster_reply_ok(redisReply *reply)
{
    return reply != NULL && reply->type == REDIS_REPLY_STATUS
        && reply->str != NULL && strcasecmp(reply->str, "OK") == 0;
}

static redisContext *cluster_connect(const st_cluster_config *config)
{
    struct timeval connect_timeout = {
        .tv_sec = config->command_timeout_ms / 1000L,
        .tv_usec = (config->command_timeout_ms % 1000L) * 1000L
    };
    redisContext *redis = redisConnectWithTimeout(config->host, config->port, connect_timeout);
    if (redis == NULL || redis->err) {
        fprintf(stderr, "public transfer Redis connect failed: %s\n",
                redis == NULL ? "out of memory" : redis->errstr);
        if (redis != NULL) redisFree(redis);
        return NULL;
    }
    if (redisSetTimeout(redis, connect_timeout) != REDIS_OK) {
        redisFree(redis);
        return NULL;
    }
    redisReply *reply = NULL;
    if (config->password[0] != '\0') {
        if (config->username[0] != '\0')
            reply = redisCommand(redis, "AUTH %s %s", config->username, config->password);
        else
            reply = redisCommand(redis, "AUTH %s", config->password);
        if (!cluster_reply_ok(reply)) {
            fprintf(stderr, "public transfer Redis authentication failed\n");
            freeReplyObject(reply);
            redisFree(redis);
            return NULL;
        }
        freeReplyObject(reply);
    }
    if (config->database != 0) {
        reply = redisCommand(redis, "SELECT %d", config->database);
        if (!cluster_reply_ok(reply)) {
            fprintf(stderr, "public transfer Redis database selection failed\n");
            freeReplyObject(reply);
            redisFree(redis);
            return NULL;
        }
        freeReplyObject(reply);
    }
    reply = redisCommand(redis, "PING");
    int pong = reply != NULL && (reply->type == REDIS_REPLY_STATUS || reply->type == REDIS_REPLY_STRING)
        && reply->str != NULL && strcasecmp(reply->str, "PONG") == 0;
    freeReplyObject(reply);
    if (!pong) {
        redisFree(redis);
        return NULL;
    }
    return redis;
}

static void cluster_mark_unavailable(void)
{
    st_public_cluster_event_handler handler = NULL;
    void *context = NULL;
    int notify = 0;
    pthread_mutex_lock(&cluster_state.state_lock);
    if (cluster_state.available && !cluster_state.stopping) {
        cluster_state.available = 0;
        handler = cluster_state.handler;
        context = cluster_state.handler_context;
        notify = 1;
    }
    pthread_mutex_unlock(&cluster_state.state_lock);
    if (notify && handler != NULL) {
        st_public_cluster_event event;
        memset(&event, 0, sizeof(event));
        event.kind = ST_PUBLIC_CLUSTER_EVENT_UNAVAILABLE;
        handler(&event, context);
    }
}

int st_public_coordination_available(void)
{
    int available;
    pthread_mutex_lock(&cluster_state.state_lock);
    available = cluster_state.available;
    pthread_mutex_unlock(&cluster_state.state_lock);
    return available;
}

long st_public_coordination_refresh_interval_ms(void)
{
    pthread_mutex_lock(&cluster_state.state_lock);
    long interval = cluster_state.config.refresh_interval_ms;
    pthread_mutex_unlock(&cluster_state.state_lock);
    return interval > 0L ? interval : 10000L;
}

static redisReply *cluster_command_argv(int argc, const char **argv, const size_t *lengths)
{
    pthread_mutex_lock(&cluster_state.command_lock);
    pthread_mutex_lock(&cluster_state.state_lock);
    redisContext *command = cluster_state.available ? cluster_state.command : NULL;
    pthread_mutex_unlock(&cluster_state.state_lock);
    redisReply *reply = command == NULL ? NULL
        : (redisReply *)redisCommandArgv(command, argc, argv, lengths);
    int failed = reply == NULL || reply->type == REDIS_REPLY_ERROR;
    if (failed && reply != NULL && reply->str != NULL)
        fprintf(stderr, "public transfer Redis command failed: %s\n", reply->str);
    pthread_mutex_unlock(&cluster_state.command_lock);
    if (failed) cluster_mark_unavailable();
    return reply;
}

static redisReply *cluster_eval(const char *script,
                                const char **keys,
                                size_t key_count,
                                const char **arguments,
                                const size_t *argument_lengths,
                                size_t argument_count)
{
    size_t count = 3U + key_count + argument_count;
    const char **argv = (const char **)calloc(count, sizeof(*argv));
    size_t *lengths = (size_t *)calloc(count, sizeof(*lengths));
    char key_count_text[32];
    if (argv == NULL || lengths == NULL
        || snprintf(key_count_text, sizeof(key_count_text), "%zu", key_count) >= (int)sizeof(key_count_text)) {
        free(argv);
        free(lengths);
        return NULL;
    }
    argv[0] = "EVAL";
    argv[1] = script;
    argv[2] = key_count_text;
    lengths[0] = 4U;
    lengths[1] = strlen(script);
    lengths[2] = strlen(key_count_text);
    for (size_t i = 0U; i < key_count; ++i) {
        argv[3U + i] = keys[i];
        lengths[3U + i] = strlen(keys[i]);
    }
    for (size_t i = 0U; i < argument_count; ++i) {
        argv[3U + key_count + i] = arguments[i];
        lengths[3U + key_count + i] = argument_lengths == NULL
            ? strlen(arguments[i]) : argument_lengths[i];
    }
    redisReply *reply = cluster_command_argv((int)count, argv, lengths);
    free(argv);
    free(lengths);
    return reply;
}

static void cluster_sha_hex_bytes(const uint8_t *data, size_t len, char out[65])
{
    uint8_t digest[ST_SHA256_LEN];
    st_sha256(data, len, digest);
    st_hex_encode(digest, sizeof(digest), out);
}

static void cluster_sha_hex(const char *value, char out[65])
{
    cluster_sha_hex_bytes((const uint8_t *)(value == NULL ? "" : value),
                          value == NULL ? 0U : strlen(value),
                          out);
}

static int cluster_random(uint8_t *out, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t offset = 0U;
    while (offset < len) {
        ssize_t read_len = read(fd, out + offset, len - offset);
        if (read_len < 0 && errno == EINTR) continue;
        if (read_len <= 0) {
            close(fd);
            return -1;
        }
        offset += (size_t)read_len;
    }
    close(fd);
    return 0;
}

static int cluster_base64url(const uint8_t *data, size_t len, char *out, size_t out_len)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t needed = (len / 3U) * 4U + (len % 3U == 0U ? 0U : len % 3U + 1U);
    if (needed + 1U > out_len) return -1;
    size_t source = 0U;
    size_t written = 0U;
    while (source < len) {
        size_t remaining = len - source;
        uint32_t value = (uint32_t)data[source++] << 16U;
        if (remaining > 1U) value |= (uint32_t)data[source++] << 8U;
        if (remaining > 2U) value |= data[source++];
        out[written++] = alphabet[(value >> 18U) & 63U];
        out[written++] = alphabet[(value >> 12U) & 63U];
        if (remaining > 1U) out[written++] = alphabet[(value >> 6U) & 63U];
        if (remaining > 2U) out[written++] = alphabet[value & 63U];
    }
    out[written] = '\0';
    return 0;
}

static int cluster_compute_ids(st_public_cluster_participant *participant)
{
    size_t room_len = strlen(participant->room_id);
    size_t key_len = strlen(participant->room_key);
    if (room_len > SIZE_MAX - key_len - 1U) return -1;
    uint8_t *group_input = (uint8_t *)malloc(room_len + 1U + key_len);
    if (group_input == NULL) return -1;
    memcpy(group_input, participant->room_id, room_len);
    group_input[room_len] = 0U;
    memcpy(group_input + room_len + 1U, participant->room_key, key_len);
    cluster_sha_hex_bytes(group_input, room_len + 1U + key_len, participant->group_id);
    free(group_input);
    cluster_sha_hex(participant->public_address, participant->net_id);
    return 0;
}

int st_public_coordination_prepare_participant(st_public_cluster_participant *participant)
{
    if (participant == NULL || participant->peer_id[0] == '\0' || participant->room_id[0] == '\0'
        || participant->room_key[0] == '\0') return -1;
    uint8_t random[24];
    if (cluster_random(random, sizeof(random)) != 0
        || cluster_base64url(random,
                             sizeof(random),
                             participant->lease_id,
                             sizeof(participant->lease_id)) != 0) return -1;
    return cluster_compute_ids(participant);
}

static int cluster_key(char *out, size_t out_len, const char *kind, const char *id)
{
    int written = snprintf(out,
                           out_len,
                           "%s:%s:%s",
                           cluster_state.config.key_prefix,
                           kind,
                           id);
    return written < 0 || (size_t)written >= out_len ? -1 : 0;
}

static int cluster_presence_prefix(char *out, size_t out_len, const char *group_id)
{
    int written = snprintf(out,
                           out_len,
                           "%s:presence:%s:",
                           cluster_state.config.key_prefix,
                           group_id);
    return written < 0 || (size_t)written >= out_len ? -1 : 0;
}

static int cluster_presence_base_prefix(char *out, size_t out_len)
{
    int written = snprintf(out,
                           out_len,
                           "%s:presence:",
                           cluster_state.config.key_prefix);
    return written < 0 || (size_t)written >= out_len ? -1 : 0;
}

static int cluster_presence_key(char *out,
                                size_t out_len,
                                const char *group_id,
                                const char *member_id)
{
    int written = snprintf(out,
                           out_len,
                           "%s:presence:%s:%s",
                           cluster_state.config.key_prefix,
                           group_id,
                           member_id);
    return written < 0 || (size_t)written >= out_len ? -1 : 0;
}

static int cluster_normalized_name_hash(const char *display_name, char out[65])
{
    if (display_name == NULL) return -1;
    const unsigned char *start = (const unsigned char *)display_name;
    while (*start != '\0' && *start <= 0x20U) ++start;
    size_t len = strlen((const char *)start);
    while (len > 0U && start[len - 1U] <= 0x20U) --len;
    utf8proc_uint8_t *nfc = NULL;
    utf8proc_ssize_t nfc_len = utf8proc_map(start,
                                            (utf8proc_ssize_t)len,
                                            &nfc,
                                            UTF8PROC_STABLE | UTF8PROC_COMPOSE);
    if (nfc_len < 0 || nfc == NULL || (size_t)nfc_len > (SIZE_MAX - 1U) / 4U) {
        free(nfc);
        return -1;
    }
    size_t capacity = (size_t)nfc_len * 4U + 1U;
    utf8proc_uint8_t *lowered = (utf8proc_uint8_t *)malloc(capacity);
    if (lowered == NULL) {
        free(nfc);
        return -1;
    }
    size_t read_offset = 0U;
    size_t write_offset = 0U;
    while (read_offset < (size_t)nfc_len) {
        utf8proc_int32_t codepoint = 0;
        utf8proc_ssize_t consumed = utf8proc_iterate(nfc + read_offset,
                                                     nfc_len - (utf8proc_ssize_t)read_offset,
                                                     &codepoint);
        if (consumed <= 0) {
            free(nfc);
            free(lowered);
            return -1;
        }
        read_offset += (size_t)consumed;
        utf8proc_ssize_t encoded = utf8proc_encode_char(utf8proc_tolower(codepoint),
                                                        lowered + write_offset);
        if (encoded <= 0 || write_offset + (size_t)encoded >= capacity) {
            free(nfc);
            free(lowered);
            return -1;
        }
        write_offset += (size_t)encoded;
    }
    cluster_sha_hex_bytes(lowered, write_offset, out);
    free(nfc);
    free(lowered);
    return 0;
}

static int cluster_name_key(char *out, size_t out_len, const char *display_name)
{
    char digest[65];
    if (cluster_normalized_name_hash(display_name, digest) != 0) return -1;
    return cluster_key(out, out_len, "name", digest);
}

static int cluster_participant_value(const st_public_cluster_participant *participant,
                                     char **value_out,
                                     char **name_value_out)
{
    char *lease = st_json_escape(participant->lease_id);
    char *peer = st_json_escape(participant->peer_id);
    char *name = st_json_escape(participant->display_name);
    char *room = st_json_escape(participant->room_id);
    char *address = st_json_escape(participant->public_address);
    char *room_key = st_json_escape(participant->room_key);
    char *role = st_json_escape(participant->room_role);
    char *connected = st_json_escape(participant->connected_at);
    if (lease == NULL || peer == NULL || name == NULL || room == NULL || address == NULL
        || room_key == NULL || role == NULL || connected == NULL) {
        free(lease); free(peer); free(name); free(room); free(address);
        free(room_key); free(role); free(connected);
        return -1;
    }
    size_t capacity = strlen(lease) + strlen(peer) + strlen(name) + strlen(room)
        + strlen(address) + strlen(room_key) + strlen(role) + strlen(connected) + 256U;
    char *value = (char *)malloc(capacity);
    size_t name_capacity = strlen(participant->lease_id) + strlen(participant->peer_id) + 2U;
    char *name_value = (char *)malloc(name_capacity);
    int written = value == NULL ? -1 : snprintf(value,
        capacity,
        "%s\n{\"leaseId\":\"%s\",\"peerId\":\"%s\",\"displayName\":\"%s\"," 
        "\"roomId\":\"%s\",\"publicAddress\":\"%s\",\"roomKey\":\"%s\"," 
        "\"roomRole\":\"%s\",\"sharedRoom\":%s,\"connectedAt\":\"%s\"}",
        participant->lease_id,
        lease,
        peer,
        name,
        room,
        address,
        room_key,
        role,
        participant->shared_room ? "true" : "false",
        connected);
    int name_written = name_value == NULL ? -1 : snprintf(name_value,
                                                           name_capacity,
                                                           "%s\n%s",
                                                           participant->lease_id,
                                                           participant->peer_id);
    free(lease); free(peer); free(name); free(room); free(address);
    free(room_key); free(role); free(connected);
    if (written < 0 || (size_t)written >= capacity || name_written < 0
        || (size_t)name_written >= name_capacity) {
        free(value);
        free(name_value);
        return -1;
    }
    *value_out = value;
    *name_value_out = name_value;
    return 0;
}

static int cluster_reply_integer(const redisReply *reply, long long *value)
{
    if (reply == NULL || value == NULL) return -1;
    if (reply->type == REDIS_REPLY_INTEGER) {
        *value = reply->integer;
        return 0;
    }
    if ((reply->type == REDIS_REPLY_STRING || reply->type == REDIS_REPLY_STATUS)
        && reply->str != NULL) {
        char *end = NULL;
        errno = 0;
        long long parsed = strtoll(reply->str, &end, 10);
        if (errno == 0 && end != reply->str && *end == '\0') {
            *value = parsed;
            return 0;
        }
    }
    return -1;
}

int st_public_coordination_register(const st_public_cluster_participant *participant,
                                    int room_limit,
                                    uint64_t *revision)
{
    if (participant == NULL || revision == NULL || !st_public_coordination_available()) return -1;
    char member_id[65];
    cluster_sha_hex(participant->peer_id, member_id);
    char presence[512], name_key[512], members[512], group_revision[512];
    char net_revision[512], nets[512], presence_prefix[512], presence_base[512];
    if (cluster_presence_key(presence, sizeof(presence), participant->group_id, member_id) != 0
        || cluster_name_key(name_key, sizeof(name_key), participant->display_name) != 0
        || cluster_key(members, sizeof(members), "members", participant->group_id) != 0
        || cluster_key(group_revision, sizeof(group_revision), "revision", participant->group_id) != 0
        || cluster_key(net_revision, sizeof(net_revision), "revision", participant->net_id) != 0
        || cluster_key(nets, sizeof(nets), "nets", participant->net_id) != 0
        || cluster_presence_prefix(presence_prefix, sizeof(presence_prefix), participant->group_id) != 0
        || cluster_presence_base_prefix(presence_base, sizeof(presence_base)) != 0) return -1;
    char *peer_value = NULL;
    char *name_value = NULL;
    if (cluster_participant_value(participant, &peer_value, &name_value) != 0) return -1;
    char lease_ms[32], limit_text[32], revision_ttl[32];
    snprintf(lease_ms, sizeof(lease_ms), "%ld", cluster_state.config.lease_seconds * 1000L);
    snprintf(limit_text, sizeof(limit_text), "%d", room_limit < 1 ? 1 : room_limit);
    snprintf(revision_ttl, sizeof(revision_ttl), "%lld", ST_CLUSTER_REVISION_TTL_MS);
    const char *keys[] = {presence, name_key, members, group_revision, net_revision, nets};
    const char *arguments[] = {peer_value, name_value, member_id, lease_ms, limit_text,
                               presence_prefix, revision_ttl, participant->group_id, presence_base};
    redisReply *reply = cluster_eval(cluster_register_script,
                                     keys,
                                     sizeof(keys) / sizeof(keys[0]),
                                     arguments,
                                     NULL,
                                     sizeof(arguments) / sizeof(arguments[0]));
    free(peer_value);
    free(name_value);
    if (reply == NULL || reply->type != REDIS_REPLY_ARRAY || reply->elements != 2U) {
        freeReplyObject(reply);
        return -1;
    }
    long long code = 0;
    long long returned_revision = 0;
    int valid = cluster_reply_integer(reply->element[0], &code) == 0
        && cluster_reply_integer(reply->element[1], &returned_revision) == 0;
    freeReplyObject(reply);
    if (!valid) return -1;
    *revision = returned_revision < 0 ? 0U : (uint64_t)returned_revision;
    if (code == 1) return 0;
    if (code == -1) return 1;
    if (code == -2) return 2;
    if (code == -3) return 3;
    return -1;
}

int st_public_coordination_refresh(const st_public_cluster_participant *participant)
{
    if (participant == NULL || !st_public_coordination_available()) return -1;
    char member_id[65];
    cluster_sha_hex(participant->peer_id, member_id);
    char presence[512], name_key[512], members[512], nets[512];
    if (cluster_presence_key(presence, sizeof(presence), participant->group_id, member_id) != 0
        || cluster_name_key(name_key, sizeof(name_key), participant->display_name) != 0
        || cluster_key(members, sizeof(members), "members", participant->group_id) != 0
        || cluster_key(nets, sizeof(nets), "nets", participant->net_id) != 0) return -1;
    char *peer_value = NULL;
    char *name_value = NULL;
    if (cluster_participant_value(participant, &peer_value, &name_value) != 0) return -1;
    char lease_ms[32];
    snprintf(lease_ms, sizeof(lease_ms), "%ld", cluster_state.config.lease_seconds * 1000L);
    const char *keys[] = {presence, name_key, members, nets};
    const char *arguments[] = {peer_value, name_value, lease_ms};
    redisReply *reply = cluster_eval(cluster_refresh_script,
                                     keys,
                                     sizeof(keys) / sizeof(keys[0]),
                                     arguments,
                                     NULL,
                                     sizeof(arguments) / sizeof(arguments[0]));
    free(peer_value);
    free(name_value);
    long long refreshed = 0;
    int had_reply = reply != NULL;
    int result = cluster_reply_integer(reply, &refreshed) == 0 && refreshed == 1 ? 0 : 1;
    freeReplyObject(reply);
    return had_reply ? result : -1;
}

int st_public_coordination_unregister(const st_public_cluster_participant *participant,
                                      uint64_t *revision)
{
    if (participant == NULL || revision == NULL || !st_public_coordination_available()) return -1;
    char member_id[65];
    cluster_sha_hex(participant->peer_id, member_id);
    char presence[512], name_key[512], members[512], group_revision[512];
    char net_revision[512], nets[512];
    if (cluster_presence_key(presence, sizeof(presence), participant->group_id, member_id) != 0
        || cluster_name_key(name_key, sizeof(name_key), participant->display_name) != 0
        || cluster_key(members, sizeof(members), "members", participant->group_id) != 0
        || cluster_key(group_revision, sizeof(group_revision), "revision", participant->group_id) != 0
        || cluster_key(net_revision, sizeof(net_revision), "revision", participant->net_id) != 0
        || cluster_key(nets, sizeof(nets), "nets", participant->net_id) != 0) return -1;
    char *peer_value = NULL;
    char *name_value = NULL;
    if (cluster_participant_value(participant, &peer_value, &name_value) != 0) return -1;
    char revision_ttl[32];
    snprintf(revision_ttl, sizeof(revision_ttl), "%lld", ST_CLUSTER_REVISION_TTL_MS);
    const char *keys[] = {presence, name_key, members, group_revision, net_revision, nets};
    const char *arguments[] = {peer_value, name_value, member_id, revision_ttl,
                               participant->group_id};
    redisReply *reply = cluster_eval(cluster_unregister_script,
                                     keys,
                                     sizeof(keys) / sizeof(keys[0]),
                                     arguments,
                                     NULL,
                                     sizeof(arguments) / sizeof(arguments[0]));
    free(peer_value);
    free(name_value);
    long long returned_revision = 0;
    int result = cluster_reply_integer(reply, &returned_revision);
    freeReplyObject(reply);
    if (result != 0) return -1;
    *revision = returned_revision < 0 ? 0U : (uint64_t)returned_revision;
    return 0;
}

static int cluster_cleanup(const char *group_id,
                           const char *net_id,
                           long long *removed,
                           uint64_t *revision)
{
    char members[512], group_revision[512], net_revision[512], nets[512];
    char presence_prefix[512], revision_ttl[32];
    if (cluster_key(members, sizeof(members), "members", group_id) != 0
        || cluster_key(group_revision, sizeof(group_revision), "revision", group_id) != 0
        || cluster_key(net_revision, sizeof(net_revision), "revision", net_id) != 0
        || cluster_key(nets, sizeof(nets), "nets", net_id) != 0
        || cluster_presence_prefix(presence_prefix, sizeof(presence_prefix), group_id) != 0) return -1;
    snprintf(revision_ttl, sizeof(revision_ttl), "%lld", ST_CLUSTER_REVISION_TTL_MS);
    const char *keys[] = {members, group_revision, net_revision, nets};
    const char *arguments[] = {presence_prefix, revision_ttl, group_id};
    redisReply *reply = cluster_eval(cluster_cleanup_script,
                                     keys,
                                     sizeof(keys) / sizeof(keys[0]),
                                     arguments,
                                     NULL,
                                     sizeof(arguments) / sizeof(arguments[0]));
    if (reply == NULL || reply->type != REDIS_REPLY_ARRAY || reply->elements != 2U
        || cluster_reply_integer(reply->element[0], removed) != 0) {
        freeReplyObject(reply);
        return -1;
    }
    long long returned_revision = 0;
    if (cluster_reply_integer(reply->element[1], &returned_revision) != 0) {
        freeReplyObject(reply);
        return -1;
    }
    freeReplyObject(reply);
    *revision = returned_revision < 0 ? 0U : (uint64_t)returned_revision;
    return 0;
}

int st_public_coordination_sweep(const st_public_cluster_participant *participant)
{
    if (participant == NULL || !st_public_coordination_available()) return -1;
    long long removed = 0;
    uint64_t revision = 0U;
    if (cluster_cleanup(participant->group_id,
                        participant->net_id,
                        &removed,
                        &revision) != 0) return -1;
    if (removed > 0) {
        if (st_public_coordination_publish_roster(participant->group_id, revision) != 0
            || st_public_coordination_publish_roster(participant->net_id, revision) != 0) return -1;
    }
    return 0;
}

static int cluster_copy_json_string(const char *json,
                                    const char *name,
                                    char *out,
                                    size_t out_len)
{
    char *value = st_json_get_top_level_string(json, name);
    if (value == NULL || strlen(value) >= out_len) {
        free(value);
        return -1;
    }
    memcpy(out, value, strlen(value) + 1U);
    free(value);
    return 0;
}

static int cluster_decode_participant(const char *encoded,
                                      size_t encoded_len,
                                      st_public_cluster_participant *participant)
{
    const char *separator = memchr(encoded, '\n', encoded_len);
    if (separator == NULL || separator == encoded) return -1;
    size_t lease_len = (size_t)(separator - encoded);
    size_t json_len = encoded_len - lease_len - 1U;
    if (lease_len > ST_PUBLIC_CLUSTER_LEASE_BYTES || json_len == 0U) return -1;
    char *json = (char *)malloc(json_len + 1U);
    if (json == NULL) return -1;
    memcpy(json, separator + 1, json_len);
    json[json_len] = '\0';
    memset(participant, 0, sizeof(*participant));
    int valid = st_json_is_valid_object(json)
        && cluster_copy_json_string(json, "leaseId", participant->lease_id,
                                    sizeof(participant->lease_id)) == 0
        && strlen(participant->lease_id) == lease_len
        && memcmp(participant->lease_id, encoded, lease_len) == 0
        && cluster_copy_json_string(json, "peerId", participant->peer_id,
                                    sizeof(participant->peer_id)) == 0
        && cluster_copy_json_string(json, "displayName", participant->display_name,
                                    sizeof(participant->display_name)) == 0
        && cluster_copy_json_string(json, "roomId", participant->room_id,
                                    sizeof(participant->room_id)) == 0
        && cluster_copy_json_string(json, "publicAddress", participant->public_address,
                                    sizeof(participant->public_address)) == 0
        && cluster_copy_json_string(json, "roomKey", participant->room_key,
                                    sizeof(participant->room_key)) == 0
        && cluster_copy_json_string(json, "roomRole", participant->room_role,
                                    sizeof(participant->room_role)) == 0
        && cluster_copy_json_string(json, "connectedAt", participant->connected_at,
                                    sizeof(participant->connected_at)) == 0;
    char *shared = valid ? st_json_get_top_level_raw(json, "sharedRoom") : NULL;
    if (valid && shared != NULL && strcmp(shared, "true") == 0) participant->shared_room = 1;
    else if (valid && shared != NULL && strcmp(shared, "false") == 0) participant->shared_room = 0;
    else valid = 0;
    free(shared);
    free(json);
    return valid && cluster_compute_ids(participant) == 0 ? 0 : -1;
}

static int cluster_smembers(const char *key, char ***values, size_t *count)
{
    const char *argv[] = {"SMEMBERS", key};
    size_t lengths[] = {8U, strlen(key)};
    redisReply *reply = cluster_command_argv(2, argv, lengths);
    if (reply == NULL || reply->type != REDIS_REPLY_ARRAY) {
        freeReplyObject(reply);
        return -1;
    }
    char **items = (char **)calloc(reply->elements == 0U ? 1U : reply->elements, sizeof(*items));
    if (items == NULL) {
        freeReplyObject(reply);
        return -1;
    }
    size_t copied = 0U;
    for (size_t i = 0U; i < reply->elements; ++i) {
        redisReply *item = reply->element[i];
        if (item == NULL || item->type != REDIS_REPLY_STRING || item->str == NULL) continue;
        items[copied] = strndup(item->str, item->len);
        if (items[copied] == NULL) {
            for (size_t j = 0U; j < copied; ++j) free(items[j]);
            free(items);
            freeReplyObject(reply);
            return -1;
        }
        ++copied;
    }
    freeReplyObject(reply);
    *values = items;
    *count = copied;
    return 0;
}

static void cluster_strings_free(char **values, size_t count)
{
    if (values == NULL) return;
    for (size_t i = 0U; i < count; ++i) free(values[i]);
    free(values);
}

static int cluster_get(const char *key, char **value, size_t *value_len, int *found)
{
    const char *argv[] = {"GET", key};
    size_t lengths[] = {3U, strlen(key)};
    redisReply *reply = cluster_command_argv(2, argv, lengths);
    if (reply == NULL) return -1;
    if (reply->type == REDIS_REPLY_NIL) {
        *found = 0;
        *value = NULL;
        *value_len = 0U;
        freeReplyObject(reply);
        return 0;
    }
    if (reply->type != REDIS_REPLY_STRING || reply->str == NULL) {
        freeReplyObject(reply);
        return -1;
    }
    char *copy = (char *)malloc(reply->len + 1U);
    if (copy == NULL) {
        freeReplyObject(reply);
        return -1;
    }
    memcpy(copy, reply->str, reply->len);
    copy[reply->len] = '\0';
    *found = 1;
    *value = copy;
    *value_len = reply->len;
    freeReplyObject(reply);
    return 0;
}

static int cluster_revision(const char *id, uint64_t *revision)
{
    char key[512];
    if (cluster_key(key, sizeof(key), "revision", id) != 0) return -1;
    char *value = NULL;
    size_t value_len = 0U;
    int found = 0;
    if (cluster_get(key, &value, &value_len, &found) != 0) return -1;
    if (!found) {
        *revision = 0U;
        return 0;
    }
    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(value, &end, 10);
    int valid = errno == 0 && end != value && *end == '\0';
    free(value);
    if (!valid) return -1;
    *revision = (uint64_t)parsed;
    return 0;
}

static int cluster_append_unique_string(char ***values,
                                        size_t *count,
                                        size_t *capacity,
                                        const char *value)
{
    for (size_t i = 0U; i < *count; ++i) {
        if (strcmp((*values)[i], value) == 0) return 0;
    }
    if (*count == *capacity) {
        size_t next = *capacity == 0U ? 8U : *capacity * 2U;
        char **grown = (char **)realloc(*values, next * sizeof(*grown));
        if (grown == NULL) return -1;
        *values = grown;
        *capacity = next;
    }
    (*values)[*count] = strdup(value);
    if ((*values)[*count] == NULL) return -1;
    ++*count;
    return 0;
}

static int cluster_net_groups(const st_public_cluster_participant *recipient,
                              char ***groups,
                              size_t *group_count)
{
    char nets_key[512];
    if (cluster_key(nets_key, sizeof(nets_key), "nets", recipient->net_id) != 0) return -1;
    char **members = NULL;
    size_t member_count = 0U;
    if (cluster_smembers(nets_key, &members, &member_count) != 0) return -1;
    char **result = NULL;
    size_t count = 0U;
    size_t capacity = 0U;
    int failed = cluster_append_unique_string(&result,
                                              &count,
                                              &capacity,
                                              recipient->group_id) != 0;
    for (size_t i = 0U; i < member_count && !failed; ++i)
        failed = cluster_append_unique_string(&result, &count, &capacity, members[i]) != 0;
    cluster_strings_free(members, member_count);
    if (failed) {
        cluster_strings_free(result, count);
        return -1;
    }
    *groups = result;
    *group_count = count;
    return 0;
}

static int cluster_address_known(const char *address)
{
    return address != NULL && *address != '\0' && strcasecmp(address, "unknown") != 0;
}

static int cluster_visible(const st_public_cluster_participant *recipient,
                           const st_public_cluster_participant *participant)
{
    return (strcmp(recipient->room_id, participant->room_id) == 0
            && strcmp(recipient->room_key, participant->room_key) == 0)
        || (cluster_address_known(recipient->public_address)
            && strcmp(recipient->public_address, participant->public_address) == 0);
}

static int cluster_roster_append(st_public_cluster_roster *roster,
                                 size_t *capacity,
                                 const st_public_cluster_participant *participant)
{
    for (size_t i = 0U; i < roster->count; ++i) {
        if (strcmp(roster->participants[i].peer_id, participant->peer_id) == 0) return 0;
    }
    if (roster->count == *capacity) {
        size_t next = *capacity == 0U ? 8U : *capacity * 2U;
        st_public_cluster_participant *grown = (st_public_cluster_participant *)realloc(
            roster->participants,
            next * sizeof(*grown));
        if (grown == NULL) return -1;
        roster->participants = grown;
        *capacity = next;
    }
    roster->participants[roster->count++] = *participant;
    return 0;
}

static int cluster_participant_compare(const void *left, const void *right)
{
    const st_public_cluster_participant *a = (const st_public_cluster_participant *)left;
    const st_public_cluster_participant *b = (const st_public_cluster_participant *)right;
    int connected = strcmp(a->connected_at, b->connected_at);
    return connected != 0 ? connected : strcmp(a->peer_id, b->peer_id);
}

static int cluster_read_participants(const st_public_cluster_participant *recipient,
                                     char **groups,
                                     size_t group_count,
                                     st_public_cluster_roster *roster)
{
    size_t capacity = 0U;
    for (size_t group = 0U; group < group_count; ++group) {
        char members_key[512];
        if (cluster_key(members_key, sizeof(members_key), "members", groups[group]) != 0) return -1;
        char **members = NULL;
        size_t member_count = 0U;
        if (cluster_smembers(members_key, &members, &member_count) != 0) return -1;
        for (size_t member = 0U; member < member_count; ++member) {
            char presence_key[512];
            char *encoded = NULL;
            size_t encoded_len = 0U;
            int found = 0;
            if (cluster_presence_key(presence_key,
                                     sizeof(presence_key),
                                     groups[group],
                                     members[member]) != 0
                || cluster_get(presence_key, &encoded, &encoded_len, &found) != 0) {
                cluster_strings_free(members, member_count);
                return -1;
            }
            if (found) {
                st_public_cluster_participant participant;
                if (cluster_decode_participant(encoded, encoded_len, &participant) == 0
                    && strcmp(participant.group_id, groups[group]) == 0
                    && cluster_visible(recipient, &participant)
                    && cluster_roster_append(roster, &capacity, &participant) != 0) {
                    free(encoded);
                    cluster_strings_free(members, member_count);
                    return -1;
                }
            }
            free(encoded);
        }
        cluster_strings_free(members, member_count);
    }
    return 0;
}

void st_public_coordination_roster_free(st_public_cluster_roster *roster)
{
    if (roster == NULL) return;
    free(roster->participants);
    memset(roster, 0, sizeof(*roster));
}

int st_public_coordination_roster(const st_public_cluster_participant *recipient,
                                  st_public_cluster_roster *roster)
{
    if (recipient == NULL || roster == NULL || !st_public_coordination_available()) return -1;
    memset(roster, 0, sizeof(*roster));
    char **groups = NULL;
    size_t group_count = 0U;
    if (cluster_net_groups(recipient, &groups, &group_count) != 0) return -1;
    int removed_any = 0;
    uint64_t cleanup_revision = 0U;
    for (size_t i = 0U; i < group_count; ++i) {
        long long removed = 0;
        uint64_t revision = 0U;
        if (cluster_cleanup(groups[i], recipient->net_id, &removed, &revision) != 0) {
            cluster_strings_free(groups, group_count);
            return -1;
        }
        if (removed > 0) {
            removed_any = 1;
            cleanup_revision = revision;
        }
    }
    if (removed_any) {
        (void)st_public_coordination_publish_roster(recipient->group_id, cleanup_revision);
        (void)st_public_coordination_publish_roster(recipient->net_id, cleanup_revision);
    }
    int result = -1;
    for (int attempt = 0; attempt < 2; ++attempt) {
        uint64_t before_group = 0U, before_net = 0U, after_group = 0U, after_net = 0U;
        st_public_coordination_roster_free(roster);
        if (cluster_revision(recipient->group_id, &before_group) != 0
            || cluster_revision(recipient->net_id, &before_net) != 0
            || cluster_read_participants(recipient, groups, group_count, roster) != 0
            || cluster_revision(recipient->group_id, &after_group) != 0
            || cluster_revision(recipient->net_id, &after_net) != 0) break;
        if (attempt == 1 || (before_group == after_group && before_net == after_net)) {
            roster->revision = after_group + after_net;
            qsort(roster->participants,
                  roster->count,
                  sizeof(*roster->participants),
                  cluster_participant_compare);
            result = 0;
            break;
        }
    }
    cluster_strings_free(groups, group_count);
    if (result != 0) st_public_coordination_roster_free(roster);
    return result;
}

int st_public_coordination_find_peer(const st_public_cluster_participant *recipient,
                                    const char *peer_id,
                                    st_public_cluster_participant *target,
                                    int *found)
{
    if (recipient == NULL || peer_id == NULL || target == NULL || found == NULL) return -1;
    *found = 0;
    st_public_cluster_roster roster;
    if (st_public_coordination_roster(recipient, &roster) != 0) return -1;
    for (size_t i = 0U; i < roster.count; ++i) {
        if (strcmp(roster.participants[i].peer_id, peer_id) == 0) {
            *target = roster.participants[i];
            *found = 1;
            break;
        }
    }
    st_public_coordination_roster_free(&roster);
    return 0;
}

int st_public_coordination_name_available(const char *display_name,
                                          const char *exclude_peer_id,
                                          int *available)
{
    if (display_name == NULL || available == NULL || !st_public_coordination_available()) return -1;
    char key[512];
    if (cluster_name_key(key, sizeof(key), display_name) != 0) return -1;
    char *owner = NULL;
    size_t owner_len = 0U;
    int found = 0;
    if (cluster_get(key, &owner, &owner_len, &found) != 0) return -1;
    if (!found) {
        *available = 1;
        return 0;
    }
    const char *separator = memchr(owner, '\n', owner_len);
    const char *peer = separator == NULL ? "" : separator + 1;
    *available = exclude_peer_id != NULL && *exclude_peer_id != '\0'
        && strcmp(peer, exclude_peer_id) == 0;
    free(owner);
    return 0;
}

int st_public_coordination_allow_rate(const char *bucket,
                                      const char *identity,
                                      long limit,
                                      long window_seconds,
                                      int *allowed)
{
    if (bucket == NULL || identity == NULL || allowed == NULL
        || !st_public_coordination_available()) return -1;
    size_t bucket_len = strlen(bucket);
    size_t identity_len = strlen(identity);
    uint8_t *input = (uint8_t *)malloc(bucket_len + 1U + identity_len);
    if (input == NULL) return -1;
    memcpy(input, bucket, bucket_len);
    input[bucket_len] = 0U;
    memcpy(input + bucket_len + 1U, identity, identity_len);
    char digest[65];
    cluster_sha_hex_bytes(input, bucket_len + 1U + identity_len, digest);
    free(input);
    char key[512];
    int written = snprintf(key,
                           sizeof(key),
                           "%s:rate:%s",
                           cluster_state.config.key_prefix,
                           digest);
    if (written < 0 || (size_t)written >= sizeof(key)) return -1;
    char limit_text[32], window_text[32];
    snprintf(limit_text, sizeof(limit_text), "%ld", limit < 1L ? 1L : limit);
    long normalized_window = window_seconds < 1L ? 1L : window_seconds;
    long window_milliseconds = normalized_window > LONG_MAX / 1000L
        ? LONG_MAX : normalized_window * 1000L;
    snprintf(window_text,
             sizeof(window_text),
             "%ld",
             window_milliseconds);
    const char *keys[] = {key};
    const char *arguments[] = {limit_text, window_text};
    redisReply *reply = cluster_eval(cluster_rate_script,
                                     keys,
                                     1U,
                                     arguments,
                                     NULL,
                                     2U);
    long long value = 0;
    int result = cluster_reply_integer(reply, &value);
    freeReplyObject(reply);
    if (result != 0) return -1;
    *allowed = value == 1;
    return 0;
}

static void cluster_write_u16(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)(value >> 8U);
    out[1] = (uint8_t)value;
}

static void cluster_write_u32(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value >> 24U);
    out[1] = (uint8_t)(value >> 16U);
    out[2] = (uint8_t)(value >> 8U);
    out[3] = (uint8_t)value;
}

static void cluster_write_u64(uint8_t *out, uint64_t value)
{
    for (size_t i = 0U; i < 8U; ++i)
        out[i] = (uint8_t)(value >> ((7U - i) * 8U));
}

static uint16_t cluster_read_u16(const uint8_t *data)
{
    return (uint16_t)(((uint16_t)data[0] << 8U) | data[1]);
}

static uint32_t cluster_read_u32(const uint8_t *data)
{
    return ((uint32_t)data[0] << 24U) | ((uint32_t)data[1] << 16U)
        | ((uint32_t)data[2] << 8U) | data[3];
}

static uint64_t cluster_read_u64(const uint8_t *data)
{
    uint64_t value = 0U;
    for (size_t i = 0U; i < 8U; ++i) value = (value << 8U) | data[i];
    return value;
}

static int cluster_event_encode(uint8_t kind,
                                const char *group_id,
                                const char *target_peer_id,
                                const char *source_lease_id,
                                int exclude_source,
                                uint64_t revision,
                                const uint8_t *payload,
                                size_t payload_len,
                                uint8_t **encoded,
                                size_t *encoded_len)
{
    size_t group_len = group_id == NULL ? 0U : strlen(group_id);
    size_t target_len = target_peer_id == NULL ? 0U : strlen(target_peer_id);
    size_t source_len = source_lease_id == NULL ? 0U : strlen(source_lease_id);
    if (kind < ST_PUBLIC_CLUSTER_EVENT_ROSTER || kind > ST_PUBLIC_CLUSTER_EVENT_MANAGEMENT
        || group_len == 0U || group_len > ST_CLUSTER_EVENT_MAX_GROUP_BYTES
        || target_len > ST_CLUSTER_EVENT_MAX_ID_BYTES
        || source_len > ST_CLUSTER_EVENT_MAX_ID_BYTES
        || payload_len > ST_CLUSTER_EVENT_MAX_PAYLOAD_BYTES
        || (payload_len > 0U && payload == NULL)
        || (kind == ST_PUBLIC_CLUSTER_EVENT_ROSTER && payload_len != 0U)
        || (kind == ST_PUBLIC_CLUSTER_EVENT_BINARY && target_len == 0U)) return -1;
    size_t total = ST_CLUSTER_EVENT_HEADER_BYTES + group_len + target_len + source_len + payload_len;
    uint8_t *result = (uint8_t *)calloc(total, 1U);
    if (result == NULL) return -1;
    memcpy(result, "STCE", 4U);
    result[4] = 2U;
    result[5] = kind;
    result[6] = exclude_source ? 1U : 0U;
    cluster_write_u64(result + 8U, revision);
    cluster_write_u16(result + 16U, (uint16_t)group_len);
    cluster_write_u16(result + 18U, (uint16_t)target_len);
    cluster_write_u16(result + 20U, (uint16_t)source_len);
    cluster_write_u32(result + 22U, (uint32_t)payload_len);
    size_t offset = ST_CLUSTER_EVENT_HEADER_BYTES;
    memcpy(result + offset, group_id, group_len);
    offset += group_len;
    if (target_len > 0U) memcpy(result + offset, target_peer_id, target_len);
    offset += target_len;
    if (source_len > 0U) memcpy(result + offset, source_lease_id, source_len);
    offset += source_len;
    if (payload_len > 0U) memcpy(result + offset, payload, payload_len);
    *encoded = result;
    *encoded_len = total;
    return 0;
}

static int cluster_event_decode(const uint8_t *encoded,
                                size_t encoded_len,
                                st_public_cluster_event *event)
{
    if (encoded == NULL || event == NULL || encoded_len < ST_CLUSTER_EVENT_HEADER_BYTES
        || memcmp(encoded, "STCE", 4U) != 0 || encoded[4] != 2U) return -1;
    uint8_t kind = encoded[5];
    uint8_t flags = encoded[6];
    size_t group_len = cluster_read_u16(encoded + 16U);
    size_t target_len = cluster_read_u16(encoded + 18U);
    size_t source_len = cluster_read_u16(encoded + 20U);
    size_t payload_len = cluster_read_u32(encoded + 22U);
    if (kind < ST_PUBLIC_CLUSTER_EVENT_ROSTER || kind > ST_PUBLIC_CLUSTER_EVENT_MANAGEMENT
        || (flags & ~1U) != 0U || encoded[7] != 0U
        || group_len == 0U || group_len > ST_CLUSTER_EVENT_MAX_GROUP_BYTES
        || target_len > ST_PUBLIC_CLUSTER_PEER_BYTES
        || source_len > ST_PUBLIC_CLUSTER_LEASE_BYTES
        || payload_len > ST_CLUSTER_EVENT_MAX_PAYLOAD_BYTES
        || ST_CLUSTER_EVENT_HEADER_BYTES + group_len + target_len + source_len + payload_len
            != encoded_len
        || (kind == ST_PUBLIC_CLUSTER_EVENT_ROSTER && payload_len != 0U)
        || (kind == ST_PUBLIC_CLUSTER_EVENT_BINARY && target_len == 0U)) return -1;
    memset(event, 0, sizeof(*event));
    event->kind = kind;
    event->exclude_source = (flags & 1U) != 0U;
    event->revision = cluster_read_u64(encoded + 8U);
    size_t offset = ST_CLUSTER_EVENT_HEADER_BYTES;
    memcpy(event->group_id, encoded + offset, group_len);
    event->group_id[group_len] = '\0';
    offset += group_len;
    memcpy(event->target_peer_id, encoded + offset, target_len);
    event->target_peer_id[target_len] = '\0';
    offset += target_len;
    memcpy(event->source_lease_id, encoded + offset, source_len);
    event->source_lease_id[source_len] = '\0';
    offset += source_len;
    if (payload_len > 0U) {
        event->payload = (uint8_t *)malloc(payload_len);
        if (event->payload == NULL) return -1;
        memcpy(event->payload, encoded + offset, payload_len);
    }
    event->payload_len = payload_len;
    return 0;
}

static int cluster_publish(uint8_t kind,
                           const char *group_id,
                           const char *target_peer_id,
                           const char *source_lease_id,
                           int exclude_source,
                           uint64_t revision,
                           const uint8_t *payload,
                           size_t payload_len)
{
    uint8_t *encoded = NULL;
    size_t encoded_len = 0U;
    if (!st_public_coordination_available()
        || cluster_event_encode(kind,
                                group_id,
                                target_peer_id,
                                source_lease_id,
                                exclude_source,
                                revision,
                                payload,
                                payload_len,
                                &encoded,
                                &encoded_len) != 0) return -1;
    char channel[512];
    int channel_len = snprintf(channel,
                               sizeof(channel),
                               "%s:events",
                               cluster_state.config.key_prefix);
    if (channel_len < 0 || (size_t)channel_len >= sizeof(channel)) {
        free(encoded);
        return -1;
    }
    const char *argv[] = {"PUBLISH", channel, (const char *)encoded};
    size_t lengths[] = {7U, (size_t)channel_len, encoded_len};
    redisReply *reply = cluster_command_argv(3, argv, lengths);
    free(encoded);
    long long receivers = 0;
    int result = cluster_reply_integer(reply, &receivers);
    freeReplyObject(reply);
    return result;
}

int st_public_coordination_publish_roster(const char *group_id, uint64_t revision)
{
    return cluster_publish(ST_PUBLIC_CLUSTER_EVENT_ROSTER,
                           group_id,
                           "",
                           "",
                           0,
                           revision,
                           NULL,
                           0U);
}

int st_public_coordination_publish_text(const char *group_id,
                                        const char *target_peer_id,
                                        const char *source_lease_id,
                                        int exclude_source,
                                        const uint8_t *payload,
                                        size_t payload_len)
{
    return cluster_publish(ST_PUBLIC_CLUSTER_EVENT_TEXT,
                           group_id,
                           target_peer_id == NULL ? "" : target_peer_id,
                           source_lease_id == NULL ? "" : source_lease_id,
                           exclude_source,
                           0U,
                           payload,
                           payload_len);
}

int st_public_coordination_publish_binary(const char *group_id,
                                          const char *target_peer_id,
                                          const uint8_t *payload,
                                          size_t payload_len)
{
    return cluster_publish(ST_PUBLIC_CLUSTER_EVENT_BINARY,
                           group_id,
                           target_peer_id,
                           "",
                           0,
                           0U,
                           payload,
                           payload_len);
}

static void *cluster_subscriber_thread(void *unused)
{
    (void)unused;
    for (;;) {
        void *raw_reply = NULL;
        pthread_mutex_lock(&cluster_state.state_lock);
        redisContext *subscriber = cluster_state.subscriber;
        int stopping = cluster_state.stopping;
        pthread_mutex_unlock(&cluster_state.state_lock);
        if (subscriber == NULL || stopping) break;
        if (redisGetReply(subscriber, &raw_reply) != REDIS_OK || raw_reply == NULL) {
            freeReplyObject(raw_reply);
            cluster_mark_unavailable();
            break;
        }
        redisReply *reply = (redisReply *)raw_reply;
        if (reply->type == REDIS_REPLY_ARRAY && reply->elements == 3U
            && reply->element[0] != NULL && reply->element[0]->str != NULL
            && strcmp(reply->element[0]->str, "message") == 0
            && reply->element[2] != NULL && reply->element[2]->type == REDIS_REPLY_STRING) {
            st_public_cluster_event event;
            if (cluster_event_decode((const uint8_t *)reply->element[2]->str,
                                     reply->element[2]->len,
                                     &event) == 0) {
                st_public_cluster_event_handler handler = NULL;
                void *context = NULL;
                pthread_mutex_lock(&cluster_state.state_lock);
                handler = cluster_state.handler;
                context = cluster_state.handler_context;
                pthread_mutex_unlock(&cluster_state.state_lock);
                if (handler != NULL) handler(&event, context);
                free(event.payload);
            }
        }
        freeReplyObject(reply);
    }
    return NULL;
}

int st_public_coordination_initialize(st_public_cluster_event_handler handler, void *context)
{
    if (!st_public_coordination_enabled()) return 0;
    pthread_mutex_lock(&cluster_state.state_lock);
    if (cluster_state.initialized) {
        cluster_state.handler = handler;
        cluster_state.handler_context = context;
        int available = cluster_state.available;
        pthread_mutex_unlock(&cluster_state.state_lock);
        return available ? 0 : -1;
    }
    st_cluster_config config;
    memset(&config, 0, sizeof(config));
    if (cluster_parse_uri(&config) != 0) {
        pthread_mutex_unlock(&cluster_state.state_lock);
        return -1;
    }
    redisContext *command = cluster_connect(&config);
    redisContext *subscriber = command == NULL ? NULL : cluster_connect(&config);
    if (command == NULL || subscriber == NULL) {
        if (command != NULL) redisFree(command);
        if (subscriber != NULL) redisFree(subscriber);
        pthread_mutex_unlock(&cluster_state.state_lock);
        return -1;
    }
    char channel[512];
    int channel_len = snprintf(channel, sizeof(channel), "%s:events", config.key_prefix);
    const char *argv[] = {"SUBSCRIBE", channel};
    size_t lengths[] = {9U, channel_len < 0 ? 0U : (size_t)channel_len};
    redisReply *subscription = channel_len < 0 || (size_t)channel_len >= sizeof(channel)
        ? NULL : (redisReply *)redisCommandArgv(subscriber, 2, argv, lengths);
    int subscribed = subscription != NULL && subscription->type == REDIS_REPLY_ARRAY
        && subscription->elements == 3U;
    freeReplyObject(subscription);
    struct timeval no_read_timeout = {0};
    if (subscribed
        && setsockopt(subscriber->fd,
                      SOL_SOCKET,
                      SO_RCVTIMEO,
                      &no_read_timeout,
                      sizeof(no_read_timeout)) != 0) subscribed = 0;
    if (!subscribed) {
        redisFree(command);
        redisFree(subscriber);
        pthread_mutex_unlock(&cluster_state.state_lock);
        return -1;
    }
    cluster_state.command = command;
    cluster_state.subscriber = subscriber;
    cluster_state.config = config;
    cluster_state.handler = handler;
    cluster_state.handler_context = context;
    cluster_state.stopping = 0;
    cluster_state.available = 1;
    cluster_state.initialized = 1;
    if (pthread_create(&cluster_state.subscriber_thread,
                       NULL,
                       cluster_subscriber_thread,
                       NULL) != 0) {
        cluster_state.command = NULL;
        cluster_state.subscriber = NULL;
        cluster_state.available = 0;
        cluster_state.initialized = 0;
        redisFree(command);
        redisFree(subscriber);
        pthread_mutex_unlock(&cluster_state.state_lock);
        return -1;
    }
    cluster_state.subscriber_started = 1;
    pthread_mutex_unlock(&cluster_state.state_lock);
    fprintf(stderr,
            "[public-transfer] Redis coordination enabled prefix=%s\n",
            config.key_prefix);
    return 0;
}

void st_public_coordination_shutdown(void)
{
    pthread_mutex_lock(&cluster_state.state_lock);
    if (!cluster_state.initialized) {
        pthread_mutex_unlock(&cluster_state.state_lock);
        return;
    }
    cluster_state.stopping = 1;
    cluster_state.available = 0;
    redisContext *subscriber = cluster_state.subscriber;
    int subscriber_started = cluster_state.subscriber_started;
    pthread_t subscriber_thread = cluster_state.subscriber_thread;
    if (subscriber != NULL && subscriber->fd >= 0) (void)shutdown(subscriber->fd, SHUT_RDWR);
    pthread_mutex_unlock(&cluster_state.state_lock);
    if (subscriber_started && !pthread_equal(pthread_self(), subscriber_thread))
        (void)pthread_join(subscriber_thread, NULL);
    pthread_mutex_lock(&cluster_state.command_lock);
    pthread_mutex_lock(&cluster_state.state_lock);
    redisContext *command = cluster_state.command;
    subscriber = cluster_state.subscriber;
    cluster_state.command = NULL;
    cluster_state.subscriber = NULL;
    cluster_state.subscriber_started = 0;
    cluster_state.initialized = 0;
    cluster_state.stopping = 0;
    cluster_state.handler = NULL;
    cluster_state.handler_context = NULL;
    pthread_mutex_unlock(&cluster_state.state_lock);
    if (command != NULL) redisFree(command);
    if (subscriber != NULL) redisFree(subscriber);
    pthread_mutex_unlock(&cluster_state.command_lock);
}
