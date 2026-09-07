#define _POSIX_C_SOURCE 200809L

#include "public_discovery.h"

#include "crypto.h"
#include "json.h"
#include "public_coordination.h"
#include "public_room.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#define ST_PUBLIC_TICKET_BYTES 32U
#define ST_PUBLIC_TICKET_TTL_SECONDS 45
#define ST_PUBLIC_MAX_TICKETS 1024U
#define ST_PUBLIC_ROOM_ID_BYTES 480U
#define ST_PUBLIC_PEER_ID_BYTES 480U
#define ST_PUBLIC_DISPLAY_NAME_BYTES 480U
#define ST_PUBLIC_ROOM_TOKEN_BYTES 2048U
#define ST_PUBLIC_ADDRESS_BYTES 128U
#define ST_PUBLIC_ROOM_KEY_BYTES 80U
#define ST_PUBLIC_MAX_MESSAGE_CHARS (64U * 1024U)
#define ST_PUBLIC_MAX_MESSAGE_BYTES (3U * ST_PUBLIC_MAX_MESSAGE_CHARS)
#define ST_PUBLIC_MAX_BINARY_BYTES (64U * 1024U)

typedef struct st_public_ticket {
    uint8_t token_hash[ST_SHA256_LEN];
    uint8_t remote_hash[ST_SHA256_LEN];
    char room_id[ST_PUBLIC_ROOM_ID_BYTES + 1U];
    char peer_id[ST_PUBLIC_PEER_ID_BYTES + 1U];
    char display_name[ST_PUBLIC_DISPLAY_NAME_BYTES + 1U];
    char public_address[ST_PUBLIC_ADDRESS_BYTES + 1U];
    char room_key[ST_PUBLIC_ROOM_KEY_BYTES + 1U];
    char room_role[16];
    int shared_room;
    int discoverable;
    time_t expires_at;
    struct st_public_ticket *next;
} st_public_ticket;

typedef struct st_public_peer {
    int fd;
    char room_id[ST_PUBLIC_ROOM_ID_BYTES + 1U];
    char peer_id[ST_PUBLIC_PEER_ID_BYTES + 1U];
    char display_name[ST_PUBLIC_DISPLAY_NAME_BYTES + 1U];
    char public_address[ST_PUBLIC_ADDRESS_BYTES + 1U];
    char room_key[ST_PUBLIC_ROOM_KEY_BYTES + 1U];
    char room_role[16];
    char connected_at[40];
    int shared_room;
    int discoverable;
    st_public_cluster_participant cluster;
    time_t rate_window_started;
    unsigned int rate_window_count;
    pthread_mutex_t send_lock;
    struct st_public_peer *next;
} st_public_peer;

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} st_public_builder;

static pthread_mutex_t public_ticket_lock = PTHREAD_MUTEX_INITIALIZER;
static st_public_ticket *public_tickets = NULL;
static pthread_mutex_t public_peer_lock = PTHREAD_MUTEX_INITIALIZER;
static st_public_peer *public_peers = NULL;
static uint64_t public_roster_revision = 0U;
static pthread_mutex_t public_discovery_init_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t public_refresh_cond = PTHREAD_COND_INITIALIZER;
static pthread_t public_refresh_thread;
static int public_discovery_initialized = 0;
static int public_refresh_started = 0;
static int public_refresh_stop = 0;

static void public_cluster_event_handler(const st_public_cluster_event *event, void *context);
static void *public_cluster_refresh_thread(void *unused);

int st_public_discovery_initialize(void)
{
    pthread_mutex_lock(&public_discovery_init_lock);
    if (public_discovery_initialized) {
        int result = !st_public_coordination_enabled() || st_public_coordination_available() ? 0 : -1;
        pthread_mutex_unlock(&public_discovery_init_lock);
        return result;
    }
    if (st_public_coordination_enabled()) {
        if (st_public_coordination_initialize(public_cluster_event_handler, NULL) != 0) {
            pthread_mutex_unlock(&public_discovery_init_lock);
            return -1;
        }
        public_refresh_stop = 0;
        if (pthread_create(&public_refresh_thread,
                           NULL,
                           public_cluster_refresh_thread,
                           NULL) != 0) {
            st_public_coordination_shutdown();
            pthread_mutex_unlock(&public_discovery_init_lock);
            return -1;
        }
        public_refresh_started = 1;
    }
    public_discovery_initialized = 1;
    pthread_mutex_unlock(&public_discovery_init_lock);
    return 0;
}

void st_public_discovery_shutdown(void)
{
    pthread_mutex_lock(&public_discovery_init_lock);
    if (!public_discovery_initialized) {
        pthread_mutex_unlock(&public_discovery_init_lock);
        return;
    }
    public_refresh_stop = 1;
    pthread_cond_broadcast(&public_refresh_cond);
    int refresh_started = public_refresh_started;
    pthread_t refresh_thread = public_refresh_thread;
    public_refresh_started = 0;
    public_discovery_initialized = 0;
    pthread_mutex_unlock(&public_discovery_init_lock);
    if (refresh_started && !pthread_equal(pthread_self(), refresh_thread))
        (void)pthread_join(refresh_thread, NULL);
    st_public_coordination_shutdown();
}

static int public_send_all(int fd, const void *data, size_t len)
{
    const uint8_t *bytes = (const uint8_t *)data;
    size_t offset = 0U;
    while (offset < len) {
        ssize_t written = send(fd, bytes + offset, len - offset, MSG_NOSIGNAL);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return -1;
        }
        offset += (size_t)written;
    }
    return 0;
}

static int public_recv_all(int fd, void *data, size_t len)
{
    uint8_t *bytes = (uint8_t *)data;
    size_t offset = 0U;
    while (offset < len) {
        ssize_t received = recv(fd, bytes + offset, len - offset, 0);
        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received <= 0) {
            return -1;
        }
        offset += (size_t)received;
    }
    return 0;
}

static int public_random(uint8_t *out, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    size_t offset = 0U;
    while (offset < len) {
        ssize_t received = read(fd, out + offset, len - offset);
        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received <= 0) {
            close(fd);
            return -1;
        }
        offset += (size_t)received;
    }
    close(fd);
    return 0;
}

static void public_hash_text(const char *value, uint8_t out[ST_SHA256_LEN])
{
    const char *text = value == NULL ? "" : value;
    st_sha256((const uint8_t *)text, strlen(text), out);
}

static int public_base64(const uint8_t *data, size_t len, int url_safe, char *out, size_t out_len)
{
    static const char standard[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static const char url[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const char *alphabet = url_safe ? url : standard;
    size_t needed = ((len + 2U) / 3U) * 4U;
    if (url_safe) {
        size_t padding = (3U - (len % 3U)) % 3U;
        needed -= padding;
    }
    if (needed + 1U > out_len) {
        return -1;
    }
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
        else if (!url_safe) out[written++] = '=';
        if (remaining > 2U) out[written++] = alphabet[value & 63U];
        else if (!url_safe) out[written++] = '=';
    }
    out[written] = '\0';
    return 0;
}

static int public_iso_time(time_t value, char out[40])
{
    struct tm utc;
    if (gmtime_r(&value, &utc) == NULL) {
        return -1;
    }
    return strftime(out, 40U, "%Y-%m-%dT%H:%M:%SZ", &utc) == 0U ? -1 : 0;
}

static long public_env_long(const char *name, long fallback)
{
    const char *value = getenv(name);
    if (value == NULL || *value == '\0') return fallback;
    char *end = NULL;
    long parsed = strtol(value, &end, 10);
    return end != value && *end == '\0' && parsed > 0 ? parsed : fallback;
}

static int public_utf8_next(const uint8_t *data,
                            size_t len,
                            size_t *offset,
                            uint32_t *codepoint,
                            size_t *units)
{
    if (*offset >= len) return -1;
    size_t start = *offset;
    uint8_t first = data[(*offset)++];
    size_t continuation;
    uint32_t value;
    if (first <= 0x7fU) {
        value = first;
        continuation = 0U;
    } else if (first >= 0xc2U && first <= 0xdfU) {
        value = first & 0x1fU;
        continuation = 1U;
    } else if (first >= 0xe0U && first <= 0xefU) {
        value = first & 0x0fU;
        continuation = 2U;
    } else if (first >= 0xf0U && first <= 0xf4U) {
        value = first & 0x07U;
        continuation = 3U;
    } else {
        return -1;
    }
    if (continuation > len - *offset) return -1;
    for (size_t i = 0U; i < continuation; ++i) {
        uint8_t next = data[(*offset)++];
        if ((next & 0xc0U) != 0x80U) return -1;
        value = (value << 6U) | (next & 0x3fU);
    }
    if ((continuation == 2U && value < 0x800U)
        || (continuation == 3U && value < 0x10000U)
        || (value >= 0xd800U && value <= 0xdfffU)
        || value > 0x10ffffU) {
        return -1;
    }
    if (codepoint != NULL) *codepoint = value;
    if (units != NULL) *units = value > 0xffffU ? 2U : 1U;
    return (int)(*offset - start);
}

static int public_utf8_units(const uint8_t *data, size_t len, size_t max_units, size_t *units)
{
    size_t offset = 0U;
    size_t total = 0U;
    while (offset < len) {
        size_t increment = 0U;
        if (public_utf8_next(data, len, &offset, NULL, &increment) < 0) return -1;
        if (total > max_units - increment) return -2;
        total += increment;
    }
    if (units != NULL) *units = total;
    return 0;
}

static int public_normalize_text(char *value,
                                 const char *fallback,
                                 size_t max_units,
                                 char *out,
                                 size_t out_len)
{
    const char *source = value == NULL ? "" : value;
    while (*source != '\0' && isspace((unsigned char)*source)) ++source;
    size_t len = strlen(source);
    while (len > 0U && isspace((unsigned char)source[len - 1U])) --len;
    if (len == 0U && fallback != NULL) {
        source = fallback;
        len = strlen(fallback);
    }
    size_t offset = 0U;
    size_t units = 0U;
    size_t accepted = 0U;
    while (offset < len) {
        size_t before = offset;
        size_t increment = 0U;
        if (public_utf8_next((const uint8_t *)source, len, &offset, NULL, &increment) < 0) {
            return -1;
        }
        if (units + increment > max_units) break;
        units += increment;
        accepted = offset;
        if (offset == before) return -1;
    }
    if (accepted >= out_len) return -1;
    memcpy(out, source, accepted);
    out[accepted] = '\0';
    return 0;
}

static int public_hex_digit(char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static char *public_query_value(const char *path, const char *name)
{
    const char *query = path == NULL ? NULL : strchr(path, '?');
    if (query == NULL) return NULL;
    ++query;
    size_t name_len = strlen(name);
    while (*query != '\0') {
        const char *end = strchr(query, '&');
        if (end == NULL) end = query + strlen(query);
        const char *equals = memchr(query, '=', (size_t)(end - query));
        if (equals != NULL && (size_t)(equals - query) == name_len
            && memcmp(query, name, name_len) == 0) {
            size_t encoded_len = (size_t)(end - equals - 1);
            char *decoded = (char *)malloc(encoded_len + 1U);
            if (decoded == NULL) return NULL;
            size_t written = 0U;
            for (size_t i = 0U; i < encoded_len; ++i) {
                char ch = equals[1 + i];
                if (ch == '+') {
                    decoded[written++] = ' ';
                } else if (ch == '%' && i + 2U < encoded_len) {
                    int high = public_hex_digit(equals[1 + i + 1U]);
                    int low = public_hex_digit(equals[1 + i + 2U]);
                    if (high < 0 || low < 0) {
                        free(decoded);
                        return NULL;
                    }
                    unsigned char decoded_byte = (unsigned char)((high << 4) | low);
                    if (decoded_byte == 0U) {
                        free(decoded);
                        return NULL;
                    }
                    decoded[written++] = (char)decoded_byte;
                    i += 2U;
                } else {
                    decoded[written++] = ch;
                }
            }
            decoded[written] = '\0';
            return decoded;
        }
        query = *end == '&' ? end + 1 : end;
    }
    return NULL;
}

static int public_has_iso_control(const uint8_t *data, size_t len)
{
    size_t offset = 0U;
    while (offset < len) {
        uint32_t codepoint = 0U;
        if (public_utf8_next(data, len, &offset, &codepoint, NULL) < 0) return 1;
        if (codepoint < 0x20U || (codepoint >= 0x7fU && codepoint <= 0x9fU)) return 1;
    }
    return 0;
}

static int public_write_response(char *out,
                                 size_t out_len,
                                 int status,
                                 const char *reason,
                                 const char *body)
{
    size_t body_len = body == NULL ? 0U : strlen(body);
    int written = snprintf(out,
                           out_len,
                           "HTTP/1.1 %d %s\r\n"
                           "Content-Type: application/json\r\n"
                           "Cache-Control: no-store\r\n"
                           "X-Content-Type-Options: nosniff\r\n"
                           "Content-Length: %zu\r\n\r\n%s",
                           status,
                           reason,
                           body_len,
                           body == NULL ? "" : body);
    return written < 0 || (size_t)written >= out_len ? -1 : written;
}

static size_t public_prune_tickets_locked(time_t now)
{
    size_t count = 0U;
    st_public_ticket **cursor = &public_tickets;
    while (*cursor != NULL) {
        st_public_ticket *ticket = *cursor;
        if (ticket->expires_at <= now) {
            *cursor = ticket->next;
            free(ticket);
        } else {
            ++count;
            cursor = &ticket->next;
        }
    }
    return count;
}

static int public_issue_ticket(st_public_ticket *ticket, char out[64], time_t *expires_at)
{
    uint8_t random_bytes[ST_PUBLIC_TICKET_BYTES];
    if (ticket == NULL || out == NULL || expires_at == NULL
        || public_random(random_bytes, sizeof(random_bytes)) != 0
        || public_base64(random_bytes, sizeof(random_bytes), 1, out, 64U) != 0) {
        return -1;
    }
    public_hash_text(out, ticket->token_hash);
    ticket->expires_at = time(NULL) + ST_PUBLIC_TICKET_TTL_SECONDS;
    pthread_mutex_lock(&public_ticket_lock);
    size_t count = public_prune_tickets_locked(time(NULL));
    if (count >= ST_PUBLIC_MAX_TICKETS) {
        pthread_mutex_unlock(&public_ticket_lock);
        return -2;
    }
    ticket->next = public_tickets;
    public_tickets = ticket;
    *expires_at = ticket->expires_at;
    pthread_mutex_unlock(&public_ticket_lock);
    return 0;
}

static st_public_ticket *public_consume_ticket(const char *token, const char *remote_address)
{
    if (token == NULL || strlen(token) < 32U || strlen(token) > 128U) return NULL;
    uint8_t token_hash[ST_SHA256_LEN];
    uint8_t remote_hash[ST_SHA256_LEN];
    public_hash_text(token, token_hash);
    public_hash_text(remote_address, remote_hash);
    pthread_mutex_lock(&public_ticket_lock);
    public_prune_tickets_locked(time(NULL));
    st_public_ticket **cursor = &public_tickets;
    while (*cursor != NULL) {
        st_public_ticket *ticket = *cursor;
        if (!st_constant_time_eq(ticket->token_hash, token_hash, sizeof(token_hash))) {
            cursor = &ticket->next;
            continue;
        }
        if (!st_constant_time_eq(ticket->remote_hash, remote_hash, sizeof(remote_hash))) {
            pthread_mutex_unlock(&public_ticket_lock);
            return NULL;
        }
        *cursor = ticket->next;
        ticket->next = NULL;
        pthread_mutex_unlock(&public_ticket_lock);
        return ticket;
    }
    pthread_mutex_unlock(&public_ticket_lock);
    return NULL;
}

int st_public_discovery_issue_ticket_response(const char *body,
                                              const char *remote_address,
                                              char *out,
                                              size_t out_len)
{
    if (body == NULL || strlen(body) > 4096U || !st_json_is_valid_object(body)
        || strstr(body, "\\u0000") != NULL) {
        return public_write_response(out, out_len, 400, "Bad Request", "{\"error\":\"invalid request\"}");
    }
    char *room_id = st_json_get_top_level_string(body, "roomId");
    char *room_token = st_json_get_top_level_string(body, "roomToken");
    char *peer_id = st_json_get_top_level_string(body, "peerId");
    char *display_name = st_json_get_top_level_string(body, "displayName");
    char *discoverable_raw = st_json_get_top_level_raw(body, "discoverable");
    int discoverable = 1;
    if (discoverable_raw != NULL) {
        if (strcmp(discoverable_raw, "true") == 0) discoverable = 1;
        else if (strcmp(discoverable_raw, "false") == 0) discoverable = 0;
        else {
            free(room_id); free(room_token); free(peer_id); free(display_name); free(discoverable_raw);
            return public_write_response(out, out_len, 400, "Bad Request", "{\"error\":\"invalid request\"}");
        }
    }

    char generated_peer[32];
    uint8_t random_peer[5];
    if (public_random(random_peer, sizeof(random_peer)) != 0) {
        free(room_id); free(room_token); free(peer_id); free(display_name); free(discoverable_raw);
        return public_write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"ticket generation failed\"}");
    }
    char peer_hex[sizeof(random_peer) * 2U + 1U];
    st_hex_encode(random_peer, sizeof(random_peer), peer_hex);
    snprintf(generated_peer, sizeof(generated_peer), "web-%s", peer_hex);

    st_public_ticket *ticket = (st_public_ticket *)calloc(1, sizeof(*ticket));
    if (ticket == NULL
        || public_normalize_text(room_id, "nearby", 120U, ticket->room_id, sizeof(ticket->room_id)) != 0
        || public_normalize_text(peer_id, generated_peer, 120U, ticket->peer_id, sizeof(ticket->peer_id)) != 0
        || public_normalize_text(display_name, "web", 120U, ticket->display_name, sizeof(ticket->display_name)) != 0) {
        free(ticket); free(room_id); free(room_token); free(peer_id); free(display_name); free(discoverable_raw);
        return public_write_response(out, out_len, 400, "Bad Request", "{\"error\":\"invalid request\"}");
    }
    char normalized_token[ST_PUBLIC_ROOM_TOKEN_BYTES + 1U];
    if (public_normalize_text(room_token, "", 512U, normalized_token, sizeof(normalized_token)) != 0) {
        free(ticket); free(room_id); free(room_token); free(peer_id); free(display_name); free(discoverable_raw);
        return public_write_response(out, out_len, 400, "Bad Request", "{\"error\":\"invalid request\"}");
    }
    free(room_id); free(room_token); free(peer_id); free(display_name); free(discoverable_raw);
    snprintf(ticket->public_address,
             sizeof(ticket->public_address),
             "%s",
             remote_address == NULL || *remote_address == '\0' ? "unknown" : remote_address);
    ticket->discoverable = discoverable;
    if (*normalized_token != '\0') {
        st_public_room_access access;
        int resolved = st_public_room_resolve(ticket->room_id,
                                              normalized_token,
                                              ticket->peer_id,
                                              &access);
        if (resolved == 0) {
            snprintf(ticket->room_key, sizeof(ticket->room_key), "%s", access.room_key);
            snprintf(ticket->room_role, sizeof(ticket->room_role), "%s", access.role);
        } else if (resolved == 1
                   && strncasecmp(normalized_token, "st-editor-", 10U) != 0
                   && strncasecmp(normalized_token, "st-viewer-", 10U) != 0) {
            uint8_t digest[ST_SHA256_LEN];
            char digest_hex[ST_SHA256_HEX_LEN + 1U];
            public_hash_text(normalized_token, digest);
            st_hex_encode(digest, sizeof(digest), digest_hex);
            snprintf(ticket->room_key, sizeof(ticket->room_key), "room:%s", digest_hex);
            snprintf(ticket->room_role, sizeof(ticket->room_role), "OWNER");
        } else {
            free(ticket);
            return public_write_response(out,
                                         out_len,
                                         resolved == 2 ? 403 : 500,
                                         resolved == 2 ? "Forbidden" : "Internal Server Error",
                                         resolved == 2
                                             ? "{\"error\":\"room access token is invalid or expired\"}"
                                             : "{\"error\":\"room persistence failed\"}");
        }
        ticket->shared_room = 1;
    } else {
        snprintf(ticket->room_key, sizeof(ticket->room_key), "public:%.70s", ticket->public_address);
        snprintf(ticket->room_role, sizeof(ticket->room_role), "EDITOR");
        ticket->shared_room = 0;
    }
    public_hash_text(remote_address, ticket->remote_hash);

    char token[64];
    time_t expires_at = 0;
    int issue = public_issue_ticket(ticket, token, &expires_at);
    if (issue != 0) {
        free(ticket);
        return public_write_response(out,
                                     out_len,
                                     issue == -2 ? 429 : 500,
                                     issue == -2 ? "Too Many Requests" : "Internal Server Error",
                                     issue == -2 ? "{\"error\":\"too many active websocket tickets\"}"
                                                 : "{\"error\":\"ticket generation failed\"}");
    }
    char expires_text[40];
    char response[256];
    if (public_iso_time(expires_at, expires_text) != 0
        || snprintf(response,
                    sizeof(response),
                    "{\"ticket\":\"%s\",\"expiresAt\":\"%s\"}",
                    token,
                    expires_text) >= (int)sizeof(response)) {
        return public_write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"ticket response failed\"}");
    }
    return public_write_response(out, out_len, 200, "OK", response);
}

int st_public_discovery_name_availability_response(const char *path,
                                                   char *out,
                                                   size_t out_len)
{
    char *requested = public_query_value(path, "clientName");
    char *exclude = public_query_value(path, "excludePeerId");
    if (requested == NULL) {
        free(exclude);
        return public_write_response(out, out_len, 400, "Bad Request", "{\"error\":\"client name is required\"}");
    }
    char *trimmed = requested;
    while (*trimmed != '\0' && isspace((unsigned char)*trimmed)) ++trimmed;
    size_t len = strlen(trimmed);
    while (len > 0U && isspace((unsigned char)trimmed[len - 1U])) --len;
    if (len == 0U) {
        free(requested); free(exclude);
        return public_write_response(out, out_len, 400, "Bad Request", "{\"error\":\"client name is required\"}");
    }
    if (public_utf8_units((const uint8_t *)trimmed, len, 120U, NULL) != 0
        || public_has_iso_control((const uint8_t *)trimmed, len)) {
        free(requested); free(exclude);
        return public_write_response(out, out_len, 400, "Bad Request", "{\"error\":\"client name is invalid\"}");
    }
    char normalized[ST_PUBLIC_DISPLAY_NAME_BYTES + 1U];
    if (len >= sizeof(normalized)) {
        free(requested); free(exclude);
        return public_write_response(out, out_len, 400, "Bad Request", "{\"error\":\"client name is invalid\"}");
    }
    memcpy(normalized, trimmed, len);
    normalized[len] = '\0';
    if (exclude != NULL) {
        char *exclude_trimmed = exclude;
        while (*exclude_trimmed != '\0' && isspace((unsigned char)*exclude_trimmed)) ++exclude_trimmed;
        if (exclude_trimmed != exclude) memmove(exclude, exclude_trimmed, strlen(exclude_trimmed) + 1U);
        size_t exclude_len = strlen(exclude);
        while (exclude_len > 0U && isspace((unsigned char)exclude[exclude_len - 1U])) exclude[--exclude_len] = '\0';
    }
    int available = 1;
    if (st_public_coordination_enabled()) {
        if (st_public_discovery_initialize() != 0
            || st_public_coordination_name_available(normalized,
                                                     exclude == NULL ? "" : exclude,
                                                     &available) != 0) {
            free(requested); free(exclude);
            return public_write_response(out,
                                         out_len,
                                         503,
                                         "Service Unavailable",
                                         "{\"error\":\"coordination unavailable\"}");
        }
    } else {
        pthread_mutex_lock(&public_peer_lock);
        for (st_public_peer *peer = public_peers; peer != NULL; peer = peer->next) {
            if ((exclude == NULL || *exclude == '\0' || strcmp(peer->peer_id, exclude) != 0)
                && strcasecmp(peer->display_name, normalized) == 0) {
                available = 0;
                break;
            }
        }
        pthread_mutex_unlock(&public_peer_lock);
    }
    char *escaped = st_json_escape(normalized);
    char response[1024];
    int written = escaped == NULL ? -1 : snprintf(response,
                                                   sizeof(response),
                                                   "{\"clientName\":\"%s\",\"available\":%s}",
                                                   escaped,
                                                   available ? "true" : "false");
    free(escaped); free(requested); free(exclude);
    if (written < 0 || (size_t)written >= sizeof(response)) {
        return public_write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"availability response failed\"}");
    }
    return public_write_response(out, out_len, 200, "OK", response);
}

static int public_builder_reserve(st_public_builder *builder, size_t extra)
{
    if (builder == NULL || extra > SIZE_MAX - builder->len - 1U) return -1;
    size_t needed = builder->len + extra + 1U;
    if (needed <= builder->cap) return 0;
    size_t next = builder->cap == 0U ? 256U : builder->cap;
    while (next < needed) {
        if (next > SIZE_MAX / 2U) return -1;
        next *= 2U;
    }
    char *grown = (char *)realloc(builder->data, next);
    if (grown == NULL) return -1;
    builder->data = grown;
    builder->cap = next;
    return 0;
}

static int public_builder_append_len(st_public_builder *builder, const char *value, size_t len)
{
    if (value == NULL || public_builder_reserve(builder, len) != 0) return -1;
    memcpy(builder->data + builder->len, value, len);
    builder->len += len;
    builder->data[builder->len] = '\0';
    return 0;
}

static int public_builder_append(st_public_builder *builder, const char *value)
{
    return public_builder_append_len(builder, value, value == NULL ? 0U : strlen(value));
}

static int public_builder_append_json(st_public_builder *builder, const char *value)
{
    char *escaped = st_json_escape(value == NULL ? "" : value);
    if (escaped == NULL) return -1;
    int result = public_builder_append(builder, "\"")
        || public_builder_append(builder, escaped)
        || public_builder_append(builder, "\"")
        ? -1 : 0;
    free(escaped);
    return result;
}

static int public_path_equals(const char *path, const char *expected)
{
    if (path == NULL || expected == NULL) return 0;
    size_t len = strcspn(path, "?");
    return strlen(expected) == len && memcmp(path, expected, len) == 0;
}

static char *public_header_value(const char *request, const char *name)
{
    if (request == NULL || name == NULL) return NULL;
    size_t name_len = strlen(name);
    const char *line = strstr(request, "\r\n");
    if (line == NULL) return NULL;
    line += 2;
    while (*line != '\0' && strncmp(line, "\r\n", 2U) != 0) {
        const char *end = strstr(line, "\r\n");
        if (end == NULL) break;
        const char *colon = memchr(line, ':', (size_t)(end - line));
        if (colon != NULL && (size_t)(colon - line) == name_len
            && strncasecmp(line, name, name_len) == 0) {
            const char *start = colon + 1;
            while (start < end && isspace((unsigned char)*start)) ++start;
            while (end > start && isspace((unsigned char)end[-1])) --end;
            size_t len = (size_t)(end - start);
            char *value = (char *)malloc(len + 1U);
            if (value == NULL) return NULL;
            memcpy(value, start, len);
            value[len] = '\0';
            return value;
        }
        line = end + 2;
    }
    return NULL;
}

static int public_header_has_token(const char *request, const char *name, const char *wanted)
{
    char *value = public_header_value(request, name);
    if (value == NULL) return 0;
    int found = 0;
    char *cursor = value;
    while (*cursor != '\0') {
        while (*cursor != '\0' && (isspace((unsigned char)*cursor) || *cursor == ',')) ++cursor;
        char *end = cursor;
        while (*end != '\0' && *end != ',') ++end;
        char *trimmed = end;
        while (trimmed > cursor && isspace((unsigned char)trimmed[-1])) --trimmed;
        if ((size_t)(trimmed - cursor) == strlen(wanted)
            && strncasecmp(cursor, wanted, strlen(wanted)) == 0) {
            found = 1;
            break;
        }
        cursor = end;
    }
    free(value);
    return found;
}

static char *public_single_ticket_query(const char *path, int *single)
{
    if (single != NULL) *single = 0;
    const char *query = path == NULL ? NULL : strchr(path, '?');
    if (query == NULL || strncmp(query + 1, "ticket=", 7U) != 0 || strchr(query + 1, '&') != NULL) {
        return NULL;
    }
    const char *value = query + 8;
    size_t len = strlen(value);
    char *ticket = (char *)malloc(len + 1U);
    if (ticket == NULL) return NULL;
    memcpy(ticket, value, len + 1U);
    if (single != NULL) *single = 1;
    return ticket;
}

static char *public_websocket_accept(const char *client_key)
{
    static const char guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    if (client_key == NULL || *client_key == '\0') return NULL;
    size_t key_len = strlen(client_key);
    size_t joined_len = key_len + sizeof(guid) - 1U;
    char *joined = (char *)malloc(joined_len);
    if (joined == NULL) return NULL;
    memcpy(joined, client_key, key_len);
    memcpy(joined + key_len, guid, sizeof(guid) - 1U);
    uint8_t digest[ST_SHA1_LEN];
    st_sha1((const uint8_t *)joined, joined_len, digest);
    free(joined);
    char *accept = (char *)malloc(32U);
    if (accept == NULL || public_base64(digest, sizeof(digest), 0, accept, 32U) != 0) {
        free(accept);
        return NULL;
    }
    return accept;
}

static int public_send_frame_fd(int fd, uint8_t opcode, const uint8_t *payload, size_t payload_len)
{
    uint8_t header[10];
    size_t header_len;
    header[0] = (uint8_t)(0x80U | (opcode & 0x0fU));
    if (payload_len <= 125U) {
        header[1] = (uint8_t)payload_len;
        header_len = 2U;
    } else if (payload_len <= 0xffffU) {
        header[1] = 126U;
        header[2] = (uint8_t)(payload_len >> 8U);
        header[3] = (uint8_t)payload_len;
        header_len = 4U;
    } else {
        header[1] = 127U;
        for (int i = 7; i >= 0; --i) {
            header[2U + (size_t)(7 - i)] = (uint8_t)(((uint64_t)payload_len >> ((unsigned int)i * 8U)) & 0xffU);
        }
        header_len = 10U;
    }
    return public_send_all(fd, header, header_len) != 0
        || (payload_len > 0U && public_send_all(fd, payload, payload_len) != 0)
        ? -1 : 0;
}

static int public_peer_send(st_public_peer *peer,
                            uint8_t opcode,
                            const uint8_t *payload,
                            size_t payload_len)
{
    pthread_mutex_lock(&peer->send_lock);
    int result = public_send_frame_fd(peer->fd, opcode, payload, payload_len);
    pthread_mutex_unlock(&peer->send_lock);
    return result;
}

static int public_peer_send_text(st_public_peer *peer, const char *text)
{
    return public_peer_send(peer, 0x1U, (const uint8_t *)text, strlen(text));
}

static int public_peer_send_error(st_public_peer *peer, const char *error)
{
    st_public_builder builder = {0};
    int failed = public_builder_append(&builder, "{\"type\":\"error\",\"error\":")
        || public_builder_append_json(&builder, error)
        || public_builder_append(&builder, "}");
    int result = failed ? -1 : public_peer_send_text(peer, builder.data);
    free(builder.data);
    return result;
}

static void public_peer_close(st_public_peer *peer, uint16_t code)
{
    uint8_t payload[2] = {(uint8_t)(code >> 8U), (uint8_t)code};
    (void)public_peer_send(peer, 0x8U, payload, sizeof(payload));
}

static int public_same_group(const st_public_peer *left, const st_public_peer *right)
{
    return strcmp(left->room_id, right->room_id) == 0
        && strcmp(left->room_key, right->room_key) == 0;
}

static int public_address_known(const char *address)
{
    return address != NULL && *address != '\0' && strcasecmp(address, "unknown") != 0;
}

static int public_same_net(const st_public_peer *left, const st_public_peer *right)
{
    return public_address_known(left->public_address)
        && strcmp(left->public_address, right->public_address) == 0;
}

static int public_same_scope(const st_public_peer *left, const st_public_peer *right)
{
    return public_same_group(left, right) || public_same_net(left, right);
}

static int public_build_peer_json(st_public_builder *builder,
                                  const st_public_peer *peer,
                                  const st_public_peer *recipient)
{
    return public_builder_append(builder, "{\"peerId\":")
        || public_builder_append_json(builder, peer->peer_id)
        || public_builder_append(builder, ",\"displayName\":")
        || public_builder_append_json(builder, peer->display_name)
        || public_builder_append(builder, ",\"roomId\":")
        || public_builder_append_json(builder, peer->room_id)
        || public_builder_append(builder, ",\"publicAddress\":")
        || public_builder_append_json(builder, peer->public_address)
        || public_builder_append(builder, peer->shared_room ? ",\"sharedRoom\":true,\"roomRole\":"
                                                            : ",\"sharedRoom\":false,\"roomRole\":")
        || public_builder_append_json(builder, peer->room_role)
        || public_builder_append(builder,
                                 strcmp(peer->room_key, recipient->room_key) == 0
                                     ? ",\"sameRoom\":true"
                                     : ",\"sameRoom\":false")
        || public_builder_append(builder, ",\"connectedAt\":")
        || public_builder_append_json(builder, peer->connected_at)
        || public_builder_append(builder, "}")
        ? -1 : 0;
}

static int public_build_cluster_peer_json(st_public_builder *builder,
                                          const st_public_cluster_participant *peer,
                                          const st_public_cluster_participant *recipient)
{
    return public_builder_append(builder, "{\"peerId\":")
        || public_builder_append_json(builder, peer->peer_id)
        || public_builder_append(builder, ",\"displayName\":")
        || public_builder_append_json(builder, peer->display_name)
        || public_builder_append(builder, ",\"roomId\":")
        || public_builder_append_json(builder, peer->room_id)
        || public_builder_append(builder, ",\"publicAddress\":")
        || public_builder_append_json(builder, peer->public_address)
        || public_builder_append(builder, peer->shared_room ? ",\"sharedRoom\":true,\"roomRole\":"
                                                            : ",\"sharedRoom\":false,\"roomRole\":")
        || public_builder_append_json(builder, peer->room_role)
        || public_builder_append(builder,
                                 strcmp(peer->room_key, recipient->room_key) == 0
                                     ? ",\"sameRoom\":true"
                                     : ",\"sameRoom\":false")
        || public_builder_append(builder, ",\"connectedAt\":")
        || public_builder_append_json(builder, peer->connected_at)
        || public_builder_append(builder, "}")
        ? -1 : 0;
}

static char *public_build_cluster_roster_text(const st_public_cluster_participant *recipient,
                                              const st_public_cluster_roster *roster)
{
    st_public_builder builder = {0};
    char revision[32];
    snprintf(revision, sizeof(revision), "%llu", (unsigned long long)roster->revision);
    int failed = public_builder_append(&builder, "{\"type\":\"roster\",\"roomId\":")
        || public_builder_append_json(&builder, recipient->room_id)
        || public_builder_append(&builder, ",\"publicAddress\":")
        || public_builder_append_json(&builder, recipient->public_address)
        || public_builder_append(&builder, recipient->shared_room
            ? ",\"sharedRoom\":true,\"rosterRevision\":"
            : ",\"sharedRoom\":false,\"rosterRevision\":")
        || public_builder_append(&builder, revision)
        || public_builder_append(&builder, ",\"peers\":[");
    for (size_t i = 0U; !failed && i < roster->count; ++i) {
        if (i > 0U && public_builder_append(&builder, ",") != 0) failed = 1;
        if (!failed
            && public_build_cluster_peer_json(&builder,
                                              &roster->participants[i],
                                              recipient) != 0) failed = 1;
    }
    if (!failed && public_builder_append(&builder, "]}") != 0) failed = 1;
    if (failed) {
        free(builder.data);
        return NULL;
    }
    return builder.data;
}

static int public_send_roster_locked(st_public_peer *recipient, uint64_t revision)
{
    st_public_builder builder = {0};
    char number[32];
    snprintf(number, sizeof(number), "%llu", (unsigned long long)revision);
    int failed = public_builder_append(&builder, "{\"type\":\"roster\",\"roomId\":")
        || public_builder_append_json(&builder, recipient->room_id)
        || public_builder_append(&builder, ",\"publicAddress\":")
        || public_builder_append_json(&builder, recipient->public_address)
        || public_builder_append(&builder, recipient->shared_room ? ",\"sharedRoom\":true,\"rosterRevision\":"
                                                                 : ",\"sharedRoom\":false,\"rosterRevision\":")
        || public_builder_append(&builder, number)
        || public_builder_append(&builder, ",\"peers\":[");
    int first = 1;
    for (st_public_peer *peer = public_peers; !failed && peer != NULL; peer = peer->next) {
        if (!public_same_scope(recipient, peer) || !peer->discoverable) continue;
        if (!first && public_builder_append(&builder, ",") != 0) failed = 1;
        if (!failed && public_build_peer_json(&builder, peer, recipient) != 0) failed = 1;
        first = 0;
    }
    if (!failed && public_builder_append(&builder, "]}") != 0) failed = 1;
    int result = failed ? -1 : public_peer_send_text(recipient, builder.data);
    free(builder.data);
    return result;
}

static void public_broadcast_roster_locked(const st_public_peer *scope, uint64_t revision)
{
    for (st_public_peer *peer = public_peers; peer != NULL; peer = peer->next) {
        if (public_same_scope(scope, peer)) {
            (void)public_send_roster_locked(peer, revision);
        }
    }
}

static st_public_peer *public_find_cluster_peer_locked(const char *lease_id)
{
    for (st_public_peer *peer = public_peers; peer != NULL; peer = peer->next) {
        if (strcmp(peer->cluster.lease_id, lease_id) == 0) return peer;
    }
    return NULL;
}

static void public_cluster_event_handler(const st_public_cluster_event *event, void *context)
{
    (void)context;
    if (event == NULL) return;
    if (event->kind == ST_PUBLIC_CLUSTER_EVENT_UNAVAILABLE) {
        pthread_mutex_lock(&public_peer_lock);
        for (st_public_peer *peer = public_peers; peer != NULL; peer = peer->next)
            (void)shutdown(peer->fd, SHUT_RDWR);
        pthread_mutex_unlock(&public_peer_lock);
        return;
    }
    if (event->kind == ST_PUBLIC_CLUSTER_EVENT_ROSTER) {
        pthread_mutex_lock(&public_peer_lock);
        size_t count = 0U;
        for (st_public_peer *peer = public_peers; peer != NULL; peer = peer->next) {
            if (strcmp(peer->cluster.group_id, event->group_id) == 0
                || strcmp(peer->cluster.net_id, event->group_id) == 0) ++count;
        }
        st_public_cluster_participant *recipients = count == 0U ? NULL
            : (st_public_cluster_participant *)calloc(count, sizeof(*recipients));
        size_t copied = 0U;
        if (recipients != NULL) {
            for (st_public_peer *peer = public_peers; peer != NULL && copied < count; peer = peer->next) {
                if (strcmp(peer->cluster.group_id, event->group_id) == 0
                    || strcmp(peer->cluster.net_id, event->group_id) == 0)
                    recipients[copied++] = peer->cluster;
            }
        }
        pthread_mutex_unlock(&public_peer_lock);
        for (size_t i = 0U; i < copied; ++i) {
            st_public_cluster_roster roster = {0};
            if (st_public_coordination_roster(&recipients[i], &roster) != 0) break;
            char *text = public_build_cluster_roster_text(&recipients[i], &roster);
            st_public_coordination_roster_free(&roster);
            if (text != NULL) {
                pthread_mutex_lock(&public_peer_lock);
                st_public_peer *peer = public_find_cluster_peer_locked(recipients[i].lease_id);
                if (peer != NULL) (void)public_peer_send_text(peer, text);
                pthread_mutex_unlock(&public_peer_lock);
                free(text);
            }
        }
        free(recipients);
        return;
    }
    if (event->kind == ST_PUBLIC_CLUSTER_EVENT_TEXT) {
        char *payload = (char *)malloc(event->payload_len + 1U);
        if (payload == NULL) return;
        memcpy(payload, event->payload, event->payload_len);
        payload[event->payload_len] = '\0';
        if (strlen(payload) != event->payload_len || !st_json_is_valid_object(payload)) {
            free(payload);
            return;
        }
        pthread_mutex_lock(&public_peer_lock);
        for (st_public_peer *peer = public_peers; peer != NULL; peer = peer->next) {
            if (strcmp(peer->cluster.group_id, event->group_id) != 0
                && strcmp(peer->cluster.net_id, event->group_id) != 0) continue;
            if (*event->target_peer_id != '\0'
                && strcmp(peer->peer_id, event->target_peer_id) != 0) continue;
            if (event->exclude_source
                && strcmp(peer->cluster.lease_id, event->source_lease_id) == 0) continue;
            (void)public_peer_send_text(peer, payload);
        }
        pthread_mutex_unlock(&public_peer_lock);
        free(payload);
        return;
    }
    if (event->kind == ST_PUBLIC_CLUSTER_EVENT_BINARY
        && event->payload_len <= ST_PUBLIC_MAX_BINARY_BYTES) {
        pthread_mutex_lock(&public_peer_lock);
        for (st_public_peer *peer = public_peers; peer != NULL; peer = peer->next) {
            if ((strcmp(peer->cluster.group_id, event->group_id) == 0
                 || strcmp(peer->cluster.net_id, event->group_id) == 0)
                && strcmp(peer->peer_id, event->target_peer_id) == 0) {
                (void)public_peer_send(peer, 0x2U, event->payload, event->payload_len);
                break;
            }
        }
        pthread_mutex_unlock(&public_peer_lock);
    }
}

static int public_send_hello(st_public_peer *peer, uint64_t revision)
{
    st_public_builder builder = {0};
    char number[32];
    snprintf(number, sizeof(number), "%llu", (unsigned long long)revision);
    int failed = public_builder_append(&builder, "{\"type\":\"hello\",\"peerId\":")
        || public_builder_append_json(&builder, peer->peer_id)
        || public_builder_append(&builder, ",\"displayName\":")
        || public_builder_append_json(&builder, peer->display_name)
        || public_builder_append(&builder, ",\"roomId\":")
        || public_builder_append_json(&builder, peer->room_id)
        || public_builder_append(&builder, ",\"publicAddress\":")
        || public_builder_append_json(&builder, peer->public_address)
        || public_builder_append(&builder, peer->shared_room ? ",\"sharedRoom\":true,\"roomRole\":"
                                                            : ",\"sharedRoom\":false,\"roomRole\":")
        || public_builder_append_json(&builder, peer->room_role)
        || public_builder_append(&builder, ",\"rosterRevision\":")
        || public_builder_append(&builder, number)
        || public_builder_append(&builder, ",\"connectedAt\":")
        || public_builder_append_json(&builder, peer->connected_at)
        || public_builder_append(&builder, "}");
    int result = failed ? -1 : public_peer_send_text(peer, builder.data);
    free(builder.data);
    return result;
}

/* Returns 0 on success, -1 for I/O, -2 duplicate, -3 full, -4 display-name conflict. */
static int public_register_peer(st_public_peer *peer)
{
    long max_room = public_env_long("SPECUS_PUBLIC_TRANSFER_MAX_DISCOVERY_PEERS_PER_ROOM", 32L);
    if (max_room > INT_MAX) max_room = INT_MAX;
    if (st_public_coordination_enabled()) {
        uint64_t revision = 0U;
        int registration = 0;
        if (peer->discoverable) {
            registration = st_public_coordination_register(&peer->cluster,
                                                           (int)max_room,
                                                           &revision);
            if (registration != 0) {
                if (registration == 1) return -2;
                if (registration == 2) return -4;
                if (registration == 3) return -3;
                return -1;
            }
        }
        pthread_mutex_lock(&public_peer_lock);
        st_public_peer **tail = &public_peers;
        while (*tail != NULL) tail = &(*tail)->next;
        *tail = peer;
        int send_result = public_send_hello(peer, revision);
        if (send_result != 0) *tail = NULL;
        pthread_mutex_unlock(&public_peer_lock);
        if (send_result != 0) {
            if (peer->discoverable) {
                uint64_t ignored = 0U;
                (void)st_public_coordination_unregister(&peer->cluster, &ignored);
            }
            return -1;
        }
        if (st_public_coordination_publish_roster(peer->cluster.group_id, revision) != 0
            || st_public_coordination_publish_roster(peer->cluster.net_id, revision) != 0) {
            pthread_mutex_lock(&public_peer_lock);
            st_public_peer **cursor = &public_peers;
            while (*cursor != NULL && *cursor != peer) cursor = &(*cursor)->next;
            if (*cursor == peer) *cursor = peer->next;
            pthread_mutex_unlock(&public_peer_lock);
            if (peer->discoverable) {
                uint64_t ignored = 0U;
                (void)st_public_coordination_unregister(&peer->cluster, &ignored);
            }
            return -1;
        }
        return 0;
    }
    size_t room_count = 0U;
    pthread_mutex_lock(&public_peer_lock);
    if (!peer->discoverable) {
        st_public_peer **hidden_tail = &public_peers;
        while (*hidden_tail != NULL) hidden_tail = &(*hidden_tail)->next;
        *hidden_tail = peer;
        int hidden_send = public_send_hello(peer, 0U);
        if (hidden_send == 0) public_broadcast_roster_locked(peer, 0U);
        else *hidden_tail = NULL;
        pthread_mutex_unlock(&public_peer_lock);
        return hidden_send == 0 ? 0 : -1;
    }
    for (st_public_peer *existing = public_peers; existing != NULL; existing = existing->next) {
        if (public_same_scope(existing, peer) && strcmp(existing->peer_id, peer->peer_id) == 0) {
            pthread_mutex_unlock(&public_peer_lock);
            return -2;
        }
        if (public_same_group(existing, peer)) {
            ++room_count;
        }
    }
    for (st_public_peer *existing = public_peers; existing != NULL; existing = existing->next) {
        if (strcasecmp(existing->display_name, peer->display_name) == 0) {
            pthread_mutex_unlock(&public_peer_lock);
            return -4;
        }
    }
    if (room_count >= (size_t)max_room) {
        pthread_mutex_unlock(&public_peer_lock);
        return -3;
    }
    st_public_peer **tail = &public_peers;
    while (*tail != NULL) tail = &(*tail)->next;
    *tail = peer;
    uint64_t revision = ++public_roster_revision;
    int send_result = public_send_hello(peer, revision);
    if (send_result == 0) {
        public_broadcast_roster_locked(peer, revision);
    } else {
        *tail = NULL;
    }
    pthread_mutex_unlock(&public_peer_lock);
    return send_result == 0 ? 0 : -1;
}

static void public_remove_peer(st_public_peer *peer)
{
    int removed = 0;
    pthread_mutex_lock(&public_peer_lock);
    st_public_peer **cursor = &public_peers;
    while (*cursor != NULL && *cursor != peer) cursor = &(*cursor)->next;
    if (*cursor == peer) {
        *cursor = peer->next;
        removed = 1;
        if (peer->discoverable && !st_public_coordination_enabled()) {
            uint64_t revision = ++public_roster_revision;
            public_broadcast_roster_locked(peer, revision);
        }
    }
    pthread_mutex_unlock(&public_peer_lock);
    if (removed && peer->discoverable && st_public_coordination_enabled()) {
        uint64_t revision = 0U;
        if (st_public_coordination_unregister(&peer->cluster, &revision) == 0
            && revision > 0U) {
            (void)st_public_coordination_publish_roster(peer->cluster.group_id, revision);
            (void)st_public_coordination_publish_roster(peer->cluster.net_id, revision);
        }
    }
}

static int public_allow_message(st_public_peer *peer)
{
    long limit = public_env_long("SPECUS_PUBLIC_TRANSFER_DISCOVERY_MESSAGE_RATE_LIMIT_PER_CONNECTION", 360L);
    long window = public_env_long("SPECUS_PUBLIC_TRANSFER_DISCOVERY_MESSAGE_RATE_LIMIT_WINDOW_SECONDS", 60L);
    if (st_public_coordination_enabled()) {
        char identity[ST_PUBLIC_CLUSTER_ID_BYTES + ST_PUBLIC_PEER_ID_BYTES + 2U];
        int written = snprintf(identity,
                               sizeof(identity),
                               "%s\n%s",
                               peer->cluster.group_id,
                               peer->peer_id);
        int allowed = 0;
        return written >= 0 && (size_t)written < sizeof(identity)
            && st_public_coordination_allow_rate("discovery-message",
                                                 identity,
                                                 limit,
                                                 window,
                                                 &allowed) == 0
            && allowed;
    }
    time_t now = time(NULL);
    if (peer->rate_window_started == 0 || now - peer->rate_window_started >= window) {
        peer->rate_window_started = now;
        peer->rate_window_count = 0U;
    }
    if (peer->rate_window_count >= (unsigned long)limit) return 0;
    ++peer->rate_window_count;
    return 1;
}

static void public_drop_cluster_lease(const char *lease_id)
{
    pthread_mutex_lock(&public_peer_lock);
    st_public_peer *peer = public_find_cluster_peer_locked(lease_id);
    if (peer != NULL) (void)shutdown(peer->fd, SHUT_RDWR);
    pthread_mutex_unlock(&public_peer_lock);
}

static void *public_cluster_refresh_thread(void *unused)
{
    (void)unused;
    for (;;) {
        long interval_ms = st_public_coordination_refresh_interval_ms();
        struct timespec deadline;
        (void)clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_sec += interval_ms / 1000L;
        deadline.tv_nsec += (interval_ms % 1000L) * 1000000L;
        if (deadline.tv_nsec >= 1000000000L) {
            ++deadline.tv_sec;
            deadline.tv_nsec -= 1000000000L;
        }
        pthread_mutex_lock(&public_discovery_init_lock);
        while (!public_refresh_stop) {
            int wait_result = pthread_cond_timedwait(&public_refresh_cond,
                                                     &public_discovery_init_lock,
                                                     &deadline);
            if (wait_result == ETIMEDOUT) break;
        }
        int stopping = public_refresh_stop;
        pthread_mutex_unlock(&public_discovery_init_lock);
        if (stopping) break;

        pthread_mutex_lock(&public_peer_lock);
        size_t count = 0U;
        for (st_public_peer *peer = public_peers; peer != NULL; peer = peer->next)
            if (peer->discoverable) ++count;
        st_public_cluster_participant *participants = count == 0U ? NULL
            : (st_public_cluster_participant *)calloc(count, sizeof(*participants));
        size_t copied = 0U;
        if (participants != NULL) {
            for (st_public_peer *peer = public_peers; peer != NULL && copied < count; peer = peer->next)
                if (peer->discoverable) participants[copied++] = peer->cluster;
        }
        pthread_mutex_unlock(&public_peer_lock);
        for (size_t i = 0U; i < copied; ++i) {
            int refreshed = st_public_coordination_refresh(&participants[i]);
            if (refreshed < 0) break;
            if (refreshed > 0) {
                public_drop_cluster_lease(participants[i].lease_id);
                continue;
            }
            if (st_public_coordination_sweep(&participants[i]) != 0
                || st_public_coordination_publish_roster(participants[i].net_id, 0U) != 0)
                break;
        }
        free(participants);
    }
    return NULL;
}

static uint16_t public_read_u16(const uint8_t *data)
{
    return (uint16_t)(((uint16_t)data[0] << 8U) | data[1]);
}

static uint32_t public_read_u32(const uint8_t *data)
{
    return ((uint32_t)data[0] << 24U)
        | ((uint32_t)data[1] << 16U)
        | ((uint32_t)data[2] << 8U)
        | data[3];
}

static void public_write_u16(uint8_t *data, uint16_t value)
{
    data[0] = (uint8_t)(value >> 8U);
    data[1] = (uint8_t)value;
}

static void public_write_u32(uint8_t *data, uint32_t value)
{
    data[0] = (uint8_t)(value >> 24U);
    data[1] = (uint8_t)(value >> 16U);
    data[2] = (uint8_t)(value >> 8U);
    data[3] = (uint8_t)value;
}

static int public_validate_stap2(const uint8_t *frame, size_t len)
{
    if (len < 72U || memcmp(frame, "STAP", 4U) != 0 || frame[4] != 2U
        || (frame[5] != 1U && frame[5] != 2U && frame[5] != 3U && frame[5] != 127U)) {
        return -1;
    }
    uint16_t flags = public_read_u16(frame + 6U);
    uint32_t chunk_index = public_read_u32(frame + 24U);
    uint32_t chunk_count = public_read_u32(frame + 28U);
    uint32_t total_len = public_read_u32(frame + 32U);
    uint32_t payload_len = public_read_u32(frame + 36U);
    if ((flags & ~1U) != 0U || chunk_count == 0U || chunk_count > 2048U
        || chunk_index >= chunk_count || total_len > 8U * 1024U * 1024U
        || payload_len != len - 72U || payload_len > total_len) {
        return -1;
    }
    if (frame[5] == 127U && (flags != 0U || chunk_index != 0U || chunk_count != 1U
        || total_len != 0U || payload_len != 0U)) {
        return -1;
    }
    return 0;
}

static char *public_json_text(const char *json, const char *key, const char *fallback)
{
    if (!st_json_is_valid_object(json)) return strdup(fallback);
    char *raw = st_json_get_top_level_raw(json, key);
    if (raw == NULL || strcmp(raw, "null") == 0) {
        free(raw);
        return strdup(fallback);
    }
    if (*raw == '"') {
        free(raw);
        char *value = st_json_get_top_level_string(json, key);
        return value == NULL ? strdup(fallback) : value;
    }
    if (*raw == '{' || *raw == '[') {
        free(raw);
        return strdup("");
    }
    return raw;
}

static void public_route_text(st_public_peer *source, const char *json)
{
    if (!st_json_is_valid(json)) {
        (void)public_peer_send_error(source, "invalid message");
        return;
    }
    char *type = public_json_text(json, "type", "signal");
    if (type == NULL) return;
    if (strcmp(type, "ping") == 0) {
        char now_text[40];
        st_public_builder pong = {0};
        if (public_iso_time(time(NULL), now_text) == 0
            && public_builder_append(&pong, "{\"type\":\"pong\",\"ts\":") == 0
            && public_builder_append_json(&pong, now_text) == 0
            && public_builder_append(&pong, "}") == 0) {
            (void)public_peer_send_text(source, pong.data);
        }
        free(pong.data);
        free(type);
        return;
    }
    if (strcmp(source->room_role, "VIEWER") == 0
        && (strcmp(type, "attachment") == 0 || strcmp(type, "clipboard") == 0
            || strcmp(type, "whiteboard") == 0)) {
        (void)public_peer_send_error(source, "viewer is read-only");
        free(type);
        return;
    }
    char *target = public_json_text(json, "targetPeerId", "");
    char *payload = st_json_is_valid_object(json) ? st_json_get_top_level_raw(json, "payload") : NULL;
    if (payload == NULL) payload = strdup("null");
    if (payload == NULL) {
        free(type);
        free(target);
        return;
    }
    st_public_builder envelope = {0};
    int failed = public_builder_append(&envelope, "{\"type\":")
        || public_builder_append_json(&envelope, type)
        || public_builder_append(&envelope, ",\"sourcePeerId\":")
        || public_builder_append_json(&envelope, source->peer_id)
        || public_builder_append(&envelope, ",\"sourceRole\":")
        || public_builder_append_json(&envelope, source->room_role)
        || public_builder_append(&envelope, ",\"targetPeerId\":")
        || (target != NULL && *target != '\0' ? public_builder_append_json(&envelope, target)
                                               : public_builder_append(&envelope, "null"))
        || public_builder_append(&envelope, ",\"roomId\":")
        || public_builder_append_json(&envelope, source->room_id)
        || public_builder_append(&envelope, ",\"publicAddress\":")
        || public_builder_append_json(&envelope, source->public_address)
        || public_builder_append(&envelope, ",\"payload\":")
        || public_builder_append(&envelope, payload)
        || public_builder_append(&envelope, "}");
    if (!failed && st_public_coordination_enabled()) {
        const char *group_id = source->cluster.group_id;
        st_public_cluster_participant target_participant;
        int found = 0;
        if (target != NULL && *target != '\0') {
            if (st_public_coordination_find_peer(&source->cluster,
                                                target,
                                                &target_participant,
                                                &found) != 0) {
                (void)public_peer_send_error(source, "coordination unavailable");
                (void)shutdown(source->fd, SHUT_RDWR);
                failed = 1;
            } else if (found) {
                group_id = target_participant.group_id;
            }
        }
        if (!failed
            && st_public_coordination_publish_text(group_id,
                                                   target == NULL ? "" : target,
                                                   source->cluster.lease_id,
                                                   target == NULL || *target == '\0',
                                                   (const uint8_t *)envelope.data,
                                                   envelope.len) != 0) {
            (void)public_peer_send_error(source, "coordination unavailable");
            (void)shutdown(source->fd, SHUT_RDWR);
        }
    } else if (!failed) {
        pthread_mutex_lock(&public_peer_lock);
        for (st_public_peer *peer = public_peers; peer != NULL; peer = peer->next) {
            int targeted = target != NULL && *target != '\0';
            if (targeted) {
                if (!public_same_scope(source, peer) || strcmp(peer->peer_id, target) != 0) continue;
            } else if (peer == source || !public_same_group(source, peer)) {
                continue;
            }
            (void)public_peer_send_text(peer, envelope.data);
            if (targeted) break;
        }
        pthread_mutex_unlock(&public_peer_lock);
    }
    free(envelope.data);
    free(payload);
    free(target);
    free(type);
}

static int public_route_binary(st_public_peer *source, const uint8_t *frame, size_t len)
{
    if (len < 14U || len > ST_PUBLIC_MAX_BINARY_BYTES || memcmp(frame, "STWR", 4U) != 0
        || frame[4] != 2U || frame[5] != 0U) {
        (void)public_peer_send_error(source, "invalid binary relay frame");
        public_peer_close(source, 1008U);
        return -1;
    }
    uint16_t target_len = public_read_u16(frame + 6U);
    uint16_t source_len = public_read_u16(frame + 8U);
    uint32_t app_len = public_read_u32(frame + 10U);
    if (target_len == 0U || target_len > 512U || source_len != 0U
        || (size_t)app_len != len - 14U - target_len
        || public_utf8_units(frame + 14U, target_len, 512U, NULL) != 0
        || memchr(frame + 14U, '\0', target_len) != NULL
        || public_validate_stap2(frame + 14U + target_len, app_len) != 0) {
        (void)public_peer_send_error(source, "invalid binary relay frame");
        public_peer_close(source, 1008U);
        return -1;
    }
    const uint8_t *app_frame = frame + 14U + target_len;
    if (strcmp(source->room_role, "VIEWER") == 0 && app_frame[5] != 127U) {
        (void)public_peer_send_error(source, "viewer is read-only");
        return 0;
    }
    size_t source_id_len = strlen(source->peer_id);
    size_t outgoing_len = 14U + target_len + source_id_len + app_len;
    if (source_id_len > 512U || outgoing_len > ST_PUBLIC_MAX_BINARY_BYTES) {
        (void)public_peer_send_error(source, "binary relay frame is too large");
        public_peer_close(source, 1008U);
        return -1;
    }
    char target[513];
    memcpy(target, frame + 14U, target_len);
    target[target_len] = '\0';
    uint8_t *outgoing = (uint8_t *)malloc(outgoing_len);
    if (outgoing == NULL) return -1;
    memcpy(outgoing, "STWR", 4U);
    outgoing[4] = 2U;
    outgoing[5] = 0U;
    public_write_u16(outgoing + 6U, target_len);
    public_write_u16(outgoing + 8U, (uint16_t)source_id_len);
    public_write_u32(outgoing + 10U, app_len);
    memcpy(outgoing + 14U, target, target_len);
    memcpy(outgoing + 14U + target_len, source->peer_id, source_id_len);
    memcpy(outgoing + 14U + target_len + source_id_len,
           frame + 14U + target_len,
           app_len);
    if (st_public_coordination_enabled()) {
        const char *group_id = source->cluster.group_id;
        st_public_cluster_participant target_participant;
        int found = 0;
        if (st_public_coordination_find_peer(&source->cluster,
                                            target,
                                            &target_participant,
                                            &found) != 0
            || st_public_coordination_publish_binary(found ? target_participant.group_id : group_id,
                                                     target,
                                                     outgoing,
                                                     outgoing_len) != 0) {
            free(outgoing);
            (void)public_peer_send_error(source, "coordination unavailable");
            (void)shutdown(source->fd, SHUT_RDWR);
            return -1;
        }
    } else {
        pthread_mutex_lock(&public_peer_lock);
        for (st_public_peer *peer = public_peers; peer != NULL; peer = peer->next) {
            if (public_same_scope(source, peer) && strcmp(peer->peer_id, target) == 0) {
                (void)public_peer_send(peer, 0x2U, outgoing, outgoing_len);
                break;
            }
        }
        pthread_mutex_unlock(&public_peer_lock);
    }
    free(outgoing);
    return 0;
}

static void public_drain_peer(st_public_peer *peer)
{
    st_public_builder fragmented = {0};
    uint8_t fragment_opcode = 0U;
    for (;;) {
        uint8_t header[2];
        if (public_recv_all(peer->fd, header, sizeof(header)) != 0) break;
        int fin = (header[0] & 0x80U) != 0U;
        uint8_t rsv = (uint8_t)((header[0] >> 4U) & 7U);
        uint8_t opcode = header[0] & 0x0fU;
        int masked = (header[1] & 0x80U) != 0U;
        uint64_t payload_len = header[1] & 0x7fU;
        if (payload_len == 126U) {
            uint8_t extended[2];
            if (public_recv_all(peer->fd, extended, sizeof(extended)) != 0) break;
            payload_len = public_read_u16(extended);
        } else if (payload_len == 127U) {
            uint8_t extended[8];
            if (public_recv_all(peer->fd, extended, sizeof(extended)) != 0) break;
            payload_len = 0U;
            for (size_t i = 0U; i < sizeof(extended); ++i) payload_len = (payload_len << 8U) | extended[i];
        }
        int control = opcode >= 0x8U;
        int protocol_error = !masked || rsv != 0U || (control && (!fin || payload_len > 125U))
            || (opcode == 0x0U && fragment_opcode == 0U)
            || ((opcode == 0x1U || opcode == 0x2U) && fragment_opcode != 0U)
            || (opcode != 0x0U && opcode != 0x1U && opcode != 0x2U
                && opcode != 0x8U && opcode != 0x9U && opcode != 0xaU);
        int too_large = !control
            && (payload_len > ST_PUBLIC_MAX_MESSAGE_BYTES
                || payload_len > ST_PUBLIC_MAX_MESSAGE_BYTES - fragmented.len);
        if (protocol_error || too_large) {
            public_peer_close(peer, too_large ? 1009U : 1002U);
            break;
        }
        uint8_t mask[4];
        if (public_recv_all(peer->fd, mask, sizeof(mask)) != 0) break;
        uint8_t *payload = (uint8_t *)malloc(payload_len == 0U ? 1U : (size_t)payload_len);
        if (payload == NULL) break;
        if (payload_len > 0U && public_recv_all(peer->fd, payload, (size_t)payload_len) != 0) {
            free(payload);
            break;
        }
        for (size_t i = 0U; i < (size_t)payload_len; ++i) payload[i] ^= mask[i % 4U];
        if (opcode == 0x8U) {
            if (payload_len == 1U) public_peer_close(peer, 1002U);
            else (void)public_peer_send(peer, 0x8U, payload, (size_t)payload_len);
            free(payload);
            break;
        }
        if (opcode == 0x9U) {
            (void)public_peer_send(peer, 0xaU, payload, (size_t)payload_len);
            free(payload);
            continue;
        }
        if (opcode == 0xaU) {
            free(payload);
            continue;
        }
        if (fragment_opcode == 0U) fragment_opcode = opcode;
        if (public_builder_append_len(&fragmented, (const char *)payload, (size_t)payload_len) != 0) {
            free(payload);
            break;
        }
        free(payload);
        if (!fin) continue;
        if (!public_allow_message(peer)) {
            (void)public_peer_send_error(peer, "rate limited");
            public_peer_close(peer, 1008U);
            break;
        }
        if (fragment_opcode == 0x1U) {
            int utf8 = public_utf8_units((const uint8_t *)fragmented.data,
                                         fragmented.len,
                                         ST_PUBLIC_MAX_MESSAGE_CHARS,
                                         NULL);
            if (utf8 != 0 || memchr(fragmented.data, '\0', fragmented.len) != NULL) {
                public_peer_close(peer, utf8 == -2 ? 1009U : 1007U);
                break;
            }
            public_route_text(peer, fragmented.data == NULL ? "" : fragmented.data);
        } else if (fragmented.len > ST_PUBLIC_MAX_BINARY_BYTES) {
            public_peer_close(peer, 1009U);
            break;
        } else {
            if (public_route_binary(peer, (const uint8_t *)fragmented.data, fragmented.len) != 0) {
                break;
            }
        }
        free(fragmented.data);
        memset(&fragmented, 0, sizeof(fragmented));
        fragment_opcode = 0U;
    }
    free(fragmented.data);
}

static void public_send_http_error(int fd, int status, const char *reason, const char *error)
{
    char body[256];
    char response[768];
    char *escaped = st_json_escape(error);
    if (escaped == NULL) return;
    int body_len = snprintf(body, sizeof(body), "{\"error\":\"%s\"}", escaped);
    free(escaped);
    if (body_len < 0 || (size_t)body_len >= sizeof(body)) return;
    int response_len = public_write_response(response, sizeof(response), status, reason, body);
    if (response_len > 0) (void)public_send_all(fd, response, (size_t)response_len);
}

int st_public_discovery_handle_websocket(int fd,
                                         const char *method,
                                         const char *path,
                                         const char *request,
                                         const char *remote_address)
{
    if (!public_path_equals(path, "/ws/public-transfer/discovery")) return 0;
    if (st_public_discovery_initialize() != 0) {
        public_send_http_error(fd, 503, "Service Unavailable", "coordination unavailable");
        return 1;
    }
    if (method == NULL || strcmp(method, "GET") != 0
        || !public_header_has_token(request, "Connection", "Upgrade")) {
        public_send_http_error(fd, 426, "Upgrade Required", "websocket upgrade required");
        return 1;
    }
    char *upgrade = public_header_value(request, "Upgrade");
    char *version = public_header_value(request, "Sec-WebSocket-Version");
    char *client_key = public_header_value(request, "Sec-WebSocket-Key");
    if (upgrade == NULL || strcasecmp(upgrade, "websocket") != 0
        || version == NULL || strcmp(version, "13") != 0 || client_key == NULL) {
        free(upgrade); free(version); free(client_key);
        public_send_http_error(fd, 400, "Bad Request", "invalid websocket upgrade");
        return 1;
    }
    free(upgrade);
    free(version);
    int single_ticket = 0;
    char *ticket_text = public_single_ticket_query(path, &single_ticket);
    st_public_ticket *ticket = ticket_text == NULL
        ? NULL : public_consume_ticket(ticket_text, remote_address);
    free(ticket_text);
    if (ticket == NULL) {
        free(client_key);
        public_send_http_error(fd,
                               403,
                               "Forbidden",
                               single_ticket ? "invalid or consumed ticket" : "single-use ticket required");
        return 1;
    }
    char *accept = public_websocket_accept(client_key);
    free(client_key);
    if (accept == NULL) {
        free(ticket);
        public_send_http_error(fd, 500, "Internal Server Error", "websocket accept failed");
        return 1;
    }
    char response[512];
    int response_len = snprintf(response,
                                sizeof(response),
                                "HTTP/1.1 101 Switching Protocols\r\n"
                                "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                                "Sec-WebSocket-Accept: %s\r\n\r\n",
                                accept);
    free(accept);
    if (response_len < 0 || (size_t)response_len >= sizeof(response)
        || public_send_all(fd, response, (size_t)response_len) != 0) {
        free(ticket);
        return 1;
    }
    st_public_peer *peer = (st_public_peer *)calloc(1, sizeof(*peer));
    if (peer == NULL) {
        free(ticket);
        return 1;
    }
    peer->fd = fd;
    snprintf(peer->room_id, sizeof(peer->room_id), "%s", ticket->room_id);
    snprintf(peer->peer_id, sizeof(peer->peer_id), "%s", ticket->peer_id);
    snprintf(peer->display_name, sizeof(peer->display_name), "%s", ticket->display_name);
    snprintf(peer->public_address, sizeof(peer->public_address), "%s", ticket->public_address);
    snprintf(peer->room_key, sizeof(peer->room_key), "%s", ticket->room_key);
    snprintf(peer->room_role, sizeof(peer->room_role), "%s", ticket->room_role);
    peer->shared_room = ticket->shared_room;
    peer->discoverable = ticket->discoverable;
    (void)public_iso_time(time(NULL), peer->connected_at);
    snprintf(peer->cluster.peer_id, sizeof(peer->cluster.peer_id), "%s", peer->peer_id);
    snprintf(peer->cluster.display_name,
             sizeof(peer->cluster.display_name),
             "%s",
             peer->display_name);
    snprintf(peer->cluster.room_id, sizeof(peer->cluster.room_id), "%s", peer->room_id);
    snprintf(peer->cluster.public_address,
             sizeof(peer->cluster.public_address),
             "%s",
             peer->public_address);
    snprintf(peer->cluster.room_key, sizeof(peer->cluster.room_key), "%s", peer->room_key);
    snprintf(peer->cluster.room_role, sizeof(peer->cluster.room_role), "%s", peer->room_role);
    snprintf(peer->cluster.connected_at,
             sizeof(peer->cluster.connected_at),
             "%s",
             peer->connected_at);
    peer->cluster.shared_room = peer->shared_room;
    if (st_public_coordination_enabled()
        && st_public_coordination_prepare_participant(&peer->cluster) != 0) {
        free(ticket);
        free(peer);
        return 1;
    }
    long write_timeout = public_env_long(
        "SPECUS_PUBLIC_TRANSFER_DISCOVERY_WRITE_TIMEOUT_SECONDS",
        5L);
    if (write_timeout > 300L) write_timeout = 300L;
    struct timeval send_timeout = {
        .tv_sec = write_timeout,
        .tv_usec = 0
    };
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &send_timeout, sizeof(send_timeout));
    pthread_mutex_init(&peer->send_lock, NULL);
    free(ticket);
    int registered = public_register_peer(peer);
    if (registered != 0) {
        if (registered == -2) (void)public_peer_send_error(peer, "peer id is already connected");
        else if (registered == -3) (void)public_peer_send_error(peer, "room is full");
        else if (registered == -4) (void)public_peer_send_error(peer, "display name is already connected");
        if (registered != -1) public_peer_close(peer, 1008U);
        pthread_mutex_destroy(&peer->send_lock);
        free(peer);
        return 1;
    }
    public_drain_peer(peer);
    public_remove_peer(peer);
    pthread_mutex_destroy(&peer->send_lock);
    free(peer);
    return 1;
}

void st_public_discovery_reset_for_tests(void)
{
    st_public_discovery_shutdown();
    st_public_room_reset_for_tests();
    pthread_mutex_lock(&public_ticket_lock);
    while (public_tickets != NULL) {
        st_public_ticket *next = public_tickets->next;
        free(public_tickets);
        public_tickets = next;
    }
    pthread_mutex_unlock(&public_ticket_lock);
    pthread_mutex_lock(&public_peer_lock);
    public_roster_revision = 0U;
    pthread_mutex_unlock(&public_peer_lock);
}
