#define _POSIX_C_SOURCE 200809L

#include "public_discovery.h"
#include "admin_http.h"

#include "crypto.h"
#include "json.h"
#include "public_coordination.h"
#include "public_room.h"
#include "websocket_ticket.h"

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
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>
#include <utf8proc.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

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
    char room_id[ST_PUBLIC_ROOM_ID_BYTES + 1U];
    char peer_id[ST_PUBLIC_PEER_ID_BYTES + 1U];
    char display_name[ST_PUBLIC_DISPLAY_NAME_BYTES + 1U];
    char public_address[ST_PUBLIC_ADDRESS_BYTES + 1U];
    char room_key[ST_PUBLIC_ROOM_KEY_BYTES + 1U];
    char room_role[16];
    int shared_room;
    int discoverable;
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
    long write_timeout_ms;
    /*
     * Under public_peer_lock: refs counts threads that took the peer from the list and write to
     * it after releasing the lock; its owner waits for zero before freeing it. linked is 1 while
     * it is in public_peers (a peer dropped as Java's dropLocal drops one is unlinked at once).
     */
    unsigned int refs;
    int linked;
    /* Under send_lock: a frame failed or timed out, so the stream may be cut mid-frame. */
    int dead;
    pthread_mutex_t send_lock;
    struct st_public_peer *next;
} st_public_peer;

/* Peers written to outside public_peer_lock; each entry holds a reference. */
typedef struct {
    st_public_peer *peer;
    char *text; /* this recipient's own text, or NULL for the shared one */
} st_public_delivery;

typedef struct {
    st_public_delivery *items;
    size_t count;
    size_t capacity;
} st_public_deliveries;

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} st_public_builder;

/*
 * Guards the peer list and the per-peer bookkeeping above. No socket write happens while it is
 * held, so one slow browser only delays the threads writing to that browser (Java synchronizes
 * a send on the target session alone).
 */
static pthread_mutex_t public_peer_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t public_peer_released = PTHREAD_COND_INITIALIZER;
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
        /* A later Redis failure is not terminal: each operation fails alone and reconnects. */
        pthread_mutex_unlock(&public_discovery_init_lock);
        return 0;
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

/* Java Character.isWhitespace: separators other than the no-break spaces, plus TAB..CR and FS..US. */
static int public_java_whitespace(uint32_t codepoint)
{
    if ((codepoint >= 0x09U && codepoint <= 0x0dU) || (codepoint >= 0x1cU && codepoint <= 0x1fU)) return 1;
    if (codepoint == 0xa0U || codepoint == 0x2007U || codepoint == 0x202fU) return 0;
    utf8proc_category_t category = utf8proc_category((utf8proc_int32_t)codepoint);
    return category == UTF8PROC_CATEGORY_ZS || category == UTF8PROC_CATEGORY_ZL
        || category == UTF8PROC_CATEGORY_ZP;
}

/* Java String.isBlank of valid UTF-8 text: empty or whitespace only. */
static int public_text_blank(const uint8_t *data, size_t len)
{
    size_t offset = 0U;
    while (offset < len) {
        uint32_t codepoint = 0U;
        if (public_utf8_next(data, len, &offset, &codepoint, NULL) < 0) return 0;
        if (!public_java_whitespace(codepoint)) return 0;
    }
    return 1;
}

/*
 * Java String.equalsIgnoreCase for the in-process name checks: code point by code point, two code
 * points match when equal, when their simple upper-case mappings are equal, or when the lower-case
 * mappings of those are. Invalid UTF-8 only matches byte for byte.
 */
static int public_names_equal_ignore_case(const char *left, const char *right)
{
    const uint8_t *a = (const uint8_t *)left;
    const uint8_t *b = (const uint8_t *)right;
    size_t a_len = strlen(left);
    size_t b_len = strlen(right);
    size_t a_offset = 0U;
    size_t b_offset = 0U;
    while (a_offset < a_len && b_offset < b_len) {
        uint32_t a_codepoint = 0U;
        uint32_t b_codepoint = 0U;
        if (public_utf8_next(a, a_len, &a_offset, &a_codepoint, NULL) < 0
            || public_utf8_next(b, b_len, &b_offset, &b_codepoint, NULL) < 0) {
            return strcmp(left, right) == 0;
        }
        if (a_codepoint == b_codepoint) continue;
        utf8proc_int32_t a_upper = utf8proc_toupper((utf8proc_int32_t)a_codepoint);
        utf8proc_int32_t b_upper = utf8proc_toupper((utf8proc_int32_t)b_codepoint);
        if (a_upper == b_upper || utf8proc_tolower(a_upper) == utf8proc_tolower(b_upper)) continue;
        return 0;
    }
    return a_offset == a_len && b_offset == b_len;
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

static int public_issue_ticket(const st_public_ticket *ticket, const char *remote_address, char out[64], char expires_at[ST_INSTANT_CAPACITY])
{
    if (ticket == NULL) return -1;
    const char *values[] = {ticket->room_id, ticket->peer_id, ticket->display_name, ticket->public_address, ticket->room_key, ticket->room_role};
    char *escaped[6] = {0}; size_t capacity = 256U; int valid = 1;
    for (size_t i = 0; i < 6U; ++i) { escaped[i] = st_json_escape(values[i]); if (escaped[i] == NULL) valid = 0; else capacity += strlen(escaped[i]); }
    char *json = valid ? malloc(capacity) : NULL;
    int rc = -1;
    if (json != NULL) {
        snprintf(json, capacity, "{\"roomId\":\"%s\",\"peerId\":\"%s\",\"displayName\":\"%s\",\"publicAddress\":\"%s\",\"roomKey\":\"%s\",\"roomRole\":\"%s\",\"sharedRoom\":%s,\"discoverable\":%s}",
            escaped[0], escaped[1], escaped[2], escaped[3], escaped[4], escaped[5], ticket->shared_room ? "true" : "false", ticket->discoverable ? "true" : "false");
        rc = st_websocket_ticket_issue("public-transfer", json, remote_address, out, expires_at);
    }
    free(json); for (size_t i = 0; i < 6U; ++i) free(escaped[i]); return rc;
}

static st_public_ticket *public_consume_ticket(const char *token, const char *remote_address)
{
    char *json = NULL;
    if (st_websocket_ticket_consume("public-transfer", token, remote_address, &json) != 0) return NULL;
    st_public_ticket *ticket = calloc(1U, sizeof(*ticket));
    int valid = ticket != NULL
        && st_websocket_ticket_json_string(json, "roomId", ticket->room_id, sizeof(ticket->room_id), 1) == 0
        && st_websocket_ticket_json_string(json, "peerId", ticket->peer_id, sizeof(ticket->peer_id), 1) == 0
        && st_websocket_ticket_json_string(json, "displayName", ticket->display_name, sizeof(ticket->display_name), 1) == 0
        && st_websocket_ticket_json_string(json, "publicAddress", ticket->public_address, sizeof(ticket->public_address), 1) == 0
        && st_websocket_ticket_json_string(json, "roomKey", ticket->room_key, sizeof(ticket->room_key), 1) == 0
        && st_websocket_ticket_json_string(json, "roomRole", ticket->room_role, sizeof(ticket->room_role), 1) == 0
        && st_json_get_bool(json, "sharedRoom", &ticket->shared_room) == 0 && st_json_get_bool(json, "discoverable", &ticket->discoverable) == 0
        && (strcmp(ticket->room_role, "OWNER") == 0 || strcmp(ticket->room_role, "EDITOR") == 0 || strcmp(ticket->room_role, "VIEWER") == 0);
    free(json); if (!valid) { free(ticket); return NULL; } return ticket;
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
    char token[64];
    char expires_text[ST_INSTANT_CAPACITY];
    int issue = public_issue_ticket(ticket, remote_address, token, expires_text);
    free(ticket);
    if (issue != 0) {
        return public_write_response(out,
                                     out_len,
                                     issue == -2 ? 429 : 500,
                                     issue == -2 ? "Too Many Requests" : "Internal Server Error",
                                     issue == -2 ? "{\"error\":\"too many active websocket tickets\"}"
                                                 : "{\"error\":\"ticket generation failed\"}");
    }
    char response[256];
    if (snprintf(response,
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
            /* Java: the IllegalStateException of command() through GlobalExceptionHandler. */
            return public_write_response(out,
                                         out_len,
                                         409,
                                         "Conflict",
                                         "{\"error\":\"public transfer Redis coordination unavailable\"}");
        }
    } else {
        pthread_mutex_lock(&public_peer_lock);
        for (st_public_peer *peer = public_peers; peer != NULL; peer = peer->next) {
            if ((exclude == NULL || *exclude == '\0' || strcmp(peer->peer_id, exclude) != 0)
                && public_names_equal_ignore_case(peer->display_name, normalized)) {
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

int st_public_discovery_shared_rate_allow(const char *bucket,
                                          const char *identity,
                                          long limit,
                                          long window_seconds)
{
    int allowed = 0;
    if (!st_public_coordination_enabled() || st_public_discovery_initialize() != 0
        || st_public_coordination_allow_rate(bucket, identity, limit, window_seconds, &allowed) != 0) {
        return -1;
    }
    return allowed ? 1 : 0;
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

static long long public_now_ms(void)
{
    struct timespec now;
    (void)clock_gettime(CLOCK_MONOTONIC, &now);
    return (long long)now.tv_sec * 1000LL + now.tv_nsec / 1000000L;
}

/*
 * Writes one whole frame, header and payload, within timeout_ms in total (a trickling reader
 * cannot stretch it); -1 when it fails or does not finish in time.
 */
static int public_send_frame_fd(int fd,
                                uint8_t opcode,
                                const uint8_t *payload,
                                size_t payload_len,
                                long timeout_ms)
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
    struct iovec parts[2] = {
        {.iov_base = header, .iov_len = header_len},
        {.iov_base = (void *)payload, .iov_len = payload_len}
    };
    size_t part_count = payload_len > 0U ? 2U : 1U;
    size_t part = 0U;
    long long deadline = public_now_ms() + (timeout_ms < 0L ? 0L : timeout_ms);
    while (part < part_count) {
        struct msghdr message;
        memset(&message, 0, sizeof(message));
        message.msg_iov = parts + part;
        message.msg_iovlen = part_count - part;
        ssize_t written = sendmsg(fd, &message, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (written < 0 && errno == EINTR) continue;
        if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            long long remaining = deadline - public_now_ms();
            if (remaining <= 0) return -1;
            struct pollfd poller = {.fd = fd, .events = POLLOUT, .revents = 0};
            int ready = poll(&poller, 1, remaining > INT_MAX ? INT_MAX : (int)remaining);
            if (ready < 0 && errno != EINTR) return -1;
            if (ready > 0 && (poller.revents & (POLLERR | POLLNVAL)) != 0) return -1;
            continue;
        }
        if (written <= 0) return -1;
        size_t advance = (size_t)written;
        while (advance > 0U && part < part_count) {
            if (advance >= parts[part].iov_len) {
                advance -= parts[part].iov_len;
                ++part;
            } else {
                parts[part].iov_base = (uint8_t *)parts[part].iov_base + advance;
                parts[part].iov_len -= advance;
                advance = 0U;
            }
        }
    }
    return 0;
}

/*
 * Tomcat closes a session whose blocking send fails or exceeds its timeout. Here the failed frame
 * may already be partly written, so the peer is marked dead (no further frame can follow the cut
 * one) and its socket shut down; its own thread then sees the end and removes it.
 */
static int public_peer_send_within(st_public_peer *peer,
                                   uint8_t opcode,
                                   const uint8_t *payload,
                                   size_t payload_len,
                                   long timeout_ms)
{
    pthread_mutex_lock(&peer->send_lock);
    int result = -1;
    if (!peer->dead) {
        result = public_send_frame_fd(peer->fd, opcode, payload, payload_len, timeout_ms);
        if (result != 0) {
            peer->dead = 1;
            (void)shutdown(peer->fd, SHUT_RDWR);
        }
    }
    pthread_mutex_unlock(&peer->send_lock);
    return result;
}

static int public_peer_send(st_public_peer *peer,
                            uint8_t opcode,
                            const uint8_t *payload,
                            size_t payload_len)
{
    return public_peer_send_within(peer, opcode, payload, payload_len, peer->write_timeout_ms);
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

/*
 * Java PublicTransferCoordinationService.sameNetAddress: an empty, blank or "unknown" address is
 * not identifiable, so two such participants never share a net even when the strings are equal.
 */
static int public_address_known(const char *address)
{
    if (address == NULL || strcasecmp(address, "unknown") == 0) return 0;
    for (const unsigned char *cursor = (const unsigned char *)address; *cursor != '\0'; ++cursor)
        if (!isspace(*cursor)) return 1;
    return 0;
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

/* With public_peer_lock held: adds a reference to peer; text (owned, may be NULL) goes with it. */
static int public_deliveries_add_locked(st_public_deliveries *list, st_public_peer *peer, char *text)
{
    if (list->count == list->capacity) {
        size_t next = list->capacity == 0U ? 8U : list->capacity * 2U;
        st_public_delivery *grown = (st_public_delivery *)realloc(list->items, next * sizeof(*grown));
        if (grown == NULL) {
            free(text);
            return -1;
        }
        list->items = grown;
        list->capacity = next;
    }
    list->items[list->count].peer = peer;
    list->items[list->count].text = text;
    ++list->count;
    ++peer->refs;
    return 0;
}

static void public_deliveries_release(st_public_deliveries *list)
{
    if (list->count > 0U) {
        pthread_mutex_lock(&public_peer_lock);
        int released = 0;
        for (size_t i = 0U; i < list->count; ++i) {
            if (--list->items[i].peer->refs == 0U) released = 1;
        }
        if (released) pthread_cond_broadcast(&public_peer_released);
        pthread_mutex_unlock(&public_peer_lock);
    }
    for (size_t i = 0U; i < list->count; ++i) free(list->items[i].text);
    free(list->items);
    memset(list, 0, sizeof(*list));
}

/* Writes each entry's text, or the shared one, outside public_peer_lock. */
static void public_deliver_texts(const st_public_deliveries *list, const char *shared)
{
    for (size_t i = 0U; i < list->count; ++i) {
        const char *text = list->items[i].text != NULL ? list->items[i].text : shared;
        if (text != NULL) (void)public_peer_send(list->items[i].peer, 0x1U,
                                                 (const uint8_t *)text, strlen(text));
    }
}

/* The owner's last step before freeing peer: no other thread may still write to it. */
static void public_wait_unreferenced(st_public_peer *peer)
{
    pthread_mutex_lock(&public_peer_lock);
    while (peer->refs > 0U) pthread_cond_wait(&public_peer_released, &public_peer_lock);
    pthread_mutex_unlock(&public_peer_lock);
}

static char *public_build_roster_text_locked(const st_public_peer *recipient, uint64_t revision)
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
    if (failed) {
        free(builder.data);
        return NULL;
    }
    return builder.data;
}

/* Java emitRoster in process-local mode: every connection in scope's group or net gets its view. */
static void public_collect_rosters_locked(st_public_deliveries *list,
                                          const st_public_peer *scope,
                                          uint64_t revision)
{
    for (st_public_peer *peer = public_peers; peer != NULL; peer = peer->next) {
        if (!public_same_scope(scope, peer)) continue;
        char *text = public_build_roster_text_locked(peer, revision);
        if (text != NULL) (void)public_deliveries_add_locked(list, peer, text);
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
    if (event->kind == ST_PUBLIC_CLUSTER_EVENT_MANAGEMENT
        || event->kind == ST_PUBLIC_CLUSTER_EVENT_MANAGEMENT_REVOCATION) {
        st_admin_handle_cluster_event(event);
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
        /*
         * Java emitRoster: one Redis snapshot per (groupId, netId) of the recipients in this event,
         * each recipient's view built from it; a failed read discards the rest of the event.
         */
        st_public_cluster_roster *snapshots = copied == 0U ? NULL
            : (st_public_cluster_roster *)calloc(copied, sizeof(*snapshots));
        size_t *snapshot_of = copied == 0U ? NULL : (size_t *)calloc(copied, sizeof(*snapshot_of));
        size_t snapshot_count = 0U;
        for (size_t i = 0U; snapshots != NULL && snapshot_of != NULL && i < copied; ++i) {
            size_t found = SIZE_MAX;
            for (size_t j = 0U; j < i && found == SIZE_MAX; ++j) {
                if (strcmp(recipients[j].group_id, recipients[i].group_id) == 0
                    && strcmp(recipients[j].net_id, recipients[i].net_id) == 0) found = snapshot_of[j];
            }
            if (found == SIZE_MAX) {
                if (st_public_coordination_roster(&recipients[i], &snapshots[snapshot_count]) != 0) break;
                found = snapshot_count++;
            }
            snapshot_of[i] = found;
            char *text = public_build_cluster_roster_text(&recipients[i], &snapshots[found]);
            if (text == NULL) continue;
            st_public_deliveries target = {0};
            pthread_mutex_lock(&public_peer_lock);
            st_public_peer *peer = public_find_cluster_peer_locked(recipients[i].lease_id);
            if (peer != NULL) (void)public_deliveries_add_locked(&target, peer, text);
            else free(text);
            pthread_mutex_unlock(&public_peer_lock);
            public_deliver_texts(&target, NULL);
            public_deliveries_release(&target);
        }
        for (size_t i = 0U; snapshots != NULL && i < snapshot_count; ++i)
            st_public_coordination_roster_free(&snapshots[i]);
        free(snapshots);
        free(snapshot_of);
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
        st_public_deliveries targets = {0};
        pthread_mutex_lock(&public_peer_lock);
        for (st_public_peer *peer = public_peers; peer != NULL; peer = peer->next) {
            if (strcmp(peer->cluster.group_id, event->group_id) != 0
                && strcmp(peer->cluster.net_id, event->group_id) != 0) continue;
            if (*event->target_peer_id != '\0'
                && strcmp(peer->peer_id, event->target_peer_id) != 0) continue;
            if (event->exclude_source
                && strcmp(peer->cluster.lease_id, event->source_lease_id) == 0) continue;
            (void)public_deliveries_add_locked(&targets, peer, NULL);
        }
        pthread_mutex_unlock(&public_peer_lock);
        public_deliver_texts(&targets, payload);
        public_deliveries_release(&targets);
        free(payload);
        return;
    }
    if (event->kind == ST_PUBLIC_CLUSTER_EVENT_BINARY
        && event->payload_len <= ST_PUBLIC_MAX_BINARY_BYTES) {
        st_public_deliveries target = {0};
        pthread_mutex_lock(&public_peer_lock);
        for (st_public_peer *peer = public_peers; peer != NULL; peer = peer->next) {
            if ((strcmp(peer->cluster.group_id, event->group_id) == 0
                 || strcmp(peer->cluster.net_id, event->group_id) == 0)
                && strcmp(peer->peer_id, event->target_peer_id) == 0) {
                (void)public_deliveries_add_locked(&target, peer, NULL);
                break;
            }
        }
        pthread_mutex_unlock(&public_peer_lock);
        for (size_t i = 0U; i < target.count; ++i)
            (void)public_peer_send(target.items[i].peer, 0x2U, event->payload, event->payload_len);
        public_deliveries_release(&target);
    }
}

/*
 * The hello is written while public_peer_lock still hides the new peer from other writers, so it
 * is always the first frame. It is the first data on a fresh socket and fits its send buffer;
 * the write is attempted once and never waits there.
 */
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
    int result = failed ? -1 : public_peer_send_within(peer, 0x1U, (const uint8_t *)builder.data,
                                                         builder.len, 0L);
    free(builder.data);
    return result;
}

/* With public_peer_lock held: appends peer to the list. */
static void public_link_locked(st_public_peer *peer)
{
    st_public_peer **tail = &public_peers;
    while (*tail != NULL) tail = &(*tail)->next;
    peer->next = NULL;
    *tail = peer;
    peer->linked = 1;
}

/* With public_peer_lock held: takes peer out of the list; 1 when it was in it. */
static int public_unlink_locked(st_public_peer *peer)
{
    if (!peer->linked) return 0;
    st_public_peer **cursor = &public_peers;
    while (*cursor != NULL && *cursor != peer) cursor = &(*cursor)->next;
    if (*cursor == peer) *cursor = peer->next;
    peer->next = NULL;
    peer->linked = 0;
    return 1;
}

enum {
    PUBLIC_JOIN_OK = 0,
    PUBLIC_JOIN_IO = -1,
    PUBLIC_JOIN_DUPLICATE = -2,
    PUBLIC_JOIN_FULL = -3,
    PUBLIC_JOIN_NAME = -4,
    /* hello sent and the peer joined, but publishing its roster failed: Java closes with 1011 */
    PUBLIC_JOIN_ROSTER_FAILED = -5,
    /* the Redis registration failed: Java answers "coordination unavailable" and 1008 */
    PUBLIC_JOIN_UNAVAILABLE = -6
};

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
                if (registration == 1) return PUBLIC_JOIN_DUPLICATE;
                if (registration == 2) return PUBLIC_JOIN_NAME;
                if (registration == 3) return PUBLIC_JOIN_FULL;
                return PUBLIC_JOIN_UNAVAILABLE;
            }
        }
        pthread_mutex_lock(&public_peer_lock);
        public_link_locked(peer);
        int send_result = public_send_hello(peer, revision);
        if (send_result != 0) (void)public_unlink_locked(peer);
        pthread_mutex_unlock(&public_peer_lock);
        if (send_result != 0) {
            if (peer->discoverable) {
                uint64_t ignored = 0U;
                (void)st_public_coordination_unregister(&peer->cluster, &ignored);
            }
            return PUBLIC_JOIN_IO;
        }
        if (st_public_coordination_publish_roster(peer->cluster.group_id, revision) != 0
            || st_public_coordination_publish_roster(peer->cluster.net_id, revision) != 0) {
            return PUBLIC_JOIN_ROSTER_FAILED;
        }
        return PUBLIC_JOIN_OK;
    }
    st_public_deliveries rosters = {0};
    size_t room_count = 0U;
    pthread_mutex_lock(&public_peer_lock);
    if (!peer->discoverable) {
        public_link_locked(peer);
        int hidden_send = public_send_hello(peer, 0U);
        if (hidden_send == 0) public_collect_rosters_locked(&rosters, peer, 0U);
        else (void)public_unlink_locked(peer);
        pthread_mutex_unlock(&public_peer_lock);
        public_deliver_texts(&rosters, NULL);
        public_deliveries_release(&rosters);
        return hidden_send == 0 ? PUBLIC_JOIN_OK : PUBLIC_JOIN_IO;
    }
    for (st_public_peer *existing = public_peers; existing != NULL; existing = existing->next) {
        if (public_same_scope(existing, peer) && strcmp(existing->peer_id, peer->peer_id) == 0) {
            pthread_mutex_unlock(&public_peer_lock);
            return PUBLIC_JOIN_DUPLICATE;
        }
        if (public_same_group(existing, peer)) {
            ++room_count;
        }
    }
    for (st_public_peer *existing = public_peers; existing != NULL; existing = existing->next) {
        if (public_names_equal_ignore_case(existing->display_name, peer->display_name)) {
            pthread_mutex_unlock(&public_peer_lock);
            return PUBLIC_JOIN_NAME;
        }
    }
    if (room_count >= (size_t)max_room) {
        pthread_mutex_unlock(&public_peer_lock);
        return PUBLIC_JOIN_FULL;
    }
    public_link_locked(peer);
    uint64_t revision = ++public_roster_revision;
    int send_result = public_send_hello(peer, revision);
    if (send_result == 0) public_collect_rosters_locked(&rosters, peer, revision);
    else (void)public_unlink_locked(peer);
    pthread_mutex_unlock(&public_peer_lock);
    /* The new peer is last in the list, so the others' rosters go out before its own. */
    public_deliver_texts(&rosters, NULL);
    public_deliveries_release(&rosters);
    return send_result == 0 ? PUBLIC_JOIN_OK : PUBLIC_JOIN_IO;
}

/* Java afterConnectionClosed; a peer this instance dropped (dropLocal) is already forgotten. */
static void public_remove_peer(st_public_peer *peer)
{
    st_public_deliveries rosters = {0};
    int cluster = st_public_coordination_enabled();
    pthread_mutex_lock(&public_peer_lock);
    int removed = public_unlink_locked(peer);
    if (removed && peer->discoverable && !cluster) {
        uint64_t revision = ++public_roster_revision;
        public_collect_rosters_locked(&rosters, peer, revision);
    }
    pthread_mutex_unlock(&public_peer_lock);
    public_deliver_texts(&rosters, NULL);
    public_deliveries_release(&rosters);
    if (removed && peer->discoverable && cluster) {
        uint64_t revision = 0U;
        if (st_public_coordination_unregister(&peer->cluster, &revision) == 0
            && revision > 0U) {
            (void)st_public_coordination_publish_roster(peer->cluster.group_id, revision);
            (void)st_public_coordination_publish_roster(peer->cluster.net_id, revision);
        }
    }
    public_wait_unreferenced(peer);
}

/*
 * Java dropLocal(session, SERVER_ERROR): forgets the connection at once (so it is neither
 * unregistered nor announced when it ends), closes it with 1011 and ends it. lease_id NULL drops
 * every local connection, hidden ones included.
 */
static void public_drop_peers(const char *lease_id)
{
    st_public_deliveries dropped = {0};
    pthread_mutex_lock(&public_peer_lock);
    st_public_peer *peer = public_peers;
    while (peer != NULL) {
        st_public_peer *next = peer->next;
        if (lease_id == NULL || strcmp(peer->cluster.lease_id, lease_id) == 0) {
            if (public_deliveries_add_locked(&dropped, peer, NULL) == 0) (void)public_unlink_locked(peer);
            if (lease_id != NULL) break;
        }
        peer = next;
    }
    pthread_mutex_unlock(&public_peer_lock);
    for (size_t i = 0U; i < dropped.count; ++i) {
        st_public_peer *target = dropped.items[i].peer;
        uint8_t code[2] = {(uint8_t)(1011U >> 8U), (uint8_t)(1011U & 0xffU)};
        (void)public_peer_send(target, 0x8U, code, sizeof(code));
        (void)shutdown(target->fd, SHUT_RDWR);
    }
    public_deliveries_release(&dropped);
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

/* Appends value unless an equal string is already among the first count entries. */
static int public_unique_add(const char **values, size_t *count, const char *value)
{
    for (size_t i = 0U; i < *count; ++i)
        if (strcmp(values[i], value) == 0) return 0;
    values[(*count)++] = value;
    return 1;
}

/*
 * Java refreshClusterPresence: renew every visible local lease (a lost lease drops that socket
 * with 1011), then sweep each distinct (group, net) once and publish one roster per distinct net.
 * Any Redis failure in the cycle drops every local discovery socket with 1011.
 */
static void public_refresh_cluster_presence(void)
{
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
    if (copied == 0U) {
        free(participants);
        return;
    }
    const st_public_cluster_participant **group_nets =
        (const st_public_cluster_participant **)calloc(copied, sizeof(*group_nets));
    const char **nets = (const char **)calloc(copied, sizeof(*nets));
    size_t group_net_count = 0U;
    size_t net_count = 0U;
    int failed = group_nets == NULL || nets == NULL;
    for (size_t i = 0U; !failed && i < copied; ++i) {
        int distinct = 1;
        for (size_t j = 0U; j < group_net_count && distinct; ++j) {
            distinct = strcmp(group_nets[j]->group_id, participants[i].group_id) != 0
                || strcmp(group_nets[j]->net_id, participants[i].net_id) != 0;
        }
        if (distinct) group_nets[group_net_count++] = &participants[i];
        (void)public_unique_add(nets, &net_count, participants[i].net_id);
        int refreshed = st_public_coordination_refresh(&participants[i]);
        if (refreshed < 0) failed = 1;
        else if (refreshed > 0) public_drop_peers(participants[i].lease_id);
    }
    for (size_t i = 0U; !failed && i < group_net_count; ++i)
        failed = st_public_coordination_sweep(group_nets[i]->group_id, group_nets[i]->net_id) != 0;
    for (size_t i = 0U; !failed && i < net_count; ++i)
        failed = st_public_coordination_publish_roster(nets[i], 0U) != 0;
    if (failed) {
        fprintf(stderr, "[public-transfer] Redis coordination unavailable; closing local discovery sockets\n");
        public_drop_peers(NULL);
    }
    free((void *)group_nets);
    free((void *)nets);
    free(participants);
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
        public_refresh_cluster_presence();
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
        /*
         * Java handleTextMessage catches the coordination failure of findPeer or publishText and
         * answers "invalid message"; the socket stays open.
         */
        if (target != NULL && *target != '\0') {
            if (st_public_coordination_find_peer(&source->cluster,
                                                target,
                                                &target_participant,
                                                &found) != 0) {
                failed = 1;
            } else if (found) {
                group_id = target_participant.group_id;
            }
        }
        if (failed
            || st_public_coordination_publish_text(group_id,
                                                   target == NULL ? "" : target,
                                                   source->cluster.lease_id,
                                                   target == NULL || *target == '\0',
                                                   (const uint8_t *)envelope.data,
                                                   envelope.len) != 0) {
            (void)public_peer_send_error(source, "invalid message");
        }
    } else if (!failed) {
        st_public_deliveries targets = {0};
        pthread_mutex_lock(&public_peer_lock);
        for (st_public_peer *peer = public_peers; peer != NULL; peer = peer->next) {
            int targeted = target != NULL && *target != '\0';
            if (targeted) {
                if (!public_same_scope(source, peer) || strcmp(peer->peer_id, target) != 0) continue;
            } else if (peer == source || !public_same_group(source, peer)) {
                continue;
            }
            (void)public_deliveries_add_locked(&targets, peer, NULL);
            if (targeted) break;
        }
        pthread_mutex_unlock(&public_peer_lock);
        public_deliver_texts(&targets, envelope.data);
        public_deliveries_release(&targets);
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
        || public_has_iso_control(frame + 14U, target_len)
        || public_text_blank(frame + 14U, target_len)
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
            /*
             * Java handleBinaryMessage catches only IllegalArgumentException; the coordination
             * failure reaches Spring's ExceptionWebSocketHandlerDecorator, which closes with 1011.
             */
            free(outgoing);
            public_peer_close(source, 1011U);
            return -1;
        }
    } else {
        st_public_deliveries target_peer = {0};
        pthread_mutex_lock(&public_peer_lock);
        for (st_public_peer *peer = public_peers; peer != NULL; peer = peer->next) {
            if (public_same_scope(source, peer) && strcmp(peer->peer_id, target) == 0) {
                (void)public_deliveries_add_locked(&target_peer, peer, NULL);
                break;
            }
        }
        pthread_mutex_unlock(&public_peer_lock);
        for (size_t i = 0U; i < target_peer.count; ++i)
            (void)public_peer_send(target_peer.items[i].peer, 0x2U, outgoing, outgoing_len);
        public_deliveries_release(&target_peer);
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
    /*
     * Each frame must be written within this time in total, as Tomcat bounds a blocking send
     * (20 s there); a peer that does not take its frame in time is closed.
     */
    long write_timeout = public_env_long(
        "SPECUS_PUBLIC_TRANSFER_DISCOVERY_WRITE_TIMEOUT_SECONDS",
        5L);
    if (write_timeout > 300L) write_timeout = 300L;
    peer->write_timeout_ms = write_timeout * 1000L;
    pthread_mutex_init(&peer->send_lock, NULL);
    free(ticket);
    /* Java normalizeDisplayName refuses ISO control characters when the connection joins. */
    if (public_has_iso_control((const uint8_t *)peer->display_name, strlen(peer->display_name))) {
        (void)public_peer_send_error(peer, "client name contains invalid characters");
        public_peer_close(peer, 1008U);
        pthread_mutex_destroy(&peer->send_lock);
        free(peer);
        return 1;
    }
    int registered = public_register_peer(peer);
    if (registered == PUBLIC_JOIN_ROSTER_FAILED) {
        public_peer_close(peer, 1011U);
        public_remove_peer(peer);
        pthread_mutex_destroy(&peer->send_lock);
        free(peer);
        return 1;
    }
    if (registered != PUBLIC_JOIN_OK) {
        if (registered == PUBLIC_JOIN_DUPLICATE) (void)public_peer_send_error(peer, "peer id is already connected");
        else if (registered == PUBLIC_JOIN_FULL) (void)public_peer_send_error(peer, "room is full");
        else if (registered == PUBLIC_JOIN_NAME) (void)public_peer_send_error(peer, "client name is already in use");
        else if (registered == PUBLIC_JOIN_UNAVAILABLE) (void)public_peer_send_error(peer, "coordination unavailable");
        if (registered != PUBLIC_JOIN_IO) public_peer_close(peer, 1008U);
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
    st_websocket_ticket_reset_memory_scope("public-transfer");
    pthread_mutex_lock(&public_peer_lock);
    public_roster_revision = 0U;
    pthread_mutex_unlock(&public_peer_lock);
}
