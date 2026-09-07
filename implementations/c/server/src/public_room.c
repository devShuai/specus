#define _POSIX_C_SOURCE 200809L

#include "public_room.h"

#include "crypto.h"
#include "json.h"
#include "security.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#define ST_ROOM_MAX_BODY (5U * 1024U * 1024U)
#define ST_ROOM_MAX_SNAPSHOT (3U * 1024U * 1024U)
#define ST_ROOM_MAX_ACCESS 20
#define ST_ROOM_RATE_SOURCES 1024U

typedef struct st_room_rate_window {
    char address[128];
    time_t started_at;
    unsigned int count;
    struct st_room_rate_window *next;
} st_room_rate_window;

static pthread_mutex_t room_rate_lock = PTHREAD_MUTEX_INITIALIZER;
static st_room_rate_window *room_rate_windows = NULL;

static int room_write_response(char *out,
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

static int room_error(char *out, size_t out_len, int status, const char *message)
{
    const char *reason = status == 400 ? "Bad Request"
        : status == 403 ? "Forbidden"
        : status == 404 ? "Not Found"
        : status == 409 ? "Conflict"
        : status == 429 ? "Too Many Requests"
        : status == 503 ? "Service Unavailable" : "Internal Server Error";
    char *escaped = st_json_escape(message == NULL ? "服务器内部错误" : message);
    if (escaped == NULL) return -1;
    char response[512];
    int written = snprintf(response, sizeof(response), "{\"error\":\"%s\"}", escaped);
    free(escaped);
    if (written < 0 || (size_t)written >= sizeof(response)) return -1;
    return room_write_response(out, out_len, status, reason, response);
}

static int room_open(sqlite3 **db)
{
    const char *path = getenv("SPECUS_DATABASE_PATH");
    if (path == NULL || *path == '\0') return 1;
    if (sqlite3_open(path, db) != SQLITE_OK) {
        if (*db != NULL) sqlite3_close(*db);
        *db = NULL;
        return -1;
    }
    if (sqlite3_busy_timeout(*db, 5000) != SQLITE_OK) {
        sqlite3_close(*db);
        *db = NULL;
        return -1;
    }
    static const char schema[] =
        "CREATE TABLE IF NOT EXISTS public_transfer_room ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "room_name TEXT NOT NULL,owner_token_hash TEXT NOT NULL,"
        "created_by_peer_id TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,"
        "UNIQUE(room_name,owner_token_hash));"
        "CREATE INDEX IF NOT EXISTS idx_public_transfer_room_name "
        "ON public_transfer_room(room_name);"
        "CREATE TABLE IF NOT EXISTS public_transfer_room_access ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,room_id INTEGER NOT NULL,token_hash TEXT NOT NULL UNIQUE,"
        "role TEXT NOT NULL,label TEXT NOT NULL,created_at TEXT NOT NULL,expires_at TEXT,revoked_at TEXT);"
        "CREATE INDEX IF NOT EXISTS idx_public_transfer_access_room "
        "ON public_transfer_room_access(room_id);"
        "CREATE TABLE IF NOT EXISTS public_transfer_room_pairing_code ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,room_id INTEGER NOT NULL,code_hash TEXT NOT NULL UNIQUE,"
        "role TEXT NOT NULL,label TEXT NOT NULL,created_at TEXT NOT NULL,expires_at TEXT NOT NULL,"
        "max_uses INTEGER NOT NULL,used_count INTEGER NOT NULL DEFAULT 0,revoked_at TEXT);"
        "CREATE INDEX IF NOT EXISTS idx_public_transfer_pairing_room "
        "ON public_transfer_room_pairing_code(room_id);"
        "CREATE TABLE IF NOT EXISTS public_transfer_diagram_version ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,room_id INTEGER NOT NULL,name TEXT NOT NULL,"
        "author_peer_id TEXT NOT NULL,snapshot_data BLOB NOT NULL,size_bytes INTEGER NOT NULL,"
        "created_at TEXT NOT NULL);"
        "CREATE INDEX IF NOT EXISTS idx_public_transfer_version_room "
        "ON public_transfer_diagram_version(room_id);"
        "CREATE INDEX IF NOT EXISTS idx_public_transfer_version_created "
        "ON public_transfer_diagram_version(created_at);";
    char *error = NULL;
    int rc = sqlite3_exec(*db, schema, NULL, NULL, &error);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "public room sqlite error: %s\n", error == NULL ? sqlite3_errmsg(*db) : error);
        sqlite3_free(error);
        sqlite3_close(*db);
        *db = NULL;
        return -1;
    }
    return 0;
}

static int room_random(uint8_t *out, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t offset = 0U;
    while (offset < len) {
        ssize_t received = read(fd, out + offset, len - offset);
        if (received < 0 && errno == EINTR) continue;
        if (received <= 0) {
            close(fd);
            return -1;
        }
        offset += (size_t)received;
    }
    close(fd);
    return 0;
}

static int room_base64url(const uint8_t *data, size_t len, char *out, size_t out_len)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t needed = (len / 3U) * 4U + (len % 3U == 0U ? 0U : len % 3U + 1U);
    if (needed + 1U > out_len) return -1;
    size_t read_offset = 0U;
    size_t write_offset = 0U;
    while (read_offset < len) {
        size_t remaining = len - read_offset;
        uint32_t value = (uint32_t)data[read_offset++] << 16U;
        if (remaining > 1U) value |= (uint32_t)data[read_offset++] << 8U;
        if (remaining > 2U) value |= data[read_offset++];
        out[write_offset++] = alphabet[(value >> 18U) & 63U];
        out[write_offset++] = alphabet[(value >> 12U) & 63U];
        if (remaining > 1U) out[write_offset++] = alphabet[(value >> 6U) & 63U];
        if (remaining > 2U) out[write_offset++] = alphabet[value & 63U];
    }
    out[write_offset] = '\0';
    return 0;
}

static int room_base64_value(unsigned char value)
{
    if (value >= 'A' && value <= 'Z') return value - 'A';
    if (value >= 'a' && value <= 'z') return value - 'a' + 26;
    if (value >= '0' && value <= '9') return value - '0' + 52;
    if (value == '+') return 62;
    if (value == '/') return 63;
    return -1;
}

static int room_base64_decode(const char *encoded, uint8_t **out, size_t *out_len)
{
    if (encoded == NULL || out == NULL || out_len == NULL) return -1;
    size_t len = strlen(encoded);
    if (len == 0U || len % 4U != 0U || len > 4U * 1024U * 1024U + 16U) return -1;
    size_t padding = encoded[len - 1U] == '=' ? 1U : 0U;
    if (len >= 2U && encoded[len - 2U] == '=') padding = 2U;
    size_t decoded_len = len / 4U * 3U - padding;
    if (decoded_len == 0U || decoded_len > ST_ROOM_MAX_SNAPSHOT) return -1;
    uint8_t *decoded = (uint8_t *)malloc(decoded_len);
    if (decoded == NULL) return -1;
    size_t written = 0U;
    for (size_t offset = 0U; offset < len; offset += 4U) {
        int a = room_base64_value((unsigned char)encoded[offset]);
        int b = room_base64_value((unsigned char)encoded[offset + 1U]);
        int c = encoded[offset + 2U] == '=' ? -2
            : room_base64_value((unsigned char)encoded[offset + 2U]);
        int d = encoded[offset + 3U] == '=' ? -2
            : room_base64_value((unsigned char)encoded[offset + 3U]);
        int last = offset + 4U == len;
        if (a < 0 || b < 0 || c == -1 || d == -1
            || (!last && (c < 0 || d < 0))
            || (c == -2 && d != -2)
            || (!last && (c == -2 || d == -2))) {
            free(decoded);
            return -1;
        }
        uint32_t value = (uint32_t)a << 18U | (uint32_t)b << 12U;
        if (c >= 0) value |= (uint32_t)c << 6U;
        if (d >= 0) value |= (uint32_t)d;
        if (written < decoded_len) decoded[written++] = (uint8_t)(value >> 16U);
        if (written < decoded_len) decoded[written++] = (uint8_t)(value >> 8U);
        if (written < decoded_len) decoded[written++] = (uint8_t)value;
    }
    if (written != decoded_len) {
        free(decoded);
        return -1;
    }
    *out = decoded;
    *out_len = decoded_len;
    return 0;
}

static char *room_base64_encode(const uint8_t *data, size_t len)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if (data == NULL || len > ST_ROOM_MAX_SNAPSHOT) return NULL;
    size_t encoded_len = ((len + 2U) / 3U) * 4U;
    char *encoded = (char *)malloc(encoded_len + 1U);
    if (encoded == NULL) return NULL;
    size_t source = 0U;
    size_t written = 0U;
    while (source < len) {
        size_t remaining = len - source;
        uint32_t value = (uint32_t)data[source++] << 16U;
        if (remaining > 1U) value |= (uint32_t)data[source++] << 8U;
        if (remaining > 2U) value |= data[source++];
        encoded[written++] = alphabet[(value >> 18U) & 63U];
        encoded[written++] = alphabet[(value >> 12U) & 63U];
        encoded[written++] = remaining > 1U ? alphabet[(value >> 6U) & 63U] : '=';
        encoded[written++] = remaining > 2U ? alphabet[value & 63U] : '=';
    }
    encoded[written] = '\0';
    return encoded;
}

static void room_sha256_hex(const char *value, char out[65])
{
    uint8_t digest[ST_SHA256_LEN];
    st_sha256((const uint8_t *)value, strlen(value), digest);
    st_hex_encode(digest, sizeof(digest), out);
}

static int room_iso_time(time_t value, char out[40])
{
    struct tm utc;
    if (gmtime_r(&value, &utc) == NULL) return -1;
    return strftime(out, 40U, "%Y-%m-%dT%H:%M:%SZ", &utc) == 0U ? -1 : 0;
}

static int room_utf8_units(const unsigned char *text, size_t *units)
{
    size_t total = 0U;
    size_t offset = 0U;
    size_t len = strlen((const char *)text);
    while (offset < len) {
        unsigned char first = text[offset++];
        uint32_t codepoint;
        size_t continuation;
        if (first <= 0x7fU) {
            codepoint = first;
            continuation = 0U;
        } else if (first >= 0xc2U && first <= 0xdfU) {
            codepoint = first & 0x1fU;
            continuation = 1U;
        } else if (first >= 0xe0U && first <= 0xefU) {
            codepoint = first & 0x0fU;
            continuation = 2U;
        } else if (first >= 0xf0U && first <= 0xf4U) {
            codepoint = first & 0x07U;
            continuation = 3U;
        } else return -1;
        if (continuation > len - offset) return -1;
        for (size_t i = 0U; i < continuation; ++i) {
            unsigned char next = text[offset++];
            if ((next & 0xc0U) != 0x80U) return -1;
            codepoint = (codepoint << 6U) | (next & 0x3fU);
        }
        if ((continuation == 1U && codepoint < 0x80U)
            || (continuation == 2U && codepoint < 0x800U)
            || (continuation == 3U && codepoint < 0x10000U)
            || (codepoint >= 0xd800U && codepoint <= 0xdfffU)
            || codepoint > 0x10ffffU) return -1;
        total += codepoint > 0xffffU ? 2U : 1U;
    }
    *units = total;
    return 0;
}

static int room_normalize(char *value,
                          const char *fallback,
                          size_t max_units,
                          int required,
                          char *out,
                          size_t out_len)
{
    const char *start = value == NULL ? "" : value;
    while (*start != '\0' && isspace((unsigned char)*start)) ++start;
    size_t len = strlen(start);
    while (len > 0U && isspace((unsigned char)start[len - 1U])) --len;
    if (len == 0U && fallback != NULL) {
        start = fallback;
        len = strlen(fallback);
    }
    if ((required && len == 0U) || len + 1U > out_len) return -1;
    memcpy(out, start, len);
    out[len] = '\0';
    if (strchr(out, '\r') != NULL || strchr(out, '\n') != NULL) return -1;
    size_t units = 0U;
    return room_utf8_units((const unsigned char *)out, &units) == 0 && units <= max_units ? 0 : -1;
}

static int room_bind_text(sqlite3_stmt *stmt, int index, const char *value)
{
    return sqlite3_bind_text(stmt, index, value, -1, SQLITE_TRANSIENT) == SQLITE_OK ? 0 : -1;
}

static int room_prepare(sqlite3 *db, sqlite3_stmt **stmt, const char *sql)
{
    return sqlite3_prepare_v2(db, sql, -1, stmt, NULL) == SQLITE_OK ? 0 : -1;
}

static int room_resolve_db(sqlite3 *db,
                           const char *room_name,
                           const char *room_token,
                           const char *peer_id,
                           long long *room_id,
                           char role[16])
{
    char token_hash[65];
    room_sha256_hex(room_token, token_hash);
    sqlite3_stmt *stmt = NULL;
    if (room_prepare(db, &stmt,
            "SELECT id FROM public_transfer_room WHERE room_name=? AND owner_token_hash=?") != 0
        || room_bind_text(stmt, 1, room_name) != 0
        || room_bind_text(stmt, 2, token_hash) != 0) {
        sqlite3_finalize(stmt);
        return -1;
    }
    int step = sqlite3_step(stmt);
    if (step == SQLITE_ROW) {
        *room_id = sqlite3_column_int64(stmt, 0);
        strcpy(role, "OWNER");
        sqlite3_finalize(stmt);
        return 0;
    }
    sqlite3_finalize(stmt);
    if (step != SQLITE_DONE) return -1;

    if (room_prepare(db, &stmt,
            "SELECT a.room_id,a.role,r.room_name,a.revoked_at,a.expires_at "
            "FROM public_transfer_room_access a JOIN public_transfer_room r ON r.id=a.room_id "
            "WHERE a.token_hash=?") != 0
        || room_bind_text(stmt, 1, token_hash) != 0) {
        sqlite3_finalize(stmt);
        return -1;
    }
    step = sqlite3_step(stmt);
    if (step == SQLITE_ROW) {
        const char *stored_role = (const char *)sqlite3_column_text(stmt, 1);
        const char *stored_room = (const char *)sqlite3_column_text(stmt, 2);
        int revoked = sqlite3_column_type(stmt, 3) != SQLITE_NULL;
        int expired = 0;
        if (sqlite3_column_type(stmt, 4) != SQLITE_NULL) {
            const char *expires = (const char *)sqlite3_column_text(stmt, 4);
            sqlite3_stmt *expiry = NULL;
            if (room_prepare(db, &expiry,
                    "SELECT COALESCE(julianday(?) <= julianday('now'),1)") != 0
                || room_bind_text(expiry, 1, expires) != 0
                || sqlite3_step(expiry) != SQLITE_ROW) {
                sqlite3_finalize(expiry);
                sqlite3_finalize(stmt);
                return -1;
            }
            expired = sqlite3_column_int(expiry, 0) != 0;
            sqlite3_finalize(expiry);
        }
        int valid = !revoked && !expired && stored_room != NULL && strcmp(stored_room, room_name) == 0
            && stored_role != NULL
            && (strcmp(stored_role, "EDITOR") == 0 || strcmp(stored_role, "VIEWER") == 0);
        if (valid) {
            *room_id = sqlite3_column_int64(stmt, 0);
            snprintf(role, 16U, "%s", stored_role);
        }
        sqlite3_finalize(stmt);
        return valid ? 0 : 2;
    }
    sqlite3_finalize(stmt);
    if (step != SQLITE_DONE) return -1;
    if (strncasecmp(room_token, "st-editor-", 10U) == 0
        || strncasecmp(room_token, "st-viewer-", 10U) == 0) return 2;

    char now[40];
    if (room_iso_time(time(NULL), now) != 0
        || room_prepare(db, &stmt,
            "INSERT OR IGNORE INTO public_transfer_room "
            "(room_name,owner_token_hash,created_by_peer_id,created_at,updated_at) VALUES(?,?,?,?,?)") != 0
        || room_bind_text(stmt, 1, room_name) != 0
        || room_bind_text(stmt, 2, token_hash) != 0
        || room_bind_text(stmt, 3, peer_id) != 0
        || room_bind_text(stmt, 4, now) != 0
        || room_bind_text(stmt, 5, now) != 0
        || sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return -1;
    }
    sqlite3_finalize(stmt);
    if (room_prepare(db, &stmt,
            "SELECT id FROM public_transfer_room WHERE room_name=? AND owner_token_hash=?") != 0
        || room_bind_text(stmt, 1, room_name) != 0
        || room_bind_text(stmt, 2, token_hash) != 0
        || sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }
    *room_id = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    strcpy(role, "OWNER");
    return 0;
}

int st_public_room_resolve(const char *room_name,
                           const char *room_token,
                           const char *peer_id,
                           st_public_room_access *out)
{
    if (room_name == NULL || *room_name == '\0' || room_token == NULL || *room_token == '\0'
        || peer_id == NULL || out == NULL) return 2;
    sqlite3 *db = NULL;
    int opened = room_open(&db);
    if (opened != 0) return opened == 1 ? 1 : -1;
    long long room_id = 0;
    int rc = room_resolve_db(db, room_name, room_token, peer_id, &room_id, out->role);
    sqlite3_close(db);
    if (rc == 0) {
        int written = snprintf(out->room_key, sizeof(out->room_key), "room:%lld", room_id);
        if (written < 0 || (size_t)written >= sizeof(out->room_key)) return -1;
    }
    return rc;
}

static int room_extract_credential(const char *body,
                                   char room_name[481],
                                   char room_token[2049],
                                   char peer_id[481])
{
    if (body == NULL || strlen(body) > ST_ROOM_MAX_BODY || strstr(body, "\\u0000") != NULL
        || !st_json_is_valid_object(body)) return -1;
    char *raw_room = st_json_get_top_level_string(body, "roomId");
    char *raw_token = st_json_get_top_level_string(body, "roomToken");
    char *raw_peer = st_json_get_top_level_string(body, "peerId");
    int rc = room_normalize(raw_room, NULL, 120U, 1, room_name, 481U) == 0
        && room_normalize(raw_token, NULL, 512U, 1, room_token, 2049U) == 0
        && room_normalize(raw_peer, "web", 120U, 0, peer_id, 481U) == 0 ? 0 : -1;
    free(raw_room);
    free(raw_token);
    free(raw_peer);
    return rc;
}

static int room_require_owner(sqlite3 *db,
                              const char *room_name,
                              const char *room_token,
                              const char *peer_id,
                              long long *room_id)
{
    char role[16];
    int rc = room_resolve_db(db, room_name, room_token, peer_id, room_id, role);
    if (rc != 0) return rc;
    return strcmp(role, "OWNER") == 0 ? 0 : 2;
}

static int room_access_view(sqlite3_stmt *stmt, char *out, size_t out_len)
{
    long long id = sqlite3_column_int64(stmt, 0);
    const char *role = (const char *)sqlite3_column_text(stmt, 1);
    const char *label = (const char *)sqlite3_column_text(stmt, 2);
    const char *created = (const char *)sqlite3_column_text(stmt, 3);
    const char *expires = sqlite3_column_type(stmt, 4) == SQLITE_NULL
        ? NULL : (const char *)sqlite3_column_text(stmt, 4);
    const char *revoked = sqlite3_column_type(stmt, 5) == SQLITE_NULL
        ? NULL : (const char *)sqlite3_column_text(stmt, 5);
    char *escaped_label = st_json_escape(label == NULL ? "" : label);
    if (escaped_label == NULL) return -1;
    int written = snprintf(out,
                           out_len,
                           "{\"id\":%lld,\"role\":\"%s\",\"label\":\"%s\","
                           "\"createdAt\":\"%s\",\"expiresAt\":%s%s%s,\"revokedAt\":%s%s%s}",
                           id,
                           role == NULL ? "VIEWER" : role,
                           escaped_label,
                           created == NULL ? "" : created,
                           expires == NULL ? "" : "\"",
                           expires == NULL ? "null" : expires,
                           expires == NULL ? "" : "\"",
                           revoked == NULL ? "" : "\"",
                           revoked == NULL ? "null" : revoked,
                           revoked == NULL ? "" : "\"");
    free(escaped_label);
    return written < 0 || (size_t)written >= out_len ? -1 : written;
}

static int room_list_access(const char *body, char *out, size_t out_len)
{
    char room_name[481], token[2049], peer[481];
    if (room_extract_credential(body, room_name, token, peer) != 0)
        return room_error(out, out_len, 400, "请求体无效");
    sqlite3 *db = NULL;
    int opened = room_open(&db);
    if (opened != 0) return room_error(out, out_len, opened == 1 ? 503 : 500, "房间存储不可用");
    long long room_id = 0;
    int authorized = room_require_owner(db, room_name, token, peer, &room_id);
    if (authorized != 0) {
        sqlite3_close(db);
        return room_error(out, out_len, authorized == 2 ? 403 : 500,
                          authorized == 2 ? "需要房主权限" : "服务器内部错误");
    }
    sqlite3_stmt *stmt = NULL;
    if (room_prepare(db, &stmt,
            "SELECT id,role,label,created_at,expires_at,revoked_at "
            "FROM public_transfer_room_access WHERE room_id=? ORDER BY created_at DESC,id DESC") != 0
        || sqlite3_bind_int64(stmt, 1, room_id) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return room_error(out, out_len, 500, "服务器内部错误");
    }
    char response[32768];
    size_t used = 0U;
    response[used++] = '[';
    int step;
    int first = 1;
    while ((step = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (!first) response[used++] = ',';
        int written = room_access_view(stmt, response + used, sizeof(response) - used);
        if (written < 0) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return room_error(out, out_len, 500, "响应过大");
        }
        used += (size_t)written;
        first = 0;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    if (step != SQLITE_DONE || used + 2U > sizeof(response))
        return room_error(out, out_len, 500, "服务器内部错误");
    response[used++] = ']';
    response[used] = '\0';
    return room_write_response(out, out_len, 200, "OK", response);
}

static int room_parse_invite_role(const char *body, char role[16])
{
    char *raw = st_json_get_top_level_string(body, "role");
    char normalized[32];
    int rc = room_normalize(raw, NULL, 16U, 1, normalized, sizeof(normalized));
    free(raw);
    if (rc != 0) return -1;
    if (strcasecmp(normalized, "EDITOR") == 0) strcpy(role, "EDITOR");
    else if (strcasecmp(normalized, "VIEWER") == 0) strcpy(role, "VIEWER");
    else return -1;
    return 0;
}

static int room_optional_integer(const char *body,
                                 const char *name,
                                 long long fallback,
                                 long long *out,
                                 int *present)
{
    char *raw = st_json_get_top_level_raw(body, name);
    if (raw == NULL || strcmp(raw, "null") == 0) {
        free(raw);
        *out = fallback;
        if (present != NULL) *present = 0;
        return 0;
    }
    char *end = NULL;
    errno = 0;
    long long parsed = strtoll(raw, &end, 10);
    int valid = errno == 0 && end != raw && *end == '\0';
    free(raw);
    if (!valid) return -1;
    *out = parsed;
    if (present != NULL) *present = 1;
    return 0;
}

static int room_active_access_count(sqlite3 *db, long long room_id, int *count)
{
    sqlite3_stmt *stmt = NULL;
    if (room_prepare(db, &stmt,
            "SELECT COUNT(*) FROM public_transfer_room_access WHERE room_id=? AND revoked_at IS NULL "
            "AND (expires_at IS NULL OR julianday(expires_at)>julianday('now'))") != 0
        || sqlite3_bind_int64(stmt, 1, room_id) != SQLITE_OK
        || sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }
    *count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return 0;
}

static int room_new_access_token(const char *role, char token[64], char hash[65])
{
    uint8_t random[32];
    char encoded[48];
    if (room_random(random, sizeof(random)) != 0
        || room_base64url(random, sizeof(random), encoded, sizeof(encoded)) != 0) return -1;
    int written = snprintf(token, 64U, "st-%s-%s",
                           strcmp(role, "EDITOR") == 0 ? "editor" : "viewer", encoded);
    if (written < 0 || written >= 64) return -1;
    room_sha256_hex(token, hash);
    return 0;
}

static int room_create_access(const char *body, char *out, size_t out_len)
{
    char room_name[481], owner_token[2049], peer[481], role[16];
    if (room_extract_credential(body, room_name, owner_token, peer) != 0
        || room_parse_invite_role(body, role) != 0)
        return room_error(out, out_len, 400, "邀请角色必须是 EDITOR 或 VIEWER");
    char *raw_label = st_json_get_top_level_string(body, "label");
    char label[321];
    int label_rc = room_normalize(raw_label,
                                  strcmp(role, "EDITOR") == 0 ? "编辑者邀请" : "访客邀请",
                                  80U,
                                  0,
                                  label,
                                  sizeof(label));
    free(raw_label);
    long long ttl = 0;
    int has_ttl = 0;
    if (label_rc != 0 || room_optional_integer(body, "expiresInSeconds", 0, &ttl, &has_ttl) != 0
        || (has_ttl && (ttl < 300 || ttl > 604800)))
        return room_error(out, out_len, 400, "邀请有效期必须在 300 到 604800 秒之间");
    sqlite3 *db = NULL;
    int opened = room_open(&db);
    if (opened != 0) return room_error(out, out_len, opened == 1 ? 503 : 500, "房间存储不可用");
    long long room_id = 0;
    int authorized = room_require_owner(db, room_name, owner_token, peer, &room_id);
    if (authorized != 0) {
        sqlite3_close(db);
        return room_error(out, out_len, authorized == 2 ? 403 : 500,
                          authorized == 2 ? "需要房主权限" : "服务器内部错误");
    }
    char *transaction_error = NULL;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &transaction_error) != SQLITE_OK) {
        sqlite3_free(transaction_error);
        sqlite3_close(db);
        return room_error(out, out_len, 500, "服务器内部错误");
    }
    int active = 0;
    if (room_active_access_count(db, room_id, &active) != 0) {
        (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        sqlite3_close(db);
        return room_error(out, out_len, 500, "服务器内部错误");
    }
    if (active >= ST_ROOM_MAX_ACCESS) {
        (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        sqlite3_close(db);
        return room_error(out, out_len, 409, "房间有效邀请 Token 已达到 20 个上限");
    }
    char now[40], expires[40];
    if (room_iso_time(time(NULL), now) != 0 || (has_ttl && room_iso_time(time(NULL) + ttl, expires) != 0)) {
        (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        sqlite3_close(db);
        return room_error(out, out_len, 500, "服务器内部错误");
    }
    char plain_token[64], token_hash[65];
    sqlite3_stmt *stmt = NULL;
    int inserted = 0;
    for (int attempt = 0; attempt < 4 && !inserted; ++attempt) {
        if (room_new_access_token(role, plain_token, token_hash) != 0
            || room_prepare(db, &stmt,
                "INSERT INTO public_transfer_room_access "
                "(room_id,token_hash,role,label,created_at,expires_at,revoked_at) VALUES(?,?,?,?,?,?,NULL)") != 0
            || sqlite3_bind_int64(stmt, 1, room_id) != SQLITE_OK
            || room_bind_text(stmt, 2, token_hash) != 0
            || room_bind_text(stmt, 3, role) != 0
            || room_bind_text(stmt, 4, label) != 0
            || room_bind_text(stmt, 5, now) != 0
            || (has_ttl ? room_bind_text(stmt, 6, expires) : sqlite3_bind_null(stmt, 6)) != SQLITE_OK) {
            sqlite3_finalize(stmt);
            (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
            sqlite3_close(db);
            return room_error(out, out_len, 500, "服务器内部错误");
        }
        inserted = sqlite3_step(stmt) == SQLITE_DONE;
        sqlite3_finalize(stmt);
        stmt = NULL;
    }
    if (!inserted) {
        (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        sqlite3_close(db);
        return room_error(out, out_len, 409, "无法生成邀请 Token");
    }
    long long access_id = sqlite3_last_insert_rowid(db);
    if (sqlite3_exec(db, "COMMIT", NULL, NULL, &transaction_error) != SQLITE_OK) {
        sqlite3_free(transaction_error);
        (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        sqlite3_close(db);
        return room_error(out, out_len, 500, "服务器内部错误");
    }
    sqlite3_close(db);
    char *escaped_label = st_json_escape(label);
    if (escaped_label == NULL) return room_error(out, out_len, 500, "服务器内部错误");
    char response[1024];
    int written = snprintf(response, sizeof(response),
        "{\"access\":{\"id\":%lld,\"role\":\"%s\",\"label\":\"%s\","
        "\"createdAt\":\"%s\",\"expiresAt\":%s%s%s,\"revokedAt\":null},\"token\":\"%s\"}",
        access_id, role, escaped_label, now,
        has_ttl ? "\"" : "", has_ttl ? expires : "null", has_ttl ? "\"" : "", plain_token);
    free(escaped_label);
    if (written < 0 || (size_t)written >= sizeof(response))
        return room_error(out, out_len, 500, "响应过大");
    return room_write_response(out, out_len, 200, "OK", response);
}

static int room_revoke_access(const char *path, const char *body, char *out, size_t out_len)
{
    static const char prefix[] = "/api/public/transfer/rooms/access-tokens/";
    static const char suffix[] = "/revoke";
    const char *id_start = path + sizeof(prefix) - 1U;
    char *id_end = NULL;
    errno = 0;
    long long access_id = strtoll(id_start, &id_end, 10);
    if (errno != 0 || id_end == id_start || access_id <= 0 || strcmp(id_end, suffix) != 0)
        return room_error(out, out_len, 400, "accessId 无效");
    char room_name[481], owner_token[2049], peer[481];
    if (room_extract_credential(body, room_name, owner_token, peer) != 0)
        return room_error(out, out_len, 400, "请求体无效");
    sqlite3 *db = NULL;
    int opened = room_open(&db);
    if (opened != 0) return room_error(out, out_len, opened == 1 ? 503 : 500, "房间存储不可用");
    long long room_id = 0;
    int authorized = room_require_owner(db, room_name, owner_token, peer, &room_id);
    if (authorized != 0) {
        sqlite3_close(db);
        return room_error(out, out_len, authorized == 2 ? 403 : 500,
                          authorized == 2 ? "需要房主权限" : "服务器内部错误");
    }
    char now[40];
    sqlite3_stmt *stmt = NULL;
    if (room_iso_time(time(NULL), now) != 0
        || room_prepare(db, &stmt,
            "UPDATE public_transfer_room_access SET revoked_at=COALESCE(revoked_at,?) WHERE id=? AND room_id=?") != 0
        || room_bind_text(stmt, 1, now) != 0
        || sqlite3_bind_int64(stmt, 2, access_id) != SQLITE_OK
        || sqlite3_bind_int64(stmt, 3, room_id) != SQLITE_OK
        || sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return room_error(out, out_len, 500, "服务器内部错误");
    }
    int changed = sqlite3_changes(db);
    sqlite3_finalize(stmt);
    if (!changed || room_prepare(db, &stmt,
            "SELECT id,role,label,created_at,expires_at,revoked_at "
            "FROM public_transfer_room_access WHERE id=? AND room_id=?") != 0
        || sqlite3_bind_int64(stmt, 1, access_id) != SQLITE_OK
        || sqlite3_bind_int64(stmt, 2, room_id) != SQLITE_OK
        || sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return room_error(out, out_len, changed ? 500 : 404,
                          changed ? "服务器内部错误" : "邀请 Token 不存在");
    }
    char response[1024];
    int written = room_access_view(stmt, response, sizeof(response));
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    if (written < 0) return room_error(out, out_len, 500, "响应过大");
    return room_write_response(out, out_len, 200, "OK", response);
}

static long room_env_long(const char *name, long fallback)
{
    const char *value = getenv(name);
    if (value == NULL || *value == '\0') return fallback;
    char *end = NULL;
    long parsed = strtol(value, &end, 10);
    return end != value && *end == '\0' && parsed > 0 ? parsed : fallback;
}

static int room_pairing_rate_allowed(const char *remote_address)
{
    const char *address = remote_address == NULL || *remote_address == '\0' ? "unknown" : remote_address;
    long limit = room_env_long("SPECUS_PUBLIC_TRANSFER_PAIRING_CODE_REDEEM_RATE_LIMIT_PER_IP", 10);
    long window = room_env_long("SPECUS_PUBLIC_TRANSFER_PAIRING_CODE_REDEEM_RATE_LIMIT_WINDOW_SECONDS", 300);
    time_t now = time(NULL);
    pthread_mutex_lock(&room_rate_lock);
    size_t count = 0U;
    st_room_rate_window **cursor = &room_rate_windows;
    st_room_rate_window *match = NULL;
    while (*cursor != NULL) {
        st_room_rate_window *item = *cursor;
        if (now - item->started_at >= window) {
            *cursor = item->next;
            free(item);
            continue;
        }
        if (strcmp(item->address, address) == 0) match = item;
        ++count;
        cursor = &item->next;
    }
    if (match == NULL) {
        if (count >= ST_ROOM_RATE_SOURCES) {
            pthread_mutex_unlock(&room_rate_lock);
            return 0;
        }
        match = (st_room_rate_window *)calloc(1, sizeof(*match));
        if (match == NULL) {
            pthread_mutex_unlock(&room_rate_lock);
            return 0;
        }
        snprintf(match->address, sizeof(match->address), "%s", address);
        match->started_at = now;
        match->next = room_rate_windows;
        room_rate_windows = match;
    }
    ++match->count;
    int allowed = match->count <= (unsigned long)limit;
    pthread_mutex_unlock(&room_rate_lock);
    return allowed;
}

static int room_new_pairing_code(sqlite3 *db, char code[9], char hash[65])
{
    for (int attempt = 0; attempt < 16; ++attempt) {
        uint32_t random;
        do {
            if (room_random((uint8_t *)&random, sizeof(random)) != 0) return -1;
        } while (random >= UINT32_MAX - (UINT32_MAX % 100000000U));
        snprintf(code, 9U, "%08u", random % 100000000U);
        if (st_security_pairing_code_hash(code, hash) != 0) return -1;
        sqlite3_stmt *stmt = NULL;
        if (room_prepare(db, &stmt,
                "SELECT COUNT(*) FROM public_transfer_room_pairing_code WHERE code_hash=?") != 0
            || room_bind_text(stmt, 1, hash) != 0
            || sqlite3_step(stmt) != SQLITE_ROW) {
            sqlite3_finalize(stmt);
            return -1;
        }
        int exists = sqlite3_column_int(stmt, 0) != 0;
        sqlite3_finalize(stmt);
        if (!exists) return 0;
    }
    return 1;
}

static int room_create_pairing(const char *body, char *out, size_t out_len)
{
    char room_name[481], owner_token[2049], peer[481], role[16];
    if (room_extract_credential(body, room_name, owner_token, peer) != 0
        || room_parse_invite_role(body, role) != 0)
        return room_error(out, out_len, 400, "邀请角色必须是 EDITOR 或 VIEWER");
    long long max_uses = 1;
    if (room_optional_integer(body, "maxUses", 1, &max_uses, NULL) != 0
        || max_uses < 1 || max_uses > 5)
        return room_error(out, out_len, 400, "配对码可用次数必须在 1 到 5 之间");
    char *raw_label = st_json_get_top_level_string(body, "label");
    char label[321];
    int label_rc = room_normalize(raw_label,
                                  strcmp(role, "EDITOR") == 0 ? "编辑者配对" : "访客配对",
                                  80U,
                                  0,
                                  label,
                                  sizeof(label));
    free(raw_label);
    if (label_rc != 0) return room_error(out, out_len, 400, "字段长度不能超过 80");
    sqlite3 *db = NULL;
    int opened = room_open(&db);
    if (opened != 0) return room_error(out, out_len, opened == 1 ? 503 : 500, "房间存储不可用");
    long long room_id = 0;
    int authorized = room_require_owner(db, room_name, owner_token, peer, &room_id);
    if (authorized != 0) {
        sqlite3_close(db);
        return room_error(out, out_len, authorized == 2 ? 403 : 500,
                          authorized == 2 ? "需要房主权限" : "服务器内部错误");
    }
    char code[9], code_hash[65];
    int generated = room_new_pairing_code(db, code, code_hash);
    long ttl = room_env_long("SPECUS_PUBLIC_TRANSFER_PAIRING_CODE_TTL_SECONDS", 300);
    if (ttl < 60) ttl = 60;
    if (ttl > 900) ttl = 900;
    char now[40], expires[40];
    sqlite3_stmt *stmt = NULL;
    if (generated != 0 || room_iso_time(time(NULL), now) != 0
        || room_iso_time(time(NULL) + ttl, expires) != 0
        || room_prepare(db, &stmt,
            "INSERT INTO public_transfer_room_pairing_code "
            "(room_id,code_hash,role,label,created_at,expires_at,max_uses,used_count,revoked_at) "
            "VALUES(?,?,?,?,?,?,?,0,NULL)") != 0
        || sqlite3_bind_int64(stmt, 1, room_id) != SQLITE_OK
        || room_bind_text(stmt, 2, code_hash) != 0
        || room_bind_text(stmt, 3, role) != 0
        || room_bind_text(stmt, 4, label) != 0
        || room_bind_text(stmt, 5, now) != 0
        || room_bind_text(stmt, 6, expires) != 0
        || sqlite3_bind_int64(stmt, 7, max_uses) != SQLITE_OK
        || sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return room_error(out, out_len, generated == 1 ? 409 : 500,
                          generated == 1 ? "无法生成唯一配对码" : "服务器内部错误");
    }
    sqlite3_finalize(stmt);
    long long id = sqlite3_last_insert_rowid(db);
    sqlite3_close(db);
    char *escaped_label = st_json_escape(label);
    if (escaped_label == NULL) return room_error(out, out_len, 500, "服务器内部错误");
    char response[1024];
    int written = snprintf(response, sizeof(response),
        "{\"id\":%lld,\"code\":\"%s\",\"role\":\"%s\",\"label\":\"%s\","
        "\"createdAt\":\"%s\",\"expiresAt\":\"%s\",\"maxUses\":%lld,\"usedCount\":0}",
        id, code, role, escaped_label, now, expires, max_uses);
    free(escaped_label);
    if (written < 0 || (size_t)written >= sizeof(response))
        return room_error(out, out_len, 500, "响应过大");
    return room_write_response(out, out_len, 200, "OK", response);
}

static int room_redeem_pairing(const char *body,
                               const char *remote_address,
                               char *out,
                               size_t out_len)
{
    if (!room_pairing_rate_allowed(remote_address))
        return room_error(out, out_len, 429, "请求过于频繁,请稍后再试");
    if (body == NULL || strlen(body) > ST_ROOM_MAX_BODY || strstr(body, "\\u0000") != NULL
        || !st_json_is_valid_object(body))
        return room_error(out, out_len, 400, "请求体无效");
    char *raw_code = st_json_get_top_level_string(body, "code");
    char *raw_peer = st_json_get_top_level_string(body, "peerId");
    char code[16], peer[481];
    int valid = room_normalize(raw_code, NULL, 8U, 1, code, sizeof(code)) == 0
        && strlen(code) == 8U
        && strspn(code, "0123456789") == 8U
        && room_normalize(raw_peer, "web", 120U, 0, peer, sizeof(peer)) == 0;
    free(raw_code);
    free(raw_peer);
    if (!valid) return room_error(out, out_len, 400, "配对码无效或已过期");
    char code_hash[65];
    if (st_security_pairing_code_hash(code, code_hash) != 0)
        return room_error(out, out_len, 500, "服务器内部错误");
    sqlite3 *db = NULL;
    int opened = room_open(&db);
    if (opened != 0) return room_error(out, out_len, opened == 1 ? 503 : 500, "房间存储不可用");
    char *error = NULL;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &error) != SQLITE_OK) {
        sqlite3_free(error);
        sqlite3_close(db);
        return room_error(out, out_len, 500, "服务器内部错误");
    }
    int status = 500;
    const char *message = "服务器内部错误";
    sqlite3_stmt *stmt = NULL;
    long long room_id = 0;
    char role[16] = "";
    char label[321] = "";
    char room_name[481] = "";
    if (room_prepare(db, &stmt,
            "SELECT c.room_id,c.role,c.label,r.room_name FROM public_transfer_room_pairing_code c "
            "JOIN public_transfer_room r ON r.id=c.room_id WHERE c.code_hash=? AND c.revoked_at IS NULL "
            "AND julianday(c.expires_at)>julianday('now') AND c.used_count<c.max_uses") != 0
        || room_bind_text(stmt, 1, code_hash) != 0) goto rollback;
    int step = sqlite3_step(stmt);
    if (step != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        stmt = NULL;
        status = step == SQLITE_DONE ? 400 : 500;
        message = step == SQLITE_DONE ? "配对码无效或已过期" : "服务器内部错误";
        goto rollback;
    }
    room_id = sqlite3_column_int64(stmt, 0);
    snprintf(role, sizeof(role), "%s", (const char *)sqlite3_column_text(stmt, 1));
    snprintf(label, sizeof(label), "%s", (const char *)sqlite3_column_text(stmt, 2));
    snprintf(room_name, sizeof(room_name), "%s", (const char *)sqlite3_column_text(stmt, 3));
    sqlite3_finalize(stmt);
    stmt = NULL;
    if ((strcmp(role, "EDITOR") != 0 && strcmp(role, "VIEWER") != 0)) {
        status = 400;
        message = "配对码无效或已过期";
        goto rollback;
    }
    int active = 0;
    if (room_active_access_count(db, room_id, &active) != 0) goto rollback;
    if (active >= ST_ROOM_MAX_ACCESS) {
        status = 409;
        message = "房间有效邀请 Token 已达到 20 个上限";
        goto rollback;
    }
    if (room_prepare(db, &stmt,
            "UPDATE public_transfer_room_pairing_code SET used_count=used_count+1 WHERE code_hash=? "
            "AND revoked_at IS NULL AND julianday(expires_at)>julianday('now') AND used_count<max_uses") != 0
        || room_bind_text(stmt, 1, code_hash) != 0
        || sqlite3_step(stmt) != SQLITE_DONE
        || sqlite3_changes(db) != 1) {
        sqlite3_finalize(stmt);
        stmt = NULL;
        status = 400;
        message = "配对码无效或已过期";
        goto rollback;
    }
    sqlite3_finalize(stmt);
    stmt = NULL;
    char plain_token[64], token_hash[65], now[40], expires[40];
    if (room_new_access_token(role, plain_token, token_hash) != 0
        || room_iso_time(time(NULL), now) != 0
        || room_iso_time(time(NULL) + 86400, expires) != 0
        || room_prepare(db, &stmt,
            "INSERT INTO public_transfer_room_access "
            "(room_id,token_hash,role,label,created_at,expires_at,revoked_at) VALUES(?,?,?,?,?,?,NULL)") != 0
        || sqlite3_bind_int64(stmt, 1, room_id) != SQLITE_OK
        || room_bind_text(stmt, 2, token_hash) != 0
        || room_bind_text(stmt, 3, role) != 0
        || room_bind_text(stmt, 4, label) != 0
        || room_bind_text(stmt, 5, now) != 0
        || room_bind_text(stmt, 6, expires) != 0
        || sqlite3_step(stmt) != SQLITE_DONE) goto rollback;
    sqlite3_finalize(stmt);
    stmt = NULL;
    if (sqlite3_exec(db, "COMMIT", NULL, NULL, &error) != SQLITE_OK) {
        sqlite3_free(error);
        sqlite3_close(db);
        return room_error(out, out_len, 500, "服务器内部错误");
    }
    sqlite3_close(db);
    char *escaped_room = st_json_escape(room_name);
    if (escaped_room == NULL) return room_error(out, out_len, 500, "服务器内部错误");
    char response[1024];
    int written = snprintf(response, sizeof(response),
        "{\"roomId\":\"%s\",\"role\":\"%s\",\"roomToken\":\"%s\",\"expiresAt\":\"%s\"}",
        escaped_room, role, plain_token, expires);
    free(escaped_room);
    if (written < 0 || (size_t)written >= sizeof(response))
        return room_error(out, out_len, 500, "响应过大");
    return room_write_response(out, out_len, 200, "OK", response);

rollback:
    sqlite3_finalize(stmt);
    (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    sqlite3_close(db);
    return room_error(out, out_len, status, message);
}

static int room_version_view(long long id,
                             const char *name,
                             const char *author_peer_id,
                             long long size_bytes,
                             const char *created_at,
                             char *out,
                             size_t out_len)
{
    char *escaped_name = st_json_escape(name == NULL ? "" : name);
    char *escaped_author = st_json_escape(author_peer_id == NULL ? "" : author_peer_id);
    if (escaped_name == NULL || escaped_author == NULL) {
        free(escaped_name);
        free(escaped_author);
        return -1;
    }
    int written = snprintf(out,
                           out_len,
                           "{\"id\":%lld,\"name\":\"%s\",\"authorPeerId\":\"%s\","
                           "\"sizeBytes\":%lld,\"createdAt\":\"%s\"}",
                           id,
                           escaped_name,
                           escaped_author,
                           size_bytes,
                           created_at == NULL ? "" : created_at);
    free(escaped_name);
    free(escaped_author);
    return written < 0 || (size_t)written >= out_len ? -1 : written;
}

static int room_resolve_request(sqlite3 *db,
                                const char *body,
                                long long *room_id,
                                char role[16],
                                char peer_id[481])
{
    char room_name[481], room_token[2049];
    if (room_extract_credential(body, room_name, room_token, peer_id) != 0) return -2;
    return room_resolve_db(db, room_name, room_token, peer_id, room_id, role);
}

static int room_list_versions(const char *body, char *out, size_t out_len)
{
    sqlite3 *db = NULL;
    int opened = room_open(&db);
    if (opened != 0) return room_error(out, out_len, opened == 1 ? 503 : 500, "房间存储不可用");
    long long room_id = 0;
    char role[16], peer_id[481];
    int resolved = room_resolve_request(db, body, &room_id, role, peer_id);
    if (resolved != 0) {
        sqlite3_close(db);
        return room_error(out,
                          out_len,
                          resolved == -2 ? 400 : resolved == 2 ? 403 : 500,
                          resolved == -2 ? "请求体无效"
                              : resolved == 2 ? "房间凭证无效" : "服务器内部错误");
    }
    sqlite3_stmt *stmt = NULL;
    if (room_prepare(db, &stmt,
            "SELECT id,name,author_peer_id,size_bytes,created_at "
            "FROM public_transfer_diagram_version WHERE room_id=? ORDER BY created_at DESC,id DESC") != 0
        || sqlite3_bind_int64(stmt, 1, room_id) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return room_error(out, out_len, 500, "服务器内部错误");
    }
    size_t cap = 131072U;
    char *response = (char *)malloc(cap);
    if (response == NULL) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return room_error(out, out_len, 500, "服务器内部错误");
    }
    size_t used = 0U;
    response[used++] = '[';
    int step;
    int first = 1;
    while ((step = sqlite3_step(stmt)) == SQLITE_ROW) {
        char view[2048];
        int view_len = room_version_view(sqlite3_column_int64(stmt, 0),
                                         (const char *)sqlite3_column_text(stmt, 1),
                                         (const char *)sqlite3_column_text(stmt, 2),
                                         sqlite3_column_int64(stmt, 3),
                                         (const char *)sqlite3_column_text(stmt, 4),
                                         view,
                                         sizeof(view));
        if (view_len < 0 || used + (size_t)view_len + 2U > cap) {
            free(response);
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return room_error(out, out_len, 500, "响应过大");
        }
        if (!first) response[used++] = ',';
        memcpy(response + used, view, (size_t)view_len);
        used += (size_t)view_len;
        first = 0;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    if (step != SQLITE_DONE) {
        free(response);
        return room_error(out, out_len, 500, "服务器内部错误");
    }
    response[used++] = ']';
    response[used] = '\0';
    int result = room_write_response(out, out_len, 200, "OK", response);
    free(response);
    return result;
}

static int room_create_version(const char *body, char *out, size_t out_len)
{
    sqlite3 *db = NULL;
    int opened = room_open(&db);
    if (opened != 0) return room_error(out, out_len, opened == 1 ? 503 : 500, "房间存储不可用");
    long long room_id = 0;
    char role[16], peer_id[481];
    int resolved = room_resolve_request(db, body, &room_id, role, peer_id);
    if (resolved != 0) {
        sqlite3_close(db);
        return room_error(out,
                          out_len,
                          resolved == -2 ? 400 : resolved == 2 ? 403 : 500,
                          resolved == -2 ? "请求体无效"
                              : resolved == 2 ? "房间凭证无效" : "服务器内部错误");
    }
    if (strcmp(role, "VIEWER") == 0) {
        sqlite3_close(db);
        return room_error(out, out_len, 403, "访客不能创建流程图版本");
    }
    char *raw_name = st_json_get_top_level_string(body, "name");
    char *encoded = st_json_get_top_level_string(body, "update");
    char name[321];
    uint8_t *snapshot = NULL;
    size_t snapshot_len = 0U;
    int valid = room_normalize(raw_name, NULL, 80U, 1, name, sizeof(name)) == 0
        && room_base64_decode(encoded, &snapshot, &snapshot_len) == 0;
    free(raw_name);
    free(encoded);
    if (!valid) {
        free(snapshot);
        sqlite3_close(db);
        return room_error(out, out_len, 400, "流程图版本数据无效或超过 3 MB");
    }
    char now[40];
    sqlite3_stmt *stmt = NULL;
    char *transaction_error = NULL;
    if (room_iso_time(time(NULL), now) != 0
        || sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &transaction_error) != SQLITE_OK
        || room_prepare(db, &stmt,
            "INSERT INTO public_transfer_diagram_version "
            "(room_id,name,author_peer_id,snapshot_data,size_bytes,created_at) VALUES(?,?,?,?,?,?)") != 0
        || sqlite3_bind_int64(stmt, 1, room_id) != SQLITE_OK
        || room_bind_text(stmt, 2, name) != 0
        || room_bind_text(stmt, 3, peer_id) != 0
        || sqlite3_bind_blob(stmt, 4, snapshot, (int)snapshot_len, SQLITE_TRANSIENT) != SQLITE_OK
        || sqlite3_bind_int64(stmt, 5, (sqlite3_int64)snapshot_len) != SQLITE_OK
        || room_bind_text(stmt, 6, now) != 0
        || sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_free(transaction_error);
        sqlite3_finalize(stmt);
        (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        free(snapshot);
        sqlite3_close(db);
        return room_error(out, out_len, 500, "服务器内部错误");
    }
    sqlite3_finalize(stmt);
    stmt = NULL;
    long long version_id = sqlite3_last_insert_rowid(db);
    if (room_prepare(db, &stmt,
            "DELETE FROM public_transfer_diagram_version WHERE room_id=? AND id NOT IN "
            "(SELECT id FROM public_transfer_diagram_version WHERE room_id=? "
            "ORDER BY created_at DESC,id DESC LIMIT 50)") != 0
        || sqlite3_bind_int64(stmt, 1, room_id) != SQLITE_OK
        || sqlite3_bind_int64(stmt, 2, room_id) != SQLITE_OK
        || sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        free(snapshot);
        sqlite3_close(db);
        return room_error(out, out_len, 500, "服务器内部错误");
    }
    sqlite3_finalize(stmt);
    if (sqlite3_exec(db, "COMMIT", NULL, NULL, &transaction_error) != SQLITE_OK) {
        sqlite3_free(transaction_error);
        (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        free(snapshot);
        sqlite3_close(db);
        return room_error(out, out_len, 500, "服务器内部错误");
    }
    free(snapshot);
    sqlite3_close(db);
    char response[2048];
    if (room_version_view(version_id,
                          name,
                          peer_id,
                          (long long)snapshot_len,
                          now,
                          response,
                          sizeof(response)) < 0)
        return room_error(out, out_len, 500, "响应过大");
    return room_write_response(out, out_len, 200, "OK", response);
}

static int room_parse_version_path(const char *path, long long *version_id, int *delete_request)
{
    static const char prefix[] = "/api/public/transfer/rooms/diagram/versions/";
    const char *start = path + sizeof(prefix) - 1U;
    char *end = NULL;
    errno = 0;
    long long parsed = strtoll(start, &end, 10);
    if (errno != 0 || end == start || parsed <= 0) return -1;
    if (*end == '\0') *delete_request = 0;
    else if (strcmp(end, "/delete") == 0) *delete_request = 1;
    else return -1;
    *version_id = parsed;
    return 0;
}

static int room_get_or_delete_version(const char *path,
                                      const char *body,
                                      char *out,
                                      size_t out_len)
{
    long long version_id = 0;
    int delete_request = 0;
    if (room_parse_version_path(path, &version_id, &delete_request) != 0)
        return room_error(out, out_len, 400, "versionId 无效");
    sqlite3 *db = NULL;
    int opened = room_open(&db);
    if (opened != 0) return room_error(out, out_len, opened == 1 ? 503 : 500, "房间存储不可用");
    long long room_id = 0;
    char role[16], peer_id[481];
    int resolved = room_resolve_request(db, body, &room_id, role, peer_id);
    if (resolved != 0) {
        sqlite3_close(db);
        return room_error(out,
                          out_len,
                          resolved == -2 ? 400 : resolved == 2 ? 403 : 500,
                          resolved == -2 ? "请求体无效"
                              : resolved == 2 ? "房间凭证无效" : "服务器内部错误");
    }
    if (delete_request) {
        if (strcmp(role, "OWNER") != 0) {
            sqlite3_close(db);
            return room_error(out, out_len, 403, "需要房主权限");
        }
        sqlite3_stmt *stmt = NULL;
        if (room_prepare(db, &stmt,
                "DELETE FROM public_transfer_diagram_version WHERE id=? AND room_id=?") != 0
            || sqlite3_bind_int64(stmt, 1, version_id) != SQLITE_OK
            || sqlite3_bind_int64(stmt, 2, room_id) != SQLITE_OK
            || sqlite3_step(stmt) != SQLITE_DONE) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return room_error(out, out_len, 500, "服务器内部错误");
        }
        int changed = sqlite3_changes(db);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        if (!changed) return room_error(out, out_len, 404, "流程图版本不存在");
        return room_write_response(out, out_len, 204, "No Content", "");
    }
    sqlite3_stmt *stmt = NULL;
    if (room_prepare(db, &stmt,
            "SELECT name,author_peer_id,snapshot_data,size_bytes,created_at "
            "FROM public_transfer_diagram_version WHERE id=? AND room_id=?") != 0
        || sqlite3_bind_int64(stmt, 1, version_id) != SQLITE_OK
        || sqlite3_bind_int64(stmt, 2, room_id) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return room_error(out, out_len, 500, "服务器内部错误");
    }
    int step = sqlite3_step(stmt);
    if (step != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return room_error(out, out_len, step == SQLITE_DONE ? 404 : 500,
                          step == SQLITE_DONE ? "流程图版本不存在" : "服务器内部错误");
    }
    const char *name = (const char *)sqlite3_column_text(stmt, 0);
    const char *author = (const char *)sqlite3_column_text(stmt, 1);
    const uint8_t *snapshot = (const uint8_t *)sqlite3_column_blob(stmt, 2);
    size_t snapshot_len = (size_t)sqlite3_column_bytes(stmt, 2);
    long long size_bytes = sqlite3_column_int64(stmt, 3);
    const char *created = (const char *)sqlite3_column_text(stmt, 4);
    char view[2048];
    int view_len = room_version_view(version_id,
                                     name,
                                     author,
                                     size_bytes,
                                     created,
                                     view,
                                     sizeof(view));
    char *encoded = room_base64_encode(snapshot, snapshot_len);
    if (view_len < 0 || encoded == NULL) {
        free(encoded);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return room_error(out, out_len, 500, "服务器内部错误");
    }
    size_t response_cap = (size_t)view_len + strlen(encoded) + 64U;
    char *response = (char *)malloc(response_cap);
    if (response == NULL) {
        free(encoded);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return room_error(out, out_len, 500, "服务器内部错误");
    }
    int written = snprintf(response,
                           response_cap,
                           "{\"version\":%s,\"update\":\"%s\"}",
                           view,
                           encoded);
    free(encoded);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    if (written < 0 || (size_t)written >= response_cap) {
        free(response);
        return room_error(out, out_len, 500, "响应过大");
    }
    int result = room_write_response(out, out_len, 200, "OK", response);
    free(response);
    return result;
}

int st_public_room_build_response(const char *method,
                                  const char *path,
                                  const char *body,
                                  const char *remote_address,
                                  char *out,
                                  size_t out_len)
{
    if (method == NULL || path == NULL || strcmp(method, "POST") != 0) return 0;
    if (strcmp(path, "/api/public/transfer/rooms/access-tokens/list") == 0)
        return room_list_access(body, out, out_len);
    if (strcmp(path, "/api/public/transfer/rooms/access-tokens") == 0)
        return room_create_access(body, out, out_len);
    if (strncmp(path,
                "/api/public/transfer/rooms/access-tokens/",
                strlen("/api/public/transfer/rooms/access-tokens/")) == 0)
        return room_revoke_access(path, body, out, out_len);
    if (strcmp(path, "/api/public/transfer/rooms/pairing-codes") == 0)
        return room_create_pairing(body, out, out_len);
    if (strcmp(path, "/api/public/transfer/rooms/pairing-codes/redeem") == 0)
        return room_redeem_pairing(body, remote_address, out, out_len);
    if (strcmp(path, "/api/public/transfer/rooms/diagram/versions/list") == 0)
        return room_list_versions(body, out, out_len);
    if (strcmp(path, "/api/public/transfer/rooms/diagram/versions") == 0)
        return room_create_version(body, out, out_len);
    if (strncmp(path,
                "/api/public/transfer/rooms/diagram/versions/",
                strlen("/api/public/transfer/rooms/diagram/versions/")) == 0)
        return room_get_or_delete_version(path, body, out, out_len);
    return 0;
}

void st_public_room_reset_for_tests(void)
{
    pthread_mutex_lock(&room_rate_lock);
    while (room_rate_windows != NULL) {
        st_room_rate_window *next = room_rate_windows->next;
        free(room_rate_windows);
        room_rate_windows = next;
    }
    pthread_mutex_unlock(&room_rate_lock);
}
