#define _POSIX_C_SOURCE 200809L

#include "http_share.h"

#include "crypto.h"
#include "json.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#define ST_HTTP_SHARE_GCRA_BUCKETS 1024U

const char *const st_http_share_read_methods[ST_HTTP_SHARE_READ_METHOD_COUNT] = {"GET", "HEAD"};
const char *const st_http_share_revoke_reasons[ST_HTTP_SHARE_REVOKE_REASON_COUNT] = {
    "revoked-by-user", "route-disabled", "route-made-public", "route-deleted",
    "client-disabled", "client-deleted", "creator-lost-access"
};
const char *const st_http_share_audit_actions[ST_HTTP_SHARE_AUDIT_ACTION_COUNT] = {
    "share.created", "share.revoked", "share.expired", "route.created",
    "route.exposure-changed", "route.credentials-changed", "route.deleted"
};

static atomic_llong share_fixed_now_ms;
static pthread_mutex_t share_random_lock = PTHREAD_MUTEX_INITIALIZER;
static st_http_share_random_source share_random_source = NULL;

long long st_http_share_now_ms(void)
{
    long long fixed = atomic_load(&share_fixed_now_ms);
    if (fixed > 0) {
        return fixed;
    }
    struct timeval tv;
    if (gettimeofday(&tv, NULL) != 0) {
        return 0;
    }
    return (long long)tv.tv_sec * 1000LL + (long long)tv.tv_usec / 1000LL;
}

void st_http_share_set_clock_for_testing(long long fixed_now_ms)
{
    atomic_store(&share_fixed_now_ms, fixed_now_ms > 0 ? fixed_now_ms : 0);
}

void st_http_share_set_random_for_testing(st_http_share_random_source source)
{
    pthread_mutex_lock(&share_random_lock);
    share_random_source = source;
    pthread_mutex_unlock(&share_random_lock);
}

/* Never build_prefixed_token: a share secret must come from the CSPRNG (spec 1.4). */
static int share_random_bytes(uint8_t *out, size_t len)
{
    pthread_mutex_lock(&share_random_lock);
    st_http_share_random_source source = share_random_source;
    pthread_mutex_unlock(&share_random_lock);
    if (source != NULL) {
        return source(out, len);
    }
    if (len > (size_t)INT_MAX) {
        return -1;
    }
    return RAND_bytes(out, (int)len) == 1 ? 0 : -1;
}

static int share_base64url_char(int ch)
{
    return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')
        || ch == '-' || ch == '_';
}

static void share_base64url(const uint8_t *data, size_t len, char *out)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t written = 0U;
    for (size_t i = 0U; i < len; i += 3U) {
        uint32_t value = (uint32_t)data[i] << 16U;
        size_t remaining = len - i;
        if (remaining > 1U) value |= (uint32_t)data[i + 1U] << 8U;
        if (remaining > 2U) value |= data[i + 2U];
        out[written++] = alphabet[(value >> 18U) & 63U];
        out[written++] = alphabet[(value >> 12U) & 63U];
        if (remaining > 1U) out[written++] = alphabet[(value >> 6U) & 63U];
        if (remaining > 2U) out[written++] = alphabet[value & 63U];
    }
    out[written] = '\0';
}

int st_http_share_new_token(char share_id[ST_HTTP_SHARE_ID_LEN + 1U],
                            char token[ST_HTTP_SHARE_TOKEN_LEN + 1U])
{
    uint8_t id_bytes[ST_HTTP_SHARE_ID_BYTES];
    uint8_t secret_bytes[ST_HTTP_SHARE_SECRET_BYTES];
    if (share_random_bytes(id_bytes, sizeof(id_bytes)) != 0
        || share_random_bytes(secret_bytes, sizeof(secret_bytes)) != 0) {
        return -1;
    }
    char secret[ST_HTTP_SHARE_SECRET_LEN + 1U];
    share_base64url(id_bytes, sizeof(id_bytes), share_id);
    share_base64url(secret_bytes, sizeof(secret_bytes), secret);
    memset(secret_bytes, 0, sizeof(secret_bytes));
    int written = snprintf(token, ST_HTTP_SHARE_TOKEN_LEN + 1U, "%s.%s.%s",
                           ST_HTTP_SHARE_TOKEN_VERSION, share_id, secret);
    memset(secret, 0, sizeof(secret));
    return written == (int)ST_HTTP_SHARE_TOKEN_LEN ? 0 : -1;
}

int st_http_share_valid_id(const char *text, size_t len)
{
    if (text == NULL || len != ST_HTTP_SHARE_ID_LEN) {
        return 0;
    }
    for (size_t i = 0U; i < len; ++i) {
        if (!share_base64url_char((unsigned char)text[i])) {
            return 0;
        }
    }
    return 1;
}

int st_http_share_parse_token(const char *text, size_t len, char share_id[ST_HTTP_SHARE_ID_LEN + 1U])
{
    /* The whole string must match: no trimming, a trailing newline is not tolerated. */
    if (text == NULL || len != ST_HTTP_SHARE_TOKEN_LEN
        || memcmp(text, ST_HTTP_SHARE_TOKEN_VERSION ".", 4U) != 0
        || text[4U + ST_HTTP_SHARE_ID_LEN] != '.'
        || !st_http_share_valid_id(text + 4U, ST_HTTP_SHARE_ID_LEN)) {
        return -1;
    }
    const char *secret = text + 5U + ST_HTTP_SHARE_ID_LEN;
    for (size_t i = 0U; i < ST_HTTP_SHARE_SECRET_LEN; ++i) {
        if (!share_base64url_char((unsigned char)secret[i])) {
            return -1;
        }
    }
    memcpy(share_id, text + 4U, ST_HTTP_SHARE_ID_LEN);
    share_id[ST_HTTP_SHARE_ID_LEN] = '\0';
    return 0;
}

void st_http_share_token_hash(const char *token, size_t len, char out[65])
{
    uint8_t digest[ST_SHA256_LEN];
    st_sha256((const uint8_t *)token, len, digest);
    st_hex_encode(digest, sizeof(digest), out);
}

int st_http_share_hash_matches(const char *token, const char *expected_hex)
{
    uint8_t expected[ST_SHA256_LEN];
    uint8_t actual[ST_SHA256_LEN];
    if (token == NULL || expected_hex == NULL || st_hex_decode_32(expected_hex, expected) != 0) {
        return 0;
    }
    st_sha256((const uint8_t *)token, strlen(token), actual);
    return st_constant_time_eq(actual, expected, sizeof(actual));
}

void st_http_share_format_time(long long epoch_seconds, char out[32])
{
    time_t value = (time_t)epoch_seconds;
    struct tm utc;
    if (gmtime_r(&value, &utc) == NULL || strftime(out, 32U, "%Y-%m-%dT%H:%M:%SZ", &utc) == 0U) {
        snprintf(out, 32U, "1970-01-01T00:00:00Z");
    }
}

/* ------------------------------------------------------------------------------------------------
 * Paths (spec 6.3)
 */

static int share_unreserved(int ch)
{
    return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')
        || ch == '-' || ch == '.' || ch == '_' || ch == '~';
}

/* RFC 3986 pchar without ";" (servlet containers cut path parameters at it), plus "/". */
static int share_path_char(int ch)
{
    return share_unreserved(ch) || (ch != '\0' && strchr("!$&'()*+,=:@/", ch) != NULL);
}

static int share_hex_value(int ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

char *st_http_share_normalize_path(const char *raw, size_t len)
{
    if (raw == NULL) {
        return NULL;
    }
    char *out = (char *)malloc(len + 1U);
    if (out == NULL) {
        return NULL;
    }
    static const char upper_hex[] = "0123456789ABCDEF";
    size_t written = 0U;
    for (size_t i = 0U; i < len;) {
        unsigned char ch = (unsigned char)raw[i];
        if (ch == '%') {
            int high = i + 2U < len ? share_hex_value((unsigned char)raw[i + 1U]) : -1;
            int low = i + 2U < len ? share_hex_value((unsigned char)raw[i + 2U]) : -1;
            if (high < 0 || low < 0) {
                free(out);
                return NULL;
            }
            int decoded = (high << 4) | low;
            if (share_unreserved(decoded)) {
                out[written++] = (char)decoded;
            } else {
                out[written++] = '%';
                out[written++] = upper_hex[high];
                out[written++] = upper_hex[low];
            }
            i += 3U;
            continue;
        }
        if (!share_path_char(ch)) {
            free(out);
            return NULL;
        }
        out[written++] = (char)ch;
        ++i;
    }
    out[written] = '\0';
    return out;
}

/* A dot segment, or an escaped slash, backslash or control character (spec 6.3 rule 3). */
static int share_unsafe_for_prefix(const char *normalized)
{
    for (const char *p = normalized; *p != '\0'; ++p) {
        if (*p == '%' && share_hex_value((unsigned char)p[1]) >= 0 && share_hex_value((unsigned char)p[2]) >= 0) {
            int value = (share_hex_value((unsigned char)p[1]) << 4) | share_hex_value((unsigned char)p[2]);
            if (value == 0x2F || value == 0x5C || value < 0x20 || value == 0x7F) {
                return 1;
            }
        }
    }
    const char *segment = strchr(normalized, '/');
    while (segment != NULL) {
        const char *start = segment + 1;
        const char *end = strchr(start, '/');
        size_t len = end == NULL ? strlen(start) : (size_t)(end - start);
        if ((len == 1U && start[0] == '.') || (len == 2U && start[0] == '.' && start[1] == '.')) {
            return 1;
        }
        segment = end;
    }
    return 0;
}

int st_http_share_canonical_prefix(const char *value, size_t len, char out[ST_HTTP_SHARE_PREFIX_MAX_BYTES + 1U])
{
    if (value == NULL || len == 0U || value[0] != '/' || (len > 1U && value[1] == '/')) {
        return -1;
    }
    char *normalized = st_http_share_normalize_path(value, len);
    if (normalized == NULL) {
        return -1;
    }
    if (share_unsafe_for_prefix(normalized)) {
        free(normalized);
        return -1;
    }
    size_t normalized_len = strlen(normalized);
    int trailing = normalized[normalized_len - 1U] == '/';
    /* The inner part between the leading and the trailing slash has no empty segment. */
    const char *inner = normalized + 1;
    size_t inner_len = normalized_len - 1U - (trailing && normalized_len > 1U ? 1U : 0U);
    if (inner_len > 0U) {
        int empty = inner[0] == '/' || inner[inner_len - 1U] == '/';
        for (size_t i = 0U; !empty && i + 1U < inner_len; ++i) {
            empty = inner[i] == '/' && inner[i + 1U] == '/';
        }
        if (empty) {
            free(normalized);
            return -1;
        }
    }
    size_t canonical_len = normalized_len + (trailing ? 0U : 1U);
    if (canonical_len > ST_HTTP_SHARE_PREFIX_MAX_BYTES) {
        free(normalized);
        return -1;
    }
    memcpy(out, normalized, normalized_len);
    if (!trailing) {
        out[normalized_len] = '/';
    }
    out[canonical_len] = '\0';
    free(normalized);
    return 0;
}

int st_http_share_path_in_scope(const char *prefix, const char *relative_path, size_t len)
{
    if (prefix == NULL || relative_path == NULL) {
        return 0;
    }
    if (strcmp(prefix, "/") == 0) {
        return 1; /* the whole route: no rule beyond the route's own */
    }
    char *normalized = st_http_share_normalize_path(relative_path, len);
    if (normalized == NULL) {
        return 0;
    }
    int in_scope = 0;
    if (!share_unsafe_for_prefix(normalized)) {
        size_t prefix_len = strlen(prefix);
        size_t normalized_len = strlen(normalized);
        in_scope = (normalized_len + 1U == prefix_len && memcmp(normalized, prefix, normalized_len) == 0)
            || strncmp(normalized, prefix, prefix_len) == 0;
    }
    free(normalized);
    return in_scope;
}

/* ------------------------------------------------------------------------------------------------
 * Request bodies (spec 4.1 and 5.2)
 */

static const char *share_json_ws(const char *p)
{
    while (*p != '\0' && isspace((unsigned char)*p)) {
        ++p;
    }
    return p;
}

static const char *share_json_skip_string(const char *p)
{
    if (*p != '"') {
        return NULL;
    }
    ++p;
    while (*p != '\0') {
        if (*p == '\\') {
            if (p[1] == '\0') {
                return NULL;
            }
            p += 2;
            continue;
        }
        if (*p == '"') {
            return p + 1;
        }
        ++p;
    }
    return NULL;
}

/* Only ever called on text st_json_is_valid_object accepted. */
static const char *share_json_skip_value(const char *p)
{
    p = share_json_ws(p);
    if (*p == '"') {
        return share_json_skip_string(p);
    }
    if (*p == '{' || *p == '[') {
        int depth = 0;
        while (*p != '\0') {
            if (*p == '"') {
                p = share_json_skip_string(p);
                if (p == NULL) {
                    return NULL;
                }
                continue;
            }
            if (*p == '{' || *p == '[') {
                ++depth;
            } else if (*p == '}' || *p == ']') {
                if (--depth == 0) {
                    return p + 1;
                }
            }
            ++p;
        }
        return NULL;
    }
    while (*p != '\0' && *p != ',' && *p != '}' && *p != ']' && !isspace((unsigned char)*p)) {
        ++p;
    }
    return p;
}

typedef int (*share_member_fn)(void *ctx, const char *key, size_t key_len, const char *value, size_t value_len);

/* Visits every top-level member of a validated JSON object; a later duplicate key wins. */
static int share_json_each_member(const char *json, share_member_fn fn, void *ctx)
{
    const char *p = share_json_ws(json);
    if (*p != '{') {
        return -1;
    }
    p = share_json_ws(p + 1);
    if (*p == '}') {
        return 0;
    }
    for (;;) {
        const char *key_end = share_json_skip_string(p);
        if (key_end == NULL) {
            return -1;
        }
        size_t raw_len = (size_t)(key_end - p);
        char *raw_key = (char *)malloc(raw_len + 1U);
        if (raw_key == NULL) {
            return -1;
        }
        memcpy(raw_key, p, raw_len);
        raw_key[raw_len] = '\0';
        size_t key_len = 0U;
        char *key = st_json_decode_string(raw_key, &key_len);
        free(raw_key);
        if (key == NULL) {
            return -1;
        }
        p = share_json_ws(key_end);
        if (*p != ':') {
            free(key);
            return -1;
        }
        const char *value = share_json_ws(p + 1);
        const char *value_end = share_json_skip_value(value);
        if (value_end == NULL) {
            free(key);
            return -1;
        }
        int rc = fn(ctx, key, key_len, value, (size_t)(value_end - value));
        free(key);
        if (rc != 0) {
            return rc;
        }
        p = share_json_ws(value_end);
        if (*p == ',') {
            p = share_json_ws(p + 1);
            continue;
        }
        return *p == '}' ? 0 : -1;
    }
}

static char *share_copy_body(const char *body, size_t body_len)
{
    if (body == NULL) {
        return NULL;
    }
    char *copy = (char *)malloc(body_len + 1U);
    if (copy == NULL) {
        return NULL;
    }
    memcpy(copy, body, body_len);
    copy[body_len] = '\0';
    if (strlen(copy) != body_len || !st_json_is_valid_object(copy)) {
        free(copy);
        return NULL;
    }
    return copy;
}

static int share_hex4(const char *text, uint32_t *out)
{
    uint32_t value = 0U;
    for (int i = 0; i < 4; ++i) {
        int digit = share_hex_value((unsigned char)text[i]);
        if (digit < 0) {
            return -1;
        }
        value = (value << 4U) | (uint32_t)digit;
    }
    *out = value;
    return 0;
}

/*
 * A JSON string value (raw, quotes included, already validated) decoded to UTF-8; NULL when the
 * value is not a string. Unlike st_json_decode_string, which reads raw bytes above 0x7F as
 * Latin-1, UTF-8 in the text is kept as it is, so a label such as "周报评审" survives.
 */
static char *share_json_string(const char *raw, size_t raw_len, size_t *out_len)
{
    if (raw_len < 2U || raw[0] != '"' || raw[raw_len - 1U] != '"') {
        return NULL;
    }
    char *out = (char *)malloc(raw_len);
    if (out == NULL) {
        return NULL;
    }
    size_t written = 0U;
    size_t end = raw_len - 1U;
    for (size_t i = 1U; i < end;) {
        unsigned char ch = (unsigned char)raw[i];
        if (ch != '\\') {
            out[written++] = (char)ch;
            ++i;
            continue;
        }
        if (i + 1U >= end) {
            free(out);
            return NULL;
        }
        char escaped = raw[i + 1U];
        i += 2U;
        if (escaped != 'u') {
            const char *from = "\"\\/bfnrt";
            const char *to = "\"\\/\b\f\n\r\t";
            const char *found = strchr(from, escaped);
            if (escaped == '\0' || found == NULL) {
                free(out);
                return NULL;
            }
            out[written++] = to[found - from];
            continue;
        }
        uint32_t code_point = 0U;
        if (i + 4U > end || share_hex4(raw + i, &code_point) != 0) {
            free(out);
            return NULL;
        }
        i += 4U;
        if (code_point >= 0xD800U && code_point <= 0xDBFFU) {
            uint32_t low = 0U;
            if (i + 6U > end || raw[i] != '\\' || raw[i + 1U] != 'u' || share_hex4(raw + i + 2U, &low) != 0
                || low < 0xDC00U || low > 0xDFFFU) {
                free(out);
                return NULL;
            }
            i += 6U;
            code_point = 0x10000U + ((code_point - 0xD800U) << 10U) + (low - 0xDC00U);
        } else if (code_point >= 0xDC00U && code_point <= 0xDFFFU) {
            free(out);
            return NULL;
        }
        if (code_point < 0x80U) {
            out[written++] = (char)code_point;
        } else if (code_point < 0x800U) {
            out[written++] = (char)(0xC0U | (code_point >> 6U));
            out[written++] = (char)(0x80U | (code_point & 0x3FU));
        } else if (code_point < 0x10000U) {
            out[written++] = (char)(0xE0U | (code_point >> 12U));
            out[written++] = (char)(0x80U | ((code_point >> 6U) & 0x3FU));
            out[written++] = (char)(0x80U | (code_point & 0x3FU));
        } else {
            out[written++] = (char)(0xF0U | (code_point >> 18U));
            out[written++] = (char)(0x80U | ((code_point >> 12U) & 0x3FU));
            out[written++] = (char)(0x80U | ((code_point >> 6U) & 0x3FU));
            out[written++] = (char)(0x80U | (code_point & 0x3FU));
        }
    }
    out[written] = '\0';
    if (out_len != NULL) {
        *out_len = written;
    }
    return out;
}

typedef struct {
    const char *expires;
    size_t expires_len;
    const char *access;
    size_t access_len;
    const char *prefix;
    size_t prefix_len;
    const char *label;
    size_t label_len;
} share_create_members;

static int share_key_is(const char *key, size_t key_len, const char *expected)
{
    return key_len == strlen(expected) && memcmp(key, expected, key_len) == 0;
}

static int share_collect_create_member(void *ctx, const char *key, size_t key_len,
                                       const char *value, size_t value_len)
{
    share_create_members *members = (share_create_members *)ctx;
    if (share_key_is(key, key_len, "expiresInSeconds")) {
        members->expires = value;
        members->expires_len = value_len;
    } else if (share_key_is(key, key_len, "access")) {
        members->access = value;
        members->access_len = value_len;
    } else if (share_key_is(key, key_len, "pathPrefix")) {
        members->prefix = value;
        members->prefix_len = value_len;
    } else if (share_key_is(key, key_len, "label")) {
        members->label = value;
        members->label_len = value_len;
    } else {
        /* Unknown fields are refused so no client believes a limit such as maxUses holds. */
        return 1;
    }
    return 0;
}

/* Code points in valid UTF-8, or -1; control characters (< 0x20, 0x7F) are refused too. */
static long share_label_code_points(const unsigned char *text, size_t len)
{
    long count = 0;
    for (size_t i = 0U; i < len;) {
        unsigned char ch = text[i];
        size_t need;
        uint32_t value;
        uint32_t minimum;
        if (ch < 0x80U) {
            if (ch < 0x20U || ch == 0x7FU) {
                return -1;
            }
            ++i;
            ++count;
            continue;
        }
        if (ch >= 0xC2U && ch <= 0xDFU) {
            need = 1U;
            value = ch & 0x1FU;
            minimum = 0x80U;
        } else if (ch >= 0xE0U && ch <= 0xEFU) {
            need = 2U;
            value = ch & 0x0FU;
            minimum = 0x800U;
        } else if (ch >= 0xF0U && ch <= 0xF4U) {
            need = 3U;
            value = ch & 0x07U;
            minimum = 0x10000U;
        } else {
            return -1;
        }
        if (len - i <= need) {
            return -1;
        }
        for (size_t j = 1U; j <= need; ++j) {
            unsigned char next = text[i + j];
            if ((next & 0xC0U) != 0x80U) {
                return -1;
            }
            value = (value << 6U) | (next & 0x3FU);
        }
        if (value < minimum || value > 0x10FFFFU || (value >= 0xD800U && value <= 0xDFFFU)) {
            return -1;
        }
        i += need + 1U;
        ++count;
    }
    return count;
}

int st_http_share_parse_create_body(const char *body, size_t body_len, st_http_share_create_fields *out)
{
    memset(out, 0, sizeof(*out));
    char *json = share_copy_body(body, body_len);
    if (json == NULL) {
        return -1;
    }
    share_create_members members;
    memset(&members, 0, sizeof(members));
    int rc = share_json_each_member(json, share_collect_create_member, &members);
    if (rc != 0 || members.expires == NULL) {
        free(json);
        return -1; /* the expiry is mandatory: there is no default */
    }
    /* A JSON integer only: no string, boolean, null, fraction or exponent. */
    size_t start = members.expires[0] == '-' ? 1U : 0U;
    int integer = members.expires_len > start;
    for (size_t i = start; integer && i < members.expires_len; ++i) {
        integer = members.expires[i] >= '0' && members.expires[i] <= '9';
    }
    if (!integer) {
        free(json);
        return -1;
    }
    errno = 0;
    char *end = NULL;
    long long seconds = strtoll(members.expires, &end, 10);
    if (errno == ERANGE || end != members.expires + members.expires_len
        || seconds < ST_HTTP_SHARE_MIN_EXPIRES_SECONDS || seconds > ST_HTTP_SHARE_MAX_EXPIRES_SECONDS) {
        free(json);
        return -1;
    }
    out->expires_in_seconds = seconds;

    snprintf(out->access, sizeof(out->access), "%s", "read");
    if (members.access != NULL) {
        size_t access_len = 0U;
        char *access = share_json_string(members.access, members.access_len, &access_len);
        int valid = access != NULL && access_len == 4U
            && (strcmp(access, "read") == 0 || strcmp(access, "full") == 0);
        if (valid) {
            snprintf(out->access, sizeof(out->access), "%s", access);
        }
        free(access);
        if (!valid) {
            free(json);
            return -1;
        }
    }

    snprintf(out->path_prefix, sizeof(out->path_prefix), "%s", "/");
    if (members.prefix != NULL) {
        size_t prefix_len = 0U;
        char *prefix = share_json_string(members.prefix, members.prefix_len, &prefix_len);
        int valid = prefix != NULL && st_http_share_canonical_prefix(prefix, prefix_len, out->path_prefix) == 0;
        free(prefix);
        if (!valid) {
            free(json);
            return -1;
        }
    }

    if (members.label != NULL && !(members.label_len == 4U && memcmp(members.label, "null", 4U) == 0)) {
        size_t label_len = 0U;
        char *label = share_json_string(members.label, members.label_len, &label_len);
        if (label == NULL) {
            free(json);
            return -1;
        }
        /* Only U+0020 is trimmed; everything else counts. */
        size_t first = 0U;
        while (first < label_len && label[first] == ' ') {
            ++first;
        }
        size_t last = label_len;
        while (last > first && label[last - 1U] == ' ') {
            --last;
        }
        long code_points = share_label_code_points((const unsigned char *)label + first, last - first);
        int valid = code_points >= 0 && code_points <= (long)ST_HTTP_SHARE_LABEL_MAX_CODE_POINTS
            && last - first <= ST_HTTP_SHARE_LABEL_MAX_BYTES;
        if (valid && last > first) {
            memcpy(out->label, label + first, last - first);
            out->label[last - first] = '\0';
            out->has_label = 1;
        }
        free(label);
        if (!valid) {
            free(json);
            return -1;
        }
    }
    free(json);
    return 0;
}

typedef struct {
    const char *token;
    size_t token_len;
    int other;
} share_exchange_members;

static int share_collect_exchange_member(void *ctx, const char *key, size_t key_len,
                                         const char *value, size_t value_len)
{
    share_exchange_members *members = (share_exchange_members *)ctx;
    if (share_key_is(key, key_len, "token")) {
        members->token = value;
        members->token_len = value_len;
        return 0;
    }
    members->other = 1;
    return 1;
}

int st_http_share_parse_exchange_body(const char *body, size_t body_len, char **token, size_t *token_len)
{
    *token = NULL;
    *token_len = 0U;
    if (body_len > ST_HTTP_SHARE_EXCHANGE_MAX_BODY) {
        return -1;
    }
    char *json = share_copy_body(body, body_len);
    if (json == NULL) {
        return -1;
    }
    share_exchange_members members;
    memset(&members, 0, sizeof(members));
    int rc = share_json_each_member(json, share_collect_exchange_member, &members);
    if (rc != 0 || members.other || members.token == NULL) {
        free(json);
        return -1;
    }
    *token = share_json_string(members.token, members.token_len, token_len);
    free(json);
    return *token == NULL ? -1 : 0;
}

/* ------------------------------------------------------------------------------------------------
 * Cookies and response headers (spec 5.2, 6.2, 6.4, 6.5)
 */

typedef int (*share_pair_fn)(void *ctx, const char *pair, size_t pair_len);

/* Every non-empty "name=value" pair of the Cookie headers in order, trimmed of space and tab. */
static int share_each_cookie_pair(char *const *headers, size_t count, share_pair_fn fn, void *ctx)
{
    for (size_t i = 0U; i < count; ++i) {
        const char *cursor = headers[i];
        if (cursor == NULL) {
            continue;
        }
        for (;;) {
            const char *semi = strchr(cursor, ';');
            const char *end = semi == NULL ? cursor + strlen(cursor) : semi;
            const char *start = cursor;
            while (start < end && (*start == ' ' || *start == '\t')) ++start;
            while (end > start && (end[-1] == ' ' || end[-1] == '\t')) --end;
            if (end > start) {
                int rc = fn(ctx, start, (size_t)(end - start));
                if (rc != 0) {
                    return rc;
                }
            }
            if (semi == NULL) {
                break;
            }
            cursor = semi + 1;
        }
    }
    return 0;
}

static void share_pair_split(const char *pair, size_t pair_len,
                             const char **name, size_t *name_len,
                             const char **value, size_t *value_len)
{
    const char *equals = memchr(pair, '=', pair_len);
    const char *name_end = equals == NULL ? pair + pair_len : equals;
    const char *name_start = pair;
    while (name_start < name_end && (*name_start == ' ' || *name_start == '\t')) ++name_start;
    while (name_end > name_start && (name_end[-1] == ' ' || name_end[-1] == '\t')) --name_end;
    *name = name_start;
    *name_len = (size_t)(name_end - name_start);
    if (equals == NULL) {
        *value = pair + pair_len;
        *value_len = 0U;
        return;
    }
    const char *value_start = equals + 1;
    const char *value_end = pair + pair_len;
    while (value_start < value_end && (*value_start == ' ' || *value_start == '\t')) ++value_start;
    while (value_end > value_start && (value_end[-1] == ' ' || value_end[-1] == '\t')) --value_end;
    *value = value_start;
    *value_len = (size_t)(value_end - value_start);
}

static int share_is_cookie_name(const char *name, size_t name_len)
{
    return name_len == strlen(ST_HTTP_SHARE_COOKIE_NAME)
        && memcmp(name, ST_HTTP_SHARE_COOKIE_NAME, name_len) == 0;
}

typedef struct {
    const char *share_id;
    char (*out)[ST_HTTP_SHARE_TOKEN_LEN + 1U];
    size_t count;
} share_candidate_ctx;

static int share_collect_candidate(void *ctx, const char *pair, size_t pair_len)
{
    share_candidate_ctx *candidates = (share_candidate_ctx *)ctx;
    const char *name;
    const char *value;
    size_t name_len;
    size_t value_len;
    share_pair_split(pair, pair_len, &name, &name_len, &value, &value_len);
    char share_id[ST_HTTP_SHARE_ID_LEN + 1U];
    if (share_is_cookie_name(name, name_len)
        && st_http_share_parse_token(value, value_len, share_id) == 0
        && strcmp(share_id, candidates->share_id) == 0) {
        memcpy(candidates->out[candidates->count], value, value_len);
        candidates->out[candidates->count][value_len] = '\0';
        if (++candidates->count == ST_HTTP_SHARE_MAX_COOKIE_CANDIDATES) {
            return 1;
        }
    }
    return 0;
}

size_t st_http_share_credential_candidates(char *const *cookie_headers,
                                           size_t count,
                                           const char *share_id,
                                           char out[ST_HTTP_SHARE_MAX_COOKIE_CANDIDATES][ST_HTTP_SHARE_TOKEN_LEN + 1U])
{
    share_candidate_ctx candidates = {share_id, out, 0U};
    (void)share_each_cookie_pair(cookie_headers, count, share_collect_candidate, &candidates);
    return candidates.count;
}

typedef struct {
    char *data;
    size_t len;
    size_t cap;
    int failed;
} share_text;

static void share_text_append(share_text *text, const char *value, size_t len)
{
    if (text->failed) {
        return;
    }
    if (text->len + len + 1U > text->cap) {
        size_t next = text->cap == 0U ? 128U : text->cap;
        while (next < text->len + len + 1U) {
            next *= 2U;
        }
        char *grown = (char *)realloc(text->data, next);
        if (grown == NULL) {
            text->failed = 1;
            return;
        }
        text->data = grown;
        text->cap = next;
    }
    memcpy(text->data + text->len, value, len);
    text->len += len;
    text->data[text->len] = '\0';
}

static int share_keep_cookie_pair(void *ctx, const char *pair, size_t pair_len)
{
    share_text *text = (share_text *)ctx;
    const char *name;
    const char *value;
    size_t name_len;
    size_t value_len;
    share_pair_split(pair, pair_len, &name, &name_len, &value, &value_len);
    if (share_is_cookie_name(name, name_len)) {
        return 0;
    }
    if (text->len > 0U) {
        share_text_append(text, "; ", 2U);
    }
    share_text_append(text, pair, pair_len);
    return 0;
}

int st_http_share_forwarded_cookie(char *const *cookie_headers, size_t count, char **out)
{
    share_text text = {NULL, 0U, 0U, 0};
    (void)share_each_cookie_pair(cookie_headers, count, share_keep_cookie_pair, &text);
    if (text.failed) {
        free(text.data);
        *out = NULL;
        return -1;
    }
    *out = text.len == 0U ? NULL : text.data;
    if (text.len == 0U) {
        free(text.data);
    }
    return 0;
}

static void share_trim(const char **start, const char **end, int any_space)
{
    while (*start < *end && (any_space ? isspace((unsigned char)**start) : (**start == ' ' || **start == '\t'))) {
        ++*start;
    }
    while (*end > *start
           && (any_space ? isspace((unsigned char)(*end)[-1]) : ((*end)[-1] == ' ' || (*end)[-1] == '\t'))) {
        --*end;
    }
}

static int share_ascii_prefix_ci(const char *text, size_t len, const char *prefix)
{
    size_t prefix_len = strlen(prefix);
    if (len < prefix_len) {
        return 0;
    }
    for (size_t i = 0U; i < prefix_len; ++i) {
        if (tolower((unsigned char)text[i]) != tolower((unsigned char)prefix[i])) {
            return 0;
        }
    }
    return 1;
}

static int share_ascii_equals_ci(const char *text, size_t len, const char *expected)
{
    return len == strlen(expected) && share_ascii_prefix_ci(text, len, expected);
}

int st_http_share_scope_set_cookie(const char *value, const char *share_id, char **out)
{
    *out = NULL;
    const char *first_end = strchr(value, ';');
    if (first_end == NULL) {
        first_end = value + strlen(value);
    }
    const char *equals = memchr(value, '=', (size_t)(first_end - value));
    const char *name_start = value;
    const char *name_end = equals == NULL ? first_end : equals;
    share_trim(&name_start, &name_end, 0);
    size_t name_len = (size_t)(name_end - name_start);
    /* The share's own cookie and __Host- cookies (which must keep Path=/) never reach the visitor. */
    if (share_is_cookie_name(name_start, name_len) || share_ascii_prefix_ci(name_start, name_len, "__host-")) {
        return 1;
    }
    share_text text = {NULL, 0U, 0U, 0};
    const char *pair_start = value;
    const char *pair_end = first_end;
    share_trim(&pair_start, &pair_end, 0);
    share_text_append(&text, pair_start, (size_t)(pair_end - pair_start));
    const char *cursor = *first_end == ';' ? first_end + 1 : NULL;
    while (cursor != NULL) {
        const char *semi = strchr(cursor, ';');
        const char *end = semi == NULL ? cursor + strlen(cursor) : semi;
        const char *start = cursor;
        share_trim(&start, &end, 0);
        cursor = semi == NULL ? NULL : semi + 1;
        if (end == start) {
            continue;
        }
        const char *attr_equals = memchr(start, '=', (size_t)(end - start));
        const char *key_start = start;
        const char *key_end = attr_equals == NULL ? end : attr_equals;
        share_trim(&key_start, &key_end, 0);
        size_t key_len = (size_t)(key_end - key_start);
        if (share_ascii_equals_ci(key_start, key_len, "domain")) {
            continue;
        }
        share_text_append(&text, "; ", 2U);
        if (share_ascii_equals_ci(key_start, key_len, "path")) {
            const char *path_start = attr_equals == NULL ? end : attr_equals + 1;
            const char *path_end = end;
            share_trim(&path_start, &path_end, 0);
            if (path_end > path_start && *path_start == '/') {
                /* A Path is moved under the share path; a missing or relative one already is. */
                share_text_append(&text, "Path=", 5U);
                share_text_append(&text, ST_HTTP_SHARE_PATH_ROOT, strlen(ST_HTTP_SHARE_PATH_ROOT));
                share_text_append(&text, share_id, strlen(share_id));
                share_text_append(&text, path_start, (size_t)(path_end - path_start));
                continue;
            }
        }
        share_text_append(&text, start, (size_t)(end - start));
    }
    if (text.failed || text.data == NULL) {
        free(text.data);
        return -1;
    }
    *out = text.data;
    return 0;
}

void st_http_share_free_strings(char **values, size_t count)
{
    if (values == NULL) {
        return;
    }
    for (size_t i = 0U; i < count; ++i) {
        free(values[i]);
    }
    free(values);
}

static int share_cache_header(const char *name, size_t len)
{
    return share_ascii_equals_ci(name, len, "cache-control")
        || share_ascii_equals_ci(name, len, "cdn-cache-control")
        || share_ascii_equals_ci(name, len, "surrogate-control")
        || share_ascii_equals_ci(name, len, "expires")
        || share_ascii_equals_ci(name, len, "pragma");
}

static int share_has_no_store(const char *value)
{
    const char *cursor = value;
    for (;;) {
        const char *comma = strchr(cursor, ',');
        const char *end = comma == NULL ? cursor + strlen(cursor) : comma;
        const char *start = cursor;
        share_trim(&start, &end, 1);
        const char *equals = memchr(start, '=', (size_t)(end - start));
        if (equals != NULL) {
            end = equals;
        }
        if (share_ascii_equals_ci(start, (size_t)(end - start), "no-store")) {
            return 1;
        }
        if (comma == NULL) {
            return 0;
        }
        cursor = comma + 1;
    }
}

static char *share_dup_range(const char *value, size_t len)
{
    char *copy = (char *)malloc(len + 1U);
    if (copy != NULL) {
        memcpy(copy, value, len);
        copy[len] = '\0';
    }
    return copy;
}

int st_http_share_rewrite_response_headers(int status,
                                           char *const *headers,
                                           size_t count,
                                           const char *share_id,
                                           char ***out,
                                           size_t *out_len)
{
    *out = NULL;
    *out_len = 0U;
    char **result = (char **)calloc(count + 1U, sizeof(*result));
    if (result == NULL) {
        return -1;
    }
    size_t written = 0U;
    int no_store = 0;
    for (size_t i = 0U; i < count; ++i) {
        const char *header = headers[i];
        if (header == NULL) {
            continue;
        }
        const char *colon = strchr(header, ':');
        const char *name_start = header;
        const char *name_end = colon == NULL ? header + strlen(header) : colon;
        share_trim(&name_start, &name_end, 1);
        size_t name_len = (size_t)(name_end - name_start);
        const char *value = colon == NULL ? "" : colon + 1;
        if (share_ascii_equals_ci(name_start, name_len, "clear-site-data")) {
            continue; /* it would wipe the whole origin: the console and every other share */
        }
        if (share_ascii_equals_ci(name_start, name_len, "set-cookie")) {
            const char *value_start = value;
            const char *value_end = value + strlen(value);
            share_trim(&value_start, &value_end, 0);
            char *trimmed = share_dup_range(value_start, (size_t)(value_end - value_start));
            char *scoped = NULL;
            int rc = trimmed == NULL ? -1 : st_http_share_scope_set_cookie(trimmed, share_id, &scoped);
            free(trimmed);
            if (rc < 0) {
                st_http_share_free_strings(result, written);
                return -1;
            }
            if (rc == 0) {
                size_t len = name_len + 1U + strlen(scoped);
                result[written] = (char *)malloc(len + 1U);
                if (result[written] == NULL) {
                    free(scoped);
                    st_http_share_free_strings(result, written);
                    return -1;
                }
                snprintf(result[written], len + 1U, "%.*s:%s", (int)name_len, name_start, scoped);
                ++written;
            }
            free(scoped);
            continue;
        }
        if (status != 101 && share_cache_header(name_start, name_len)) {
            if (share_ascii_equals_ci(name_start, name_len, "cache-control") && share_has_no_store(value)) {
                no_store = 1;
            }
            continue;
        }
        result[written] = share_dup_range(header, strlen(header));
        if (result[written] == NULL) {
            st_http_share_free_strings(result, written);
            return -1;
        }
        ++written;
    }
    if (status != 101) {
        /* No shared cache keeps a copy, and the browser revalidates every reuse. */
        const char *cache = no_store ? "Cache-Control:private, no-store" : "Cache-Control:private, no-cache";
        result[written] = share_dup_range(cache, strlen(cache));
        if (result[written] == NULL) {
            st_http_share_free_strings(result, written);
            return -1;
        }
        ++written;
    }
    *out = result;
    *out_len = written;
    return 0;
}

/* ------------------------------------------------------------------------------------------------
 * GCRA (spec 9)
 */

typedef struct share_gcra_entry {
    char *key;
    long long tat;
    struct share_gcra_entry *next;
} share_gcra_entry;

struct st_http_share_gcra {
    pthread_mutex_t lock;
    long long interval;
    long long tolerance;
    size_t max_keys;
    size_t count;
    share_gcra_entry *buckets[ST_HTTP_SHARE_GCRA_BUCKETS];
};

st_http_share_gcra *st_http_share_gcra_create(long long interval_ms, long long burst, size_t max_keys)
{
    if (interval_ms <= 0 || burst <= 0 || max_keys == 0U) {
        return NULL;
    }
    st_http_share_gcra *limiter = (st_http_share_gcra *)calloc(1U, sizeof(*limiter));
    if (limiter == NULL) {
        return NULL;
    }
    pthread_mutex_init(&limiter->lock, NULL);
    limiter->interval = interval_ms;
    limiter->tolerance = (burst - 1) * interval_ms;
    limiter->max_keys = max_keys;
    return limiter;
}

static void share_gcra_clear_locked(st_http_share_gcra *limiter)
{
    for (size_t i = 0U; i < ST_HTTP_SHARE_GCRA_BUCKETS; ++i) {
        share_gcra_entry *entry = limiter->buckets[i];
        while (entry != NULL) {
            share_gcra_entry *next = entry->next;
            free(entry->key);
            free(entry);
            entry = next;
        }
        limiter->buckets[i] = NULL;
    }
    limiter->count = 0U;
}

void st_http_share_gcra_free(st_http_share_gcra *limiter)
{
    if (limiter == NULL) {
        return;
    }
    pthread_mutex_lock(&limiter->lock);
    share_gcra_clear_locked(limiter);
    pthread_mutex_unlock(&limiter->lock);
    pthread_mutex_destroy(&limiter->lock);
    free(limiter);
}

void st_http_share_gcra_reset(st_http_share_gcra *limiter)
{
    if (limiter == NULL) {
        return;
    }
    pthread_mutex_lock(&limiter->lock);
    share_gcra_clear_locked(limiter);
    pthread_mutex_unlock(&limiter->lock);
}

long long st_http_share_gcra_interval(const st_http_share_gcra *limiter)
{
    return limiter == NULL ? 0 : limiter->interval;
}

long long st_http_share_gcra_tolerance(const st_http_share_gcra *limiter)
{
    return limiter == NULL ? 0 : limiter->tolerance;
}

static size_t share_gcra_bucket(const char *key)
{
    uint32_t hash = 2166136261U;
    for (const unsigned char *p = (const unsigned char *)key; *p != '\0'; ++p) {
        hash ^= *p;
        hash *= 16777619U;
    }
    return hash % ST_HTTP_SHARE_GCRA_BUCKETS;
}

static share_gcra_entry *share_gcra_find_locked(st_http_share_gcra *limiter, const char *key)
{
    for (share_gcra_entry *entry = limiter->buckets[share_gcra_bucket(key)]; entry != NULL; entry = entry->next) {
        if (strcmp(entry->key, key) == 0) {
            return entry;
        }
    }
    return NULL;
}

/* An entry whose TAT is not after now says nothing a missing entry would not. */
static void share_gcra_evict_locked(st_http_share_gcra *limiter, long long now_ms)
{
    for (size_t i = 0U; i < ST_HTTP_SHARE_GCRA_BUCKETS; ++i) {
        share_gcra_entry **link = &limiter->buckets[i];
        while (*link != NULL) {
            share_gcra_entry *entry = *link;
            if (entry->tat <= now_ms) {
                *link = entry->next;
                free(entry->key);
                free(entry);
                --limiter->count;
            } else {
                link = &entry->next;
            }
        }
    }
}

static share_gcra_entry *share_gcra_add_locked(st_http_share_gcra *limiter, const char *key, long long now_ms)
{
    if (limiter->count >= limiter->max_keys) {
        share_gcra_evict_locked(limiter, now_ms);
        if (limiter->count >= limiter->max_keys) {
            return NULL; /* every entry still counts: refuse the new key, evict nothing valid */
        }
    }
    share_gcra_entry *entry = (share_gcra_entry *)calloc(1U, sizeof(*entry));
    char *copy = share_dup_range(key, strlen(key));
    if (entry == NULL || copy == NULL) {
        free(entry);
        free(copy);
        return NULL;
    }
    size_t bucket = share_gcra_bucket(key);
    entry->key = copy;
    entry->tat = now_ms;
    entry->next = limiter->buckets[bucket];
    limiter->buckets[bucket] = entry;
    ++limiter->count;
    return entry;
}

long long st_http_share_gcra_take(st_http_share_gcra *limiter, const char *key, long long now_ms)
{
    if (limiter == NULL || key == NULL) {
        return 1;
    }
    pthread_mutex_lock(&limiter->lock);
    share_gcra_entry *entry = share_gcra_find_locked(limiter, key);
    long long tat = entry == NULL ? now_ms : entry->tat;
    long long wait = tat - limiter->tolerance - now_ms;
    if (wait > 0) {
        pthread_mutex_unlock(&limiter->lock);
        long long seconds = (wait + 999LL) / 1000LL;
        return seconds < 1 ? 1 : seconds;
    }
    if (entry == NULL) {
        entry = share_gcra_add_locked(limiter, key, now_ms);
        if (entry == NULL) {
            pthread_mutex_unlock(&limiter->lock);
            return 1;
        }
    }
    entry->tat = (tat > now_ms ? tat : now_ms) + limiter->interval;
    pthread_mutex_unlock(&limiter->lock);
    return 0;
}

int st_http_share_gcra_set_tat(st_http_share_gcra *limiter, const char *key, long long tat_ms)
{
    if (limiter == NULL || key == NULL) {
        return -1;
    }
    pthread_mutex_lock(&limiter->lock);
    share_gcra_entry *entry = share_gcra_find_locked(limiter, key);
    if (entry == NULL) {
        entry = share_gcra_add_locked(limiter, key, LLONG_MIN);
    }
    if (entry != NULL) {
        entry->tat = tat_ms;
    }
    pthread_mutex_unlock(&limiter->lock);
    return entry == NULL ? -1 : 0;
}

static pthread_once_t share_limiters_once = PTHREAD_ONCE_INIT;
static st_http_share_gcra *share_exchange_limiter = NULL;
static st_http_share_gcra *share_request_limiter = NULL;

static void share_limiters_init(void)
{
    share_exchange_limiter = st_http_share_gcra_create(ST_HTTP_SHARE_EXCHANGE_INTERVAL_MS,
                                                       ST_HTTP_SHARE_EXCHANGE_BURST,
                                                       ST_HTTP_SHARE_LIMITER_MAX_KEYS);
    share_request_limiter = st_http_share_gcra_create(ST_HTTP_SHARE_REQUEST_INTERVAL_MS,
                                                      ST_HTTP_SHARE_REQUEST_BURST,
                                                      ST_HTTP_SHARE_LIMITER_MAX_KEYS);
}

st_http_share_gcra *st_http_share_exchange_limiter(void)
{
    pthread_once(&share_limiters_once, share_limiters_init);
    return share_exchange_limiter;
}

st_http_share_gcra *st_http_share_request_limiter(void)
{
    pthread_once(&share_limiters_once, share_limiters_init);
    return share_request_limiter;
}
