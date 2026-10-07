#define _POSIX_C_SOURCE 200809L

#include "traffic_capture.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <zlib.h>

/* Java TrafficInspectionService decodes at most capture-decode-max-bytes (1 MiB) per layer. */
#define ST_TRAFFIC_DECODE_MAX_BYTES (1024U * 1024U)
/* looksLikeText inspects this many leading bytes. */
#define ST_TRAFFIC_TEXT_SNIFF_BYTES 512U

int st_traffic_capture_enabled(void)
{
    const char *value = getenv("SPECUS_TRAFFIC_CAPTURE_DETAIL_ENABLED");
    return value != NULL && (strcmp(value, "1") == 0 || strcasecmp(value, "true") == 0
                             || strcasecmp(value, "yes") == 0);
}

size_t st_traffic_preview_bytes(void)
{
    const char *value = getenv("SPECUS_TRAFFIC_CAPTURE_PREVIEW_BYTES");
    if (value == NULL || *value == '\0') return ST_TRAFFIC_PREVIEW_BYTES_DEFAULT;
    char *end = NULL;
    long parsed = strtol(value, &end, 10);
    if (end == value || *end != '\0') return ST_TRAFFIC_PREVIEW_BYTES_DEFAULT;
    if (parsed < 0) return 0U;
    return parsed > (long)ST_TRAFFIC_PREVIEW_BYTES_MAX ? ST_TRAFFIC_PREVIEW_BYTES_MAX : (size_t)parsed;
}

/* The media type before any parameter, trimmed and lower-cased (HttpBodyTypeClassifier.mediaType). */
static void media_type(const char *content_type, char *out, size_t out_len)
{
    out[0] = '\0';
    if (content_type == NULL) return;
    const char *start = content_type;
    while (*start != '\0' && isspace((unsigned char)*start)) ++start;
    const char *end = strchr(start, ';');
    if (end == NULL) end = start + strlen(start);
    while (end > start && isspace((unsigned char)end[-1])) --end;
    size_t len = (size_t)(end - start);
    if (len >= out_len) len = out_len - 1U;
    for (size_t i = 0; i < len; ++i) out[i] = (char)tolower((unsigned char)start[i]);
    out[len] = '\0';
}

static int ends_with(const char *value, const char *suffix)
{
    size_t value_len = strlen(value);
    size_t suffix_len = strlen(suffix);
    return value_len >= suffix_len && strcmp(value + value_len - suffix_len, suffix) == 0;
}

const char *st_traffic_body_type(const char *content_type, long long body_bytes)
{
    if (body_bytes <= 0) return "empty";
    char media[256];
    media_type(content_type, media, sizeof(media));
    if (media[0] == '\0') return "binary";
    if (strcmp(media, "application/json") == 0 || ends_with(media, "+json")) return "json";
    if (strcmp(media, "text/html") == 0) return "html";
    if (strcmp(media, "application/xml") == 0 || strcmp(media, "text/xml") == 0 || ends_with(media, "+xml")) {
        return "xml";
    }
    if (strncmp(media, "image/", 6U) == 0) return "image";
    if (strncmp(media, "video/", 6U) == 0) return "video";
    if (strncmp(media, "audio/", 6U) == 0) return "audio";
    if (strcmp(media, "application/x-www-form-urlencoded") == 0 || strcmp(media, "multipart/form-data") == 0) {
        return "form";
    }
    if (strcmp(media, "application/javascript") == 0 || strcmp(media, "application/ecmascript") == 0
        || strcmp(media, "text/javascript") == 0 || strcmp(media, "text/ecmascript") == 0) {
        return "script";
    }
    if (strncmp(media, "text/", 5U) == 0) return "text";
    return "binary";
}

static const char *const traffic_supported_body_types[] = {
    "empty", "json", "html", "xml", "image", "video", "audio", "form", "script", "text", "binary"
};

const char *st_traffic_body_type_or_classify(const char *stored, const char *content_type, long long body_bytes)
{
    if (stored != NULL) {
        char normalized[32];
        media_type(stored, normalized, sizeof(normalized));
        for (size_t i = 0; i < sizeof(traffic_supported_body_types) / sizeof(traffic_supported_body_types[0]); ++i) {
            if (strcmp(normalized, traffic_supported_body_types[i]) == 0) return traffic_supported_body_types[i];
        }
    }
    return st_traffic_body_type(content_type, body_bytes);
}

const char *st_traffic_body_type_normalize(const char *value)
{
    if (value == NULL) return NULL;
    while (isspace((unsigned char)*value)) ++value;
    size_t len = strlen(value);
    while (len > 0U && isspace((unsigned char)value[len - 1U])) --len;
    for (size_t i = 0; i < sizeof(traffic_supported_body_types) / sizeof(traffic_supported_body_types[0]); ++i) {
        if (strlen(traffic_supported_body_types[i]) == len && strncasecmp(value, traffic_supported_body_types[i], len) == 0) {
            return traffic_supported_body_types[i];
        }
    }
    return NULL;
}

void st_traffic_hex_preview(const uint8_t *data, size_t len, size_t preview_bytes, char *out, size_t out_len)
{
    static const char hex[] = "0123456789ABCDEF";
    if (out_len == 0U) return;
    size_t count = len < preview_bytes ? len : preview_bytes;
    size_t used = 0U;
    for (size_t i = 0; data != NULL && i < count && used + (i == 0U ? 2U : 3U) < out_len; ++i) {
        if (i > 0U) out[used++] = ' ';
        out[used++] = hex[data[i] >> 4U];
        out[used++] = hex[data[i] & 0x0fU];
    }
    out[used] = '\0';
}

/* Appends one code point; returns how many UTF-16 units Java counts for what was appended. */
static size_t append_code_point(unsigned long cp, char *out, size_t out_len, size_t *used)
{
    char encoded[4];
    size_t encoded_len;
    size_t units = 1U;
    if ((cp < 0x20UL && cp != '\r' && cp != '\n' && cp != '\t') || (cp >= 0x7fUL && cp <= 0x9fUL)) {
        encoded[0] = '.';
        encoded_len = 1U;
    } else if (cp >= 0x10000UL) {
        /* Java sees a surrogate pair and replaces each half with '.'. */
        encoded[0] = '.';
        encoded[1] = '.';
        encoded_len = 2U;
        units = 2U;
    } else if (cp < 0x80UL) {
        encoded[0] = (char)cp;
        encoded_len = 1U;
    } else if (cp < 0x800UL) {
        encoded[0] = (char)(0xc0UL | (cp >> 6U));
        encoded[1] = (char)(0x80UL | (cp & 0x3fUL));
        encoded_len = 2U;
    } else {
        encoded[0] = (char)(0xe0UL | (cp >> 12U));
        encoded[1] = (char)(0x80UL | ((cp >> 6U) & 0x3fUL));
        encoded[2] = (char)(0x80UL | (cp & 0x3fUL));
        encoded_len = 3U;
    }
    if (*used + encoded_len >= out_len) return 0U;
    memcpy(out + *used, encoded, encoded_len);
    *used += encoded_len;
    return units;
}

/* The next code point of UTF-8 text, U+FFFD (one byte consumed) for a malformed sequence. */
static unsigned long next_code_point(const uint8_t *data, size_t len, size_t *offset)
{
    uint8_t lead = data[*offset];
    size_t need;
    unsigned long cp;
    unsigned long minimum;
    if (lead < 0x80U) {
        ++*offset;
        return lead;
    } else if (lead >= 0xc2U && lead <= 0xdfU) {
        need = 1U; cp = lead & 0x1fU; minimum = 0x80UL;
    } else if (lead >= 0xe0U && lead <= 0xefU) {
        need = 2U; cp = lead & 0x0fU; minimum = 0x800UL;
    } else if (lead >= 0xf0U && lead <= 0xf4U) {
        need = 3U; cp = lead & 0x07U; minimum = 0x10000UL;
    } else {
        ++*offset;
        return 0xfffdUL;
    }
    for (size_t i = 1; i <= need; ++i) {
        if (*offset + i >= len || (data[*offset + i] & 0xc0U) != 0x80U) {
            ++*offset;
            return 0xfffdUL;
        }
        cp = (cp << 6U) | (data[*offset + i] & 0x3fU);
    }
    if (cp < minimum || cp > 0x10ffffUL || (cp >= 0xd800UL && cp <= 0xdfffUL)) {
        ++*offset;
        return 0xfffdUL;
    }
    *offset += need + 1U;
    return cp;
}

/* Java sanitizeText(new String(data, UTF_8)), cut to max_units UTF-16 units. */
static void sanitize_utf8(const uint8_t *data, size_t len, size_t max_units, char *out, size_t out_len)
{
    if (out_len == 0U) return;
    size_t used = 0U;
    size_t units = 0U;
    for (size_t offset = 0U; data != NULL && offset < len && units < max_units;) {
        unsigned long cp = next_code_point(data, len, &offset);
        if (cp >= 0x10000UL && units + 1U == max_units) {
            /* Java's substring keeps the first '.' of the pair. */
            if (used + 1U < out_len) out[used++] = '.';
            break;
        }
        size_t added = append_code_point(cp, out, out_len, &used);
        if (added == 0U) break;
        units += added;
    }
    out[used] = '\0';
}

void st_traffic_tcp_text_preview(const uint8_t *data, size_t len, size_t preview_bytes, char *out, size_t out_len)
{
    size_t count = len < preview_bytes ? len : preview_bytes;
    sanitize_utf8(data, count, (size_t)-1, out, out_len);
}

/* Inflates at most limit bytes; 0 with *out set (possibly a prefix), -1 when nothing decoded. */
static int inflate_prefix(const uint8_t *data, size_t len, int window_bits, size_t limit,
                          uint8_t **out, size_t *out_len)
{
    *out = NULL;
    *out_len = 0U;
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    if (len > (size_t)UINT32_MAX || inflateInit2(&stream, window_bits) != Z_OK) return -1;
    uint8_t *buffer = (uint8_t *)malloc(limit == 0U ? 1U : limit);
    if (buffer == NULL) {
        inflateEnd(&stream);
        return -1;
    }
    stream.next_in = (Bytef *)data;
    stream.avail_in = (uInt)len;
    stream.next_out = buffer;
    stream.avail_out = (uInt)limit;
    int rc = Z_OK;
    while (stream.avail_out > 0U && rc == Z_OK) {
        rc = inflate(&stream, Z_NO_FLUSH);
    }
    size_t produced = limit - stream.avail_out;
    /* Complete, or cut at the limit like Java's readLimited. A corrupt stream, or one whose input
     * ends early (Java's EOFException), is not decoded at all: Java falls back to the raw bytes. */
    int complete = rc == Z_STREAM_END || (rc == Z_OK && stream.avail_out == 0U);
    inflateEnd(&stream);
    if (!complete) {
        free(buffer);
        return -1;
    }
    *out = buffer;
    *out_len = produced;
    return 0;
}

static int token_equals(const char *token, size_t len, const char *name)
{
    return strlen(name) == len && strncasecmp(token, name, len) == 0;
}

/*
 * Decodes the Content-Encoding layers, last applied first. Returns a malloc'd buffer, or NULL
 * when the body stays as it came (no encoding, an unknown one, or a decoding error). Inner layers
 * decode up to Java's 1 MiB; the outermost only as far as the preview can need (final_limit).
 */
static uint8_t *decode_content_encoding(const uint8_t *data,
                                        size_t len,
                                        const char *encoding,
                                        size_t final_limit,
                                        size_t *out_len)
{
    if (encoding == NULL) return NULL;
    char *tokens = strdup(encoding);
    if (tokens == NULL) return NULL;
    const char *items[16];
    size_t lengths[16];
    size_t count = 0U;
    for (char *cursor = tokens; count < 16U;) {
        char *comma = strchr(cursor, ',');
        char *end = comma == NULL ? cursor + strlen(cursor) : comma;
        char *start = cursor;
        while (start < end && isspace((unsigned char)*start)) ++start;
        while (end > start && isspace((unsigned char)end[-1])) --end;
        items[count] = start;
        lengths[count] = (size_t)(end - start);
        ++count;
        if (comma == NULL) break;
        cursor = comma + 1;
    }
    size_t outermost = count;
    for (size_t i = 0; i < count && outermost == count; ++i) {
        if (lengths[i] != 0U && !token_equals(items[i], lengths[i], "identity")) outermost = i;
    }
    uint8_t *current = NULL;
    size_t current_len = len;
    int decoded = 0;
    int failed = 0;
    for (size_t i = count; i-- > 0U && !failed;) {
        if (lengths[i] == 0U || token_equals(items[i], lengths[i], "identity")) continue;
        const uint8_t *input = current == NULL ? data : current;
        size_t limit = i == outermost && final_limit < ST_TRAFFIC_DECODE_MAX_BYTES
            ? final_limit : ST_TRAFFIC_DECODE_MAX_BYTES;
        uint8_t *next = NULL;
        size_t next_len = 0U;
        if (token_equals(items[i], lengths[i], "gzip") || token_equals(items[i], lengths[i], "x-gzip")) {
            failed = inflate_prefix(input, current_len, 16 + MAX_WBITS, limit, &next, &next_len) != 0;
        } else if (token_equals(items[i], lengths[i], "deflate") || token_equals(items[i], lengths[i], "x-deflate")) {
            failed = inflate_prefix(input, current_len, MAX_WBITS, limit, &next, &next_len) != 0
                && inflate_prefix(input, current_len, -MAX_WBITS, limit, &next, &next_len) != 0;
        } else {
            failed = 1;
        }
        if (failed) break;
        free(current);
        current = next;
        current_len = next_len;
        decoded = 1;
    }
    free(tokens);
    if (failed || !decoded) {
        free(current);
        return NULL;
    }
    *out_len = current_len;
    return current;
}

/* TrafficInspectionService.isTextBody, with its strict media-type pattern. */
static int text_media_type(const char *content_type)
{
    char media[256];
    media_type(content_type, media, sizeof(media));
    const char *slash = strchr(media, '/');
    if (media[0] == '\0' || slash == NULL || slash == media || slash[1] == '\0' || strchr(slash + 1, '/') != NULL) {
        return 0;
    }
    for (const char *p = media; *p != '\0'; ++p) {
        if (!isalnum((unsigned char)*p) && strchr("!#$&^_.+-/", *p) == NULL) return 0;
    }
    static const char *const exact[] = {
        "application/json", "application/xml", "application/x-www-form-urlencoded", "application/graphql",
        "application/javascript", "application/ecmascript", "application/x-yaml", "application/yaml"
    };
    if (strncmp(media, "text/", 5U) == 0 || ends_with(media, "+json") || ends_with(media, "+xml")) return 1;
    for (size_t i = 0; i < sizeof(exact) / sizeof(exact[0]); ++i) {
        if (strcmp(media, exact[i]) == 0) return 1;
    }
    return 0;
}

/* TrafficInspectionService.looksLikeText: no NUL and at most 10 % other controls in 512 bytes. */
static int looks_like_text(const uint8_t *data, size_t len)
{
    size_t inspected = len < ST_TRAFFIC_TEXT_SNIFF_BYTES ? len : ST_TRAFFIC_TEXT_SNIFF_BYTES;
    size_t controls = 0U;
    for (size_t i = 0; i < inspected; ++i) {
        if (data[i] == 0U) return 0;
        if (data[i] < 0x20U && data[i] != '\r' && data[i] != '\n' && data[i] != '\t') ++controls;
    }
    return inspected == 0U || controls * 10U <= inspected;
}

void st_traffic_http_text_preview(const uint8_t *data,
                                  size_t len,
                                  const char *content_type,
                                  const char *content_encoding,
                                  size_t preview_bytes,
                                  char *out,
                                  size_t out_len)
{
    if (out_len == 0U) return;
    out[0] = '\0';
    if (data == NULL || len == 0U || preview_bytes == 0U) return;
    /* Enough for the text check and for preview_bytes characters of up to three bytes each. */
    size_t needed = preview_bytes * 3U + 4U;
    if (needed < ST_TRAFFIC_TEXT_SNIFF_BYTES) needed = ST_TRAFFIC_TEXT_SNIFF_BYTES;
    size_t decoded_len = 0U;
    uint8_t *decoded = decode_content_encoding(data, len, content_encoding, needed, &decoded_len);
    const uint8_t *display = decoded == NULL ? data : decoded;
    size_t display_len = decoded == NULL ? len : decoded_len;
    if (text_media_type(content_type) || looks_like_text(display, display_len)) {
        sanitize_utf8(display, display_len, preview_bytes, out, out_len);
    }
    free(decoded);
}
