#define _POSIX_C_SOURCE 200809L

#include "upstream_browser_headers.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *scheme;
    size_t scheme_len;
    const char *host;
    size_t host_len;
    long port;
    /* Path, query and fragment, from the end of the authority to the end of the text. */
    const char *rest;
    size_t rest_len;
} absolute_url;

static int ascii_ieq(const char *left, size_t left_len, const char *right)
{
    size_t right_len = strlen(right);
    if (left_len != right_len) return 0;
    for (size_t i = 0; i < left_len; ++i) {
        if (tolower((unsigned char)left[i]) != tolower((unsigned char)right[i])) return 0;
    }
    return 1;
}

static int hex_digit(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

/*
 * What java.net.URI refuses outside the authority: controls, space, the excluded ASCII
 * characters and a '%' that does not start an escape. Bytes from 0x80 up are its "other"
 * characters and pass.
 */
static int uri_text_valid(const char *text, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)text[i];
        if (c <= 0x20U || c == 0x7fU || strchr("\"<>\\^`{|}", (int)c) != NULL) return 0;
        if (c == '%' && (i + 2U >= len || !hex_digit(text[i + 1U]) || !hex_digit(text[i + 2U]))) return 0;
    }
    return 1;
}

static int host_valid(const char *host, size_t len)
{
    if (len == 0U) return 0;
    if (host[0] == '[') {
        if (len < 3U || host[len - 1U] != ']') return 0;
        for (size_t i = 1; i + 1U < len; ++i) {
            if (!hex_digit(host[i]) && host[i] != ':' && host[i] != '.') return 0;
        }
        return 1;
    }
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)host[i];
        if (!isalnum(c) && c != '-' && c != '.') return 0;
    }
    return 1;
}

/*
 * A server-based absolute URL as java.net.URI reads one (scheme "://" [userinfo "@"] host
 * [":" port]); anything else, including a registry-based authority, has no host.
 */
static int parse_absolute_url(const char *text, size_t len, absolute_url *out)
{
    memset(out, 0, sizeof(*out));
    out->port = -1;
    size_t scheme_len = 0U;
    while (scheme_len < len && text[scheme_len] != ':') ++scheme_len;
    if (scheme_len == 0U || scheme_len + 3U > len || memcmp(text + scheme_len, "://", 3U) != 0
        || !isalpha((unsigned char)text[0])) return -1;
    for (size_t i = 1; i < scheme_len; ++i) {
        unsigned char c = (unsigned char)text[i];
        if (!isalnum(c) && c != '+' && c != '-' && c != '.') return -1;
    }
    const char *authority = text + scheme_len + 3U;
    const char *end = text + len;
    const char *authority_end = authority;
    while (authority_end < end && *authority_end != '/' && *authority_end != '?' && *authority_end != '#') {
        ++authority_end;
    }
    const char *host = authority;
    for (const char *cursor = authority; cursor < authority_end; ++cursor) {
        if (*cursor == '@') host = cursor + 1;
    }
    const char *host_end = host;
    if (host < authority_end && *host == '[') {
        while (host_end < authority_end && *host_end != ']') ++host_end;
        if (host_end == authority_end) return -1;
        ++host_end;
    } else {
        while (host_end < authority_end && *host_end != ':') ++host_end;
    }
    if (!host_valid(host, (size_t)(host_end - host))) return -1;
    if (host_end < authority_end) {
        if (*host_end != ':') return -1;
        long port = 0;
        for (const char *digit = host_end + 1; digit < authority_end; ++digit) {
            if (!isdigit((unsigned char)*digit) || port > 9999999L) return -1;
            port = port * 10L + (*digit - '0');
        }
        /* "host:" names no port; Java then reports -1 as well. */
        out->port = host_end + 1 < authority_end ? port : -1;
    }
    if (!uri_text_valid(authority_end, (size_t)(end - authority_end))) return -1;
    out->scheme = text;
    out->scheme_len = scheme_len;
    out->host = host;
    out->host_len = (size_t)(host_end - host);
    out->rest = authority_end;
    out->rest_len = (size_t)(end - authority_end);
    return 0;
}

static void trim(const char **text, size_t *len)
{
    while (*len > 0U && isspace((unsigned char)(*text)[0])) {
        ++*text;
        --*len;
    }
    while (*len > 0U && isspace((unsigned char)(*text)[*len - 1U])) --*len;
}

int st_upstream_origin_of(const char *target_base_url, char *out, size_t out_len)
{
    if (out == NULL || out_len == 0U) return -1;
    out[0] = '\0';
    if (target_base_url == NULL) return -1;
    const char *text = target_base_url;
    size_t len = strlen(text);
    trim(&text, &len);
    absolute_url url;
    if (len == 0U || parse_absolute_url(text, len, &url) != 0) return -1;
    const char *scheme = NULL;
    if (ascii_ieq(url.scheme, url.scheme_len, "http") || ascii_ieq(url.scheme, url.scheme_len, "ws")) {
        scheme = "http";
    } else if (ascii_ieq(url.scheme, url.scheme_len, "https") || ascii_ieq(url.scheme, url.scheme_len, "wss")) {
        scheme = "https";
    } else {
        return -1;
    }
    int written = url.port > 0
        ? snprintf(out, out_len, "%s://%.*s:%ld", scheme, (int)url.host_len, url.host, url.port)
        : snprintf(out, out_len, "%s://%.*s", scheme, (int)url.host_len, url.host);
    if (written < 0 || (size_t)written >= out_len) {
        out[0] = '\0';
        return -1;
    }
    return 0;
}

/*
 * The browser's user info is dropped rather than carried over as Java's URI constructor does:
 * browsers never send it in a Referer, and Go's client drops it too.
 */
char *st_upstream_rewrite_referer(const char *referer, const char *origin)
{
    const char *text = referer == NULL ? "" : referer;
    size_t len = strlen(text);
    trim(&text, &len);
    absolute_url url;
    int absolute = parse_absolute_url(text, len, &url) == 0;
    size_t origin_len = strlen(origin);
    size_t rest_len = absolute ? url.rest_len : 1U;
    char *rewritten = (char *)malloc(origin_len + rest_len + 1U);
    if (rewritten == NULL) return NULL;
    memcpy(rewritten, origin, origin_len);
    memcpy(rewritten + origin_len, absolute ? url.rest : "/", rest_len);
    rewritten[origin_len + rest_len] = '\0';
    return rewritten;
}

static char *header_line(const char *name, size_t name_len, const char *value)
{
    size_t value_len = strlen(value);
    char *line = (char *)malloc(name_len + 1U + value_len + 1U);
    if (line == NULL) return NULL;
    memcpy(line, name, name_len);
    line[name_len] = ':';
    memcpy(line + name_len + 1U, value, value_len + 1U);
    return line;
}

int st_upstream_browser_headers_rewrite(char **headers, size_t headers_len, const char *target_base_url)
{
    char origin[ST_UPSTREAM_ORIGIN_MAX];
    if (headers == NULL || headers_len == 0U
        || st_upstream_origin_of(target_base_url, origin, sizeof(origin)) != 0) return 0;
    for (size_t i = 0; i < headers_len; ++i) {
        const char *header = headers[i];
        const char *separator = header == NULL ? NULL : strchr(header, ':');
        if (separator == NULL || separator == header) continue;
        size_t name_len = (size_t)(separator - header);
        const char *value = separator + 1;
        char *replacement = NULL;
        if (ascii_ieq(header, name_len, "Origin")) {
            replacement = header_line(header, name_len, origin);
        } else if (ascii_ieq(header, name_len, "Referer")) {
            char *referer = st_upstream_rewrite_referer(value, origin);
            replacement = referer == NULL ? NULL : header_line(header, name_len, referer);
            free(referer);
        } else if (ascii_ieq(header, name_len, "Sec-Fetch-Site")) {
            size_t value_len = strlen(value);
            trim(&value, &value_len);
            if (!ascii_ieq(value, value_len, "cross-site")) continue;
            replacement = header_line(header, name_len, "same-origin");
        } else {
            continue;
        }
        if (replacement == NULL) return -1;
        free(headers[i]);
        headers[i] = replacement;
    }
    return 0;
}
