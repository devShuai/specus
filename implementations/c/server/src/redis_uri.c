#define _POSIX_C_SOURCE 200809L

#include "redis_uri.h"

#include "java_uri.h"

#include <ctype.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define ST_REDIS_DEFAULT_PORT 6379
#define ST_REDIS_DEFAULT_SENTINEL_PORT 26379

__attribute__((format(printf, 3, 4)))
static int uri_fail(char *error, size_t error_len, const char *format, ...)
{
    if (error != NULL && error_len > 0U) {
        va_list arguments;
        va_start(arguments, format);
        (void)vsnprintf(error, error_len, format, arguments);
        va_end(arguments);
    }
    return -1;
}

static int uri_copy(char *out, size_t out_len, const char *value, size_t value_len)
{
    if (value_len >= out_len) return -1;
    memcpy(out, value, value_len);
    out[value_len] = '\0';
    return 0;
}

static int uri_hex(int c)
{
    return isdigit(c) ? c - '0' : tolower(c) - 'a' + 10;
}

/*
 * java.net.URI's getters (decode(s, true)): every %XX escape outside square brackets becomes its
 * byte. A NULL component stays NULL. -1 for an escaped NUL, which a C string cannot carry.
 */
static int uri_decode(const char *raw, char **out)
{
    *out = NULL;
    if (raw == NULL) return 0;
    size_t len = strlen(raw);
    char *decoded = (char *)malloc(len + 1U);
    if (decoded == NULL) return -1;
    size_t used = 0U;
    int bracketed = 0;
    for (size_t i = 0U; i < len; ++i) {
        unsigned char c = (unsigned char)raw[i];
        if (c == '[') bracketed = 1;
        else if (bracketed && c == ']') bracketed = 0;
        if (c == '%' && !bracketed) {
            if (len - i < 3U || !isxdigit((unsigned char)raw[i + 1U]) || !isxdigit((unsigned char)raw[i + 2U])) {
                free(decoded);
                return -1;
            }
            c = (unsigned char)(uri_hex((unsigned char)raw[i + 1U]) * 16 + uri_hex((unsigned char)raw[i + 2U]));
            i += 2U;
            if (c == 0U) {
                free(decoded);
                return -1;
            }
        }
        decoded[used++] = (char)c;
    }
    decoded[used] = '\0';
    *out = decoded;
    return 0;
}

/* Integer.parseInt for ASCII text: an optional sign, then decimal digits within int range. */
static int uri_java_int(const char *text, int *out)
{
    const char *cursor = text;
    int negative = 0;
    if (*cursor == '+' || *cursor == '-') {
        negative = *cursor == '-';
        ++cursor;
    }
    if (*cursor == '\0') return -1;
    long long value = 0;
    for (; *cursor != '\0'; ++cursor) {
        if (*cursor < '0' || *cursor > '9') return -1;
        value = value * 10 + (*cursor - '0');
        if (value > (long long)INT_MAX + 1LL) return -1;
    }
    if (negative) value = -value;
    if (value < INT_MIN || value > INT_MAX) return -1;
    *out = (int)value;
    return 0;
}

/* getHost() keeps the brackets of an IPv6 literal; the connection takes the address without them. */
static int uri_unbracket(const char *host, char *out, size_t out_len)
{
    size_t len = strlen(host);
    if (len >= 2U && host[0] == '[' && host[len - 1U] == ']') return uri_copy(out, out_len, host + 1, len - 2U);
    return uri_copy(out, out_len, host, len);
}

/* The port of a server-based authority: -1 without one (none, or "host:"), else its value. */
static int uri_server_port(const st_java_uri *uri)
{
    const char *cursor = uri->raw_authority;
    if (cursor == NULL) return -1;
    if (uri->user_info != NULL) cursor += strlen(uri->user_info) + 1U;
    cursor += strlen(uri->host);
    if (*cursor != ':' || cursor[1] == '\0') return -1;
    int port = -1;
    /* java.net.URI accepted digits only, at most Integer.MAX_VALUE. */
    return uri_java_int(cursor + 1, &port) == 0 ? port : -1;
}

/*
 * Lettuce's HostAndPort.parse: "[v6]:port", "[v6]", "host:port" or a bare host, where text with
 * two or more colons is an unbracketed IPv6 literal. port is -1 when none is given.
 */
static int uri_host_and_port(const char *text, char *host, size_t host_len, int *port)
{
    const char *host_start = text;
    size_t host_size = strlen(text);
    const char *port_text = NULL;
    *port = -1;
    if (text[0] == '[') {
        const char *colon = strchr(text, ':');
        const char *close = strrchr(text, ']');
        if (colon == NULL || close == NULL || close < colon) return -1;
        host_start = text + 1;
        host_size = (size_t)(close - host_start);
        if (close[1] != '\0') {
            if (close[1] != ':') return -1;
            for (const char *digit = close + 2; *digit != '\0'; ++digit)
                if (!isdigit((unsigned char)*digit)) return -1;
            port_text = close + 2;
        }
    } else {
        const char *colon = strchr(text, ':');
        if (colon != NULL && strchr(colon + 1, ':') == NULL) {
            host_size = (size_t)(colon - text);
            port_text = colon + 1;
        }
    }
    if (port_text != NULL && *port_text != '\0') {
        int value = 0;
        if (*port_text == '+' || uri_java_int(port_text, &value) != 0 || value < 0 || value > 65535) return -1;
        *port = value;
    }
    if (host_size == 0U) return -1;
    return uri_copy(host, host_len, host_start, host_size);
}

/*
 * RedisURI.parseTimeout on the lower-cased parameter: leading digits, then a unit (ns, us, ms, s,
 * m, h, d; anything else means ms). Long.parseLong, Duration's exact arithmetic and the final
 * non-negative check can fail startup; the value itself is replaced by the command timeout.
 */
static int uri_check_timeout(const char *value)
{
    size_t digits = 0U;
    while (isdigit((unsigned char)value[digits])) ++digits;
    if (digits == 0U) return 0;
    long long amount = 0;
    for (size_t i = 0U; i < digits; ++i) {
        int digit = value[i] - '0';
        if (amount > (LLONG_MAX - digit) / 10) return -1;
        amount = amount * 10 + digit;
    }
    const char *unit = value + digits;
    long long factor = strcasecmp(unit, "m") == 0 ? 60LL
        : strcasecmp(unit, "h") == 0 ? 3600LL
        : strcasecmp(unit, "d") == 0 ? 86400LL : 1LL;
    if (amount > LLONG_MAX / factor) return -1;
    if (strcasecmp(unit, "us") == 0) {
        /* Duration.ofNanos(us * 1000) wraps silently; a negative result fails RedisURI.setTimeout. */
        uint64_t nanos = (uint64_t)amount * 1000U;
        if (nanos > (uint64_t)LLONG_MAX) return -1;
    }
    return 0;
}

static int uri_starts(const char *text, const char *prefix, int ignore_case)
{
    size_t len = strlen(prefix);
    return ignore_case ? strncasecmp(text, prefix, len) == 0 : strncmp(text, prefix, len) == 0;
}

/* RedisURI's query loop: StringTokenizer(query, "&;"), each known parameter by prefix. */
static int uri_apply_query(char *query, st_redis_uri *out, char *error, size_t error_len)
{
    char *state = NULL;
    for (char *token = strtok_r(query, "&;", &state); token != NULL; token = strtok_r(NULL, "&;", &state)) {
        const char *value = strchr(token, '=');
        value = value == NULL ? "" : value + 1;
        if (uri_starts(token, "timeout=", 1) && uri_check_timeout(value) != 0)
            return uri_fail(error, error_len, "invalid timeout parameter");
        if (uri_starts(token, "database=", 1) || uri_starts(token, "db=", 0)) {
            size_t digits = 0U;
            while (isdigit((unsigned char)value[digits])) ++digits;
            if (digits > 0U) {
                char number[16];
                int database = 0;
                if (digits >= sizeof(number)) return uri_fail(error, error_len, "invalid database parameter");
                memcpy(number, value, digits);
                number[digits] = '\0';
                if (uri_java_int(number, &database) != 0)
                    return uri_fail(error, error_len, "invalid database parameter");
                out->database = database;
            }
        }
        if (uri_starts(token, "clientname=", 1) && *value != '\0'
            && uri_copy(out->client_name, sizeof(out->client_name), value, strlen(value)) != 0)
            return uri_fail(error, error_len, "clientName is too long");
        if (uri_starts(token, "libraryname=", 1) && *value != '\0') {
            if (strchr(value, ' ') != NULL) return uri_fail(error, error_len, "Library name must not contain spaces");
            if (uri_copy(out->library_name, sizeof(out->library_name), value, strlen(value)) != 0)
                return uri_fail(error, error_len, "libraryName is too long");
        }
        if (uri_starts(token, "libraryversion=", 1) && *value != '\0') {
            if (strchr(value, ' ') != NULL)
                return uri_fail(error, error_len, "Library version must not contain spaces");
            if (uri_copy(out->library_version, sizeof(out->library_version), value, strlen(value)) != 0)
                return uri_fail(error, error_len, "libraryVersion is too long");
        }
        if (uri_starts(token, "verifypeer=", 1) && *value != '\0') {
            /* SslVerifyMode.valueOf(value.toUpperCase()) */
            if (strcasecmp(value, "NONE") == 0) out->verify = ST_REDIS_VERIFY_NONE;
            else if (strcasecmp(value, "CA") == 0) out->verify = ST_REDIS_VERIFY_CA;
            else if (strcasecmp(value, "FULL") == 0) out->verify = ST_REDIS_VERIFY_FULL;
            else return uri_fail(error, error_len, "verifyPeer must be NONE, CA or FULL");
        }
        if (uri_starts(token, "sentinelmasterid=", 1) && *value != '\0'
            && uri_copy(out->master_id, sizeof(out->master_id), value, strlen(value)) != 0)
            return uri_fail(error, error_len, "sentinelMasterId is too long");
    }
    return 0;
}

/* configureSentinel's host list: one server-based host, or the comma-separated authority. */
static int uri_sentinels(const st_java_uri *uri, const char *authority, st_redis_uri *out,
                         char *error, size_t error_len)
{
    if (uri->host != NULL && uri->host[0] != '\0') {
        int port = uri_server_port(uri);
        if (port > 65535) return uri_fail(error, error_len, "Port out of range: %d", port);
        if (uri_unbracket(uri->host, out->sentinels[0].host, sizeof(out->sentinels[0].host)) != 0)
            return uri_fail(error, error_len, "Sentinel host is too long");
        out->sentinels[0].port = port < 0 ? ST_REDIS_DEFAULT_SENTINEL_PORT : port;
        out->sentinel_count = 1U;
        return 0;
    }
    if (authority == NULL || authority[0] == '\0')
        return uri_fail(error, error_len, "Invalid URI, cannot get host part");
    const char *hosts = strrchr(authority, '@');
    hosts = hosts == NULL ? authority : hosts + 1;
    /* String.split(","): empty entries fail, except trailing ones, which split drops. */
    size_t len = strlen(hosts);
    while (len > 0U && hosts[len - 1U] == ',') --len;
    size_t start = 0U;
    while (start <= len) {
        size_t end = start;
        while (end < len && hosts[end] != ',') ++end;
        char entry[ST_REDIS_URI_HOST_BYTES + 16U];
        int port = -1;
        if (out->sentinel_count >= ST_REDIS_URI_MAX_SENTINELS)
            return uri_fail(error, error_len, "at most %u Sentinels are supported", ST_REDIS_URI_MAX_SENTINELS);
        st_redis_endpoint *sentinel = &out->sentinels[out->sentinel_count];
        if (uri_copy(entry, sizeof(entry), hosts + start, end - start) != 0
            || uri_host_and_port(entry, sentinel->host, sizeof(sentinel->host), &port) != 0)
            return uri_fail(error, error_len, "invalid Sentinel host or port (entry %zu)", out->sentinel_count + 1U);
        sentinel->port = port < 0 ? ST_REDIS_DEFAULT_SENTINEL_PORT : port;
        ++out->sentinel_count;
        if (end >= len) break;
        start = end + 1U;
    }
    return 0;
}

/* configureStandalone: getHost() and a positive port, else the whole authority as Lettuce takes it. */
static int uri_server(const st_java_uri *uri, const char *authority, st_redis_uri *out,
                      char *error, size_t error_len)
{
    if (uri->host != NULL && uri->host[0] != '\0') {
        int port = uri_server_port(uri);
        if (port > 65535) return uri_fail(error, error_len, "Port out of range: %d", port);
        if (uri_unbracket(uri->host, out->server.host, sizeof(out->server.host)) != 0)
            return uri_fail(error, error_len, "host is too long");
        out->server.port = port > 0 ? port : ST_REDIS_DEFAULT_PORT;
        return 0;
    }
    if (authority == NULL || authority[0] == '\0')
        return uri_fail(error, error_len, "Invalid URI, cannot get host or socket part");
    /*
     * A registry-based authority (java.net.URI could not read a host name, e.g. one with '_'):
     * Lettuce connects to everything after the last '@' as the host name, ":port" included, on
     * port 6379. C does the same, so such a URI works or fails as it does for Java.
     */
    const char *host = strrchr(authority, '@');
    host = host == NULL ? authority : host + 1;
    if (*host == '\0') return uri_fail(error, error_len, "Host must not be empty");
    if (uri_copy(out->server.host, sizeof(out->server.host), host, strlen(host)) != 0)
        return uri_fail(error, error_len, "host is too long");
    out->server.port = ST_REDIS_DEFAULT_PORT;
    return 0;
}

/* The user information, as buildRedisUriFromUri splits it; an empty password means no AUTH. */
static int uri_credentials(const char *info, st_redis_uri *out, char *error, size_t error_len)
{
    if (info == NULL || *info == '\0') return 0;
    const char *password = info;
    const char *username = NULL;
    size_t username_len = 0U;
    if (info[0] == ':') {
        password = info + 1;
    } else {
        const char *colon = strchr(info, ':');
        if (colon != NULL && colon > info) {
            username = info;
            username_len = (size_t)(colon - info);
            password = colon + 1;
        }
    }
    if (*password == '\0') return 0;
    if (uri_copy(out->password, sizeof(out->password), password, strlen(password)) != 0
        || (username != NULL && uri_copy(out->username, sizeof(out->username), username, username_len) != 0))
        return uri_fail(error, error_len, "user name or password is too long");
    return 0;
}

static int uri_build(const st_java_uri *uri, st_redis_uri *out, char *error, size_t error_len)
{
    const char *scheme = uri->scheme;
    int socket = 0;
    if (scheme == NULL) return uri_fail(error, error_len, "URI scheme must not be null");
    if (strcmp(scheme, "redis-sentinel") == 0) {
        out->sentinel = 1;
    } else if (strcmp(scheme, "rediss-sentinel") == 0) {
        out->sentinel = 1;
        out->tls = 1;
    } else if (strcmp(scheme, "rediss") == 0 || strcmp(scheme, "redis+ssl") == 0) {
        out->tls = 1;
    } else if (strcmp(scheme, "redis-socket") == 0 || strcmp(scheme, "redis+socket") == 0) {
        socket = 1;
    } else if (strcmp(scheme, "redis+tls") == 0) {
        return uri_fail(error, error_len,
                        "redis+tls:// asks for STARTTLS, which Redis does not negotiate; use rediss://");
    } else if (strcmp(scheme, "redis") != 0) {
        return uri_fail(error, error_len, "Scheme %.32s not supported", scheme);
    }
    char *authority = NULL;
    char *user_info = NULL;
    char *path = NULL;
    char *query = NULL;
    char *fragment = NULL;
    char *fallback_info = NULL;
    int rc = -1;
    if (uri_decode(uri->raw_authority, &authority) != 0 || uri_decode(uri->user_info, &user_info) != 0
        || uri_decode(uri->raw_path, &path) != 0 || uri_decode(uri->raw_query, &query) != 0
        || uri_decode(uri->raw_fragment, &fragment) != 0) {
        (void)uri_fail(error, error_len, "the URI holds an escaped NUL byte (%%00)");
        goto done;
    }
    if (out->sentinel) {
        if (uri_sentinels(uri, authority, out, error, error_len) != 0) goto done;
        if (fragment != NULL && fragment[0] != '\0'
            && uri_copy(out->master_id, sizeof(out->master_id), fragment, strlen(fragment)) != 0) {
            (void)uri_fail(error, error_len, "sentinelMasterId is too long");
            goto done;
        }
    } else if (socket) {
        if (path == NULL || path[0] == '\0') {
            (void)uri_fail(error, error_len,
                           "Cannot build a RedisURI. One of the following must be provided Host, Socket or Sentinel");
            goto done;
        }
        if (uri_copy(out->socket_path, sizeof(out->socket_path), path, strlen(path)) != 0) {
            (void)uri_fail(error, error_len, "socket path is too long");
            goto done;
        }
    } else if (uri_server(uri, authority, out, error, error_len) != 0) {
        goto done;
    }
    /* getUserInfo(), or for a registry-based authority what precedes its last '@'. */
    const char *info = user_info;
    if ((info == NULL || info[0] == '\0') && authority != NULL) {
        const char *at = strrchr(authority, '@');
        if (at != NULL && at > authority) {
            fallback_info = strndup(authority, (size_t)(at - authority));
            if (fallback_info == NULL) {
                (void)uri_fail(error, error_len, "out of memory");
                goto done;
            }
            info = fallback_info;
        }
    }
    if (uri_credentials(info, out, error, error_len) != 0) goto done;
    if (!socket && path != NULL && path[0] != '\0' && path[1] != '\0') {
        int database = 0;
        if (uri_java_int(path + 1, &database) != 0) {
            (void)uri_fail(error, error_len, "the path must be a database number");
            goto done;
        }
        if (database < 0) {
            (void)uri_fail(error, error_len, "Invalid database number: %d", database);
            goto done;
        }
        out->database = database;
    }
    if (query != NULL && query[0] != '\0' && uri_apply_query(query, out, error, error_len) != 0) goto done;
    if (out->sentinel && out->master_id[0] == '\0') {
        (void)uri_fail(error, error_len, "URI must contain the sentinelMasterId");
        goto done;
    }
    rc = 0;
done:
    free(authority);
    free(user_info);
    free(path);
    free(query);
    free(fragment);
    free(fallback_info);
    return rc;
}

int st_redis_uri_parse(const char *text, st_redis_uri *uri, char *error, size_t error_len)
{
    memset(uri, 0, sizeof(*uri));
    uri->verify = ST_REDIS_VERIFY_FULL;
    if (error != NULL && error_len > 0U) error[0] = '\0';
    if (text == NULL || text[0] == '\0') return uri_fail(error, error_len, "URI must not be empty");
    st_java_uri parsed;
    if (st_java_uri_parse(text, &parsed) != 0) {
        /* URISyntaxException's message ends with ": <input>"; the input may hold a password. */
        size_t len = parsed.error == NULL ? 0U : strlen(parsed.error);
        size_t text_len = strlen(text);
        if (len >= text_len + 2U && strcmp(parsed.error + len - text_len, text) == 0) len -= text_len + 2U;
        int written = len > 0U ? (int)(len > 200U ? 200U : len) : 0;
        (void)uri_fail(error, error_len, "%.*s", written, written > 0 ? parsed.error : "");
        if (written == 0) (void)uri_fail(error, error_len, "not a valid URI");
        st_java_uri_free(&parsed);
        memset(uri, 0, sizeof(*uri));
        return -1;
    }
    int rc = uri_build(&parsed, uri, error, error_len);
    st_java_uri_free(&parsed);
    if (rc != 0) {
        memset(uri, 0, sizeof(*uri));
        uri->verify = ST_REDIS_VERIFY_FULL;
    }
    return rc;
}
