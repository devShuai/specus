#define _POSIX_C_SOURCE 200809L

#include "java_uri.h"

#include <limits.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <utf8proc.h>

/*
 * A port of java.net.URI.Parser (JDK 21) for parse(false), the path new URI(String) takes. Every
 * method keeps its Java name in a comment and its control flow, so the indices and the order of
 * the failures stay those of the JDK; Java's exceptions are a longjmp to the nearest handler, which
 * parseAuthority's try/catch around parseServer re-arms.
 */

/* A character class: bit c of low for c < 64, bit c - 64 of high for c < 128; bit 0 means escapes. */
typedef struct {
    uint64_t low;
    uint64_t high;
} uri_mask;

#define URI_ESCAPED 1ULL

typedef struct {
    uri_mask digit;
    uri_mask alpha;
    uri_mask alphanum;
    uri_mask alphanum_dash;
    uri_mask digit_dot;
    uri_mask hex;
    uri_mask uric;
    uri_mask path;
    uri_mask userinfo;
    uri_mask reg_name;
    uri_mask server;
    uri_mask server_percent;
    uri_mask scheme;
    uri_mask scope_id;
} uri_masks;

typedef struct {
    const uint16_t *s;
    int n;
    const uri_masks *m;
    jmp_buf *on_fail;
    char reason[96];
    int index;
    int ipv6_bytes;
    int scheme_end;
    int user_start;
    int user_end;
    int host_start;
    int host_end;
    int authority_start;
    int authority_end;
    int path_start;
    int path_end;
    int query_start;
    int query_end;
    int fragment_start;
    int fragment_end;
} uri_parser;

static void mask_add(uri_mask *mask, int c)
{
    if (c < 64) {
        mask->low |= 1ULL << c;
    } else {
        mask->high |= 1ULL << (c - 64);
    }
}

static uri_mask mask_of(const char *chars)
{
    uri_mask mask = {0ULL, 0ULL};
    for (; *chars != '\0'; ++chars) {
        mask_add(&mask, (unsigned char)*chars);
    }
    return mask;
}

static uri_mask mask_range(int first, int last)
{
    uri_mask mask = {0ULL, 0ULL};
    for (int c = first; c <= last; ++c) {
        mask_add(&mask, c);
    }
    return mask;
}

static uri_mask mask_or(uri_mask a, uri_mask b)
{
    uri_mask mask = {a.low | b.low, a.high | b.high};
    return mask;
}

static void build_masks(uri_masks *m)
{
    uri_mask escaped = {URI_ESCAPED, 0ULL};
    m->digit = mask_range('0', '9');
    m->alpha = mask_or(mask_range('A', 'Z'), mask_range('a', 'z'));
    m->alphanum = mask_or(m->digit, m->alpha);
    m->alphanum_dash = mask_or(m->alphanum, mask_of("-"));
    m->digit_dot = mask_or(m->digit, mask_of("."));
    m->hex = mask_or(m->digit, mask_or(mask_range('A', 'F'), mask_range('a', 'f')));
    uri_mask unreserved = mask_or(m->alphanum, mask_of("-_.!~*'()"));
    m->uric = mask_or(mask_or(mask_of(";/?:@&=+$,[]"), unreserved), escaped);
    uri_mask pchar = mask_or(mask_or(unreserved, escaped), mask_of(":@&=+$,"));
    m->path = mask_or(pchar, mask_of(";/"));
    m->userinfo = mask_or(mask_or(unreserved, escaped), mask_of(";:&=+$,"));
    m->reg_name = mask_or(mask_or(unreserved, escaped), mask_of("$,;:@&=+"));
    m->server = mask_or(mask_or(m->userinfo, m->alphanum_dash), mask_of(".:@[]"));
    m->server_percent = mask_or(m->server, mask_of("%"));
    m->scheme = mask_or(m->alphanum, mask_of("+-."));
    m->scope_id = mask_or(m->alphanum, mask_of("_."));
}

static _Noreturn void fail(uri_parser *p, const char *reason, int index)
{
    snprintf(p->reason, sizeof(p->reason), "%s", reason);
    p->index = index;
    longjmp(*p->on_fail, 1);
}

/* failExpecting */
static _Noreturn void fail_expecting(uri_parser *p, const char *expected, int index)
{
    char reason[96];
    snprintf(reason, sizeof(reason), "Expected %s", expected);
    fail(p, reason, index);
}

static int match(uint16_t c, uri_mask mask)
{
    if (c == 0) return 0;
    if (c < 64) return ((1ULL << c) & mask.low) != 0;
    if (c < 128) return ((1ULL << (c - 64)) & mask.high) != 0;
    return 0;
}

/* Character.isSpaceChar(char) and Character.isISOControl(char). */
static int space_char(uint16_t c)
{
    if (c >= 0xD800U && c <= 0xDFFFU) return 0;
    utf8proc_category_t category = utf8proc_category((utf8proc_int32_t)c);
    return category == UTF8PROC_CATEGORY_ZS || category == UTF8PROC_CATEGORY_ZL
        || category == UTF8PROC_CATEGORY_ZP;
}

static int iso_control(uint16_t c)
{
    return c <= 0x1FU || (c >= 0x7FU && c <= 0x9FU);
}

/* at(start, end, c) */
static int at(const uri_parser *p, int start, int end, uint16_t c)
{
    return start < end && p->s[start] == c;
}

/* at(start, end, s) */
static int at_text(const uri_parser *p, int start, int end, const char *text)
{
    int length = (int)strlen(text);
    if (length > end - start) return 0;
    for (int i = 0; i < length; ++i) {
        if (p->s[start + i] != (uint16_t)(unsigned char)text[i]) return 0;
    }
    return 1;
}

/* scan(start, end, c) */
static int scan_char(const uri_parser *p, int start, int end, uint16_t c)
{
    return start < end && p->s[start] == c ? start + 1 : start;
}

/* scan(start, end, err, stop): -1 at a character of err, the index of one of stop, or end. */
static int scan_text(const uri_parser *p, int start, int end, const char *err, const char *stop)
{
    int i = start;
    while (i < end) {
        uint16_t c = p->s[i];
        if (c != 0 && c < 128 && strchr(err, (int)c) != NULL) return -1;
        if (c != 0 && c < 128 && strchr(stop, (int)c) != NULL) break;
        ++i;
    }
    return i;
}

/* scanEscape */
static int scan_escape(uri_parser *p, int start, int n, uint16_t first)
{
    if (first == '%') {
        if (start + 3 <= n && match(p->s[start + 1], p->m->hex) && match(p->s[start + 2], p->m->hex)) {
            return start + 3;
        }
        fail(p, "Malformed escape pair", start);
    } else if (first > 128 && !space_char(first) && !iso_control(first)) {
        return start + 1;
    }
    return start;
}

/* scan(start, end, lowMask, highMask) */
static int scan_mask(uri_parser *p, int start, int end, uri_mask mask)
{
    int i = start;
    while (i < end) {
        uint16_t c = p->s[i];
        if (match(c, mask)) {
            ++i;
            continue;
        }
        if ((mask.low & URI_ESCAPED) != 0) {
            int q = scan_escape(p, i, end, c);
            if (q > i) {
                i = q;
                continue;
            }
        }
        break;
    }
    return i;
}

/* checkChars */
static void check_chars(uri_parser *p, int start, int end, uri_mask mask, const char *what)
{
    int i = scan_mask(p, start, end, mask);
    if (i < end) {
        char reason[96];
        snprintf(reason, sizeof(reason), "Illegal character in %s", what);
        fail(p, reason, i);
    }
}

/*
 * scanByte: a byte of at most 255. Integer.parseInt overflows past ten digits; Java's
 * NumberFormatException is caught where an IPv4 address is only tried (parseIPv4Address) and here
 * counts as a byte that is too large, which only changes the message inside an IPv6 literal.
 */
static int scan_byte(uri_parser *p, int start, int n)
{
    int q = scan_mask(p, start, n, p->m->digit);
    if (q <= start) return q;
    long long value = 0;
    for (int i = start; i < q; ++i) {
        value = value * 10 + (p->s[i] - '0');
        if (value > 255) return start;
    }
    return q;
}

/* scanIPv4Address */
static int scan_ipv4_address(uri_parser *p, int start, int n, int strict)
{
    int i = start;
    int q = start;
    int m = scan_mask(p, i, n, p->m->digit_dot);
    if (m <= i || (strict && m != n)) return -1;
    for (;;) {
        if ((q = scan_byte(p, i, m)) <= i) break;
        i = q;
        if ((q = scan_char(p, i, m, '.')) <= i) break;
        i = q;
        if ((q = scan_byte(p, i, m)) <= i) break;
        i = q;
        if ((q = scan_char(p, i, m, '.')) <= i) break;
        i = q;
        if ((q = scan_byte(p, i, m)) <= i) break;
        i = q;
        if ((q = scan_char(p, i, m, '.')) <= i) break;
        i = q;
        if ((q = scan_byte(p, i, m)) <= i) break;
        i = q;
        if (q < m) break;
        return q;
    }
    fail(p, "Malformed IPv4 address", q);
    return -1;
}

/* takeIPv4Address */
static int take_ipv4_address(uri_parser *p, int start, int n, const char *expected)
{
    int i = scan_ipv4_address(p, start, n, 1);
    if (i <= start) fail_expecting(p, expected, start);
    return i;
}

/* parseIPv4Address: an address only tried, so its failure is no failure. */
static int parse_ipv4_address(uri_parser *p, int start, int n)
{
    jmp_buf attempt;
    jmp_buf *outer = p->on_fail;
    int i;
    p->on_fail = &attempt;
    if (setjmp(attempt) == 0) {
        i = scan_ipv4_address(p, start, n, 0);
        p->on_fail = outer;
    } else {
        p->on_fail = outer;
        return -1;
    }
    if (i > start && i < n && p->s[i] != ':') {
        i = -1;
    }
    if (i > start) {
        p->host_start = start;
        p->host_end = i;
    }
    return i;
}

/* parseHostname */
static int parse_hostname(uri_parser *p, int start, int n)
{
    int i = start;
    int q;
    int label = -1;
    do {
        q = scan_mask(p, i, n, p->m->alphanum);
        if (q <= i) break;
        label = i;
        i = q;
        q = scan_mask(p, i, n, p->m->alphanum_dash);
        if (q > i) {
            if (p->s[q - 1] == '-') fail(p, "Illegal character in hostname", q - 1);
            i = q;
        }
        q = scan_char(p, i, n, '.');
        if (q <= i) break;
        i = q;
    } while (i < n);
    if (i < n && !at(p, i, n, ':')) fail(p, "Illegal character in hostname", i);
    if (label < 0) fail_expecting(p, "hostname", start);
    if (label > start && !match(p->s[label], p->m->alpha)) fail(p, "Illegal character in hostname", label);
    p->host_start = start;
    p->host_end = i;
    return i;
}

/* scanHexSeq */
static int scan_hex_seq(uri_parser *p, int start, int n)
{
    int i = start;
    int q = scan_mask(p, i, n, p->m->hex);
    if (q <= i) return -1;
    if (at(p, q, n, '.')) return -1;
    if (q > i + 4) fail(p, "IPv6 hexadecimal digit sequence too long", i);
    p->ipv6_bytes += 2;
    i = q;
    while (i < n) {
        if (!at(p, i, n, ':')) break;
        if (at(p, i + 1, n, ':')) break;
        ++i;
        q = scan_mask(p, i, n, p->m->hex);
        if (q <= i) fail_expecting(p, "digits for an IPv6 address", i);
        if (at(p, q, n, '.')) {
            --i;
            break;
        }
        if (q > i + 4) fail(p, "IPv6 hexadecimal digit sequence too long", i);
        p->ipv6_bytes += 2;
        i = q;
    }
    return i;
}

/* scanHexPost */
static int scan_hex_post(uri_parser *p, int start, int n)
{
    int i = start;
    if (i == n) return i;
    int q = scan_hex_seq(p, i, n);
    if (q > i) {
        i = q;
        if (at(p, i, n, ':')) {
            ++i;
            i = take_ipv4_address(p, i, n, "hex digits or IPv4 address");
            p->ipv6_bytes += 4;
        }
    } else {
        i = take_ipv4_address(p, i, n, "hex digits or IPv4 address");
        p->ipv6_bytes += 4;
    }
    return i;
}

/* parseIPv6Reference */
static int parse_ipv6_reference(uri_parser *p, int start, int n)
{
    int i = start;
    int compressed_zeros = 0;
    int q = scan_hex_seq(p, i, n);
    if (q > i) {
        i = q;
        if (at_text(p, i, n, "::")) {
            compressed_zeros = 1;
            i = scan_hex_post(p, i + 2, n);
        } else if (at(p, i, n, ':')) {
            i = take_ipv4_address(p, i + 1, n, "IPv4 address");
            p->ipv6_bytes += 4;
        }
    } else if (at_text(p, i, n, "::")) {
        compressed_zeros = 1;
        i = scan_hex_post(p, i + 2, n);
    }
    if (i < n) fail(p, "Malformed IPv6 address", start);
    if (p->ipv6_bytes > 16) fail(p, "IPv6 address too long", start);
    if (!compressed_zeros && p->ipv6_bytes < 16) fail(p, "IPv6 address too short", start);
    if (compressed_zeros && p->ipv6_bytes == 16) fail(p, "Malformed IPv6 address", start);
    return i;
}

/* parseServer */
static int parse_server(uri_parser *p, int start, int n)
{
    int i = start;
    int q = scan_text(p, i, n, "/?#", "@");
    if (q >= i && at(p, q, n, '@')) {
        check_chars(p, i, q, p->m->userinfo, "user info");
        p->user_start = i;
        p->user_end = q;
        i = q + 1;
    }
    if (at(p, i, n, '[')) {
        ++i;
        q = scan_text(p, i, n, "/?#", "]");
        if (q > i && at(p, q, n, ']')) {
            int r = scan_text(p, i, q, "", "%");
            if (r > i) {
                parse_ipv6_reference(p, i, r);
                if (r + 1 == q) fail(p, "scope id expected", -1);
                check_chars(p, r + 1, q, p->m->scope_id, "scope id");
            } else {
                parse_ipv6_reference(p, i, q);
            }
            p->host_start = i - 1;
            p->host_end = q + 1;
            i = q + 1;
        } else {
            fail_expecting(p, "closing bracket for IPv6 address", q);
        }
    } else {
        q = parse_ipv4_address(p, i, n);
        if (q <= i) q = parse_hostname(p, i, n);
        i = q;
    }
    if (at(p, i, n, ':')) {
        ++i;
        q = scan_text(p, i, n, "", "/");
        if (q > i) {
            check_chars(p, i, q, p->m->digit, "port number");
            long long port = 0;
            for (int k = i; k < q; ++k) {
                port = port * 10 + (p->s[k] - '0');
                if (port > INT_MAX) fail(p, "Malformed port number", i);
            }
            i = q;
        }
    }
    if (i < n) fail_expecting(p, "port number", i);
    return i;
}

/* parseAuthority */
static int parse_authority(uri_parser *p, int start, int n)
{
    int i = start;
    volatile int q = i;
    volatile int failed = 0;
    int bracketed = scan_text(p, i, n, "", "]") < n;
    int server_chars = scan_mask(p, i, n, bracketed ? p->m->server_percent : p->m->server) == n;
    int reg_end = scan_mask(p, i, n, p->m->reg_name);
    int reg_chars = reg_end == n;
    if (reg_chars && !server_chars) {
        p->authority_start = i;
        p->authority_end = n;
        return n;
    }
    if (server_chars) {
        jmp_buf attempt;
        jmp_buf *outer = p->on_fail;
        p->on_fail = &attempt;
        if (setjmp(attempt) == 0) {
            q = parse_server(p, i, n);
            if (q < n) fail_expecting(p, "end of authority", q);
            p->authority_start = i;
            p->authority_end = n;
            p->on_fail = outer;
        } else {
            p->on_fail = outer;
            p->user_start = p->user_end = -1;
            p->host_start = p->host_end = -1;
            failed = 1;
            q = i;
        }
    }
    if (q < n) {
        if (reg_chars) {
            p->authority_start = i;
            p->authority_end = n;
        } else if (failed) {
            longjmp(*p->on_fail, 1);
        } else {
            fail(p, "Illegal character in authority", server_chars ? q : reg_end);
        }
    }
    return n;
}

/* parseHierarchical */
static int parse_hierarchical(uri_parser *p, int start, int n)
{
    int i = start;
    if (at(p, i, n, '/') && at(p, i + 1, n, '/')) {
        i += 2;
        int q = scan_text(p, i, n, "", "/?#");
        if (q > i) {
            i = parse_authority(p, i, q);
        } else if (q >= n) {
            fail_expecting(p, "authority", i);
        }
    }
    int q = scan_text(p, i, n, "", "?#");
    check_chars(p, i, q, p->m->path, "path");
    p->path_start = i;
    p->path_end = q;
    i = q;
    if (at(p, i, n, '?')) {
        ++i;
        q = scan_text(p, i, n, "", "#");
        check_chars(p, i, q, p->m->uric, "query");
        p->query_start = i;
        p->query_end = q;
        i = q;
    }
    return i;
}

/* parse(false) */
static void parse(uri_parser *p)
{
    int n = p->n;
    int i = scan_text(p, 0, n, "/?#", ":");
    if (i >= 0 && at(p, i, n, ':')) {
        if (i == 0) fail_expecting(p, "scheme name", 0);
        check_chars(p, 0, 1, p->m->alpha, "scheme name");
        check_chars(p, 1, i, p->m->scheme, "scheme name");
        p->scheme_end = i;
        ++i;
        if (at(p, i, n, '/')) {
            i = parse_hierarchical(p, i, n);
        } else {
            int q = scan_text(p, i, n, "", "#");
            if (q <= i) fail_expecting(p, "scheme-specific part", i);
            check_chars(p, i, q, p->m->uric, "opaque part");
            i = q;
        }
    } else {
        i = parse_hierarchical(p, 0, n);
    }
    if (at(p, i, n, '#')) {
        check_chars(p, i + 1, n, p->m->uric, "fragment");
        p->fragment_start = i + 1;
        p->fragment_end = n;
        i = n;
    }
    if (i < n) fail(p, "end of URI", i);
}

static char *copy_range(const char *text, const size_t *offsets, int start, int end)
{
    if (start < 0 || end < start) return NULL;
    size_t length = offsets[end] - offsets[start];
    char *copy = (char *)malloc(length + 1U);
    if (copy != NULL) {
        memcpy(copy, text + offsets[start], length);
        copy[length] = '\0';
    }
    return copy;
}

void st_java_uri_free(st_java_uri *uri)
{
    if (uri == NULL) return;
    free(uri->error);
    free(uri->scheme);
    free(uri->user_info);
    free(uri->host);
    free(uri->raw_authority);
    free(uri->raw_path);
    free(uri->raw_query);
    free(uri->raw_fragment);
    memset(uri, 0, sizeof(*uri));
}

int st_java_uri_parse(const char *text, st_java_uri *uri)
{
    memset(uri, 0, sizeof(*uri));
    size_t length = strlen(text);
    /* At most one UTF-16 unit per byte. */
    uint16_t *units = (uint16_t *)malloc((length + 1U) * sizeof(uint16_t));
    size_t *offsets = (size_t *)malloc((length + 1U) * sizeof(size_t));
    if (units == NULL || offsets == NULL) {
        free(units);
        free(offsets);
        uri->error = strdup("out of memory");
        return -1;
    }
    int n = 0;
    for (size_t at_byte = 0U; at_byte < length;) {
        utf8proc_int32_t point = 0;
        utf8proc_ssize_t width = utf8proc_iterate((const utf8proc_uint8_t *)text + at_byte,
                                                  (utf8proc_ssize_t)(length - at_byte), &point);
        if (width <= 0) {
            free(units);
            free(offsets);
            uri->error = strdup("invalid UTF-8");
            return -1;
        }
        if (point >= 0x10000) {
            offsets[n] = at_byte;
            units[n++] = (uint16_t)(0xD800 + ((point - 0x10000) >> 10));
            offsets[n] = at_byte;
            units[n++] = (uint16_t)(0xDC00 + ((point - 0x10000) & 0x3FF));
        } else {
            offsets[n] = at_byte;
            units[n++] = (uint16_t)point;
        }
        at_byte += (size_t)width;
    }
    offsets[n] = length;
    uri_masks masks;
    build_masks(&masks);
    jmp_buf on_fail;
    uri_parser parser;
    memset(&parser, 0, sizeof(parser));
    parser.s = units;
    parser.n = n;
    parser.m = &masks;
    parser.on_fail = &on_fail;
    parser.index = -1;
    parser.scheme_end = -1;
    parser.user_start = parser.user_end = -1;
    parser.host_start = parser.host_end = -1;
    parser.authority_start = parser.authority_end = -1;
    parser.path_start = parser.path_end = -1;
    parser.query_start = parser.query_end = -1;
    parser.fragment_start = parser.fragment_end = -1;
    int rc = 0;
    if (setjmp(on_fail) == 0) {
        parse(&parser);
        uri->scheme = parser.scheme_end < 0 ? NULL : copy_range(text, offsets, 0, parser.scheme_end);
        uri->user_info = copy_range(text, offsets, parser.user_start, parser.user_end);
        uri->host = copy_range(text, offsets, parser.host_start, parser.host_end);
        uri->raw_authority = copy_range(text, offsets, parser.authority_start, parser.authority_end);
        uri->raw_path = copy_range(text, offsets, parser.path_start, parser.path_end);
        uri->raw_query = copy_range(text, offsets, parser.query_start, parser.query_end);
        uri->raw_fragment = copy_range(text, offsets, parser.fragment_start, parser.fragment_end);
    } else {
        int needed = parser.index >= 0
            ? snprintf(NULL, 0U, "%s at index %d: %s", parser.reason, parser.index, text)
            : snprintf(NULL, 0U, "%s: %s", parser.reason, text);
        uri->error = needed < 0 ? NULL : (char *)malloc((size_t)needed + 1U);
        if (uri->error != NULL) {
            if (parser.index >= 0) {
                snprintf(uri->error, (size_t)needed + 1U, "%s at index %d: %s", parser.reason, parser.index, text);
            } else {
                snprintf(uri->error, (size_t)needed + 1U, "%s: %s", parser.reason, text);
            }
        }
        rc = -1;
    }
    free(units);
    free(offsets);
    return rc;
}
