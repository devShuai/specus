#include "json.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static char *st_strdup_len(const char *value, size_t len)
{
    char *out = (char *)malloc(len + 1U);
    if (out == NULL) {
        return NULL;
    }
    memcpy(out, value, len);
    out[len] = '\0';
    return out;
}

static const char *skip_ws(const char *p)
{
    while (*p != '\0' && isspace((unsigned char)*p)) {
        ++p;
    }
    return p;
}

static const char *skip_json_string(const char *p)
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

static int key_equals(const char *start, const char *end, const char *key)
{
    size_t len = (size_t)(end - start);
    return strlen(key) == len && memcmp(start, key, len) == 0;
}

static const char *find_value(const char *json, const char *key)
{
    const char *p = json;
    while ((p = strchr(p, '"')) != NULL) {
        const char *key_start = p + 1;
        const char *key_end = skip_json_string(p);
        if (key_end == NULL) {
            return NULL;
        }
        if (key_equals(key_start, key_end - 1, key)) {
            const char *colon = skip_ws(key_end);
            if (*colon == ':') {
                return skip_ws(colon + 1);
            }
        }
        p = key_end;
    }
    return NULL;
}

char *st_json_escape(const char *value)
{
    if (value == NULL) {
        value = "";
    }
    size_t extra = 0;
    for (const unsigned char *p = (const unsigned char *)value; *p != '\0'; ++p) {
        if (*p == '"' || *p == '\\' || *p < 0x20U) {
            extra += 5U;
        }
    }
    size_t len = strlen(value);
    if (len > SIZE_MAX - extra - 1U) {
        return NULL;
    }
    char *out = (char *)malloc(len + extra + 1U);
    if (out == NULL) {
        return NULL;
    }
    char *w = out;
    static const char hex[] = "0123456789abcdef";
    for (const unsigned char *p = (const unsigned char *)value; *p != '\0'; ++p) {
        if (*p == '"' || *p == '\\') {
            *w++ = '\\';
            *w++ = (char)*p;
        } else if (*p < 0x20U) {
            *w++ = '\\';
            *w++ = 'u';
            *w++ = '0';
            *w++ = '0';
            *w++ = hex[*p >> 4];
            *w++ = hex[*p & 0x0fU];
        } else {
            *w++ = (char)*p;
        }
    }
    *w = '\0';
    return out;
}

static int append_utf8(char **out, size_t *len, size_t *cap, unsigned int codepoint)
{
    unsigned char bytes[4];
    size_t need;
    if (codepoint <= 0x7fU) {
        bytes[0] = (unsigned char)codepoint;
        need = 1;
    } else if (codepoint <= 0x7ffU) {
        bytes[0] = (unsigned char)(0xc0U | (codepoint >> 6));
        bytes[1] = (unsigned char)(0x80U | (codepoint & 0x3fU));
        need = 2;
    } else if (codepoint <= 0xffffU) {
        bytes[0] = (unsigned char)(0xe0U | (codepoint >> 12));
        bytes[1] = (unsigned char)(0x80U | ((codepoint >> 6) & 0x3fU));
        bytes[2] = (unsigned char)(0x80U | (codepoint & 0x3fU));
        need = 3;
    } else {
        bytes[0] = (unsigned char)(0xf0U | (codepoint >> 18));
        bytes[1] = (unsigned char)(0x80U | ((codepoint >> 12) & 0x3fU));
        bytes[2] = (unsigned char)(0x80U | ((codepoint >> 6) & 0x3fU));
        bytes[3] = (unsigned char)(0x80U | (codepoint & 0x3fU));
        need = 4;
    }
    if (*len + need + 1U > *cap) {
        size_t next = *cap == 0 ? 32U : *cap;
        while (next < *len + need + 1U) {
            if (next > SIZE_MAX / 2U) {
                return -1;
            }
            next *= 2U;
        }
        char *grown = (char *)realloc(*out, next);
        if (grown == NULL) {
            return -1;
        }
        *out = grown;
        *cap = next;
    }
    memcpy(*out + *len, bytes, need);
    *len += need;
    (*out)[*len] = '\0';
    return 0;
}

static int hex_value(char ch)
{
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }
    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }
    return -1;
}

char *st_json_get_string(const char *json, const char *key)
{
    const char *p = find_value(json, key);
    if (p == NULL || *p != '"') {
        return NULL;
    }
    ++p;
    char *out = NULL;
    size_t len = 0;
    size_t cap = 0;
    while (*p != '\0' && *p != '"') {
        unsigned char ch = (unsigned char)*p++;
        if (ch == '\\') {
            ch = (unsigned char)*p++;
            switch (ch) {
                case '"':
                case '\\':
                case '/':
                    break;
                case 'b':
                    ch = '\b';
                    break;
                case 'f':
                    ch = '\f';
                    break;
                case 'n':
                    ch = '\n';
                    break;
                case 'r':
                    ch = '\r';
                    break;
                case 't':
                    ch = '\t';
                    break;
                case 'u': {
                    unsigned int codepoint = 0;
                    for (int i = 0; i < 4; ++i) {
                        int hex = hex_value(*p++);
                        if (hex < 0) {
                            free(out);
                            return NULL;
                        }
                        codepoint = (codepoint << 4U) | (unsigned int)hex;
                    }
                    if (append_utf8(&out, &len, &cap, codepoint) != 0) {
                        free(out);
                        return NULL;
                    }
                    continue;
                }
                default:
                    free(out);
                    return NULL;
            }
        }
        if (append_utf8(&out, &len, &cap, ch) != 0) {
            free(out);
            return NULL;
        }
    }
    if (*p != '"') {
        free(out);
        return NULL;
    }
    if (out == NULL) {
        return st_strdup_len("", 0);
    }
    return out;
}

int st_json_get_i64(const char *json, const char *key, long long *out)
{
    const char *p = find_value(json, key);
    if (p == NULL) {
        return -1;
    }
    char *string_value = NULL;
    if (*p == '"') {
        string_value = st_json_get_string(json, key);
        if (string_value == NULL) {
            return -1;
        }
        p = string_value;
    }
    char *end = NULL;
    errno = 0;
    long long parsed = strtoll(p, &end, 10);
    int ok = end != p && errno != ERANGE;
    free(string_value);
    if (!ok) {
        return -1;
    }
    *out = parsed;
    return 0;
}

int st_json_get_int(const char *json, const char *key, int *out)
{
    long long parsed = 0;
    if (st_json_get_i64(json, key, &parsed) != 0 || parsed < INT_MIN || parsed > INT_MAX) {
        return -1;
    }
    *out = (int)parsed;
    return 0;
}

int st_json_get_bool(const char *json, const char *key, int *out)
{
    const char *p = find_value(json, key);
    if (p == NULL) {
        return -1;
    }
    if (strncmp(p, "true", 4) == 0 && !isalnum((unsigned char)p[4]) && p[4] != '_') {
        *out = 1;
        return 0;
    }
    if (strncmp(p, "false", 5) == 0 && !isalnum((unsigned char)p[5]) && p[5] != '_') {
        *out = 0;
        return 0;
    }
    char *string_value = NULL;
    if (*p == '"') {
        string_value = st_json_get_string(json, key);
        if (string_value == NULL) {
            return -1;
        }
        if (strcmp(string_value, "true") == 0 || strcmp(string_value, "1") == 0) {
            *out = 1;
            free(string_value);
            return 0;
        }
        if (strcmp(string_value, "false") == 0 || strcmp(string_value, "0") == 0) {
            *out = 0;
            free(string_value);
            return 0;
        }
        free(string_value);
        return -1;
    }
    int int_value = 0;
    if (st_json_get_int(json, key, &int_value) == 0 && (int_value == 0 || int_value == 1)) {
        *out = int_value;
        return 0;
    }
    return -1;
}
