#include "url_decode.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int hex_value(unsigned char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

char *st_url_decode(const char *value, size_t len, size_t *decoded_len)
{
    if (decoded_len != NULL) *decoded_len = 0U;
    if (value == NULL || len == SIZE_MAX) return NULL;
    char *out = (char *)malloc(len + 1U);
    if (out == NULL) return NULL;
    size_t w = 0U;
    for (size_t i = 0U; i < len; ++i) {
        if (value[i] == '%' && len - i > 2U) {
            int high = hex_value((unsigned char)value[i + 1U]);
            int low = hex_value((unsigned char)value[i + 2U]);
            if (high >= 0 && low >= 0) {
                out[w++] = (char)((high << 4) | low);
                i += 2U;
                continue;
            }
        }
        out[w++] = value[i] == '+' ? ' ' : value[i];
    }
    out[w] = '\0';
    if (decoded_len != NULL) *decoded_len = w;
    return out;
}

char *st_url_decode_string(const char *value, size_t len)
{
    size_t decoded_len = 0U;
    char *decoded = st_url_decode(value, len, &decoded_len);
    if (decoded != NULL && memchr(decoded, '\0', decoded_len) != NULL) {
        free(decoded);
        return NULL;
    }
    return decoded;
}
