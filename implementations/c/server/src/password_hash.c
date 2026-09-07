#define _POSIX_C_SOURCE 200809L

#include "password_hash.h"

#include "crypto.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ST_PASSWORD_HASH_ALGORITHM "pbkdf2-sha256"
#define ST_PASSWORD_HASH_VERSION 1U
#define ST_PASSWORD_SALT_BYTES 16U
#define ST_PASSWORD_KEY_BYTES 32U
#define ST_PASSWORD_MATERIAL_MAX_BYTES 64U

static int password_secure_random(uint8_t *out, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    size_t offset = 0;
    while (offset < len) {
        ssize_t count = read(fd, out + offset, len - offset);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            close(fd);
            return -1;
        }
        offset += (size_t)count;
    }
    (void)close(fd);
    return 0;
}

static int password_is_blank(const char *value)
{
    if (value == NULL || *value == '\0') {
        return 1;
    }
    for (const unsigned char *cursor = (const unsigned char *)value; *cursor != '\0'; ++cursor) {
        if (!isspace(*cursor)) {
            return 0;
        }
    }
    return 1;
}

static int base64_value(unsigned char ch)
{
    if (ch >= 'A' && ch <= 'Z') {
        return ch - 'A';
    }
    if (ch >= 'a' && ch <= 'z') {
        return ch - 'a' + 26;
    }
    if (ch >= '0' && ch <= '9') {
        return ch - '0' + 52;
    }
    if (ch == '+') {
        return 62;
    }
    if (ch == '/') {
        return 63;
    }
    return -1;
}

static int base64_raw_encode(const uint8_t *data, size_t len, char *out, size_t out_len)
{
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t needed = (len / 3U) * 4U;
    size_t remainder = len % 3U;
    if (remainder != 0U) {
        needed += remainder + 1U;
    }
    if (out_len <= needed) {
        return -1;
    }
    size_t input = 0;
    size_t output = 0;
    while (input + 3U <= len) {
        uint32_t value = ((uint32_t)data[input] << 16U)
            | ((uint32_t)data[input + 1U] << 8U)
            | (uint32_t)data[input + 2U];
        out[output++] = alphabet[(value >> 18U) & 0x3fU];
        out[output++] = alphabet[(value >> 12U) & 0x3fU];
        out[output++] = alphabet[(value >> 6U) & 0x3fU];
        out[output++] = alphabet[value & 0x3fU];
        input += 3U;
    }
    if (remainder == 1U) {
        uint32_t value = (uint32_t)data[input] << 16U;
        out[output++] = alphabet[(value >> 18U) & 0x3fU];
        out[output++] = alphabet[(value >> 12U) & 0x3fU];
    } else if (remainder == 2U) {
        uint32_t value = ((uint32_t)data[input] << 16U) | ((uint32_t)data[input + 1U] << 8U);
        out[output++] = alphabet[(value >> 18U) & 0x3fU];
        out[output++] = alphabet[(value >> 12U) & 0x3fU];
        out[output++] = alphabet[(value >> 6U) & 0x3fU];
    }
    out[output] = '\0';
    return 0;
}

static int base64_raw_decode(const char *value, uint8_t *out, size_t out_len, size_t *written)
{
    if (value == NULL || written == NULL) {
        return -1;
    }
    size_t len = strlen(value);
    size_t remainder = len % 4U;
    if (len == 0U || remainder == 1U) {
        return -1;
    }
    size_t needed = (len / 4U) * 3U;
    if (remainder != 0U) {
        needed += remainder - 1U;
    }
    if (needed > out_len) {
        return -1;
    }
    size_t input = 0;
    size_t output = 0;
    while (input + 4U <= len) {
        int a = base64_value((unsigned char)value[input]);
        int b = base64_value((unsigned char)value[input + 1U]);
        int c = base64_value((unsigned char)value[input + 2U]);
        int d = base64_value((unsigned char)value[input + 3U]);
        if (a < 0 || b < 0 || c < 0 || d < 0) {
            return -1;
        }
        uint32_t combined = ((uint32_t)a << 18U) | ((uint32_t)b << 12U)
            | ((uint32_t)c << 6U) | (uint32_t)d;
        out[output++] = (uint8_t)(combined >> 16U);
        out[output++] = (uint8_t)(combined >> 8U);
        out[output++] = (uint8_t)combined;
        input += 4U;
    }
    if (remainder == 2U) {
        int a = base64_value((unsigned char)value[input]);
        int b = base64_value((unsigned char)value[input + 1U]);
        if (a < 0 || b < 0 || (b & 0x0f) != 0) {
            return -1;
        }
        out[output++] = (uint8_t)(((uint32_t)a << 2U) | ((uint32_t)b >> 4U));
    } else if (remainder == 3U) {
        int a = base64_value((unsigned char)value[input]);
        int b = base64_value((unsigned char)value[input + 1U]);
        int c = base64_value((unsigned char)value[input + 2U]);
        if (a < 0 || b < 0 || c < 0 || (c & 0x03) != 0) {
            return -1;
        }
        out[output++] = (uint8_t)(((uint32_t)a << 2U) | ((uint32_t)b >> 4U));
        out[output++] = (uint8_t)(((uint32_t)b << 4U) | ((uint32_t)c >> 2U));
    }
    *written = output;
    return 0;
}

static int password_hash_with_salt(const char *plaintext,
                                   const uint8_t *salt,
                                   size_t salt_len,
                                   unsigned int iterations,
                                   char *out,
                                   size_t out_len)
{
    uint8_t derived[ST_PASSWORD_KEY_BYTES];
    char salt_base64[ST_PASSWORD_SALT_BYTES * 2U + 1U];
    char key_base64[ST_PASSWORD_KEY_BYTES * 2U + 1U];
    if (password_is_blank(plaintext)
        || iterations < ST_PASSWORD_HASH_MIN_ITERATIONS
        || st_pbkdf2_hmac_sha256((const uint8_t *)plaintext,
                                 strlen(plaintext),
                                 salt,
                                 salt_len,
                                 iterations,
                                 derived,
                                 sizeof(derived)) != 0
        || base64_raw_encode(salt, salt_len, salt_base64, sizeof(salt_base64)) != 0
        || base64_raw_encode(derived, sizeof(derived), key_base64, sizeof(key_base64)) != 0) {
        memset(derived, 0, sizeof(derived));
        return -1;
    }
    int count = snprintf(out,
                         out_len,
                         "$%s$v=%u$i=%u$%s$%s",
                         ST_PASSWORD_HASH_ALGORITHM,
                         ST_PASSWORD_HASH_VERSION,
                         iterations,
                         salt_base64,
                         key_base64);
    memset(derived, 0, sizeof(derived));
    return count < 0 || (size_t)count >= out_len ? -1 : 0;
}

int st_password_hash(const char *plaintext, char out[ST_PASSWORD_HASH_MAX_LEN + 1U])
{
    if (out == NULL || password_is_blank(plaintext)) {
        return -1;
    }
    uint8_t salt[ST_PASSWORD_SALT_BYTES];
    if (password_secure_random(salt, sizeof(salt)) != 0) {
        return -1;
    }
    int rc = password_hash_with_salt(plaintext,
                                     salt,
                                     sizeof(salt),
                                     ST_PASSWORD_HASH_DEFAULT_ITERATIONS,
                                     out,
                                     ST_PASSWORD_HASH_MAX_LEN + 1U);
    memset(salt, 0, sizeof(salt));
    return rc;
}

static int copy_trimmed_hash(const char *stored_hash, char *out, size_t out_len)
{
    if (stored_hash == NULL || out == NULL || out_len == 0U) {
        return -1;
    }
    const char *start = stored_hash;
    while (*start != '\0' && isspace((unsigned char)*start)) {
        ++start;
    }
    const char *end = start + strlen(start);
    while (end > start && isspace((unsigned char)end[-1])) {
        --end;
    }
    size_t len = (size_t)(end - start);
    if (len == 0U || len >= out_len) {
        return -1;
    }
    memcpy(out, start, len);
    out[len] = '\0';
    return 0;
}

static int legacy_password_matches(const char *plaintext, const char *stored_hash)
{
    uint8_t actual[ST_SHA256_LEN];
    uint8_t expected[ST_SHA256_LEN];
    if (strlen(stored_hash) != ST_SHA256_HEX_LEN
        || st_hex_decode_32(stored_hash, expected) != 0) {
        return 0;
    }
    st_sha256((const uint8_t *)plaintext, strlen(plaintext), actual);
    int matches = st_constant_time_eq(actual, expected, sizeof(actual));
    memset(actual, 0, sizeof(actual));
    memset(expected, 0, sizeof(expected));
    return matches;
}

static int parse_password_hash(char *stored,
                               unsigned int *iterations,
                               uint8_t *salt,
                               size_t *salt_len,
                               uint8_t *key,
                               size_t *key_len)
{
    if (stored == NULL || stored[0] != '$') {
        return -1;
    }
    char *parts[5];
    char *cursor = stored + 1;
    for (size_t i = 0; i < 4U; ++i) {
        parts[i] = cursor;
        char *separator = strchr(cursor, '$');
        if (separator == NULL) {
            return -1;
        }
        *separator = '\0';
        cursor = separator + 1;
    }
    parts[4] = cursor;
    if (strchr(parts[4], '$') != NULL
        || strcmp(parts[0], ST_PASSWORD_HASH_ALGORITHM) != 0
        || strcmp(parts[1], "v=1") != 0
        || strncmp(parts[2], "i=", 2U) != 0
        || parts[2][2] == '\0') {
        return -1;
    }
    errno = 0;
    char *number_end = NULL;
    unsigned long parsed_iterations = strtoul(parts[2] + 2, &number_end, 10);
    if (errno != 0 || number_end == parts[2] + 2 || *number_end != '\0'
        || parsed_iterations < ST_PASSWORD_HASH_MIN_ITERATIONS
        || parsed_iterations > INT_MAX) {
        return -1;
    }
    if (base64_raw_decode(parts[3], salt, ST_PASSWORD_MATERIAL_MAX_BYTES, salt_len) != 0
        || *salt_len == 0U
        || base64_raw_decode(parts[4], key, ST_PASSWORD_MATERIAL_MAX_BYTES, key_len) != 0
        || *key_len == 0U) {
        return -1;
    }
    *iterations = (unsigned int)parsed_iterations;
    return 0;
}

int st_password_verify(const char *plaintext,
                       const char *stored_hash,
                       st_password_verification *verification)
{
    if (plaintext == NULL || verification == NULL) {
        return -1;
    }
    memset(verification, 0, sizeof(*verification));
    char stored[ST_PASSWORD_HASH_MAX_LEN + 1U];
    if (copy_trimmed_hash(stored_hash, stored, sizeof(stored)) != 0) {
        return 0;
    }
    if (stored[0] != '$') {
        verification->stored_is_legacy = 1;
        if (!legacy_password_matches(plaintext, stored)) {
            return 0;
        }
        verification->matches = 1;
        verification->needs_upgrade = 1;
        return st_password_hash(plaintext, verification->upgraded_hash);
    }

    unsigned int iterations = 0;
    uint8_t salt[ST_PASSWORD_MATERIAL_MAX_BYTES];
    uint8_t expected[ST_PASSWORD_MATERIAL_MAX_BYTES];
    uint8_t actual[ST_PASSWORD_MATERIAL_MAX_BYTES];
    size_t salt_len = 0;
    size_t key_len = 0;
    if (parse_password_hash(stored, &iterations, salt, &salt_len, expected, &key_len) != 0
        || st_pbkdf2_hmac_sha256((const uint8_t *)plaintext,
                                 strlen(plaintext),
                                 salt,
                                 salt_len,
                                 iterations,
                                 actual,
                                 key_len) != 0) {
        memset(salt, 0, sizeof(salt));
        memset(expected, 0, sizeof(expected));
        memset(actual, 0, sizeof(actual));
        return 0;
    }
    verification->matches = st_constant_time_eq(actual, expected, key_len);
    memset(salt, 0, sizeof(salt));
    memset(expected, 0, sizeof(expected));
    memset(actual, 0, sizeof(actual));
    if (!verification->matches || iterations >= ST_PASSWORD_HASH_DEFAULT_ITERATIONS) {
        return 0;
    }
    verification->needs_upgrade = 1;
    return st_password_hash(plaintext, verification->upgraded_hash);
}

int st_password_is_legacy_hash(const char *stored_hash)
{
    char stored[ST_PASSWORD_HASH_MAX_LEN + 1U];
    return copy_trimmed_hash(stored_hash, stored, sizeof(stored)) == 0 && stored[0] != '$';
}
