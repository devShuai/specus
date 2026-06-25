#include "crypto.h"

#include <string.h>

typedef struct {
    uint32_t state[5];
    uint64_t bit_len;
    uint8_t buffer[64];
    size_t buffer_len;
} sha1_ctx;

typedef struct {
    uint32_t state[8];
    uint64_t bit_len;
    uint8_t buffer[64];
    size_t buffer_len;
} sha256_ctx;

static uint32_t rotr(uint32_t value, uint32_t bits)
{
    return (value >> bits) | (value << (32U - bits));
}

static uint32_t rotl(uint32_t value, uint32_t bits)
{
    return (value << bits) | (value >> (32U - bits));
}

static uint32_t load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24)
        | ((uint32_t)p[1] << 16)
        | ((uint32_t)p[2] << 8)
        | (uint32_t)p[3];
}

static void store_be64(uint8_t *p, uint64_t value)
{
    for (int i = 7; i >= 0; --i) {
        p[i] = (uint8_t)(value & 0xffU);
        value >>= 8;
    }
}

static void sha1_transform(sha1_ctx *ctx, const uint8_t block[64])
{
    uint32_t w[80];
    for (int i = 0; i < 16; ++i) {
        w[i] = load_be32(block + (size_t)i * 4U);
    }
    for (int i = 16; i < 80; ++i) {
        w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    uint32_t a = ctx->state[0];
    uint32_t b = ctx->state[1];
    uint32_t c = ctx->state[2];
    uint32_t d = ctx->state[3];
    uint32_t e = ctx->state[4];

    for (int i = 0; i < 80; ++i) {
        uint32_t f;
        uint32_t k_value;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k_value = 0x5a827999U;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k_value = 0x6ed9eba1U;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k_value = 0x8f1bbcdcU;
        } else {
            f = b ^ c ^ d;
            k_value = 0xca62c1d6U;
        }
        uint32_t temp = rotl(a, 5) + f + e + k_value + w[i];
        e = d;
        d = c;
        c = rotl(b, 30);
        b = a;
        a = temp;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}

static void sha1_init(sha1_ctx *ctx)
{
    ctx->state[0] = 0x67452301U;
    ctx->state[1] = 0xefcdab89U;
    ctx->state[2] = 0x98badcfeU;
    ctx->state[3] = 0x10325476U;
    ctx->state[4] = 0xc3d2e1f0U;
    ctx->bit_len = 0;
    ctx->buffer_len = 0;
}

static void sha1_update(sha1_ctx *ctx, const uint8_t *data, size_t len)
{
    ctx->bit_len += (uint64_t)len * 8U;
    while (len > 0) {
        size_t space = sizeof(ctx->buffer) - ctx->buffer_len;
        size_t copy = len < space ? len : space;
        memcpy(ctx->buffer + ctx->buffer_len, data, copy);
        ctx->buffer_len += copy;
        data += copy;
        len -= copy;

        if (ctx->buffer_len == sizeof(ctx->buffer)) {
            sha1_transform(ctx, ctx->buffer);
            ctx->buffer_len = 0;
        }
    }
}

static void sha1_final(sha1_ctx *ctx, uint8_t out[ST_SHA1_LEN])
{
    ctx->buffer[ctx->buffer_len++] = 0x80U;
    if (ctx->buffer_len > 56) {
        while (ctx->buffer_len < 64) {
            ctx->buffer[ctx->buffer_len++] = 0;
        }
        sha1_transform(ctx, ctx->buffer);
        ctx->buffer_len = 0;
    }
    while (ctx->buffer_len < 56) {
        ctx->buffer[ctx->buffer_len++] = 0;
    }
    store_be64(ctx->buffer + 56, ctx->bit_len);
    sha1_transform(ctx, ctx->buffer);

    for (int i = 0; i < 5; ++i) {
        out[(size_t)i * 4U] = (uint8_t)(ctx->state[i] >> 24);
        out[(size_t)i * 4U + 1U] = (uint8_t)(ctx->state[i] >> 16);
        out[(size_t)i * 4U + 2U] = (uint8_t)(ctx->state[i] >> 8);
        out[(size_t)i * 4U + 3U] = (uint8_t)ctx->state[i];
    }
}

static const uint32_t k[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

static void sha256_transform(sha256_ctx *ctx, const uint8_t block[64])
{
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = load_be32(block + (size_t)i * 4U);
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = ctx->state[0];
    uint32_t b = ctx->state[1];
    uint32_t c = ctx->state[2];
    uint32_t d = ctx->state[3];
    uint32_t e = ctx->state[4];
    uint32_t f = ctx->state[5];
    uint32_t g = ctx->state[6];
    uint32_t h = ctx->state[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t temp1 = h + s1 + ch + k[i] + w[i];
        uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

static void sha256_init(sha256_ctx *ctx)
{
    ctx->state[0] = 0x6a09e667U;
    ctx->state[1] = 0xbb67ae85U;
    ctx->state[2] = 0x3c6ef372U;
    ctx->state[3] = 0xa54ff53aU;
    ctx->state[4] = 0x510e527fU;
    ctx->state[5] = 0x9b05688cU;
    ctx->state[6] = 0x1f83d9abU;
    ctx->state[7] = 0x5be0cd19U;
    ctx->bit_len = 0;
    ctx->buffer_len = 0;
}

static void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len)
{
    ctx->bit_len += (uint64_t)len * 8U;
    while (len > 0) {
        size_t space = sizeof(ctx->buffer) - ctx->buffer_len;
        size_t copy = len < space ? len : space;
        memcpy(ctx->buffer + ctx->buffer_len, data, copy);
        ctx->buffer_len += copy;
        data += copy;
        len -= copy;

        if (ctx->buffer_len == sizeof(ctx->buffer)) {
            sha256_transform(ctx, ctx->buffer);
            ctx->buffer_len = 0;
        }
    }
}

static void sha256_final(sha256_ctx *ctx, uint8_t out[ST_SHA256_LEN])
{
    ctx->buffer[ctx->buffer_len++] = 0x80U;
    if (ctx->buffer_len > 56) {
        while (ctx->buffer_len < 64) {
            ctx->buffer[ctx->buffer_len++] = 0;
        }
        sha256_transform(ctx, ctx->buffer);
        ctx->buffer_len = 0;
    }
    while (ctx->buffer_len < 56) {
        ctx->buffer[ctx->buffer_len++] = 0;
    }
    store_be64(ctx->buffer + 56, ctx->bit_len);
    sha256_transform(ctx, ctx->buffer);

    for (int i = 0; i < 8; ++i) {
        out[(size_t)i * 4U] = (uint8_t)(ctx->state[i] >> 24);
        out[(size_t)i * 4U + 1U] = (uint8_t)(ctx->state[i] >> 16);
        out[(size_t)i * 4U + 2U] = (uint8_t)(ctx->state[i] >> 8);
        out[(size_t)i * 4U + 3U] = (uint8_t)ctx->state[i];
    }
}

void st_sha1(const uint8_t *data, size_t len, uint8_t out[ST_SHA1_LEN])
{
    sha1_ctx ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, data, len);
    sha1_final(&ctx, out);
}

void st_sha256(const uint8_t *data, size_t len, uint8_t out[ST_SHA256_LEN])
{
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, out);
}

void st_hmac_sha256(const uint8_t *key, size_t key_len,
                    const uint8_t *data, size_t len,
                    uint8_t out[ST_SHA256_LEN])
{
    uint8_t normalized_key[ST_SHA256_LEN];
    uint8_t block[64];
    uint8_t inner_hash[ST_SHA256_LEN];

    if (key_len > sizeof(block)) {
        st_sha256(key, key_len, normalized_key);
        key = normalized_key;
        key_len = sizeof(normalized_key);
    }

    memset(block, 0x36, sizeof(block));
    for (size_t i = 0; i < key_len; ++i) {
        block[i] ^= key[i];
    }

    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, block, sizeof(block));
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, inner_hash);

    memset(block, 0x5c, sizeof(block));
    for (size_t i = 0; i < key_len; ++i) {
        block[i] ^= key[i];
    }

    sha256_init(&ctx);
    sha256_update(&ctx, block, sizeof(block));
    sha256_update(&ctx, inner_hash, sizeof(inner_hash));
    sha256_final(&ctx, out);

    memset(normalized_key, 0, sizeof(normalized_key));
    memset(inner_hash, 0, sizeof(inner_hash));
    memset(block, 0, sizeof(block));
}

static int hex_digit(char ch)
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

int st_hex_decode_32(const char *hex, uint8_t out[ST_SHA256_LEN])
{
    if (hex == NULL || strlen(hex) != ST_SHA256_HEX_LEN) {
        return -1;
    }
    for (size_t i = 0; i < ST_SHA256_LEN; ++i) {
        int high = hex_digit(hex[i * 2U]);
        int low = hex_digit(hex[i * 2U + 1U]);
        if (high < 0 || low < 0) {
            return -1;
        }
        out[i] = (uint8_t)((high << 4) | low);
    }
    return 0;
}

void st_hex_encode(const uint8_t *data, size_t len, char *out)
{
    static const char alphabet[] = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) {
        out[i * 2U] = alphabet[(data[i] >> 4) & 0x0fU];
        out[i * 2U + 1U] = alphabet[data[i] & 0x0fU];
    }
    out[len * 2U] = '\0';
}

int st_constant_time_eq(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}
