#include "decompression_limits.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#ifdef ST_HAVE_BROTLI_ENCODER
#include <brotli/encode.h>
#endif

static int compress_payload(const uint8_t *input,
                            size_t input_len,
                            int window_bits,
                            uint8_t **out,
                            size_t *out_len)
{
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    if (input_len > UINT_MAX || deflateInit2(&stream,
                                             Z_BEST_COMPRESSION,
                                             Z_DEFLATED,
                                             window_bits,
                                             8,
                                             Z_DEFAULT_STRATEGY) != Z_OK) {
        return -1;
    }
    uLong bound = deflateBound(&stream, (uLong)input_len);
    uint8_t *buffer = (uint8_t *)malloc((size_t)bound);
    if (buffer == NULL) {
        deflateEnd(&stream);
        return -1;
    }
    stream.next_in = (Bytef *)input;
    stream.avail_in = (uInt)input_len;
    stream.next_out = buffer;
    stream.avail_out = (uInt)bound;
    int status = deflate(&stream, Z_FINISH);
    if (status != Z_STREAM_END) {
        free(buffer);
        deflateEnd(&stream);
        return -1;
    }
    *out_len = (size_t)stream.total_out;
    *out = buffer;
    deflateEnd(&stream);
    return 0;
}

static int expect_round_trip(st_decompression_format format, int window_bits)
{
    static const char fragment[] = "the quick brown fox. ";
    size_t fragment_len = sizeof(fragment) - 1U;
    size_t plain_len = fragment_len * 2000U;
    uint8_t *plain = (uint8_t *)malloc(plain_len);
    if (plain == NULL) {
        return 1;
    }
    for (size_t offset = 0; offset < plain_len; offset += fragment_len) {
        memcpy(plain + offset, fragment, fragment_len);
    }
    uint8_t *compressed = NULL;
    size_t compressed_len = 0U;
    uint8_t *decoded = NULL;
    size_t decoded_len = 0U;
    int failed = compress_payload(plain, plain_len, window_bits, &compressed, &compressed_len) != 0
        || st_decompress_bounded(compressed, compressed_len, format, &decoded, &decoded_len)
            != ST_DECOMPRESSION_OK
        || decoded_len != plain_len
        || memcmp(decoded, plain, plain_len) != 0;
    free(decoded);
    free(compressed);
    free(plain);
    if (failed) {
        fprintf(stderr, "bounded decompression round trip failed for format %d\n", (int)format);
        return 1;
    }
    return 0;
}

static int expect_exact_allowance(void)
{
    size_t plain_len = ST_DECOMPRESSION_MIN_ALLOWANCE_BYTES;
    uint8_t *plain = (uint8_t *)malloc(plain_len);
    if (plain == NULL) {
        return 1;
    }
    memset(plain, 'x', plain_len);
    uint8_t *compressed = NULL;
    size_t compressed_len = 0U;
    uint8_t *decoded = NULL;
    size_t decoded_len = 0U;
    int failed = compress_payload(plain, plain_len, 16 + MAX_WBITS, &compressed, &compressed_len) != 0
        || st_decompression_limit_for(compressed_len) != plain_len
        || st_decompress_bounded(compressed,
                                 compressed_len,
                                 ST_DECOMPRESSION_GZIP,
                                 &decoded,
                                 &decoded_len) != ST_DECOMPRESSION_OK
        || decoded_len != plain_len;
    free(decoded);
    free(compressed);
    free(plain);
    if (failed) {
        fprintf(stderr, "exact decompression allowance was rejected\n");
        return 1;
    }
    return 0;
}

static int expect_bomb_rejected(void)
{
    size_t plain_len = 32U * 1024U * 1024U;
    uint8_t *plain = (uint8_t *)calloc(plain_len, 1U);
    if (plain == NULL) {
        return 1;
    }
    uint8_t *compressed = NULL;
    size_t compressed_len = 0U;
    if (compress_payload(plain, plain_len, 16 + MAX_WBITS, &compressed, &compressed_len) != 0) {
        free(plain);
        return 1;
    }
    free(plain);
    uint8_t *decoded = NULL;
    size_t decoded_len = 0U;
    st_decompression_result result = st_decompress_bounded(compressed,
                                                           compressed_len,
                                                           ST_DECOMPRESSION_GZIP,
                                                           &decoded,
                                                           &decoded_len);
    free(compressed);
    free(decoded);
    if (result != ST_DECOMPRESSION_LIMIT_EXCEEDED || decoded_len != 0U) {
        fprintf(stderr, "decompression bomb was not rejected by the ratio limit: result=%d\n", result);
        return 1;
    }
    return 0;
}

/*
 * RFC 7932 written out by hand, so the decoder is checked without an encoder: WBITS 16 (one 0
 * bit), a meta-block that is not last with 4 nibbles of MLEN-1 = 11 and ISUNCOMPRESSED, padding,
 * the 12 bytes as they are, and a last, empty meta-block (ISLAST, ISLASTEMPTY).
 */
static const uint8_t brotli_hello[] = {
    0xB0U, 0x00U, 0x10U, 'h', 'e', 'l', 'l', 'o', ' ', 'b', 'r', 'o', 't', 'l', 'i', 0x03U
};

#ifdef ST_HAVE_BROTLI_ENCODER
/* body brotli-compressed by libbrotlienc; NULL when it fails. */
static uint8_t *brotli_compress(const uint8_t *body, size_t body_len, size_t *out_len)
{
    size_t capacity = BrotliEncoderMaxCompressedSize(body_len);
    uint8_t *out = (uint8_t *)malloc(capacity == 0U ? 64U : capacity);
    *out_len = capacity == 0U ? 64U : capacity;
    if (out != NULL && BrotliEncoderCompress(5, BROTLI_DEFAULT_WINDOW, BROTLI_MODE_GENERIC, body_len, body,
                                             out_len, out) != BROTLI_TRUE) {
        free(out);
        out = NULL;
    }
    return out;
}
#endif

/*
 * Content-Encoding br, which Java reads with org.brotli:dec under the same DecompressionLimits:
 * decoded when the build has libbrotlidec, and never decoded (INVALID, so a body stays as stored)
 * when it has not.
 */
static int expect_brotli(void)
{
    uint8_t *out = NULL;
    size_t out_len = 0U;
    st_decompression_result rc = st_decompress_bounded(brotli_hello, sizeof(brotli_hello), ST_DECOMPRESSION_BROTLI,
                                                       &out, &out_len);
#ifndef ST_HAVE_BROTLI
    int ok = st_decompression_brotli_supported() == 0 && rc == ST_DECOMPRESSION_INVALID && out == NULL;
    free(out);
    out = NULL;
    ok = ok && st_decompress_brotli_prefix(brotli_hello, sizeof(brotli_hello), 5U, &out, &out_len)
        == ST_DECOMPRESSION_INVALID && out == NULL;
    free(out);
    if (!ok) {
        fprintf(stderr, "br was decoded by a build without libbrotlidec\n");
        return 1;
    }
    printf("br: built without libbrotlidec, left as stored\n");
    return 0;
#else
    int ok = st_decompression_brotli_supported() == 1 && rc == ST_DECOMPRESSION_OK && out_len == 12U
        && memcmp(out, "hello brotli", 12U) == 0;
    free(out);
    out = NULL;
    /* A preview reads a prefix, as Java's readLimited. */
    ok = ok && st_decompress_brotli_prefix(brotli_hello, sizeof(brotli_hello), 5U, &out, &out_len)
        == ST_DECOMPRESSION_OK && out_len == 5U && memcmp(out, "hello", 5U) == 0;
    free(out);
    out = NULL;
    /* Input that ends before the stream does is not decoded (Java's EOFException). */
    ok = ok && st_decompress_bounded(brotli_hello, sizeof(brotli_hello) - 1U, ST_DECOMPRESSION_BROTLI, &out,
                                     &out_len) == ST_DECOMPRESSION_INVALID && out == NULL;
    if (!ok) {
        fprintf(stderr, "br decoding mismatch\n");
        return 1;
    }
#ifdef ST_HAVE_BROTLI_ENCODER
    /* A bomb: 32 MiB of zeros in a few bytes stops at the ratio limit. */
    size_t plain_len = 32U * 1024U * 1024U;
    uint8_t *plain = (uint8_t *)calloc(plain_len, 1U);
    size_t compressed_len = 0U;
    uint8_t *compressed = plain == NULL ? NULL : brotli_compress(plain, plain_len, &compressed_len);
    ok = compressed != NULL
        && st_decompress_bounded(compressed, compressed_len, ST_DECOMPRESSION_BROTLI, &out, &out_len)
        == ST_DECOMPRESSION_LIMIT_EXCEEDED && out == NULL && out_len == 0U;
    free(compressed);
    /* A body of 256 KiB that does not compress much round trips whole. */
    size_t text_len = 256U * 1024U;
    uint32_t state = 2463534242U;
    for (size_t i = 0U; ok && i < text_len; ++i) {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        plain[i] = (uint8_t)('a' + state % 26U);
    }
    compressed = ok ? brotli_compress(plain, text_len, &compressed_len) : NULL;
    ok = ok && compressed != NULL
        && st_decompress_bounded(compressed, compressed_len, ST_DECOMPRESSION_BROTLI, &out, &out_len)
        == ST_DECOMPRESSION_OK && out_len == text_len && memcmp(out, plain, text_len) == 0;
    free(out);
    free(compressed);
    free(plain);
    if (!ok) {
        fprintf(stderr, "br bomb or round trip mismatch\n");
        return 1;
    }
#endif
    printf("br: decoded with libbrotlidec\n");
    return 0;
#endif
}

int main(void)
{
    if (expect_brotli() != 0) {
        return 1;
    }
    if (st_decompression_limit_for(0U) != ST_DECOMPRESSION_MIN_ALLOWANCE_BYTES
        || st_decompression_limit_for(256U * 1024U) != 256U * 1024U * ST_DECOMPRESSION_MAX_RATIO
        || st_decompression_limit_for(ST_DECOMPRESSION_MAX_BYTES / ST_DECOMPRESSION_MAX_RATIO)
            != (ST_DECOMPRESSION_MAX_BYTES / ST_DECOMPRESSION_MAX_RATIO)
                * ST_DECOMPRESSION_MAX_RATIO
        || st_decompression_limit_for(1024U * 1024U) != ST_DECOMPRESSION_MAX_BYTES
        || st_decompression_limit_for(SIZE_MAX) != ST_DECOMPRESSION_MAX_BYTES) {
        fprintf(stderr, "decompression limit arithmetic mismatch\n");
        return 1;
    }
    if (expect_round_trip(ST_DECOMPRESSION_GZIP, 16 + MAX_WBITS) != 0
        || expect_round_trip(ST_DECOMPRESSION_ZLIB, MAX_WBITS) != 0
        || expect_round_trip(ST_DECOMPRESSION_RAW_DEFLATE, -MAX_WBITS) != 0
        || expect_exact_allowance() != 0
        || expect_bomb_rejected() != 0) {
        return 1;
    }
    static const uint8_t invalid[] = {0x00U, 0x01U, 0x02U, 0x03U};
    uint8_t *out = NULL;
    size_t out_len = 0U;
    if (st_decompress_bounded(invalid,
                              sizeof(invalid),
                              ST_DECOMPRESSION_GZIP,
                              &out,
                              &out_len) != ST_DECOMPRESSION_INVALID
        || out != NULL || out_len != 0U) {
        fprintf(stderr, "invalid compressed body handling mismatch\n");
        free(out);
        return 1;
    }
    return 0;
}
