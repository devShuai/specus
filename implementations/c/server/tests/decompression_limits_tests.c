#include "decompression_limits.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

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

int main(void)
{
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
