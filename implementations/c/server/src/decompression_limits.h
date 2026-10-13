#ifndef SPECUS_DECOMPRESSION_LIMITS_H
#define SPECUS_DECOMPRESSION_LIMITS_H

#include <stddef.h>
#include <stdint.h>

#define ST_DECOMPRESSION_MAX_BYTES (64U * 1024U * 1024U)
#define ST_DECOMPRESSION_MAX_RATIO 100U
#define ST_DECOMPRESSION_MIN_ALLOWANCE_BYTES (64U * 1024U)

/*
 * ST_DECOMPRESSION_BROTLI (Content-Encoding: br, which Java reads with org.brotli:dec) decodes only
 * when the build found libbrotlidec and defined ST_HAVE_BROTLI; otherwise it is always INVALID, and
 * a br body stays as it came.
 */
typedef enum {
    ST_DECOMPRESSION_GZIP = 0,
    ST_DECOMPRESSION_ZLIB = 1,
    ST_DECOMPRESSION_RAW_DEFLATE = 2,
    ST_DECOMPRESSION_BROTLI = 3
} st_decompression_format;

typedef enum {
    ST_DECOMPRESSION_OK = 0,
    ST_DECOMPRESSION_INVALID = -1,
    ST_DECOMPRESSION_LIMIT_EXCEEDED = -2
} st_decompression_result;

/* Returns min(64 MiB, max(64 KiB, compressed_size * 100)) without overflow. */
size_t st_decompression_limit_for(size_t compressed_size);

/* Caller owns *out after success. Failures leave *out NULL and *out_len zero. */
st_decompression_result st_decompress_bounded(const uint8_t *body,
                                              size_t body_len,
                                              st_decompression_format format,
                                              uint8_t **out,
                                              size_t *out_len);

/* 1 when this build decodes ST_DECOMPRESSION_BROTLI (libbrotlidec was found), else 0. */
int st_decompression_brotli_supported(void);

/*
 * Brotli decoded into at most limit bytes, as Java's readLimited reads a preview: output that
 * reaches the limit is a success holding that prefix. A corrupt stream, or one whose input ends
 * early, is INVALID, as is every stream when the build has no libbrotlidec. Caller owns *out.
 */
st_decompression_result st_decompress_brotli_prefix(const uint8_t *body,
                                                    size_t body_len,
                                                    size_t limit,
                                                    uint8_t **out,
                                                    size_t *out_len);

#endif
