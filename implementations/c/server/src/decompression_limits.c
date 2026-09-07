#include "decompression_limits.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

size_t st_decompression_limit_for(size_t compressed_size)
{
    if (compressed_size == 0U) {
        return ST_DECOMPRESSION_MIN_ALLOWANCE_BYTES;
    }
    if (compressed_size > ST_DECOMPRESSION_MAX_BYTES / ST_DECOMPRESSION_MAX_RATIO) {
        return ST_DECOMPRESSION_MAX_BYTES;
    }
    size_t scaled = compressed_size * ST_DECOMPRESSION_MAX_RATIO;
    if (scaled > ST_DECOMPRESSION_MAX_BYTES) {
        return ST_DECOMPRESSION_MAX_BYTES;
    }
    return scaled < ST_DECOMPRESSION_MIN_ALLOWANCE_BYTES
        ? ST_DECOMPRESSION_MIN_ALLOWANCE_BYTES
        : scaled;
}

static int window_bits_for(st_decompression_format format)
{
    switch (format) {
        case ST_DECOMPRESSION_GZIP: return 16 + MAX_WBITS;
        case ST_DECOMPRESSION_ZLIB: return MAX_WBITS;
        case ST_DECOMPRESSION_RAW_DEFLATE: return -MAX_WBITS;
        default: return 0;
    }
}

st_decompression_result st_decompress_bounded(const uint8_t *body,
                                              size_t body_len,
                                              st_decompression_format format,
                                              uint8_t **out,
                                              size_t *out_len)
{
    if (out == NULL || out_len == NULL) {
        return ST_DECOMPRESSION_INVALID;
    }
    *out = NULL;
    *out_len = 0U;
    int window_bits = window_bits_for(format);
    if ((body == NULL && body_len != 0U) || window_bits == 0 || body_len > UINT_MAX) {
        return ST_DECOMPRESSION_INVALID;
    }

    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    stream.next_in = (Bytef *)body;
    stream.avail_in = (uInt)body_len;
    if (inflateInit2(&stream, window_bits) != Z_OK) {
        return ST_DECOMPRESSION_INVALID;
    }

    size_t limit = st_decompression_limit_for(body_len);
    size_t cap = body_len <= (SIZE_MAX - 1024U) / 2U ? body_len * 2U + 1024U : limit;
    if (cap < 1024U) {
        cap = 1024U;
    }
    if (cap > limit) {
        cap = limit;
    }
    uint8_t *buffer = (uint8_t *)malloc(cap + 1U);
    if (buffer == NULL) {
        inflateEnd(&stream);
        return ST_DECOMPRESSION_INVALID;
    }

    int status = Z_OK;
    while (status == Z_OK) {
        if ((size_t)stream.total_out == cap) {
            size_t next;
            if (cap < limit) {
                next = cap > limit / 2U ? limit : cap * 2U;
            } else {
                /* One sentinel byte distinguishes an exact-limit stream from an over-limit one. */
                next = limit + 1U;
            }
            uint8_t *grown = (uint8_t *)realloc(buffer, next + 1U);
            if (grown == NULL) {
                free(buffer);
                inflateEnd(&stream);
                return ST_DECOMPRESSION_INVALID;
            }
            buffer = grown;
            cap = next;
        }
        stream.next_out = buffer + stream.total_out;
        stream.avail_out = (uInt)(cap - (size_t)stream.total_out);
        status = inflate(&stream, Z_NO_FLUSH);
        if ((size_t)stream.total_out > limit) {
            free(buffer);
            inflateEnd(&stream);
            return ST_DECOMPRESSION_LIMIT_EXCEEDED;
        }
    }
    if (status != Z_STREAM_END) {
        free(buffer);
        inflateEnd(&stream);
        return ST_DECOMPRESSION_INVALID;
    }

    *out_len = (size_t)stream.total_out;
    buffer[*out_len] = '\0';
    *out = buffer;
    inflateEnd(&stream);
    return ST_DECOMPRESSION_OK;
}
