#include "decompression_limits.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#ifdef ST_HAVE_BROTLI
#include <brotli/decode.h>
#endif

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

int st_decompression_brotli_supported(void)
{
#ifdef ST_HAVE_BROTLI
    return 1;
#else
    return 0;
#endif
}

/*
 * Streams body through BrotliDecoderDecompressStream into a buffer that grows up to limit bytes.
 * With allow_prefix, reaching the limit ends the read with what was decoded; without it, one more
 * byte tells a stream of exactly limit bytes from a longer one, which is LIMIT_EXCEEDED.
 */
static st_decompression_result brotli_decode(const uint8_t *body,
                                             size_t body_len,
                                             size_t limit,
                                             int allow_prefix,
                                             uint8_t **out,
                                             size_t *out_len)
{
    if (out == NULL || out_len == NULL) {
        return ST_DECOMPRESSION_INVALID;
    }
    *out = NULL;
    *out_len = 0U;
    if (body == NULL && body_len != 0U) {
        return ST_DECOMPRESSION_INVALID;
    }
#ifdef ST_HAVE_BROTLI
    size_t ceiling = allow_prefix ? limit : limit + 1U;
    if (ceiling == 0U) {
        uint8_t *empty = (uint8_t *)malloc(1U);
        if (empty == NULL) {
            return ST_DECOMPRESSION_INVALID;
        }
        empty[0] = 0U;
        *out = empty;
        return ST_DECOMPRESSION_OK;
    }
    BrotliDecoderState *state = BrotliDecoderCreateInstance(NULL, NULL, NULL);
    if (state == NULL) {
        return ST_DECOMPRESSION_INVALID;
    }
    size_t cap = body_len <= (SIZE_MAX - 1024U) / 2U ? body_len * 2U + 1024U : ceiling;
    if (cap > ceiling) {
        cap = ceiling;
    }
    uint8_t *buffer = (uint8_t *)malloc(cap + 1U);
    st_decompression_result rc = ST_DECOMPRESSION_INVALID;
    size_t available_in = body_len;
    const uint8_t *next_in = body;
    size_t total = 0U;
    while (buffer != NULL) {
        size_t available_out = cap - total;
        uint8_t *next_out = buffer + total;
        BrotliDecoderResult result = BrotliDecoderDecompressStream(state, &available_in, &next_in,
                                                                   &available_out, &next_out, NULL);
        total = (size_t)(next_out - buffer);
        if (result == BROTLI_DECODER_RESULT_SUCCESS) {
            rc = total > limit ? ST_DECOMPRESSION_LIMIT_EXCEEDED : ST_DECOMPRESSION_OK;
            break;
        }
        /* An error, or input that ends before the stream does (Java's EOFException). */
        if (result != BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) {
            break;
        }
        if (cap >= ceiling) {
            rc = allow_prefix ? ST_DECOMPRESSION_OK : ST_DECOMPRESSION_LIMIT_EXCEEDED;
            break;
        }
        size_t next = cap > ceiling / 2U ? ceiling : cap * 2U;
        uint8_t *grown = (uint8_t *)realloc(buffer, next + 1U);
        if (grown == NULL) {
            break;
        }
        buffer = grown;
        cap = next;
    }
    BrotliDecoderDestroyInstance(state);
    if (rc != ST_DECOMPRESSION_OK) {
        free(buffer);
        return rc;
    }
    buffer[total] = 0U;
    *out = buffer;
    *out_len = total;
    return ST_DECOMPRESSION_OK;
#else
    (void)limit;
    (void)allow_prefix;
    return ST_DECOMPRESSION_INVALID;
#endif
}

st_decompression_result st_decompress_brotli_prefix(const uint8_t *body,
                                                    size_t body_len,
                                                    size_t limit,
                                                    uint8_t **out,
                                                    size_t *out_len)
{
    return brotli_decode(body, body_len, limit, 1, out, out_len);
}

st_decompression_result st_decompress_bounded(const uint8_t *body,
                                              size_t body_len,
                                              st_decompression_format format,
                                              uint8_t **out,
                                              size_t *out_len)
{
    if (format == ST_DECOMPRESSION_BROTLI) {
        return brotli_decode(body, body_len, st_decompression_limit_for(body_len), 0, out, out_len);
    }
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
