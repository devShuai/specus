#ifndef SHUAI_TUNNEL_C_TEST_UTIL_H
#define SHUAI_TUNNEL_C_TEST_UTIL_H

#include "protocol.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ST_FIXTURE_DIR "../tunnel-server-csharp/tests/fixtures/"

static int st_test_read_file(const char *path, uint8_t **out, size_t *out_len)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        perror(path);
        return 1;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return 1;
    }
    long len = ftell(file);
    if (len < 0) {
        fclose(file);
        return 1;
    }
    rewind(file);
    uint8_t *bytes = (uint8_t *)malloc((size_t)len == 0 ? 1U : (size_t)len);
    if (bytes == NULL) {
        fclose(file);
        return 1;
    }
    if (fread(bytes, 1, (size_t)len, file) != (size_t)len) {
        free(bytes);
        fclose(file);
        return 1;
    }
    fclose(file);
    *out = bytes;
    *out_len = (size_t)len;
    return 0;
}

static int st_test_read_fixture(const char *fixture, uint8_t **out, size_t *out_len)
{
    char path[256];
    snprintf(path, sizeof(path), "%s%s", ST_FIXTURE_DIR, fixture);
    return st_test_read_file(path, out, out_len);
}

static int st_test_expect_fixture_bytes(const char *fixture, const st_buffer *actual)
{
    uint8_t *expected = NULL;
    size_t expected_len = 0;
    if (st_test_read_fixture(fixture, &expected, &expected_len) != 0) {
        return 1;
    }
    int mismatch = expected_len != actual->len || memcmp(expected, actual->data, actual->len) != 0;
    if (mismatch) {
        fprintf(stderr, "%s bytes mismatch (expected %zu bytes, got %zu bytes)\n",
                fixture, expected_len, actual->len);
    }
    free(expected);
    return mismatch ? 1 : 0;
}

static int st_test_decode_fixture_header(const char *fixture, uint8_t **bytes, st_frame_header *header)
{
    size_t len = 0;
    if (st_test_read_fixture(fixture, bytes, &len) != 0) {
        return 1;
    }
    if (len < ST_HEADER_SIZE || st_protocol_read_header(*bytes, header) != 0
        || header->length != len - ST_HEADER_SIZE) {
        fprintf(stderr, "%s header mismatch\n", fixture);
        free(*bytes);
        *bytes = NULL;
        return 1;
    }
    return 0;
}

#endif
