#include "url_decode.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "URL decoding check failed at line %d\n", __LINE__); return 1; } } while (0)

int main(void)
{
    /* Generic byte-decoding coverage, without endpoint requests or credentials. */
    unsigned cases = 0U;
    for (unsigned byte = 0U; byte <= 255U; ++byte) {
        for (unsigned lower = 0U; lower < 2U; ++lower) {
            char encoded[4];
            CHECK(snprintf(encoded, sizeof(encoded), lower ? "%%%02x" : "%%%02X", byte) == 3);
            size_t len = 99U;
            char *raw = st_url_decode(encoded, 3U, &len);
            CHECK(raw != NULL && len == 1U && (unsigned char)raw[0] == byte && raw[1] == '\0');
            free(raw);
            char *string = st_url_decode_string(encoded, 3U);
            if (byte == 0U) CHECK(string == NULL);
            else CHECK(string != NULL && strlen(string) == 1U && (unsigned char)string[0] == byte);
            free(string);
            ++cases;
        }
    }
    for (size_t position = 0U; position < 5U; ++position) {
        char raw[5] = {'a','b','c','d','e'}; raw[position] = '\0';
        size_t len = 0U; char *decoded = st_url_decode(raw, sizeof(raw), &len);
        CHECK(decoded != NULL && len == sizeof(raw) && memcmp(decoded, raw, len) == 0);
        free(decoded);
        CHECK(st_url_decode_string(raw, sizeof(raw)) == NULL);
        ++cases;
    }
    const char *inputs[] = {"", "abc", "a+b", "%", "%0", "%G0", "%0G", "%25", "%2520", "abc?x=y&z=1"};
    const char *expected[] = {"", "abc", "a b", "%", "%0", "%G0", "%0G", "%", "%20", "abc?x=y&z=1"};
    for (size_t i = 0U; i < sizeof(inputs)/sizeof(inputs[0]); ++i) {
        char *decoded = st_url_decode_string(inputs[i], strlen(inputs[i]));
        CHECK(decoded != NULL && strcmp(decoded, expected[i]) == 0);
        free(decoded); ++cases;
    }
    size_t len = 99U;
    CHECK(st_url_decode(NULL, 0U, &len) == NULL && len == 0U);
    CHECK(st_url_decode("", SIZE_MAX, &len) == NULL && len == 0U);
    CHECK(st_url_decode_string(NULL, 0U) == NULL);
    char *bounded = st_url_decode_string("abcdef", 3U);
    CHECK(bounded != NULL && strcmp(bounded, "abc") == 0); free(bounded);
    printf("URL decoding: %u generic byte/string cases plus input-boundary checks passed\n", cases);
    return 0;
}
