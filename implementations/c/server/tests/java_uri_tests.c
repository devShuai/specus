/*
 * The java.net.URI port against the uriCases of protocol/test-vectors/client-download-link-validation-v1.json,
 * which Java's ClientDownloadLinkValidationVectorTests proves are what java.net.URI does: the
 * URISyntaxException message, or the scheme, raw user info, host, raw authority, path, query and fragment.
 *
 *   java_uri_tests <client-download-link-validation-v1.json>
 */
#define _POSIX_C_SOURCE 200809L

#include "java_uri.h"
#include "json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *read_file(const char *path)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL) return NULL;
    size_t capacity = 1U << 20;
    char *text = (char *)malloc(capacity + 1U);
    size_t bytes = text == NULL ? 0U : fread(text, 1U, capacity, file);
    int failed = text == NULL || ferror(file) || bytes == capacity;
    fclose(file);
    if (failed) {
        free(text);
        return NULL;
    }
    text[bytes] = '\0';
    return text;
}

/* Expected and actual agree, NULL standing for Java's null. */
static int same(const char *expected, const char *actual)
{
    return expected == NULL ? actual == NULL : actual != NULL && strcmp(expected, actual) == 0;
}

int main(int argc, char **argv)
{
    char *vector = argc == 2 ? read_file(argv[1]) : NULL;
    char **cases = NULL;
    size_t count = 0U;
    int version = 0;
    if (vector == NULL || !st_json_is_valid_object(vector) || st_json_get_int(vector, "version", &version) != 0
        || version != 1 || st_json_get_raw_array(vector, "uriCases", &cases, &count) != 0 || count == 0U) {
        fprintf(stderr, "cannot read the uriCases of %s\n", argc == 2 ? argv[1] : "(no vector given)");
        free(vector);
        return 1;
    }
    int failures = 0;
    for (size_t i = 0U; i < count; ++i) {
        static const char *const members[] = {"scheme", "userInfo", "host", "rawAuthority", "rawPath",
                                              "rawQuery", "rawFragment"};
        char *input = st_json_get_top_level_string(cases[i], "input");
        char *error = st_json_get_top_level_string(cases[i], "error");
        st_java_uri uri;
        int rc = input == NULL ? -1 : st_java_uri_parse(input, &uri);
        int ok = input != NULL;
        if (ok && error != NULL) {
            ok = rc != 0 && same(error, uri.error);
            if (!ok) fprintf(stderr, "FAIL %s: expected \"%s\", got %s \"%s\"\n", input, error,
                             rc == 0 ? "a parse" : "the error", uri.error == NULL ? "" : uri.error);
        } else if (ok) {
            const char *actual[] = {uri.scheme, uri.user_info, uri.host, uri.raw_authority, uri.raw_path,
                                    uri.raw_query, uri.raw_fragment};
            ok = rc == 0;
            if (!ok) fprintf(stderr, "FAIL %s: expected a parse, got \"%s\"\n", input, uri.error);
            for (size_t m = 0U; ok && m < sizeof(members) / sizeof(members[0]); ++m) {
                char *expected = st_json_get_top_level_string(cases[i], members[m]);
                ok = same(expected, actual[m]);
                if (!ok) fprintf(stderr, "FAIL %s: %s expected %s, got %s\n", input, members[m],
                                 expected == NULL ? "null" : expected, actual[m] == NULL ? "null" : actual[m]);
                free(expected);
            }
        }
        failures += !ok;
        if (input != NULL) st_java_uri_free(&uri);
        free(input);
        free(error);
    }
    st_json_free_string_array(cases, count);
    free(vector);
    printf("%s java.net.URI port: %zu cases, %d failed\n", failures == 0 ? "ok  " : "FAIL", count, failures);
    return failures == 0 ? 0 : 1;
}
