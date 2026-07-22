#include "json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    const char *json = "{\"channelId\":\"c-1\",\"port\":18080,\"largeId\":3813672224291582,\"escaped\":\"line\\nnext\",\"asString\":\"42\"}";
    int port = 0;
    long long large_id = 0;
    if (st_json_get_int(json, "port", &port) != 0 || port != 18080) {
        fprintf(stderr, "json int mismatch\n");
        return 1;
    }
    if (st_json_get_i64(json, "largeId", &large_id) != 0 || large_id != 3813672224291582LL) {
        fprintf(stderr, "json i64 mismatch\n");
        return 1;
    }
    if (st_json_get_int(json, "asString", &port) != 0 || port != 42) {
        fprintf(stderr, "json string-int mismatch\n");
        return 1;
    }
    char *channel_id = st_json_get_string(json, "channelId");
    char *escaped = st_json_get_string(json, "escaped");
    if (channel_id == NULL || strcmp(channel_id, "c-1") != 0
        || escaped == NULL || strcmp(escaped, "line\nnext") != 0) {
        fprintf(stderr, "json string mismatch\n");
        free(channel_id);
        free(escaped);
        return 1;
    }
    free(channel_id);
    free(escaped);

    char *encoded = st_json_escape("a\"b\\c\n");
    if (encoded == NULL || strcmp(encoded, "a\\\"b\\\\c\\u000a") != 0) {
        fprintf(stderr, "json escape mismatch: %s\n", encoded == NULL ? "(null)" : encoded);
        free(encoded);
        return 1;
    }
    free(encoded);

    char **values = NULL;
    size_t values_len = 0;
    const char *arrays = "{\"headers\":[\"Content-Type:text/plain\",\"X-Test:line\\nnext\"],\"empty\":[]}";
    if (st_json_get_string_array(arrays, "headers", &values, &values_len) != 0
        || values_len != 2U
        || strcmp(values[0], "Content-Type:text/plain") != 0
        || strcmp(values[1], "X-Test:line\nnext") != 0) {
        fprintf(stderr, "json string array mismatch\n");
        st_json_free_string_array(values, values_len);
        return 1;
    }
    st_json_free_string_array(values, values_len);
    values = NULL;
    values_len = 0;
    if (st_json_get_string_array(arrays, "empty", &values, &values_len) != 0
        || values != NULL || values_len != 0U
        || st_json_get_string_array("{\"bad\":[1]}", "bad", &values, &values_len) == 0) {
        fprintf(stderr, "json string array validation mismatch\n");
        st_json_free_string_array(values, values_len);
        return 1;
    }
    return 0;
}
