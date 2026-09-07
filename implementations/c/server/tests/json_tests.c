#include "json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    const char *json = "{\"channelId\":\"c-1\",\"port\":18080,\"largeId\":3813672224291582,\"escaped\":\"line\\nnext\",\"asString\":\"42\"}";
    if (!st_json_is_valid(json)
        || !st_json_is_valid("[1,true,null]")
        || !st_json_is_valid("\"text\"")
        || st_json_is_valid("true trailing")
        || !st_json_is_valid_object(json)
        || !st_json_is_valid_object(" {\"nested\":[true,false,null,{\"value\":-1.25e+2}],\"emoji\":\"\\ud83d\\ude00\"} \n")
        || st_json_is_valid_object("{\"missing\":}")
        || st_json_is_valid_object("{\"trailing\":true,}")
        || st_json_is_valid_object("{\"badEscape\":\"\\x\"}")
        || st_json_is_valid_object("{\"badUnicode\":\"\\u12\"}")
        || st_json_is_valid_object("[1,2,3]")) {
        fprintf(stderr, "json object validation mismatch\n");
        return 1;
    }
    char *top_level = st_json_get_top_level_string(
        "{\"nested\":{\"value\":\"wrong\"},\"value\":\"first\",\"value\":\"last\",\"emoji\":\"\\ud83d\\ude00\"}",
        "value");
    char *emoji = st_json_get_top_level_string(
        "{\"nested\":{\"emoji\":\"wrong\"},\"emoji\":\"\\ud83d\\ude00\"}",
        "emoji");
    if (top_level == NULL || strcmp(top_level, "last") != 0
        || emoji == NULL || strcmp(emoji, "\xf0\x9f\x98\x80") != 0
        || st_json_get_top_level_string("{\"nested\":{\"value\":\"wrong\"}}", "value") != NULL) {
        fprintf(stderr, "json top-level string mismatch\n");
        free(top_level);
        free(emoji);
        return 1;
    }
    free(top_level);
    free(emoji);
    char *raw = st_json_get_top_level_raw(
        "{\"payload\":{\"nested\":[1,true,null]},\"other\":{\"payload\":\"wrong\"}}",
        "payload");
    if (raw == NULL || strcmp(raw, "{\"nested\":[1,true,null]}") != 0) {
        fprintf(stderr, "json top-level raw mismatch\n");
        free(raw);
        return 1;
    }
    free(raw);
    raw = st_json_get_top_level_raw("{\"payload\":1,\"payload\":{\"last\":true}}", "payload");
    if (raw == NULL || strcmp(raw, "{\"last\":true}") != 0) {
        fprintf(stderr, "json duplicate top-level raw mismatch\n");
        free(raw);
        return 1;
    }
    free(raw);
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
