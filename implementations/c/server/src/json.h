#ifndef SPECUS_JSON_H
#define SPECUS_JSON_H

#include <stddef.h>

char *st_json_escape(const char *value);
int st_json_is_valid(const char *json);
int st_json_is_valid_object(const char *json);
char *st_json_get_string(const char *json, const char *key);
char *st_json_get_top_level_string(const char *json, const char *key);
char *st_json_get_top_level_raw(const char *json, const char *key);
/*
 * Decodes raw text that must be exactly one JSON string, such as a value returned by
 * st_json_get_top_level_raw; anything else yields NULL. The decoded length is reported so a caller
 * can refuse an escaped NUL, which would otherwise cut the C string short without notice.
 */
char *st_json_decode_string(const char *raw, size_t *out_len);
int st_json_get_i64(const char *json, const char *key, long long *out);
int st_json_get_int(const char *json, const char *key, int *out);
int st_json_get_bool(const char *json, const char *key, int *out);
int st_json_get_string_array(const char *json, const char *key, char ***out, size_t *out_len);
int st_json_get_raw_array(const char *json, const char *key, char ***out, size_t *out_len);
void st_json_free_string_array(char **values, size_t values_len);

#endif
