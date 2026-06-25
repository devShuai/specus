#ifndef SHUAI_TUNNEL_JSON_H
#define SHUAI_TUNNEL_JSON_H

char *st_json_escape(const char *value);
char *st_json_get_string(const char *json, const char *key);
int st_json_get_i64(const char *json, const char *key, long long *out);
int st_json_get_int(const char *json, const char *key, int *out);
int st_json_get_bool(const char *json, const char *key, int *out);

#endif
