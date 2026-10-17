#define _POSIX_C_SOURCE 200809L
#include "admin_http.h"
#include "json.h"
#include "storage.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef ST_DISCONNECT_REASONS_FIXTURE_FILE
#error "disconnect-reason vector must be supplied by the build"
#endif

#define CHECK(ok) do { if (!(ok)) { fprintf(stderr, "FAIL disconnect reasons line %d: %s\n", __LINE__, #ok); goto done; } } while (0)

static int seed(const char *path, const char *channel, const char *reason)
{
    return st_storage_record_connection_detail_with_tenant_and_id(path, "reason-vector", 0,
        "vector-client", channel, "127.0.0.1:12345", 1, NULL, reason,
        "2026-10-16T00:00:00Z", reason == NULL ? NULL : "2026-10-16T00:01:00Z", NULL);
}

int main(void)
{
    int rc = 1, version = 0;
    char directory[] = "/tmp/specus-disconnect-reasons.XXXXXX";
    char path[256] = {0}, vector[8192], response[32768];
    char **reasons = NULL, **rows = NULL;
    size_t reason_count = 0, row_count = 0;
    FILE *file = fopen(ST_DISCONNECT_REASONS_FIXTURE_FILE, "rb");
    CHECK(file != NULL);
    size_t length = fread(vector, 1, sizeof(vector) - 1U, file);
    int complete = !ferror(file) && feof(file);
    fclose(file);
    file = NULL;
    CHECK(complete);
    vector[length] = '\0';
    CHECK(st_json_is_valid(vector) && st_json_get_int(vector, "version", &version) == 0 && version == 1);
    CHECK(st_json_get_raw_array(vector, "reasons", &reasons, &reason_count) == 0 && reason_count == 17U);
    CHECK(mkdtemp(directory) != NULL);
    snprintf(path, sizeof(path), "%s/audit.db", directory);
    CHECK(setenv("SPECUS_DATABASE_PATH", path, 1) == 0);
    CHECK(setenv("SPECUS_AUTH_TENANT_ID", "reason-vector", 1) == 0);
    CHECK(setenv("SPECUS_AUTH_USERNAME", "admin", 1) == 0);
    CHECK(setenv("SPECUS_DB_SEED_DEMO_CLIENT", "0", 1) == 0);
    CHECK(st_storage_init(path, 0) == 0);
    for (size_t i = 0; i < reason_count; ++i) {
        char *code = st_json_get_top_level_string(reasons[i], "code");
        int seeded = code != NULL && seed(path, code, code) == 0;
        free(code);
        CHECK(seeded);
    }
    CHECK(seed(path, "unmarked", NULL) == 0 && seed(path, "FUTURE_REASON", "FUTURE_REASON") == 0);
    // Exercise the production management response builder and native persistence, not a test label map.
    CHECK(st_admin_build_response("GET", "/api/admin/connections?page=0&size=100", response, sizeof(response)) > 0);
    CHECK(strstr(response, "HTTP/1.1 200 ") != NULL);
    char *body = strstr(response, "\r\n\r\n");
    CHECK(body != NULL);
    CHECK(st_json_get_raw_array(body + 4, "items", &rows, &row_count) == 0 && row_count == 19U);
    for (size_t i = 0; i < row_count; ++i) {
        char *channel = st_json_get_top_level_string(rows[i], "channelId");
        char *code = st_json_get_top_level_string(rows[i], "disconnectReason");
        char *text = st_json_get_top_level_string(rows[i], "disconnectReasonText");
        int valid = 0;
        if (channel != NULL && strcmp(channel, "unmarked") == 0) {
            char *raw_code = st_json_get_top_level_raw(rows[i], "disconnectReason");
            char *raw_text = st_json_get_top_level_raw(rows[i], "disconnectReasonText");
            valid = raw_code != NULL && !strcmp(raw_code, "null") && raw_text != NULL && !strcmp(raw_text, "null");
            free(raw_code); free(raw_text);
        } else if (channel != NULL && strcmp(channel, "FUTURE_REASON") == 0) {
            valid = code != NULL && !strcmp(code, "FUTURE_REASON") && text != NULL && !strcmp(text, "未知");
        } else {
            size_t matches = 0;
            for (size_t j = 0; j < reason_count; ++j) {
                char *expected_code = st_json_get_top_level_string(reasons[j], "code");
                char *expected_text = st_json_get_top_level_string(reasons[j], "text");
                if (channel != NULL && expected_code != NULL && !strcmp(channel, expected_code)) {
                    ++matches;
                    valid = code != NULL && !strcmp(code, expected_code) && expected_text != NULL
                        && text != NULL && !strcmp(text, expected_text);
                }
                free(expected_code); free(expected_text);
            }
            valid = valid && matches == 1U;
        }
        if (!valid) fprintf(stderr, "unexpected audit read model: %s\n", rows[i]);
        free(channel); free(code); free(text);
        CHECK(valid);
    }
    rc = 0;
    puts("PASS disconnect reasons: 17 shared labels, native management JSON, unmarked and future fallback");
done:
    if (file != NULL) fclose(file);
    st_json_free_string_array(rows, row_count);
    st_json_free_string_array(reasons, reason_count);
    if (path[0] != '\0') {
        unsetenv("SPECUS_DATABASE_PATH");
        unlink(path);
        char side[272];
        snprintf(side, sizeof(side), "%s-wal", path); unlink(side);
        snprintf(side, sizeof(side), "%s-shm", path); unlink(side);
        rmdir(directory);
    }
    return rc;
}
