#ifndef ST_CONNECTIVITY_CHECK_TEST_SUPPORT_H
#define ST_CONNECTIVITY_CHECK_TEST_SUPPORT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "connectivity_check.h"
#include "json.h"

#ifndef ST_CONNECTIVITY_VECTOR_DIR
#define ST_CONNECTIVITY_VECTOR_DIR "../../../protocol/test-vectors/"
#endif

#define CHECK_START_MS 7000000LL
#define CHECKED_AT "2026-10-06T08:00:00Z"

typedef struct {
    char kind[16];
    int status;
    char failure[32];
    char cause[16];
    long long at_ms;
} scripted_answer;

typedef struct {
    long long now;
    long long check_start;
    int control_online;
    int data_online;
    int capability;
    scripted_answer answers[4];
    size_t answers_len;
    size_t next_answer;
    char metadata[4][1024];
    long long timeouts[4];
    size_t probes;
    char last_log[512];
    size_t logs;
    size_t refusal_logs;
    char refusal_lines[2][512];
} fake_device;

static inline void fake_presence(void *ctx, const char *client_name, int *control_online, int *data_online)
{
    (void)client_name;
    fake_device *device = (fake_device *)ctx;
    *control_online = device->control_online;
    *data_online = device->data_online;
}

static inline void fake_probe(void *ctx,
                       const char *client_name,
                       const char *metadata_json,
                       long long timeout_ms,
                       st_connectivity_probe_answer *answer)
{
    (void)client_name;
    fake_device *device = (fake_device *)ctx;
    if (device->probes < 4U) {
        snprintf(device->metadata[device->probes], sizeof(device->metadata[0]), "%s", metadata_json);
        device->timeouts[device->probes] = timeout_ms;
    }
    ++device->probes;
    memset(answer, 0, sizeof(*answer));
    answer->capability = device->capability;
    if (device->next_answer >= device->answers_len) {
        answer->kind = ST_CONNECTIVITY_PROBE_TIMEOUT;
        device->now = device->check_start + ST_CONNECTIVITY_BUDGET_MS;
        return;
    }
    const scripted_answer *scripted = &device->answers[device->next_answer++];
    device->now = device->check_start + scripted->at_ms;
    if (strcmp(scripted->kind, "response") == 0) {
        answer->kind = ST_CONNECTIVITY_PROBE_RESPONSE;
        answer->status_code = scripted->status;
    } else if (strcmp(scripted->kind, "rst") == 0) {
        answer->kind = ST_CONNECTIVITY_PROBE_RESET;
        snprintf(answer->failure, sizeof(answer->failure), "%s", scripted->failure);
    } else if (strcmp(scripted->kind, "link-lost") == 0) {
        answer->kind = ST_CONNECTIVITY_PROBE_LINK_LOST;
    } else if (strcmp(scripted->kind, "open-failed") == 0) {
        answer->kind = strcmp(scripted->cause, "stream-limit") == 0
            ? ST_CONNECTIVITY_PROBE_STREAM_LIMIT : ST_CONNECTIVITY_PROBE_WRITE_FAILED;
    } else {
        answer->kind = ST_CONNECTIVITY_PROBE_TIMEOUT;
        device->now = device->check_start + ST_CONNECTIVITY_BUDGET_MS;
    }
}

static inline long long fake_now(void *ctx)
{
    return ((fake_device *)ctx)->now;
}

static inline void fake_log(void *ctx, const char *line)
{
    fake_device *device = (fake_device *)ctx;
    snprintf(device->last_log, sizeof(device->last_log), "%s", line);
    ++device->logs;
    if (strstr(line, " refused code=CHECK_RATE_LIMITED") != NULL) {
        if (device->refusal_logs < 2U) {
            snprintf(device->refusal_lines[device->refusal_logs], sizeof(device->refusal_lines[0]), "%s", line);
        }
        ++device->refusal_logs;
    }
}

static inline char *read_vector(void)
{
    char path[1024];
    snprintf(path, sizeof(path), "%s%s", ST_CONNECTIVITY_VECTOR_DIR, "service-connectivity-check-v1.json");
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        fprintf(stderr, "cannot open %s\n", path);
        return NULL;
    }
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    char *data = size > 0 ? (char *)malloc((size_t)size + 1U) : NULL;
    if (data != NULL && fread(data, 1, (size_t)size, file) == (size_t)size) {
        data[size] = '\0';
    } else {
        free(data);
        data = NULL;
    }
    fclose(file);
    return data;
}

/* Drops whitespace outside strings, so the pretty-printed expectation compares byte for byte. */
static inline int minify(const char *in, char *out, size_t out_len)
{
    size_t written = 0;
    int in_string = 0;
    if (out_len == 0U) return 1;
    for (const char *p = in; *p != '\0'; ++p) {
        if (!in_string && (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t')) continue;
        if (written + 1U >= out_len) { out[written] = '\0'; return 1; }
        if (in_string) {
            out[written++] = *p;
            if (*p == '\\' && p[1] != '\0') {
                if (written + 1U >= out_len) { out[written] = '\0'; return 1; }
                out[written++] = *++p;
            } else if (*p == '"') {
                in_string = 0;
            }
        } else if (*p == '"') {
            in_string = 1;
            out[written++] = *p;
        } else if (*p != ' ' && *p != '\n' && *p != '\r' && *p != '\t') {
            out[written++] = *p;
        }
    }
    out[written] = '\0';
    return 0;
}

/* The shared comparison helper must reject truncation, including an escape at the buffer edge. */
static inline int assert_minify_bounds(void)
{
    char tiny[4] = {'x', 'x', 'x', '!'};
    char exact[5];
    return minify("\"\\n\"", tiny, 3U) != 1 || tiny[2] != '\0' || tiny[3] != '!'
        || minify(" \"\\n\" ", exact, sizeof(exact)) != 0 || strcmp(exact, "\"\\n\"") != 0
        || minify("", tiny, 0U) != 1;
}

static inline int bool_or(const char *json, const char *key, int fallback)
{
    int value = fallback;
    if (json != NULL && st_json_get_bool(json, key, &value) != 0) {
        value = fallback;
    }
    return value;
}

static inline void copy_string(const char *json, const char *key, char *out, size_t out_len)
{
    char *value = st_json_get_top_level_string(json, key);
    snprintf(out, out_len, "%s", value == NULL ? "" : value);
    free(value);
}

/* Both replays enforce identical result/probe contracts. */
static inline int assert_vector_response(const char *name, const char *expect,
                                         const fake_device *device,
                                         const st_connectivity_response *response)
{
    int failed = 0;
    int want_status = 0;
    int want_retry = 0;
    (void)st_json_get_int(expect == NULL ? "{}" : expect, "httpStatus", &want_status);
    if (!failed && response->status != want_status) {
        fprintf(stderr, "%s: status %d, want %d\n", name, response->status, want_status);
        failed = 1;
    }
    if (!failed && want_status != 200) {
        char want_code[48];
        copy_string(expect, "code", want_code, sizeof(want_code));
        if (st_json_get_int(expect, "retryAfterSeconds", &want_retry) != 0) {
            want_retry = want_status == 429 || want_status == 503 ? 1 : 0;
        }
        char want_body[96];
        snprintf(want_body, sizeof(want_body), "{\"code\":\"%s\"}", want_code);
        if (want_status == 401 ? response->body != NULL
                               : response->body == NULL || strcmp(response->body, want_body) != 0) {
            fprintf(stderr, "%s: body %s, want %s\n", name, response->body == NULL ? "(none)" : response->body,
                    want_status == 401 ? "(none)" : want_body);
            failed = 1;
        }
        if (response->retry_after_seconds != want_retry) {
            fprintf(stderr, "%s: Retry-After %d, want %d\n", name, response->retry_after_seconds, want_retry);
            failed = 1;
        }
        if (device->probes != 0U) {
            fprintf(stderr, "%s: a refused check reached the device\n", name);
            failed = 1;
        }
        if (device->logs != 0U) {
            fprintf(stderr, "%s: a refused check emitted a completion log\n", name);
            failed = 1;
        }
    } else if (!failed) {
        char *body_raw = st_json_get_top_level_raw(expect, "body");
        static char want[8192];
        static char got[8192];
        failed |= minify(body_raw == NULL ? "" : body_raw, want, sizeof(want));
        free(body_raw);
        /* Take the runtime fields out; they must be present and well-formed. */
        const char *prefix = "{\"schemaVersion\":1,\"kind\":\"http-route\",\"routeId\":42,\"checkedAt\":\"";
        const char *checked_at = strncmp(response->body, prefix, strlen(prefix)) == 0
            ? response->body + strlen(prefix) : NULL;
        if (checked_at == NULL || strlen(checked_at) < 22U || strncmp(checked_at, CHECKED_AT, 20U) != 0
            || checked_at[20] != '"' || checked_at[21] != ',') {
            fprintf(stderr, "%s: runtime fields malformed in %s\n", name, response->body);
            failed = 1;
        } else {
            snprintf(got, sizeof(got), "{\"schemaVersion\":1,\"kind\":\"http-route\",%s", checked_at + 22);
            if (strcmp(got, want) != 0) {
                fprintf(stderr, "%s: body mismatch\n got: %s\nwant: %s\n", name, got, want);
                failed = 1;
            }
        }
        char *expected_body = st_json_get_top_level_raw(expect, "body");
        char **requests = NULL;
        size_t requests_len = 0;
        if (expected_body == NULL || st_json_get_string_array(expected_body, "requests", &requests, &requests_len) != 0
            || requests_len != device->probes || requests_len != device->answers_len
            || device->next_answer != device->answers_len || response->retry_after_seconds != 0) {
            fprintf(stderr, "%s: probe/script counts or successful Retry-After differ\n", name);
            failed = 1;
        }
        /* Exact key order and values reject extra headers/fields, not merely a substring match. */
        for (size_t i = 0; i < device->probes && i < 4U; ++i) {
            const char *metadata = device->metadata[i];
            char *request_id = st_json_get_top_level_string(metadata, "requestId");
            int ok = request_id != NULL && strlen(request_id) == 32U;
            for (size_t j = 0U; ok && j < 32U; ++j) {
                char c = request_id[j];
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) ok = 0;
            }
            char wanted_metadata[1024];
            char got_metadata[1024];
            snprintf(wanted_metadata, sizeof(wanted_metadata),
                     "{\"source\":\"http\",\"phase\":\"request\",\"requestId\":\"%s\",\"method\":\"%s\","
                     "\"route\":\"api\",\"relativePath\":\"/healthz\",\"rawQuery\":\"\","
                     "\"headers\":[\"Accept:*/*\",\"User-Agent:specus-connectivity-check/1\"]}",
                     request_id == NULL ? "" : request_id, i < requests_len ? requests[i] : "missing-request");
            failed |= minify(metadata, got_metadata, sizeof(got_metadata));
            long long wanted_timeout = ST_CONNECTIVITY_BUDGET_MS - (i == 0U ? 0 : device->answers[0].at_ms);
            ok = ok && strcmp(got_metadata, wanted_metadata) == 0 && device->timeouts[i] == wanted_timeout;
            free(request_id);
            if (!ok) {
                fprintf(stderr, "%s: probe %zu metadata/budget differs: %s timeout=%lld want=%lld\n",
                        name, i, metadata, device->timeouts[i], wanted_timeout);
                failed = 1;
            }
        }
        char outcome[32], stopped_at[32], code[64];
        copy_string(expected_body, "outcome", outcome, sizeof(outcome));
        copy_string(expected_body, "stoppedAt", stopped_at, sizeof(stopped_at));
        copy_string(expected_body, "code", code, sizeof(code));
        long long total_ms = -1;
        (void)st_json_get_i64(expected_body, "totalMs", &total_ms);
        char wanted_log[512];
        snprintf(wanted_log, sizeof(wanted_log),
                 "[connectivity-check] tenant=t1 user=alice route=42 outcome=%s stage=%s code=%s totalMs=%lld",
                 outcome, stopped_at[0] == '\0' ? "-" : stopped_at, code, total_ms);
        if (device->logs != 1U || strcmp(device->last_log, wanted_log) != 0
            || strstr(device->last_log, "/healthz") != NULL || strstr(device->last_log, "127.0.0.1") != NULL) {
            fprintf(stderr, "%s: log line %s\n", name, device->last_log);
            failed = 1;
        }
        st_json_free_string_array(requests, requests_len);
        free(expected_body);
    }
    return failed;
}

#endif
