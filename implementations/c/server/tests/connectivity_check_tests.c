#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "connectivity_check.h"
#include "json.h"

/*
 * Replays protocol/test-vectors/service-connectivity-check-v1.json through the real checker: a fake
 * route loader, a fake device that answers each probe as the case scripts it, and a fake monotonic
 * clock that the device moves to the scripted atMs. The 200 body must equal the vector's byte for
 * byte once the runtime routeId and checkedAt are taken out.
 */

#ifndef ST_CONNECTIVITY_VECTOR_DIR
#define ST_CONNECTIVITY_VECTOR_DIR "../../../protocol/test-vectors/"
#endif

typedef struct {
    char kind[16];
    int status;
    char failure[32];
    char cause[16];
    long long at_ms;
} scripted_answer;

typedef struct {
    long long now;
    int control_online;
    int data_online;
    int capability;
    scripted_answer answers[4];
    size_t answers_len;
    size_t next_answer;
    char metadata[4][1024];
    size_t probes;
    char last_log[512];
    size_t logs;
    size_t refusal_logs;
} fake_device;

static void fake_presence(void *ctx, const char *client_name, int *control_online, int *data_online)
{
    (void)client_name;
    fake_device *device = (fake_device *)ctx;
    *control_online = device->control_online;
    *data_online = device->data_online;
}

static void fake_probe(void *ctx,
                       const char *client_name,
                       const char *metadata_json,
                       long long timeout_ms,
                       st_connectivity_probe_answer *answer)
{
    (void)client_name;
    (void)timeout_ms;
    fake_device *device = (fake_device *)ctx;
    if (device->probes < 4U) {
        snprintf(device->metadata[device->probes], sizeof(device->metadata[0]), "%s", metadata_json);
    }
    ++device->probes;
    memset(answer, 0, sizeof(*answer));
    answer->capability = device->capability;
    if (device->next_answer >= device->answers_len) {
        answer->kind = ST_CONNECTIVITY_PROBE_TIMEOUT;
        device->now = ST_CONNECTIVITY_BUDGET_MS;
        return;
    }
    const scripted_answer *scripted = &device->answers[device->next_answer++];
    device->now = scripted->at_ms;
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
        device->now = ST_CONNECTIVITY_BUDGET_MS;
    }
}

static long long fake_now(void *ctx)
{
    return ((fake_device *)ctx)->now;
}

static void fake_log(void *ctx, const char *line)
{
    fake_device *device = (fake_device *)ctx;
    snprintf(device->last_log, sizeof(device->last_log), "%s", line);
    ++device->logs;
    if (strstr(line, " refused code=CHECK_RATE_LIMITED") != NULL) {
        ++device->refusal_logs;
    }
}

typedef struct {
    int readable;
    int visible;
    st_connectivity_route route;
} fake_routes;

static int fake_load(void *ctx, long long route_id, st_connectivity_route *route)
{
    fake_routes *routes = (fake_routes *)ctx;
    if (!routes->readable) {
        return ST_CONNECTIVITY_ROUTE_UNREADABLE;
    }
    if (!routes->visible) {
        return ST_CONNECTIVITY_ROUTE_ABSENT;
    }
    *route = routes->route;
    route->id = route_id;
    return ST_CONNECTIVITY_ROUTE_FOUND;
}

static char *read_vector(void)
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
static void minify(const char *in, char *out, size_t out_len)
{
    size_t written = 0;
    int in_string = 0;
    for (const char *p = in; *p != '\0' && written + 1U < out_len; ++p) {
        if (in_string) {
            out[written++] = *p;
            if (*p == '\\' && p[1] != '\0') {
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
}

static int bool_or(const char *json, const char *key, int fallback)
{
    int value = fallback;
    if (json != NULL && st_json_get_bool(json, key, &value) != 0) {
        value = fallback;
    }
    return value;
}

static void copy_string(const char *json, const char *key, char *out, size_t out_len)
{
    char *value = st_json_get_top_level_string(json, key);
    snprintf(out, out_len, "%s", value == NULL ? "" : value);
    free(value);
}

static int run_case(const char *raw_case)
{
    char name[96];
    copy_string(raw_case, "name", name, sizeof(name));
    char *input = st_json_get_top_level_raw(raw_case, "input");
    char *expect = st_json_get_top_level_raw(raw_case, "expect");
    char *route_raw = input == NULL ? NULL : st_json_get_top_level_raw(input, "route");
    char *device_raw = input == NULL ? NULL : st_json_get_top_level_raw(input, "device");
    int failed = input == NULL || expect == NULL;

    fake_device device;
    memset(&device, 0, sizeof(device));
    device.control_online = 1;
    device.data_online = 1;
    fake_routes routes = {
        .readable = bool_or(input, "configReadable", 1),
        .visible = bool_or(input, "routeVisible", 1),
    };
    snprintf(routes.route.tenant_id, sizeof(routes.route.tenant_id), "default");
    snprintf(routes.route.client_name, sizeof(routes.route.client_name), "device-a");
    snprintf(routes.route.route, sizeof(routes.route.route), "app");
    snprintf(routes.route.target_base_url, sizeof(routes.route.target_base_url), "http://127.0.0.1:8080/base");
    routes.route.route_enabled = 1;
    routes.route.client_enabled = 1;
    if (route_raw != NULL) {
        routes.route.route_enabled = bool_or(route_raw, "enabled", 1);
        if (!bool_or(route_raw, "targetValid", 1)) {
            snprintf(routes.route.target_base_url, sizeof(routes.route.target_base_url), "ftp://127.0.0.1/");
        }
    }
    if (device_raw != NULL) {
        routes.route.client_enabled = bool_or(device_raw, "enabled", 1);
        device.control_online = bool_or(device_raw, "controlOnline", 1);
        device.data_online = bool_or(device_raw, "dataOnline", 1);
        if (st_json_get_int(device_raw, "httpRouteCapability", &device.capability) != 0) {
            device.capability = 0;
        }
    }
    char **answers = NULL;
    size_t answers_len = 0;
    if (input != NULL && st_json_get_raw_array(input, "answers", &answers, &answers_len) == 0) {
        for (size_t i = 0; i < answers_len && i < 4U; ++i) {
            scripted_answer *answer = &device.answers[device.answers_len++];
            copy_string(answers[i], "kind", answer->kind, sizeof(answer->kind));
            copy_string(answers[i], "failure", answer->failure, sizeof(answer->failure));
            copy_string(answers[i], "cause", answer->cause, sizeof(answer->cause));
            (void)st_json_get_int(answers[i], "status", &answer->status);
            (void)st_json_get_i64(answers[i], "atMs", &answer->at_ms);
        }
    }
    st_json_free_string_array(answers, answers_len);

    st_connectivity_device fake = {fake_presence, fake_probe, fake_now, fake_log, &device};
    st_connectivity_checker *checker = st_connectivity_checker_new(&fake);
    st_connectivity_refusal occupied;
    char admission[32];
    copy_string(input == NULL ? "{}" : input, "admission", admission, sizeof(admission));
    if (strcmp(admission, "route-in-progress") == 0) {
        failed |= st_connectivity_admit(checker, "default", "admin", 42, 0, &occupied) != 0;
    } else if (strcmp(admission, "server-busy") == 0) {
        for (long long id = 1; id <= 32; ++id) {
            char user[32];
            snprintf(user, sizeof(user), "user-%lld", id);
            failed |= st_connectivity_admit(checker, "other", user, 1000 + id, 0, &occupied) != 0;
        }
    }

    const char *body = bool_or(input, "requestValid", 1) ? "" : "{\"path\":\"/../admin\"}";
    st_connectivity_request request = {
        .authenticated = bool_or(input, "authenticated", 1),
        .tenant_id = "default",
        .username = "alice",
        .route_id = "42",
        .body = body,
        .body_len = strlen(body),
    };
    st_connectivity_response response;
    failed |= st_connectivity_handle(checker, &request, fake_load, &routes, &response) != 0;

    int want_status = 0;
    int want_retry = 0;
    (void)st_json_get_int(expect == NULL ? "{}" : expect, "httpStatus", &want_status);
    if (!failed && response.status != want_status) {
        fprintf(stderr, "%s: status %d, want %d\n", name, response.status, want_status);
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
        if (want_status == 401 ? response.body != NULL
                               : response.body == NULL || strcmp(response.body, want_body) != 0) {
            fprintf(stderr, "%s: body %s, want %s\n", name, response.body == NULL ? "(none)" : response.body,
                    want_status == 401 ? "(none)" : want_body);
            failed = 1;
        }
        if (response.retry_after_seconds != want_retry) {
            fprintf(stderr, "%s: Retry-After %d, want %d\n", name, response.retry_after_seconds, want_retry);
            failed = 1;
        }
        if (device.probes != 0U) {
            fprintf(stderr, "%s: a refused check reached the device\n", name);
            failed = 1;
        }
    } else if (!failed) {
        char *body_raw = st_json_get_top_level_raw(expect, "body");
        static char want[8192];
        static char got[8192];
        minify(body_raw == NULL ? "" : body_raw, want, sizeof(want));
        free(body_raw);
        /* Take the runtime fields out; they must be present and well-formed. */
        const char *prefix = "{\"schemaVersion\":1,\"kind\":\"http-route\",\"routeId\":42,\"checkedAt\":\"";
        const char *checked_at = strncmp(response.body, prefix, strlen(prefix)) == 0
            ? response.body + strlen(prefix) : NULL;
        if (checked_at == NULL || strlen(checked_at) < 22U || checked_at[4] != '-' || checked_at[10] != 'T'
            || checked_at[19] != 'Z' || checked_at[20] != '"' || checked_at[21] != ',') {
            fprintf(stderr, "%s: runtime fields malformed in %s\n", name, response.body);
            failed = 1;
        } else {
            snprintf(got, sizeof(got), "{\"schemaVersion\":1,\"kind\":\"http-route\",%s", checked_at + 22);
            if (strcmp(got, want) != 0) {
                fprintf(stderr, "%s: body mismatch\n got: %s\nwant: %s\n", name, got, want);
                failed = 1;
            }
        }
        /* Each request is one probe with the fixed metadata; the log line names no target. */
        for (size_t i = 0; i < device.probes && i < 4U; ++i) {
            const char *metadata = device.metadata[i];
            char *method = st_json_get_top_level_string(metadata, "method");
            char *relative = st_json_get_top_level_string(metadata, "relativePath");
            char *query = st_json_get_top_level_string(metadata, "rawQuery");
            int ok = method != NULL && strcmp(method, i == 0U ? "HEAD" : "GET") == 0
                && relative != NULL && strcmp(relative, "/") == 0 && query != NULL && *query == '\0'
                && strstr(metadata, "\"headers\":[\"Accept:*/*\",\"User-Agent:specus-connectivity-check/1\"]") != NULL
                && strstr(metadata, "contentLength") == NULL && strstr(metadata, "\"requestId\":\"") != NULL;
            free(method);
            free(relative);
            free(query);
            if (!ok) {
                fprintf(stderr, "%s: probe metadata %s\n", name, metadata);
                failed = 1;
            }
        }
        if (strncmp(device.last_log, "[connectivity-check] tenant=default user=alice route=42 outcome=", 64U) != 0
            || strstr(device.last_log, "127.0.0.1") != NULL) {
            fprintf(stderr, "%s: log line %s\n", name, device.last_log);
            failed = 1;
        }
    }
    st_connectivity_response_free(&response);
    st_connectivity_checker_free(checker);
    free(input);
    free(expect);
    free(route_raw);
    free(device_raw);
    return failed;
}

static int run_rate_events(const char *vector)
{
    char *rate = st_json_get_top_level_raw(vector, "rate");
    char **events = NULL;
    size_t events_len = 0;
    if (rate == NULL || st_json_get_raw_array(rate, "events", &events, &events_len) != 0 || events_len == 0U) {
        fprintf(stderr, "rate events did not load\n");
        free(rate);
        return 1;
    }
    fake_device device;
    memset(&device, 0, sizeof(device));
    st_connectivity_device fake = {fake_presence, fake_probe, fake_now, fake_log, &device};
    st_connectivity_checker *limiter = st_connectivity_checker_new(&fake);
    st_connectivity_checker *checker = st_connectivity_checker_new(&fake);
    fake_routes routes = {.readable = 1, .visible = 1};
    snprintf(routes.route.tenant_id, sizeof(routes.route.tenant_id), "default");
    snprintf(routes.route.client_name, sizeof(routes.route.client_name), "device");
    snprintf(routes.route.route, sizeof(routes.route.route), "app");
    snprintf(routes.route.target_base_url, sizeof(routes.route.target_base_url), "http://127.0.0.1/");
    routes.route.route_enabled = 1;
    routes.route.client_enabled = 1;
    int failed = 0;
    for (size_t i = 0; i < events_len; ++i) {
        long long at_ms = 0;
        long long route_id = 0;
        int admitted = 0;
        int status = 0;
        int retry = 0;
        char username[32];
        char code[32];
        char limited_by[16];
        (void)st_json_get_i64(events[i], "atMs", &at_ms);
        (void)st_json_get_i64(events[i], "routeId", &route_id);
        (void)st_json_get_bool(events[i], "admitted", &admitted);
        (void)st_json_get_int(events[i], "httpStatus", &status);
        (void)st_json_get_int(events[i], "retryAfterSeconds", &retry);
        copy_string(events[i], "username", username, sizeof(username));
        copy_string(events[i], "code", code, sizeof(code));
        copy_string(events[i], "limitedBy", limited_by, sizeof(limited_by));

        st_connectivity_refusal refusal;
        int rc = st_connectivity_rate(limiter, "default", username, route_id, at_ms, &refusal);
        if ((rc == 0) != admitted
            || (rc != 0 && (refusal.status != status || strcmp(refusal.code, code) != 0
                            || refusal.limited_by == NULL || strcmp(refusal.limited_by, limited_by) != 0
                            || refusal.retry_after_seconds != retry))) {
            fprintf(stderr, "rate event %zu (%s route %lld at %lld): limiter disagrees\n", i, username, route_id, at_ms);
            failed = 1;
        }

        /* The same event through the whole request: refusals answer 429 and never reach the device. */
        device.now = at_ms;
        char route_text[24];
        snprintf(route_text, sizeof(route_text), "%lld", route_id);
        st_connectivity_request request = {1, "default", username, route_text, "", 0U};
        st_connectivity_response response;
        size_t probes_before = device.probes;
        if (st_connectivity_handle(checker, &request, fake_load, &routes, &response) != 0
            || (admitted ? response.status != 200
                         : response.status != status || response.retry_after_seconds != retry
                               || device.probes != probes_before)) {
            fprintf(stderr, "rate event %zu: handled as %d\n", i, response.status);
            failed = 1;
        }
        st_connectivity_response_free(&response);
    }
    /* alice is refused at 1, 9999, 10008 and 40000 -- one line a minute -- and admin once. */
    if (device.refusal_logs != 2U) {
        fprintf(stderr, "logged %zu rate refusals, want 2\n", device.refusal_logs);
        failed = 1;
    }
    st_json_free_string_array(events, events_len);
    st_connectivity_checker_free(limiter);
    st_connectivity_checker_free(checker);
    free(rate);
    return failed;
}

static int run_request_rules(void)
{
    static const struct {
        const char *body;
        const char *path;
    } valid[] = {
        {"", "/"},
        {"  ", "/"},
        {"{}", "/"},
        {"{\"path\":\"/healthz\"}", "/healthz"},
        {" { \"path\" : \"/a//b\" } ", "/a//b"},
        {"{\"path\":\"/v1/%E4%B8%AD\"}", "/v1/%E4%B8%AD"},
        {"{\"path\":\"/a.b/..c/~x\"}", "/a.b/..c/~x"},
        {"{\"path\":\"/a:b@c!$&'()*+,;=\"}", "/a:b@c!$&'()*+,;="},
        {"{\"path\":\"\\/esc\"}", "/esc"},
    };
    static const char *const invalid[] = {
        "null", "[]", "\"x\"", "1", "{", "{\"path\":null}", "{\"path\":1}", "{\"other\":\"/\"}",
        "{\"path\":\"/\",\"x\":1}", "{\"path\":\"/a\",\"path\":\"/b\"}", "{} {}", "{\"path\":\"\"}",
        "{\"path\":\"healthz\"}", "{\"path\":\"//evil.example/\"}", "{\"path\":\"/a?b\"}", "{\"path\":\"/a#b\"}",
        "{\"path\":\"/a\\\\b\"}", "{\"path\":\"/a b\"}", "{\"path\":\"/a\\tb\"}", "{\"path\":\"/.\"}",
        "{\"path\":\"/a/../b\"}", "{\"path\":\"/%2e%2E/x\"}", "{\"path\":\"/a/%2e\"}", "{\"path\":\"/%zz\"}",
        "{\"path\":\"/%4\"}", "{\"path\":\"/\\u00e4\"}", "{\"path\":\"/a\\u0000\"}",
    };
    int failed = 0;
    char path[ST_CONNECTIVITY_MAX_PATH_BYTES + 2U];
    for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); ++i) {
        if (st_connectivity_parse_body(valid[i].body, strlen(valid[i].body), path, sizeof(path)) != 0
            || strcmp(path, valid[i].path) != 0) {
            fprintf(stderr, "body %s refused or misread as %s\n", valid[i].body, path);
            failed = 1;
        }
    }
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        if (st_connectivity_parse_body(invalid[i], strlen(invalid[i]), path, sizeof(path)) == 0) {
            fprintf(stderr, "body %s accepted as %s\n", invalid[i], path);
            failed = 1;
        }
    }
    char long_body[400];
    char long_path[260];
    memset(long_path, 'a', sizeof(long_path));
    long_path[0] = '/';
    long_path[256] = '\0';
    snprintf(long_body, sizeof(long_body), "{\"path\":\"%s\"}", long_path);
    failed |= st_connectivity_parse_body(long_body, strlen(long_body), path, sizeof(path)) != 0;
    long_path[256] = 'a';
    long_path[257] = '\0';
    snprintf(long_body, sizeof(long_body), "{\"path\":\"%s\"}", long_path);
    failed |= st_connectivity_parse_body(long_body, strlen(long_body), path, sizeof(path)) == 0;
    char oversized[ST_CONNECTIVITY_MAX_BODY_BYTES + 2U];
    memset(oversized, ' ', sizeof(oversized) - 1U);
    oversized[sizeof(oversized) - 1U] = '\0';
    failed |= st_connectivity_parse_body(oversized, strlen(oversized), path, sizeof(path)) == 0;

    static const char *const targets_ok[] = {"http://127.0.0.1:8080", "https://example.com/base/", "HTTP://host",
                                             "http://[::1]:80/"};
    static const char *const targets_bad[] = {"", "ftp://host/", "http://", "/relative", "http:///path", "host:80",
                                              "http://a b/"};
    for (size_t i = 0; i < sizeof(targets_ok) / sizeof(targets_ok[0]); ++i) {
        failed |= !st_connectivity_valid_target_base_url(targets_ok[i]);
    }
    for (size_t i = 0; i < sizeof(targets_bad) / sizeof(targets_bad[0]); ++i) {
        failed |= st_connectivity_valid_target_base_url(targets_bad[i]);
    }
    if (failed) {
        fprintf(stderr, "request rules failed\n");
    }
    return failed;
}

int main(void)
{
    char *vector = read_vector();
    if (vector == NULL) {
        return 1;
    }
    long long budget = 0;
    char **cases = NULL;
    size_t cases_len = 0;
    if (st_json_get_i64(vector, "checkBudgetMs", &budget) != 0 || budget != ST_CONNECTIVITY_BUDGET_MS
        || st_json_get_raw_array(vector, "cases", &cases, &cases_len) != 0 || cases_len == 0U) {
        fprintf(stderr, "vector did not load\n");
        free(vector);
        return 1;
    }
    int failed = 0;
    size_t passed = 0;
    for (size_t i = 0; i < cases_len; ++i) {
        if (run_case(cases[i]) == 0) {
            ++passed;
        } else {
            failed = 1;
        }
    }
    printf("connectivity vector: %zu/%zu cases passed\n", passed, cases_len);
    st_json_free_string_array(cases, cases_len);
    failed |= run_rate_events(vector);
    failed |= run_request_rules();
    free(vector);
    return failed ? 1 : 0;
}
