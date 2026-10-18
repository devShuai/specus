#define main retained_session_lifecycle_test_entry
#include "session_lifecycle_tests.c"
#undef main

static const char *const observation_names[] = {
    "push-send-lock-entered", "push-kernel-reset-observed", "push-handler-result"
};

static int clear_push_observation(void)
{
    for (size_t i = 0; i < sizeof(observation_names)/sizeof(observation_names[0]); ++i) {
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", login_gate_dir, observation_names[i]);
        if (unlink(path) != 0 && errno != ENOENT) return -1;
    }
    return 0;
}

static int wait_push_observation(const char *name, long long expected)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", login_gate_dir, name);
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    do {
        FILE *file = fopen(path, "r");
        long long value = 0;
        int read_value = file != NULL && fscanf(file, "%lld", &value) == 1;
        if (file != NULL) fclose(file);
        if (read_value) {
            if (value == expected) return 0;
            fprintf(stderr, "%s observed %lld, expected %lld\n", name, value, expected);
            return -1;
        }
        sleep_ms(1);
    } while (monotonic_ms() < deadline);
    fprintf(stderr, "missing actual NAT_CONTROL observation: %s\n", name);
    return -1;
}

static int check_persisted_route(test_server *server, const runtime_session *runtime,
                                 long long id, const char *route, const char *target, int exists)
{
    char count[32];
    if (db_scalar(server->db_path, "SELECT COUNT(*) FROM http_route_mapping WHERE id=?",
                  NULL, id, count, sizeof(count)) != 0 || strcmp(count, exists ? "1" : "0") != 0) return -1;
    if (!exists) return 0;
    st_storage_http_route row;
    int found = 0;
    return st_storage_find_http_route_by_id(server->db_path, id, &row, &found) == 0 && found
        && strcmp(row.client_name, runtime->client_name) == 0 && strcmp(row.route, route) == 0
        && strcmp(row.target_base_url, target) == 0 && row.enabled ? 0 : -1;
}

static int replay_all_write_failures(test_server *server)
{
    char *token = admin_access_token(server);
    CHECK(token != NULL, "admin login");
    int status = 0;
    char *created = NULL;
    CHECK(http_request(server->admin_port, "POST", "/api/admin/client-credentials",
                         "{\"enabled\":true,\"maxOnlineInstances\":2}", token, &status, &created) == 0
              && status == 201, "fresh management credential");
    char *credential = st_json_get_top_level_raw(created, "credential");
    char *key = credential == NULL ? NULL : st_json_get_top_level_string(credential, "apiKey");
    char *secret = st_json_get_top_level_string(created, "secret");
    runtime_session runtime;
    int authenticated = key != NULL && secret != NULL
        && http_client_login(server, key, secret, "machine-push-write-failure", "vector", &runtime) == 0;
    free(credential);
    free(key);
    free(secret);
    free(created);
    CHECK(authenticated, "real HTTP login with freshly created credential");

    char *vector = read_text_file(ST_NAT_CONTROL_SIZE_VECTOR_FILE);
    char *scenario = vector == NULL ? NULL : st_json_get_top_level_raw(vector, "writeFailure");
    char *error = scenario == NULL ? NULL : st_json_get_top_level_string(scenario, "errorContains");
    char **steps = NULL;
    size_t step_count = 0U;
    int loaded = error != NULL && st_json_get_raw_array(scenario, "steps", &steps, &step_count) == 0;
    free(vector);
    free(scenario);
    CHECK(loaded && step_count == 4U, "complete shared writeFailure four-step contract");
    long long route_id = 0;
    char persisted_route[128] = "";
    char persisted_target[512] = "";
    for (size_t i = 0; i < step_count; ++i) {
        clear_login_gate();
        CHECK(clear_push_observation() == 0, "clear previous step observation");
        int control = -1;
        CHECK(start_held_login(server, &runtime, "control", "published", &control) == 0,
              "step %zu: same HTTP session's real control published and held", i);
        char *op = st_json_get_top_level_string(steps[i], "op");
        int expect = 0;
        CHECK(op != NULL && st_json_get_int(steps[i], "expect", &expect) == 0, "step shape");
        char path[192];
        char body[1024];
        const char *method = "POST";
        const char *request_body = NULL;
        if (strcmp(op, "createRoute") == 0) {
            char *route = st_json_get_top_level_string(steps[i], "route");
            char *target = st_json_get_top_level_string(steps[i], "targetBaseUrl");
            int enabled = 0;
            CHECK(route != NULL && target != NULL && st_json_get_bool(steps[i], "enabled", &enabled) == 0
                      && enabled && strlen(route) < sizeof(persisted_route)
                      && strlen(target) < sizeof(persisted_target), "createRoute input");
            snprintf(persisted_route, sizeof(persisted_route), "%s", route);
            snprintf(persisted_target, sizeof(persisted_target), "%s", target);
            char *escaped_route = st_json_escape(route);
            char *escaped_target = st_json_escape(target);
            CHECK(escaped_route != NULL && escaped_target != NULL, "escape route fields");
            int length = snprintf(body, sizeof(body), "{\"route\":\"%s\",\"targetBaseUrl\":\"%s\",\"enabled\":true}",
                                  escaped_route, escaped_target);
            free(escaped_route);
            free(escaped_target);
            free(route);
            free(target);
            CHECK(length > 0 && (size_t)length < sizeof(body), "complete createRoute body");
            snprintf(path, sizeof(path), "/api/admin/clients/%lld/http-routes", runtime.client_id);
            request_body = body;
        } else if (strcmp(op, "pushNatControl") == 0 || strcmp(op, "forceRefreshPortMapping") == 0) {
            snprintf(path, sizeof(path), "/api/admin/clients/%lld/%s", runtime.client_id,
                     strcmp(op, "pushNatControl") == 0 ? "nat-control" : "force-refresh-port-mapping");
        } else if (strcmp(op, "deleteRoute") == 0) {
            CHECK(route_id > 0, "delete the route created by step0");
            char *route = st_json_get_top_level_string(steps[i], "route");
            int same_route = route != NULL && strcmp(route, persisted_route) == 0;
            free(route);
            CHECK(same_route, "deleteRoute names the route created by step0");
            method = "DELETE";
            snprintf(path, sizeof(path), "/api/admin/http-routes/%lld", route_id);
        } else {
            CHECK(0, "unknown shared writeFailure op %s", op);
        }
        int request = http_request_start(server->admin_port, method, path, request_body, token);
        CHECK(request >= 0, "step %zu %s: actual API request", i, op);
        CHECK(wait_push_observation("push-send-lock-entered", runtime.client_id) == 0,
              "step %zu %s: production NAT_CONTROL reached the real control send lock", i, op);
        reset_fd(&control);
        CHECK(wait_push_observation("push-kernel-reset-observed", runtime.client_id) == 0,
              "step %zu %s: actual kernel reset before releasing login", i, op);
        CHECK(release_login_gate("control", "published") == 0, "release held login after observed RST");
        char answer[4096];
        http_response_text(request, answer, sizeof(answer));
        close_fd(&request);
        status = -1;
        CHECK(sscanf(answer, "HTTP/1.1 %d", &status) == 1 && status == expect,
              "step %zu %s answered %d, expected %d: %s", i, op, status, expect, answer);
        char *payload = strstr(answer, "\r\n\r\n");
        if (status == 409) {
            char *reason = payload != NULL && st_json_is_valid_object(payload + 4)
                ? st_json_get_top_level_string(payload + 4, "error") : NULL;
            int expected_reason = reason != NULL && strstr(reason, error) != NULL;
            free(reason);
            CHECK(expected_reason, "offline JSON error field contains shared error");
        }
        CHECK(wait_push_observation("push-handler-result", -1) == 0,
              "step %zu %s: real NAT_CONTROL handler returned failed write", i, op);
        if (strcmp(op, "createRoute") == 0) {
            CHECK(payload != NULL && st_json_get_i64(payload+4, "id", &route_id) == 0 && route_id > 0,
                  "created route id from actual REST response");
        }
        CHECK(check_persisted_route(server, &runtime, route_id, persisted_route, persisted_target,
                                     strcmp(op, "deleteRoute") != 0) == 0,
              "step %zu %s: persistence unchanged by failed push", i, op);
        CHECK(wait_session_status(server->db_path, runtime.session_id, "DISCONNECTED", IO_TIMEOUT_MS) == 0,
              "step %zu %s: failed real channel retired before the next same-token login", i, op);
        printf("NAT push reference step%zu %s: actual send-lock attempt, kernel RST, failed handler, HTTP%d and persistent route state passed\n",
               i, op, status);
        free(op);
    }
    st_json_free_string_array(steps, step_count);
    free(error);
    free(token);
    clear_login_gate();
    CHECK(clear_push_observation() == 0, "final observer cleanup");
    puts("NAT push reference: all4 shared writeFailure steps, same HTTP session and persistent route, real failed writes passed");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    server_binary = argv[1];
    signal(SIGPIPE, SIG_IGN);
    snprintf(login_gate_dir, sizeof(login_gate_dir), "/tmp/specus-c-push-ref-XXXXXX");
    if (mkdtemp(login_gate_dir) == NULL) return 1;
    snprintf(login_gate_env, sizeof(login_gate_env), "SPECUS_LOGIN_TEST_GATE_DIR=%s", login_gate_dir);
    const char *const environment[] = {login_gate_env, NULL};
    int failed = run_on_fresh_server("all-four-NAT_CONTROL-write-failure-steps", replay_all_write_failures, environment);
    clear_login_gate();
    (void)clear_push_observation();
    if (rmdir(login_gate_dir) != 0) failed = 1;
    return failed;
}
