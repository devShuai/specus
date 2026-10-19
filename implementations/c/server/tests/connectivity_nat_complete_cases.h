/* Remaining NatConnectivityProbeTests assertions on actual process/socket paths. */
static int complete_string(const char *object, const char *key, const char *expected)
{
    return parity_string(object, key, expected);
}

static int complete_reply(const connectivity_call *call, const char *outcome, const char *stage,
                          const char *code, const char *requests, const char *status_class)
{
    CHECK(call->status == 200 && call->body != NULL, "complete NAT HTTP%d %s", call->status,
          call->body == NULL ? "" : call->body);
    char *actual_requests = st_json_get_top_level_raw(call->body, "requests");
    char *actual_class = st_json_get_top_level_string(call->body, "statusClass");
    char *raw_class = st_json_get_top_level_raw(call->body, "statusClass");
    char *actual_stage = st_json_get_top_level_raw(call->body, "stoppedAt");
    int failed = complete_string(call->body, "outcome", outcome)
        || (stage == NULL ? actual_stage == NULL || strcmp(actual_stage, "null") != 0
                          : complete_string(call->body, "stoppedAt", stage))
        || complete_string(call->body, "code", code)
        || actual_requests == NULL || strcmp(actual_requests, requests) != 0
        || (status_class == NULL ? raw_class != NULL
                                : actual_class == NULL || strcmp(actual_class, status_class) != 0);
    const char *leaks[] = {"10.20.30.40", "s3cret", "connection refused", "Server", "10.9.9.9"};
    for (size_t i = 0U; i < sizeof(leaks) / sizeof(leaks[0]); ++i)
        if (strstr(call->body, leaks[i]) != NULL) failed = 1;
    free(actual_requests); free(actual_class); free(raw_class); free(actual_stage);
    CHECK(!failed, "complete NAT expected%s/%s/%s, got%s", outcome, stage == NULL ? "null" : stage, code, call->body);
    return 0;
}

static int complete_open(int fd, const char *method, const char *route, uint32_t *stream)
{
    st_nat_message frame;
    CHECK(next_nat_frame(fd, monotonic_ms() + IO_TIMEOUT_MS, &frame) == 1, "complete NAT OPEN missing");
    char *id = frame.meta_json == NULL ? NULL : st_json_get_top_level_string(frame.meta_json, "requestId");
    int failed = frame.type != ST_NAT_OPEN || frame.flags != 0U || frame.stream_id == 0U
        || frame.value != 0U || frame.data_len != 0U || id == NULL || strlen(id) != 32U;
    for (size_t i = 0U; !failed && i < 32U; ++i)
        if (!((id[i] >= '0' && id[i] <= '9') || (id[i] >= 'a' && id[i] <= 'f'))) failed = 1;
    char expected[1024];
    if (!failed) {
        int size = snprintf(expected, sizeof(expected),
            "{\"source\":\"http\",\"phase\":\"request\",\"requestId\":\"%s\",\"method\":\"%s\",\"route\":\"%s\","
            "\"relativePath\":\"/\",\"rawQuery\":\"\",\"headers\":[\"Accept:*/*\",\"User-Agent:specus-connectivity-check/1\"]}",
            id, method, route);
        failed = size < 0 || (size_t)size >= sizeof(expected) || strcmp(frame.meta_json, expected) != 0;
    }
    if (failed) fprintf(stderr, "complete NAT metadata: %s\n", frame.meta_json == NULL ? "NULL" : frame.meta_json);
    *stream = frame.stream_id;
    free(id); st_nat_message_free(&frame);
    CHECK(!failed, "complete NAT OPEN field order/value/id differs");
    st_frame_header header;
    uint8_t *raw = NULL;
    CHECK(read_frame(fd, IO_TIMEOUT_MS, &header, &raw) == 1, "complete NAT FIN missing");
    int decoded = header.command == ST_CMD_NAT_MESSAGE
        && st_protocol_decode_nat_message(raw, header.length, &frame) == 0;
    failed = !decoded || header.length != 16U || raw[2] != 0U || raw[3] != 0U;
    free(raw);
    CHECK(decoded, "complete NAT FIN decode");
    failed |= frame.type != ST_NAT_FIN || frame.flags != 0U || frame.stream_id != *stream
        || frame.value != 0U || frame.data_len != 0U;
    st_nat_message_free(&frame);
    CHECK(!failed, "complete NAT OPEN must be followed by its empty FIN");
    return 0;
}

static int complete_reset(int fd, uint32_t stream, long long deadline)
{
    st_nat_message frame;
    CHECK(next_nat_frame(fd, deadline, &frame) == 1, "complete NAT server RST missing");
    int failed = frame.type != ST_NAT_RST || frame.stream_id != stream || frame.value != 1U
        || frame.flags != 0U || frame.data_len != 0U;
    st_nat_message_free(&frame);
    CHECK(!failed, "complete NAT server RST order/id/code differs");
    return 0;
}

static int complete_response(int fd, uint32_t stream, int status, int fin)
{
    char metadata[256];
    snprintf(metadata, sizeof(metadata), "{\"source\":\"http\",\"phase\":\"response\",\"statusCode\":%d,"
        "\"headers\":[\"Server:secret-server\",\"Location:http://10.9.9.9/\"]}", status);
    CHECK(send_nat(fd, ST_NAT_OPEN, 0U, stream, 0U, metadata, NULL, 0U) == 0, "complete NAT response head");
    if (fin) CHECK(send_nat(fd, ST_NAT_FIN, 0U, stream, 0U, NULL, NULL, 0U) == 0, "complete NAT response FIN");
    return 0;
}

static int complete_fallback(test_server *server, client_pair *pair)
{
    connectivity_call call;
    pthread_t thread;
    CHECK(parity_begin(server, &call, &thread) == 0, "begin complete fallback");
    uint32_t head = 0U, get = 0U;
    int failed = complete_open(pair->data, "HEAD", ROUTE, &head)
        || complete_response(pair->data, head, 405, 0)
        || complete_reset(pair->data, head, monotonic_ms() + IO_TIMEOUT_MS)
        || complete_open(pair->data, "GET", ROUTE, &get) || get == head
        || complete_response(pair->data, get, 204, 1);
    pthread_join(thread, NULL);
    if (!failed) failed = complete_reply(&call, "succeeded", NULL, "ACCESS_OK", "[\"HEAD\",\"GET\"]", "2xx");
    free(call.body);
    CHECK(!failed, "complete NAT fallback/frame metadata");
    CHECK(expect_alive_without_stream_reply(pair->data, get) == 0, "FIN-ended GET must not be reset");
    CHECK(check_stale_probe_frames(pair->data, head) == 0, "complete fallback stale HEAD");
    CHECK(check_stale_probe_frames(pair->data, get) == 0, "complete fallback stale FIN-ended GET");
    puts("connectivity NAT complete:HEAD OPEN/emptyFIN/RST,GET OPEN/emptyFIN,full metadata and stale frames passed");
    return expect_data_connection_served(server, pair);
}

/* Only this new 10-second silence test needs a 12-second HTTP observation window. The existing
 * harness's 5-second I/O gate is untouched, as are the actual production 10-second probe budget. */
static void *complete_long_http(void *arg)
{
    connectivity_call *call = arg;
    call->status = 0; call->body = NULL;
    char token[1024], request[2048];
    if (st_security_issue_local_token(ADMIN_USERNAME, "default", "ADMIN", ADMIN_JWT_SECRET, 600,
                                      token, sizeof(token)) != 0) return NULL;
    int length = snprintf(request, sizeof(request),
        "POST /api/admin/http-routes/%lld/connectivity-check HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        "Authorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
        call->route_id, token);
    int fd = connect_local(call->server->admin_port);
    if (fd < 0) return NULL;
    if (length < 0 || (size_t)length >= sizeof(request)
        || send_all(fd, (const uint8_t *)request, (size_t)length) != 0) { close(fd); return NULL; }
    char response[16384]; size_t used = 0U;
    long long deadline = monotonic_ms() + 12000LL;
    int eof = 0;
    while (used < sizeof(response) - 1U) {
        long long remaining = deadline - monotonic_ms();
        if (remaining <= 0) break;
        struct pollfd ready = {fd, POLLIN, 0};
        int rc = poll(&ready, 1, (int)remaining);
        if (rc < 0 && errno == EINTR) continue;
        if (rc <= 0) break;
        ssize_t got = recv(fd, response + used, sizeof(response) - 1U - used, 0);
        if (got < 0 && errno == EINTR) continue;
        if (got == 0) { eof = 1; break; }
        if (got < 0) break;
        used += (size_t)got;
    }
    close(fd); response[used] = '\0';
    char *body = strstr(response, "\r\n\r\n");
    if (eof && body != NULL && st_json_is_valid_object(body + 4)
        && sscanf(response, "HTTP/1.1 %d", &call->status) == 1) call->body = strdup(body + 4);
    return NULL;
}

static int complete_silence(test_server *server, client_pair *pair)
{
    char route_id[32];
    CHECK(db_scalar(server->db_path, "SELECT id FROM http_route_mapping WHERE route = ?", ROUTE, 0,
                    route_id, sizeof(route_id)) == 0, "complete silence route");
    connectivity_call call = {server, atoll(route_id), 0, NULL};
    pthread_t thread;
    long long started = monotonic_ms();
    CHECK(pthread_create(&thread, NULL, complete_long_http, &call) == 0, "complete silence thread");
    uint32_t stream = 0U;
    int failed = complete_open(pair->data, "HEAD", ROUTE, &stream)
        || complete_reset(pair->data, stream, started + 12000LL);
    long long elapsed = monotonic_ms() - started;
    pthread_join(thread, NULL);
    if (!failed) failed = elapsed < 9900LL
        || complete_reply(&call, "failed", "target-reachable", "TARGET_TIMEOUT", "[\"HEAD\"]", NULL);
    long long total = -1;
    if (!failed) failed = st_json_get_i64(call.body, "totalMs", &total) != 0 || total != 10000LL;
    free(call.body);
    CHECK(!failed, "complete silence must honor10s and reset its stream (elapsed%lld)", elapsed);
    CHECK(complete_response(pair->data, stream, 200, 0) == 0, "late response after actual timeout");
    CHECK(expect_alive_without_stream_reply(pair->data, stream) == 0, "late timeout head must be silently dropped");
    printf("connectivity NAT complete:actual10s silence/OPEN FIN RST/late head silent passed,elapsedMs=%lld\n", elapsed);
    return expect_data_connection_served(server, pair);
}

static int complete_offline(const test_server *server, long long route, const char *code)
{
    connectivity_call call = {server, route, 0, NULL};
    run_connectivity_check(&call);
    int failed = complete_reply(&call, "failed", "device-online", code, "[]", NULL);
    free(call.body);
    return failed;
}

static int complete_session_exchange(test_server *server, int data, long long route, const char *name,
                                     const char *code, const char *outcome)
{
    connectivity_call call = {server, route, 0, NULL};
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, run_connectivity_check, &call) == 0, "session probe thread");
    uint32_t stream = 0U;
    int failed = complete_open(data, "HEAD", name, &stream)
        || send_nat(data, ST_NAT_RST, 0U, stream, 26U,
              "{\"reason\":\"dial tcp 10.20.30.40:8080: connection refused (GET /admin?token=s3cret)\","
              "\"failure\":\"connect-refused\"}", NULL, 0U) != 0;
    pthread_join(thread, NULL);
    if (!failed) failed = complete_reply(&call, outcome, "target-reachable", code, "[\"HEAD\"]", NULL);
    free(call.body);
    CHECK(!failed, "capability of actual bound session differs");
    return expect_alive_without_stream_reply(data, stream);
}

static int complete_sessions(test_server *server)
{
    runtime_session legacy, capable;
    int control = -1, data = -1, next_control = -1, next_data = -1;
    char reason[256];
    CHECK(create_credential(server->db_path, "ck_nat_sessions", "nat-session-secret", 3) == 0, "session credential");
    CHECK(http_client_login(server, "ck_nat_sessions", "nat-session-secret", "nat-session-machine", "alice", &legacy) == 0,
          "legacy HTTP auth");
    long long routes[7];
    char names[7][32];
    for (size_t i = 0U; i < 7U; ++i) {
        snprintf(names[i], sizeof(names[i]), "session-%zu", i);
        st_storage_http_route route;
        CHECK(st_storage_create_http_route_for_client(server->db_path, legacy.client_id, names[i],
            "http://127.0.0.1:9", 1, 0, 0, 0, 0, 0, NULL, NULL, &route) == 0, "session route");
        routes[i] = route.id;
    }
    CHECK(complete_offline(server, routes[0], "DEVICE_OFFLINE") == 0, "unbound client offline");
    CHECK(channel_login(server->control_port, &legacy, "control", &control, reason, sizeof(reason)) == 1,
          "session control bind: %s", reason);
    CHECK(complete_offline(server, routes[1], "DEVICE_DATA_CHANNEL_DOWN") == 0, "control-only link");
    CHECK(channel_login(server->control_port, &legacy, "data", &data, reason, sizeof(reason)) == 1,
          "legacy data bind: %s", reason);
    CHECK(complete_session_exchange(server, data, routes[2], names[2], "TARGET_UNVERIFIED", "unverified") == 0,
          "legacy bound version0");
    harness_login_environment_extra = ",\"clientHttpRouteCapabilities\":{\"version\":1}";
    int logged_in = http_client_login(server, "ck_nat_sessions", "nat-session-secret", "nat-session-machine", "alice", &capable);
    harness_login_environment_extra = "";
    CHECK(logged_in == 0 && capable.client_id == legacy.client_id && capable.session_id != legacy.session_id,
          "capable HTTP session must preserve client identity, create new session");
    CHECK(complete_session_exchange(server, data, routes[3], names[3], "TARGET_UNVERIFIED", "unverified") == 0,
          "unbound newer capability must not affect bound legacy data");
    CHECK(channel_login(server->control_port, &capable, "control", &next_control, reason, sizeof(reason)) == 1,
          "replace control with version1 session: %s", reason);
    CHECK(expect_channel_closed(control, IO_TIMEOUT_MS) == 0 && expect_channel_closed(data, IO_TIMEOUT_MS) == 0,
          "new control must retire old pair");
    close_fd(&control); close_fd(&data);
    CHECK(channel_login(server->control_port, &capable, "data", &next_data, reason, sizeof(reason)) == 1,
          "capable data bind: %s", reason);
    CHECK(complete_session_exchange(server, next_data, routes[4], names[4], "TARGET_CONNECT_REFUSED", "failed") == 0,
          "new bound data version1");
    CHECK(shutdown(next_data, SHUT_WR) == 0 && expect_channel_closed(next_data, IO_TIMEOUT_MS) == 0,
          "wait for data removal, not an arbitrary sleep");
    close_fd(&next_data);
    CHECK(expect_channel_alive(next_control) == 0, "data closure leaves control");
    CHECK(complete_offline(server, routes[5], "DEVICE_DATA_CHANNEL_DOWN") == 0, "removed data link");
    CHECK(shutdown(next_control, SHUT_WR) == 0 && expect_channel_closed(next_control, IO_TIMEOUT_MS) == 0,
          "wait for control removal");
    close_fd(&next_control);
    CHECK(complete_offline(server, routes[6], "DEVICE_OFFLINE") == 0, "removed control link");
    puts("connectivity NAT complete:same client offline/control/data v0/unbound v1/bound v1/data-down/offline passed");
    return 0;
}

static int run_nat_complete_cases(void)
{
    if (!selected("connectivity NAT complete")) return 0;
    int failures = 0;
    static const char *const await_get[] = {"SPECUS_CONTROL_READ_IDLE_SECONDS=900",
        "SPECUS_CONNECTIVITY_PROBE_TEST_AWAIT_END=get", NULL};
    static const char *const two_per_machine[] = {"SPECUS_CONTROL_READ_IDLE_SECONDS=900",
        "SPECUS_CLIENT_AUTH_PER_MACHINE_USER_MAX_INSTANCES=2", NULL};
    current_check = complete_fallback;
    failures += run_on_fresh_server("connectivity NAT complete fixed metadata and mixed reset/FIN fallback",
                                    run_current_check_capable, await_get);
    current_check = complete_silence;
    failures += run_on_fresh_server("connectivity NAT complete silent device timeout", run_current_check_capable, long_idle);
    failures += run_on_fresh_server("connectivity NAT complete live session/capability transitions", complete_sessions, two_per_machine);
    return failures;
}
