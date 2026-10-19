/* Real-process/socket supplements for NatConnectivityProbeTests. Included after the NAT harness
 * helpers so all original stream scenarios and their unchanged limits remain in the same target. */
static const char *parity_failure;
static const char *parity_code;
static const char *parity_stage;
static const char *parity_outcome;
static int parity_status;

/* A valid unique-key object: count only its own members, never nested fields or quoted colons. */
static size_t parity_member_count(const char *json)
{
    if (!st_json_is_valid_object(json) || !st_json_object_keys_unique(json)) return (size_t)-1;
    size_t members = 0U;
    int depth = 0, quoted = 0, escaped = 0;
    for (const char *at = json; *at != '\0'; ++at) {
        if (quoted) {
            if (escaped) escaped = 0;
            else if (*at == '\\') escaped = 1;
            else if (*at == '"') quoted = 0;
        } else if (*at == '"') quoted = 1;
        else if (*at == '{' || *at == '[') ++depth;
        else if (*at == '}' || *at == ']') --depth;
        else if (*at == ':' && depth == 1) ++members;
    }
    return members;
}

static int parity_string(const char *object, const char *key, const char *expected)
{
    char *actual = st_json_get_top_level_string(object, key);
    int failed = actual == NULL || strcmp(actual, expected) != 0;
    free(actual);
    return failed;
}

static int parity_result(const connectivity_call *call)
{
    CHECK(call->status == 200 && call->body != NULL, "NAT parity HTTP%d %s", call->status,
          call->body == NULL ? "" : call->body);
    char *requests = st_json_get_top_level_raw(call->body, "requests");
    char *status_class = st_json_get_top_level_raw(call->body, "statusClass");
    char **stages = NULL;
    size_t count = 0U;
    int failed = parity_string(call->body, "code", parity_code)
        || parity_string(call->body, "stoppedAt", parity_stage)
        || parity_string(call->body, "outcome", parity_outcome)
        || requests == NULL || strcmp(requests, "[\"HEAD\"]") != 0 || status_class != NULL
        || st_json_get_raw_array(call->body, "stages", &stages, &count) != 0 || count != 4U;
    if (!failed && strcmp(parity_stage, "device-online") != 0)
        failed = parity_string(stages[1], "code", "DEVICE_ONLINE");
    const char *leaks[] = {"10.20.30.40", "s3cret", "connection refused", "Server", "10.9.9.9"};
    for (size_t i = 0U; i < sizeof(leaks) / sizeof(leaks[0]); ++i)
        if (strstr(call->body, leaks[i]) != NULL) failed = 1;
    free(requests); free(status_class); st_json_free_string_array(stages, count);
    CHECK(!failed, "NAT parity expected %s/%s/%s, got %s", parity_outcome, parity_stage, parity_code, call->body);
    return 0;
}

/* Do not skip other NAT frames: these must be the first OPEN, then its empty FIN. */
static int parity_open_and_fin(int data_fd, uint32_t *stream)
{
    st_nat_message frame;
    CHECK(next_nat_frame(data_fd, monotonic_ms() + IO_TIMEOUT_MS, &frame) == 1, "NAT parity OPEN missing");
    int failed = frame.type != ST_NAT_OPEN || frame.stream_id == 0U || frame.flags != 0U || frame.data_len != 0U;
    *stream = frame.stream_id;
    st_nat_message_free(&frame);
    CHECK(!failed, "NAT parity first frame is not request OPEN");
    st_frame_header header;
    uint8_t *raw = NULL;
    CHECK(read_frame(data_fd, IO_TIMEOUT_MS, &header, &raw) == 1, "NAT parity FIN missing");
    /* Decoder maps absent metadata to an allocated {}, so inspect zero length on the actual wire. */
    int decoded = header.command == ST_CMD_NAT_MESSAGE
        && st_protocol_decode_nat_message(raw, header.length, &frame) == 0;
    failed = !decoded || header.length != 16U || raw[2] != 0U || raw[3] != 0U;
    free(raw);
    CHECK(decoded, "NAT parity FIN decode failed");
    failed |= frame.type != ST_NAT_FIN || frame.stream_id != *stream || frame.flags != 0U
        || frame.value != 0U || frame.data_len != 0U;
    st_nat_message_free(&frame);
    CHECK(!failed, "NAT parity request FIN shape/order differs");
    return 0;
}

static int parity_begin(test_server *server, connectivity_call *call, pthread_t *thread)
{
    char route_id[32];
    CHECK(db_scalar(server->db_path, "SELECT id FROM http_route_mapping WHERE route = ?", ROUTE, 0,
                    route_id, sizeof(route_id)) == 0, "NAT parity route id");
    *call = (connectivity_call){server, atoll(route_id), 0, NULL};
    CHECK(pthread_create(thread, NULL, run_connectivity_check, call) == 0, "NAT parity check thread");
    return 0;
}

static int parity_reset(test_server *server, client_pair *pair)
{
    connectivity_call call;
    pthread_t thread;
    CHECK(parity_begin(server, &call, &thread) == 0, "begin reset scenario");
    uint32_t stream = 0U;
    char metadata[512];
    snprintf(metadata, sizeof(metadata),
        "{\"reason\":\"dial tcp 10.20.30.40:8080: connect: connection refused (GET /admin?token=s3cret)\"%s%s%s}",
        parity_failure == NULL ? "" : ",\"failure\":\"", parity_failure == NULL ? "" : parity_failure,
        parity_failure == NULL ? "" : "\"");
    int failed = parity_open_and_fin(pair->data, &stream)
        || send_nat(pair->data, ST_NAT_RST, 0U, stream, 26U, metadata, NULL, 0U) != 0;
    pthread_join(thread, NULL);
    if (!failed) failed = parity_result(&call);
    free(call.body);
    CHECK(!failed, "NAT parity reset exchange");
    /* The client reset ended it: no server RST or WINDOW_UPDATE may follow before this barrier. */
    CHECK(expect_alive_without_stream_reply(pair->data, stream) == 0, "server replied to client-ended probe");
    return expect_data_connection_served(server, pair);
}

static int parity_bad_status(test_server *server, client_pair *pair)
{
    connectivity_call call;
    pthread_t thread;
    CHECK(parity_begin(server, &call, &thread) == 0, "begin invalid status");
    uint32_t stream = 0U;
    char metadata[256];
    snprintf(metadata, sizeof(metadata), "{\"source\":\"http\",\"phase\":\"response\",\"statusCode\":%d,"
        "\"headers\":[\"Server:secret-server\",\"Location:http://10.9.9.9/\"]}", parity_status);
    int failed = parity_open_and_fin(pair->data, &stream)
        || send_nat(pair->data, ST_NAT_OPEN, 0U, stream, 0U, metadata, NULL, 0U) != 0
        || send_nat(pair->data, ST_NAT_FIN, 0U, stream, 0U, NULL, NULL, 0U) != 0;
    pthread_join(thread, NULL);
    if (!failed) failed = parity_result(&call);
    free(call.body);
    CHECK(!failed, "NAT parity invalid response status %d", parity_status);
    return expect_data_connection_served(server, pair);
}

static int parity_closed_link(test_server *server, client_pair *pair)
{
    connectivity_call call;
    pthread_t thread;
    CHECK(parity_begin(server, &call, &thread) == 0, "begin closed data link");
    uint32_t stream = 0U;
    int failed = parity_open_and_fin(pair->data, &stream);
    close_fd(&pair->data);
    pthread_join(thread, NULL);
    if (!failed) failed = parity_result(&call);
    free(call.body);
    CHECK(!failed, "NAT parity data close must be DEVICE_LINK_LOST");
    CHECK(expect_channel_alive(pair->control) == 0, "data close must preserve control");
    CHECK(login_data(server, pair) == 0, "rebind data after lost probe");
    return expect_data_connection_served(server, pair);
}

static char *parity_vector(void)
{
    FILE *file = fopen(ST_CONNECTIVITY_VECTOR_DIR "service-connectivity-check-v1.json", "rb");
    if (file == NULL) return NULL;
    if (fseek(file, 0, SEEK_END) != 0) { fclose(file); return NULL; }
    long length = ftell(file);
    if (length < 0 || length > 1024 * 1024 || fseek(file, 0, SEEK_SET) != 0) { fclose(file); return NULL; }
    char *text = malloc((size_t)length + 1U);
    if (text == NULL || fread(text, 1U, (size_t)length, file) != (size_t)length) {
        free(text); fclose(file); return NULL;
    }
    text[length] = '\0';
    fclose(file);
    return text;
}

static int run_nat_parity_cases(void)
{
    if (!selected("connectivity NAT parity")) return 0;
    char *vector = parity_vector();
    char *failures = vector == NULL ? NULL : st_json_get_top_level_raw(vector, "rstFailures");
    CHECK(failures != NULL, "shared NAT reset classifications missing");
    const char *names[] = {"route-not-loaded", "target-invalid", "connect-refused", "connect-timeout",
                           "dns-failed", "tls-failed", "unreachable", "protocol-error"};
    CHECK(parity_member_count("{}") == 0U
        && parity_member_count("{\"a\":1,\"b\":{\"nested\":\"key:value\"},\"c\":[{\"d\":2}]}") == 3U
        && parity_member_count("{\"a\":1,\"a\":2}") == (size_t)-1
        && parity_member_count("[]") == (size_t)-1
        && parity_member_count("{") == (size_t)-1, "NAT member-count helper controls");
    CHECK(parity_member_count(failures) == sizeof(names) / sizeof(names[0]),
          "shared reset classifications must exactly match all known C failure names");
    int result = 0;
    parity_outcome = "failed";
    for (size_t i = 0U; i < sizeof(names) / sizeof(names[0]); ++i) {
        char *entry = st_json_get_top_level_raw(failures, names[i]);
        char *code = entry == NULL ? NULL : st_json_get_top_level_string(entry, "code");
        char *stage = entry == NULL ? NULL : st_json_get_top_level_string(entry, "stage");
        if (code == NULL || stage == NULL) result += 1;
        else {
            char label[160]; snprintf(label, sizeof(label), "connectivity NAT parity classified %s", names[i]);
            parity_failure = names[i]; parity_code = code; parity_stage = stage;
            current_check = parity_reset;
            result += run_scenario(label, run_current_check_capable, long_idle);
        }
        free(entry); free(code); free(stage);
    }
    free(failures); free(vector);
    parity_outcome = "unverified"; parity_stage = "target-reachable"; parity_code = "TARGET_UNVERIFIED";
    parity_failure = "connect-refused"; current_check = parity_reset;
    result += run_scenario("connectivity NAT parity legacy capability reset", run_current_check, long_idle);
    parity_failure = "something-newer";
    result += run_scenario("connectivity NAT parity unknown failure", run_current_check_capable, long_idle);
    parity_failure = NULL;
    result += run_scenario("connectivity NAT parity absent failure", run_current_check_capable, long_idle);
    parity_outcome = "failed"; parity_stage = "target-reachable"; parity_code = "TARGET_PROTOCOL_ERROR";
    current_check = parity_bad_status;
    for (int i = 0; i < 2; ++i) {
        parity_status = i == 0 ? 103 : 600;
        char label[100]; snprintf(label, sizeof(label), "connectivity NAT parity response status %d", parity_status);
        result += run_scenario(label, run_current_check_capable, long_idle);
    }
    parity_status = 600;
    result += run_scenario("connectivity NAT parity legacy response status 600", run_current_check, long_idle);
    parity_stage = "device-online"; parity_code = "DEVICE_LINK_LOST"; current_check = parity_closed_link;
    result += run_scenario("connectivity NAT parity data closes mid-probe", run_current_check_capable, long_idle);
    return result;
}
