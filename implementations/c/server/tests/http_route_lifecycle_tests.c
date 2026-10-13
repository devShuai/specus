/*
 * HTTP route lifecycle against a real specus-server-c process (protocol/spec/http-route.md
 * sections 1 and 2): every server scenario of protocol/test-vectors/http-route-lifecycle-v1.json
 * is replayed on a fresh server through the real management API, the real public /http/ entry on
 * the admin port and a fake client logged in for real on control and data connections. The
 * vector's notes define each op and expectation; the vector is read from the repository, never
 * copied here.
 *
 * The fake client answers every HTTP OPEN with the vector's fakeClientResponse, as a client that
 * still holds an old route list and forwards any route name would, and counts the OPENs it saw.
 *
 * On top of the vector, C checks the disconnect reason the server records when it closes a
 * disabled, renamed or deleted client (ADMIN_DISABLED, ADMIN_RENAMED, ADMIN_DELETED), and that a
 * request never reaches a data connection of another account of the same name: one scenario
 * renames the account in the database behind the server's back and creates a new account of the
 * old name, so the old connection is still open when the new account's route is requested.
 *
 * Usage: specus_c_http_route_lifecycle_tests <path-to-specus-server-c>
 */
#define _POSIX_C_SOURCE 200809L

#include "server_harness.h"

#include "json.h"
#include "protocol.h"
#include "storage.h"

#include <errno.h>
#include <openssl/evp.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef ST_ROUTE_LIFECYCLE_VECTOR_FILE
#define ST_ROUTE_LIFECYCLE_VECTOR_FILE "../../../protocol/test-vectors/http-route-lifecycle-v1.json"
#endif

/* expectSessionClosed: both connections closed within 5 s (the vector's notes). */
#define SESSION_CLOSE_TIMEOUT_MS 5000
#define MAX_ROUTES 16
#define CREDENTIAL_KEY "ck_route_lifecycle"
#define CREDENTIAL_SECRET "route-lifecycle-secret"

/* ------------------------------------------------------------------------------------------- */
/* Vector access                                                                                 */

static char *vector_json;
static char basic_username[128];
static char basic_password[128];
static char target_base_url[256];
static char fake_response_meta[1024];
static char fake_response_body[256];

static char *read_file(const char *path)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        return NULL;
    }
    char *text = NULL;
    long size = fseek(file, 0, SEEK_END) == 0 ? ftell(file) : -1;
    if (size > 0 && fseek(file, 0, SEEK_SET) == 0) {
        text = (char *)malloc((size_t)size + 1U);
        if (text != NULL && fread(text, 1, (size_t)size, file) == (size_t)size) {
            text[size] = '\0';
        } else {
            free(text);
            text = NULL;
        }
    }
    fclose(file);
    return text;
}

/* The raw elements of the array under key. */
static int vec_array(const char *object, const char *key, char ***items, size_t *count)
{
    *items = NULL;
    *count = 0U;
    char *raw = st_json_get_top_level_raw(object, key);
    if (raw == NULL) {
        return -1;
    }
    size_t len = strlen(raw) + 8U;
    char *wrapped = (char *)malloc(len);
    int rc = -1;
    if (wrapped != NULL) {
        snprintf(wrapped, len, "{\"a\":%s}", raw);
        rc = st_json_get_raw_array(wrapped, "a", items, count);
    }
    free(wrapped);
    free(raw);
    return rc;
}

/* A string array under key: 0 with the strings, 1 when it is null, -1 when absent or malformed. */
static int vec_string_list(const char *object, const char *key, char ***items, size_t *count)
{
    *items = NULL;
    *count = 0U;
    char *raw = st_json_get_top_level_raw(object, key);
    if (raw == NULL) {
        return -1;
    }
    if (strcmp(raw, "null") == 0) {
        free(raw);
        return 1;
    }
    size_t len = strlen(raw) + 8U;
    char *wrapped = (char *)malloc(len);
    int rc = -1;
    if (wrapped != NULL) {
        snprintf(wrapped, len, "{\"a\":%s}", raw);
        rc = st_json_get_string_array(wrapped, "a", items, count);
    }
    free(wrapped);
    free(raw);
    return rc;
}

static int vec_present(const char *object, const char *key)
{
    char *raw = st_json_get_top_level_raw(object, key);
    int present = raw != NULL;
    free(raw);
    return present;
}

static int vec_bool(const char *object, const char *key)
{
    char *raw = st_json_get_top_level_raw(object, key);
    int value = raw != NULL && strcmp(raw, "true") == 0;
    free(raw);
    return value;
}

static int vec_i64(const char *object, const char *key, long long *out)
{
    char *raw = st_json_get_top_level_raw(object, key);
    char *end = NULL;
    int rc = raw == NULL ? -1 : 0;
    if (rc == 0) {
        *out = strtoll(raw, &end, 10);
        rc = end != raw && *end == '\0' ? 0 : -1;
    }
    free(raw);
    return rc;
}

/* Copies the string under key into out; "" when it is missing or not a string. */
static void vec_text(const char *object, const char *key, char *out, size_t out_len)
{
    char *value = st_json_get_top_level_string(object, key);
    snprintf(out, out_len, "%s", value == NULL ? "" : value);
    free(value);
}

static void join_names(char **names, size_t count, char *out, size_t out_len)
{
    size_t used = 0U;
    out[0] = '\0';
    for (size_t i = 0; i < count && used < out_len; ++i) {
        int written = snprintf(out + used, out_len - used, "%s%s", i == 0U ? "" : ",", names[i]);
        if (written < 0) {
            break;
        }
        used += (size_t)written;
    }
}

/* Whether two name lists hold the same set; the vector compares route names as sets. */
static int same_name_set(char **left, size_t left_count, char **right, size_t right_count)
{
    if (left_count != right_count) {
        return 0;
    }
    for (size_t i = 0; i < left_count; ++i) {
        int in_right = 0;
        int in_left = 0;
        for (size_t j = 0; j < right_count; ++j) {
            in_right |= strcmp(left[i], right[j]) == 0;
            in_left |= strcmp(right[i], left[j]) == 0;
        }
        if (!in_right || !in_left) {
            return 0;
        }
    }
    return 1;
}

/* ------------------------------------------------------------------------------------------- */
/* Replay state                                                                                  */

typedef struct {
    char name[128];
    long long id;
} route_record;

typedef struct {
    test_server *server;
    const char *scenario_id;
    size_t step_index;
    const char *op;
    char admin_token[1024];
    runtime_session runtime;
    long long client_id;
    char client_name[256];
    char former_name[256];
    route_record routes[MAX_ROUTES];
    size_t route_count;
    /* The name the last connect logged in with; reconnect presents its token under it again. */
    char connected_name[256];
    int control;
    int data;
    int failures;
} replay;

static void step_fail(replay *r, int line, const char *format, ...)
{
    fprintf(stderr, "FAIL %s:%d: scenario %s step %zu (%s): ", __FILE__, line, r->scenario_id,
            r->step_index, r->op == NULL ? "setup" : r->op);
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fprintf(stderr, "\n");
    ++r->failures;
}

#define STEP_CHECK(r, condition, ...)                  \
    do {                                               \
        if (!(condition)) {                            \
            step_fail((r), __LINE__, __VA_ARGS__);     \
            return 1;                                  \
        }                                              \
    } while (0)

static route_record *find_route(replay *r, const char *name)
{
    for (size_t i = 0; i < r->route_count; ++i) {
        if (strcmp(r->routes[i].name, name) == 0) {
            return &r->routes[i];
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------------------------------- */
/* Management API                                                                                */

/* One management API call; 0 when it answered expected_status, with *response for the caller. */
static int admin_call(replay *r, const char *method, const char *path, const char *body,
                      int expected_status, char **response)
{
    int status = 0;
    char *answer = NULL;
    int rc = http_request(r->server->admin_port, method, path, body, r->admin_token, &status, &answer);
    if (rc != 0 || status != expected_status) {
        fprintf(stderr, "  %s %s answered %d, expected %d: %s\n", method, path, status, expected_status,
                answer == NULL ? "(no response)" : answer);
        free(answer);
        return -1;
    }
    if (response != NULL) {
        *response = answer;
    } else {
        free(answer);
    }
    return 0;
}

static int admin_login(replay *r)
{
    char body[256];
    snprintf(body, sizeof(body), "{\"username\":\"%s\",\"password\":\"%s\"}", ADMIN_USERNAME, ADMIN_PASSWORD);
    int status = 0;
    char *response = NULL;
    if (http_request(r->server->admin_port, "POST", "/auth/login", body, NULL, &status, &response) != 0) {
        return -1;
    }
    char *token = status == 200 ? st_json_get_top_level_string(response, "accessToken") : NULL;
    free(response);
    if (token == NULL || strlen(token) >= sizeof(r->admin_token)) {
        free(token);
        return -1;
    }
    snprintf(r->admin_token, sizeof(r->admin_token), "%s", token);
    free(token);
    return 0;
}

/* ------------------------------------------------------------------------------------------- */
/* Fake client                                                                                   */

static int send_nat(int fd, int type, uint32_t stream_id, const char *meta, const void *data, size_t data_len)
{
    st_buffer frame = st_protocol_encode_nat_message(type, 0U, stream_id, 0U, meta, (const uint8_t *)data, data_len);
    return send_buffer(fd, &frame);
}

/* The vector's fakeClientResponse for one stream: response OPEN, DATA and FIN. */
static int answer_open(int data_fd, uint32_t stream_id)
{
    size_t body_len = strlen(fake_response_body);
    return send_nat(data_fd, ST_NAT_OPEN, stream_id, fake_response_meta, NULL, 0U) == 0
        && (body_len == 0U || send_nat(data_fd, ST_NAT_DATA, stream_id, NULL, fake_response_body, body_len) == 0)
        && send_nat(data_fd, ST_NAT_FIN, stream_id, NULL, NULL, 0U) == 0
        ? 0 : -1;
}

/* The next NAT_CONTROL on the control connection: 1 with *json set, 0 when closed, -1 otherwise. */
static int next_nat_control(int fd, int timeout_ms, char **json)
{
    *json = NULL;
    long long deadline = monotonic_ms() + timeout_ms;
    for (;;) {
        long long remaining = deadline - monotonic_ms();
        if (remaining <= 0) {
            return -1;
        }
        st_frame_header header;
        uint8_t *body = NULL;
        int rc = read_frame(fd, (int)remaining, &header, &body);
        if (rc != 1) {
            return rc == 0 ? 0 : -1;
        }
        if (header.command != ST_CMD_MESSAGE_RESPONSE) {
            free(body);
            continue;
        }
        st_message_response message;
        int decoded = st_protocol_decode_message_response(body, header.length, &message);
        free(body);
        if (decoded != 0) {
            return -1;
        }
        if (message.message_type == ST_MESSAGE_TYPE_NAT_CONTROL && message.message != NULL) {
            *json = message.message;
            message.message = NULL;
            st_message_response_free(&message);
            return 1;
        }
        st_message_response_free(&message);
    }
}

/*
 * expectLoginPush / expectPush: the next NAT_CONTROL carries an httpSpecusConfigList array with
 * exactly these route names. Absent or null means there is nothing to check (the client is
 * offline for a null expectPush).
 */
static int check_push(replay *r, const char *step, const char *key)
{
    char **expected = NULL;
    size_t expected_count = 0U;
    int kind = vec_string_list(step, key, &expected, &expected_count);
    if (kind != 0) {
        STEP_CHECK(r, kind == 1 || !vec_present(step, key), "%s is neither an array nor null", key);
        return 0;
    }
    char expected_text[512];
    join_names(expected, expected_count, expected_text, sizeof(expected_text));
    if (r->control < 0) {
        st_json_free_string_array(expected, expected_count);
        STEP_CHECK(r, 0, "%s [%s] expected, but the fake client is not connected", key, expected_text);
    }
    char *json = NULL;
    int rc = next_nat_control(r->control, IO_TIMEOUT_MS, &json);
    if (rc != 1) {
        st_json_free_string_array(expected, expected_count);
        STEP_CHECK(r, 0, "%s [%s]: no NAT_CONTROL arrived (%s)", key, expected_text,
                   rc == 0 ? "the control connection closed" : "timed out");
    }
    char **items = NULL;
    size_t item_count = 0U;
    int list_rc = vec_array(json, "httpSpecusConfigList", &items, &item_count);
    char **names = list_rc == 0 ? (char **)calloc(item_count + 1U, sizeof(*names)) : NULL;
    int names_ok = names != NULL;
    for (size_t i = 0; names_ok && i < item_count; ++i) {
        names[i] = st_json_get_top_level_string(items[i], "route");
        names_ok = names[i] != NULL;
    }
    char actual_text[512] = "";
    if (names_ok) {
        join_names(names, item_count, actual_text, sizeof(actual_text));
    }
    int matches = names_ok && same_name_set(names, item_count, expected, expected_count);
    if (!matches) {
        step_fail(r, __LINE__, "%s: NAT_CONTROL routes [%s], expected [%s]; NAT_CONTROL was %s", key,
                  names_ok ? actual_text : "(no httpSpecusConfigList array of routes)", expected_text, json);
    }
    st_json_free_string_array(names, names == NULL ? 0U : item_count);
    st_json_free_string_array(items, item_count);
    st_json_free_string_array(expected, expected_count);
    free(json);
    return matches ? 0 : 1;
}

/* Waits until a closed connection record of the client carries the given disconnect reason. */
static int wait_connection_reason(const char *db_path, const char *client_name, const char *reason,
                                  int timeout_ms, char *records, size_t records_len)
{
    char sql[512];
    snprintf(sql, sizeof(sql),
             "SELECT COUNT(*) FROM connection_record WHERE client_name = ? AND success = 1 "
             "AND disconnect_reason = '%s' AND disconnected_at IS NOT NULL AND disconnected_at <> ''",
             reason);
    long long deadline = monotonic_ms() + timeout_ms;
    char count[32] = "";
    for (;;) {
        if (db_scalar(db_path, sql, client_name, 0, count, sizeof(count)) == 0 && atoi(count) > 0) {
            return 0;
        }
        if (monotonic_ms() >= deadline) {
            db_scalar(db_path,
                      "SELECT COALESCE(group_concat(id || '|' || success || '|' || COALESCE(disconnect_reason, 'NULL')"
                      " || '|' || COALESCE(disconnected_at, 'NULL'), ', '), 'none') FROM connection_record"
                      " WHERE client_name = ?",
                      client_name, 0, records, records_len);
            return -1;
        }
        sleep_ms(50);
    }
}

/*
 * expectSessionClosed: the server closes both connections within 5 s. C also checks the reason the
 * connection record keeps for it.
 */
static int check_session_closed(replay *r, const char *reason, const char *recorded_name)
{
    STEP_CHECK(r, r->control >= 0 && r->data >= 0, "expectSessionClosed, but the fake client is not connected");
    long long started = monotonic_ms();
    long long deadline = started + SESSION_CLOSE_TIMEOUT_MS;
    int control_rc = expect_channel_closed(r->control, (int)(deadline - monotonic_ms()));
    long long remaining = deadline - monotonic_ms();
    int data_rc = expect_channel_closed(r->data, remaining > 0 ? (int)remaining : 1);
    STEP_CHECK(r, control_rc == 0 && data_rc == 0,
               "the server did not close the fake client's connections within %d ms "
               "(control %s, data %s after %lld ms)",
               SESSION_CLOSE_TIMEOUT_MS, control_rc == 0 ? "closed" : "still open",
               data_rc == 0 ? "closed" : "still open", monotonic_ms() - started);
    close_fd(&r->control);
    close_fd(&r->data);
    char records[2048] = "";
    STEP_CHECK(r, wait_connection_reason(r->server->db_path, recorded_name, reason, SESSION_CLOSE_TIMEOUT_MS,
                                         records, sizeof(records)) == 0,
               "no closed connection record of %s with disconnect reason %s; its records "
               "(id|success|disconnect reason|disconnected at): %s",
               recorded_name, reason, records);
    return 0;
}

/* ------------------------------------------------------------------------------------------- */
/* Public /http/ entry                                                                           */

static void url_encode(const char *value, char *out, size_t out_len)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t used = 0U;
    for (const unsigned char *cursor = (const unsigned char *)value; *cursor != '\0' && used + 4U < out_len; ++cursor) {
        unsigned char c = *cursor;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
            || c == '-' || c == '_' || c == '.' || c == '~') {
            out[used++] = (char)c;
        } else {
            out[used++] = '%';
            out[used++] = hex[c >> 4U];
            out[used++] = hex[c & 0x0fU];
        }
    }
    out[used] = '\0';
}

typedef struct {
    int status;
    char head[4096];
    char body[4096];
} public_response;

/* Copies the value of the first header of that name in a response head; 0 when found. */
static int header_value(const char *head, const char *name, char *out, size_t out_len)
{
    size_t name_len = strlen(name);
    const char *line = strstr(head, "\r\n");
    while (line != NULL && line[2] != '\0' && strncmp(line, "\r\n\r\n", 4) != 0) {
        line += 2;
        const char *end = strstr(line, "\r\n");
        if (end == NULL) {
            end = line + strlen(line);
        }
        if ((size_t)(end - line) > name_len && strncasecmp(line, name, name_len) == 0 && line[name_len] == ':') {
            const char *value = line + name_len + 1;
            while (*value == ' ' || *value == '\t') {
                ++value;
            }
            snprintf(out, out_len, "%.*s", (int)(end - value), value);
            return 0;
        }
        line = end;
    }
    out[0] = '\0';
    return -1;
}

/* Splits a raw response into status, head and (de-chunked) body. */
static void parse_response(const char *raw, public_response *response)
{
    memset(response, 0, sizeof(*response));
    if (sscanf(raw, "HTTP/1.1 %d", &response->status) != 1) {
        response->status = 0;
    }
    const char *separator = strstr(raw, "\r\n\r\n");
    if (separator == NULL) {
        snprintf(response->head, sizeof(response->head), "%s", raw);
        return;
    }
    snprintf(response->head, sizeof(response->head), "%.*s", (int)(separator - raw + 2), raw);
    const char *body = separator + 4;
    char encoding[64];
    if (header_value(response->head, "Transfer-Encoding", encoding, sizeof(encoding)) != 0
        || strstr(encoding, "chunked") == NULL) {
        snprintf(response->body, sizeof(response->body), "%s", body);
        return;
    }
    size_t used = 0U;
    for (;;) {
        char *end = NULL;
        unsigned long size = strtoul(body, &end, 16);
        const char *data = end == NULL ? NULL : strstr(end, "\r\n");
        if (data == NULL || size == 0UL) {
            break;
        }
        data += 2;
        if (strlen(data) < size || used + size >= sizeof(response->body)) {
            break;
        }
        memcpy(response->body + used, data, size);
        used += size;
        body = data + size;
        if (strncmp(body, "\r\n", 2) == 0) {
            body += 2;
        }
    }
    response->body[used] = '\0';
}

/*
 * Sends GET /http/{client}/{route}{path} and reads the answer, while the fake client answers every
 * OPEN its data connection gets in the meantime; *opens counts them.
 */
static int public_request(replay *r, const char *step, public_response *response, int *opens)
{
    *opens = 0;
    char route[128];
    char path[256];
    char credentials[16];
    char which_client[16];
    vec_text(step, "route", route, sizeof(route));
    vec_text(step, "path", path, sizeof(path));
    vec_text(step, "credentials", credentials, sizeof(credentials));
    vec_text(step, "client", which_client, sizeof(which_client));
    int websocket = vec_bool(step, "websocket");
    char *route_raw = st_json_get_top_level_raw(step, "route");
    int no_route = route_raw == NULL || strcmp(route_raw, "null") == 0;
    free(route_raw);

    const char *client = strcmp(which_client, "former") == 0 ? r->former_name : r->client_name;
    STEP_CHECK(r, *client != '\0', "request for the %s client name, which this scenario has none of", which_client);
    char encoded_client[768];
    char encoded_route[384];
    url_encode(client, encoded_client, sizeof(encoded_client));
    url_encode(route, encoded_route, sizeof(encoded_route));
    char target[1536];
    if (no_route) {
        snprintf(target, sizeof(target), "/http/%s/", encoded_client);
    } else {
        snprintf(target, sizeof(target), "/http/%s/%s%s", encoded_client, encoded_route, path);
    }

    char authorization[640] = "";
    if (strcmp(credentials, "valid") == 0 || strcmp(credentials, "wrong") == 0) {
        char plain[300];
        snprintf(plain, sizeof(plain), "%s:%s", basic_username,
                 strcmp(credentials, "valid") == 0 ? basic_password : "wrong");
        unsigned char encoded[512];
        EVP_EncodeBlock(encoded, (const unsigned char *)plain, (int)strlen(plain));
        snprintf(authorization, sizeof(authorization), "Authorization: Basic %s\r\n", (const char *)encoded);
    } else {
        STEP_CHECK(r, strcmp(credentials, "none") == 0, "unknown credentials \"%s\"", credentials);
    }
    char request[4096];
    int request_len = snprintf(request, sizeof(request),
                               "GET %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n%s%s\r\n",
                               target, r->server->admin_port, authorization,
                               websocket
                                   ? "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                                     "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
                                   : "Connection: close\r\n");
    int fd = connect_local(r->server->admin_port);
    if (fd >= 0 && (request_len <= 0 || (size_t)request_len >= sizeof(request)
                    || send_all(fd, (const uint8_t *)request, (size_t)request_len) != 0)) {
        close_fd(&fd);
    }
    STEP_CHECK(r, fd >= 0, "GET %s could not be sent", target);

    char raw[16384];
    size_t used = 0U;
    raw[0] = '\0';
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    for (;;) {
        long long remaining = deadline - monotonic_ms();
        if (remaining <= 0) {
            break;
        }
        struct pollfd ready[2] = {
            {.fd = fd, .events = POLLIN, .revents = 0},
            {.fd = r->data, .events = POLLIN, .revents = 0},
        };
        nfds_t count = r->data >= 0 ? 2U : 1U;
        int polled = poll(ready, count, (int)remaining);
        if (polled < 0 && errno == EINTR) {
            continue;
        }
        if (polled <= 0) {
            break;
        }
        if (count == 2U && ready[1].revents != 0) {
            st_frame_header header;
            uint8_t *body = NULL;
            if (read_frame(r->data, IO_TIMEOUT_MS, &header, &body) != 1) {
                /* The server closed the data connection: nothing more can reach the fake client. */
                close_fd(&r->data);
                continue;
            }
            st_nat_message message;
            if (header.command == ST_CMD_NAT_MESSAGE
                && st_protocol_decode_nat_message(body, header.length, &message) == 0) {
                if (message.type == ST_NAT_OPEN) {
                    ++*opens;
                    (void)answer_open(r->data, message.stream_id);
                }
                st_nat_message_free(&message);
            }
            free(body);
        }
        if (ready[0].revents != 0) {
            ssize_t received = recv(fd, raw + used, sizeof(raw) - 1U - used, 0);
            if (received < 0 && errno == EINTR) {
                continue;
            }
            if (received <= 0) {
                break;
            }
            used += (size_t)received;
            raw[used] = '\0';
            /* A 101 has no body and keeps the socket open: its head is all there is to read. */
            if ((strncmp(raw, "HTTP/1.1 101", 12) == 0 && strstr(raw, "\r\n\r\n") != NULL)
                || used == sizeof(raw) - 1U) {
                break;
            }
        }
    }
    close(fd);
    parse_response(raw, response);
    STEP_CHECK(r, response->status != 0, "GET %s: no HTTP response (%zu bytes: %s)", target, used, raw);
    return 0;
}

static int check_request(replay *r, const char *step)
{
    public_response response;
    int opens = 0;
    if (public_request(r, step, &response, &opens) != 0) {
        return 1;
    }
    char *expect = st_json_get_top_level_raw(step, "expect");
    STEP_CHECK(r, expect != NULL, "request step without expect");
    int failed = 0;
    long long expected_status = 0;
    char reason[1024] = "";
    if (vec_i64(expect, "status", &expected_status) == 0) {
        if (response.status != expected_status) {
            snprintf(reason, sizeof(reason), "status %d, expected %lld", response.status, expected_status);
            failed = 1;
        }
    } else if (vec_present(expect, "statusAnyOf")) {
        char **statuses = NULL;
        size_t status_count = 0U;
        int any = 0;
        if (vec_array(expect, "statusAnyOf", &statuses, &status_count) == 0) {
            for (size_t i = 0; i < status_count; ++i) {
                any |= atoi(statuses[i]) == response.status;
            }
        }
        st_json_free_string_array(statuses, status_count);
        if (!any) {
            snprintf(reason, sizeof(reason), "status %d, expected one of the statusAnyOf", response.status);
            failed = 1;
        }
    } else {
        snprintf(reason, sizeof(reason), "expect has neither status nor statusAnyOf");
        failed = 1;
    }
    char value[512];
    if (!failed && vec_bool(step, "websocket") && response.status == 101) {
        snprintf(reason, sizeof(reason), "the WebSocket upgrade was accepted with 101");
        failed = 1;
    }
    if (!failed && vec_bool(expect, "noStore")
        && (header_value(response.head, "Cache-Control", value, sizeof(value)) != 0
            || strstr(value, "no-store") == NULL)) {
        snprintf(reason, sizeof(reason), "Cache-Control is \"%s\", expected no-store", value);
        failed = 1;
    }
    if (!failed && vec_bool(expect, "basicChallenge")
        && (header_value(response.head, "WWW-Authenticate", value, sizeof(value)) != 0
            || strncmp(value, "Basic", 5) != 0)) {
        snprintf(reason, sizeof(reason), "WWW-Authenticate is \"%s\", expected a Basic challenge", value);
        failed = 1;
    }
    char expected_body[512];
    if (!failed && vec_present(expect, "body")) {
        vec_text(expect, "body", expected_body, sizeof(expected_body));
        if (strcmp(response.body, expected_body) != 0) {
            snprintf(reason, sizeof(reason), "body \"%.400s\", expected \"%.400s\"", response.body, expected_body);
            failed = 1;
        }
    }
    if (!failed && vec_present(expect, "forwarded")) {
        int expected_opens = vec_bool(expect, "forwarded") ? 1 : 0;
        if (opens != expected_opens) {
            snprintf(reason, sizeof(reason), "the fake client received %d OPEN(s), expected %d", opens, expected_opens);
            failed = 1;
        }
    }
    free(expect);
    char route[128];
    char path[256];
    vec_text(step, "route", route, sizeof(route));
    vec_text(step, "path", path, sizeof(path));
    STEP_CHECK(r, !failed, "GET route=%s path=%s: %s (OPENs at the fake client: %d)\n%s\n%s", route, path, reason,
               opens, response.head, response.body);
    return 0;
}

/* ------------------------------------------------------------------------------------------- */
/* Ops                                                                                           */

static int op_create_route(replay *r, const char *step)
{
    char route[128];
    vec_text(step, "route", route, sizeof(route));
    STEP_CHECK(r, *route != '\0' && r->route_count < MAX_ROUTES, "createRoute without a route name");
    char *route_json = st_json_escape(route);
    char *target_json = st_json_escape(target_base_url);
    char *user_json = st_json_escape(basic_username);
    char *password_json = st_json_escape(basic_password);
    char body[1024];
    if (vec_bool(step, "auth")) {
        snprintf(body, sizeof(body),
                 "{\"route\":\"%s\",\"targetBaseUrl\":\"%s\",\"enabled\":true,\"authEnabled\":true,"
                 "\"authUsername\":\"%s\",\"authPassword\":\"%s\"}",
                 route_json, target_json, user_json, password_json);
    } else {
        snprintf(body, sizeof(body), "{\"route\":\"%s\",\"targetBaseUrl\":\"%s\",\"enabled\":true}",
                 route_json, target_json);
    }
    free(route_json);
    free(target_json);
    free(user_json);
    free(password_json);
    char path[128];
    snprintf(path, sizeof(path), "/api/admin/clients/%lld/http-routes", r->client_id);
    char *response = NULL;
    STEP_CHECK(r, admin_call(r, "POST", path, body, 201, &response) == 0, "route %s was not created", route);
    long long id = 0;
    int parsed = st_json_get_i64(response, "id", &id) == 0 && id > 0;
    free(response);
    STEP_CHECK(r, parsed, "the created route %s has no id", route);
    route_record *record = &r->routes[r->route_count++];
    snprintf(record->name, sizeof(record->name), "%s", route);
    record->id = id;
    return 0;
}

static int op_set_route_enabled(replay *r, const char *step)
{
    char route[128];
    vec_text(step, "route", route, sizeof(route));
    route_record *record = find_route(r, route);
    STEP_CHECK(r, record != NULL, "setRouteEnabled for route %s, which this scenario did not create", route);
    char path[128];
    char body[64];
    snprintf(path, sizeof(path), "/api/admin/http-routes/%lld", record->id);
    snprintf(body, sizeof(body), "{\"enabled\":%s}", vec_bool(step, "enabled") ? "true" : "false");
    STEP_CHECK(r, admin_call(r, "PUT", path, body, 200, NULL) == 0, "route %s was not updated", route);
    return 0;
}

static int op_delete_route(replay *r, const char *step)
{
    char route[128];
    vec_text(step, "route", route, sizeof(route));
    route_record *record = find_route(r, route);
    STEP_CHECK(r, record != NULL, "deleteRoute for route %s, which this scenario did not create", route);
    char path[128];
    snprintf(path, sizeof(path), "/api/admin/http-routes/%lld", record->id);
    STEP_CHECK(r, admin_call(r, "DELETE", path, NULL, 204, NULL) == 0, "route %s was not deleted", route);
    *record = r->routes[--r->route_count];
    return 0;
}

static int op_set_client_enabled(replay *r, const char *step)
{
    char path[128];
    char body[64];
    snprintf(path, sizeof(path), "/api/admin/clients/%lld", r->client_id);
    snprintf(body, sizeof(body), "{\"enabled\":%s}", vec_bool(step, "enabled") ? "true" : "false");
    STEP_CHECK(r, admin_call(r, "PUT", path, body, 200, NULL) == 0, "client %s was not updated", r->client_name);
    return 0;
}

static int op_rename_client(replay *r, const char *step)
{
    char suffix[64];
    vec_text(step, "suffix", suffix, sizeof(suffix));
    char renamed[256];
    snprintf(renamed, sizeof(renamed), "%.190s%.60s", r->client_name, suffix);
    char *name_json = st_json_escape(renamed);
    char path[128];
    char body[512];
    snprintf(path, sizeof(path), "/api/admin/clients/%lld", r->client_id);
    snprintf(body, sizeof(body), "{\"clientName\":\"%s\"}", name_json == NULL ? "" : name_json);
    free(name_json);
    STEP_CHECK(r, admin_call(r, "PUT", path, body, 200, NULL) == 0, "client %s was not renamed", r->client_name);
    snprintf(r->former_name, sizeof(r->former_name), "%s", r->client_name);
    snprintf(r->client_name, sizeof(r->client_name), "%s", renamed);
    return 0;
}

static int op_delete_client(replay *r)
{
    char path[128];
    snprintf(path, sizeof(path), "/api/admin/clients/%lld", r->client_id);
    STEP_CHECK(r, admin_call(r, "DELETE", path, NULL, 204, NULL) == 0, "client %s was not deleted", r->client_name);
    /* Its routes went with it; the name stays for createClient. */
    r->route_count = 0U;
    r->client_id = 0;
    return 0;
}

static int op_create_client(replay *r)
{
    char *name_json = st_json_escape(r->client_name);
    char body[512];
    snprintf(body, sizeof(body), "{\"clientName\":\"%s\",\"enabled\":true}", name_json == NULL ? "" : name_json);
    free(name_json);
    char *response = NULL;
    STEP_CHECK(r, admin_call(r, "POST", "/api/admin/clients", body, 201, &response) == 0,
               "client %s was not created", r->client_name);
    long long id = 0;
    int parsed = st_json_get_i64(response, "id", &id) == 0 && id > 0;
    free(response);
    STEP_CHECK(r, parsed, "the created client %s has no id", r->client_name);
    r->client_id = id;
    r->route_count = 0U;
    return 0;
}

/*
 * C only: the account is renamed to its name plus suffix in the database without this process
 * being told, as by another instance or a change made in the database itself, so its connections
 * stay open here under the old name. Its routes move with it; the old name is free for
 * createClient.
 */
static int op_rename_client_in_database(replay *r, const char *step)
{
    char suffix[64];
    vec_text(step, "suffix", suffix, sizeof(suffix));
    char renamed[256];
    snprintf(renamed, sizeof(renamed), "%.190s%.60s", r->client_name, suffix);
    st_storage_client client;
    st_storage_client updated;
    STEP_CHECK(r, st_storage_get_client(r->server->db_path, r->client_id, &client) == 0
                   && st_storage_upsert_client(r->server->db_path, r->client_id, client.tenant_id, renamed,
                                               client.owner_username, client.enabled,
                                               client.connection_rate_limit_per_minute, &updated) == 0,
               "client %lld could not be renamed to %s in the database", r->client_id, renamed);
    r->route_count = 0U;
    r->client_id = 0;
    return 0;
}

/* C only: both connections are still served, so whatever was refused had a connection to go to. */
static int op_expect_still_connected(replay *r)
{
    STEP_CHECK(r, r->control >= 0 && r->data >= 0
                   && expect_channel_alive(r->control) == 0 && expect_channel_alive(r->data) == 0,
               "the fake client's connections are no longer served");
    return 0;
}

/* Another account under the name before the last rename, with the given routes; it never logs in. */
static int op_create_former_name_client(replay *r, const char *step)
{
    STEP_CHECK(r, *r->former_name != '\0', "createFormerNameClient without an earlier renameClient");
    char *name_json = st_json_escape(r->former_name);
    char body[512];
    snprintf(body, sizeof(body), "{\"clientName\":\"%s\",\"enabled\":true}", name_json == NULL ? "" : name_json);
    free(name_json);
    char *response = NULL;
    STEP_CHECK(r, admin_call(r, "POST", "/api/admin/clients", body, 201, &response) == 0,
               "client %s was not created", r->former_name);
    long long id = 0;
    int parsed = st_json_get_i64(response, "id", &id) == 0 && id > 0;
    free(response);
    STEP_CHECK(r, parsed && id != r->client_id, "the created client %s has no id of its own", r->former_name);
    char **routes = NULL;
    size_t route_count = 0U;
    STEP_CHECK(r, vec_string_list(step, "routes", &routes, &route_count) == 0, "createFormerNameClient without routes");
    int failed = 0;
    for (size_t i = 0; !failed && i < route_count; ++i) {
        char *route_json = st_json_escape(routes[i]);
        char *target_json = st_json_escape(target_base_url);
        char route_body[1024];
        char path[128];
        snprintf(route_body, sizeof(route_body), "{\"route\":\"%s\",\"targetBaseUrl\":\"%s\",\"enabled\":true}",
                 route_json == NULL ? "" : route_json, target_json == NULL ? "" : target_json);
        snprintf(path, sizeof(path), "/api/admin/clients/%lld/http-routes", id);
        free(route_json);
        free(target_json);
        failed = admin_call(r, "POST", path, route_body, 201, NULL) != 0;
        if (failed) {
            step_fail(r, __LINE__, "route %s of %s was not created", routes[i], r->former_name);
        }
    }
    st_json_free_string_array(routes, route_count);
    return failed;
}

static int op_connect(replay *r)
{
    char reason[256];
    STEP_CHECK(r, r->control < 0 && r->data < 0, "connect while the fake client is still connected");
    int control_rc = channel_login(r->server->control_port, &r->runtime, "control", &r->control, reason, sizeof(reason));
    STEP_CHECK(r, control_rc == 1, "control login of %s: %s", r->runtime.client_name, reason);
    int data_rc = channel_login(r->server->control_port, &r->runtime, "data", &r->data, reason, sizeof(reason));
    STEP_CHECK(r, data_rc == 1, "data login of %s: %s", r->runtime.client_name, reason);
    snprintf(r->connected_name, sizeof(r->connected_name), "%s", r->runtime.client_name);
    return 0;
}

/*
 * The token of the last connect again, under the name it logged in with then and no new HTTP
 * login: refused, or accepted under the account's current name.
 */
static int op_reconnect(replay *r, const char *step)
{
    STEP_CHECK(r, r->control < 0 && r->data < 0, "reconnect while the fake client is still connected");
    STEP_CHECK(r, *r->connected_name != '\0', "reconnect without an earlier connect");
    STEP_CHECK(r, vec_present(step, "expectRefused"), "reconnect without expectRefused");
    runtime_session token = r->runtime;
    snprintf(token.client_name, sizeof(token.client_name), "%s", r->connected_name);
    char answered[256];
    char reason[256];
    int control_rc = channel_login_answer(r->server->control_port, &token, "control", &r->control,
                                          answered, sizeof(answered), reason, sizeof(reason));
    if (vec_bool(step, "expectRefused")) {
        STEP_CHECK(r, control_rc == 0, "the token of %s %s, expected it refused (answered as %s)",
                   r->connected_name, control_rc == 1 ? "logged in again" : "got no login answer", answered);
        return 0;
    }
    STEP_CHECK(r, control_rc == 1, "control login with the token of %s: %s", r->connected_name, reason);
    STEP_CHECK(r, strcmp(answered, r->client_name) == 0,
               "control login answered as %s, expected the account's current name %s", answered, r->client_name);
    int data_rc = channel_login(r->server->control_port, &token, "data", &r->data, reason, sizeof(reason));
    STEP_CHECK(r, data_rc == 1, "data login with the token of %s: %s", r->connected_name, reason);
    return 0;
}

/* Closes both connections and waits until the server has the runtime session offline. */
static int op_disconnect(replay *r)
{
    close_fd(&r->data);
    close_fd(&r->control);
    long long deadline = monotonic_ms() + SESSION_CLOSE_TIMEOUT_MS;
    char status[64] = "";
    for (;;) {
        if (db_scalar(r->server->db_path, "SELECT status FROM specus_client_session WHERE id = ?", NULL,
                      r->runtime.session_id, status, sizeof(status)) == 0
            && strcmp(status, "DISCONNECTED") == 0) {
            return 0;
        }
        STEP_CHECK(r, monotonic_ms() < deadline, "runtime session %lld is %s, not DISCONNECTED, %d ms after the "
                   "fake client closed its connections", r->runtime.session_id, status, SESSION_CLOSE_TIMEOUT_MS);
        sleep_ms(50);
    }
}

static int run_step(replay *r, const char *step)
{
    char op[64];
    vec_text(step, "op", op, sizeof(op));
    r->op = op;
    int failed;
    const char *closed_reason = NULL;
    char recorded_name[256];
    snprintf(recorded_name, sizeof(recorded_name), "%s", r->client_name);
    if (strcmp(op, "createRoute") == 0) {
        failed = op_create_route(r, step);
    } else if (strcmp(op, "setRouteEnabled") == 0) {
        failed = op_set_route_enabled(r, step);
    } else if (strcmp(op, "deleteRoute") == 0) {
        failed = op_delete_route(r, step);
    } else if (strcmp(op, "setClientEnabled") == 0) {
        failed = op_set_client_enabled(r, step);
        closed_reason = vec_bool(step, "enabled") ? NULL : "ADMIN_DISABLED";
    } else if (strcmp(op, "renameClient") == 0) {
        failed = op_rename_client(r, step);
        closed_reason = "ADMIN_RENAMED";
    } else if (strcmp(op, "deleteClient") == 0) {
        failed = op_delete_client(r);
        closed_reason = "ADMIN_DELETED";
    } else if (strcmp(op, "createClient") == 0) {
        failed = op_create_client(r);
    } else if (strcmp(op, "createFormerNameClient") == 0) {
        failed = op_create_former_name_client(r, step);
    } else if (strcmp(op, "connect") == 0) {
        failed = op_connect(r) || check_push(r, step, "expectLoginPush");
    } else if (strcmp(op, "reconnect") == 0) {
        failed = op_reconnect(r, step) || (!vec_bool(step, "expectRefused") && check_push(r, step, "expectLoginPush"));
    } else if (strcmp(op, "disconnect") == 0) {
        failed = op_disconnect(r);
    } else if (strcmp(op, "request") == 0) {
        failed = check_request(r, step);
    } else if (strcmp(op, "renameClientInDatabase") == 0) {
        failed = op_rename_client_in_database(r, step);
    } else if (strcmp(op, "expectStillConnected") == 0) {
        failed = op_expect_still_connected(r);
    } else {
        step_fail(r, __LINE__, "unknown op");
        failed = 1;
    }
    if (failed) {
        return 1;
    }
    if (vec_present(step, "expectPush") && check_push(r, step, "expectPush") != 0) {
        return 1;
    }
    if (vec_bool(step, "expectSessionClosed")) {
        STEP_CHECK(r, closed_reason != NULL, "expectSessionClosed on an op that closes nothing");
        return check_session_closed(r, closed_reason, recorded_name);
    }
    return 0;
}

/* ------------------------------------------------------------------------------------------- */
/* Scenarios                                                                                     */

static const char *current_scenario;

static int replay_current_scenario(test_server *server)
{
    replay r;
    memset(&r, 0, sizeof(r));
    r.server = server;
    r.control = -1;
    r.data = -1;
    char scenario_id[128];
    vec_text(current_scenario, "id", scenario_id, sizeof(scenario_id));
    r.scenario_id = scenario_id;

    /* A new account of its own: the HTTP login creates it, and connect reuses its runtime token. */
    STEP_CHECK(&r, admin_login(&r) == 0, "admin login");
    STEP_CHECK(&r, create_credential(server->db_path, CREDENTIAL_KEY, CREDENTIAL_SECRET, 2) == 0,
               "credential %s not stored", CREDENTIAL_KEY);
    STEP_CHECK(&r, http_client_login(server, CREDENTIAL_KEY, CREDENTIAL_SECRET, "machine-route-lifecycle",
                                     "route-owner", &r.runtime) == 0,
               "client HTTP login (status and body above)");
    r.client_id = r.runtime.client_id;
    snprintf(r.client_name, sizeof(r.client_name), "%s", r.runtime.client_name);

    char **steps = NULL;
    size_t step_count = 0U;
    STEP_CHECK(&r, vec_array(current_scenario, "steps", &steps, &step_count) == 0 && step_count > 0U,
               "scenario without steps");
    /* Every step runs even after a failed one, so a run shows each expectation the server misses. */
    for (size_t i = 0; i < step_count; ++i) {
        r.step_index = i;
        (void)run_step(&r, steps[i]);
    }
    st_json_free_string_array(steps, step_count);
    close_fd(&r.data);
    close_fd(&r.control);
    return r.failures != 0;
}

/*
 * C only (http-route.md section 1, defense in depth): the account is renamed away in the database
 * while its connections stay open here under the old name, then a new account of that name gets a
 * route of the old route's name. The public entry lets the request in for the new account; it must
 * not be forwarded to the other account's connection, which matches by name only.
 */
static const char account_replaced_scenario[] =
    "{\"id\":\"account-replaced-behind-the-server\",\"steps\":["
    "{\"op\":\"createRoute\",\"route\":\"web\",\"auth\":false,\"expectPush\":null},"
    "{\"op\":\"connect\",\"expectLoginPush\":[\"web\"]},"
    "{\"op\":\"renameClientInDatabase\",\"suffix\":\"-elsewhere\"},"
    "{\"op\":\"createClient\"},"
    "{\"op\":\"createRoute\",\"route\":\"web\",\"auth\":false,\"expectPush\":null},"
    "{\"op\":\"expectStillConnected\"},"
    "{\"op\":\"request\",\"route\":\"web\",\"path\":\"/secret\",\"credentials\":\"none\",\"websocket\":false,"
    "\"client\":\"current\",\"expect\":{\"statusAnyOf\":[502,503],\"forwarded\":false}},"
    "{\"op\":\"request\",\"route\":\"web\",\"path\":\"/secret\",\"credentials\":\"none\",\"websocket\":true,"
    "\"client\":\"current\",\"expect\":{\"statusAnyOf\":[502,503],\"forwarded\":false}},"
    "{\"op\":\"expectStillConnected\"}"
    "]}";

/* Reads what the scenarios share: credentials, target, and the fake client's answer. */
static int load_vector_constants(void)
{
    char name[64];
    long long version = 0;
    vec_text(vector_json, "name", name, sizeof(name));
    char *credentials = st_json_get_top_level_raw(vector_json, "basicCredentials");
    char *fake = st_json_get_top_level_raw(vector_json, "fakeClientResponse");
    char *headers = fake == NULL ? NULL : st_json_get_top_level_raw(fake, "headers");
    long long status = 0;
    int ok = strcmp(name, "http-route-lifecycle-v1") == 0
        && vec_i64(vector_json, "version", &version) == 0 && version == 1
        && credentials != NULL && fake != NULL && headers != NULL
        && vec_i64(fake, "status", &status) == 0;
    if (ok) {
        vec_text(credentials, "username", basic_username, sizeof(basic_username));
        vec_text(credentials, "password", basic_password, sizeof(basic_password));
        vec_text(vector_json, "targetBaseUrl", target_base_url, sizeof(target_base_url));
        vec_text(fake, "body", fake_response_body, sizeof(fake_response_body));
        int written = snprintf(fake_response_meta, sizeof(fake_response_meta),
                               "{\"source\":\"http\",\"phase\":\"response\",\"statusCode\":%lld,\"headers\":%s}",
                               status, headers);
        ok = written > 0 && (size_t)written < sizeof(fake_response_meta)
            && *basic_username != '\0' && *basic_password != '\0' && *target_base_url != '\0';
    }
    free(credentials);
    free(fake);
    free(headers);
    return ok ? 0 : -1;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <specus-server-c>\n", argv[0]);
        return 2;
    }
    server_binary = argv[1];
    /* Line by line, so in a CI log each scenario's verdict follows its own failure details. */
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGPIPE, SIG_IGN);
    srand((unsigned int)wall_clock_ms());

    vector_json = read_file(ST_ROUTE_LIFECYCLE_VECTOR_FILE);
    if (vector_json == NULL || !st_json_is_valid_object(vector_json) || load_vector_constants() != 0) {
        fprintf(stderr, "cannot read %s, or it is not http-route-lifecycle-v1\n", ST_ROUTE_LIFECYCLE_VECTOR_FILE);
        free(vector_json);
        return 1;
    }
    char *server_section = st_json_get_top_level_raw(vector_json, "server");
    char **scenarios = NULL;
    size_t scenario_count = 0U;
    if (server_section == NULL || vec_array(server_section, "scenarios", &scenarios, &scenario_count) != 0
        || scenario_count == 0U) {
        fprintf(stderr, "the vector has no server scenarios\n");
        free(server_section);
        free(vector_json);
        return 1;
    }
    int failures = 0;
    for (size_t i = 0; i < scenario_count; ++i) {
        char scenario_id[128];
        vec_text(scenarios[i], "id", scenario_id, sizeof(scenario_id));
        current_scenario = scenarios[i];
        failures += run_on_fresh_server(scenario_id, replay_current_scenario, NULL);
    }
    printf("http route lifecycle vector: %zu/%zu server scenarios passed\n",
           scenario_count - (size_t)failures, scenario_count);
    current_scenario = account_replaced_scenario;
    int extra_failures = run_on_fresh_server("account-replaced-behind-the-server", replay_current_scenario, NULL);
    failures += extra_failures;
    st_json_free_string_array(scenarios, scenario_count);
    free(server_section);
    free(vector_json);
    if (failures != 0) {
        fprintf(stderr, "%d HTTP route lifecycle scenario(s) failed\n", failures);
        return 1;
    }
    printf("HTTP route lifecycle tests passed\n");
    return 0;
}
