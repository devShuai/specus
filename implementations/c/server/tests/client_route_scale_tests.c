/*
 * One client with more TCP mappings and HTTP routes than the 64 of each the C server used to hold
 * per client (issue #191), on a real specus-server-c process. The HTTP login, the control login's
 * NAT_CONTROL, a runtime NAT_CONTROL push, the management detail and the lists carry every entry,
 * and entries past the 64th are served: a NAT REGISTER of the last mapping, a public request to
 * the last route.
 *
 * The one bound left is protocol/spec/control-protocol.md's 1 MiB MESSAGE body, which NAT_CONTROL
 * travels in. The management API refuses the route that would push the client's NAT_CONTROL past
 * it, and everything it accepted still reaches the client.
 *
 * Usage: specus_c_client_route_scale_tests <path-to-specus-server-c>
 */
#define _POSIX_C_SOURCE 200809L

#include "server_harness.h"

#include "json.h"
#include "protocol.h"

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef ST_NAT_CONTROL_SIZE_VECTOR_FILE
#define ST_NAT_CONTROL_SIZE_VECTOR_FILE "../../../protocol/test-vectors/nat-control-size-v1.json"
#endif

#define CREDENTIAL_KEY "ck_route_scale"
#define CREDENTIAL_SECRET "route-scale-secret"
#define FINGERPRINT "machine-route-scale"
#define OS_USER "route-scale-owner"
/* Well past the 64 mappings and 64 routes a client's runtime configuration used to hold. */
#define SCALE_COUNT 100
/* Listen ports of the mappings, below the ephemeral range a picked port comes from; never bound. */
#define MAPPING_PORT_BASE 21000
#define TARGET_PORT_BASE 31000
/* Routes written straight to the database in the limit scenario: about 1 MB of NAT_CONTROL. */
#define BULK_ROUTE_COUNT 1800
#define MAX_LIMIT_ATTEMPTS 200
/* About 1.2 KiB kept for a rename to the longest client name, plus less than one 570-byte route. */
#define NAME_ROOM_SLACK 2048U

typedef struct {
    test_server *server;
    char admin_token[1024];
    runtime_session runtime;
    int control;
    int data;
} scale_client;

static void scale_client_init(scale_client *c, test_server *server)
{
    memset(c, 0, sizeof(*c));
    c->server = server;
    c->control = -1;
    c->data = -1;
}

static void scale_client_close(scale_client *c)
{
    close_fd(&c->data);
    close_fd(&c->control);
}

/* ------------------------------------------------------------------------------------------- */
/* Management API                                                                                */

static int admin_login(scale_client *c)
{
    char body[256];
    snprintf(body, sizeof(body), "{\"username\":\"%s\",\"password\":\"%s\"}", ADMIN_USERNAME, ADMIN_PASSWORD);
    int status = 0;
    char *response = NULL;
    if (http_request(c->server->admin_port, "POST", "/auth/login", body, NULL, &status, &response) != 0) {
        return -1;
    }
    char *token = status == 200 ? st_json_get_top_level_string(response, "accessToken") : NULL;
    free(response);
    int rc = token != NULL && strlen(token) < sizeof(c->admin_token) ? 0 : -1;
    if (rc == 0) {
        snprintf(c->admin_token, sizeof(c->admin_token), "%s", token);
    }
    free(token);
    return rc;
}

/* One management API call; 0 when it answered expected_status, with *response for the caller. */
static int admin_call(const scale_client *c, const char *method, const char *path, const char *body,
                      int expected_status, char **response)
{
    int status = 0;
    char *answer = NULL;
    int rc = http_request(c->server->admin_port, method, path, body, c->admin_token, &status, &answer);
    if (rc != 0 || status != expected_status) {
        fprintf(stderr, "  %s %s answered %d, expected %d: %.300s\n", method, path, status, expected_status,
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

static int create_mapping_api(const scale_client *c, int listen_port, int target_port)
{
    char path[128];
    char body[256];
    snprintf(path, sizeof(path), "/api/admin/clients/%lld/specus-mappings", c->runtime.client_id);
    snprintf(body, sizeof(body),
             "{\"listenPort\":%d,\"targetAddress\":\"127.0.0.1\",\"targetPort\":%d,\"enabled\":true}",
             listen_port, target_port);
    return admin_call(c, "POST", path, body, 201, NULL);
}

static int create_route_api(const scale_client *c, const char *route, const char *target, int expected_status,
                            char **response)
{
    char path[128];
    char body[1024];
    snprintf(path, sizeof(path), "/api/admin/clients/%lld/http-routes", c->runtime.client_id);
    snprintf(body, sizeof(body), "{\"route\":\"%s\",\"targetBaseUrl\":\"%s\",\"enabled\":true}", route, target);
    return admin_call(c, "POST", path, body, expected_status, response);
}

/* The real HTTP login of the credential, keeping the whole answer the client receives. */
static int client_login(scale_client *c, char **response)
{
    *response = NULL;
    char body[2048];
    signed_login_body(CREDENTIAL_KEY, CREDENTIAL_SECRET, FINGERPRINT, OS_USER, body, sizeof(body));
    int status = 0;
    char *answer = NULL;
    if (http_request(c->server->admin_port, "POST", "/api/client/auth/login", body, NULL, &status, &answer) != 0
        || status != 200) {
        fprintf(stderr, "  client login answered %d: %.300s\n", status, answer == NULL ? "(no response)" : answer);
        free(answer);
        return -1;
    }
    char *client_name = st_json_get_top_level_string(answer, "clientName");
    char *token = st_json_get_top_level_string(answer, "accessToken");
    int rc = client_name != NULL && token != NULL
        && strlen(client_name) < sizeof(c->runtime.client_name) && strlen(token) < sizeof(c->runtime.access_token)
        && st_json_get_i64(answer, "clientSessionId", &c->runtime.session_id) == 0
        && st_json_get_i64(answer, "clientId", &c->runtime.client_id) == 0
        ? 0 : -1;
    if (rc == 0) {
        snprintf(c->runtime.client_name, sizeof(c->runtime.client_name), "%s", client_name);
        snprintf(c->runtime.access_token, sizeof(c->runtime.access_token), "%s", token);
        *response = answer;
    } else {
        fprintf(stderr, "  client login answer is incomplete: %.300s\n", answer);
        free(answer);
    }
    free(client_name);
    free(token);
    return rc;
}

/* ------------------------------------------------------------------------------------------- */
/* JSON                                                                                          */

/* Elements of the first array named key in json; -1 when there is none. */
static long array_length(const char *json, const char *key)
{
    char **items = NULL;
    size_t count = 0U;
    if (json == NULL || st_json_get_raw_array(json, key, &items, &count) != 0) {
        return -1;
    }
    st_json_free_string_array(items, count);
    return (long)count;
}

/* Elements of json when it is a top-level array, as the list endpoints answer; -1 otherwise. */
static long top_level_array_length(const char *json)
{
    if (json == NULL) {
        return -1;
    }
    size_t wrapped_len = strlen(json) + 16U;
    char *wrapped = (char *)malloc(wrapped_len);
    if (wrapped == NULL) {
        return -1;
    }
    snprintf(wrapped, wrapped_len, "{\"items\":%s}", json);
    long count = array_length(wrapped, "items");
    free(wrapped);
    return count;
}

/* ------------------------------------------------------------------------------------------- */
/* Fake client                                                                                   */

/*
 * The next NAT_CONTROL on the control connection: 1 with *json set and *body_len the size of the
 * MESSAGE body it came in, 0 when the connection closed, -1 otherwise.
 */
static int next_nat_control(int fd, char **json, size_t *body_len)
{
    *json = NULL;
    *body_len = 0U;
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
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
            *body_len = header.length;
            message.message = NULL;
            st_message_response_free(&message);
            return 1;
        }
        st_message_response_free(&message);
    }
}

/*
 * The next NAT_CONTROL carries mappings TCP entries and routes HTTP entries; *body_len_out, unless
 * NULL, receives the size of the MESSAGE body it came in.
 */
static int expect_nat_control(scale_client *c, const char *when, long mappings, long routes, char **json_out,
                              size_t *body_len_out)
{
    char *json = NULL;
    size_t body_len = 0U;
    int rc = next_nat_control(c->control, &json, &body_len);
    CHECK(rc == 1, "%s: no NAT_CONTROL arrived (rc=%d)", when, rc);
    long tcp = array_length(json, "specusConfigList");
    long http = array_length(json, "httpSpecusConfigList");
    if (tcp != mappings || http != routes) {
        fprintf(stderr, "FAIL %s: NAT_CONTROL of %zu bytes carries %ld TCP and %ld HTTP entries, expected %ld and %ld\n",
                when, body_len, tcp, http, mappings, routes);
        free(json);
        return 1;
    }
    if (json_out != NULL) {
        *json_out = json;
    } else {
        free(json);
    }
    if (body_len_out != NULL) {
        *body_len_out = body_len;
    }
    return 0;
}

/*
 * A public GET of /http/<client>/<route>/scale on the admin port. The fake client answers the OPEN
 * its data connection gets with a 200 "forwarded"; *forwarded tells whether one arrived.
 */
static int public_route_request(scale_client *c, const char *route, int *status, int *forwarded)
{
    *status = 0;
    *forwarded = 0;
    char encoded_client[768];
    size_t used = 0U;
    for (const unsigned char *p = (const unsigned char *)c->runtime.client_name;
         *p != '\0' && used + 4U < sizeof(encoded_client); ++p) {
        if ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9')
            || *p == '-' || *p == '_' || *p == '.' || *p == '~') {
            encoded_client[used++] = (char)*p;
        } else {
            used += (size_t)snprintf(encoded_client + used, sizeof(encoded_client) - used, "%%%02X", *p);
        }
    }
    encoded_client[used] = '\0';
    char request[2048];
    int request_len = snprintf(request, sizeof(request),
                               "GET /http/%s/%s/scale HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n",
                               encoded_client, route, c->server->admin_port);
    int fd = connect_local(c->server->admin_port);
    if (fd < 0 || request_len <= 0 || (size_t)request_len >= sizeof(request)
        || send_all(fd, (const uint8_t *)request, (size_t)request_len) != 0) {
        close_fd(&fd);
        return -1;
    }
    char raw[8192];
    size_t raw_used = 0U;
    raw[0] = '\0';
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    for (;;) {
        long long remaining = deadline - monotonic_ms();
        if (remaining <= 0) {
            break;
        }
        struct pollfd ready[2] = {
            {.fd = fd, .events = POLLIN, .revents = 0},
            {.fd = c->data, .events = POLLIN, .revents = 0},
        };
        int polled = poll(ready, 2U, (int)remaining);
        if (polled < 0 && errno == EINTR) {
            continue;
        }
        if (polled <= 0) {
            break;
        }
        if (ready[1].revents != 0) {
            st_frame_header header;
            uint8_t *body = NULL;
            if (read_frame(c->data, IO_TIMEOUT_MS, &header, &body) != 1) {
                close_fd(&fd);
                return -1;
            }
            st_nat_message message;
            if (header.command == ST_CMD_NAT_MESSAGE
                && st_protocol_decode_nat_message(body, header.length, &message) == 0) {
                if (message.type == ST_NAT_OPEN) {
                    *forwarded = 1;
                    const char *meta = "{\"source\":\"http\",\"phase\":\"response\",\"statusCode\":200,"
                                       "\"headers\":[\"Content-Type:text/plain\"]}";
                    st_buffer open = st_protocol_encode_nat_message(ST_NAT_OPEN, 0U, message.stream_id, 0U,
                                                                    meta, NULL, 0U);
                    st_buffer data = st_protocol_encode_nat_message(ST_NAT_DATA, 0U, message.stream_id, 0U,
                                                                    NULL, (const uint8_t *)"forwarded", 9U);
                    st_buffer fin = st_protocol_encode_nat_message(ST_NAT_FIN, 0U, message.stream_id, 0U,
                                                                   NULL, NULL, 0U);
                    (void)send_buffer(c->data, &open);
                    (void)send_buffer(c->data, &data);
                    (void)send_buffer(c->data, &fin);
                }
                st_nat_message_free(&message);
            }
            free(body);
        }
        if (ready[0].revents != 0) {
            ssize_t received = recv(fd, raw + raw_used, sizeof(raw) - 1U - raw_used, 0);
            if (received < 0 && errno == EINTR) {
                continue;
            }
            if (received <= 0) {
                break;
            }
            raw_used += (size_t)received;
            raw[raw_used] = '\0';
            if (raw_used == sizeof(raw) - 1U) {
                break;
            }
        }
    }
    close_fd(&fd);
    if (sscanf(raw, "HTTP/1.1 %d", status) != 1) {
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------------------------------- */
/* Scenarios                                                                                     */

/*
 * SCALE_COUNT mappings and routes through the management API: the last mapping (on a free port,
 * so it can be registered) and the last route sort after every other one, past the 64th entry.
 */
static int scenario_hundred_mappings_and_routes(test_server *server)
{
    scale_client c;
    scale_client_init(&c, server);
    CHECK(admin_login(&c) == 0, "admin login");
    CHECK(create_credential(server->db_path, CREDENTIAL_KEY, CREDENTIAL_SECRET, 2) == 0, "credential not stored");
    char *login = NULL;
    CHECK(client_login(&c, &login) == 0, "first client HTTP login");
    free(login);

    int last_port = pick_free_port();
    CHECK(last_port > MAPPING_PORT_BASE + SCALE_COUNT, "picked port %d is not above the fixed mapping ports", last_port);
    for (int i = 0; i < SCALE_COUNT; ++i) {
        int listen_port = i == SCALE_COUNT - 1 ? last_port : MAPPING_PORT_BASE + i;
        CHECK(create_mapping_api(&c, listen_port, TARGET_PORT_BASE + i) == 0, "mapping %d was not created", i);
        char route[32];
        char target[64];
        snprintf(route, sizeof(route), "route-%03d", i);
        snprintf(target, sizeof(target), "http://127.0.0.1:%d", TARGET_PORT_BASE + i);
        CHECK(create_route_api(&c, route, target, 201, NULL) == 0, "route %s was not created", route);
    }

    /* The login answer is the client's whole configuration. */
    CHECK(client_login(&c, &login) == 0, "client HTTP login with %d mappings and %d routes", SCALE_COUNT, SCALE_COUNT);
    long login_tcp = array_length(login, "specusConfigList");
    long login_http = array_length(login, "httpSpecusConfigList");
    char last_port_entry[64];
    snprintf(last_port_entry, sizeof(last_port_entry), "\"port\":%d,", last_port);
    int login_has_last = strstr(login, last_port_entry) != NULL && strstr(login, "\"route\":\"route-099\"") != NULL;
    free(login);
    CHECK(login_tcp == SCALE_COUNT && login_http == SCALE_COUNT,
          "the login answer carries %ld TCP and %ld HTTP entries, expected %d of each", login_tcp, login_http, SCALE_COUNT);
    CHECK(login_has_last, "the login answer misses the last mapping or route");

    char reason[256];
    int rc = channel_login(server->control_port, &c.runtime, "control", &c.control, reason, sizeof(reason));
    CHECK(rc == 1, "control login: %s", reason);
    char *nat = NULL;
    if (expect_nat_control(&c, "control login", SCALE_COUNT, SCALE_COUNT, &nat, NULL) != 0) {
        scale_client_close(&c);
        return 1;
    }
    int nat_has_last = strstr(nat, last_port_entry) != NULL && strstr(nat, "\"route\":\"route-099\"") != NULL;
    free(nat);
    CHECK(nat_has_last, "the login NAT_CONTROL misses the last mapping or route");
    rc = channel_login(server->control_port, &c.runtime, "data", &c.data, reason, sizeof(reason));
    CHECK(rc == 1, "data login: %s", reason);

    /* Entries past the 64th are served, not only listed. */
    CHECK(nat_register(c.data, c.runtime.client_name, last_port, TARGET_PORT_BASE + SCALE_COUNT - 1) == 0,
          "REGISTER of the last mapping (port %d) was refused", last_port);
    int status = 0;
    int forwarded = 0;
    CHECK(public_route_request(&c, "route-099", &status, &forwarded) == 0, "public request to route-099 failed");
    CHECK(forwarded && status == 200, "public request to route-099 answered %d, forwarded=%d", status, forwarded);

    /* Each change while online pushes the whole set again. */
    CHECK(create_mapping_api(&c, MAPPING_PORT_BASE + SCALE_COUNT, TARGET_PORT_BASE + SCALE_COUNT) == 0,
          "mapping %d was not created", SCALE_COUNT);
    if (expect_nat_control(&c, "push after a mapping was created", SCALE_COUNT + 1, SCALE_COUNT, NULL, NULL) != 0) {
        scale_client_close(&c);
        return 1;
    }
    CHECK(create_route_api(&c, "route-100", "http://127.0.0.1:31100", 201, NULL) == 0, "route-100 was not created");
    if (expect_nat_control(&c, "push after a route was created", SCALE_COUNT + 1, SCALE_COUNT + 1, NULL, NULL) != 0) {
        scale_client_close(&c);
        return 1;
    }
    char path[160];
    char *answer = NULL;
    snprintf(path, sizeof(path), "/api/admin/clients/%lld/nat-control", c.runtime.client_id);
    CHECK(admin_call(&c, "POST", path, NULL, 200, &answer) == 0, "the explicit NAT_CONTROL push failed");
    long long pushed_mappings = 0;
    long long pushed_routes = 0;
    int counted = st_json_get_i64(answer, "specusMappings", &pushed_mappings) == 0
        && st_json_get_i64(answer, "httpRoutes", &pushed_routes) == 0;
    free(answer);
    CHECK(counted && pushed_mappings == SCALE_COUNT + 1 && pushed_routes == SCALE_COUNT + 1,
          "the push reports %lld mappings and %lld routes", pushed_mappings, pushed_routes);
    if (expect_nat_control(&c, "explicit push", SCALE_COUNT + 1, SCALE_COUNT + 1, NULL, NULL) != 0) {
        scale_client_close(&c);
        return 1;
    }
    CHECK(expect_channel_alive(c.control) == 0 && expect_channel_alive(c.data) == 0,
          "the client's connections are no longer served");

    /* The management views list every entry. */
    snprintf(path, sizeof(path), "/api/admin/clients/%lld", c.runtime.client_id);
    CHECK(admin_call(&c, "GET", path, NULL, 200, &answer) == 0, "client detail failed");
    long detail_tcp = array_length(answer, "specusMappings");
    long detail_http = array_length(answer, "httpRoutes");
    free(answer);
    CHECK(detail_tcp == SCALE_COUNT + 1 && detail_http == SCALE_COUNT + 1,
          "client detail lists %ld mappings and %ld routes", detail_tcp, detail_http);
    snprintf(path, sizeof(path), "/api/admin/specus-mappings?clientId=%lld", c.runtime.client_id);
    CHECK(admin_call(&c, "GET", path, NULL, 200, &answer) == 0, "mapping list failed");
    long listed = top_level_array_length(answer);
    free(answer);
    CHECK(listed == SCALE_COUNT + 1, "the client's mapping list has %ld entries", listed);
    CHECK(admin_call(&c, "GET", "/api/admin/specus-mappings", NULL, 200, &answer) == 0, "full mapping list failed");
    listed = top_level_array_length(answer);
    free(answer);
    CHECK(listed >= SCALE_COUNT + 1, "the full mapping list has %ld entries", listed);
    snprintf(path, sizeof(path), "/api/admin/http-routes?clientId=%lld", c.runtime.client_id);
    CHECK(admin_call(&c, "GET", path, NULL, 200, &answer) == 0, "route list failed");
    listed = top_level_array_length(answer);
    free(answer);
    CHECK(listed == SCALE_COUNT + 1, "the client's route list has %ld entries", listed);
    CHECK(admin_call(&c, "GET", "/api/admin/http-routes", NULL, 200, &answer) == 0, "full route list failed");
    listed = top_level_array_length(answer);
    free(answer);
    CHECK(listed >= SCALE_COUNT + 1, "the full route list has %ld entries", listed);
    CHECK(admin_call(&c, "GET", "/api/admin/overview", NULL, 200, &answer) == 0, "overview failed");
    long long overview_mappings = 0;
    int overview_counted = st_json_get_i64(answer, "tcpMappings", &overview_mappings) == 0;
    free(answer);
    CHECK(overview_counted && overview_mappings >= SCALE_COUNT + 1, "the overview counts %lld mappings",
          overview_mappings);
    scale_client_close(&c);
    return 0;
}

/* Routes route-prefix-0001.. with target, straight into the database as an earlier process left them. */
static int insert_routes(const char *db_path, const char *client_name, const char *prefix, int count,
                         const char *target, int enabled)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(db_path, &db) != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_busy_timeout(db, 5000);
    sqlite3_stmt *stmt = NULL;
    int rc = -1;
    if (sqlite3_prepare_v2(db,
                           "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?) "
                           "INSERT INTO http_route_mapping(client_name, route, target_base_url, enabled) "
                           "SELECT ?, printf('%s-%04d', ?, i), ?, ? FROM n",
                           -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, count);
        sqlite3_bind_text(stmt, 2, client_name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, prefix, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, target, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 5, enabled ? 1 : 0);
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc;
}

static int find_route_id(const char *db_path, const char *client_name, const char *route, long long *id)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(db_path, &db) != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_busy_timeout(db, 5000);
    sqlite3_stmt *stmt = NULL;
    int rc = -1;
    if (sqlite3_prepare_v2(db, "SELECT id FROM http_route_mapping WHERE client_name = ? AND route = ?",
                           -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, client_name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, route, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            *id = sqlite3_column_int64(stmt, 0);
            rc = 0;
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc;
}

/*
 * Routes with 500-character targets, about 570 bytes of NAT_CONTROL each, fill the client's
 * NAT_CONTROL towards the 1 MiB MESSAGE body limit; the API then refuses the route that would not
 * fit, and enabling a route of that size, while a change that keeps the size is accepted. The
 * login and its NAT_CONTROL still carry every enabled route.
 */
static int scenario_nat_control_message_limit(test_server *server)
{
    scale_client c;
    scale_client_init(&c, server);
    CHECK(admin_login(&c) == 0, "admin login");
    CHECK(create_credential(server->db_path, CREDENTIAL_KEY, CREDENTIAL_SECRET, 2) == 0, "credential not stored");
    char *login = NULL;
    CHECK(client_login(&c, &login) == 0, "first client HTTP login");
    free(login);

    char target[501];
    const char *origin = "http://127.0.0.1:8080/";
    size_t origin_len = strlen(origin);
    memcpy(target, origin, origin_len);
    memset(target + origin_len, 'a', sizeof(target) - 1U - origin_len);
    target[sizeof(target) - 1U] = '\0';
    /* Every name has the same length, so every entry has the same size. */
    CHECK(insert_routes(server->db_path, c.runtime.client_name, "bulk", BULK_ROUTE_COUNT, target, 1) == 0
              && insert_routes(server->db_path, c.runtime.client_name, "idle", 1, target, 0) == 0
              && insert_routes(server->db_path, c.runtime.client_name, "kept", 1, target, 1) == 0,
          "routes could not be written to the database");

    int accepted = 0;
    int refused = 0;
    for (int i = 1; i <= MAX_LIMIT_ATTEMPTS && !refused; ++i) {
        char route[32];
        snprintf(route, sizeof(route), "more-%04d", i);
        int status = 0;
        char *answer = NULL;
        char path[128];
        char body[1024];
        snprintf(path, sizeof(path), "/api/admin/clients/%lld/http-routes", c.runtime.client_id);
        snprintf(body, sizeof(body), "{\"route\":\"%s\",\"targetBaseUrl\":\"%s\",\"enabled\":true}", route, target);
        CHECK(http_request(server->admin_port, "POST", path, body, c.admin_token, &status, &answer) == 0,
              "route %s: no answer", route);
        if (status == 201) {
            ++accepted;
        } else {
            int named = answer != NULL && strstr(answer, "NAT_CONTROL") != NULL;
            fprintf(stderr, "  route %s answered %d: %.300s\n", route, status, answer == NULL ? "" : answer);
            free(answer);
            CHECK(status == 400 && named, "route %s was refused with %d, not the NAT_CONTROL limit", route, status);
            refused = 1;
            break;
        }
        free(answer);
    }
    CHECK(accepted > 0 && refused, "%d routes accepted, refused=%d", accepted, refused);
    long enabled_routes = BULK_ROUTE_COUNT + 1 + accepted;

    /* Enabling a route as large as the refused one does not fit either; same-size changes do. */
    long long idle_id = 0;
    long long kept_id = 0;
    CHECK(find_route_id(server->db_path, c.runtime.client_name, "idle-0001", &idle_id) == 0
              && find_route_id(server->db_path, c.runtime.client_name, "kept-0001", &kept_id) == 0,
          "the database routes have no ids");
    char path[160];
    snprintf(path, sizeof(path), "/api/admin/http-routes/%lld", idle_id);
    CHECK(admin_call(&c, "PUT", path, "{\"enabled\":true}", 400, NULL) == 0, "enabling idle-0001 was not refused");
    snprintf(path, sizeof(path), "/api/admin/http-routes/%lld", kept_id);
    CHECK(admin_call(&c, "PUT", path, "{\"detailCaptureEnabled\":true}", 200, NULL) == 0,
          "a change of kept-0001 that keeps its size was refused");

    /* Everything accepted reaches the client: the login answer and the NAT_CONTROL. */
    CHECK(client_login(&c, &login) == 0, "client HTTP login with %ld routes", enabled_routes);
    long login_http = array_length(login, "httpSpecusConfigList");
    free(login);
    CHECK(login_http == enabled_routes, "the login answer carries %ld routes, expected %ld", login_http, enabled_routes);
    char reason[256];
    int rc = channel_login(server->control_port, &c.runtime, "control", &c.control, reason, sizeof(reason));
    CHECK(rc == 1, "control login: %s", reason);
    size_t nat_body_len = 0U;
    if (expect_nat_control(&c, "control login near the limit", 0, enabled_routes, NULL, &nat_body_len) != 0) {
        scale_client_close(&c);
        return 1;
    }
    /*
     * The frame was read within the limit; the refusal left it short by less than one more route
     * plus the room kept for the longest name a rename can give the client.
     */
    CHECK(nat_body_len <= ST_MAX_MESSAGE_BODY_SIZE && nat_body_len + NAME_ROOM_SLACK > ST_MAX_MESSAGE_BODY_SIZE,
          "the NAT_CONTROL near the limit is %zu bytes", nat_body_len);
    CHECK(expect_channel_alive(c.control) == 0, "the control connection is no longer served");
    char *answer = NULL;
    snprintf(path, sizeof(path), "/api/admin/clients/%lld", c.runtime.client_id);
    CHECK(admin_call(&c, "GET", path, NULL, 200, &answer) == 0, "client detail failed");
    long detail_http = array_length(answer, "httpRoutes");
    free(answer);
    CHECK(detail_http == enabled_routes + 1, "client detail lists %ld routes, expected %ld", detail_http,
          enabled_routes + 1);
    scale_client_close(&c);
    return 0;
}

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

/*
 * A heartbeat round trip on the control connection: 0 once its answer arrives, -1 when the
 * connection closed or nothing came in time. NAT_CONTROL frames that came before the answer are
 * added to *nat_controls, the first one's JSON kept in *first_nat_json, and *peer_config is set when
 * a Peer Mesh peer-config came. The server writes a push before it answers a later heartbeat, so a
 * round after a management call sees whatever that call sent.
 */
static int control_round(int fd, int *nat_controls, int *peer_config, char **first_nat_json)
{
    st_buffer heartbeat = st_protocol_encode_empty_packet(ST_CMD_HEARTBEAT_REQUEST);
    if (send_buffer(fd, &heartbeat) != 0) {
        return -1;
    }
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    for (;;) {
        long long remaining = deadline - monotonic_ms();
        if (remaining <= 0) {
            return -1;
        }
        st_frame_header header;
        uint8_t *body = NULL;
        if (read_frame(fd, (int)remaining, &header, &body) != 1) {
            return -1;
        }
        if (header.command == ST_CMD_HEARTBEAT_RESPONSE) {
            free(body);
            return 0;
        }
        st_message_response message;
        if (header.command != ST_CMD_MESSAGE_RESPONSE
            || st_protocol_decode_message_response(body, header.length, &message) != 0) {
            free(body);
            continue;
        }
        free(body);
        if (message.message_type == ST_MESSAGE_TYPE_NAT_CONTROL) {
            ++*nat_controls;
            if (*first_nat_json == NULL) {
                *first_nat_json = message.message;
                message.message = NULL;
            }
        } else if (message.message_type == ST_MESSAGE_TYPE_PEER_CONTROL && message.message != NULL) {
            char *type = st_json_get_top_level_string(message.message, "type");
            *peer_config = *peer_config || (type != NULL && strcmp(type, "peer-config") == 0);
            free(type);
        }
        st_message_response_free(&message);
    }
}

/*
 * Replays existingOversize of protocol/test-vectors/nat-control-size-v1.json: routes written straight
 * to the database take the client's NAT_CONTROL past the 1 MiB MESSAGE body. The control login stands
 * and the Peer Mesh login push still arrives, the manual pushes answer 409, route changes are stored
 * and answered as usual, and nothing reaches the connection, which stays open, until the configuration
 * is back within the limit. Before, the login closed the connection without the Peer Mesh push, and
 * the client logged in again into the same failure.
 */
static int scenario_existing_oversize_nat_control(test_server *server)
{
    char *vector = read_file(ST_NAT_CONTROL_SIZE_VECTOR_FILE);
    char *scenario = vector == NULL ? NULL : st_json_get_top_level_raw(vector, "existingOversize");
    char *error_contains = vector == NULL ? NULL : st_json_get_top_level_string(vector, "errorContains");
    free(vector);
    int json_bytes = 0;
    int target_bytes = 0;
    char **steps = NULL;
    size_t step_count = 0U;
    int loaded = scenario != NULL && error_contains != NULL
        && st_json_get_int(scenario, "jsonBytesWithEmptyClientName", &json_bytes) == 0
        && st_json_get_int(scenario, "fillTargetBaseUrlMaxBytes", &target_bytes) == 0
        && st_json_get_raw_array(scenario, "steps", &steps, &step_count) == 0;
    free(scenario);
    CHECK(loaded && json_bytes > 0 && target_bytes > 32 && target_bytes < 512,
          "cannot read existingOversize of %s", ST_NAT_CONTROL_SIZE_VECTOR_FILE);

    scale_client c;
    scale_client_init(&c, server);
    CHECK(admin_login(&c) == 0, "admin login");
    CHECK(create_credential(server->db_path, CREDENTIAL_KEY, CREDENTIAL_SECRET, 2) == 0, "credential not stored");
    char *login = NULL;
    CHECK(client_login(&c, &login) == 0, "client HTTP login");
    free(login);

    /* Enough routes that their targets alone take the NAT_CONTROL JSON past jsonBytes. */
    char target[512];
    const char *origin = "http://127.0.0.1:8080/";
    size_t origin_len = strlen(origin);
    memcpy(target, origin, origin_len);
    memset(target + origin_len, 'f', (size_t)target_bytes - origin_len);
    target[target_bytes] = '\0';
    int fill_count = (json_bytes + target_bytes - 1) / target_bytes;
    CHECK(insert_routes(server->db_path, c.runtime.client_name, "fill", fill_count, target, 1) == 0,
          "routes could not be written to the database");

    int nat_controls = 0;
    int peer_config = 0;
    char *first_nat = NULL;
    int next_fill = 1;
    int failed = 0;
    for (size_t i = 0; i < step_count && !failed; ++i) {
        char *op = st_json_get_string(steps[i], "op");
        int expect = 0;
        int nat_control_expected = 0;
        (void)st_json_get_int(steps[i], "expect", &expect);
        (void)st_json_get_bool(steps[i], "natControl", &nat_control_expected);
        char path[192];
        int status = 0;
        char *answer = NULL;
        int called = 0;
        if (op != NULL && strcmp(op, "connect") == 0) {
            char reason[256];
            int rc = channel_login(server->control_port, &c.runtime, "control", &c.control, reason, sizeof(reason));
            if (rc != 1) {
                fprintf(stderr, "FAIL step %zu: control login: %s\n", i, reason);
                failed = 1;
            }
        } else if (op != NULL && (strcmp(op, "pushNatControl") == 0 || strcmp(op, "forceRefreshPortMapping") == 0)) {
            snprintf(path, sizeof(path), "/api/admin/clients/%lld/%s", c.runtime.client_id,
                     strcmp(op, "pushNatControl") == 0 ? "nat-control" : "force-refresh-port-mapping");
            called = http_request(server->admin_port, "POST", path, NULL, c.admin_token, &status, &answer) == 0;
        } else if (op != NULL && strcmp(op, "createRoute") == 0) {
            char *route = st_json_get_string(steps[i], "route");
            char *route_target = st_json_get_string(steps[i], "targetBaseUrl");
            int enabled = 1;
            (void)st_json_get_bool(steps[i], "enabled", &enabled);
            char body[512];
            snprintf(body, sizeof(body), "{\"route\":\"%s\",\"targetBaseUrl\":\"%s\",\"enabled\":%s}",
                     route == NULL ? "" : route, route_target == NULL ? "" : route_target,
                     enabled ? "true" : "false");
            free(route);
            free(route_target);
            snprintf(path, sizeof(path), "/api/admin/clients/%lld/http-routes", c.runtime.client_id);
            called = http_request(server->admin_port, "POST", path, body, c.admin_token, &status, &answer) == 0;
        } else if (op != NULL && strcmp(op, "deleteFillRoute") == 0) {
            char route[32];
            long long route_id = 0;
            snprintf(route, sizeof(route), "fill-%04d", next_fill++);
            if (find_route_id(server->db_path, c.runtime.client_name, route, &route_id) != 0) {
                fprintf(stderr, "FAIL step %zu: %s has no id\n", i, route);
                failed = 1;
            } else {
                snprintf(path, sizeof(path), "/api/admin/http-routes/%lld", route_id);
                called = http_request(server->admin_port, "DELETE", path, NULL, c.admin_token, &status, &answer) == 0;
            }
        } else if (op != NULL && strcmp(op, "shrinkInStore") == 0) {
            sqlite3 *db = NULL;
            sqlite3_stmt *stmt = NULL;
            int rc = -1;
            if (sqlite3_open(server->db_path, &db) == SQLITE_OK) {
                sqlite3_busy_timeout(db, 5000);
                if (sqlite3_prepare_v2(db,
                                       "UPDATE http_route_mapping SET enabled = 0 "
                                       "WHERE client_name = ? AND route LIKE 'fill-%'",
                                       -1, &stmt, NULL) == SQLITE_OK) {
                    sqlite3_bind_text(stmt, 1, c.runtime.client_name, -1, SQLITE_TRANSIENT);
                    rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
                }
            }
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            if (rc != 0) {
                fprintf(stderr, "FAIL step %zu: the routes could not be disabled in the database\n", i);
                failed = 1;
            }
        } else {
            fprintf(stderr, "FAIL step %zu: unknown op %s\n", i, op == NULL ? "(none)" : op);
            failed = 1;
        }

        if (!failed && expect != 0) {
            if (!called || status != expect) {
                fprintf(stderr, "FAIL step %zu %s: answered %d, expected %d: %.300s\n", i, op, status, expect,
                        answer == NULL ? "(no response)" : answer);
                failed = 1;
            } else if (status == 409 && (answer == NULL || strstr(answer, error_contains) == NULL)) {
                fprintf(stderr, "FAIL step %zu %s: the 409 does not name %s: %.300s\n", i, op, error_contains,
                        answer == NULL ? "" : answer);
                failed = 1;
            }
        }
        free(answer);
        if (!failed && control_round(c.control, &nat_controls, &peer_config, &first_nat) != 0) {
            fprintf(stderr, "FAIL step %zu %s: the control connection is no longer served\n", i, op);
            failed = 1;
        }
        if (!failed && strcmp(op, "connect") == 0 && !peer_config) {
            fprintf(stderr, "FAIL step %zu: no Peer Mesh login push arrived\n", i);
            failed = 1;
        }
        if (!failed && nat_control_expected
            && (nat_controls == 0 || first_nat == NULL || strstr(first_nat, "\"fill-") != NULL)) {
            fprintf(stderr, "FAIL step %zu %s: %d NAT_CONTROL(s), the first %s\n", i, op, nat_controls,
                    first_nat == NULL ? "missing" : "still listing the database routes");
            failed = 1;
        } else if (!failed && !nat_control_expected && nat_controls != 0) {
            fprintf(stderr, "FAIL step %zu %s: %d NAT_CONTROL(s) reached the client\n", i, op, nat_controls);
            failed = 1;
        }
        free(op);
    }
    free(first_nat);
    free(error_contains);
    st_json_free_string_array(steps, step_count);
    scale_client_close(&c);
    return failed;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <specus-server-c>\n", argv[0]);
        return 2;
    }
    server_binary = argv[1];
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGPIPE, SIG_IGN);
    srand((unsigned int)wall_clock_ms());

    int failures = 0;
    failures += run_on_fresh_server("hundred-mappings-and-routes", scenario_hundred_mappings_and_routes, NULL);
    failures += run_on_fresh_server("nat-control-message-limit", scenario_nat_control_message_limit, NULL);
    /* Peer Mesh on for its login push, its STUN/TURN listener on an ephemeral loopback port. */
    static const char *const peer_mesh[] = {
        "SPECUS_PEER_MESH_ENABLED=true", "SPECUS_PEER_MESH_STUN_TURN_PORT=0",
        "SPECUS_PEER_MESH_BIND_ADDRESS=127.0.0.1", NULL,
    };
    failures += run_on_fresh_server("nat-control-existing-oversize", scenario_existing_oversize_nat_control,
                                    peer_mesh);
    if (failures != 0) {
        fprintf(stderr, "%d client route scale scenario(s) failed\n", failures);
        return 1;
    }
    printf("client route scale tests passed\n");
    return 0;
}
