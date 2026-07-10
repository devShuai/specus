#include "json.h"
#include "protocol.h"
#include "test_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int test_login_request_decode(void)
{
    uint8_t *bytes = NULL;
    st_frame_header header;
    if (st_test_decode_fixture_header("login_request.bin", &bytes, &header) != 0) {
        return 1;
    }
    st_login_request request;
    int ok = header.command == ST_CMD_LOGIN_REQUEST
        && st_protocol_decode_login_request(bytes + ST_HEADER_SIZE, header.length, &request) != 0;
    if (!ok) {
        fprintf(stderr, "legacy login request fixture should be rejected\n");
        st_login_request_free(&request);
    }
    free(bytes);
    return ok ? 0 : 1;
}

static int test_message_response_decode(void)
{
    uint8_t *bytes = NULL;
    st_frame_header header;
    if (st_test_decode_fixture_header("message_response.bin", &bytes, &header) != 0) {
        return 1;
    }
    st_message_response response;
    int rc = header.command == ST_CMD_MESSAGE_RESPONSE
        && st_protocol_decode_message_response(bytes + ST_HEADER_SIZE, header.length, &response) == 0;
    if (!rc) {
        fprintf(stderr, "message response decode failed\n");
        free(bytes);
        return 1;
    }
    int ok = strcmp(response.client_name, "admin") == 0
        && strcmp(response.to_client_name, "Demo client") == 0
        && response.message_type == 3
        && strcmp(response.message, "{\"clientName\":\"Demo client\",\"remotePort\":7010}") == 0;
    if (!ok) {
        fprintf(stderr, "message response content mismatch\n");
    }
    st_message_response_free(&response);
    free(bytes);
    return ok ? 0 : 1;
}

static int test_empty_packets(void)
{
    const struct {
        const char *fixture;
        int command;
    } cases[] = {
        {"heartbeat_request.bin", ST_CMD_HEARTBEAT_REQUEST},
        {"heartbeat_response.bin", ST_CMD_HEARTBEAT_RESPONSE},
        {"logout_request.bin", ST_CMD_LOGOUT_REQUEST}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint8_t *bytes = NULL;
        st_frame_header header;
        if (st_test_decode_fixture_header(cases[i].fixture, &bytes, &header) != 0) {
            return 1;
        }
        int ok = header.command == cases[i].command
            && st_protocol_decode_empty_packet(bytes + ST_HEADER_SIZE, header.length) == 0;
        free(bytes);
        if (!ok) {
            fprintf(stderr, "%s empty packet mismatch\n", cases[i].fixture);
            return 1;
        }
    }
    return 0;
}

static int test_frame_limit_includes_header(void)
{
    uint8_t raw[ST_HEADER_SIZE] = {0};
    st_frame_header header;
    raw[0] = (uint8_t)(ST_MAGIC >> 24U);
    raw[1] = (uint8_t)(ST_MAGIC >> 16U);
    raw[2] = (uint8_t)(ST_MAGIC >> 8U);
    raw[3] = (uint8_t)ST_MAGIC;
    raw[4] = ST_VERSION;
    raw[5] = ST_SERIALIZER_COMPACT_BINARY;
    raw[6] = (uint8_t)ST_CMD_HEARTBEAT_REQUEST;
    raw[7] = (uint8_t)(ST_MAX_BODY_SIZE >> 24U);
    raw[8] = (uint8_t)(ST_MAX_BODY_SIZE >> 16U);
    raw[9] = (uint8_t)(ST_MAX_BODY_SIZE >> 8U);
    raw[10] = (uint8_t)ST_MAX_BODY_SIZE;
    if (st_protocol_read_header(raw, &header) != 0 || header.length != ST_MAX_BODY_SIZE) {
        fprintf(stderr, "maximum Java-compatible frame should be accepted\n");
        return 1;
    }

    uint32_t oversized = ST_MAX_BODY_SIZE + 1U;
    raw[7] = (uint8_t)(oversized >> 24U);
    raw[8] = (uint8_t)(oversized >> 16U);
    raw[9] = (uint8_t)(oversized >> 8U);
    raw[10] = (uint8_t)oversized;
    if (st_protocol_read_header(raw, &header) == 0) {
        fprintf(stderr, "frame larger than Java's complete-frame limit should be rejected\n");
        return 1;
    }
    return 0;
}

static int test_nat_decode(void)
{
    const struct {
        const char *fixture;
        int type;
    } cases[] = {
        {"nat_register.bin", ST_NAT_REGISTER},
        {"nat_unregister.bin", ST_NAT_UNREGISTER},
        {"nat_data_small.bin", ST_NAT_DATA},
        {"nat_data_large_deflated.bin", ST_NAT_DATA}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint8_t *bytes = NULL;
        st_frame_header header;
        if (st_test_decode_fixture_header(cases[i].fixture, &bytes, &header) != 0) {
            return 1;
        }
        st_nat_message message;
        int ok = header.command == ST_CMD_NAT_MESSAGE
            && st_protocol_decode_nat_message(bytes + ST_HEADER_SIZE, header.length, &message) == 0
            && message.type == cases[i].type;
        if (!ok) {
            fprintf(stderr, "%s NAT decode mismatch\n", cases[i].fixture);
            free(bytes);
            return 1;
        }
        if (cases[i].type == ST_NAT_REGISTER) {
            char *client_name = st_json_get_string(message.meta_json, "clientName");
            char *address = st_json_get_string(message.meta_json, "tunnelAddress");
            int port = 0;
            int tunnel_port = 0;
            ok = client_name != NULL && strcmp(client_name, "Demo client") == 0
                && address != NULL && strcmp(address, "127.0.0.1") == 0
                && st_json_get_int(message.meta_json, "port", &port) == 0 && port == 18080
                && st_json_get_int(message.meta_json, "tunnelPort", &tunnel_port) == 0 && tunnel_port == 80;
            free(client_name);
            free(address);
        } else if (strcmp(cases[i].fixture, "nat_data_small.bin") == 0) {
            ok = message.data_len == 5U && memcmp(message.data, "hello", 5) == 0;
        } else if (strcmp(cases[i].fixture, "nat_data_large_deflated.bin") == 0) {
            ok = message.data_len == 256U && message.data[0] == 'A' && message.data[255] == 'A';
        }
        st_nat_message_free(&message);
        free(bytes);
        if (!ok) {
            fprintf(stderr, "%s NAT content mismatch\n", cases[i].fixture);
            return 1;
        }
    }
    return 0;
}

static int test_inflated_payload_limit_is_inclusive(void)
{
    uint8_t *data = (uint8_t *)malloc(ST_MAX_INFLATED_SIZE + 1U);
    if (data == NULL) {
        return 1;
    }
    memset(data, 'A', ST_MAX_INFLATED_SIZE + 1U);

    st_buffer exact = st_protocol_encode_nat_message(ST_NAT_DATA, "{}", data, ST_MAX_INFLATED_SIZE);
    st_frame_header header;
    st_nat_message decoded;
    int exact_ok = exact.data != NULL
        && st_protocol_read_header(exact.data, &header) == 0
        && st_protocol_decode_nat_message(exact.data + ST_HEADER_SIZE, header.length, &decoded) == 0
        && decoded.data_len == ST_MAX_INFLATED_SIZE;
    if (exact_ok) {
        st_nat_message_free(&decoded);
    }
    st_buffer_free(&exact);
    if (!exact_ok) {
        free(data);
        fprintf(stderr, "exactly 16 MiB inflated payload should be accepted\n");
        return 1;
    }

    st_buffer oversized = st_protocol_encode_nat_message(
        ST_NAT_DATA,
        "{}",
        data,
        ST_MAX_INFLATED_SIZE + 1U);
    int oversized_rejected = oversized.data != NULL
        && st_protocol_read_header(oversized.data, &header) == 0
        && st_protocol_decode_nat_message(
            oversized.data + ST_HEADER_SIZE,
            header.length,
            &decoded) != 0;
    st_buffer_free(&oversized);
    free(data);
    if (!oversized_rejected) {
        fprintf(stderr, "inflated payload larger than 16 MiB should be rejected\n");
        return 1;
    }
    return 0;
}

static int test_direct_http_decode(void)
{
    uint8_t *bytes = NULL;
    st_frame_header header;
    if (st_test_decode_fixture_header("direct_http_request.bin", &bytes, &header) != 0) {
        return 1;
    }
    st_direct_http_request request;
    int ok = header.command == ST_CMD_DIRECT_HTTP_REQUEST
        && st_protocol_decode_direct_http_request(bytes + ST_HEADER_SIZE, header.length, &request) == 0;
    if (!ok) {
        fprintf(stderr, "direct HTTP request decode failed\n");
        free(bytes);
        return 1;
    }
    ok = strcmp(request.request_id, "11111111-2222-3333-4444-555555555555") == 0
        && strcmp(request.request_method, "GET") == 0
        && strcmp(request.route, "api") == 0
        && strcmp(request.relative_path, "/v1/items") == 0
        && strcmp(request.raw_query, "limit=10&page=1") == 0
        && request.headers_len == 2U
        && strcmp(request.headers[0], "accept: application/json") == 0
        && strcmp(request.headers[1], "x-fixture: 1") == 0
        && request.body_len == 0U;
    if (!ok) {
        fprintf(stderr, "direct HTTP request content mismatch\n");
    }
    st_direct_http_request_free(&request);
    free(bytes);
    if (!ok) {
        return 1;
    }

    if (st_test_decode_fixture_header("direct_http_response.bin", &bytes, &header) != 0) {
        return 1;
    }
    st_direct_http_response response;
    ok = header.command == ST_CMD_DIRECT_HTTP_RESPONSE
        && st_protocol_decode_direct_http_response(bytes + ST_HEADER_SIZE, header.length, &response) == 0;
    if (!ok) {
        fprintf(stderr, "direct HTTP response decode failed\n");
        free(bytes);
        return 1;
    }
    ok = strcmp(response.request_id, "11111111-2222-3333-4444-555555555555") == 0
        && response.status_code == 200
        && response.headers_len == 1U
        && strcmp(response.headers[0], "content-type: application/json") == 0
        && response.body_len == strlen("{\"ok\":true}")
        && memcmp(response.body, "{\"ok\":true}", response.body_len) == 0
        && response.error == NULL;
    if (!ok) {
        fprintf(stderr, "direct HTTP response content mismatch\n");
    }
    st_direct_http_response_free(&response);
    free(bytes);
    return ok ? 0 : 1;
}

static int test_direct_http_encode_round_trip(void)
{
    char *headers[] = {"accept: application/json", "x-test: 1"};
    const uint8_t body[] = "{\"hello\":\"world\"}";
    st_direct_http_request request = {
        .request_id = "22222222-3333-4444-5555-666666666666",
        .request_method = "POST",
        .route = "api",
        .relative_path = "/v1/create",
        .raw_query = "debug=true",
        .headers = headers,
        .headers_len = 2,
        .body = (uint8_t *)body,
        .body_len = sizeof(body) - 1U
    };
    st_buffer packet = st_protocol_encode_direct_http_request(&request);
    if (packet.data == NULL) {
        fprintf(stderr, "direct HTTP request encode failed\n");
        return 1;
    }
    st_frame_header header;
    st_direct_http_request decoded;
    int ok = st_protocol_read_header(packet.data, &header) == 0
        && header.command == ST_CMD_DIRECT_HTTP_REQUEST
        && st_protocol_decode_direct_http_request(packet.data + ST_HEADER_SIZE, header.length, &decoded) == 0;
    if (!ok) {
        fprintf(stderr, "direct HTTP request round-trip decode failed\n");
        st_buffer_free(&packet);
        return 1;
    }
    ok = strcmp(decoded.request_id, request.request_id) == 0
        && strcmp(decoded.request_method, request.request_method) == 0
        && strcmp(decoded.route, request.route) == 0
        && strcmp(decoded.relative_path, request.relative_path) == 0
        && strcmp(decoded.raw_query, request.raw_query) == 0
        && decoded.headers_len == request.headers_len
        && strcmp(decoded.headers[0], request.headers[0]) == 0
        && strcmp(decoded.headers[1], request.headers[1]) == 0
        && decoded.body_len == request.body_len
        && memcmp(decoded.body, request.body, request.body_len) == 0;
    if (!ok) {
        fprintf(stderr, "direct HTTP request round-trip content mismatch\n");
    }
    st_direct_http_request_free(&decoded);
    st_buffer_free(&packet);
    return ok ? 0 : 1;
}

static int test_java_encode_fixtures(void)
{
    st_buffer login = st_protocol_encode_login_response("Demo client", 1, NULL);
    if (login.data == NULL || st_test_expect_fixture_bytes("login_response.bin", &login) != 0) {
        st_buffer_free(&login);
        return 1;
    }
    st_buffer_free(&login);

    st_buffer heartbeat = st_protocol_encode_empty_packet(ST_CMD_HEARTBEAT_RESPONSE);
    if (heartbeat.data == NULL || st_test_expect_fixture_bytes("heartbeat_response.bin", &heartbeat) != 0) {
        st_buffer_free(&heartbeat);
        return 1;
    }
    st_buffer_free(&heartbeat);

    st_buffer register_result = st_protocol_encode_nat_message(
        ST_NAT_REGISTER_RESULT,
        "{\"port\":18080,\"success\":true}",
        NULL,
        0);
    if (register_result.data == NULL
        || st_test_expect_fixture_bytes("nat_register_result.bin", &register_result) != 0) {
        st_buffer_free(&register_result);
        return 1;
    }
    st_buffer_free(&register_result);

    st_buffer connected = st_protocol_encode_nat_message(
        ST_NAT_CONNECTED,
        "{\"channelId\":\"00010203-aaaa-bbbb-cccc-ddddeeeeffff\",\"port\":18080}",
        NULL,
        0);
    if (connected.data == NULL || st_test_expect_fixture_bytes("nat_connected.bin", &connected) != 0) {
        st_buffer_free(&connected);
        return 1;
    }
    st_buffer_free(&connected);

    st_buffer disconnected = st_protocol_encode_nat_message(
        ST_NAT_DISCONNECTED,
        "{\"channelId\":\"00010203-aaaa-bbbb-cccc-ddddeeeeffff\"}",
        NULL,
        0);
    if (disconnected.data == NULL
        || st_test_expect_fixture_bytes("nat_disconnected.bin", &disconnected) != 0) {
        st_buffer_free(&disconnected);
        return 1;
    }
    st_buffer_free(&disconnected);

    st_buffer small_data = st_protocol_encode_nat_message(
        ST_NAT_DATA,
        "{\"channelId\":\"00010203-aaaa-bbbb-cccc-ddddeeeeffff\"}",
        (const uint8_t *)"hello",
        5);
    if (small_data.data == NULL || st_test_expect_fixture_bytes("nat_data_small.bin", &small_data) != 0) {
        st_buffer_free(&small_data);
        return 1;
    }
    st_buffer_free(&small_data);

    uint8_t repeated[256];
    memset(repeated, 'A', sizeof(repeated));
    st_buffer large_data = st_protocol_encode_nat_message(
        ST_NAT_DATA,
        "{\"channelId\":\"00010203-aaaa-bbbb-cccc-ddddeeeeffff\"}",
        repeated,
        sizeof(repeated));
    if (large_data.data == NULL
        || st_test_expect_fixture_bytes("nat_data_large_deflated.bin", &large_data) != 0) {
        st_buffer_free(&large_data);
        return 1;
    }
    st_buffer_free(&large_data);

    return 0;
}

int main(void)
{
    return test_login_request_decode() != 0
        || test_message_response_decode() != 0
        || test_empty_packets() != 0
        || test_frame_limit_includes_header() != 0
        || test_nat_decode() != 0
        || test_inflated_payload_limit_is_inclusive() != 0
        || test_direct_http_decode() != 0
        || test_direct_http_encode_round_trip() != 0
        || test_java_encode_fixtures() != 0;
}
