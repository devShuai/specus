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
    int rc = header.command == ST_CMD_LOGIN_REQUEST
        && st_protocol_decode_login_request(bytes + ST_HEADER_SIZE, header.length, &request) == 0;
    if (!rc) {
        fprintf(stderr, "login request decode failed\n");
        free(bytes);
        return 1;
    }
    int ok = strcmp(request.client_name, "Demo client") == 0
        && strcmp(request.timestamp, "1700000000000") == 0
        && strcmp(request.nonce, "nonce-fixture") == 0
        && request.check_sign_len == 32U
        && request.check_sign[0] == 1U
        && request.check_sign[31] == 32U;
    if (!ok) {
        fprintf(stderr, "login request content mismatch\n");
    }
    st_login_request_free(&request);
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
        || test_nat_decode() != 0
        || test_java_encode_fixtures() != 0;
}
