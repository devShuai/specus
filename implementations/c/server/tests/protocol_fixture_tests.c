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
    st_login_request request = {0};
    int ok = header.command == ST_CMD_LOGIN_REQUEST
        && st_protocol_decode_login_request(bytes + ST_HEADER_SIZE, header.length, &request) == 0;
    if (ok) {
        ok = strcmp(request.client_name, "Demo client") == 0
            && request.client_session_id == INT64_C(1700000000000)
            && strcmp(request.access_token, "cs_fixture_access_token") == 0
            && strcmp(request.connection_role, ST_CONNECTION_ROLE_CONTROL) == 0;
    }
    if (!ok) {
        fprintf(stderr, "login request fixture mismatch\n");
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
        {"nat_data_large.bin", ST_NAT_DATA},
        {"http_stream_request_open.bin", ST_NAT_OPEN},
        {"http_stream_request_data.bin", ST_NAT_DATA},
        {"http_stream_request_fin.bin", ST_NAT_FIN},
        {"http_stream_response_open.bin", ST_NAT_OPEN},
        {"http_stream_response_data.bin", ST_NAT_DATA},
        {"http_stream_response_fin.bin", ST_NAT_FIN}
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
            char *address = st_json_get_string(message.meta_json, "specusAddress");
            int port = 0;
            int specus_port = 0;
            ok = client_name != NULL && strcmp(client_name, "Demo client") == 0
                && address != NULL && strcmp(address, "127.0.0.1") == 0
                && st_json_get_int(message.meta_json, "port", &port) == 0 && port == 18080
                && st_json_get_int(message.meta_json, "specusPort", &specus_port) == 0 && specus_port == 80;
            free(client_name);
            free(address);
        } else if (strcmp(cases[i].fixture, "nat_data_small.bin") == 0) {
            ok = message.data_len == 5U && memcmp(message.data, "hello", 5) == 0;
        } else if (strcmp(cases[i].fixture, "nat_data_large.bin") == 0) {
            ok = message.data_len == 256U && message.data[0] == 'A' && message.data[255] == 'A';
        } else if (strcmp(cases[i].fixture, "http_stream_response_open.bin") == 0) {
            char *source = st_json_get_string(message.meta_json, "source");
            char *phase = st_json_get_string(message.meta_json, "phase");
            char **trailer_names = NULL;
            size_t trailer_names_len = 0;
            int status = 0;
            ok = message.stream_id == 101U
                && source != NULL && strcmp(source, "http") == 0
                && phase != NULL && strcmp(phase, "response") == 0
                && st_json_get_int(message.meta_json, "statusCode", &status) == 0 && status == 200
                && st_json_get_string_array(message.meta_json, "trailerNames",
                                            &trailer_names, &trailer_names_len) == 0
                && trailer_names_len == 1U && strcmp(trailer_names[0], "Digest") == 0;
            free(source);
            free(phase);
            st_json_free_string_array(trailer_names, trailer_names_len);
        } else if (strcmp(cases[i].fixture, "http_stream_response_fin.bin") == 0) {
            char **trailers = NULL;
            size_t trailers_len = 0;
            ok = message.stream_id == 101U
                && st_json_get_string_array(message.meta_json, "trailers",
                                            &trailers, &trailers_len) == 0
                && trailers_len == 1U
                && strcmp(trailers[0], "Digest:sha-256=fixture") == 0;
            st_json_free_string_array(trailers, trailers_len);
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

static int test_malformed_frames_are_rejected(void)
{
    const char *fixtures[] = {
        "invalid_bad_magic.bin",
        "invalid_version_v1.bin",
        "invalid_serializer.bin",
        "invalid_unknown_command.bin",
        "invalid_truncated_header.bin",
        "invalid_truncated_body.bin",
        "invalid_trailing_body.bin",
        "invalid_heartbeat_body.bin",
        "invalid_oversized_length.bin"
    };
    for (size_t index = 0; index < sizeof(fixtures) / sizeof(fixtures[0]); ++index) {
        uint8_t *bytes = NULL;
        size_t length = 0;
        if (st_test_read_fixture(fixtures[index], &bytes, &length) != 0) {
            return 1;
        }
        st_frame_header header;
        int rejected = length < ST_HEADER_SIZE || st_protocol_read_header(bytes, &header) != 0;
        if (!rejected) {
            rejected = header.length != length - ST_HEADER_SIZE;
        }
        if (!rejected && header.command == ST_CMD_HEARTBEAT_REQUEST) {
            rejected = st_protocol_decode_empty_packet(bytes + ST_HEADER_SIZE, header.length) != 0;
        }
        free(bytes);
        if (!rejected) {
            fprintf(stderr, "malformed fixture %s was accepted\n", fixtures[index]);
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
        0,
        0,
        0,
        "{\"port\":18080,\"success\":true}",
        NULL,
        0);
    if (register_result.data == NULL
        || st_test_expect_fixture_bytes("nat_register_result.bin", &register_result) != 0) {
        st_buffer_free(&register_result);
        return 1;
    }
    st_buffer_free(&register_result);

    st_buffer open = st_protocol_encode_nat_message(
        ST_NAT_OPEN,
        0,
        1,
        0,
        "{\"channelId\":\"00010203-aaaa-bbbb-cccc-ddddeeeeffff\",\"port\":18080}",
        NULL,
        0);
    if (open.data == NULL || st_test_expect_fixture_bytes("nat_open.bin", &open) != 0) {
        st_buffer_free(&open);
        return 1;
    }
    st_buffer_free(&open);

    st_buffer fin = st_protocol_encode_nat_message(
        ST_NAT_FIN,
        0,
        1,
        0,
        NULL,
        NULL,
        0);
    if (fin.data == NULL || st_test_expect_fixture_bytes("nat_fin.bin", &fin) != 0) {
        st_buffer_free(&fin);
        return 1;
    }
    st_buffer_free(&fin);

    st_buffer rst = st_protocol_encode_nat_message(
        ST_NAT_RST,
        0,
        1,
        7,
        "{\"reason\":\"upstream reset\"}",
        NULL,
        0);
    if (rst.data == NULL || st_test_expect_fixture_bytes("nat_rst.bin", &rst) != 0) {
        st_buffer_free(&rst);
        return 1;
    }
    st_buffer_free(&rst);

    st_buffer window = st_protocol_encode_nat_message(
        ST_NAT_WINDOW_UPDATE,
        0,
        1,
        65536,
        NULL,
        NULL,
        0);
    if (window.data == NULL
        || st_test_expect_fixture_bytes("nat_window_update.bin", &window) != 0) {
        st_buffer_free(&window);
        return 1;
    }
    st_buffer_free(&window);

    st_buffer small_data = st_protocol_encode_nat_message(
        ST_NAT_DATA,
        0,
        1,
        0,
        NULL,
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
        0,
        1,
        0,
        NULL,
        repeated,
        sizeof(repeated));
    if (large_data.data == NULL
        || st_test_expect_fixture_bytes("nat_data_large.bin", &large_data) != 0) {
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
        || test_malformed_frames_are_rejected() != 0
        || test_java_encode_fixtures() != 0;
}
