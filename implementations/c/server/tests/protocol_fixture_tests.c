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
        && response.message_type == ST_MESSAGE_TYPE_NAT_CONTROL
        && strcmp(response.message, "{\"clientName\":\"Demo client\",\"remotePort\":7010}") == 0;
    st_buffer encoded = st_protocol_encode_message_response(
        "admin",
        "Demo client",
        ST_MESSAGE_TYPE_NAT_CONTROL,
        "{\"clientName\":\"Demo client\",\"remotePort\":7010}");
    if (encoded.data == NULL
        || encoded.len != ST_HEADER_SIZE + header.length
        || memcmp(encoded.data, bytes, encoded.len) != 0) {
        ok = 0;
    }
    if (!ok) {
        fprintf(stderr, "message response content mismatch\n");
    }
    st_message_response_free(&response);
    st_buffer_free(&encoded);
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
            && st_protocol_decode_empty_packet(bytes + ST_HEADER_SIZE, header.length) == 0
            && st_protocol_last_rejection() == ST_PROTOCOL_REJECTION_NONE;
        free(bytes);
        if (!ok) {
            fprintf(stderr, "%s empty packet mismatch\n", cases[i].fixture);
            return 1;
        }
    }
    return 0;
}

/* Java LogoutRequestHandler answers LogoutResponsePacket(success=true, reason=null): body 01 00. */
static int test_logout_response(void)
{
    uint8_t *bytes = NULL;
    st_frame_header header;
    if (st_test_decode_fixture_header("logout_response.bin", &bytes, &header) != 0) {
        return 1;
    }
    st_logout_response response;
    int ok = header.command == ST_CMD_LOGOUT_RESPONSE
        && st_protocol_decode_logout_response(bytes + ST_HEADER_SIZE, header.length, &response) == 0
        && response.success == 1
        && response.reason == NULL;
    if (ok) {
        st_logout_response_free(&response);
    }
    free(bytes);
    st_buffer encoded = st_protocol_encode_logout_response(1, NULL);
    if (!ok || encoded.data == NULL || st_test_expect_fixture_bytes("logout_response.bin", &encoded) != 0) {
        fprintf(stderr, "logout response fixture mismatch\n");
        st_buffer_free(&encoded);
        return 1;
    }
    st_buffer_free(&encoded);

    /* A reason round-trips; the empty body the server used to send is not a LOGOUT_RESPONSE. */
    encoded = st_protocol_encode_logout_response(0, "kicked");
    ok = encoded.data != NULL
        && st_protocol_read_header(encoded.data, &header) == 0
        && header.length == encoded.len - ST_HEADER_SIZE
        && st_protocol_decode_logout_response(encoded.data + ST_HEADER_SIZE, header.length, &response) == 0
        && response.success == 0
        && response.reason != NULL && strcmp(response.reason, "kicked") == 0;
    if (ok) {
        st_logout_response_free(&response);
    }
    st_buffer_free(&encoded);
    if (!ok
        || st_protocol_decode_logout_response((const uint8_t *)"", 0U, &response) != -1
        || st_protocol_last_rejection() != ST_PROTOCOL_REJECTION_MALFORMED_BODY) {
        fprintf(stderr, "logout response round trip or empty body mismatch\n");
        return 1;
    }
    return 0;
}

/* Every well-formed shared frame is a body Java's codec reads, whatever the server then does with it. */
static int test_valid_fixtures_validate(void)
{
    static const char *const fixtures[] = {
        "login_request.bin", "login_response.bin", "login_response_fail.bin",
        "logout_request.bin", "logout_response.bin", "heartbeat_request.bin", "heartbeat_response.bin",
        "message_request.bin", "message_response.bin",
        "nat_register.bin", "nat_register_result.bin", "nat_open.bin", "nat_fin.bin", "nat_rst.bin",
        "nat_window_update.bin", "nat_keepalive.bin", "nat_unregister.bin", "nat_data_small.bin",
        "nat_data_large.bin", "http_stream_request_open.bin", "http_stream_request_data.bin",
        "http_stream_request_fin.bin", "http_stream_response_open.bin", "http_stream_response_data.bin",
        "http_stream_response_fin.bin"
    };
    for (size_t i = 0; i < sizeof(fixtures) / sizeof(fixtures[0]); ++i) {
        uint8_t *bytes = NULL;
        st_frame_header header;
        if (st_test_decode_fixture_header(fixtures[i], &bytes, &header) != 0) {
            return 1;
        }
        int ok = st_protocol_validate_body(header.command, bytes + ST_HEADER_SIZE, header.length) == 0
            && st_protocol_last_rejection() == ST_PROTOCOL_REJECTION_NONE;
        free(bytes);
        if (!ok) {
            fprintf(stderr, "%s: a well-formed body was refused (reason %d)\n", fixtures[i],
                    (int)st_protocol_last_rejection());
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

/*
 * Each malformed shared frame is refused, with the reason Java's PacketCodec gives it where the C
 * codec decides it (header and body). A frame shorter or longer than its declared length is refused
 * by its length alone, reason NONE here: Java's PacketCodec.decode, handed those bytes as one frame,
 * says INVALID_LENGTH, but on a connection both servers read exactly the declared body (Java's
 * Spliter), so a short frame waits for more bytes and a trailing byte starts the next frame.
 */
static int test_malformed_frames_are_rejected(void)
{
    static const struct {
        const char *fixture;
        st_protocol_rejection reason;
    } fixtures[] = {
        {"invalid_bad_magic.bin", ST_PROTOCOL_REJECTION_INVALID_MAGIC},
        {"invalid_version_v1.bin", ST_PROTOCOL_REJECTION_UNSUPPORTED_VERSION},
        {"invalid_serializer.bin", ST_PROTOCOL_REJECTION_UNSUPPORTED_SERIALIZER},
        {"invalid_unknown_command.bin", ST_PROTOCOL_REJECTION_UNKNOWN_COMMAND},
        {"invalid_truncated_header.bin", ST_PROTOCOL_REJECTION_NONE},
        {"invalid_truncated_body.bin", ST_PROTOCOL_REJECTION_NONE},
        {"invalid_trailing_body.bin", ST_PROTOCOL_REJECTION_NONE},
        {"invalid_heartbeat_body.bin", ST_PROTOCOL_REJECTION_MALFORMED_BODY},
        {"invalid_oversized_length.bin", ST_PROTOCOL_REJECTION_INVALID_LENGTH}
    };
    for (size_t index = 0; index < sizeof(fixtures) / sizeof(fixtures[0]); ++index) {
        uint8_t *bytes = NULL;
        size_t length = 0;
        if (st_test_read_fixture(fixtures[index].fixture, &bytes, &length) != 0) {
            return 1;
        }
        st_frame_header header;
        st_protocol_rejection reason = ST_PROTOCOL_REJECTION_NONE;
        int rejected = length < ST_HEADER_SIZE;
        if (!rejected && st_protocol_read_header(bytes, &header) != 0) {
            rejected = 1;
            reason = st_protocol_last_rejection();
        }
        if (!rejected) {
            rejected = header.length != length - ST_HEADER_SIZE;
        }
        if (!rejected && st_protocol_validate_body(header.command, bytes + ST_HEADER_SIZE, header.length) != 0) {
            rejected = 1;
            reason = st_protocol_last_rejection();
        }
        /* The decoder the server loop uses for a heartbeat agrees with the validator. */
        int same_decoder = strcmp(fixtures[index].fixture, "invalid_heartbeat_body.bin") != 0
            || (st_protocol_decode_empty_packet(bytes + ST_HEADER_SIZE, header.length) == -1
                && st_protocol_last_rejection() == ST_PROTOCOL_REJECTION_MALFORMED_BODY);
        free(bytes);
        if (!rejected || reason != fixtures[index].reason || !same_decoder) {
            fprintf(stderr, "malformed fixture %s: rejected=%d reason=%d, want reason %d\n",
                    fixtures[index].fixture, rejected, (int)reason, (int)fixtures[index].reason);
            return 1;
        }
    }
    return 0;
}

/*
 * CompactBinary writes a null string as the marker 0, and Java's codec reads a login whose
 * connectionRole is null; its login handler then refuses it. The decoder refuses it too, rather
 * than comparing the missing role (which crashed the server on the first frame of a connection).
 */
static int test_login_null_role(void)
{
    static const uint8_t null_role[] = {2, 'c', 0, 2, 't', 0};
    st_login_request request;
    if (st_protocol_decode_login_request(null_role, sizeof(null_role), &request) != -1) {
        fprintf(stderr, "a login with a null connectionRole was accepted\n");
        st_login_request_free(&request);
        return 1;
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
        || test_logout_response() != 0
        || test_valid_fixtures_validate() != 0
        || test_frame_limit_includes_header() != 0
        || test_nat_decode() != 0
        || test_malformed_frames_are_rejected() != 0
        || test_login_null_role() != 0
        || test_java_encode_fixtures() != 0;
}
