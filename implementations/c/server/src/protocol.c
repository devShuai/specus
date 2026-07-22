#include "protocol.h"
#include "json.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const uint8_t *data;
    size_t len;
    size_t pos;
} compact_reader;

typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
} compact_writer;

#define ST_NAT_HEADER_SIZE 16U

static uint16_t read_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t read_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24)
        | ((uint32_t)p[1] << 16)
        | ((uint32_t)p[2] << 8)
        | (uint32_t)p[3];
}

static void write_be32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8);
    p[3] = (uint8_t)value;
}

static int reader_u8(compact_reader *reader, uint8_t *value)
{
    if (reader->pos >= reader->len) {
        return -1;
    }
    *value = reader->data[reader->pos++];
    return 0;
}

static int reader_varint(compact_reader *reader, uint32_t *value)
{
    uint32_t result = 0;
    for (int shift = 0; shift < 32; shift += 7) {
        uint8_t b;
        if (reader_u8(reader, &b) != 0) {
            return -1;
        }
        result |= (uint32_t)(b & 0x7fU) << shift;
        if ((b & 0x80U) == 0) {
            *value = result;
            return 0;
        }
    }
    return -1;
}

static int reader_varlong(compact_reader *reader, uint64_t *value)
{
    uint64_t result = 0;
    for (int shift = 0; shift < 64; shift += 7) {
        uint8_t b;
        if (reader_u8(reader, &b) != 0) {
            return -1;
        }
        result |= (uint64_t)(b & 0x7fU) << shift;
        if ((b & 0x80U) == 0) {
            *value = result;
            return 0;
        }
    }
    return -1;
}

static int reader_string(compact_reader *reader, char **value)
{
    uint32_t marker;
    if (reader_varint(reader, &marker) != 0) {
        return -1;
    }
    if (marker == 0) {
        *value = NULL;
        return 0;
    }
    uint32_t len = marker - 1U;
    if (reader->len - reader->pos < len) {
        return -1;
    }
    char *out = (char *)malloc((size_t)len + 1U);
    if (out == NULL) {
        return -1;
    }
    memcpy(out, reader->data + reader->pos, len);
    out[len] = '\0';
    reader->pos += len;
    *value = out;
    return 0;
}

static int reader_enum(compact_reader *reader, int *value)
{
    uint32_t marker;
    if (reader_varint(reader, &marker) != 0
        || marker < ST_MESSAGE_TYPE_SERVER_TO_CLIENT
        || marker > ST_MESSAGE_TYPE_PEER_CONTROL) {
        return -1;
    }
    *value = (int)marker;
    return 0;
}

static int64_t zigzag_decode(uint64_t value)
{
    return (int64_t)((value >> 1U) ^ (uint64_t)(-(int64_t)(value & 1U)));
}

static int reader_numeric_string(compact_reader *reader, char **value)
{
    uint8_t marker;
    if (reader_u8(reader, &marker) != 0) {
        return -1;
    }
    if (marker == 0) {
        *value = NULL;
        return 0;
    }
    if (marker == 1) {
        uint64_t raw;
        if (reader_varlong(reader, &raw) != 0) {
            return -1;
        }
        char tmp[32];
        int written = snprintf(tmp, sizeof(tmp), "%lld", (long long)zigzag_decode(raw));
        if (written < 0 || (size_t)written >= sizeof(tmp)) {
            return -1;
        }
        char *out = (char *)malloc((size_t)written + 1U);
        if (out == NULL) {
            return -1;
        }
        memcpy(out, tmp, (size_t)written + 1U);
        *value = out;
        return 0;
    }
    if (marker == 2) {
        return reader_string(reader, value);
    }
    return -1;
}

static void write_be16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

static int reader_nullable_long(compact_reader *reader, int64_t *value)
{
    uint8_t marker;
    if (reader_u8(reader, &marker) != 0) {
        return -1;
    }
    if (marker == 0) {
        *value = 0;
        return 0;
    }
    if (marker != 1) {
        return -1;
    }
    uint64_t raw;
    if (reader_varlong(reader, &raw) != 0) {
        return -1;
    }
    *value = zigzag_decode(raw);
    return 0;
}

static int writer_reserve(compact_writer *writer, size_t more)
{
    if (writer->len + more <= writer->cap) {
        return 0;
    }
    size_t next = writer->cap == 0 ? 64U : writer->cap;
    while (next < writer->len + more) {
        if (next > SIZE_MAX / 2U) {
            return -1;
        }
        next *= 2U;
    }
    uint8_t *grown = (uint8_t *)realloc(writer->data, next);
    if (grown == NULL) {
        return -1;
    }
    writer->data = grown;
    writer->cap = next;
    return 0;
}

static int writer_u8(compact_writer *writer, uint8_t value)
{
    if (writer_reserve(writer, 1) != 0) {
        return -1;
    }
    writer->data[writer->len++] = value;
    return 0;
}

static int writer_bytes(compact_writer *writer, const uint8_t *data, size_t len)
{
    if (writer_reserve(writer, len) != 0) {
        return -1;
    }
    memcpy(writer->data + writer->len, data, len);
    writer->len += len;
    return 0;
}

static int writer_varint(compact_writer *writer, uint32_t value)
{
    while ((value & ~0x7fU) != 0) {
        if (writer_u8(writer, (uint8_t)((value & 0x7fU) | 0x80U)) != 0) {
            return -1;
        }
        value >>= 7;
    }
    return writer_u8(writer, (uint8_t)value);
}

static int writer_string(compact_writer *writer, const char *value)
{
    if (value == NULL) {
        return writer_varint(writer, 0);
    }
    size_t len = strlen(value);
    if (len >= UINT32_MAX) {
        return -1;
    }
    if (writer_varint(writer, (uint32_t)len + 1U) != 0) {
        return -1;
    }
    return writer_bytes(writer, (const uint8_t *)value, len);
}

static int known_command(int8_t command)
{
    switch (command) {
        case ST_CMD_LOGIN_REQUEST:
        case ST_CMD_LOGIN_RESPONSE:
        case ST_CMD_MESSAGE_REQUEST:
        case ST_CMD_MESSAGE_RESPONSE:
        case ST_CMD_LOGOUT_REQUEST:
        case ST_CMD_LOGOUT_RESPONSE:
        case ST_CMD_HEARTBEAT_REQUEST:
        case ST_CMD_HEARTBEAT_RESPONSE:
        case ST_CMD_NAT_MESSAGE:
            return 1;
        default:
            return 0;
    }
}

static size_t command_body_limit(int8_t command)
{
    if (command == ST_CMD_LOGIN_REQUEST || command == ST_CMD_LOGIN_RESPONSE) {
        return ST_PRE_AUTH_MAX_FRAME_SIZE - ST_HEADER_SIZE;
    }
    if (command == ST_CMD_MESSAGE_REQUEST || command == ST_CMD_MESSAGE_RESPONSE) {
        return ST_MAX_MESSAGE_BODY_SIZE;
    }
    return ST_MAX_BODY_SIZE;
}

static st_buffer encode_raw_frame(int8_t command, const uint8_t *body, size_t body_len)
{
    st_buffer buffer = {0};
    if (!known_command(command) || body_len > command_body_limit(command)) {
        return buffer;
    }
    size_t frame_len = ST_HEADER_SIZE + body_len;
    buffer.data = (uint8_t *)malloc(frame_len);
    if (buffer.data == NULL) {
        return buffer;
    }
    buffer.len = frame_len;
    write_be32(buffer.data, ST_MAGIC);
    buffer.data[4] = ST_VERSION;
    buffer.data[5] = ST_SERIALIZER_COMPACT_BINARY;
    buffer.data[6] = (uint8_t)command;
    write_be32(buffer.data + 7, (uint32_t)body_len);
    if (body_len > 0) {
        memcpy(buffer.data + ST_HEADER_SIZE, body, body_len);
    }
    return buffer;
}

static st_buffer encode_compact_frame(int8_t command, compact_writer *payload)
{
    return encode_raw_frame(command, payload->data, payload->len);
}

int st_protocol_read_header(const uint8_t raw[ST_HEADER_SIZE], st_frame_header *header)
{
    uint32_t magic = read_be32(raw);
    if (magic != ST_MAGIC) {
        return -1;
    }
    header->version = raw[4];
    header->serializer = raw[5];
    header->command = (int8_t)raw[6];
    header->length = read_be32(raw + 7);
    if (header->version != ST_VERSION
        || header->serializer != ST_SERIALIZER_COMPACT_BINARY
        || !known_command(header->command)
        || header->length > command_body_limit(header->command)) {
        return -1;
    }
    return 0;
}

int st_protocol_decode_empty_packet(const uint8_t *body, size_t body_len)
{
    (void)body;
    return body_len == 0 ? 0 : -1;
}

int st_protocol_decode_login_request(const uint8_t *body, size_t body_len, st_login_request *request)
{
    memset(request, 0, sizeof(*request));
    compact_reader reader = {
        .data = body,
        .len = body_len,
        .pos = 0
    };
    if (reader_string(&reader, &request->client_name) != 0
        || reader_nullable_long(&reader, &request->client_session_id) != 0
        || reader_string(&reader, &request->access_token) != 0
        || reader_string(&reader, &request->connection_role) != 0
        || (strcmp(request->connection_role, ST_CONNECTION_ROLE_CONTROL) != 0
            && strcmp(request->connection_role, ST_CONNECTION_ROLE_DATA) != 0)) {
        st_login_request_free(request);
        return -1;
    }
    if (reader.pos != reader.len) {
        st_login_request_free(request);
        return -1;
    }
    return 0;
}

int st_protocol_decode_message_response(const uint8_t *body, size_t body_len, st_message_response *response)
{
    memset(response, 0, sizeof(*response));
    compact_reader reader = {
        .data = body,
        .len = body_len,
        .pos = 0
    };
    if (reader_string(&reader, &response->client_name) != 0
        || reader_string(&reader, &response->to_client_name) != 0
        || reader_enum(&reader, &response->message_type) != 0
        || reader_string(&reader, &response->message) != 0
        || reader.pos != reader.len) {
        st_message_response_free(response);
        return -1;
    }
    return 0;
}

static int validate_nat_semantics(int type, uint8_t flags, uint32_t stream_id, uint32_t value,
                                  size_t meta_len, size_t data_len)
{
    int stream_frame = type == ST_NAT_OPEN || type == ST_NAT_FIN || type == ST_NAT_DATA
        || type == ST_NAT_RST || type == ST_NAT_WINDOW_UPDATE;
    if (stream_frame == (stream_id == 0U)) {
        return -1;
    }
    if (type != ST_NAT_DATA && flags != 0U) {
        return -1;
    }
    if (type == ST_NAT_DATA && (meta_len != 0U || value != 0U)) {
        return -1;
    }
    if (type == ST_NAT_FIN && (data_len != 0U || flags != 0U)) {
        return -1;
    }
    if (type == ST_NAT_WINDOW_UPDATE
        && (meta_len != 0U || data_len != 0U || flags != 0U)) {
        return -1;
    }
    if (type == ST_NAT_WINDOW_UPDATE && value == 0U) {
        return -1;
    }
    if (type == ST_NAT_FIN && value != 0U) {
        return -1;
    }
    if (type == ST_NAT_RST && data_len != 0U) {
        return -1;
    }
    if (!stream_frame && (value != 0U || flags != 0U || data_len != 0U)) {
        return -1;
    }
    return 0;
}

int st_protocol_decode_nat_message(const uint8_t *body, size_t body_len, st_nat_message *message)
{
    memset(message, 0, sizeof(*message));
    if (body == NULL || body_len < ST_NAT_HEADER_SIZE) {
        return -1;
    }
    message->type = (int)body[0];
    if (message->type < ST_NAT_REGISTER || message->type > ST_NAT_WINDOW_UPDATE) {
        return -1;
    }
    message->flags = body[1];
    if ((message->flags & (uint8_t)~ST_NAT_FLAG_END_STREAM) != 0U) {
        return -1;
    }
    size_t meta_len = read_be16(body + 2U);
    message->stream_id = read_be32(body + 4U);
    message->value = read_be32(body + 8U);
    size_t data_len = read_be32(body + 12U);
    if (meta_len > ST_MAX_NAT_METADATA_SIZE
        || data_len > ST_MAX_BODY_SIZE
        || meta_len > SIZE_MAX - ST_NAT_HEADER_SIZE - data_len
        || body_len != ST_NAT_HEADER_SIZE + meta_len + data_len
        || validate_nat_semantics(message->type, message->flags, message->stream_id,
                                  message->value, meta_len, data_len) != 0) {
        return -1;
    }
    if (meta_len == 0U) {
        message->meta_json = (char *)malloc(3U);
        if (message->meta_json != NULL) {
            memcpy(message->meta_json, "{}", 3U);
        }
    } else {
        message->meta_json = (char *)malloc(meta_len + 1U);
        if (message->meta_json != NULL) {
            memcpy(message->meta_json, body + ST_NAT_HEADER_SIZE, meta_len);
            message->meta_json[meta_len] = '\0';
        }
    }
    if (message->meta_json == NULL) {
        return -1;
    }
    if (data_len > 0U) {
        message->data = (uint8_t *)malloc(data_len);
        if (message->data == NULL) {
            st_nat_message_free(message);
            return -1;
        }
        memcpy(message->data, body + ST_NAT_HEADER_SIZE + meta_len, data_len);
        message->data_len = data_len;
    }
    return 0;
}

st_buffer st_protocol_encode_login_response(const char *client_name, int success, const char *reason)
{
    compact_writer payload = {0};
    st_buffer buffer = {0};
    if (writer_string(&payload, client_name) != 0
        || writer_u8(&payload, success ? 1U : 0U) != 0
        || writer_string(&payload, reason) != 0) {
        free(payload.data);
        return buffer;
    }
    buffer = encode_compact_frame(ST_CMD_LOGIN_RESPONSE, &payload);
    free(payload.data);
    return buffer;
}

st_buffer st_protocol_encode_nat_control(const char *client_name, const char *nat_control_json)
{
    compact_writer payload = {0};
    st_buffer buffer = {0};
    if (writer_string(&payload, client_name) != 0
        || writer_string(&payload, NULL) != 0
        || writer_varint(&payload, ST_MESSAGE_TYPE_NAT_CONTROL) != 0
        || writer_string(&payload, nat_control_json) != 0) {
        free(payload.data);
        return buffer;
    }
    buffer = encode_compact_frame(ST_CMD_MESSAGE_RESPONSE, &payload);
    free(payload.data);
    return buffer;
}

st_buffer st_protocol_encode_nat_message(int type, uint8_t flags, uint32_t stream_id, uint32_t value,
                                         const char *meta_json, const uint8_t *data, size_t data_len)
{
    st_buffer buffer = {0};
    if (type < ST_NAT_REGISTER || type > ST_NAT_WINDOW_UPDATE) {
        return buffer;
    }
    size_t meta_len = meta_json == NULL || strcmp(meta_json, "{}") == 0 ? 0U : strlen(meta_json);
    if (meta_len > ST_MAX_NAT_METADATA_SIZE) {
        return buffer;
    }
    if ((data == NULL && data_len > 0U)
        || data_len > UINT32_MAX
        || meta_len > ST_MAX_NAT_METADATA_SIZE
        || meta_len > SIZE_MAX - data_len - ST_NAT_HEADER_SIZE
        || validate_nat_semantics(type, flags, stream_id, value, meta_len, data_len) != 0) {
        return buffer;
    }
    size_t body_len = ST_NAT_HEADER_SIZE + meta_len + data_len;
    uint8_t *body = (uint8_t *)malloc(body_len);
    if (body == NULL) {
        return buffer;
    }
    body[0] = (uint8_t)type;
    body[1] = flags;
    write_be16(body + 2U, (uint16_t)meta_len);
    write_be32(body + 4U, stream_id);
    write_be32(body + 8U, value);
    write_be32(body + 12U, (uint32_t)data_len);
    if (meta_len > 0U) {
        memcpy(body + ST_NAT_HEADER_SIZE, meta_json, meta_len);
    }
    if (data_len > 0U) {
        memcpy(body + ST_NAT_HEADER_SIZE + meta_len, data, data_len);
    }
    buffer = encode_raw_frame(ST_CMD_NAT_MESSAGE, body, body_len);
    free(body);
    return buffer;
}

st_buffer st_protocol_encode_empty_packet(int8_t command)
{
    compact_writer payload = {0};
    return encode_compact_frame(command, &payload);
}

void st_login_request_free(st_login_request *request)
{
    if (request == NULL) {
        return;
    }
    free(request->client_name);
    free(request->access_token);
    free(request->connection_role);
    memset(request, 0, sizeof(*request));
}

void st_message_response_free(st_message_response *response)
{
    if (response == NULL) {
        return;
    }
    free(response->client_name);
    free(response->to_client_name);
    free(response->message);
    memset(response, 0, sizeof(*response));
}

void st_nat_message_free(st_nat_message *message)
{
    if (message == NULL) {
        return;
    }
    free(message->meta_json);
    free(message->data);
    memset(message, 0, sizeof(*message));
}

void st_buffer_free(st_buffer *buffer)
{
    if (buffer == NULL) {
        return;
    }
    free(buffer->data);
    buffer->data = NULL;
    buffer->len = 0;
}
