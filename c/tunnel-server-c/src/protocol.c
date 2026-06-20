#include "protocol.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

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

#define ST_RAW_PAYLOAD 0U
#define ST_DEFLATED_PAYLOAD 1U
#define ST_COMPRESSION_THRESHOLD 64U

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

static int reader_byte_array(compact_reader *reader, uint8_t **value, size_t *len)
{
    uint32_t marker;
    if (reader_varint(reader, &marker) != 0) {
        return -1;
    }
    if (marker == 0) {
        *value = NULL;
        *len = 0;
        return 0;
    }
    uint32_t bytes_len = marker - 1U;
    if (reader->len - reader->pos < bytes_len) {
        return -1;
    }
    uint8_t *out = (uint8_t *)malloc(bytes_len == 0 ? 1U : bytes_len);
    if (out == NULL) {
        return -1;
    }
    memcpy(out, reader->data + reader->pos, bytes_len);
    reader->pos += bytes_len;
    *value = out;
    *len = bytes_len;
    return 0;
}

static int reader_integer(compact_reader *reader, int *value)
{
    uint32_t raw;
    if (reader_varint(reader, &raw) != 0 || raw > (uint32_t)INT_MAX) {
        return -1;
    }
    *value = (int)raw;
    return 0;
}

static int reader_enum(compact_reader *reader, int *value)
{
    uint32_t marker;
    if (reader_varint(reader, &marker) != 0 || marker == 0) {
        return -1;
    }
    *value = (int)marker - 1;
    return 0;
}

static int reader_uuid_string(compact_reader *reader, char **value)
{
    uint8_t marker;
    if (reader_u8(reader, &marker) != 0) {
        return -1;
    }
    if (marker == 0) {
        *value = NULL;
        return 0;
    }
    if (marker == 2) {
        return reader_string(reader, value);
    }
    if (marker != 1 || reader->len - reader->pos < 16U) {
        return -1;
    }
    const uint8_t *b = reader->data + reader->pos;
    reader->pos += 16U;
    char *out = (char *)malloc(37U);
    if (out == NULL) {
        return -1;
    }
    snprintf(out, 37U,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
             b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
    *value = out;
    return 0;
}

static int reader_http_method(compact_reader *reader, char **value)
{
    static const char *methods[] = {"GET", "POST", "PUT", "DELETE"};
    uint8_t marker;
    if (reader_u8(reader, &marker) != 0) {
        return -1;
    }
    if (marker == 0) {
        *value = NULL;
        return 0;
    }
    if (marker >= 1U && marker <= 4U) {
        const char *method = methods[marker - 1U];
        char *out = (char *)malloc(strlen(method) + 1U);
        if (out == NULL) {
            return -1;
        }
        strcpy(out, method);
        *value = out;
        return 0;
    }
    if (marker == 5U) {
        return reader_string(reader, value);
    }
    return -1;
}

static int reader_string_list(compact_reader *reader, char ***values, size_t *len)
{
    uint32_t marker;
    if (reader_varint(reader, &marker) != 0) {
        return -1;
    }
    if (marker == 0) {
        *values = NULL;
        *len = 0;
        return 0;
    }
    size_t count = (size_t)marker - 1U;
    char **items = (char **)calloc(count == 0 ? 1U : count, sizeof(*items));
    if (items == NULL) {
        return -1;
    }
    for (size_t i = 0; i < count; ++i) {
        if (reader_string(reader, &items[i]) != 0) {
            for (size_t j = 0; j < i; ++j) {
                free(items[j]);
            }
            free(items);
            return -1;
        }
    }
    *values = items;
    *len = count;
    return 0;
}

static void free_string_list(char **values, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        free(values[i]);
    }
    free(values);
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

static st_buffer encode_raw_frame(uint8_t serializer, int8_t command, const uint8_t *body, size_t body_len)
{
    st_buffer buffer = {0};
    size_t frame_len = ST_HEADER_SIZE + body_len;
    if (body_len > UINT32_MAX) {
        return buffer;
    }
    buffer.data = (uint8_t *)malloc(frame_len);
    if (buffer.data == NULL) {
        return buffer;
    }
    buffer.len = frame_len;
    write_be32(buffer.data, ST_MAGIC);
    buffer.data[4] = ST_VERSION;
    buffer.data[5] = serializer;
    buffer.data[6] = (uint8_t)command;
    write_be32(buffer.data + 7, (uint32_t)body_len);
    if (body_len > 0) {
        memcpy(buffer.data + ST_HEADER_SIZE, body, body_len);
    }
    return buffer;
}

static int encode_compact_payload(const uint8_t *raw, size_t raw_len, uint8_t **out, size_t *out_len)
{
    if (raw_len >= ST_COMPRESSION_THRESHOLD) {
        z_stream stream;
        memset(&stream, 0, sizeof(stream));
        if (deflateInit2(&stream, Z_BEST_COMPRESSION, Z_DEFLATED, -MAX_WBITS, 8, Z_DEFAULT_STRATEGY) == Z_OK) {
            uLong bound = deflateBound(&stream, (uLong)raw_len);
            uint8_t *compressed = (uint8_t *)malloc((size_t)bound + 1U);
            if (compressed != NULL) {
                stream.next_in = (Bytef *)raw;
                stream.avail_in = (uInt)raw_len;
                stream.next_out = compressed + 1U;
                stream.avail_out = (uInt)bound;
                int status = deflate(&stream, Z_FINISH);
                if (status == Z_STREAM_END && stream.total_out < raw_len) {
                    compressed[0] = ST_DEFLATED_PAYLOAD;
                    *out = compressed;
                    *out_len = (size_t)stream.total_out + 1U;
                    deflateEnd(&stream);
                    return 0;
                }
                free(compressed);
            }
            deflateEnd(&stream);
        }
    }

    if (raw_len > SIZE_MAX - 1U) {
        return -1;
    }
    uint8_t *buffer = (uint8_t *)malloc(raw_len + 1U);
    if (buffer == NULL) {
        return -1;
    }
    buffer[0] = ST_RAW_PAYLOAD;
    if (raw_len > 0) {
        memcpy(buffer + 1U, raw, raw_len);
    }
    *out = buffer;
    *out_len = raw_len + 1U;
    return 0;
}

static st_buffer encode_compact_frame(int8_t command, compact_writer *payload)
{
    st_buffer buffer = {0};
    uint8_t *body = NULL;
    size_t body_len = 0;
    if (encode_compact_payload(payload->data, payload->len, &body, &body_len) != 0) {
        return buffer;
    }
    buffer = encode_raw_frame(ST_SERIALIZER_COMPACT_BINARY, command, body, body_len);
    free(body);
    return buffer;
}

static int decode_compact_payload(const uint8_t *payload, size_t payload_len, uint8_t **out, size_t *out_len)
{
    if (payload_len == 0) {
        return -1;
    }
    if (payload[0] == ST_RAW_PAYLOAD) {
        size_t len = payload_len - 1U;
        uint8_t *copy = (uint8_t *)malloc(len == 0 ? 1U : len);
        if (copy == NULL) {
            return -1;
        }
        if (len > 0) {
            memcpy(copy, payload + 1U, len);
        }
        *out = copy;
        *out_len = len;
        return 0;
    }
    if (payload[0] != ST_DEFLATED_PAYLOAD) {
        return -1;
    }

    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    stream.next_in = (Bytef *)(payload + 1U);
    stream.avail_in = (uInt)(payload_len - 1U);
    if (inflateInit2(&stream, -MAX_WBITS) != Z_OK) {
        return -1;
    }

    size_t cap = (payload_len - 1U) * 4U + 1024U;
    if (cap < 1024U) {
        cap = 1024U;
    }
    if (cap > ST_MAX_INFLATED_SIZE) {
        cap = ST_MAX_INFLATED_SIZE;
    }
    uint8_t *buffer = (uint8_t *)malloc(cap);
    if (buffer == NULL) {
        inflateEnd(&stream);
        return -1;
    }

    int status;
    do {
        if (stream.total_out == cap) {
            if (cap == ST_MAX_INFLATED_SIZE) {
                free(buffer);
                inflateEnd(&stream);
                return -1;
            }
            size_t next = cap * 2U;
            if (next > ST_MAX_INFLATED_SIZE) {
                next = ST_MAX_INFLATED_SIZE;
            }
            uint8_t *grown = (uint8_t *)realloc(buffer, next);
            if (grown == NULL) {
                free(buffer);
                inflateEnd(&stream);
                return -1;
            }
            buffer = grown;
            cap = next;
        }
        stream.next_out = buffer + stream.total_out;
        stream.avail_out = (uInt)(cap - stream.total_out);
        status = inflate(&stream, Z_NO_FLUSH);
    } while (status == Z_OK);

    if (status != Z_STREAM_END) {
        free(buffer);
        inflateEnd(&stream);
        return -1;
    }
    *out_len = stream.total_out;
    *out = buffer;
    inflateEnd(&stream);
    return 0;
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
    if (header->version != ST_VERSION || header->length > ST_MAX_FRAME_SIZE) {
        return -1;
    }
    return 0;
}

int st_protocol_decode_empty_packet(const uint8_t *body, size_t body_len)
{
    uint8_t *payload = NULL;
    size_t payload_len = 0;
    if (decode_compact_payload(body, body_len, &payload, &payload_len) != 0) {
        return -1;
    }
    free(payload);
    return payload_len == 0 ? 0 : -1;
}

int st_protocol_decode_login_request(const uint8_t *body, size_t body_len, st_login_request *request)
{
    memset(request, 0, sizeof(*request));
    if (body == NULL || body_len < 1U || body[0] != 0) {
        return -1;
    }
    compact_reader reader = {
        .data = body + 1U,
        .len = body_len - 1U,
        .pos = 0
    };
    if (reader_string(&reader, &request->client_name) != 0
        || reader_numeric_string(&reader, &request->timestamp) != 0
        || reader_string(&reader, &request->nonce) != 0
        || reader_byte_array(&reader, &request->check_sign, &request->check_sign_len) != 0) {
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
    uint8_t *payload = NULL;
    size_t payload_len = 0;
    if (decode_compact_payload(body, body_len, &payload, &payload_len) != 0) {
        return -1;
    }
    compact_reader reader = {
        .data = payload,
        .len = payload_len,
        .pos = 0
    };
    if (reader_string(&reader, &response->client_name) != 0
        || reader_string(&reader, &response->to_client_name) != 0
        || reader_enum(&reader, &response->message_type) != 0
        || reader_string(&reader, &response->message) != 0
        || reader.pos != reader.len) {
        free(payload);
        st_message_response_free(response);
        return -1;
    }
    free(payload);
    return 0;
}

int st_protocol_decode_direct_http_request(const uint8_t *body, size_t body_len, st_direct_http_request *request)
{
    memset(request, 0, sizeof(*request));
    uint8_t *payload = NULL;
    size_t payload_len = 0;
    if (decode_compact_payload(body, body_len, &payload, &payload_len) != 0) {
        return -1;
    }
    compact_reader reader = {
        .data = payload,
        .len = payload_len,
        .pos = 0
    };
    if (reader_uuid_string(&reader, &request->request_id) != 0
        || reader_http_method(&reader, &request->request_method) != 0
        || reader_string(&reader, &request->route) != 0
        || reader_string(&reader, &request->relative_path) != 0
        || reader_string(&reader, &request->raw_query) != 0
        || reader_string_list(&reader, &request->headers, &request->headers_len) != 0
        || reader_byte_array(&reader, &request->body, &request->body_len) != 0
        || reader.pos != reader.len) {
        free(payload);
        st_direct_http_request_free(request);
        return -1;
    }
    free(payload);
    return 0;
}

int st_protocol_decode_direct_http_response(const uint8_t *body, size_t body_len, st_direct_http_response *response)
{
    memset(response, 0, sizeof(*response));
    uint8_t *payload = NULL;
    size_t payload_len = 0;
    if (decode_compact_payload(body, body_len, &payload, &payload_len) != 0) {
        return -1;
    }
    compact_reader reader = {
        .data = payload,
        .len = payload_len,
        .pos = 0
    };
    if (reader_uuid_string(&reader, &response->request_id) != 0
        || reader_integer(&reader, &response->status_code) != 0
        || reader_string_list(&reader, &response->headers, &response->headers_len) != 0
        || reader_byte_array(&reader, &response->body, &response->body_len) != 0
        || reader_string(&reader, &response->error) != 0
        || reader.pos != reader.len) {
        free(payload);
        st_direct_http_response_free(response);
        return -1;
    }
    free(payload);
    return 0;
}

int st_protocol_decode_nat_message(const uint8_t *body, size_t body_len, st_nat_message *message)
{
    memset(message, 0, sizeof(*message));
    if (body == NULL || body_len < 8U) {
        return -1;
    }
    message->type = (int)read_be32(body);
    uint32_t meta_len = read_be32(body + 4U);
    if (body_len - 8U < meta_len) {
        return -1;
    }
    message->meta_json = (char *)malloc((size_t)meta_len + 1U);
    if (message->meta_json == NULL) {
        return -1;
    }
    memcpy(message->meta_json, body + 8U, meta_len);
    message->meta_json[meta_len] = '\0';

    size_t data_offset = 8U + (size_t)meta_len;
    if (body_len > data_offset) {
        if (decode_compact_payload(body + data_offset, body_len - data_offset,
                                   &message->data, &message->data_len) != 0) {
            st_nat_message_free(message);
            return -1;
        }
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
        || writer_varint(&payload, 4U) != 0
        || writer_string(&payload, nat_control_json) != 0) {
        free(payload.data);
        return buffer;
    }
    buffer = encode_compact_frame(ST_CMD_MESSAGE_RESPONSE, &payload);
    free(payload.data);
    return buffer;
}

st_buffer st_protocol_encode_nat_message(int type, const char *meta_json, const uint8_t *data, size_t data_len)
{
    st_buffer buffer = {0};
    if (meta_json == NULL) {
        meta_json = "{}";
    }
    size_t meta_len = strlen(meta_json);
    uint8_t *payload = NULL;
    size_t payload_len = 0;
    if (data != NULL && data_len > 0
        && encode_compact_payload(data, data_len, &payload, &payload_len) != 0) {
        return buffer;
    }
    if (meta_len > UINT32_MAX || payload_len > UINT32_MAX || meta_len > SIZE_MAX - payload_len - 8U) {
        free(payload);
        return buffer;
    }
    size_t body_len = 8U + meta_len + payload_len;
    uint8_t *body = (uint8_t *)malloc(body_len == 0 ? 1U : body_len);
    if (body == NULL) {
        free(payload);
        return buffer;
    }
    write_be32(body, (uint32_t)type);
    write_be32(body + 4U, (uint32_t)meta_len);
    memcpy(body + 8U, meta_json, meta_len);
    if (payload_len > 0) {
        memcpy(body + 8U + meta_len, payload, payload_len);
    }
    buffer = encode_raw_frame(ST_SERIALIZER_FASTJSON, ST_CMD_NAT_MESSAGE, body, body_len);
    free(payload);
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
    free(request->timestamp);
    free(request->nonce);
    free(request->check_sign);
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

void st_direct_http_request_free(st_direct_http_request *request)
{
    if (request == NULL) {
        return;
    }
    free(request->request_id);
    free(request->request_method);
    free(request->route);
    free(request->relative_path);
    free(request->raw_query);
    free_string_list(request->headers, request->headers_len);
    free(request->body);
    memset(request, 0, sizeof(*request));
}

void st_direct_http_response_free(st_direct_http_response *response)
{
    if (response == NULL) {
        return;
    }
    free(response->request_id);
    free_string_list(response->headers, response->headers_len);
    free(response->body);
    free(response->error);
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
