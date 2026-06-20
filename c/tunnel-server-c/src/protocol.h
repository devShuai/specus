#ifndef SHUAI_TUNNEL_PROTOCOL_H
#define SHUAI_TUNNEL_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#define ST_MAGIC 0x14353565U
#define ST_VERSION 1U
#define ST_SERIALIZER_FASTJSON 1U
#define ST_SERIALIZER_COMPACT_BINARY 4U
#define ST_HEADER_SIZE 11U
#define ST_MAX_FRAME_SIZE (32U * 1024U * 1024U)
#define ST_MAX_INFLATED_SIZE (16U * 1024U * 1024U)

#define ST_CMD_LOGIN_REQUEST 1
#define ST_CMD_LOGIN_RESPONSE -1
#define ST_CMD_MESSAGE_RESPONSE -2
#define ST_CMD_LOGOUT_REQUEST 3
#define ST_CMD_LOGOUT_RESPONSE -3
#define ST_CMD_HEARTBEAT_REQUEST 4
#define ST_CMD_HEARTBEAT_RESPONSE -4
#define ST_CMD_NAT_MESSAGE 6
#define ST_CMD_DIRECT_HTTP_REQUEST 7
#define ST_CMD_DIRECT_HTTP_RESPONSE -7

#define ST_NAT_REGISTER 1
#define ST_NAT_REGISTER_RESULT 2
#define ST_NAT_CONNECTED 3
#define ST_NAT_DISCONNECTED 4
#define ST_NAT_DATA 5
#define ST_NAT_KEEPALIVE 6
#define ST_NAT_UNREGISTER 7
#define ST_NAT_HTTP_ROUTES_REPORT 8

typedef struct {
    uint8_t version;
    uint8_t serializer;
    int8_t command;
    uint32_t length;
} st_frame_header;

typedef struct {
    char *client_name;
    char *timestamp;
    char *nonce;
    uint8_t *check_sign;
    size_t check_sign_len;
} st_login_request;

typedef struct {
    char *client_name;
    char *to_client_name;
    int message_type;
    char *message;
} st_message_response;

typedef struct {
    char *request_id;
    char *request_method;
    char *route;
    char *relative_path;
    char *raw_query;
    char **headers;
    size_t headers_len;
    uint8_t *body;
    size_t body_len;
} st_direct_http_request;

typedef struct {
    char *request_id;
    int status_code;
    char **headers;
    size_t headers_len;
    uint8_t *body;
    size_t body_len;
    char *error;
} st_direct_http_response;

typedef struct {
    uint8_t *data;
    size_t len;
} st_buffer;

typedef struct {
    int type;
    char *meta_json;
    uint8_t *data;
    size_t data_len;
} st_nat_message;

int st_protocol_read_header(const uint8_t raw[ST_HEADER_SIZE], st_frame_header *header);
int st_protocol_decode_empty_packet(const uint8_t *body, size_t body_len);
int st_protocol_decode_login_request(const uint8_t *body, size_t body_len, st_login_request *request);
int st_protocol_decode_message_response(const uint8_t *body, size_t body_len, st_message_response *response);
int st_protocol_decode_direct_http_request(const uint8_t *body, size_t body_len, st_direct_http_request *request);
int st_protocol_decode_direct_http_response(const uint8_t *body, size_t body_len, st_direct_http_response *response);
int st_protocol_decode_nat_message(const uint8_t *body, size_t body_len, st_nat_message *message);
st_buffer st_protocol_encode_login_response(const char *client_name, int success, const char *reason);
st_buffer st_protocol_encode_nat_control(const char *client_name, const char *nat_control_json);
st_buffer st_protocol_encode_nat_message(int type, const char *meta_json, const uint8_t *data, size_t data_len);
st_buffer st_protocol_encode_empty_packet(int8_t command);
void st_login_request_free(st_login_request *request);
void st_message_response_free(st_message_response *response);
void st_direct_http_request_free(st_direct_http_request *request);
void st_direct_http_response_free(st_direct_http_response *response);
void st_nat_message_free(st_nat_message *message);
void st_buffer_free(st_buffer *buffer);

#endif
