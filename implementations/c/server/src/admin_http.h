#ifndef SPECUS_ADMIN_HTTP_H
#define SPECUS_ADMIN_HTTP_H

#include <stddef.h>

#include "protocol.h"
#include "storage.h"

typedef struct {
    char *request_method;
    char *route;
    char *relative_path;
    char *raw_query;
    char **headers;
    size_t headers_len;
    const uint8_t *body;
    size_t body_len;
} st_direct_http_request;

typedef struct {
    int status_code;
    char **headers;
    size_t headers_len;
    uint8_t *body;
    size_t body_len;
    char *error;
} st_direct_http_response;

typedef struct {
    void *ctx;
    int (*on_headers)(void *ctx,
                      int status_code,
                      char *const *headers,
                      size_t headers_len,
                      char *const *trailer_names,
                      size_t trailer_names_len);
    int (*on_data)(void *ctx, const uint8_t *data, size_t data_len);
    int (*on_end)(void *ctx, char *const *trailers, size_t trailers_len);
} st_admin_direct_http_sink;

typedef int (*st_admin_direct_http_forwarder)(void *ctx,
                                              const char *client_name,
                                              const st_direct_http_request *request,
                                              const st_admin_direct_http_sink *sink);

typedef struct st_admin_direct_ws_stream st_admin_direct_ws_stream;

typedef struct {
    const char *channel_id;
    const char *client_name;
    const char *route;
    const char *relative_path;
    const char *raw_query;
    char **headers;
    size_t headers_len;
    const uint8_t *body;
    size_t body_len;
    st_admin_direct_ws_stream *stream;
} st_admin_direct_ws_request;

typedef int (*st_admin_direct_ws_open_handler)(void *ctx,
                                               const st_admin_direct_ws_request *request);
typedef int (*st_admin_direct_ws_data_handler)(void *ctx,
                                               const char *channel_id,
                                               const uint8_t *payload,
                                               size_t payload_len);
typedef void (*st_admin_direct_ws_close_handler)(void *ctx, const char *channel_id);
typedef int (*st_admin_nat_control_handler)(void *ctx,
                                            long long client_id,
                                            const char *client_name);

typedef struct {
    int online;
    long long connected_since_ms;
} st_admin_client_runtime_status;

typedef int (*st_admin_client_runtime_status_handler)(void *ctx,
                                                      long long client_id,
                                                      const char *client_name,
                                                      st_admin_client_runtime_status *status);

typedef int (*st_admin_client_message_handler)(void *ctx,
                                               long long client_id,
                                               const char *client_name,
                                               const char *from_admin_name,
                                               const char *message);
typedef int (*st_admin_peer_mesh_refresh_handler)(void *ctx,
                                                  const char *tenant_id);

typedef struct {
    int port;
    int fd;
    int started;
    char static_root[512];
    st_admin_direct_http_forwarder direct_http_forward;
    st_admin_direct_ws_open_handler direct_ws_open;
    st_admin_direct_ws_data_handler direct_ws_data;
    st_admin_direct_ws_close_handler direct_ws_close;
    void *direct_http_ctx;
    void *direct_ws_ctx;
} st_admin_server;

int st_admin_build_response(const char *method, const char *path, char *out, size_t out_len);
int st_admin_build_response_with_body(const char *method,
                                      const char *path,
                                      const char *body,
                                      char *out,
                                      size_t out_len);
int st_admin_build_response_with_remote(const char *method,
                                        const char *path,
                                        const char *body,
                                        const char *remote_address,
                                        char *out,
                                        size_t out_len);
int st_admin_build_response_with_auth(const char *method,
                                      const char *path,
                                      const char *authorization,
                                      const char *body,
                                      char *out,
                                      size_t out_len);
int st_admin_build_response_with_content(const char *method,
                                         const char *path,
                                         const char *authorization,
                                         const char *content_type,
                                         const uint8_t *body,
                                         size_t body_len,
                                         char *out,
                                         size_t out_len);
int st_admin_resolve_static_path(const char *static_root,
                                 const char *request_path,
                                 char *file_path,
                                 size_t file_path_len,
                                 const char **content_type);
int st_admin_rewrite_direct_http_response(const char *client_name,
                                          const char *route,
                                          st_direct_http_response *response);
void st_direct_http_response_free(st_direct_http_response *response);
int st_admin_server_start(st_admin_server *server, int port, const char *static_root);
int st_admin_server_start_with_forwarder(st_admin_server *server,
                                         int port,
                                         const char *static_root,
                                         st_admin_direct_http_forwarder forwarder,
                                         void *forwarder_ctx);
int st_admin_server_start_with_handlers(st_admin_server *server,
                                        int port,
                                        const char *static_root,
                                        st_admin_direct_http_forwarder http_forwarder,
                                        void *http_ctx,
                                        st_admin_direct_ws_open_handler ws_open,
                                        st_admin_direct_ws_data_handler ws_data,
                                        st_admin_direct_ws_close_handler ws_close,
                                        void *ws_ctx);
void st_admin_set_nat_control_handler(st_admin_nat_control_handler handler, void *ctx);
void st_admin_set_client_runtime_status_handler(st_admin_client_runtime_status_handler handler,
                                                void *ctx);
void st_admin_set_client_message_handler(st_admin_client_message_handler handler, void *ctx);
void st_admin_set_peer_mesh_refresh_handler(st_admin_peer_mesh_refresh_handler handler, void *ctx);
int st_admin_deliver_client_message_to_admin(const char *tenant_id,
                                             const char *from_client_name,
                                             const char *to_admin_name,
                                             const char *message);
void st_admin_broadcast_connection_event(const char *tenant_id,
                                         const char *type,
                                         const st_storage_connection *connection);
int st_admin_direct_ws_send_framed_payload(st_admin_direct_ws_stream *stream,
                                           const uint8_t *payload,
                                           size_t payload_len);
int st_admin_validate_sws2_payload(const uint8_t *payload, size_t payload_len);
int st_admin_direct_ws_add_send_credit(st_admin_direct_ws_stream *stream, uint32_t credit);
void st_admin_direct_ws_close(st_admin_direct_ws_stream *stream);

#endif
