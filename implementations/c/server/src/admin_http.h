#ifndef SPECUS_ADMIN_HTTP_H
#define SPECUS_ADMIN_HTTP_H

#include <stddef.h>

#include "connectivity_check.h"
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
    /* Optional: reports the client's free-text RST reason for server-side logging only. */
    void (*on_reset)(void *ctx, uint32_t code, const char *reason);
    /*
     * Optional: lets another thread end the stream early (a temporary HTTP share that ended,
     * protocol/spec/temporary-http-share.md section 6.6). The forwarder binds cancel(cancel_ctx)
     * once its NAT stream exists and binds NULL before that stream is released; cancel only wakes
     * the forwarder, which then resets the NAT stream and returns
     * ST_ADMIN_DIRECT_HTTP_STREAM_CANCELLED.
     */
    void (*bind_cancel)(void *ctx, void (*cancel)(void *cancel_ctx), void *cancel_ctx);
} st_admin_direct_http_sink;

/*
 * Forwarder result when the client reset the stream (http-route.md §1). The public caller gets
 * a 502 with ST_ADMIN_DIRECT_HTTP_RESET_BODY; the RST reason only reaches sink->on_reset.
 */
#define ST_ADMIN_DIRECT_HTTP_STREAM_RESET (-5)
#define ST_ADMIN_DIRECT_HTTP_RESET_BODY "HTTP 转发请求失败"
/*
 * Forwarder result when the client's data connection already holds its maximum of pending HTTP
 * streams; the public caller gets 502 "HTTP 流创建失败", as Java HttpSpecusController answers.
 */
#define ST_ADMIN_DIRECT_HTTP_STREAM_LIMIT (-6)
/* Forwarder result once sink->bind_cancel's canceller ran: the NAT stream was reset. */
#define ST_ADMIN_DIRECT_HTTP_STREAM_CANCELLED (-7)
/* The NAT RST code and reason that end the in-flight streams of a temporary HTTP share. */
#define ST_ADMIN_HTTP_SHARE_RESET_CODE 31U
#define ST_ADMIN_HTTP_SHARE_RESET_REASON "HTTP share ended"
#define ST_ADMIN_LOG_REASON_MAX_CODE_POINTS 256U

/*
 * Copies at most 256 code points of a peer-supplied reason into out, escaping control and
 * line-separator characters and invalid UTF-8 so the text cannot forge log lines. Always
 * NUL-terminates when out_len > 0; returns the length written.
 */
size_t st_admin_log_safe_reason(const char *reason, char *out, size_t out_len);

/*
 * Forwards one Direct HTTP request: 0 once the response was relayed, -2 when the response head
 * timed out, -3 when the route is not configured for the client, ST_ADMIN_DIRECT_HTTP_STREAM_RESET
 * or ST_ADMIN_DIRECT_HTTP_STREAM_LIMIT as above, and any other negative value when the client is
 * offline or the stream failed.
 */
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

/*
 * After a successful open the NAT side keeps request->stream for as long as the NAT stream is
 * mapped: it takes its own reference with st_admin_direct_ws_retain and drops it with
 * st_admin_direct_ws_release, so neither side frees the stream under the other.
 */
typedef int (*st_admin_direct_ws_open_handler)(void *ctx,
                                               const st_admin_direct_ws_request *request);
/* Sends one browser-to-client SWS2 envelope as NAT DATA; non-zero means the tunnel side is gone. */
typedef int (*st_admin_direct_ws_data_handler)(void *ctx,
                                               const char *channel_id,
                                               const uint8_t *payload,
                                               size_t payload_len);
/*
 * Ends the NAT stream once the browser side is finished: reset_code 0 sends FIN (after the SWS2
 * CLOSE that was already sent as DATA), any other value aborts the stream with that RST code.
 */
typedef void (*st_admin_direct_ws_close_handler)(void *ctx,
                                                 const char *channel_id,
                                                 uint32_t reset_code,
                                                 const char *reason);
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
/*
 * The device side of POST /api/admin/http-routes/{id}/connectivity-check: presence and the probe
 * through the client's data connection (service-connectivity-check.md). Without it the endpoint
 * answers 503 CHECK_UNAVAILABLE. Replaces any earlier device and its rate-limit state.
 */
void st_admin_set_connectivity_device(const st_connectivity_device *device);
int st_admin_deliver_client_message_to_admin(const char *tenant_id,
                                             const char *from_client_name,
                                             const char *to_admin_name,
                                             const char *message);
void st_admin_broadcast_connection_event(const char *tenant_id,
                                         const char *type,
                                         const st_storage_connection *connection);

/*
 * Temporary HTTP shares (protocol/spec/temporary-http-share.md section 6.6 and 7.5). The
 * maintenance thread calls the tick every second: it cuts streams whose share expired and, every
 * two seconds, re-reads each share that has streams on this instance, so a revoke made by another
 * instance cuts them within five seconds. The sweep runs every 30 seconds.
 */
void st_admin_http_share_tick(void);
int st_admin_http_share_sweep(void);
/* Cuts this instance's streams of the share: NAT RST, HTTP aborted, WebSocket closed with 1008. */
void st_admin_http_share_cut(const char *share_id);
size_t st_admin_http_share_stream_count(const char *share_id);
/* Test hooks: placeholder streams that count against the 64-stream admission limit. */
int st_admin_http_share_occupy_for_testing(const char *share_id, size_t count);
void st_admin_http_share_release_for_testing(void);
/* One SWS2 envelope (protocol/spec/http-route.md section 7); payload points into the encoding. */
typedef struct {
    uint8_t opcode;
    int fin;
    uint8_t rsv;
    uint16_t close_code;
    const uint8_t *payload;
    size_t payload_len;
} st_admin_sws2_frame;

#define ST_ADMIN_SWS2_HEADER_BYTES 12U
#define ST_ADMIN_SWS2_MAX_PAYLOAD ((64U * 1024U) - ST_ADMIN_SWS2_HEADER_BYTES)
/* A WebSocket message (one raw frame or a fragmented sequence) is capped at 16 MiB either way. */
#define ST_ADMIN_WS_MAX_MESSAGE_BYTES (16U * 1024U * 1024U)

/* Decodes and fully validates one envelope; frame may be NULL to validate only. */
int st_admin_sws2_decode(const uint8_t *encoded, size_t encoded_len, st_admin_sws2_frame *frame);
/* Encodes a valid envelope into a malloc'd buffer, or returns NULL for an invalid frame. */
uint8_t *st_admin_sws2_encode(const st_admin_sws2_frame *frame, size_t *encoded_len);
int st_admin_validate_sws2_payload(const uint8_t *payload, size_t payload_len);

/*
 * Result of handing the browser side something the client sent on the stream. Every failure has
 * already closed the browser socket; the NAT side drops the stream and resets it with the code
 * below (30 and 31 as the .NET server uses them for WebSocket streams, 7 as for its stream-state
 * violations).
 */
#define ST_ADMIN_DIRECT_WS_ACCEPTED 0
#define ST_ADMIN_DIRECT_WS_INVALID (-1)        /* malformed SWS2 or a broken message sequence */
#define ST_ADMIN_DIRECT_WS_AFTER_FIN (-2)      /* DATA or a second FIN after the client's FIN */
#define ST_ADMIN_DIRECT_WS_BROWSER_FAILED (-3) /* the browser socket could not be written */
#define ST_ADMIN_DIRECT_WS_RST_STREAM_STATE 7U
#define ST_ADMIN_DIRECT_WS_RST_INVALID_SWS2 30U
#define ST_ADMIN_DIRECT_WS_RST_BROWSER_GONE 31U
/* The RST code (and reason, when reason is not NULL) for one of the failed results above. */
uint32_t st_admin_direct_ws_reset_code(int result, const char **reason);

int st_admin_direct_ws_send_framed_payload(st_admin_direct_ws_stream *stream,
                                           const uint8_t *payload,
                                           size_t payload_len);
/* The client's FIN: without an earlier SWS2 CLOSE the browser is closed with 1001. */
int st_admin_direct_ws_peer_finished(st_admin_direct_ws_stream *stream);
/* The client's RST: the browser is closed with 1011 and the socket is dropped. */
void st_admin_direct_ws_peer_reset(st_admin_direct_ws_stream *stream);
int st_admin_direct_ws_add_send_credit(st_admin_direct_ws_stream *stream, uint32_t credit);
/* The control connection is gone: the browser is closed with 1001 and the socket is dropped. */
void st_admin_direct_ws_close(st_admin_direct_ws_stream *stream);
void st_admin_direct_ws_retain(st_admin_direct_ws_stream *stream);
void st_admin_direct_ws_release(st_admin_direct_ws_stream *stream);

#endif
