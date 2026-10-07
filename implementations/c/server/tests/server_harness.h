/*
 * Harness for tests that drive a real specus-server-c process over real sockets.
 *
 * Each scenario starts the server binary with its own SQLite database; the helpers log a client
 * in through the real HTTP endpoint and speak the v2 control/data protocol the way a client does.
 */
#ifndef SPECUS_C_SERVER_HARNESS_H
#define SPECUS_C_SERVER_HARNESS_H

#include "protocol.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#define ADMIN_USERNAME "lifecycle-admin"
#define ADMIN_PASSWORD "lifecycle-e2e-password-2026"
#define ADMIN_JWT_SECRET "lifecycle-e2e-jwt-secret-that-is-long-and-random-2026"
#define IO_TIMEOUT_MS 5000
#define MAX_EXTRA_ENV 4

typedef struct {
    pid_t pid;
    int control_port;
    int admin_port;
    char dir[256];
    char db_path[320];
    char log_path[320];
    const char *extra_env[MAX_EXTRA_ENV];
} test_server;

typedef struct {
    char client_name[256];
    long long client_id;
    long long session_id;
    char access_token[256];
} runtime_session;

/* The specus-server-c binary every scenario starts; set by the test's main(). */
extern const char *server_binary;

#define CHECK(condition, ...)                                   \
    do {                                                        \
        if (!(condition)) {                                     \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
            fprintf(stderr, __VA_ARGS__);                       \
            fprintf(stderr, "\n");                              \
            return 1;                                           \
        }                                                       \
    } while (0)

long long monotonic_ms(void);
long long wall_clock_ms(void);
void sleep_ms(int ms);

/* Sockets */
int pick_free_port(void);
int connect_local(int port);
int send_all(int fd, const uint8_t *data, size_t len);
/* 1 = filled, 0 = orderly EOF or reset, -1 = error, -2 = timed out. */
int recv_exact(int fd, uint8_t *buffer, size_t len, long long deadline);
int send_buffer(int fd, st_buffer *buffer);
/* Same return convention as recv_exact; on 1 the caller frees *body. */
int read_frame(int fd, int timeout_ms, st_frame_header *header, uint8_t **body);
void close_fd(int *fd);

/* Control and data connections */
int send_login_request(int fd, const runtime_session *runtime, const char *role);
/*
 * Reads the next frame as the answer to a LOGIN_REQUEST: 1 when it is a LOGIN_RESPONSE, with
 * *success and the server's reason filled; 0 when another frame came first (its command in
 * *command); -1 on I/O failure, a timeout or a malformed response. reason describes the failure.
 */
int read_login_response(int fd, int timeout_ms, int *command, int *success, char *reason, size_t reason_len);
/*
 * Logs a connection in with the given role. Returns 1 and keeps the socket in *fd_out when the
 * server accepts, 0 with the server's reason when it refuses (the socket is closed), -1 on I/O
 * failure.
 */
int channel_login(int port, const runtime_session *runtime, const char *role,
                  int *fd_out, char *reason, size_t reason_len);
/* channel_login that also copies the client name the LOGIN_RESPONSE carries into answered_name. */
int channel_login_answer(int port, const runtime_session *runtime, const char *role, int *fd_out,
                         char *answered_name, size_t answered_name_len, char *reason, size_t reason_len);
/* Reads and discards frames until the server closes the connection. */
int expect_channel_closed(int fd, int timeout_ms);
/* A heartbeat answered proves the channel is still bound and served. */
int expect_channel_alive(int fd);
/* Waits for the next NAT frame of the given type on a data connection, skipping everything else. */
int expect_nat_frame(int fd, int type, st_nat_message *message);
int nat_register(int data_fd, const char *client_name, int public_port, int target_port);
/* Opens a public TCP connection through a registered port and waits for the stream's OPEN. */
int open_public_stream(int data_fd, int public_port, int *public_fd);
int open_public_stream_id(int data_fd, int public_port, int *public_fd, uint32_t *stream_id);
int expect_socket_eof(int fd, int timeout_ms);

/* HTTP */
int http_request(int port, const char *method, const char *path, const char *body,
                 const char *bearer, int *status, char **response_body);
/*
 * Extra members appended to the login body's environment object, each with its leading comma (for
 * example ",\"clientHttpRouteCapabilities\":{\"version\":1}"); empty by default.
 */
extern const char *harness_login_environment_extra;
/* A POST /api/client/auth/login body, signed exactly as protocol/spec/client-auth.md describes. */
void signed_login_body(const char *api_key, const char *secret, const char *fingerprint,
                       const char *os_user, char *body, size_t body_len);
/* The real POST /api/client/auth/login with a freshly signed body. */
int http_client_login(const test_server *server, const char *api_key, const char *secret,
                      const char *fingerprint, const char *os_user, runtime_session *out);

/* Database */
int create_credential(const char *db_path, const char *api_key, const char *secret, int max_online);
int create_mapping(const char *db_path, long long client_id, int public_port);
/* Runs a query whose first column of the first row is text or integer; copies it as text. */
int db_scalar(const char *db_path, const char *sql, const char *text_arg, long long int_arg,
              char *out, size_t out_len);

/* Server process */
void dump_server_log(const test_server *server);
int server_prepare(test_server *server);
int server_start(test_server *server);
/* Sends SIGTERM and waits for the exit; returns the exit status, or -1 if it had to be killed. */
int server_stop(test_server *server, int timeout_ms);
void server_cleanup(test_server *server, int failed);

typedef int (*server_scenario)(test_server *server);
/* Runs one scenario against a freshly started server; returns 1 when it failed. */
int run_on_fresh_server(const char *name, server_scenario scenario, const char *const *extra_env);

#endif
