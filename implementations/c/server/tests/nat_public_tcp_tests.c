/*
 * Public TCP connections of the NAT data connection against a real specus-server-c process, as
 * Java's NatServerHandler, RemoteSpecusHandler and Netty (TcpServer, ServerBootstrapAcceptor)
 * handle them (issue #35 item 45):
 *
 *   - a public connection both sides closed leaves nothing behind while the data connection lives:
 *     the server's mappings (thread stacks) do not grow with the number of connections it served.
 *
 * The test plays the client on real control/data sockets and the public peers on real TCP
 * sockets; every check runs on its own server.
 *
 * Usage: specus_c_nat_public_tcp_tests <path-to-specus-server-c>
 */
#define _GNU_SOURCE

#include "server_harness.h"

#include "json.h"
#include "protocol.h"
#include "storage.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct {
    runtime_session runtime;
    int control;
    int data;
    int public_port;
} client_pair;

static int send_nat(int fd, int type, uint32_t stream_id, uint32_t value, const void *data, size_t data_len)
{
    st_buffer frame = st_protocol_encode_nat_message(type, 0U, stream_id, value, NULL,
                                                     (const uint8_t *)data, data_len);
    return send_buffer(fd, &frame);
}

/* Waits for a NAT frame of the given type and stream, skipping every other frame. */
static int expect_stream_frame(int fd, int type, uint32_t stream_id)
{
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    for (;;) {
        long long remaining = deadline - monotonic_ms();
        if (remaining <= 0) {
            return -1;
        }
        st_frame_header header;
        uint8_t *body = NULL;
        if (read_frame(fd, (int)remaining, &header, &body) != 1) {
            return -1;
        }
        st_nat_message message;
        int match = header.command == ST_CMD_NAT_MESSAGE
            && st_protocol_decode_nat_message(body, header.length, &message) == 0;
        free(body);
        if (!match) {
            continue;
        }
        match = message.type == type && message.stream_id == stream_id;
        int reset = message.type == ST_NAT_RST && message.stream_id == stream_id;
        st_nat_message_free(&message);
        if (match) {
            return 0;
        }
        if (reset) {
            fprintf(stderr, "stream %u was reset while waiting for NAT type %d\n", stream_id, type);
            return -1;
        }
    }
}

/* A logged-in client with one TCP mapping, its port registered on the data connection. */
static int pair_up(test_server *server, const char *tag, client_pair *pair)
{
    char api_key[64];
    char secret[64];
    char fingerprint[64];
    char reason[256];
    memset(pair, 0, sizeof(*pair));
    pair->control = -1;
    pair->data = -1;
    pair->public_port = pick_free_port();
    snprintf(api_key, sizeof(api_key), "ck_%s", tag);
    snprintf(secret, sizeof(secret), "%s-secret", tag);
    snprintf(fingerprint, sizeof(fingerprint), "machine-%s", tag);
    CHECK(create_credential(server->db_path, api_key, secret, 2) == 0, "credential");
    CHECK(http_client_login(server, api_key, secret, fingerprint, tag, &pair->runtime) == 0, "http login");
    CHECK(create_mapping(server->db_path, pair->runtime.client_id, pair->public_port) == 0, "mapping");
    CHECK(channel_login(server->control_port, &pair->runtime, "control", &pair->control, reason, sizeof(reason)) == 1,
          "control login: %s", reason);
    CHECK(channel_login(server->control_port, &pair->runtime, "data", &pair->data, reason, sizeof(reason)) == 1,
          "data login: %s", reason);
    CHECK(nat_register(pair->data, pair->runtime.client_name, pair->public_port, 9) == 0, "REGISTER");
    return 0;
}

static void pair_close(client_pair *pair)
{
    close_fd(&pair->data);
    close_fd(&pair->control);
}

/* A public connection carries bytes both ways: the stream is served. */
static int expect_stream_served(client_pair *pair)
{
    int public_fd = -1;
    uint32_t stream_id = 0U;
    CHECK(open_public_stream_id(pair->data, pair->public_port, &public_fd, &stream_id) == 0, "public OPEN");
    int ok = send_all(public_fd, (const uint8_t *)"ping", 4U) == 0
        && expect_stream_frame(pair->data, ST_NAT_DATA, stream_id) == 0
        && send_nat(pair->data, ST_NAT_DATA, stream_id, 0U, "pong", 4U) == 0;
    uint8_t answer[4];
    ok = ok && recv_exact(public_fd, answer, sizeof(answer), monotonic_ms() + IO_TIMEOUT_MS) == 1
        && memcmp(answer, "pong", 4U) == 0;
    close_fd(&public_fd);
    if (ok) {
        (void)send_nat(pair->data, ST_NAT_FIN, stream_id, 0U, NULL, 0U);
    }
    CHECK(ok, "a public connection must still be relayed both ways");
    return 0;
}

/* ------------------------------------------------------------------------------------------- */
/* Finished streams                                                                              */

static int count_mappings(pid_t pid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", (int)pid);
    FILE *maps = fopen(path, "r");
    if (maps == NULL) {
        return -1;
    }
    int lines = 0;
    int c;
    while ((c = fgetc(maps)) != EOF) {
        lines += c == '\n';
    }
    fclose(maps);
    return lines;
}

/* One public connection, closed by both sides: the peer closes, the client answers the FIN. */
static int short_connection(client_pair *pair)
{
    int public_fd = -1;
    uint32_t stream_id = 0U;
    if (open_public_stream_id(pair->data, pair->public_port, &public_fd, &stream_id) != 0) {
        close_fd(&public_fd);
        fprintf(stderr, "no OPEN for a public connection\n");
        return -1;
    }
    close_fd(&public_fd);
    if (expect_stream_frame(pair->data, ST_NAT_FIN, stream_id) != 0) {
        fprintf(stderr, "no FIN for stream %u after its public peer closed\n", stream_id);
        return -1;
    }
    return send_nat(pair->data, ST_NAT_FIN, stream_id, 0U, NULL, 0U);
}

#define WARM_UP_CONNECTIONS 20
#define MEASURED_CONNECTIONS 300
/* Room for glibc's stack cache and an arena or two; a kept stack costs two mappings per thread. */
#define MAPPING_SLACK 64

/*
 * Java drops a closed external channel from its maps at once and a Netty channel holds no thread
 * (NatServerHandler, closeFuture). The C server runs a reader and a writer thread per public
 * connection; once both are done the stream and their stacks must go too, not wait for the data
 * connection to end. Each kept (unjoined) thread keeps its stack mapped, so the server's mapping
 * count is the observable: 300 short connections may not add 300 x 4 mappings.
 */
static int check_finished_streams_released(test_server *server, client_pair *pair)
{
    for (int i = 0; i < WARM_UP_CONNECTIONS; ++i) {
        CHECK(short_connection(pair) == 0, "warm-up connection %d", i);
    }
    sleep_ms(200);
    int baseline = count_mappings(server->pid);
    CHECK(baseline > 0, "read the server's mappings");
    for (int i = 0; i < MEASURED_CONNECTIONS; ++i) {
        CHECK(short_connection(pair) == 0, "connection %d", i);
    }
    /* The last workers finish just after the client's last FIN. */
    int now = count_mappings(server->pid);
    long long deadline = monotonic_ms() + 5000;
    while (now > baseline + MAPPING_SLACK && monotonic_ms() < deadline) {
        sleep_ms(100);
        now = count_mappings(server->pid);
    }
    printf("     %d mappings before %d connections, %d after\n", baseline, MEASURED_CONNECTIONS, now);
    CHECK(now <= baseline + MAPPING_SLACK,
          "the server kept %d more mappings after %d closed connections (their threads' stacks)",
          now - baseline, MEASURED_CONNECTIONS);
    return expect_stream_served(pair);
}

/* ------------------------------------------------------------------------------------------- */

typedef int (*pair_check)(test_server *server, client_pair *pair);

static pair_check current_check = NULL;

static int run_current_check(test_server *server)
{
    client_pair pair;
    int rc = pair_up(server, "public", &pair) != 0 || current_check(server, &pair) != 0;
    pair_close(&pair);
    return rc;
}

/* The checks leave the control connection silent longer than the default read-idle timeout. */
static const char *const long_idle[] = {"SPECUS_CONTROL_READ_IDLE_SECONDS=900", NULL};

/* SPECUS_NAT_PUBLIC_TCP_ONLY=<text> runs only the checks whose name contains it. */
static int selected(const char *name)
{
    const char *only = getenv("SPECUS_NAT_PUBLIC_TCP_ONLY");
    return only == NULL || *only == '\0' || strstr(name, only) != NULL;
}

static int run_check(const char *name, pair_check check, const char *const *extra_env)
{
    if (!selected(name)) {
        return 0;
    }
    current_check = check;
    return run_on_fresh_server(name, run_current_check, extra_env);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <specus-server-c>\n", argv[0]);
        return 2;
    }
    server_binary = argv[1];
    signal(SIGPIPE, SIG_IGN);

    int failures = 0;
    failures += run_check("closed public connections are released while the data connection lives",
                          check_finished_streams_released, long_idle);
    if (failures != 0) {
        fprintf(stderr, "%d public TCP check(s) failed\n", failures);
        return 1;
    }
    printf("public TCP tests passed\n");
    return 0;
}
