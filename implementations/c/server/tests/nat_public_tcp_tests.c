/*
 * Public TCP connections of the NAT data connection against a real specus-server-c process, as
 * Java's NatServerHandler, RemoteSpecusHandler and Netty (TcpServer, ServerBootstrapAcceptor)
 * handle them (issue #35 item 45):
 *
 *   - a public connection both sides closed leaves nothing behind while the data connection lives:
 *     the server's mappings (thread stacks) do not grow with the number of connections it served;
 *   - a failed accept (descriptors exhausted with prlimit) pauses the public port or the control
 *     port for Netty's 1 s instead of closing the port or ending the server;
 *   - Java's specus.netty.* settings and defaults (application.yml) apply: SO_KEEPALIVE on accepted
 *     sockets and SO_BACKLOG on both listeners (read back from the kernel with sock_diag), the frame
 *     size limits before and after login, the external connection limits under Java's names with
 *     Java's default of 10000 and 0 as no limit, and the start is refused for values Spring cannot
 *     bind or NettyServer.validateConfiguration refuses.
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

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/wait.h>
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
#define MEASURED_CONNECTIONS 200
/* Room for glibc's stack cache and an arena or two; a kept stack costs two mappings per thread. */
#define MAPPING_SLACK 64

/*
 * Java drops a closed external channel from its maps at once and a Netty channel holds no thread
 * (NatServerHandler, closeFuture). The C server runs a reader and a writer thread per public
 * connection; once both are done the stream and their stacks must go too, not wait for the data
 * connection to end. Each kept (unjoined) thread keeps its stack mapped, so the server's mapping
 * count is the observable: 200 short connections may not add 200 x 4 mappings.
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
/* Failed accepts                                                                                */

/*
 * The lowest descriptor number the server has free. With RLIMIT_NOFILE set to it, every new
 * descriptor fails with EMFILE (a thread already blocked in accept() has reserved its own).
 */
static int lowest_free_descriptor(pid_t pid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/fd", (int)pid);
    DIR *dir = opendir(path);
    if (dir == NULL) {
        return -1;
    }
    static unsigned char used[65536];
    memset(used, 0, sizeof(used));
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        char *end = NULL;
        long number = strtol(entry->d_name, &end, 10);
        if (end != entry->d_name && *end == '\0' && number >= 0 && number < (long)sizeof(used)) {
            used[number] = 1;
        }
    }
    closedir(dir);
    for (int number = 0; number < (int)sizeof(used); ++number) {
        if (!used[number]) {
            return number;
        }
    }
    return -1;
}

/* Lowers the server's descriptor limit to what it has open now; *saved gets the old limit. */
static int exhaust_descriptors(pid_t pid, struct rlimit *saved)
{
    int lowest = lowest_free_descriptor(pid);
    if (lowest < 0 || prlimit(pid, RLIMIT_NOFILE, NULL, saved) != 0) {
        return -1;
    }
    struct rlimit exhausted = *saved;
    exhausted.rlim_cur = (rlim_t)lowest;
    return prlimit(pid, RLIMIT_NOFILE, &exhausted, NULL);
}

static void restore_descriptors(pid_t pid, const struct rlimit *saved)
{
    if (prlimit(pid, RLIMIT_NOFILE, saved, NULL) != 0) {
        fprintf(stderr, "cannot restore the server's descriptor limit: %s\n", strerror(errno));
    }
}

/* Waits up to timeout_ms for the server's log (stderr is unbuffered) to contain text. */
static int wait_log(const test_server *server, const char *text, int timeout_ms)
{
    long long deadline = monotonic_ms() + timeout_ms;
    for (;;) {
        FILE *log = fopen(server->log_path, "r");
        if (log != NULL) {
            char line[1024];
            int found = 0;
            while (!found && fgets(line, sizeof(line), log) != NULL) {
                found = strstr(line, text) != NULL;
            }
            fclose(log);
            if (found) {
                return 0;
            }
        }
        if (monotonic_ms() >= deadline) {
            return -1;
        }
        sleep_ms(50);
    }
}

static int server_running(const test_server *server)
{
    int status = 0;
    return server->pid > 0 && waitpid(server->pid, &status, WNOHANG) == 0;
}

/*
 * Netty's ServerBootstrapAcceptor keeps a public port's server channel open when accept() fails
 * (EMFILE here): it stops accepting for 1 s and resumes. The C listener thread used to end on the
 * first failed accept, closing the port while the client still had it registered.
 */
/*
 * A round may miss its failure when a descriptor the server held only for a moment (a SQLite
 * write, say) is closed after the limit came down, below it: the next accept() then succeeds.
 * Such a round is simply repeated.
 */
#define ACCEPT_FAILURE_ROUNDS 3

/*
 * One round: with the limit down, a public connection is made; the failed accept is reported or
 * not (*reported), and with the limit back the connection is taken and closed again.
 */
static int nat_accept_failure_round(test_server *server, client_pair *pair, int *reported)
{
    struct rlimit saved;
    CHECK(exhaust_descriptors(server->pid, &saved) == 0, "lower the server's descriptor limit");
    /*
     * An accept() already blocked takes this connection with the descriptor it reserved before the
     * limit came down, and the next one fails; one that was not blocked yet fails on it at once.
     */
    int first = connect_local(pair->public_port);
    char failed_line[96];
    snprintf(failed_line, sizeof(failed_line), "[nat] accept failed port=%d", pair->public_port);
    *reported = first >= 0 && wait_log(server, failed_line, 3000) == 0;
    restore_descriptors(server->pid, &saved);
    CHECK(first >= 0, "connect to the public port");
    /* Taken now, or after the 1 s pause: either way the port still has it. */
    st_nat_message open;
    int accepted = expect_nat_frame(pair->data, ST_NAT_OPEN, &open) == 0;
    uint32_t first_stream = accepted ? open.stream_id : 0U;
    if (accepted) {
        st_nat_message_free(&open);
    }
    close_fd(&first);
    CHECK(accepted, "the connection waiting through the failed accept was never taken");
    CHECK(expect_stream_frame(pair->data, ST_NAT_FIN, first_stream) == 0
              && send_nat(pair->data, ST_NAT_FIN, first_stream, 0U, NULL, 0U) == 0,
          "close the first connection");
    /* The port must still take new connections once descriptors are back. */
    CHECK(expect_stream_served(pair) == 0, "the public port after a failed accept");
    return 0;
}

static int check_nat_listener_survives_failed_accept(test_server *server, client_pair *pair)
{
    int reported = 0;
    for (int round = 0; !reported && round < ACCEPT_FAILURE_ROUNDS; ++round) {
        CHECK(nat_accept_failure_round(server, pair, &reported) == 0, "round %d", round + 1);
    }
    CHECK(reported, "no failed accept was reported on the public port in %d rounds", ACCEPT_FAILURE_ROUNDS);
    return 0;
}

/*
 * The control port is a Netty server channel too. A failed accept used to end the C accept loop
 * and with it the whole process, with exit status 0 (systemd's Restart=on-failure leaves that be).
 */
static int check_control_listener_survives_failed_accept(test_server *server, client_pair *pair)
{
    int reported = 0;
    for (int round = 0; !reported && round < ACCEPT_FAILURE_ROUNDS; ++round) {
        struct rlimit saved;
        CHECK(exhaust_descriptors(server->pid, &saved) == 0, "lower the server's descriptor limit");
        int pending = connect_local(server->control_port);
        int connected = pending >= 0;
        reported = connected && wait_log(server, "[server] accept failed", 3000) == 0;
        restore_descriptors(server->pid, &saved);
        close_fd(&pending);
        CHECK(connected, "connect to the control port");
        /* An exited server is the failure; an unreported round (see nat_accept_failure_round) is repeated. */
        CHECK(server_running(server), "the server exited on a failed accept of the control port");
    }
    CHECK(reported, "no failed accept was reported on the control port in %d rounds", ACCEPT_FAILURE_ROUNDS);
    /* After the 1 s pause a new control login goes through, and the client's connections still work. */
    runtime_session other;
    char reason[256];
    CHECK(create_credential(server->db_path, "ck_after_emfile", "after-emfile-secret", 2) == 0, "credential");
    CHECK(http_client_login(server, "ck_after_emfile", "after-emfile-secret", "machine-after-emfile", "after",
                            &other) == 0,
          "http login");
    int control = -1;
    CHECK(channel_login(server->control_port, &other, "control", &control, reason, sizeof(reason)) == 1,
          "control login after the failed accept: %s", reason);
    close_fd(&control);
    CHECK(expect_channel_alive(pair->control) == 0, "the existing control connection");
    return expect_stream_served(pair);
}

/* ------------------------------------------------------------------------------------------- */
/* specus.netty.* socket options, read back from the kernel (sock_diag)                          */

/* Kernel TCP states (include/net/tcp_states.h). */
#define DIAG_ESTABLISHED 1
#define DIAG_LISTEN 10

typedef struct {
    int found;
    /* 0 none, 1 retransmit, 2 keepalive (sk_timer), 3 TIME_WAIT, 4 zero window probe. */
    unsigned int timer;
    /* For a listening socket: the accept queue's length and its limit, the effective backlog. */
    unsigned int rqueue;
    unsigned int wqueue;
} socket_diag;

/* The IPv4 TCP socket in `state` with local port sport and, unless 0, remote port dport. */
static int tcp_socket_diag(int state, int sport, int dport, socket_diag *out)
{
    memset(out, 0, sizeof(*out));
    int fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
    if (fd < 0) {
        return -1;
    }
    struct {
        struct nlmsghdr header;
        struct inet_diag_req_v2 request;
    } message;
    memset(&message, 0, sizeof(message));
    message.header.nlmsg_len = sizeof(message);
    message.header.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    message.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    message.request.sdiag_family = AF_INET;
    message.request.sdiag_protocol = IPPROTO_TCP;
    message.request.idiag_states = 1U << state;
    struct sockaddr_nl kernel;
    memset(&kernel, 0, sizeof(kernel));
    kernel.nl_family = AF_NETLINK;
    if (sendto(fd, &message, sizeof(message), 0, (struct sockaddr *)&kernel, sizeof(kernel)) < 0) {
        close(fd);
        return -1;
    }
    long buffer[8192];
    for (;;) {
        ssize_t received = recv(fd, buffer, sizeof(buffer), 0);
        if (received <= 0) {
            close(fd);
            return -1;
        }
        unsigned int len = (unsigned int)received;
        for (struct nlmsghdr *header = (struct nlmsghdr *)buffer; NLMSG_OK(header, len);
             header = NLMSG_NEXT(header, len)) {
            if (header->nlmsg_type == NLMSG_DONE) {
                close(fd);
                return 0;
            }
            if (header->nlmsg_type == NLMSG_ERROR) {
                close(fd);
                return -1;
            }
            const struct inet_diag_msg *diag = (const struct inet_diag_msg *)NLMSG_DATA(header);
            if (ntohs(diag->id.idiag_sport) == sport && (dport == 0 || ntohs(diag->id.idiag_dport) == dport)) {
                out->found = 1;
                out->timer = diag->idiag_timer;
                out->rqueue = diag->idiag_rqueue;
                out->wqueue = diag->idiag_wqueue;
            }
        }
    }
}

static int local_port(int fd)
{
    struct sockaddr_in address;
    socklen_t length = sizeof(address);
    if (getsockname(fd, (struct sockaddr *)&address, &length) != 0) {
        return -1;
    }
    return ntohs(address.sin_port);
}

/* Whether the server's side of an idle connection has its keepalive timer running, within wait_ms. */
static int server_keepalive_armed(int server_port, int client_fd, int wait_ms, int *armed)
{
    int client_port = local_port(client_fd);
    long long deadline = monotonic_ms() + wait_ms;
    for (;;) {
        socket_diag diag;
        if (client_port < 0 || tcp_socket_diag(DIAG_ESTABLISHED, server_port, client_port, &diag) != 0 || !diag.found) {
            return -1;
        }
        /* A retransmit timer, while one is pending, is reported instead of the keepalive timer. */
        *armed = diag.timer == 2U;
        if (*armed || monotonic_ms() >= deadline) {
            return 0;
        }
        sleep_ms(50);
    }
}

/*
 * Netty's child options (TcpServer, NettyServer): SO_KEEPALIVE from SPECUS_NETTY_KEEP_ALIVE,
 * true by default, on every accepted public socket and on the control and data connections. The
 * C server never set it, so a public peer that vanished without FIN or RST held its stream (and
 * its place under the connection limits) until the data connection ended; Java's socket errors out.
 */
static int check_keepalive(int expected, client_pair *pair, int control_port)
{
    int public_fd = -1;
    uint32_t stream_id = 0U;
    CHECK(open_public_stream_id(pair->data, pair->public_port, &public_fd, &stream_id) == 0, "public OPEN");
    int public_armed = -1;
    int data_armed = -1;
    /* Armed shows at once on an idle socket; for "off", a quarter second of never seeing it will do. */
    int wait_ms = expected ? 3000 : 250;
    int read_public = server_keepalive_armed(pair->public_port, public_fd, wait_ms, &public_armed) == 0;
    int read_data = server_keepalive_armed(control_port, pair->data, wait_ms, &data_armed) == 0;
    close_fd(&public_fd);
    CHECK(read_public && read_data, "read the server's sockets through sock_diag");
    CHECK(public_armed == expected, "the server's public socket %s SO_KEEPALIVE", public_armed ? "has" : "lacks");
    CHECK(data_armed == expected, "the server's data connection socket %s SO_KEEPALIVE", data_armed ? "has" : "lacks");
    CHECK(expect_stream_frame(pair->data, ST_NAT_FIN, stream_id) == 0
              && send_nat(pair->data, ST_NAT_FIN, stream_id, 0U, NULL, 0U) == 0,
          "close the stream");
    return 0;
}

static int check_keepalive_by_default(test_server *server, client_pair *pair)
{
    return check_keepalive(1, pair, server->control_port);
}

static int check_keepalive_switched_off(test_server *server, client_pair *pair)
{
    return check_keepalive(0, pair, server->control_port);
}

static int somaxconn(void)
{
    FILE *file = fopen("/proc/sys/net/core/somaxconn", "r");
    int value = -1;
    if (file != NULL) {
        if (fscanf(file, "%d", &value) != 1) {
            value = -1;
        }
        fclose(file);
    }
    return value;
}

/* SO_BACKLOG of both server channels: Java's 8192 (the kernel caps it at somaxconn), or as set. */
static int check_backlog(test_server *server, client_pair *pair, int expected)
{
    socket_diag control;
    socket_diag public_port;
    CHECK(tcp_socket_diag(DIAG_LISTEN, server->control_port, 0, &control) == 0 && control.found,
          "the control listener through sock_diag");
    CHECK(tcp_socket_diag(DIAG_LISTEN, pair->public_port, 0, &public_port) == 0 && public_port.found,
          "the public listener through sock_diag");
    printf("     backlog: control %u, public %u (expected %d)\n", control.wqueue, public_port.wqueue, expected);
    CHECK((int)control.wqueue == expected, "the control listener's backlog is %u, not %d", control.wqueue, expected);
    CHECK((int)public_port.wqueue == expected, "the public listener's backlog is %u, not %d", public_port.wqueue,
          expected);
    return 0;
}

static int check_backlog_by_default(test_server *server, client_pair *pair)
{
    int cap = somaxconn();
    CHECK(cap > 0, "read somaxconn");
    return check_backlog(server, pair, cap < 8192 ? cap : 8192);
}

static int check_backlog_configured(test_server *server, client_pair *pair)
{
    return check_backlog(server, pair, 77);
}

#define CONFIGURED_MAX_FRAME (1024 * 1024)
#define NAT_FRAME_OVERHEAD (11 + 16)

/* A DATA frame of exactly frame_size bytes, header included, for a stream that does not exist. */
static int send_data_frame_of(int fd, size_t frame_size)
{
    size_t data_len = frame_size - NAT_FRAME_OVERHEAD;
    uint8_t *data = (uint8_t *)calloc(1U, data_len);
    if (data == NULL) {
        return -1;
    }
    int rc = send_nat(fd, ST_NAT_DATA, 0x7fff0001U, 0U, data, data_len);
    free(data);
    return rc;
}

/*
 * SPECUS_NETTY_MAX_FRAME_SIZE caps every frame after login (Java's Spliter, header included). A
 * frame of exactly the limit is read (and its unknown stream reset); one byte more closes the data
 * connection. The C server read every frame up to 32 MiB whatever was configured.
 */
static int check_max_frame_size(test_server *server, client_pair *pair)
{
    (void)server;
    CHECK(send_data_frame_of(pair->data, CONFIGURED_MAX_FRAME) == 0, "a frame of exactly the limit");
    CHECK(expect_channel_alive(pair->data) == 0, "a frame of exactly SPECUS_NETTY_MAX_FRAME_SIZE must be read");
    /* The server may close as soon as it has read the header, so the send itself may fail. */
    (void)send_data_frame_of(pair->data, CONFIGURED_MAX_FRAME + 1);
    CHECK(expect_channel_closed(pair->data, IO_TIMEOUT_MS) == 0,
          "a frame one byte over SPECUS_NETTY_MAX_FRAME_SIZE must close the data connection");
    close_fd(&pair->data);
    CHECK(expect_channel_alive(pair->control) == 0, "the control connection must stay");
    return 0;
}

/* SPECUS_NETTY_PRE_AUTH_MAX_FRAME_SIZE caps the frames before login: a larger login request is not read. */
static int test_pre_auth_frame_size(test_server *server)
{
    runtime_session runtime;
    CHECK(create_credential(server->db_path, "ck_pre_auth", "pre-auth-secret", 2) == 0, "credential");
    CHECK(http_client_login(server, "ck_pre_auth", "pre-auth-secret", "machine-pre-auth", "pre-auth", &runtime) == 0,
          "http login");
    int control = -1;
    char reason[256];
    int rc = channel_login(server->control_port, &runtime, "control", &control, reason, sizeof(reason));
    close_fd(&control);
    CHECK(rc == -1, "a login request beyond SPECUS_NETTY_PRE_AUTH_MAX_FRAME_SIZE=64 must not be answered (rc=%d)", rc);
    return 0;
}

/* Values Spring cannot bind, or that NettyServer.validateConfiguration refuses, stop the start. */
static int expect_refused_start(const char *assignment, const char *message)
{
    test_server server;
    if (server_prepare(&server) != 0) {
        fprintf(stderr, "cannot prepare server directory\n");
        return 1;
    }
    server.extra_env[0] = assignment;
    int started = server_start(&server) == 0;
    int logged = !started && wait_log(&server, message, 1000) == 0;
    if (started) {
        (void)server_stop(&server, 20000);
    }
    int failed = started || !logged;
    if (failed) {
        fprintf(stderr, "%s: %s\n", assignment,
                started ? "the server started" : "the server stopped without the expected message");
    }
    server_cleanup(&server, failed);
    return failed;
}

static int test_unusable_netty_settings(void)
{
    static const struct {
        const char *assignment;
        const char *message;
    } cases[] = {
        {"SPECUS_NETTY_SO_BACKLOG=abc", "invalid SPECUS_NETTY_SO_BACKLOG"},
        {"SPECUS_NETTY_KEEP_ALIVE=maybe", "invalid SPECUS_NETTY_KEEP_ALIVE"},
        {"SPECUS_NETTY_TCP_NO_DELAY= ", "invalid SPECUS_NETTY_TCP_NO_DELAY"},
        {"SPECUS_NETTY_REUSE_ADDRESS=enabled", "invalid SPECUS_NETTY_REUSE_ADDRESS"},
        {"SPECUS_NETTY_MAX_EXTERNAL_CONNECTIONS_PER_PORT=1x", "invalid SPECUS_NETTY_MAX_EXTERNAL_CONNECTIONS_PER_PORT"},
        {"SPECUS_NETTY_MAXFRAMESIZE=2147483648", "invalid SPECUS_NETTY_MAXFRAMESIZE"},
        {"SPECUS_NETTY_PRE_AUTH_MAX_FRAME_SIZE=10", "SPECUS_NETTY_PRE_AUTH_MAX_FRAME_SIZE must be between"},
        {"SPECUS_NETTY_MAX_FRAME_SIZE=8192", "SPECUS_NETTY_PRE_AUTH_MAX_FRAME_SIZE must be between"},
    };
    int failures = 0;
    for (size_t i = 0U; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        failures += expect_refused_start(cases[i].assignment, cases[i].message);
    }
    CHECK(failures == 0, "%d unusable specus.netty.* value(s) did not refuse the start", failures);
    return 0;
}

/* No OPEN arrives on the data connection before the answer to a heartbeat sent now. */
static int expect_no_open(int data_fd)
{
    st_buffer heartbeat = st_protocol_encode_empty_packet(ST_CMD_HEARTBEAT_REQUEST);
    CHECK(send_buffer(data_fd, &heartbeat) == 0, "heartbeat");
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    for (;;) {
        long long remaining = deadline - monotonic_ms();
        CHECK(remaining > 0, "no heartbeat answer");
        st_frame_header header;
        uint8_t *body = NULL;
        CHECK(read_frame(data_fd, (int)remaining, &header, &body) == 1, "data connection closed");
        int open = 0;
        st_nat_message message;
        if (header.command == ST_CMD_NAT_MESSAGE && st_protocol_decode_nat_message(body, header.length, &message) == 0) {
            open = message.type == ST_NAT_OPEN;
            st_nat_message_free(&message);
        }
        free(body);
        CHECK(!open, "a public connection beyond the limit was opened");
        if (header.command == ST_CMD_HEARTBEAT_RESPONSE) {
            return 0;
        }
    }
}

/* SPECUS_NETTY_MAX_EXTERNAL_CONNECTIONS_PER_PORT=1: the second connection is accepted and closed. */
static int check_port_limit_from_java_name(test_server *server, client_pair *pair)
{
    (void)server;
    int first = -1;
    uint32_t stream_id = 0U;
    CHECK(open_public_stream_id(pair->data, pair->public_port, &first, &stream_id) == 0, "first public OPEN");
    int second = connect_local(pair->public_port);
    int closed = second >= 0 && expect_socket_eof(second, IO_TIMEOUT_MS) == 0;
    close_fd(&second);
    int quiet = expect_no_open(pair->data) == 0;
    close_fd(&first);
    CHECK(closed && quiet, "the connection beyond SPECUS_NETTY_MAX_EXTERNAL_CONNECTIONS_PER_PORT=1 must be closed");
    return 0;
}

/* The Java name wins over the old C one, and 0 is no limit (RemotePortServerManager.tryIncrement). */
static int check_java_name_overrides_alias(test_server *server, client_pair *pair)
{
    (void)server;
    int fds[3] = {-1, -1, -1};
    int opened = 1;
    for (size_t i = 0U; opened && i < 3U; ++i) {
        uint32_t stream_id = 0U;
        opened = open_public_stream_id(pair->data, pair->public_port, &fds[i], &stream_id) == 0;
    }
    for (size_t i = 0U; i < 3U; ++i) {
        close_fd(&fds[i]);
    }
    CHECK(opened, "SPECUS_NETTY_MAX_EXTERNAL_CONNECTIONS_PER_PORT=0 must lift the limit SPECUS_MAX_PORT_EXTERNAL_CONNECTIONS=1 set");
    return 0;
}

/* Java's default of 10000 per port: well past the C server's former 512. */
#define DEFAULT_LIMIT_CONNECTIONS 520

static int check_default_port_limit(test_server *server, client_pair *pair)
{
    (void)server;
    int *fds = (int *)malloc(DEFAULT_LIMIT_CONNECTIONS * sizeof(int));
    CHECK(fds != NULL, "allocation");
    int opened = 0;
    int failed = 0;
    for (; !failed && opened < DEFAULT_LIMIT_CONNECTIONS; ++opened) {
        uint32_t stream_id = 0U;
        fds[opened] = -1;
        failed = open_public_stream_id(pair->data, pair->public_port, &fds[opened], &stream_id) != 0;
    }
    for (int i = 0; i < opened; ++i) {
        close_fd(&fds[i]);
    }
    free(fds);
    CHECK(!failed, "public connection %d of one port was refused under Java's default limit", opened);
    return 0;
}

static int raise_descriptor_limit(rlim_t wanted)
{
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0) {
        return -1;
    }
    if (limit.rlim_cur != RLIM_INFINITY && limit.rlim_cur < wanted) {
        limit.rlim_cur = limit.rlim_max == RLIM_INFINITY || limit.rlim_max >= wanted ? wanted : limit.rlim_max;
        if (setrlimit(RLIMIT_NOFILE, &limit) != 0) {
            return -1;
        }
    }
    return limit.rlim_cur == RLIM_INFINITY || limit.rlim_cur >= wanted ? 0 : -1;
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
    failures += run_check("a failed accept pauses the public port instead of closing it",
                          check_nat_listener_survives_failed_accept, long_idle);
    failures += run_check("a failed accept pauses the control port instead of ending the server",
                          check_control_listener_survives_failed_accept, long_idle);
    failures += run_check("accepted public and data sockets have SO_KEEPALIVE by default",
                          check_keepalive_by_default, long_idle);
    static const char *const keepalive_off[] = {"SPECUS_CONTROL_READ_IDLE_SECONDS=900",
                                                "SPECUS_NETTY_KEEP_ALIVE=false", NULL};
    failures += run_check("SPECUS_NETTY_KEEP_ALIVE=false leaves SO_KEEPALIVE off", check_keepalive_switched_off,
                          keepalive_off);
    failures += run_check("both listeners take Java's SO_BACKLOG of 8192 (capped at somaxconn)",
                          check_backlog_by_default, long_idle);
    static const char *const backlog_77[] = {"SPECUS_CONTROL_READ_IDLE_SECONDS=900", "SPECUS_NETTY_SO_BACKLOG= 0x4D ",
                                             NULL};
    failures += run_check("SPECUS_NETTY_SO_BACKLOG sets both listeners' backlog", check_backlog_configured,
                          backlog_77);
    static const char *const max_frame[] = {"SPECUS_CONTROL_READ_IDLE_SECONDS=900",
                                            "SPECUS_NETTY_MAX_FRAME_SIZE=1048576", NULL};
    failures += run_check("SPECUS_NETTY_MAX_FRAME_SIZE caps frames after login", check_max_frame_size, max_frame);
    static const char *const pre_auth[] = {"SPECUS_NETTY_PRE_AUTH_MAX_FRAME_SIZE=64", NULL};
    if (selected("SPECUS_NETTY_PRE_AUTH_MAX_FRAME_SIZE caps frames before login")) {
        failures += run_on_fresh_server("SPECUS_NETTY_PRE_AUTH_MAX_FRAME_SIZE caps frames before login",
                                        test_pre_auth_frame_size, pre_auth);
    }
    if (selected("unusable specus.netty.* values refuse the start")) {
        int failed = test_unusable_netty_settings() != 0;
        printf("%s unusable specus.netty.* values refuse the start\n", failed ? "FAIL" : "ok  ");
        failures += failed;
    }
    static const char *const port_limit[] = {"SPECUS_CONTROL_READ_IDLE_SECONDS=900",
                                             "SPECUS_NETTY_MAX_EXTERNAL_CONNECTIONS_PER_PORT=1", NULL};
    failures += run_check("SPECUS_NETTY_MAX_EXTERNAL_CONNECTIONS_PER_PORT limits a port's connections",
                          check_port_limit_from_java_name, port_limit);
    static const char *const no_port_limit[] = {"SPECUS_CONTROL_READ_IDLE_SECONDS=900",
                                                "SPECUS_NETTY_MAX_EXTERNAL_CONNECTIONS_PER_PORT=0",
                                                "SPECUS_MAX_PORT_EXTERNAL_CONNECTIONS=1", NULL};
    failures += run_check("the Java limit name wins over the old one, and 0 is no limit",
                          check_java_name_overrides_alias, no_port_limit);
    /* The server inherits the limit: 520 public connections take more than the usual 1024 with both ends. */
    if (raise_descriptor_limit(4096) == 0) {
        failures += run_check("a port takes more than 512 connections under Java's default limit",
                              check_default_port_limit, long_idle);
    } else {
        fprintf(stderr, "cannot raise the descriptor limit to 4096 for the default-limit check\n");
        failures += 1;
    }
    if (failures != 0) {
        fprintf(stderr, "%d public TCP check(s) failed\n", failures);
        return 1;
    }
    printf("public TCP tests passed\n");
    return 0;
}
