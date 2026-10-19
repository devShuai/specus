#define _POSIX_C_SOURCE 200809L
#include "server_harness.h"

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>

static in_port_t first_port;
static unsigned ephemeral_binds;
static unsigned held_port_refusals;

int __real_bind(int fd, const struct sockaddr *address, socklen_t length);

/* The kernel may reuse a just-released ephemeral port. Choose that legal outcome
 * deterministically; if the first reservation is still open, the real kernel must
 * reject it and allocate a different port. No server sockets are mocked. */
int __wrap_bind(int fd, const struct sockaddr *address, socklen_t length)
{
    if (address->sa_family != AF_INET || length != sizeof(struct sockaddr_in)
        || ((const struct sockaddr_in *)address)->sin_port != 0) {
        return __real_bind(fd, address, length);
    }
    ++ephemeral_binds;
    if (first_port != 0) {
        struct sockaddr_in repeated = *(const struct sockaddr_in *)address;
        repeated.sin_port = first_port;
        int result = __real_bind(fd, (const struct sockaddr *)&repeated, sizeof(repeated));
        if (result == 0 || errno != EADDRINUSE) {
            return result;
        }
        ++held_port_refusals;
    }
    int result = __real_bind(fd, address, length);
    if (result == 0 && first_port == 0) {
        struct sockaddr_in selected;
        socklen_t selected_length = sizeof(selected);
        if (getsockname(fd, (struct sockaddr *)&selected, &selected_length) != 0) {
            return -1;
        }
        first_port = selected.sin_port;
    }
    return result;
}

static int check_distinct_listeners(test_server *server)
{
    CHECK(ephemeral_binds == 2U && held_port_refusals == 1U,
          "the second allocation must encounter the first live reservation (binds=%u, held=%u)",
          ephemeral_binds, held_port_refusals);
    CHECK(server->control_port > 0 && server->admin_port > 0
              && server->control_port != server->admin_port,
          "listeners must have distinct ports: control=%d admin=%d",
          server->control_port, server->admin_port);
    int control = connect_local(server->control_port);
    int admin = connect_local(server->admin_port);
    int ready = control >= 0 && admin >= 0;
    close_fd(&control);
    close_fd(&admin);
    CHECK(ready, "both real server listeners must accept connections");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <specus-server-c>\n", argv[0]);
        return 2;
    }
    server_binary = argv[1];
    signal(SIGPIPE, SIG_IGN);
    int failed = run_on_fresh_server("distinct server ports under immediate port reuse",
                                     check_distinct_listeners, NULL);
    if (failed) {
        fprintf(stderr, "port reuse regression failed: binds=%u held-reservation-refusals=%u\n",
                ephemeral_binds, held_port_refusals);
    }
    return failed;
}
