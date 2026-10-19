#define _POSIX_C_SOURCE 200809L
/* Only the separately built reference server aliases these calls. */
#undef recv
#undef st_peer_mesh_push_on_logout
#undef st_product_metrics_milestone
#include "protocol.h"
#include "peer_mesh.h"
#include "product_metrics.h"
#include "json.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static pthread_mutex_t observer_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t login_lock = PTHREAD_MUTEX_INITIALIZER;
static int selected_control = -1;
static int selected_held;

typedef struct {
    int fd;
    size_t used;
    uint8_t bytes[ST_HEADER_SIZE + 4096U];
} login_prefix;
static login_prefix prefixes[64];

static const char *observer_directory(void)
{
    const char *dir = getenv("SPECUS_SESSION_REFERENCE_DIR");
    return dir != NULL && *dir != '\0' ? dir : NULL;
}

static void fixture_fatal(const char *message)
{
    fprintf(stderr, "session reference observer: %s\n", message);
    _exit(125);
}

static int marker_path(const char *name, char *out, size_t capacity)
{
    const char *dir = observer_directory();
    if (dir == NULL) return -1;
    int n = snprintf(out, capacity, "%s/%s", dir, name);
    return n < 0 || (size_t)n >= capacity ? -1 : 0;
}

static void append_event(const char *event)
{
    char path[512];
    if (marker_path("observer.jsonl", path, sizeof(path)) != 0) fixture_fatal("event path");
    pthread_mutex_lock(&observer_lock);
    int fd = open(path, O_CREAT | O_APPEND | O_WRONLY, 0600);
    size_t length = strlen(event), used = 0U;
    if (fd < 0) fixture_fatal("open event sink");
    while (used < length) {
        ssize_t n = write(fd, event + used, length - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) fixture_fatal("write event sink");
        used += (size_t)n;
    }
    close(fd);
    pthread_mutex_unlock(&observer_lock);
}

static int is_control_listener(int fd)
{
    const char *configured = getenv("SPECUS_NETTY_PORT");
    struct sockaddr_in address;
    socklen_t length = sizeof(address);
    return configured != NULL && getsockname(fd, (struct sockaddr *)&address, &length) == 0
        && address.sin_family == AF_INET && ntohs(address.sin_port) == atoi(configured);
}

/* The normal decoder identifies the first actual CONTROL login, across recv fragmentation.
 * Authentication data stays in process memory and is never put in an observer event. */
static void observe_login_bytes(int fd, const uint8_t *bytes, size_t length)
{
    if (selected_control >= 0) return;
    login_prefix *prefix = NULL;
    for (size_t i = 0U; i < sizeof(prefixes) / sizeof(prefixes[0]); ++i) {
        if (prefixes[i].fd == fd) { prefix = &prefixes[i]; break; }
        if (prefixes[i].fd == 0 && prefix == NULL) prefix = &prefixes[i];
    }
    if (prefix == NULL) fixture_fatal("login observer capacity");
    if (prefix->fd == 0) prefix->fd = fd;
    if (length > sizeof(prefix->bytes) - prefix->used) fixture_fatal("unexpected login size");
    memcpy(prefix->bytes + prefix->used, bytes, length);
    prefix->used += length;
    if (prefix->used < ST_HEADER_SIZE) return;
    st_frame_header header;
    if (st_protocol_read_header(prefix->bytes, &header) != 0
        || header.command != ST_CMD_LOGIN_REQUEST || header.serializer != ST_SERIALIZER_COMPACT_BINARY
        || header.length > 4096U) fixture_fatal("unexpected first control-listener frame");
    if (prefix->used < ST_HEADER_SIZE + header.length) return;
    st_login_request login;
    if (st_protocol_decode_login_request(prefix->bytes + ST_HEADER_SIZE, header.length, &login) != 0)
        fixture_fatal("login decode");
    if (strcmp(login.connection_role, ST_CONNECTION_ROLE_CONTROL) == 0) selected_control = fd;
    st_login_request_free(&login);
    memset(prefix, 0, sizeof(*prefix));
}

static void hold_selected_eof(int fd)
{
    char armed[512], entered[512], release[512];
    if (marker_path("gate-armed", armed, sizeof(armed)) != 0
        || marker_path("gate-entered", entered, sizeof(entered)) != 0
        || marker_path("gate-release", release, sizeof(release)) != 0) fixture_fatal("gate path");
    if (access(armed, F_OK) != 0) return;
    struct sockaddr_in peer;
    socklen_t length = sizeof(peer);
    if (getpeername(fd, (struct sockaddr *)&peer, &length) != 0 || peer.sin_family != AF_INET)
        fixture_fatal("gate peer identity");
    char port[32];
    int n = snprintf(port, sizeof(port), "%u\n", (unsigned int)ntohs(peer.sin_port));
    int marker = open(entered, O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (marker < 0 || write(marker, port, (size_t)n) != n) fixture_fatal("publish gate entry");
    close(marker);
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    long long deadline = (long long)now.tv_sec * 1000LL + now.tv_nsec / 1000000L + 5000LL;
    while (access(release, F_OK) != 0) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        if ((long long)now.tv_sec * 1000LL + now.tv_nsec / 1000000L >= deadline)
            fixture_fatal("gate release deadline");
        struct timespec pause = {0, 1000000L};
        nanosleep(&pause, NULL);
    }
}

ssize_t st_fixture_recv(int fd, void *buffer, size_t length, int flags)
{
    ssize_t result = recv(fd, buffer, length, flags);
    int saved_errno = errno;
    if (observer_directory() != NULL && is_control_listener(fd)) {
        int should_hold = 0;
        pthread_mutex_lock(&login_lock);
        if (result > 0) observe_login_bytes(fd, buffer, (size_t)result);
        else if (result == 0 || (result < 0 && saved_errno == ECONNRESET)) {
            if (fd == selected_control && !selected_held) { selected_held = 1; should_hold = 1; }
            else for (size_t i = 0U; i < sizeof(prefixes) / sizeof(prefixes[0]); ++i)
                if (prefixes[i].fd == fd) memset(&prefixes[i], 0, sizeof(prefixes[i]));
        }
        pthread_mutex_unlock(&login_lock);
        if (should_hold) hold_selected_eof(fd);
    }
    errno = saved_errno;
    return result;
}

static _Thread_local st_peer_mesh_send_fn original_send;
static _Thread_local unsigned int emitted_rosters;

static int observe_send(void *ctx, const char *target, const char *source, const char *message)
{
    char *kind = st_json_get_top_level_string(message, "type");
    if (kind != NULL && strcmp(kind, "roster") == 0) ++emitted_rosters;
    free(kind);
    return original_send(ctx, target, source, message);
}

int st_fixture_peer_logout(const st_peer_mesh_runtime *runtime, const char *client_name)
{
    if (observer_directory() == NULL) return st_peer_mesh_push_on_logout(runtime, client_name);
    int online = runtime->online(runtime->ctx, 0, client_name);
    st_peer_mesh_runtime observed = *runtime;
    original_send = runtime->send;
    emitted_rosters = 0U;
    observed.send = observe_send;
    int result = st_peer_mesh_push_on_logout(&observed, client_name);
    char *escaped = st_json_escape(client_name);
    if (escaped == NULL) fixture_fatal("escape logout identity");
    char event[4096];
    int n = snprintf(event, sizeof(event),
        "{\"kind\":\"logout\",\"client\":\"%s\",\"online\":%d,\"rosters\":%u,\"result\":%d}\n",
        escaped, online, emitted_rosters, result);
    free(escaped);
    if (n < 0 || (size_t)n >= sizeof(event)) fixture_fatal("logout event size");
    append_event(event);
    return result;
}

const char *st_fixture_milestone(const char *path, const char *tenant, const char *username, const char *step)
{
    if (observer_directory() != NULL) {
        char *owner = st_json_escape(username), *kind = st_json_escape(step), *scope = st_json_escape(tenant);
        if (owner == NULL || kind == NULL || scope == NULL) fixture_fatal("escape milestone");
        char event[4096];
        int n = snprintf(event, sizeof(event),
            "{\"kind\":\"metric\",\"tenant\":\"%s\",\"owner\":\"%s\",\"step\":\"%s\"}\n", scope, owner, kind);
        free(owner); free(kind); free(scope);
        if (n < 0 || (size_t)n >= sizeof(event)) fixture_fatal("milestone event size");
        append_event(event);
    }
    return st_product_metrics_milestone(path, tenant, username, step);
}
