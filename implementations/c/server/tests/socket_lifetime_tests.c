#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>

static ssize_t held_recv(int fd, void *buffer, size_t len, int flags);
static ssize_t held_send(int fd, const void *buffer, size_t len, int flags);
static int held_accept(int fd, struct sockaddr *address, socklen_t *length);
static int observed_create(pthread_t *thread, const pthread_attr_t *attr,
                           void *(*start)(void *), void *arg);

/* Only this executable holds libc boundaries. Production shutdown, admission, workers and
 * sockets are unchanged; each hold models descheduling immediately before real socket I/O. */
#define main specus_server_entry_for_socket_lifetime
#define recv held_recv
#define send held_send
#define accept held_accept
#define pthread_create observed_create
#include "../src/main.c"
#undef pthread_create
#undef accept
#undef send
#undef recv
#undef main
#include <fcntl.h>

#define REQUIRE(condition, message) do { if (!(condition)) { \
    fprintf(stderr, "FAIL socket lifetime mode=%d line=%d: %s\n", fixture.mode, __LINE__, message); \
    exit(1); } } while (0)

static struct {
    pthread_mutex_t lock;
    pthread_cond_t changed;
    int mode;
    int accepted_fd;
    int held;
    int released;
    int creation_failed;
    unsigned int worker_creations;
} fixture = { .lock = PTHREAD_MUTEX_INITIALIZER, .changed = PTHREAD_COND_INITIALIZER,
              .accepted_fd = -1 };

static void hold_locked(void)
{
    fixture.held = 1;
    pthread_cond_broadcast(&fixture.changed);
    while (!fixture.released) pthread_cond_wait(&fixture.changed, &fixture.lock);
}

static ssize_t held_recv(int fd, void *buffer, size_t len, int flags)
{
    pthread_mutex_lock(&fixture.lock);
    if (fixture.mode == 0 && fd == fixture.accepted_fd) hold_locked();
    pthread_mutex_unlock(&fixture.lock);
    return recv(fd, buffer, len, flags);
}

static ssize_t held_send(int fd, const void *buffer, size_t len, int flags)
{
    pthread_mutex_lock(&fixture.lock);
    if (fixture.mode == 1 && fd == fixture.accepted_fd) hold_locked();
    pthread_mutex_unlock(&fixture.lock);
    return send(fd, buffer, len, flags);
}

static int held_accept(int fd, struct sockaddr *address, socklen_t *length)
{
    int result = accept(fd, address, length);
    if (result >= 0) {
        pthread_mutex_lock(&fixture.lock);
        fixture.accepted_fd = result;
        pthread_cond_broadcast(&fixture.changed);
        if (fixture.mode >= 2 && fixture.mode <= 4) hold_locked();
        pthread_mutex_unlock(&fixture.lock);
    }
    return result;
}

static int observed_create(pthread_t *thread, const pthread_attr_t *attr,
                           void *(*start)(void *), void *arg)
{
    pthread_mutex_lock(&fixture.lock);
    int worker = start == external_writer_thread || start == external_conn_thread;
    if (worker) ++fixture.worker_creations;
    int fail = (fixture.mode == 5 && start == external_writer_thread)
        || (fixture.mode == 6 && start == external_conn_thread);
    if (fail) {
        fixture.creation_failed = 1;
        pthread_cond_broadcast(&fixture.changed);
    }
    if (fixture.mode == 7 && start == external_conn_thread) hold_locked();
    pthread_mutex_unlock(&fixture.lock);
    if (fail) { errno = EAGAIN; return EAGAIN; }
    return pthread_create(thread, attr, start, arg);
}

static void wait_fixture(int failure)
{
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 10;
    pthread_mutex_lock(&fixture.lock);
    while (!(failure ? fixture.creation_failed : fixture.held)) {
        REQUIRE(pthread_cond_timedwait(&fixture.changed, &fixture.lock, &deadline) == 0,
                "worker did not reach the selected boundary");
    }
    pthread_mutex_unlock(&fixture.lock);
}

static void release_fixture(void)
{
    pthread_mutex_lock(&fixture.lock);
    fixture.released = 1;
    pthread_cond_broadcast(&fixture.changed);
    pthread_mutex_unlock(&fixture.lock);
}

static void *shutdown_session(void *arg)
{
    session_shutdown(arg);
    return NULL;
}

static void wait_inactive(specus_session *session)
{
    struct timespec pause = {.tv_nsec = 1000000L};
    for (int i = 0; i < 10000; ++i) {
        pthread_mutex_lock(&session->map_lock);
        int inactive = !session->active;
        pthread_mutex_unlock(&session->map_lock);
        if (inactive) return;
        nanosleep(&pause, NULL);
    }
    REQUIRE(0, "session did not begin shutdown");
}

static void scenario(int mode)
{
    alarm(20);
    fixture.mode = mode;
    fixture.accepted_fd = -1;
    fixture.held = fixture.released = fixture.creation_failed = 0;
    fixture.worker_creations = 0U;
    specus_session session = {0};
    int control[2];
    REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, control) == 0, "control socketpair");
    session.control_fd = control[0];
    session.active = 1;
    session.next_stream_id = 1U;
    session.config.max_client_external_connections = 10;
    session.config.max_port_external_connections = 10;
    session.config.max_global_external_connections = 10;
    strcpy(session.config.client_name, "socket-lifetime");
    strcpy(session.config.tenant_id, "socket-lifetime");
    pthread_mutex_init(&session.send_lock, NULL);
    pthread_mutex_init(&session.map_lock, NULL);
    pthread_mutex_init(&session.direct_lock, NULL);
    char reason[256];
    REQUIRE(start_specus_listener(&session, 0, reason, sizeof(reason)) == 0, "start real listener");
    specus_listener *listener = session.listeners;
    int listener_fd = listener->fd;
    struct sockaddr_in address;
    socklen_t length = sizeof(address);
    REQUIRE(getsockname(listener_fd, (struct sockaddr *)&address, &length) == 0, "listener address");
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int peer = socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(peer >= 0 && connect(peer, (struct sockaddr *)&address, length) == 0, "public connection");

    if (mode == 1) {
        /* Wait for publication, then feed the actual writer through its production queue. */
        external_conn *conn = NULL;
        struct timespec pause = {.tv_nsec = 1000000L};
        for (int i = 0; i < 10000 && conn == NULL; ++i) {
            pthread_mutex_lock(&session.map_lock);
            conn = session.conns;
            if (conn != NULL) REQUIRE(enqueue_external_write(conn, (const uint8_t *)"payload", 7U, 0) == 0,
                                       "enqueue real public write");
            pthread_mutex_unlock(&session.map_lock);
            if (conn == NULL) nanosleep(&pause, NULL);
        }
        REQUIRE(conn != NULL, "public stream publication");
    }
    wait_fixture(mode == 5 || mode == 6);
    int accepted_fd = fixture.accepted_fd;
    REQUIRE(accepted_fd >= 0, "accept observed a real socket");

    if (mode >= 2 && mode <= 4) {
        pthread_t shutdown_thread;
        if (mode == 2) stop_specus_listener(&session, 0);
        if (mode == 3) release_session_listeners(&session);
        if (mode == 4) {
            REQUIRE(pthread_create(&shutdown_thread, NULL, shutdown_session, &session) == 0, "shutdown thread");
            wait_inactive(&session);
        }
        REQUIRE(fcntl(listener_fd, F_GETFD) >= 0, "listener descriptor closed while accept still owns it");
        release_fixture();
        if (mode == 4) pthread_join(shutdown_thread, NULL);
        else {
            pthread_join(listener->thread, NULL);
            listener->thread_started = 0;
            REQUIRE(session.conns == NULL, "late accepted socket published after listener stopped");
            session_shutdown(&session);
        }
        REQUIRE(fixture.worker_creations == 0U, "late accepted socket started workers during shutdown");
        REQUIRE(fcntl(listener_fd, F_GETFD) < 0 && errno == EBADF, "listener descriptor leaked");
    } else {
        if (mode == 7) {
            /* Reader creation is reserved but descheduled; let the already running writer exit. */
            pthread_mutex_lock(&session.map_lock);
            external_conn *conn = session.conns;
            REQUIRE(conn != NULL, "reserved stream publication");
            close_conn_locked(conn);
            pthread_mutex_unlock(&session.map_lock);
            pthread_join(conn->writer_thread, NULL);
            conn->writer_thread_started = 0;
            REQUIRE(fcntl(accepted_fd, F_GETFD) >= 0, "descriptor closed before scheduled reader starts");
            release_fixture();
        }
        stop_specus_listener(&session, 0);
        pthread_join(listener->thread, NULL);
        listener->thread_started = 0;
        external_conn *conn = session.conns;
        REQUIRE(conn != NULL, "stream remains owned until session cleanup");
        if (mode <= 1) {
            pthread_mutex_lock(&session.map_lock);
            close_conn_locked(conn);
            pthread_mutex_unlock(&session.map_lock);
            REQUIRE(fcntl(accepted_fd, F_GETFD) >= 0, "stream descriptor closed while worker still owns it");
            release_fixture();
        }
        if (conn->thread_started) { pthread_join(conn->thread, NULL); conn->thread_started = 0; }
        if (conn->writer_thread_started) { pthread_join(conn->writer_thread, NULL); conn->writer_thread_started = 0; }
        REQUIRE(fcntl(accepted_fd, F_GETFD) < 0 && errno == EBADF, "stream descriptor retained after workers exit");
        session_shutdown(&session);
    }
    REQUIRE(fcntl(accepted_fd, F_GETFD) < 0 && errno == EBADF, "accepted descriptor leaked");
    REQUIRE(global_external_connections == 0, "active connection accounting leaked");
    close(peer);
    close(control[1]);
    pthread_mutex_destroy(&session.send_lock);
    pthread_mutex_destroy(&session.map_lock);
    pthread_mutex_destroy(&session.direct_lock);
    alarm(0);
    printf("socket lifetime: mode=%d real I/O boundary, descriptor ownership and cleanup passed\n", mode);
}

int main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);
    int first = argc == 2 ? atoi(argv[1]) : 0;
    int last = argc == 2 ? first : 7;
    REQUIRE(first >= 0 && last <= 7, "scenario number");
    for (int mode = first; mode <= last; ++mode) scenario(mode);
    while (tenant_external_stats_list != NULL) {
        tenant_external_stats *next = tenant_external_stats_list->next;
        free(tenant_external_stats_list);
        tenant_external_stats_list = next;
    }
    pthread_cond_destroy(&fixture.changed);
    pthread_mutex_destroy(&fixture.lock);
    return 0;
}
