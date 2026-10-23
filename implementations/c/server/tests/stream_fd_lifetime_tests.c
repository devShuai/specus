#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>

static ssize_t held_recv(int fd, void *buffer, size_t len, int flags);
static ssize_t held_send(int fd, const void *buffer, size_t len, int flags);
static int held_accept(int fd, struct sockaddr *address, socklen_t *length);
static int observed_create(pthread_t *thread, const pthread_attr_t *attr,
                           void *(*start)(void *), void *arg);

/*
 * A TCP stream's reader and writer copy its descriptor under map_lock and call recv/send after
 * releasing it. Stopping the stream used to close the descriptor at once, so a worker descheduled
 * between the copy and the call could reach whatever socket got that number next, another
 * stream's included. Only this executable holds the libc boundaries, each hold modelling a worker
 * descheduled right before its real socket call; the server code is main.c unchanged. Adapted
 * from the socket lifetime fixture in codex/c-connection-rate-limit (339467d), whose listener
 * scenarios are the LATE_ACCEPT ones: a listener's descriptor was closed by whoever stopped it
 * (UNREGISTER, the connection's end) while its thread could still be in accept() on that number,
 * and a connection accepted as the listener stopped was still published.
 */
#define main specus_server_entry_for_stream_fd_lifetime
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
    fprintf(stderr, "FAIL stream fd lifetime scenario=%d line=%d: %s\n", fixture.scenario, __LINE__, message); \
    exit(1); } } while (0)

enum {
    HOLD_RECV,          /* the reader is about to recv when the stream is stopped */
    HOLD_SEND,          /* the writer is about to send when the stream is stopped */
    FAIL_WRITER,        /* the writer thread cannot be started */
    FAIL_READER,        /* the reader thread cannot be started */
    HOLD_READER_START,  /* the reader is reserved but not yet started when the stream is stopped */
    LATE_ACCEPT_AFTER_STOP,     /* accept() returned a connection, then UNREGISTER stopped the listener */
    LATE_ACCEPT_AFTER_RELEASE,  /* the same, the listener released by a newer login of the client */
    LATE_ACCEPT_DURING_SHUTDOWN, /* the same, the data connection ending */
    SCENARIOS
};

static struct {
    pthread_mutex_t lock;
    pthread_cond_t changed;
    int scenario;
    int accepted_fd;
    int held;
    int released;
    int creation_failed;
    unsigned int worker_creations;
} fixture = {.lock = PTHREAD_MUTEX_INITIALIZER, .accepted_fd = -1};

static int late_accept_scenario(int scenario)
{
    return scenario == LATE_ACCEPT_AFTER_STOP || scenario == LATE_ACCEPT_AFTER_RELEASE
        || scenario == LATE_ACCEPT_DURING_SHUTDOWN;
}

static void hold_locked(void)
{
    fixture.held = 1;
    pthread_cond_broadcast(&fixture.changed);
    while (!fixture.released) pthread_cond_wait(&fixture.changed, &fixture.lock);
}

static ssize_t held_recv(int fd, void *buffer, size_t len, int flags)
{
    pthread_mutex_lock(&fixture.lock);
    if (fixture.scenario == HOLD_RECV && fd == fixture.accepted_fd && !fixture.released) hold_locked();
    pthread_mutex_unlock(&fixture.lock);
    return recv(fd, buffer, len, flags);
}

static ssize_t held_send(int fd, const void *buffer, size_t len, int flags)
{
    pthread_mutex_lock(&fixture.lock);
    if (fixture.scenario == HOLD_SEND && fd == fixture.accepted_fd && !fixture.released) hold_locked();
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
        /* The listener thread descheduled between accept() and publishing the stream. */
        if (late_accept_scenario(fixture.scenario) && !fixture.released) hold_locked();
        pthread_mutex_unlock(&fixture.lock);
    }
    return result;
}

static int observed_create(pthread_t *thread, const pthread_attr_t *attr,
                           void *(*start)(void *), void *arg)
{
    pthread_mutex_lock(&fixture.lock);
    if (start == external_writer_thread || start == external_conn_thread) ++fixture.worker_creations;
    int fail = (fixture.scenario == FAIL_WRITER && start == external_writer_thread)
        || (fixture.scenario == FAIL_READER && start == external_conn_thread);
    if (fail) {
        fixture.creation_failed = 1;
        pthread_cond_broadcast(&fixture.changed);
    }
    if (fixture.scenario == HOLD_READER_START && start == external_conn_thread) hold_locked();
    pthread_mutex_unlock(&fixture.lock);
    if (fail) {
        errno = EAGAIN;
        return EAGAIN;
    }
    return pthread_create(thread, attr, start, arg);
}

static void wait_fixture(int creation_failure)
{
    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += 10;
    pthread_mutex_lock(&fixture.lock);
    while (!(creation_failure ? fixture.creation_failed : fixture.held)) {
        REQUIRE(pthread_cond_timedwait(&fixture.changed, &fixture.lock, &deadline) == 0,
                "the worker did not reach the selected boundary");
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

static external_conn *published_stream(specus_session *session)
{
    struct timespec pause = {.tv_nsec = 1000000L};
    for (int i = 0; i < 10000; ++i) {
        pthread_mutex_lock(&session->map_lock);
        external_conn *conn = session->conns;
        pthread_mutex_unlock(&session->map_lock);
        if (conn != NULL) return conn;
        nanosleep(&pause, NULL);
    }
    return NULL;
}

static void *shutdown_session(void *arg)
{
    session_shutdown((specus_session *)arg);
    return NULL;
}

/* session_shutdown has stopped the session's listeners and streams (and may be waiting on them). */
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
    REQUIRE(0, "the session did not begin to shut down");
}

/*
 * The listener's accept() has returned a connection and its thread is held before publishing it
 * while the listener is stopped. The descriptor must stay open (the thread will call accept() on
 * it again) and the late connection must be refused, not handed to workers.
 */
static void run_late_accept(specus_session *session, int scenario, int listener_fd, int accepted_fd)
{
    pthread_t shutdown_thread;
    if (scenario == LATE_ACCEPT_AFTER_STOP) {
        stop_specus_listener(session, 0);
    } else if (scenario == LATE_ACCEPT_AFTER_RELEASE) {
        release_session_listeners(session);
    } else {
        REQUIRE(pthread_create(&shutdown_thread, NULL, shutdown_session, session) == 0, "shutdown thread");
        wait_inactive(session);
    }
    REQUIRE(fcntl(listener_fd, F_GETFD) >= 0,
            "listener descriptor closed while its thread may still call accept() on it");
    release_fixture();
    if (scenario == LATE_ACCEPT_DURING_SHUTDOWN) {
        pthread_join(shutdown_thread, NULL);
    } else {
        session_shutdown(session);
    }
    pthread_mutex_lock(&fixture.lock);
    unsigned int created = fixture.worker_creations;
    pthread_mutex_unlock(&fixture.lock);
    REQUIRE(created == 0U, "a connection accepted as its listener stopped was published to workers");
    REQUIRE(fcntl(listener_fd, F_GETFD) < 0 && errno == EBADF, "listener descriptor leaked");
    REQUIRE(fcntl(accepted_fd, F_GETFD) < 0 && errno == EBADF, "the refused connection's descriptor leaked");
}

static void run_scenario(int scenario)
{
    alarm(20);
    fixture.scenario = scenario;
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
    strcpy(session.config.client_name, "stream-fd-lifetime");
    strcpy(session.config.tenant_id, "stream-fd-lifetime");
    pthread_mutex_init(&session.send_lock, NULL);
    pthread_mutex_init(&session.map_lock, NULL);
    pthread_mutex_init(&session.direct_lock, NULL);
    char reason[256];
    REQUIRE(start_specus_listener(&session, 0, reason, sizeof(reason)) == 0, "start a real listener");
    specus_listener *listener = session.listeners;
    int listener_fd = listener->fd;
    struct sockaddr_in address;
    socklen_t length = sizeof(address);
    REQUIRE(getsockname(listener_fd, (struct sockaddr *)&address, &length) == 0, "listener address");
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int peer = socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(peer >= 0 && connect(peer, (struct sockaddr *)&address, length) == 0, "public connection");

    if (scenario == HOLD_SEND) {
        /* Feed the real writer through its production queue once the stream is published. */
        external_conn *conn = published_stream(&session);
        REQUIRE(conn != NULL, "stream publication");
        pthread_mutex_lock(&session.map_lock);
        REQUIRE(enqueue_external_write(conn, (const uint8_t *)"payload", 7U, 0) == 0, "queue a public write");
        pthread_mutex_unlock(&session.map_lock);
    }
    wait_fixture(scenario == FAIL_WRITER || scenario == FAIL_READER);
    int accepted_fd = fixture.accepted_fd;
    REQUIRE(accepted_fd >= 0, "accept observed a real socket");

    if (late_accept_scenario(scenario)) {
        run_late_accept(&session, scenario, listener_fd, accepted_fd);
        REQUIRE(global_external_connections == 0, "active connection accounting leaked");
        close(peer);
        close(control[1]);
        pthread_mutex_destroy(&session.send_lock);
        pthread_mutex_destroy(&session.map_lock);
        pthread_mutex_destroy(&session.direct_lock);
        alarm(0);
        printf("ok   stream fd lifetime scenario %d\n", scenario);
        return;
    }
    if (scenario == HOLD_READER_START) {
        /* The reader is reserved but descheduled before it starts; the writer exits meanwhile. */
        external_conn *conn = published_stream(&session);
        REQUIRE(conn != NULL, "reserved stream publication");
        pthread_mutex_lock(&session.map_lock);
        close_conn_locked(conn);
        pthread_mutex_unlock(&session.map_lock);
        pthread_join(conn->writer_thread, NULL);
        conn->writer_thread_started = 0;
        REQUIRE(fcntl(accepted_fd, F_GETFD) >= 0, "descriptor closed before the reserved reader started");
        release_fixture();
    }
    if (scenario == HOLD_RECV || scenario == HOLD_SEND) {
        external_conn *conn = published_stream(&session);
        REQUIRE(conn != NULL, "stream publication");
        pthread_mutex_lock(&session.map_lock);
        close_conn_locked(conn);
        pthread_mutex_unlock(&session.map_lock);
        REQUIRE(fcntl(accepted_fd, F_GETFD) >= 0, "stream descriptor closed while a worker is about to use it");
        release_fixture();
    }
    stop_specus_listener(&session, 0);
    pthread_join(listener->thread, NULL);
    listener->thread_started = 0;
    external_conn *conn = session.conns;
    REQUIRE(conn != NULL, "the stream stays owned by the session until its cleanup");
    if (conn->thread_started) {
        pthread_join(conn->thread, NULL);
        conn->thread_started = 0;
    }
    if (conn->writer_thread_started) {
        pthread_join(conn->writer_thread, NULL);
        conn->writer_thread_started = 0;
    }
    REQUIRE(fcntl(accepted_fd, F_GETFD) < 0 && errno == EBADF, "stream descriptor kept after its workers ended");
    session_shutdown(&session);
    REQUIRE(global_external_connections == 0, "active connection accounting leaked");
    close(peer);
    close(control[1]);
    pthread_mutex_destroy(&session.send_lock);
    pthread_mutex_destroy(&session.map_lock);
    pthread_mutex_destroy(&session.direct_lock);
    alarm(0);
    printf("ok   stream fd lifetime scenario %d\n", scenario);
}

int main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);
    pthread_condattr_t attributes;
    if (pthread_condattr_init(&attributes) != 0 || pthread_condattr_setclock(&attributes, CLOCK_MONOTONIC) != 0
        || pthread_cond_init(&fixture.changed, &attributes) != 0) {
        return 1;
    }
    pthread_condattr_destroy(&attributes);
    int first = argc == 2 ? atoi(argv[1]) : 0;
    int last = argc == 2 ? first : SCENARIOS - 1;
    REQUIRE(first >= 0 && last < SCENARIOS, "scenario number");
    for (int scenario = first; scenario <= last; ++scenario) run_scenario(scenario);
    while (tenant_external_stats_list != NULL) {
        tenant_external_stats *next = tenant_external_stats_list->next;
        free(tenant_external_stats_list);
        tenant_external_stats_list = next;
    }
    pthread_cond_destroy(&fixture.changed);
    pthread_mutex_destroy(&fixture.lock);
    printf("stream fd lifetime tests passed\n");
    return 0;
}
