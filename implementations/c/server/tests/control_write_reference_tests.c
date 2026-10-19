#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>

static ssize_t fixture_send(int fd, const void *buffer, size_t len, int flags);
static int fixture_mutex_lock(pthread_mutex_t *lock);

/* Exercise the production private writer, not a reimplementation. The two substituted libc
 * calls belong only to this executable. The normal server is compiled from main.c unchanged. */
#define main specus_server_entry_for_control_reference
#define send fixture_send
#define pthread_mutex_lock fixture_mutex_lock
#include "../src/main.c"
#undef pthread_mutex_lock
#undef send
#undef main

typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t changed;
    pthread_mutex_t *writer_lock;
    int fd;
    int mode; /* 1: prefix then error; 2: hold after the prefix until explicitly released. */
    unsigned int calls;
    size_t cut;
    int held;
    int released;
    int second_queued;
} write_fixture;

static write_fixture fixture = {.lock = PTHREAD_MUTEX_INITIALIZER, .fd = -1};
static _Thread_local int second_writer;

static int fixture_mutex_lock(pthread_mutex_t *lock)
{
    if (second_writer && lock == fixture.writer_lock) {
        pthread_mutex_lock(&fixture.lock);
        fixture.second_queued = 1;
        pthread_cond_broadcast(&fixture.changed);
        pthread_mutex_unlock(&fixture.lock);
    }
    return pthread_mutex_lock(lock);
}

static ssize_t fixture_send(int fd, const void *buffer, size_t len, int flags)
{
    pthread_mutex_lock(&fixture.lock);
    int target = fd == fixture.fd;
    unsigned int call = target ? fixture.calls++ : 0U;
    int mode = fixture.mode;
    pthread_mutex_unlock(&fixture.lock);
    if (target && call == 0U) {
        ssize_t sent = sendto(fd, buffer, len / 2U, flags, NULL, 0);
        pthread_mutex_lock(&fixture.lock);
        fixture.cut = sent > 0 ? (size_t)sent : 0U;
        if (mode == 2) {
            fixture.held = 1;
            pthread_cond_broadcast(&fixture.changed);
            while (!fixture.released) pthread_cond_wait(&fixture.changed, &fixture.lock);
        }
        pthread_mutex_unlock(&fixture.lock);
        return sent;
    }
    if (target && mode == 1 && call == 1U) {
        errno = ECONNRESET;
        return -1;
    }
    return sendto(fd, buffer, len, flags, NULL, 0);
}

static int wait_for(int *flag)
{
    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += 5;
    while (!*flag) {
        int rc = pthread_cond_timedwait(&fixture.changed, &fixture.lock, &deadline);
        if (rc != 0) return 1;
    }
    return 0;
}

static int read_exact(int fd, uint8_t *buffer, size_t len)
{
    size_t used = 0U;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    long long deadline = (long long)now.tv_sec * 1000LL + now.tv_nsec / 1000000L + 2000LL;
    while (used < len) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        long long remaining = deadline - ((long long)now.tv_sec * 1000LL + now.tv_nsec / 1000000L);
        if (remaining <= 0) return 1;
        struct pollfd ready = {fd, POLLIN, 0};
        int rc = poll(&ready, 1, (int)remaining);
        if (rc < 0 && errno == EINTR) continue;
        if (rc <= 0) return 1;
        ssize_t got = recv(fd, buffer + used, len - used, 0);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) return 1;
        used += (size_t)got;
    }
    return 0;
}

static st_buffer message(const char *label)
{
    char text[4200];
    size_t prefix = strlen(label);
    memcpy(text, label, prefix);
    memset(text + prefix, 'x', 4096U);
    text[prefix + 4096U] = '\0';
    return st_protocol_encode_message_response("server", "client", ST_MESSAGE_TYPE_SERVER_TO_CLIENT, text);
}

static void reset_fixture(specus_session *session, int fd, int mode)
{
    pthread_mutex_lock(&fixture.lock);
    fixture.fd = fd;
    fixture.writer_lock = &session->send_lock;
    fixture.mode = mode;
    fixture.calls = 0U;
    fixture.cut = 0U;
    fixture.held = fixture.released = fixture.second_queued = 0;
    pthread_mutex_unlock(&fixture.lock);
}

static int cut_short(void)
{
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) return 1;
    specus_session session;
    memset(&session, 0, sizeof(session));
    session.control_fd = pair[0];
    pthread_mutex_init(&session.send_lock, NULL);
    reset_fixture(&session, pair[0], 1);
    st_buffer first = message("first");
    size_t cut = first.len / 2U;
    uint8_t *expected = first.data == NULL ? NULL : malloc(cut);
    uint8_t *received = malloc(cut);
    int failed = expected == NULL || received == NULL || cut == 0U;
    if (!failed) memcpy(expected, first.data, cut);
    int first_rc = failed ? -1 : session_send_packet(&session, &first);
    if (failed) st_buffer_free(&first);
    st_buffer second = message("second");
    st_buffer heartbeat = st_protocol_encode_empty_packet(ST_CMD_HEARTBEAT_RESPONSE);
    int second_rc = session_send_packet(&session, &second);
    int heartbeat_rc = session_send_packet(&session, &heartbeat);
    failed |= first_rc != -1 || second_rc != -1 || heartbeat_rc != -1
        || !session.write_failed || fixture.calls != 2U || fixture.cut != cut;
    if (!failed) failed = read_exact(pair[1], received, cut) || memcmp(received, expected, cut) != 0;
    struct pollfd ready = {pair[1], POLLIN, 0};
    uint8_t extra;
    if (!failed) failed = poll(&ready, 1, 2000) <= 0 || recv(pair[1], &extra, 1U, 0) != 0;
    close(pair[0]); close(pair[1]);
    fixture.fd = -1;
    pthread_mutex_destroy(&session.send_lock);
    free(expected); free(received);
    if (!failed) puts("control write reference: positive partial frame then reset, closed channel, second/heartbeat rejected and no following bytes passed");
    else fputs("FAIL control write reference: cut frame did not poison and close the writer\n", stderr);
    return failed;
}

typedef struct {
    specus_session *session;
    st_buffer packet;
    int second;
    int result;
    atomic_int done;
} write_call;

static void *write_packet(void *opaque)
{
    write_call *call = opaque;
    second_writer = call->second;
    call->result = session_send_packet(call->session, &call->packet);
    atomic_store(&call->done, 1);
    return NULL;
}

static int held_frame(void)
{
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) return 1;
    specus_session session;
    memset(&session, 0, sizeof(session));
    session.control_fd = pair[0];
    pthread_mutex_init(&session.send_lock, NULL);
    reset_fixture(&session, pair[0], 2);
    write_call first = {.session = &session, .packet = message("first"), .result = -9};
    write_call second = {.session = &session, .packet = message("second"), .second = 1, .result = -9};
    size_t total = first.packet.len + second.packet.len;
    size_t cut = first.packet.len / 2U;
    uint8_t *expected = malloc(total), *received = malloc(total);
    int failed = expected == NULL || received == NULL || first.packet.data == NULL || second.packet.data == NULL;
    if (!failed) {
        memcpy(expected, first.packet.data, first.packet.len);
        memcpy(expected + first.packet.len, second.packet.data, second.packet.len);
    }
    pthread_t threads[2];
    int first_started = 0, second_started = 0;
    if (!failed) { first_started = pthread_create(&threads[0], NULL, write_packet, &first) == 0; failed = !first_started; }
    pthread_mutex_lock(&fixture.lock);
    if (!failed) failed = wait_for(&fixture.held);
    pthread_mutex_unlock(&fixture.lock);
    if (!failed) { second_started = pthread_create(&threads[1], NULL, write_packet, &second) == 0; failed = !second_started; }
    pthread_mutex_lock(&fixture.lock);
    if (!failed) failed = wait_for(&fixture.second_queued);
    if (!failed) failed = fixture.cut != cut || atomic_load(&first.done) || atomic_load(&second.done);
    pthread_mutex_unlock(&fixture.lock);
    if (!failed) {
        int locked = pthread_mutex_trylock(&session.send_lock);
        if (locked == 0) pthread_mutex_unlock(&session.send_lock);
        failed = locked != EBUSY;
    }
    if (!failed) failed = read_exact(pair[1], received, cut) || memcmp(received, expected, cut) != 0;
    pthread_mutex_lock(&fixture.lock);
    fixture.released = 1;
    pthread_cond_broadcast(&fixture.changed);
    pthread_mutex_unlock(&fixture.lock);
    if (first_started) pthread_join(threads[0], NULL); else st_buffer_free(&first.packet);
    if (second_started) pthread_join(threads[1], NULL); else st_buffer_free(&second.packet);
    if (!failed) failed = first.result != 0 || second.result != 0 || session.write_failed
        || read_exact(pair[1], received + cut, total - cut) || memcmp(received, expected, total) != 0;
    st_buffer heartbeat = st_protocol_encode_empty_packet(ST_CMD_HEARTBEAT_RESPONSE);
    uint8_t heartbeat_bytes[ST_HEADER_SIZE];
    if (!failed) failed = heartbeat.data == NULL || heartbeat.len != sizeof(heartbeat_bytes);
    if (!failed) memcpy(heartbeat_bytes, heartbeat.data, sizeof(heartbeat_bytes));
    int heartbeat_rc = session_send_packet(&session, &heartbeat);
    if (!failed) failed = heartbeat_rc != 0 || read_exact(pair[1], received, sizeof(heartbeat_bytes))
        || memcmp(received, heartbeat_bytes, sizeof(heartbeat_bytes)) != 0;
    close(pair[0]); close(pair[1]);
    fixture.fd = -1;
    pthread_mutex_destroy(&session.send_lock);
    free(expected); free(received);
    if (!failed) puts("control write reference: held prefix/actual second lock entrant/no early return, exact whole-frame order and live heartbeat passed");
    else fputs("FAIL control write reference: held frame was not serialized to completion\n", stderr);
    return failed;
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    pthread_condattr_t attr;
    if (pthread_condattr_init(&attr) != 0) return 1;
    int ok = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) == 0
        && pthread_cond_init(&fixture.changed, &attr) == 0;
    pthread_condattr_destroy(&attr);
    if (!ok) return 1;
    int failed = cut_short();
    failed |= held_frame();
    pthread_cond_destroy(&fixture.changed);
    pthread_mutex_destroy(&fixture.lock);
    if (!failed) puts("control write reference:2 Java methods, production private writer and real socketpair passed");
    return failed;
}
