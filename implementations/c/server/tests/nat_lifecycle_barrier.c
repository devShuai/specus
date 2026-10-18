#define _POSIX_C_SOURCE 200809L
/* Test-only scheduler: pause AFTER a real bind/accept/recv, never synthesize a result.
 * Not linked into the production server. Files in the private directory arm one operation. */
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int (*native_bind)(int, const struct sockaddr *, socklen_t);
static int (*native_accept)(int, struct sockaddr *, socklen_t *);
static ssize_t (*native_recv)(int, void *, size_t, int);
static ssize_t (*native_send)(int, const void *, size_t, int);
static int (*native_listen)(int, int);
static int (*native_close)(int);
static int (*native_thread_create)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
static int (*native_mutex_destroy)(pthread_mutex_t *);
static pthread_once_t once = PTHREAD_ONCE_INIT;
static atomic_int fired;
static atomic_int watched_fd = -1;
static _Thread_local int bound_fd = -1;
static _Thread_local int late_accept;
static _Thread_local int watched_close_completed;
static _Thread_local size_t marker_matched;
static _Thread_local size_t send_marker_matched;

static void mark(const char *name, int result)
{
    const char *dir = getenv("SPECUS_TEST_NAT_LIFECYCLE_DIR");
    if (!dir) _exit(94);
    char path[512]; snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *file = fopen(path, "w");
    if (!file) _exit(95);
    fprintf(file, "%d\n", result);
    fclose(file);
}

static void symbols(void)
{
    void *b = dlsym(RTLD_NEXT, "bind"), *a = dlsym(RTLD_NEXT, "accept"), *r = dlsym(RTLD_NEXT, "recv");
    _Static_assert(sizeof(b) == sizeof(native_bind), "POSIX function pointer size");
    memcpy(&native_bind, &b, sizeof(b));
    memcpy(&native_accept, &a, sizeof(a));
    memcpy(&native_recv, &r, sizeof(r));
    void *s = dlsym(RTLD_NEXT, "send"); memcpy(&native_send, &s, sizeof(s));
    void *l = dlsym(RTLD_NEXT, "listen"), *c = dlsym(RTLD_NEXT, "close"), *t = dlsym(RTLD_NEXT, "pthread_create");
    memcpy(&native_listen, &l, sizeof(l)); memcpy(&native_close, &c, sizeof(c));
    memcpy(&native_thread_create, &t, sizeof(t));
    void *m = dlsym(RTLD_NEXT, "pthread_mutex_destroy"); memcpy(&native_mutex_destroy, &m, sizeof(m));
    if (!native_bind || !native_accept || !native_recv || !native_send || !native_listen || !native_close || !native_thread_create || !native_mutex_destroy) _exit(91);
}

static int pause_operation(const char *mode, int port, int owned_fd)
{
    const char *dir = getenv("SPECUS_TEST_NAT_LIFECYCLE_DIR");
    if (!dir || atomic_load(&fired)) return 0;
    char path[512], configured_mode[32];
    int configured_port = 0;
    snprintf(path, sizeof(path), "%s/arm", dir);
    FILE *arm = fopen(path, "r");
    if (!arm) return 0;
    int parsed = fscanf(arm, "%31s %d", configured_mode, &configured_port);
    fclose(arm);
    if (parsed != 2 || strcmp(mode, configured_mode) || (port && port != configured_port)) return 0;
    int expected = 0;
    if (!atomic_compare_exchange_strong(&fired, &expected, 1)) return 0;
    atomic_store(&watched_fd, owned_fd);
    snprintf(path, sizeof(path), "%s/ready", dir);
    int ready = open(path, O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
    if (ready < 0) _exit(92);
    close(ready);
    snprintf(path, sizeof(path), "%s/resume", dir);
    const struct timespec interval = {0, 1000000L};
    for (int i = 0; i < 30000; ++i) {
        if (access(path, F_OK) == 0) return 1;
        nanosleep(&interval, NULL);
    }
    _exit(93); /* A missing release is a test error, not a successful negative assertion. */
}

int bind(int fd, const struct sockaddr *address, socklen_t length)
{
    pthread_once(&once, symbols);
    int result = native_bind(fd, address, length);
    if (!result && address && address->sa_family == AF_INET)
        if (pause_operation("bind", ntohs(((const struct sockaddr_in *)address)->sin_port), fd)) bound_fd = fd;
    return result;
}

int accept(int fd, struct sockaddr *address, socklen_t *length)
{
    pthread_once(&once, symbols);
    int result = native_accept(fd, address, length);
    struct sockaddr_in local;
    socklen_t size = sizeof(local);
    if (result >= 0 && getsockname(fd, (struct sockaddr *)&local, &size) == 0 && local.sin_family == AF_INET)
        if (pause_operation("accept", ntohs(local.sin_port), result)) late_accept = 1;
    return result;
}

ssize_t recv(int fd, void *buffer, size_t length, int flags)
{
    pthread_once(&once, symbols);
    ssize_t result = native_recv(fd, buffer, length, flags);
    const char marker[] = "nat-retire-hold";
    /* TCP can split the marker across any number of successful recv calls. Its first byte does
     * not recur in the marker, so the only nonempty fallback prefix is that one first byte. */
    for (ssize_t i = 0; i < result; ++i) {
        char byte = ((const char *)buffer)[i];
        if (byte == marker[marker_matched]) ++marker_matched;
        else marker_matched = byte == marker[0] ? 1U : 0U;
        if (marker_matched == sizeof(marker) - 1) {
            marker_matched = 0;
            pause_operation("recv", 0, fd);
            break;
        }
    }
    return result;
}

int listen(int fd, int backlog)
{
    pthread_once(&once, symbols);
    int result = native_listen(fd, backlog);
    int saved_errno = errno;
    if (fd == bound_fd) mark("late-listen", result);
    errno = saved_errno;
    return result;
}

ssize_t send(int fd, const void *buffer, size_t length, int flags)
{
    pthread_once(&once, symbols);
    ssize_t result = native_send(fd, buffer, length, flags);
    int saved_errno = errno;
    const char marker[] = "nat-retire-hold";
    for (ssize_t i = 0; i < result; ++i) {
        char byte = ((const char *)buffer)[i];
        if (byte == marker[send_marker_matched]) ++send_marker_matched;
        else send_marker_matched = byte == marker[0] ? 1U : 0U;
        if (send_marker_matched == sizeof(marker) - 1) {
            send_marker_matched = 0;
            struct sockaddr_in local;
            socklen_t size = sizeof(local);
            if (getsockname(fd, (struct sockaddr *)&local, &size) == 0 && local.sin_family == AF_INET)
                pause_operation("send", ntohs(local.sin_port), fd);
            break;
        }
    }
    errno = saved_errno;
    return result;
}

int close(int fd)
{
    pthread_once(&once, symbols);
    int result = native_close(fd);
    int saved_errno = errno;
    int expected = fd;
    if (fd >= 0 && atomic_compare_exchange_strong(&watched_fd, &expected, -1)) {
        watched_close_completed = 1;
        mark("closed", result);
    }
    errno = saved_errno;
    return result;
}

int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start)(void *), void *arg)
{
    pthread_once(&once, symbols);
    int result = native_thread_create(thread, attr, start, arg);
    if (late_accept) mark("late-worker", result);
    return result;
}

/* For recv mode, only the DATA owner closes the watched DATA fd. In its real teardown the first
 * mutex destruction is after map/stream closure and worker joins. EOF alone is not a finally fence:
 * replacement shutdown caused EOF earlier, while this thread was still held at the recv barrier. */
int pthread_mutex_destroy(pthread_mutex_t *mutex)
{
    pthread_once(&once, symbols);
    int result = native_mutex_destroy(mutex);
    if (watched_close_completed) {
        watched_close_completed = 0;
        mark("finished", result);
    }
    return result;
}
