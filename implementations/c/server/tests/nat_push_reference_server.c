/* Test-only entry: the ordinary server never links these observers or reads their files.
 * The real registered handler, locks, TCP state and write-failure path are still executed. */
#define _DEFAULT_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#include "admin_http.h"
#include <pthread.h>
#include <netinet/tcp.h>
#include <time.h>

static int reference_mutex_lock(pthread_mutex_t *lock);
static void reference_set_nat_control_handler(st_admin_nat_control_handler handler, void *ctx);
#define main reference_server_entry
#define pthread_mutex_lock reference_mutex_lock
#define st_admin_set_nat_control_handler reference_set_nat_control_handler
#include "../src/main.c"
#undef st_admin_set_nat_control_handler
#undef pthread_mutex_lock
#undef main

static st_admin_nat_control_handler reference_handler;
static void *reference_handler_ctx;
static _Thread_local specus_session *reference_target;

static long long reference_now_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) _Exit(97);
    return (long long)now.tv_sec * 1000LL + now.tv_nsec / 1000000LL;
}

static void reference_event(const char *name, long long value)
{
    const char *directory = getenv("SPECUS_LOGIN_TEST_GATE_DIR");
    char path[512];
    int length = directory == NULL ? -1 : snprintf(path, sizeof(path), "%s/%s", directory, name);
    if (length <= 0 || (size_t)length >= sizeof(path)) _Exit(97);
    FILE *file = fopen(path, "wx");
    /* The reference requires at least one failed write per operation, not exactly one callback. */
    if (file == NULL && errno == EEXIST) return;
    if (file == NULL) _Exit(97);
    int failed = fprintf(file, "%lld\n", value) < 0;
    if (fclose(file) != 0 || failed) _Exit(97);
}

static int reference_mutex_lock(pthread_mutex_t *lock)
{
    specus_session *target = reference_target;
    if (target != NULL && lock == &target->send_lock) {
        /* Called from the actual session_send_packet in the admin handler. The login still
         * owns this lock. Wait for an observed kernel CLOSED state, not an arbitrary RST sleep. */
        reference_event("push-send-lock-entered", target->config.client_id);
        long long deadline = reference_now_ms() + 5000LL;
        for (;;) {
            struct tcp_info info;
            socklen_t length = sizeof(info);
            if (getsockopt(target->control_fd, IPPROTO_TCP, TCP_INFO, &info, &length) != 0) _Exit(97);
            if (info.tcpi_state == TCP_CLOSE) break;
            if (reference_now_ms() >= deadline) _Exit(97);
            struct timespec interval = {0, 1000000L};
            (void)nanosleep(&interval, NULL);
        }
        reference_event("push-kernel-reset-observed", target->config.client_id);
    }
    return pthread_mutex_lock(lock);
}

static int reference_push(void *ctx, long long client_id, const char *client_name)
{
    (void)ctx;
    /* Pin exactly the real control's send lock while the registered production callback runs.
     * Lookup and reference accounting use the production registry and primitives. */
    pthread_mutex_lock(&active_session_lock);
    specus_session *target = active_session_find_role_locked(client_name, 0);
    if (target != NULL && target->config.client_id == client_id) ++target->references;
    else target = NULL;
    pthread_mutex_unlock(&active_session_lock);
    reference_target = target;
    int result = reference_handler(reference_handler_ctx, client_id, client_name);
    reference_target = NULL;
    session_reference_release(target);
    reference_event("push-handler-result", result);
    return result;
}

static void reference_set_nat_control_handler(st_admin_nat_control_handler handler, void *ctx)
{
    reference_handler = handler;
    reference_handler_ctx = ctx;
    st_admin_set_nat_control_handler(handler == NULL ? NULL : reference_push, NULL);
}

int main(void)
{
    return reference_server_entry();
}
