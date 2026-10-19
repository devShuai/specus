#define _POSIX_C_SOURCE 200809L
#include "admin_http.h"
#include "security.h"
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "lifecycle ownership check failed at line %d: %s\n", __LINE__, #x); exit(1); } } while (0)
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static int entered, released;
static atomic_uintptr_t watched;
static atomic_uint frees;
static st_connectivity_checker *last_created;
static char authorization[2400];

void __real_free(void *pointer);
void __wrap_free(void *pointer)
{
    if (pointer != NULL && (uintptr_t)pointer == atomic_load_explicit(&watched, memory_order_relaxed)) {
        atomic_fetch_add_explicit(&frees, 1U, memory_order_relaxed);
    }
    __real_free(pointer);
}
st_connectivity_checker *__real_st_connectivity_checker_new(const st_connectivity_device *device);
st_connectivity_checker *__wrap_st_connectivity_checker_new(const st_connectivity_device *device)
{
    last_created = __real_st_connectivity_checker_new(device);
    return last_created;
}

/* A deterministic barrier at the checker boundary, not an end-to-end connectivity probe.
 * The real admin endpoint must acquire/release the checker around this call. */
int __wrap_st_connectivity_handle(st_connectivity_checker *checker, const st_connectivity_request *request,
                                  st_connectivity_route_loader loader, void *ctx, st_connectivity_response *response)
{
    (void)request; (void)loader; (void)ctx;
    CHECK((uintptr_t)checker == atomic_load_explicit(&watched, memory_order_relaxed));
    CHECK(pthread_mutex_lock(&lock) == 0);
    entered = 1; CHECK(pthread_cond_broadcast(&changed) == 0);
    struct timespec until; CHECK(clock_gettime(CLOCK_REALTIME, &until) == 0); until.tv_sec += 5;
    while (!released) CHECK(pthread_cond_timedwait(&changed, &lock, &until) == 0);
    CHECK(pthread_mutex_unlock(&lock) == 0);
    memset(response, 0, sizeof(*response)); response->status = 200;
    response->body = strdup("{\"test\":\"ownership-only\"}"); CHECK(response->body != NULL);
    return 0;
}
static void presence(void *ctx, const char *name, int *control, int *data)
{ (void)ctx; (void)name; *control = 0; *data = 0; }
static void probe(void *ctx, const char *name, const char *metadata, long long timeout, st_connectivity_probe_answer *answer)
{ (void)ctx; (void)name; (void)metadata; (void)timeout; (void)answer; }
static void *held_request(void *unused)
{
    (void)unused; char response[4096];
    CHECK(st_admin_build_response_with_auth("POST", "/api/admin/http-routes/1/connectivity-check", authorization, "{}", response, sizeof(response)) > 0);
    CHECK(strncmp(response, "HTTP/1.1 200 ", 13U) == 0 && strstr(response, "ownership-only") != NULL);
    return NULL;
}
int main(void)
{
    CHECK(setenv("SPECUS_AUTH_USERNAME", "admin", 1) == 0 && setenv("SPECUS_AUTH_TENANT_ID", "default", 1) == 0
        && setenv("SPECUS_AUTH_PASSWORD", "synthetic-connectivity-pass", 1) == 0 && setenv("SPECUS_AUTH_JWT_SECRET", "synthetic-connectivity-key", 1) == 0
        && unsetenv("SPECUS_DATABASE_PATH") == 0);
    char bearer[2200]; CHECK(st_security_issue_local_token("admin", "default", "ADMIN", "synthetic-connectivity-key", 600, bearer, sizeof(bearer)) == 0);
    CHECK(snprintf(authorization, sizeof(authorization), "Bearer %s", bearer) > 0);
    const st_connectivity_device device = {presence, probe, NULL, NULL, NULL};
    for (unsigned iteration = 0U; iteration < 64U; ++iteration) {
        entered = 0; released = 0; atomic_store(&frees, 0U);
        st_admin_set_connectivity_device(&device); CHECK(last_created != NULL);
        atomic_store(&watched, (uintptr_t)last_created);
        pthread_t thread; CHECK(pthread_create(&thread, NULL, held_request, NULL) == 0);
        CHECK(pthread_mutex_lock(&lock) == 0);
        struct timespec until; CHECK(clock_gettime(CLOCK_REALTIME, &until) == 0); until.tv_sec += 5;
        while (!entered) CHECK(pthread_cond_timedwait(&changed, &lock, &until) == 0);
        CHECK(pthread_mutex_unlock(&lock) == 0);
        /* Replace a checker while a real admin call is inside it, then unpublish its successor. */
        st_admin_set_connectivity_device(&device);
        CHECK(atomic_load(&frees) == 0U);
        st_admin_set_connectivity_device(NULL);
        CHECK(atomic_load(&frees) == 0U);
        char unavailable[4096];
        CHECK(st_admin_build_response_with_auth("POST", "/api/admin/http-routes/1/connectivity-check", authorization, "{}", unavailable, sizeof(unavailable)) > 0);
        CHECK(strncmp(unavailable, "HTTP/1.1 503 ", 13U) == 0);
        CHECK(pthread_mutex_lock(&lock) == 0); released = 1;
        CHECK(pthread_cond_broadcast(&changed) == 0 && pthread_mutex_unlock(&lock) == 0);
        CHECK(pthread_join(thread, NULL) == 0);
        CHECK(atomic_load(&frees) == 1U);
        atomic_store(&watched, (uintptr_t)0U); last_created = NULL;
    }
    puts("connectivity ownership:64 deterministic in-flight replacements, no early free, exactly1 final destruction, unpublished503 passed; boundary-wrapped test, not network-probe E2E");
    return 0;
}
