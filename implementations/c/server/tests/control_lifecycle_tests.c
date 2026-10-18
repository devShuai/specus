#define _POSIX_C_SOURCE 200809L
#include "control_lifecycle.h"
#include <pthread.h>
#include <stdio.h>
#include <time.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL lifecycle line %d: %s\n", __LINE__, #c); return 1; } } while (0)
static long long monotonic_ms(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (long long)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}
typedef struct { st_control_lifecycle *gate; atomic_int cancelled; atomic_int entered; int result; } waiter;
static void *wait_for_gate(void *arg)
{
    waiter *state = arg;
    atomic_store(&state->entered, 1);
    state->result = st_control_lifecycle_lock(state->gate, &state->cancelled, monotonic_ms() + 2000);
    if (state->result == 0) st_control_lifecycle_unlock(state->gate);
    st_control_lifecycle_release(state->gate);
    return NULL;
}
int main(void)
{
    st_control_lifecycle *one = st_control_lifecycle_retain(1);
    st_control_lifecycle *same = st_control_lifecycle_retain(1);
    st_control_lifecycle *collision = st_control_lifecycle_retain(257);
    CHECK(one && same == one && collision && collision != one);
    CHECK(st_control_lifecycle_lock(one, NULL, 0) == 0);
    CHECK(st_control_lifecycle_lock(collision, NULL, monotonic_ms() + 100) == 0);
    st_control_lifecycle_unlock(collision);
    CHECK(st_control_lifecycle_lock(same, NULL, monotonic_ms() + 30) == -1);
    waiter state = {.gate = same, .cancelled = ATOMIC_VAR_INIT(0), .entered = ATOMIC_VAR_INIT(0), .result = 99};
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, wait_for_gate, &state) == 0);
    while (!atomic_load(&state.entered)) { struct timespec delay = {0, 1000000}; nanosleep(&delay, NULL); }
    atomic_store(&state.cancelled, 1);
    CHECK(pthread_join(thread, NULL) == 0 && state.result == -1);
    st_control_lifecycle_unlock(one);
    CHECK(st_control_lifecycle_lock(one, NULL, monotonic_ms() - 1) == -1);
    st_control_lifecycle_release(one);
    st_control_lifecycle_release(collision);
    st_control_lifecycle *all[ST_CONTROL_LIFECYCLE_CAPACITY];
    for (size_t i = 0; i < ST_CONTROL_LIFECYCLE_CAPACITY; ++i) CHECK((all[i] = st_control_lifecycle_retain((long long)i + 1)) != NULL);
    CHECK(st_control_lifecycle_retain(90000) == NULL);
    same = st_control_lifecycle_retain(1);
    CHECK(same == all[0]);
    st_control_lifecycle_release(same);
    st_control_lifecycle_release(all[0]);
    one = st_control_lifecycle_retain(90000);
    CHECK(one != NULL);
    st_control_lifecycle_release(one);
    for (size_t i = 1; i < ST_CONTROL_LIFECYCLE_CAPACITY; ++i) st_control_lifecycle_release(all[i]);
    CHECK(st_control_lifecycle_retain(-1) == NULL);
    puts("PASS exact-CID independence, same-CID exclusion, cancellation, deadline, capacity and reclamation");
    return 0;
}
