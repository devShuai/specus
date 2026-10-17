#define _POSIX_C_SOURCE 200809L
#include "control_lifecycle.h"
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#define ST_CONTROL_BUCKETS 256U
struct st_control_lifecycle {
    long long client_id;
    size_t references;
    pthread_mutex_t mutex;
    struct st_control_lifecycle *next;
};
static pthread_mutex_t table_lock = PTHREAD_MUTEX_INITIALIZER;
static st_control_lifecycle *buckets[ST_CONTROL_BUCKETS];
static size_t gate_count;

st_control_lifecycle *st_control_lifecycle_retain(long long client_id)
{
    if (client_id < 0) return NULL;
    size_t bucket = (size_t)((uint64_t)client_id % ST_CONTROL_BUCKETS);
    pthread_mutex_lock(&table_lock);
    st_control_lifecycle *gate = buckets[bucket];
    while (gate != NULL && gate->client_id != client_id) gate = gate->next;
    if (gate != NULL) ++gate->references;
    else if (gate_count < ST_CONTROL_LIFECYCLE_CAPACITY) {
        gate = calloc(1, sizeof(*gate));
        if (gate != NULL) {
            if (pthread_mutex_init(&gate->mutex, NULL) != 0) { free(gate); gate = NULL; }
            else {
                gate->client_id = client_id;
                gate->references = 1U;
                gate->next = buckets[bucket];
                buckets[bucket] = gate;
                ++gate_count;
            }
        }
    }
    pthread_mutex_unlock(&table_lock);
    return gate;
}

void st_control_lifecycle_release(st_control_lifecycle *gate)
{
    if (gate == NULL) return;
    pthread_mutex_lock(&table_lock);
    if (--gate->references == 0U) {
        size_t bucket = (size_t)((uint64_t)gate->client_id % ST_CONTROL_BUCKETS);
        st_control_lifecycle **cursor = &buckets[bucket];
        while (*cursor != gate) cursor = &(*cursor)->next;
        *cursor = gate->next;
        --gate_count;
        pthread_mutex_destroy(&gate->mutex);
        free(gate);
    }
    pthread_mutex_unlock(&table_lock);
}

int st_control_lifecycle_lock(st_control_lifecycle *gate, const atomic_int *cancelled, long long deadline_ms)
{
    if (gate == NULL) return -1;
    for (;;) {
        if (cancelled != NULL && atomic_load(cancelled)) return -1;
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (deadline_ms > 0 && (long long)now.tv_sec * 1000LL + now.tv_nsec / 1000000L >= deadline_ms) return -1;
        int rc = pthread_mutex_trylock(&gate->mutex);
        if (rc == 0) {
            if (cancelled != NULL && atomic_load(cancelled)) { pthread_mutex_unlock(&gate->mutex); return -1; }
            return 0;
        }
        if (rc != EBUSY) return -1;
        struct timespec interval = {0, 25L * 1000000L};
        while (nanosleep(&interval, &interval) != 0 && errno == EINTR) {}
    }
}

void st_control_lifecycle_unlock(st_control_lifecycle *gate)
{
    if (gate != NULL) pthread_mutex_unlock(&gate->mutex);
}
