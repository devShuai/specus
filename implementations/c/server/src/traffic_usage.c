#define _POSIX_C_SOURCE 200809L
#include "traffic_usage.h"

#include "storage.h"

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define TRAFFIC_USAGE_BUCKETS 256U
#define TRAFFIC_USAGE_DEFAULT_INTERVAL_MS 5000LL

/*
 * One counter: a client's day (an empty resource key) or one of its resources ("tcp:<port>",
 * "http:<route>"), as Java keys its two maps. text holds the client name, a NUL, the key.
 */
typedef struct traffic_counter {
    struct traffic_counter *next;
    uint64_t hash;
    long long upload_bytes;
    long long download_bytes;
    size_t key_offset;
    char text[];
} traffic_counter;

static pthread_mutex_t counters_lock = PTHREAD_MUTEX_INITIALIZER;
static traffic_counter *counters[TRAFFIC_USAGE_BUCKETS];
/* Java's flush() is synchronized: a read that asks for one waits for one already running. */
static pthread_mutex_t flush_lock = PTHREAD_MUTEX_INITIALIZER;

static struct {
    pthread_mutex_t lock;
    pthread_cond_t wake;
    pthread_t thread;
    int started;
    int stop;
    long long interval_ms;
    char database_path[512];
} flusher = {.lock = PTHREAD_MUTEX_INITIALIZER};

static uint64_t hash_text(uint64_t hash, const char *text, size_t len)
{
    for (size_t i = 0U; i < len; ++i) {
        hash ^= (unsigned char)text[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

static uint64_t counter_hash(const char *client_name, const char *prefix, const char *suffix)
{
    uint64_t hash = hash_text(14695981039346656037ULL, client_name, strlen(client_name) + 1U);
    hash = hash_text(hash, prefix, strlen(prefix));
    return hash_text(hash, suffix, strlen(suffix));
}

static int counter_matches(const traffic_counter *counter, uint64_t hash, const char *client_name,
                           const char *prefix, const char *suffix)
{
    if (counter->hash != hash || strcmp(counter->text, client_name) != 0) {
        return 0;
    }
    const char *key = counter->text + counter->key_offset;
    size_t prefix_len = strlen(prefix);
    return strncmp(key, prefix, prefix_len) == 0 && strcmp(key + prefix_len, suffix) == 0;
}

static long long saturated_add(long long value, long long bytes)
{
    if (bytes <= 0) {
        return value;
    }
    return value > LLONG_MAX - bytes ? LLONG_MAX : value + bytes;
}

/* Adds to the counter of (client_name, prefix + suffix); a counter that cannot be made is lost. */
static void record_counter(const char *client_name, const char *prefix, const char *suffix,
                           long long upload_bytes, long long download_bytes)
{
    uint64_t hash = counter_hash(client_name, prefix, suffix);
    traffic_counter **bucket = &counters[hash % TRAFFIC_USAGE_BUCKETS];
    pthread_mutex_lock(&counters_lock);
    traffic_counter *counter = *bucket;
    while (counter != NULL && !counter_matches(counter, hash, client_name, prefix, suffix)) {
        counter = counter->next;
    }
    if (counter == NULL) {
        size_t name_len = strlen(client_name);
        size_t prefix_len = strlen(prefix);
        size_t suffix_len = strlen(suffix);
        counter = (traffic_counter *)malloc(sizeof(*counter) + name_len + prefix_len + suffix_len + 2U);
        if (counter != NULL) {
            counter->hash = hash;
            counter->upload_bytes = 0;
            counter->download_bytes = 0;
            counter->key_offset = name_len + 1U;
            memcpy(counter->text, client_name, name_len + 1U);
            memcpy(counter->text + counter->key_offset, prefix, prefix_len);
            memcpy(counter->text + counter->key_offset + prefix_len, suffix, suffix_len + 1U);
            counter->next = *bucket;
            *bucket = counter;
        }
    }
    if (counter != NULL) {
        counter->upload_bytes = saturated_add(counter->upload_bytes, upload_bytes);
        counter->download_bytes = saturated_add(counter->download_bytes, download_bytes);
    }
    pthread_mutex_unlock(&counters_lock);
    if (counter == NULL) {
        fprintf(stderr, "[traffic-usage] out of memory, %lld/%lld byte(s) of %s not counted\n",
                upload_bytes, download_bytes, client_name);
    }
}

void st_traffic_usage_record_tcp(const char *client_name, int listen_port, long long upload_bytes,
                                 long long download_bytes)
{
    if (client_name == NULL || *client_name == '\0' || (upload_bytes <= 0 && download_bytes <= 0)) {
        return;
    }
    record_counter(client_name, "", "", upload_bytes, download_bytes);
    if (listen_port > 0) {
        char port[16];
        snprintf(port, sizeof(port), "%d", listen_port);
        record_counter(client_name, "tcp:", port, upload_bytes, download_bytes);
    }
}

void st_traffic_usage_record_http(const char *client_name, const char *route, long long upload_bytes,
                                  long long download_bytes)
{
    if (client_name == NULL || *client_name == '\0' || (upload_bytes <= 0 && download_bytes <= 0)) {
        return;
    }
    record_counter(client_name, "", "", upload_bytes, download_bytes);
    record_counter(client_name, "http:", route == NULL ? "" : route, upload_bytes, download_bytes);
}

/* Takes every counter out of the table, as one list. */
static traffic_counter *take_counters(size_t *count)
{
    traffic_counter *taken = NULL;
    *count = 0U;
    pthread_mutex_lock(&counters_lock);
    for (size_t i = 0U; i < TRAFFIC_USAGE_BUCKETS; ++i) {
        while (counters[i] != NULL) {
            traffic_counter *counter = counters[i];
            counters[i] = counter->next;
            counter->next = taken;
            taken = counter;
            ++*count;
        }
    }
    pthread_mutex_unlock(&counters_lock);
    return taken;
}

/* Java adds the bytes of a failed write back to its counters: merged with what came in since. */
static void restore_counters(traffic_counter *taken)
{
    pthread_mutex_lock(&counters_lock);
    while (taken != NULL) {
        traffic_counter *counter = taken;
        taken = counter->next;
        traffic_counter **bucket = &counters[counter->hash % TRAFFIC_USAGE_BUCKETS];
        traffic_counter *current = *bucket;
        while (current != NULL
               && !counter_matches(current, counter->hash, counter->text, counter->text + counter->key_offset, "")) {
            current = current->next;
        }
        if (current != NULL) {
            current->upload_bytes = saturated_add(current->upload_bytes, counter->upload_bytes);
            current->download_bytes = saturated_add(current->download_bytes, counter->download_bytes);
            free(counter);
        } else {
            counter->next = *bucket;
            *bucket = counter;
        }
    }
    pthread_mutex_unlock(&counters_lock);
}

int st_traffic_usage_flush(const char *database_path)
{
    if (database_path == NULL || *database_path == '\0') {
        return 0;
    }
    pthread_mutex_lock(&flush_lock);
    size_t count = 0U;
    traffic_counter *taken = take_counters(&count);
    if (taken == NULL) {
        pthread_mutex_unlock(&flush_lock);
        return 0;
    }
    st_storage_traffic_delta *deltas = (st_storage_traffic_delta *)calloc(count, sizeof(*deltas));
    size_t used = 0U;
    for (traffic_counter *counter = taken; deltas != NULL && counter != NULL; counter = counter->next) {
        deltas[used].client_name = counter->text;
        deltas[used].resource_key = counter->text + counter->key_offset;
        deltas[used].upload_bytes = counter->upload_bytes;
        deltas[used].download_bytes = counter->download_bytes;
        ++used;
    }
    int rc = deltas == NULL ? -1 : st_storage_flush_traffic_usage(database_path, deltas, used);
    free(deltas);
    if (rc != 0) {
        fprintf(stderr, "[traffic-usage] flush of %zu counter(s) failed; their bytes stay counted for the next one\n",
                count);
        restore_counters(taken);
    } else {
        while (taken != NULL) {
            traffic_counter *counter = taken;
            taken = counter->next;
            free(counter);
        }
    }
    pthread_mutex_unlock(&flush_lock);
    return rc;
}

static void *flusher_thread(void *arg)
{
    (void)arg;
    pthread_mutex_lock(&flusher.lock);
    while (!flusher.stop) {
        struct timespec deadline;
        clock_gettime(CLOCK_MONOTONIC, &deadline);
        deadline.tv_sec += (time_t)(flusher.interval_ms / 1000LL);
        deadline.tv_nsec += (long)(flusher.interval_ms % 1000LL) * 1000000L;
        if (deadline.tv_nsec >= 1000000000L) {
            deadline.tv_sec += 1;
            deadline.tv_nsec -= 1000000000L;
        }
        /* 0 is a wakeup before the deadline, a spurious one included: wait on until it passes. */
        int waited = 0;
        while (!flusher.stop && waited == 0) {
            waited = pthread_cond_timedwait(&flusher.wake, &flusher.lock, &deadline);
        }
        if (flusher.stop) {
            break;
        }
        pthread_mutex_unlock(&flusher.lock);
        (void)st_traffic_usage_flush(flusher.database_path);
        pthread_mutex_lock(&flusher.lock);
    }
    pthread_mutex_unlock(&flusher.lock);
    return NULL;
}

/* SPECUS_TRAFFIC_FLUSH_INTERVAL_MS as a positive number of milliseconds, else the default. */
static long long flush_interval_ms(void)
{
    const char *value = getenv("SPECUS_TRAFFIC_FLUSH_INTERVAL_MS");
    if (value == NULL || *value == '\0') {
        return TRAFFIC_USAGE_DEFAULT_INTERVAL_MS;
    }
    char *end = NULL;
    errno = 0;
    long long parsed = strtoll(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed < 1) {
        fprintf(stderr, "invalid SPECUS_TRAFFIC_FLUSH_INTERVAL_MS; using %lld\n", TRAFFIC_USAGE_DEFAULT_INTERVAL_MS);
        return TRAFFIC_USAGE_DEFAULT_INTERVAL_MS;
    }
    return parsed;
}

int st_traffic_usage_start(const char *database_path)
{
    if (database_path == NULL || *database_path == '\0') {
        return 0;
    }
    pthread_mutex_lock(&flusher.lock);
    if (flusher.started) {
        pthread_mutex_unlock(&flusher.lock);
        return 0;
    }
    pthread_condattr_t attributes;
    int rc = pthread_condattr_init(&attributes) == 0 ? 0 : -1;
    if (rc == 0) {
        rc = pthread_condattr_setclock(&attributes, CLOCK_MONOTONIC) == 0
                && pthread_cond_init(&flusher.wake, &attributes) == 0
            ? 0 : -1;
        pthread_condattr_destroy(&attributes);
    }
    if (rc == 0) {
        flusher.stop = 0;
        flusher.interval_ms = flush_interval_ms();
        snprintf(flusher.database_path, sizeof(flusher.database_path), "%s", database_path);
        if (pthread_create(&flusher.thread, NULL, flusher_thread, NULL) != 0) {
            pthread_cond_destroy(&flusher.wake);
            rc = -1;
        } else {
            flusher.started = 1;
        }
    }
    pthread_mutex_unlock(&flusher.lock);
    return rc;
}

void st_traffic_usage_stop(void)
{
    pthread_mutex_lock(&flusher.lock);
    int started = flusher.started;
    flusher.stop = 1;
    if (started) {
        pthread_cond_broadcast(&flusher.wake);
    }
    pthread_mutex_unlock(&flusher.lock);
    if (!started) {
        return;
    }
    pthread_join(flusher.thread, NULL);
    pthread_mutex_lock(&flusher.lock);
    flusher.started = 0;
    pthread_cond_destroy(&flusher.wake);
    pthread_mutex_unlock(&flusher.lock);
    (void)st_traffic_usage_flush(flusher.database_path);
}
