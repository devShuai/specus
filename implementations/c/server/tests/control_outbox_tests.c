#define _POSIX_C_SOURCE 200809L
#include "control_outbox.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d: %s\n", __func__, __LINE__, #c); abort(); } } while (0)
static atomic_int fail_malloc, fail_calloc_after;
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void *__wrap_malloc(size_t length)
{
    return atomic_exchange(&fail_malloc, 0) ? NULL : __real_malloc(length);
}
void *__wrap_calloc(size_t count, size_t length)
{
    int remaining = atomic_load(&fail_calloc_after);
    if (remaining && atomic_fetch_sub(&fail_calloc_after, 1) == 1) return NULL;
    return __real_calloc(count, length);
}
typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t changed;
    int log[4096], delivered, released, block, entered, resume;
} probe;
typedef struct { probe *probe; int id; } item;

static void initialize(probe *p)
{
    memset(p, 0, sizeof(*p));
    CHECK(pthread_mutex_init(&p->lock, NULL) == 0);
    CHECK(pthread_cond_init(&p->changed, NULL) == 0);
}
static void finish(probe *p)
{
    pthread_cond_destroy(&p->changed); pthread_mutex_destroy(&p->lock);
}
static void deliver(void *channel_context, void *context, const unsigned char *data, size_t length)
{
    probe *p = channel_context; item *i = context; int id = 0;
    CHECK(p == i->probe && length == sizeof(id)); memcpy(&id, data, length); CHECK(id == i->id);
    pthread_mutex_lock(&p->lock);
    CHECK(p->delivered < 4096); p->log[p->delivered++] = id;
    if (id == p->block) {
        p->entered = 1; pthread_cond_broadcast(&p->changed);
        while (!p->resume) pthread_cond_wait(&p->changed, &p->lock);
    }
    pthread_mutex_unlock(&p->lock);
}
static void release_item(void *context)
{
    item *i = context; probe *p = i->probe;
    pthread_mutex_lock(&p->lock); ++p->released; pthread_cond_broadcast(&p->changed); pthread_mutex_unlock(&p->lock);
    free(i);
}
static st_control_outbox_ticket *reserve(st_control_outbox_channel *channel, probe *p, int id, size_t size)
{
    item *i = malloc(sizeof(*i)); CHECK(i != NULL); *i = (item){p, id};
    st_control_outbox_ticket *ticket = NULL;
    if (st_control_outbox_reserve(channel, size, i, &ticket) != 0) { free(i); return NULL; }
    return ticket;
}
static st_control_outbox_ticket *staged(st_control_outbox_channel *channel, probe *p, int id)
{
    st_control_outbox_ticket *ticket = reserve(channel, p, id, sizeof(id)); CHECK(ticket != NULL);
    CHECK(st_control_outbox_stage(ticket, &id, sizeof(id)) == 0); return ticket;
}
static void wait_probe(probe *p, int releases, int entered)
{
    struct timespec deadline; CHECK(clock_gettime(CLOCK_REALTIME, &deadline) == 0); deadline.tv_sec += 5;
    pthread_mutex_lock(&p->lock);
    while (p->released < releases || p->entered < entered)
        CHECK(pthread_cond_timedwait(&p->changed, &p->lock, &deadline) == 0);
    pthread_mutex_unlock(&p->lock);
}
static void resume_probe(probe *p)
{
    pthread_mutex_lock(&p->lock); p->resume = 1; pthread_cond_broadcast(&p->changed); pthread_mutex_unlock(&p->lock);
}
static st_control_outbox *box(size_t entries, size_t bytes, size_t per_entries, size_t per_bytes, size_t workers)
{
    st_control_outbox_limits limits = {entries, bytes, per_entries, per_bytes, workers};
    st_control_outbox *result = st_control_outbox_create(&limits, deliver, release_item); CHECK(result != NULL); return result;
}
static void invisible_and_abort(int abort_head)
{
    probe p, other; initialize(&p); initialize(&other);
    st_control_outbox *b = box(8, 128, 4, 64, 2);
    st_control_outbox_channel *a = st_control_outbox_channel_create(b, &p), *c = st_control_outbox_channel_create(b, &other);
    CHECK(a && c);
    st_control_outbox_ticket *head = staged(a, &p, 1);
    CHECK(st_control_outbox_commit(staged(a, &p, 2)) == 0);
    CHECK(st_control_outbox_commit(staged(c, &other, 3)) == 0);
    wait_probe(&other, 1, 0); /* worker completion fence, not a sleep-based absence claim */
    pthread_mutex_lock(&p.lock); CHECK(p.delivered == 0 && p.released == 0); pthread_mutex_unlock(&p.lock);
    if (abort_head) st_control_outbox_abort(head); else CHECK(st_control_outbox_commit(head) == 0);
    st_control_outbox_channel_wait(a);
    CHECK(p.released == 2 && p.delivered == (abort_head ? 1 : 2));
    CHECK(p.log[0] == (abort_head ? 2 : 1) && (abort_head || p.log[1] == 2));
    st_control_outbox_channel_destroy(a); st_control_outbox_channel_destroy(c); CHECK(st_control_outbox_destroy(b) == 0);
    finish(&p); finish(&other); printf("PASS outbox invisible head / %s / independent channel\n", abort_head ? "rollback" : "FIFO commit");
}
static void cancellation(void)
{
    probe p; initialize(&p); p.block = 10;
    st_control_outbox *b = box(8, 128, 4, 64, 2);
    st_control_outbox_channel *c = st_control_outbox_channel_create(b, &p); CHECK(c);
    CHECK(st_control_outbox_commit(staged(c, &p, 10)) == 0); wait_probe(&p, 0, 1);
    st_control_outbox_ticket *pending = staged(c, &p, 11);
    CHECK(st_control_outbox_commit(staged(c, &p, 12)) == 0);
    st_control_outbox_channel_close(c); /* must return while callback is deliberately blocked */
    size_t count, bytes, all_count, all_bytes;
    st_control_outbox_usage(c, &count, &bytes, &all_count, &all_bytes);
    CHECK(count == 2 && all_count == 2 && bytes == 8 && all_bytes == 8);
    CHECK(st_control_outbox_commit(pending) == 1); CHECK(reserve(c, &p, 13, 4) == NULL);
    resume_probe(&p); st_control_outbox_channel_wait(c);
    CHECK(p.delivered == 1 && p.released == 3 && p.log[0] == 10);
    st_control_outbox_usage(c, &count, &bytes, &all_count, &all_bytes); CHECK(!count && !bytes && !all_count && !all_bytes);
    st_control_outbox_channel_destroy(c); CHECK(st_control_outbox_destroy(b) == 0); finish(&p);
    puts("PASS outbox close retains producer/in-flight credits and releases ready entries exactly once");
}
static void limits_and_errors(void)
{
    probe p; initialize(&p);
    st_control_outbox *b = box(3, 12, 2, 8, 1);
    st_control_outbox_channel *a = st_control_outbox_channel_create(b, &p), *c = st_control_outbox_channel_create(b, &p); CHECK(a && c);
    CHECK(st_control_outbox_destroy(b) == -1);
    st_control_outbox_ticket *one = reserve(a, &p, 1, 4), *two = reserve(a, &p, 2, 4); CHECK(one && two);
    CHECK(reserve(a, &p, 3, 1) == NULL); /* per-channel entry bound */
    CHECK(reserve(c, &p, 4, 5) == NULL); /* global byte bound, not entries */
    st_control_outbox_ticket *three = reserve(c, &p, 5, 4); CHECK(three);
    CHECK(reserve(c, &p, 6, 1) == NULL); /* global entry bound */
    int id = 1; CHECK(st_control_outbox_stage(one, &id, 5) == -1);
    CHECK(st_control_outbox_stage(one, NULL, 4) == -1 && st_control_outbox_stage(one, &id, 0) == -1);
    CHECK(st_control_outbox_stage(one, &id, 4) == 0 && st_control_outbox_stage(one, &id, 4) == -1);
    st_control_outbox_abort(one); CHECK(st_control_outbox_commit(two) == -1); st_control_outbox_abort(three);
    CHECK(p.delivered == 0 && p.released == 3);
    one = staged(a, &p, 7); CHECK(st_control_outbox_commit(one) == 0); st_control_outbox_channel_wait(a);
    CHECK(p.delivered == 1 && p.released == 4);
    CHECK(reserve(a, &p, 8, 9) == NULL && reserve(a, &p, 8, 0) == NULL);
    st_control_outbox_ticket *out = (st_control_outbox_ticket *)&p;
    CHECK(st_control_outbox_reserve(NULL, 4, NULL, &out) == -1 && out == NULL);
    st_control_outbox_abort(NULL);
    st_control_outbox_channel_destroy(a); st_control_outbox_channel_destroy(c); CHECK(st_control_outbox_destroy(b) == 0); finish(&p);
    puts("PASS outbox entry/byte limits, invalid stage, refused live destruction and reclaimed quota reuse");
}
static void independent_limits_and_allocations(void)
{
    probe p; initialize(&p);
    /* Each entry test leaves ample byte credits; each byte test leaves entry credits. */
    st_control_outbox *b = box(3, 128, 2, 64, 1);
    st_control_outbox_channel *a = st_control_outbox_channel_create(b, &p), *c = st_control_outbox_channel_create(b, &p); CHECK(a && c);
    st_control_outbox_ticket *one = reserve(a, &p, 1, 1), *two = reserve(a, &p, 2, 1); CHECK(one && two);
    CHECK(reserve(a, &p, 3, 1) == NULL);
    st_control_outbox_ticket *three = reserve(c, &p, 3, 1); CHECK(three && reserve(c, &p, 4, 1) == NULL);
    st_control_outbox_abort(one); st_control_outbox_abort(two); st_control_outbox_abort(three);
    st_control_outbox_channel_destroy(a); st_control_outbox_channel_destroy(c); CHECK(st_control_outbox_destroy(b) == 0);
    b = box(8, 12, 4, 8, 1); a = st_control_outbox_channel_create(b, &p); c = st_control_outbox_channel_create(b, &p); CHECK(a && c);
    one = reserve(a, &p, 1, 5); CHECK(one && reserve(a, &p, 2, 4) == NULL);
    two = reserve(c, &p, 2, 7); CHECK(two && reserve(a, &p, 3, 1) == NULL);
    st_control_outbox_abort(one); st_control_outbox_abort(two);
    item *owned = malloc(sizeof(*owned)); CHECK(owned); *owned = (item){&p, 9};
    st_control_outbox_ticket *ticket = NULL;
    atomic_store(&fail_malloc, 1); CHECK(st_control_outbox_reserve(a, 4, owned, &ticket) == -1 && !ticket);
    atomic_store(&fail_calloc_after, 1); CHECK(st_control_outbox_reserve(a, 4, owned, &ticket) == -1 && !ticket);
    CHECK(p.released == 5); /* failed reservation never consumes caller-owned context */
    size_t count=1, bytes=1; st_control_outbox_usage(a, NULL, NULL, &count, &bytes); CHECK(!count && !bytes); free(owned);
    CHECK(st_control_outbox_commit(staged(a, &p, 10)) == 0); st_control_outbox_channel_wait(a); CHECK(p.released == 6);
    atomic_store(&fail_calloc_after, 1); CHECK(!st_control_outbox_channel_create(b, &p));
    st_control_outbox_channel_destroy(a); st_control_outbox_channel_destroy(c); CHECK(st_control_outbox_destroy(b) == 0);
    st_control_outbox_limits limits = {2, 8, 2, 8, 1};
    atomic_store(&fail_calloc_after, 1); CHECK(!st_control_outbox_create(&limits, deliver, release_item));
    atomic_store(&fail_calloc_after, 2); CHECK(!st_control_outbox_create(&limits, deliver, release_item));
    finish(&p); puts("PASS outbox four independent capacity bounds / buffer, entry, channel and pool allocation faults");
}
static void fairness(size_t workers)
{
    probe p; initialize(&p); p.block = 20;
    st_control_outbox *b = box(16, 128, 8, 64, workers);
    st_control_outbox_channel *a = st_control_outbox_channel_create(b, &p), *c = st_control_outbox_channel_create(b, &p); CHECK(a && c);
    CHECK(st_control_outbox_commit(staged(a, &p, 20)) == 0); wait_probe(&p, 0, 1);
    CHECK(st_control_outbox_commit(staged(a, &p, 21)) == 0);
    CHECK(st_control_outbox_commit(staged(a, &p, 22)) == 0);
    CHECK(st_control_outbox_commit(staged(c, &p, 30)) == 0);
    if (workers == 2) wait_probe(&p, 1, 1); /* slow a cannot consume the other worker */
    resume_probe(&p); st_control_outbox_channel_wait(a); st_control_outbox_channel_wait(c);
    CHECK(p.delivered == 4 && p.released == 4 && p.log[0] == 20 && p.log[1] == 30 && p.log[2] == 21 && p.log[3] == 22);
    st_control_outbox_channel_destroy(a); st_control_outbox_channel_destroy(c); CHECK(st_control_outbox_destroy(b) == 0); finish(&p);
    printf("PASS outbox %zu-worker fairness / one in-flight per physical channel\n", workers);
}
typedef struct { st_control_outbox_channel *channel; probe *probe; int number; } producer;
static void *produce(void *context)
{
    producer *arg = context;
    for (int n = 1; n <= 128; ++n) {
        int id = arg->number * 128 + n;
        st_control_outbox_ticket *ticket = staged(arg->channel, arg->probe, id);
        if (n % 7 == 0) st_control_outbox_abort(ticket); else CHECK(st_control_outbox_commit(ticket) == 0);
    }
    return NULL;
}
static void concurrent_producers(void)
{
    probe p; initialize(&p);
    st_control_outbox *b = box(2048, 8192, 2048, 8192, 4);
    st_control_outbox_channel *c = st_control_outbox_channel_create(b, &p); CHECK(c);
    pthread_t threads[8]; producer args[8];
    for (int i = 0; i < 8; ++i) { args[i] = (producer){c, &p, i}; CHECK(pthread_create(&threads[i], NULL, produce, &args[i]) == 0); }
    for (int i = 0; i < 8; ++i) CHECK(pthread_join(threads[i], NULL) == 0);
    st_control_outbox_channel_wait(c); CHECK(p.released == 1024 && p.delivered == 8 * 110);
    int last[8] = {0};
    for (int i = 0; i < p.delivered; ++i) {
        int owner = (p.log[i] - 1) / 128, sequence = (p.log[i] - 1) % 128 + 1;
        CHECK(sequence > last[owner] && sequence % 7 != 0); last[owner] = sequence;
    }
    st_control_outbox_channel_destroy(c); CHECK(st_control_outbox_destroy(b) == 0); finish(&p);
    puts("PASS outbox 8 concurrent producers / 1024 reservations / exact rollback release and per-producer FIFO");
}
typedef struct { st_control_outbox_ticket *ticket; const unsigned char *data; size_t length; pthread_barrier_t *start; int result; } racer;
static void *race_stage(void *context)
{
    racer *r = context; (void)pthread_barrier_wait(r->start);
    r->result = st_control_outbox_stage(r->ticket, r->data, r->length); return NULL;
}
static void concurrent_cancel(void)
{
    probe p; initialize(&p);
    st_control_outbox *b = box(2, 2U * 1024U * 1024U, 2, 2U * 1024U * 1024U, 1);
    unsigned char *data = malloc(1024U * 1024U); CHECK(data); memset(data, 0x5a, 1024U * 1024U);
    for (int n = 0; n < 128; ++n) {
        st_control_outbox_channel *c = st_control_outbox_channel_create(b, &p); CHECK(c);
        st_control_outbox_ticket *ticket = reserve(c, &p, 1, 1024U * 1024U); CHECK(ticket);
        pthread_barrier_t start; CHECK(pthread_barrier_init(&start, NULL, 2) == 0);
        racer r = {ticket, data, 1024U * 1024U, &start, -9}; pthread_t thread;
        CHECK(pthread_create(&thread, NULL, race_stage, &r) == 0); (void)pthread_barrier_wait(&start);
        st_control_outbox_channel_close(c); CHECK(pthread_join(thread, NULL) == 0); CHECK(r.result == 0 || r.result == 1);
        st_control_outbox_abort(ticket); st_control_outbox_channel_destroy(c); pthread_barrier_destroy(&start);
    }
    CHECK(p.delivered == 0 && p.released == 128); free(data); CHECK(st_control_outbox_destroy(b) == 0); finish(&p);
    puts("PASS outbox 128 close-vs-1MiB stage races / producer lifetime / no publication");
}
int main(void)
{
    st_control_outbox_limits invalid = {1, 1, 1, 1, 0};
    CHECK(!st_control_outbox_create(&invalid, deliver, release_item));
    CHECK(!st_control_outbox_create(NULL, deliver, release_item));
    invisible_and_abort(0); invisible_and_abort(1); cancellation(); limits_and_errors(); independent_limits_and_allocations();
    fairness(1); fairness(2); concurrent_producers(); concurrent_cancel(); return 0;
}
