#define _POSIX_C_SOURCE 200809L
#include "control_outbox.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

enum ticket_state { STAGING, READY, IN_FLIGHT, CLEANUP };

struct st_control_outbox_ticket {
    st_control_outbox_channel *channel;
    struct st_control_outbox_ticket *next;
    unsigned char *data;
    size_t capacity, length;
    void *context;
    enum ticket_state state; /* box mutex, except initial unpublished allocation */
    atomic_int cancelled;
    int staged; /* sole producer, never read by close/worker before commit */
};

struct st_control_outbox_channel {
    st_control_outbox *box;
    void *context;
    st_control_outbox_ticket *head, *tail;
    struct st_control_outbox_channel *ready_prev, *ready_next;
    size_t entries, bytes;
    int closed, busy, queued;
};

struct st_control_outbox {
    pthread_mutex_t lock;
    pthread_cond_t ready, drained;
    pthread_t *threads;
    size_t thread_count, channel_count, entries, bytes;
    st_control_outbox_channel *ready_head, *ready_tail;
    st_control_outbox_limits limits;
    st_control_outbox_deliver_fn deliver;
    st_control_outbox_release_fn release;
    int stopping;
};

static void unschedule(st_control_outbox_channel *channel)
{
    st_control_outbox *box = channel->box;
    if (!channel->queued) return;
    if (channel->ready_prev) channel->ready_prev->ready_next = channel->ready_next;
    else box->ready_head = channel->ready_next;
    if (channel->ready_next) channel->ready_next->ready_prev = channel->ready_prev;
    else box->ready_tail = channel->ready_prev;
    channel->ready_next = channel->ready_prev = NULL;
    channel->queued = 0;
}

static void schedule(st_control_outbox_channel *channel)
{
    st_control_outbox *box = channel->box;
    if (channel->closed || channel->busy || channel->queued || !channel->head
        || channel->head->state != READY) return;
    channel->queued = 1;
    channel->ready_prev = box->ready_tail;
    if (box->ready_tail) box->ready_tail->ready_next = channel;
    else box->ready_head = channel;
    box->ready_tail = channel;
    pthread_cond_signal(&box->ready);
}

/* Detach while locked. Credits remain charged until release and buffer free finish. */
static void detach(st_control_outbox_ticket *ticket)
{
    st_control_outbox_channel *channel = ticket->channel;
    st_control_outbox_ticket **cursor = &channel->head, *previous = NULL;
    while (*cursor != ticket) { previous = *cursor; cursor = &(*cursor)->next; }
    *cursor = ticket->next;
    if (channel->tail == ticket) channel->tail = previous;
    ticket->next = NULL;
    ticket->state = CLEANUP;
}

static void dispose(st_control_outbox_ticket *ticket)
{
    st_control_outbox_channel *channel = ticket->channel;
    st_control_outbox *box = channel->box;
    size_t capacity = ticket->capacity;
    if (box->release) box->release(ticket->context);
    free(ticket->data);
    free(ticket);
    pthread_mutex_lock(&box->lock);
    --channel->entries; channel->bytes -= capacity;
    --box->entries; box->bytes -= capacity;
    pthread_cond_broadcast(&box->drained);
    pthread_mutex_unlock(&box->lock);
}

static void *worker(void *context)
{
    st_control_outbox *box = context;
    pthread_mutex_lock(&box->lock);
    for (;;) {
        while (!box->ready_head && !box->stopping) pthread_cond_wait(&box->ready, &box->lock);
        if (!box->ready_head && box->stopping) break;
        st_control_outbox_channel *channel = box->ready_head;
        unschedule(channel);
        st_control_outbox_ticket *ticket = channel->head;
        channel->busy = 1;
        ticket->state = IN_FLIGHT;
        pthread_mutex_unlock(&box->lock);
        if (!atomic_load(&ticket->cancelled))
            box->deliver(channel->context, ticket->context, ticket->data, ticket->length);
        /* Keep busy through release: callbacks for one channel cannot overlap, and its
         * context stays pinned until both delivery and release finish. */
        pthread_mutex_lock(&box->lock);
        detach(ticket);
        pthread_mutex_unlock(&box->lock);
        /* dispose signals drained before busy is cleared; wait also checks busy. */
        dispose(ticket);
        pthread_mutex_lock(&box->lock);
        channel->busy = 0;
        schedule(channel);
        pthread_cond_broadcast(&box->drained);
    }
    pthread_mutex_unlock(&box->lock);
    return NULL;
}

st_control_outbox *st_control_outbox_create(const st_control_outbox_limits *limits,
    st_control_outbox_deliver_fn deliver, st_control_outbox_release_fn release)
{
    if (!limits || !deliver || !limits->entries || !limits->bytes || !limits->channel_entries
        || !limits->channel_bytes || !limits->workers || limits->workers > 32U
        || limits->channel_entries > limits->entries || limits->channel_bytes > limits->bytes) return NULL;
    st_control_outbox *box = calloc(1, sizeof(*box));
    if (!box) return NULL;
    box->limits = *limits; box->deliver = deliver; box->release = release;
    if (pthread_mutex_init(&box->lock, NULL) != 0) { free(box); return NULL; }
    if (pthread_cond_init(&box->ready, NULL) != 0) { pthread_mutex_destroy(&box->lock); free(box); return NULL; }
    if (pthread_cond_init(&box->drained, NULL) != 0) {
        pthread_cond_destroy(&box->ready); pthread_mutex_destroy(&box->lock); free(box); return NULL;
    }
    box->threads = calloc(limits->workers, sizeof(*box->threads));
    if (box->threads) {
        while (box->thread_count < limits->workers) {
            if (pthread_create(&box->threads[box->thread_count], NULL, worker, box) != 0) break;
            ++box->thread_count;
        }
    }
    if (box->thread_count != limits->workers) { (void)st_control_outbox_destroy(box); return NULL; }
    return box;
}

st_control_outbox_channel *st_control_outbox_channel_create(st_control_outbox *box, void *context)
{
    if (!box) return NULL;
    st_control_outbox_channel *channel = calloc(1, sizeof(*channel));
    if (!channel) return NULL;
    channel->box = box; channel->context = context;
    pthread_mutex_lock(&box->lock);
    ++box->channel_count;
    pthread_mutex_unlock(&box->lock);
    return channel;
}

int st_control_outbox_reserve(st_control_outbox_channel *channel, size_t capacity,
    void *item_context, st_control_outbox_ticket **out)
{
    if (!out) return -1;
    *out = NULL;
    if (!channel || !capacity) return -1;
    st_control_outbox *box = channel->box;
    if (capacity > box->limits.channel_bytes) return -1;
    st_control_outbox_ticket *ticket = calloc(1, sizeof(*ticket));
    if (!ticket) return -1;
    ticket->channel = channel; ticket->capacity = capacity; ticket->state = STAGING;
    atomic_init(&ticket->cancelled, 0);
    pthread_mutex_lock(&box->lock);
    int full = channel->closed || box->stopping || channel->entries >= box->limits.channel_entries
        || box->entries >= box->limits.entries || capacity > box->limits.bytes - box->bytes
        || capacity > box->limits.channel_bytes - channel->bytes;
    if (!full) {
        ++box->entries; box->bytes += capacity;
        ++channel->entries; channel->bytes += capacity;
        if (channel->tail) channel->tail->next = ticket;
        else channel->head = ticket;
        channel->tail = ticket;
    }
    pthread_mutex_unlock(&box->lock);
    if (full) { free(ticket); return -1; }
    /* Credit is already charged and the placeholder already ordered before allocating bytes.
     * close can cancel, but cannot detach/free a producer-owned STAGING entry. */
    ticket->data = malloc(capacity);
    if (!ticket->data || atomic_load(&ticket->cancelled)) {
        /* No ownership transfer on failed reserve; do not run the user's release callback. */
        pthread_mutex_lock(&box->lock); detach(ticket); schedule(channel); pthread_mutex_unlock(&box->lock);
        size_t reserved = ticket->capacity;
        free(ticket->data); free(ticket);
        pthread_mutex_lock(&box->lock);
        --channel->entries; channel->bytes -= reserved; --box->entries; box->bytes -= reserved;
        pthread_cond_broadcast(&box->drained); pthread_mutex_unlock(&box->lock);
        return -1;
    }
    ticket->context = item_context;
    *out = ticket;
    return 0;
}

int st_control_outbox_stage(st_control_outbox_ticket *ticket, const void *data, size_t length)
{
    if (!ticket || !data || !length || length > ticket->capacity || ticket->staged) return -1;
    if (atomic_load(&ticket->cancelled)) return 1;
    memcpy(ticket->data, data, length);
    ticket->length = length;
    ticket->staged = 1;
    return atomic_load(&ticket->cancelled) ? 1 : 0;
}

void st_control_outbox_abort(st_control_outbox_ticket *ticket)
{
    if (!ticket) return;
    st_control_outbox_channel *channel = ticket->channel;
    st_control_outbox *box = channel->box;
    pthread_mutex_lock(&box->lock);
    detach(ticket); schedule(channel);
    pthread_mutex_unlock(&box->lock);
    dispose(ticket);
}

int st_control_outbox_commit(st_control_outbox_ticket *ticket)
{
    if (!ticket) return -1;
    st_control_outbox_channel *channel = ticket->channel;
    st_control_outbox *box = channel->box;
    pthread_mutex_lock(&box->lock);
    int rc = !ticket->staged ? -1 : (channel->closed || atomic_load(&ticket->cancelled) ? 1 : 0);
    if (rc != 0) {
        detach(ticket); schedule(channel); pthread_mutex_unlock(&box->lock); dispose(ticket);
    } else {
        ticket->state = READY; schedule(channel); pthread_mutex_unlock(&box->lock);
    }
    return rc;
}

void st_control_outbox_channel_close(st_control_outbox_channel *channel)
{
    if (!channel) return;
    st_control_outbox *box = channel->box;
    st_control_outbox_ticket *discard = NULL;
    pthread_mutex_lock(&box->lock);
    channel->closed = 1;
    unschedule(channel);
    st_control_outbox_ticket *ticket = channel->head;
    while (ticket) {
        st_control_outbox_ticket *next = ticket->next;
        atomic_store(&ticket->cancelled, 1);
        if (ticket->state == READY) {
            detach(ticket); ticket->next = discard; discard = ticket;
        }
        ticket = next;
    }
    pthread_mutex_unlock(&box->lock);
    while (discard) {
        st_control_outbox_ticket *next = discard->next;
        dispose(discard); discard = next;
    }
}

void st_control_outbox_channel_wait(st_control_outbox_channel *channel)
{
    if (!channel) return;
    st_control_outbox *box = channel->box;
    pthread_mutex_lock(&box->lock);
    while (channel->entries || channel->busy) pthread_cond_wait(&box->drained, &box->lock);
    pthread_mutex_unlock(&box->lock);
}

void st_control_outbox_channel_destroy(st_control_outbox_channel *channel)
{
    if (!channel) return;
    st_control_outbox_channel_close(channel);
    st_control_outbox_channel_wait(channel);
    st_control_outbox *box = channel->box;
    pthread_mutex_lock(&box->lock); --box->channel_count; pthread_mutex_unlock(&box->lock);
    free(channel);
}

int st_control_outbox_destroy(st_control_outbox *box)
{
    if (!box) return 0;
    pthread_mutex_lock(&box->lock);
    if (box->channel_count) { pthread_mutex_unlock(&box->lock); return -1; }
    box->stopping = 1;
    pthread_cond_broadcast(&box->ready);
    pthread_mutex_unlock(&box->lock);
    for (size_t i = 0; i < box->thread_count; ++i) pthread_join(box->threads[i], NULL);
    free(box->threads);
    pthread_cond_destroy(&box->drained); pthread_cond_destroy(&box->ready);
    pthread_mutex_destroy(&box->lock); free(box);
    return 0;
}

void st_control_outbox_usage(st_control_outbox_channel *channel,
    size_t *channel_entries, size_t *channel_bytes, size_t *entries, size_t *bytes)
{
    if (!channel) return;
    st_control_outbox *box = channel->box;
    pthread_mutex_lock(&box->lock);
    if (channel_entries) *channel_entries = channel->entries;
    if (channel_bytes) *channel_bytes = channel->bytes;
    if (entries) *entries = box->entries;
    if (bytes) *bytes = box->bytes;
    pthread_mutex_unlock(&box->lock);
}
