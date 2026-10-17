#ifndef SPECUS_CONTROL_OUTBOX_H
#define SPECUS_CONTROL_OUTBOX_H

#include <stddef.h>

typedef struct st_control_outbox st_control_outbox;
typedef struct st_control_outbox_channel st_control_outbox_channel;
typedef struct st_control_outbox_ticket st_control_outbox_ticket;

typedef struct {
    size_t entries, bytes, channel_entries, channel_bytes, workers;
} st_control_outbox_limits;

/* Callbacks run WITHOUT the queue mutex. One delivery at a time per physical channel,
 * in reservation order; different channels share a bounded, fair worker pool. release runs
 * exactly once for every successful reservation, even on abort/cancellation. Callbacks may
 * enqueue/close, but must not wait for or destroy their own channel/outbox. */
typedef void (*st_control_outbox_deliver_fn)(void *channel_context, void *item_context,
    const unsigned char *data, size_t length);
typedef void (*st_control_outbox_release_fn)(void *item_context);

st_control_outbox *st_control_outbox_create(const st_control_outbox_limits *limits,
    st_control_outbox_deliver_fn deliver, st_control_outbox_release_fn release);
st_control_outbox_channel *st_control_outbox_channel_create(st_control_outbox *box, void *context);

/* BEFORE SQL: append an invisible placeholder and reserve entry AND byte credits, including
 * buffers being allocated/staged and deliveries in flight. Never wait for socket I/O or space.
 * Failure returns -1 and leaves item_context owned by the caller. Success takes its ownership.
 * The caller must consume every successful ticket with commit or abort, including after close. */
int st_control_outbox_reserve(st_control_outbox_channel *channel, size_t capacity,
    void *item_context, st_control_outbox_ticket **ticket);

/* Sole producer only. Pure bounded memory staging: no allocation, mutex, SQL or I/O. Suitable
 * inside a native writer; not a publication. Returns 1 if cancelled, -1 for invalid/duplicate
 * staging. close never frees a producer-owned ticket, even while this copy is in progress. */
int st_control_outbox_stage(st_control_outbox_ticket *ticket, const void *data, size_t length);

/* AFTER SQL closes: commit consumes the ticket, making it deliverable only if staged and not
 * cancelled (0 queued, 1 cancelled, -1 not staged). A native rollback must call abort instead.
 * Later ready entries cannot pass an uncommitted placeholder, but do not block other channels. */
int st_control_outbox_commit(st_control_outbox_ticket *ticket);
void st_control_outbox_abort(st_control_outbox_ticket *ticket);

/* Cancellation does not wait for pending producers or in-flight delivery. Ready entries are
 * released synchronously outside the queue mutex; release callbacks must not wait for I/O.
 * Already executing delivery callbacks cannot be recalled; the
 * transport must separately recheck its own physical-connection cancellation before writing.
 * Only reserved producers/in-flight callbacks can keep credits after close. */
void st_control_outbox_channel_close(st_control_outbox_channel *channel);
/* No SQL/registry/send locks may be held while waiting. Destroy also closes and waits. Owners
 * must stop new callers before destroy; channel context remains valid until it returns. */
void st_control_outbox_channel_wait(st_control_outbox_channel *channel);
void st_control_outbox_channel_destroy(st_control_outbox_channel *channel);
/* Refuses (-1) while any channel exists; never silently strands producer-owned reservations. */
int st_control_outbox_destroy(st_control_outbox *box);
void st_control_outbox_usage(st_control_outbox_channel *channel,
    size_t *channel_entries, size_t *channel_bytes, size_t *entries, size_t *bytes);

#endif
