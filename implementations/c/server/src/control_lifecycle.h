#ifndef SPECUS_CONTROL_LIFECYCLE_H
#define SPECUS_CONTROL_LIFECYCLE_H

#include <stdatomic.h>

#define ST_CONTROL_LIFECYCLE_CAPACITY 4096U
typedef struct st_control_lifecycle st_control_lifecycle;

/* Retain BEFORE waiting and release AFTER unlocking this operation. Idle connections consume no slot. Keys are
 * authenticated immutable client IDs (0 is only the single trusted environment-token client).
 * Hash buckets share only brief table bookkeeping, never the business mutex. */
st_control_lifecycle *st_control_lifecycle_retain(long long client_id);
void st_control_lifecycle_release(st_control_lifecycle *gate);
/* 0 acquired, -1 cancelled/deadline expired. deadline_ms is CLOCK_MONOTONIC, 0 means no deadline.
 * Waiting never retains the table lock or a database connection. */
int st_control_lifecycle_lock(st_control_lifecycle *gate, const atomic_int *cancelled, long long deadline_ms);
void st_control_lifecycle_unlock(st_control_lifecycle *gate);

#endif
