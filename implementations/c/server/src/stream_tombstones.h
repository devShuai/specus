#ifndef SPECUS_STREAM_TOMBSTONES_H
#define SPECUS_STREAM_TOMBSTONES_H

#include <stddef.h>
#include <stdint.h>

/*
 * Per-data-connection history of recently closed NAT stream ids (protocol/spec/control-protocol.md).
 *
 * A late RST for a stream that was just closed is idempotent and is ignored, while an RST for a
 * stream that was never opened is a data-connection protocol violation. Keeping only the most
 * recent ids, as Java RecentStreamTombstones and Go recentStreamTombstones do, stops an untrusted
 * peer from growing connection state without bound. Not thread-safe: callers serialise access.
 */
#define ST_STREAM_TOMBSTONE_LIMIT 1024U

typedef struct {
    uint32_t ids[ST_STREAM_TOMBSTONE_LIMIT];
    size_t start;
    size_t count;
} st_stream_tombstones;

/* Records a closed stream as the most recent one, evicting the oldest beyond the limit. */
void st_stream_tombstones_add(st_stream_tombstones *tombstones, uint32_t stream_id);
int st_stream_tombstones_contains(const st_stream_tombstones *tombstones, uint32_t stream_id);
/* Forgets a stream id that is being opened again. */
void st_stream_tombstones_remove(st_stream_tombstones *tombstones, uint32_t stream_id);

#endif
