#include "stream_tombstones.h"

static size_t slot(const st_stream_tombstones *tombstones, size_t index)
{
    return (tombstones->start + index) % ST_STREAM_TOMBSTONE_LIMIT;
}

static int find(const st_stream_tombstones *tombstones, uint32_t stream_id, size_t *index)
{
    for (size_t i = 0U; i < tombstones->count; ++i) {
        if (tombstones->ids[slot(tombstones, i)] == stream_id) {
            *index = i;
            return 1;
        }
    }
    return 0;
}

void st_stream_tombstones_remove(st_stream_tombstones *tombstones, uint32_t stream_id)
{
    size_t index = 0U;
    if (tombstones == NULL || !find(tombstones, stream_id, &index)) {
        return;
    }
    for (size_t i = index; i + 1U < tombstones->count; ++i) {
        tombstones->ids[slot(tombstones, i)] = tombstones->ids[slot(tombstones, i + 1U)];
    }
    --tombstones->count;
}

void st_stream_tombstones_add(st_stream_tombstones *tombstones, uint32_t stream_id)
{
    if (tombstones == NULL) {
        return;
    }
    st_stream_tombstones_remove(tombstones, stream_id);
    if (tombstones->count == ST_STREAM_TOMBSTONE_LIMIT) {
        tombstones->start = slot(tombstones, 1U);
        --tombstones->count;
    }
    tombstones->ids[slot(tombstones, tombstones->count)] = stream_id;
    ++tombstones->count;
}

int st_stream_tombstones_contains(const st_stream_tombstones *tombstones, uint32_t stream_id)
{
    size_t index = 0U;
    return tombstones != NULL && find(tombstones, stream_id, &index);
}
