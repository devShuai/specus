#include "client_auth_nonce.h"

#include "crypto.h"
#include "storage.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

/* One bucket per slot keeps the chains short; both are powers of two. */
#define ST_CLIENT_AUTH_NONCE_BUCKETS ST_CLIENT_AUTH_NONCE_CAPACITY

/*
 * Every link below is a slot index + 1, so 0 ends a list and the zero-initialised tables are
 * already a valid empty store.
 */
typedef struct {
    uint8_t digest[ST_SHA256_LEN];
    int64_t expires_at_ms;
    /* Next slot in the same bucket chain, or on the free list. */
    uint32_t chain_next;
    /* Neighbours in insertion order, oldest first. */
    uint32_t age_prev;
    uint32_t age_next;
} st_client_auth_nonce_slot;

static pthread_mutex_t nonce_lock = PTHREAD_MUTEX_INITIALIZER;
static st_client_auth_nonce_slot nonce_slots[ST_CLIENT_AUTH_NONCE_CAPACITY];
static uint32_t nonce_buckets[ST_CLIENT_AUTH_NONCE_BUCKETS];
static uint32_t nonce_oldest = 0U;
static uint32_t nonce_newest = 0U;
/* Slots below the high-water mark that were released, linked through chain_next. */
static uint32_t nonce_free_head = 0U;
/* Slots at and above this index have never been handed out. */
static size_t nonce_high_water = 0U;
static size_t nonce_used = 0U;
/*
 * Every digest gets the same TTL, so the age list is normally in expiry order too and the oldest
 * digest is the next to expire. A wall clock stepped backwards breaks that order; from then on the
 * oldest end alone cannot find every expired digest, and a full store sweeps the whole list.
 */
static int nonce_in_expiry_order = 1;
/*
 * While out of order: a lower bound on every held expiry, known after a sweep (INT64_MIN when
 * unknown). Until now passes it nothing can be reclaimed, so a full store does not sweep again.
 */
static int64_t nonce_earliest_expiry_ms = INT64_MIN;

static int nonce_digest(const char *api_key, const char *nonce, uint8_t out[ST_SHA256_LEN])
{
    uint8_t api_key_digest[ST_SHA256_LEN];
    st_sha256((const uint8_t *)api_key, strlen(api_key), api_key_digest);
    size_t nonce_len = strlen(nonce);
    size_t len = ST_SHA256_HEX_LEN + 1U + nonce_len;
    char *material = (char *)malloc(len + 1U);
    if (material == NULL) {
        return -1;
    }
    st_hex_encode(api_key_digest, sizeof(api_key_digest), material);
    material[ST_SHA256_HEX_LEN] = '\n';
    memcpy(material + ST_SHA256_HEX_LEN + 1U, nonce, nonce_len);
    material[len] = '\0';
    st_sha256((const uint8_t *)material, len, out);
    free(material);
    return 0;
}

static size_t nonce_bucket(const uint8_t digest[ST_SHA256_LEN])
{
    uint32_t value = (uint32_t)digest[0] | ((uint32_t)digest[1] << 8)
        | ((uint32_t)digest[2] << 16) | ((uint32_t)digest[3] << 24);
    return (size_t)(value & (ST_CLIENT_AUTH_NONCE_BUCKETS - 1U));
}

/* Java deletes rows with expiresAt < now, so a digest still answers at its exact expiry instant. */
static int nonce_expired(const st_client_auth_nonce_slot *slot, int64_t now_ms)
{
    return slot->expires_at_ms < now_ms;
}

/* Unlinks a slot from its bucket chain and the age list and puts it on the free list. */
static void nonce_release(uint32_t index)
{
    st_client_auth_nonce_slot *slot = &nonce_slots[index];
    uint32_t *link = &nonce_buckets[nonce_bucket(slot->digest)];
    while (*link != 0U && *link != index + 1U) {
        link = &nonce_slots[*link - 1U].chain_next;
    }
    if (*link == index + 1U) {
        *link = slot->chain_next;
    }
    if (slot->age_prev != 0U) {
        nonce_slots[slot->age_prev - 1U].age_next = slot->age_next;
    } else {
        nonce_oldest = slot->age_next;
    }
    if (slot->age_next != 0U) {
        nonce_slots[slot->age_next - 1U].age_prev = slot->age_prev;
    } else {
        nonce_newest = slot->age_prev;
    }
    slot->age_prev = 0U;
    slot->age_next = 0U;
    slot->chain_next = nonce_free_head;
    nonce_free_head = index + 1U;
    if (--nonce_used == 0U) {
        nonce_in_expiry_order = 1;
    }
}

static void nonce_reclaim_oldest(int64_t now_ms)
{
    while (nonce_oldest != 0U && nonce_expired(&nonce_slots[nonce_oldest - 1U], now_ms)) {
        nonce_release(nonce_oldest - 1U);
    }
}

/* Reclaims every expired digest and notes whether what is left is back in expiry order. */
static void nonce_sweep(int64_t now_ms)
{
    int64_t earliest_ms = INT64_MAX;
    int64_t previous_ms = INT64_MIN;
    int ordered = 1;
    uint32_t link = nonce_oldest;
    while (link != 0U) {
        uint32_t index = link - 1U;
        link = nonce_slots[index].age_next;
        int64_t expires_at_ms = nonce_slots[index].expires_at_ms;
        if (nonce_expired(&nonce_slots[index], now_ms)) {
            nonce_release(index);
            continue;
        }
        if (expires_at_ms < previous_ms) {
            ordered = 0;
        }
        previous_ms = expires_at_ms;
        if (expires_at_ms < earliest_ms) {
            earliest_ms = expires_at_ms;
        }
    }
    nonce_in_expiry_order = ordered;
    nonce_earliest_expiry_ms = earliest_ms;
}

static int nonce_allocate(uint32_t *index)
{
    if (nonce_free_head != 0U) {
        *index = nonce_free_head - 1U;
        nonce_free_head = nonce_slots[*index].chain_next;
        return 0;
    }
    if (nonce_high_water < ST_CLIENT_AUTH_NONCE_CAPACITY) {
        *index = (uint32_t)nonce_high_water++;
        return 0;
    }
    return -1;
}

st_client_auth_nonce_result st_client_auth_nonce_consume(const char *api_key,
                                                         const char *nonce,
                                                         int64_t now_ms,
                                                         int64_t *retry_after_seconds)
{
    if (retry_after_seconds != NULL) {
        *retry_after_seconds = 0;
    }
    uint8_t digest[ST_SHA256_LEN];
    if (api_key == NULL || nonce == NULL || nonce_digest(api_key, nonce, digest) != 0) {
        if (retry_after_seconds != NULL) {
            *retry_after_seconds = 1;
        }
        return ST_CLIENT_AUTH_NONCE_UNAVAILABLE;
    }

    pthread_mutex_lock(&nonce_lock);
    nonce_reclaim_oldest(now_ms);
    size_t bucket = nonce_bucket(digest);
    for (uint32_t link = nonce_buckets[bucket]; link != 0U;) {
        uint32_t index = link - 1U;
        link = nonce_slots[index].chain_next;
        if (memcmp(nonce_slots[index].digest, digest, ST_SHA256_LEN) != 0) {
            continue;
        }
        if (!nonce_expired(&nonce_slots[index], now_ms)) {
            pthread_mutex_unlock(&nonce_lock);
            return ST_CLIENT_AUTH_NONCE_REPLAYED;
        }
        nonce_release(index);
        break;
    }

    if (nonce_used >= ST_CLIENT_AUTH_NONCE_CAPACITY && !nonce_in_expiry_order
        && now_ms > nonce_earliest_expiry_ms) {
        nonce_sweep(now_ms);
    }
    uint32_t index = 0U;
    if (nonce_used >= ST_CLIENT_AUTH_NONCE_CAPACITY || nonce_allocate(&index) != 0) {
        /* The earliest digest is reclaimable once now is past its expiry. */
        int64_t earliest_ms = nonce_in_expiry_order && nonce_oldest != 0U
            ? nonce_slots[nonce_oldest - 1U].expires_at_ms
            : nonce_earliest_expiry_ms;
        int64_t seconds = 1;
        if (earliest_ms != INT64_MIN && earliest_ms >= now_ms) {
            uint64_t wait_ms = (uint64_t)earliest_ms - (uint64_t)now_ms + 1U;
            seconds = (int64_t)((wait_ms + 999U) / 1000U);
        }
        pthread_mutex_unlock(&nonce_lock);
        if (retry_after_seconds != NULL) {
            *retry_after_seconds = seconds < 1 ? 1 : seconds;
        }
        return ST_CLIENT_AUTH_NONCE_UNAVAILABLE;
    }

    st_client_auth_nonce_slot *slot = &nonce_slots[index];
    memcpy(slot->digest, digest, sizeof(digest));
    slot->expires_at_ms = now_ms > INT64_MAX - ST_CLIENT_AUTH_NONCE_TTL_MS
        ? INT64_MAX
        : now_ms + ST_CLIENT_AUTH_NONCE_TTL_MS;
    if (nonce_newest != 0U && slot->expires_at_ms < nonce_slots[nonce_newest - 1U].expires_at_ms) {
        nonce_in_expiry_order = 0;
    }
    if (nonce_earliest_expiry_ms != INT64_MIN && slot->expires_at_ms < nonce_earliest_expiry_ms) {
        nonce_earliest_expiry_ms = slot->expires_at_ms;
    }
    slot->chain_next = nonce_buckets[bucket];
    nonce_buckets[bucket] = index + 1U;
    slot->age_prev = nonce_newest;
    slot->age_next = 0U;
    if (nonce_newest != 0U) {
        nonce_slots[nonce_newest - 1U].age_next = index + 1U;
    } else {
        nonce_oldest = index + 1U;
    }
    nonce_newest = index + 1U;
    ++nonce_used;
    pthread_mutex_unlock(&nonce_lock);
    return ST_CLIENT_AUTH_NONCE_ACCEPTED;
}

st_client_auth_nonce_result st_client_auth_nonce_consume_stored(const char *database_path,
                                                                const char *api_key,
                                                                const char *nonce,
                                                                int64_t now_ms)
{
    uint8_t digest[ST_SHA256_LEN];
    uint8_t api_key_digest[ST_SHA256_LEN];
    char nonce_id[ST_SHA256_HEX_LEN + 1U];
    char api_key_hash[ST_SHA256_HEX_LEN + 1U];
    if (database_path == NULL || api_key == NULL || nonce == NULL || nonce_digest(api_key, nonce, digest) != 0) {
        return ST_CLIENT_AUTH_NONCE_UNAVAILABLE;
    }
    st_sha256((const uint8_t *)api_key, strlen(api_key), api_key_digest);
    st_hex_encode(digest, sizeof(digest), nonce_id);
    st_hex_encode(api_key_digest, sizeof(api_key_digest), api_key_hash);
    int rc = st_storage_consume_client_auth_nonce(database_path, nonce_id, api_key_hash, (long long)now_ms,
                                                  ST_CLIENT_AUTH_NONCE_TTL_MS);
    return rc == 0 ? ST_CLIENT_AUTH_NONCE_ACCEPTED
        : rc == 1 ? ST_CLIENT_AUTH_NONCE_REPLAYED
        : ST_CLIENT_AUTH_NONCE_UNAVAILABLE;
}

size_t st_client_auth_nonce_tracked(void)
{
    pthread_mutex_lock(&nonce_lock);
    size_t used = nonce_used;
    pthread_mutex_unlock(&nonce_lock);
    return used;
}

void st_client_auth_nonce_reset(void)
{
    pthread_mutex_lock(&nonce_lock);
    memset(nonce_buckets, 0, sizeof(nonce_buckets));
    nonce_oldest = 0U;
    nonce_newest = 0U;
    nonce_free_head = 0U;
    nonce_high_water = 0U;
    nonce_used = 0U;
    nonce_in_expiry_order = 1;
    nonce_earliest_expiry_ms = INT64_MIN;
    pthread_mutex_unlock(&nonce_lock);
}
