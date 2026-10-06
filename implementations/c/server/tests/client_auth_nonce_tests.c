/*
 * The client login nonce store: the cases Java's ClientAuthNonceService*Tests cover (one pair is
 * consumed once, the API key is part of the pair) plus what an in-memory store has to show on its
 * own: the 120 s retention, an atomic check-and-insert under concurrency, and a fixed capacity that
 * refuses instead of evicting a digest that could still be replayed.
 */
#define _POSIX_C_SOURCE 200809L

#include "client_auth_nonce.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>

#define T0 1780000000000LL

static const char *result_name(st_client_auth_nonce_result result)
{
    switch (result) {
        case ST_CLIENT_AUTH_NONCE_ACCEPTED: return "accepted";
        case ST_CLIENT_AUTH_NONCE_REPLAYED: return "replayed";
        default: return "unavailable";
    }
}

static int expect(const char *what,
                  const char *api_key,
                  const char *nonce,
                  int64_t now_ms,
                  st_client_auth_nonce_result expected)
{
    st_client_auth_nonce_result actual = st_client_auth_nonce_consume(api_key, nonce, now_ms, NULL);
    if (actual != expected) {
        fprintf(stderr, "%s: (%s, %s) at %lld was %s, expected %s\n",
                what, api_key, nonce, (long long)now_ms, result_name(actual), result_name(expected));
        return 1;
    }
    return 0;
}

/* ClientAuthNonceServiceTests.duplicateNonceForSameApiKeyIsRejectedAtomically */
static int test_duplicate_nonce_for_same_api_key_is_rejected(void)
{
    st_client_auth_nonce_reset();
    return expect("first use", "api-key", "nonce", T0, ST_CLIENT_AUTH_NONCE_ACCEPTED)
        || expect("second use", "api-key", "nonce", T0, ST_CLIENT_AUTH_NONCE_REPLAYED);
}

/* ClientAuthNonceServiceIntegrationTests.consumesEachApiKeyAndNoncePairOnlyOnce */
static int test_consumes_each_api_key_and_nonce_pair_only_once(void)
{
    st_client_auth_nonce_reset();
    return expect("a/nonce", "api-key-a", "nonce", T0, ST_CLIENT_AUTH_NONCE_ACCEPTED)
        || expect("a/nonce again", "api-key-a", "nonce", T0 + 1, ST_CLIENT_AUTH_NONCE_REPLAYED)
        || expect("b/nonce", "api-key-b", "nonce", T0 + 2, ST_CLIENT_AUTH_NONCE_ACCEPTED)
        /* The API key is hashed to a fixed width before the nonce is appended, so moving the
         * separator between the two never makes two different pairs collide. */
        || expect("split 1", "k\nx", "n", T0, ST_CLIENT_AUTH_NONCE_ACCEPTED)
        || expect("split 2", "k", "x\nn", T0, ST_CLIENT_AUTH_NONCE_ACCEPTED);
}

/* The digest is kept 120 s: through the expiry instant itself (Java deletes expiresAt < now). */
static int test_digest_is_kept_for_the_ttl(void)
{
    st_client_auth_nonce_reset();
    if (expect("consumed", "api-key", "ttl", T0, ST_CLIENT_AUTH_NONCE_ACCEPTED)
        || expect("119 s later", "api-key", "ttl", T0 + 119000, ST_CLIENT_AUTH_NONCE_REPLAYED)
        || expect("at the expiry instant", "api-key", "ttl", T0 + ST_CLIENT_AUTH_NONCE_TTL_MS,
                  ST_CLIENT_AUTH_NONCE_REPLAYED)
        || expect("1 ms past the expiry", "api-key", "ttl", T0 + ST_CLIENT_AUTH_NONCE_TTL_MS + 1,
                  ST_CLIENT_AUTH_NONCE_ACCEPTED)) {
        return 1;
    }
    /* Expired digests are reclaimed as time moves on, so memory follows the live set. */
    st_client_auth_nonce_reset();
    for (int i = 0; i < 100; ++i) {
        char nonce[32];
        snprintf(nonce, sizeof(nonce), "n-%d", i);
        if (expect("fill", "api-key", nonce, T0, ST_CLIENT_AUTH_NONCE_ACCEPTED)) {
            return 1;
        }
    }
    if (expect("later", "api-key", "later", T0 + ST_CLIENT_AUTH_NONCE_TTL_MS + 1,
               ST_CLIENT_AUTH_NONCE_ACCEPTED)
        || st_client_auth_nonce_tracked() != 1U) {
        fprintf(stderr, "expired digests were not reclaimed: %zu held\n", st_client_auth_nonce_tracked());
        return 1;
    }
    return 0;
}

typedef struct {
    pthread_barrier_t *start;
    const char *nonce;
    st_client_auth_nonce_result result;
} race_arg;

static void *race_consume(void *raw)
{
    race_arg *arg = (race_arg *)raw;
    pthread_barrier_wait(arg->start);
    arg->result = st_client_auth_nonce_consume("api-key", arg->nonce, T0, NULL);
    return NULL;
}

/* Check-and-insert is one step: of many logins racing with the same pair exactly one wins. */
static int test_concurrent_consumers_of_one_pair(void)
{
    enum { THREADS = 32, ROUNDS = 50 };
    for (int round = 0; round < ROUNDS; ++round) {
        st_client_auth_nonce_reset();
        pthread_barrier_t start;
        pthread_barrier_init(&start, NULL, THREADS);
        pthread_t threads[THREADS];
        race_arg args[THREADS];
        char distinct[THREADS][32];
        int distinct_round = round % 2 == 1;
        for (int i = 0; i < THREADS; ++i) {
            snprintf(distinct[i], sizeof(distinct[i]), "nonce-%d", i);
            args[i].start = &start;
            args[i].nonce = distinct_round ? distinct[i] : "shared-nonce";
            args[i].result = ST_CLIENT_AUTH_NONCE_UNAVAILABLE;
            if (pthread_create(&threads[i], NULL, race_consume, &args[i]) != 0) {
                fprintf(stderr, "thread start failed\n");
                return 1;
            }
        }
        int accepted = 0;
        int replayed = 0;
        for (int i = 0; i < THREADS; ++i) {
            pthread_join(threads[i], NULL);
            accepted += args[i].result == ST_CLIENT_AUTH_NONCE_ACCEPTED;
            replayed += args[i].result == ST_CLIENT_AUTH_NONCE_REPLAYED;
        }
        pthread_barrier_destroy(&start);
        int expected_accepted = distinct_round ? THREADS : 1;
        if (accepted != expected_accepted || accepted + replayed != THREADS
            || st_client_auth_nonce_tracked() != (size_t)expected_accepted) {
            fprintf(stderr, "race round %d: %d accepted, %d replayed, %zu held\n",
                    round, accepted, replayed, st_client_auth_nonce_tracked());
            return 1;
        }
    }
    return 0;
}

static int fill(const char *prefix, size_t count, int64_t now_ms)
{
    for (size_t i = 0; i < count; ++i) {
        char nonce[48];
        snprintf(nonce, sizeof(nonce), "%s-%zu", prefix, i);
        if (st_client_auth_nonce_consume("api-key", nonce, now_ms, NULL) != ST_CLIENT_AUTH_NONCE_ACCEPTED) {
            fprintf(stderr, "fill %s: nonce %zu was not accepted\n", prefix, i);
            return 1;
        }
    }
    return 0;
}

/* A full store refuses new pairs until a digest expires; it never evicts a live one. */
static int test_capacity_is_bounded_and_fails_closed(void)
{
    st_client_auth_nonce_reset();
    if (fill("cap", ST_CLIENT_AUTH_NONCE_CAPACITY, T0) != 0) {
        return 1;
    }
    int64_t retry_after = 0;
    st_client_auth_nonce_result full = st_client_auth_nonce_consume("api-key", "one-more", T0 + 1000,
                                                                    &retry_after);
    /* The oldest digest is reclaimable 1 ms after T0 + 120 s, i.e. 119.001 s from now. */
    if (full != ST_CLIENT_AUTH_NONCE_UNAVAILABLE || retry_after != 120
        || st_client_auth_nonce_tracked() != ST_CLIENT_AUTH_NONCE_CAPACITY) {
        fprintf(stderr, "full store: %s, retry after %lld s, %zu held\n",
                result_name(full), (long long)retry_after, st_client_auth_nonce_tracked());
        return 1;
    }
    /* A replay is still recognised as one while the store is full, and nothing was evicted. */
    if (expect("replay while full", "api-key", "cap-0", T0 + 2000, ST_CLIENT_AUTH_NONCE_REPLAYED)
        || expect("newest while full", "api-key", "cap-65535", T0 + 2000, ST_CLIENT_AUTH_NONCE_REPLAYED)
        || expect("past the expiry", "api-key", "one-more", T0 + ST_CLIENT_AUTH_NONCE_TTL_MS + 1,
                  ST_CLIENT_AUTH_NONCE_ACCEPTED)
        || st_client_auth_nonce_tracked() != 1U) {
        fprintf(stderr, "after expiry %zu held\n", st_client_auth_nonce_tracked());
        return 1;
    }
    return 0;
}

/*
 * The store keeps to the wall clock the timestamp window uses. After the clock is stepped back,
 * a digest from before the step stays until its own expiry (a request it guards would come back
 * into the window), and a full store still finds the digests that expired behind it.
 */
static int test_clock_stepped_backwards(void)
{
    const int64_t before_step = T0 + 1000000;
    st_client_auth_nonce_reset();
    if (fill("old", ST_CLIENT_AUTH_NONCE_CAPACITY - 1U, before_step) != 0
        || expect("after the step", "api-key", "stepped", T0, ST_CLIENT_AUTH_NONCE_ACCEPTED)) {
        return 1;
    }
    /* "stepped" has expired here, but it sits behind 65535 digests that have not. */
    const int64_t later = T0 + ST_CLIENT_AUTH_NONCE_TTL_MS + 1;
    if (expect("digest from before the step", "api-key", "old-0", later, ST_CLIENT_AUTH_NONCE_REPLAYED)
        || expect("full store sweeps", "api-key", "fresh", later, ST_CLIENT_AUTH_NONCE_ACCEPTED)
        || expect("full again", "api-key", "another", later + 1, ST_CLIENT_AUTH_NONCE_UNAVAILABLE)
        || expect("old digests expire", "api-key", "old-1", before_step + ST_CLIENT_AUTH_NONCE_TTL_MS + 1,
                  ST_CLIENT_AUTH_NONCE_ACCEPTED)
        || st_client_auth_nonce_tracked() != 1U) {
        fprintf(stderr, "stepped clock: %zu held\n", st_client_auth_nonce_tracked());
        return 1;
    }
    return 0;
}

int main(void)
{
    if (test_duplicate_nonce_for_same_api_key_is_rejected() != 0
        || test_consumes_each_api_key_and_nonce_pair_only_once() != 0
        || test_digest_is_kept_for_the_ttl() != 0
        || test_concurrent_consumers_of_one_pair() != 0
        || test_capacity_is_bounded_and_fails_closed() != 0
        || test_clock_stepped_backwards() != 0) {
        return 1;
    }
    st_client_auth_nonce_reset();
    printf("client auth nonce tests passed\n");
    return 0;
}
