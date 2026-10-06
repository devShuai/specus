#ifndef SPECUS_CLIENT_AUTH_NONCE_H
#define SPECUS_CLIENT_AUTH_NONCE_H

#include <stddef.h>
#include <stdint.h>

/*
 * Replay protection for the HTTP client login (protocol/spec/client-auth.md): once a request's
 * signature verifies, its (apiKey, nonce) pair is consumed atomically and the digest is kept for
 * 120 s, so the same pair is refused for as long as its +-60 s timestamp window can still accept
 * it. The digest is the one Java keys its specus_client_auth_nonce rows by:
 * SHA-256(hex(SHA-256(apiKey)) + "\n" + nonce).
 *
 * The store lives in process memory with a fixed capacity. When every slot holds a digest that
 * has not expired, a new pair is refused rather than evicting one that may still be replayed.
 */
#define ST_CLIENT_AUTH_NONCE_TTL_MS 120000LL
#define ST_CLIENT_AUTH_NONCE_CAPACITY 65536U

typedef enum {
    ST_CLIENT_AUTH_NONCE_ACCEPTED = 0,
    ST_CLIENT_AUTH_NONCE_REPLAYED = 1,
    ST_CLIENT_AUTH_NONCE_UNAVAILABLE = 2
} st_client_auth_nonce_result;

/*
 * Checks and records the pair under one lock. now_ms is the wall clock the login timestamp window
 * is judged by, so a digest outlives every timestamp that window could still accept even when the
 * clock is stepped. retry_after_seconds (optional) is set when the store is full.
 */
st_client_auth_nonce_result st_client_auth_nonce_consume(const char *api_key,
                                                         const char *nonce,
                                                         int64_t now_ms,
                                                         int64_t *retry_after_seconds);

/* Digests currently held, expired ones not yet reclaimed included. For tests and diagnostics. */
size_t st_client_auth_nonce_tracked(void);

/* Intended for deterministic tests. */
void st_client_auth_nonce_reset(void);

#endif
