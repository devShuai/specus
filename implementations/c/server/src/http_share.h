#ifndef SPECUS_HTTP_SHARE_H
#define SPECUS_HTTP_SHARE_H

#include <stddef.h>
#include <stdint.h>

/*
 * Temporary HTTP shares (protocol/spec/temporary-http-share.md): the parts that need no database
 * and no socket. Tokens, path prefixes, cookies, response header rewriting and the GCRA limiters
 * live here; storage.c keeps the share rows and audit, admin_http.c the endpoints and streams.
 * The values below are fixed by the contract and checked against the shared vector.
 */
#define ST_HTTP_SHARE_TOKEN_VERSION "hs1"
#define ST_HTTP_SHARE_TOKEN_PATTERN "hs1\\.([A-Za-z0-9_-]{16})\\.([A-Za-z0-9_-]{43})"
#define ST_HTTP_SHARE_ID_BYTES 12U
#define ST_HTTP_SHARE_SECRET_BYTES 32U
#define ST_HTTP_SHARE_ID_LEN 16U
#define ST_HTTP_SHARE_SECRET_LEN 43U
#define ST_HTTP_SHARE_TOKEN_LEN 64U
#define ST_HTTP_SHARE_COOKIE_NAME "__Secure-specus_http_share"
#define ST_HTTP_SHARE_MAX_COOKIE_CANDIDATES 4U
#define ST_HTTP_SHARE_PATH_ROOT "/http-share/"
#define ST_HTTP_SHARE_LINK_ROOT "/#/http-share/"
#define ST_HTTP_SHARE_MIN_EXPIRES_SECONDS 300LL
#define ST_HTTP_SHARE_MAX_EXPIRES_SECONDS 604800LL
#define ST_HTTP_SHARE_MAX_ACTIVE_PER_ROUTE 20
#define ST_HTTP_SHARE_LABEL_MAX_CODE_POINTS 60U
#define ST_HTTP_SHARE_LABEL_MAX_BYTES (ST_HTTP_SHARE_LABEL_MAX_CODE_POINTS * 4U)
#define ST_HTTP_SHARE_PREFIX_MAX_BYTES 256U
#define ST_HTTP_SHARE_MAX_CONCURRENT 64U
#define ST_HTTP_SHARE_EXCHANGE_INTERVAL_MS 6000LL
#define ST_HTTP_SHARE_EXCHANGE_BURST 10LL
#define ST_HTTP_SHARE_REQUEST_INTERVAL_MS 50LL
#define ST_HTTP_SHARE_REQUEST_BURST 200LL
#define ST_HTTP_SHARE_LIMITER_MAX_KEYS 10000U
#define ST_HTTP_SHARE_SWEEP_INTERVAL_SECONDS 30
#define ST_HTTP_SHARE_EXPIRY_CHECK_MS 1000LL
#define ST_HTTP_SHARE_RECHECK_INTERVAL_MS 2000LL
#define ST_HTTP_SHARE_RETENTION_DAYS 30LL
#define ST_HTTP_SHARE_AUDIT_RETENTION_DAYS 180LL
#define ST_HTTP_SHARE_EXCHANGE_MAX_BODY 4096U
#define ST_HTTP_SHARE_AUDIT_DEFAULT_LIMIT 50
#define ST_HTTP_SHARE_AUDIT_MAX_LIMIT 200

#define ST_HTTP_SHARE_READ_METHOD_COUNT 2U
#define ST_HTTP_SHARE_REVOKE_REASON_COUNT 7U
#define ST_HTTP_SHARE_AUDIT_ACTION_COUNT 7U
extern const char *const st_http_share_read_methods[ST_HTTP_SHARE_READ_METHOD_COUNT];
extern const char *const st_http_share_revoke_reasons[ST_HTTP_SHARE_REVOKE_REASON_COUNT];
extern const char *const st_http_share_audit_actions[ST_HTTP_SHARE_AUDIT_ACTION_COUNT];

/* The share clock in epoch milliseconds; tests pin it (0 restores the real clock). */
long long st_http_share_now_ms(void);
void st_http_share_set_clock_for_testing(long long fixed_now_ms);

/* Token randomness comes from the CSPRNG; tests may inject a source (NULL restores the CSPRNG). */
typedef int (*st_http_share_random_source)(uint8_t *out, size_t len);
void st_http_share_set_random_for_testing(st_http_share_random_source source);

/* A new share id and token: 12 then 32 random bytes, base64url without padding. */
int st_http_share_new_token(char share_id[ST_HTTP_SHARE_ID_LEN + 1U],
                            char token[ST_HTTP_SHARE_TOKEN_LEN + 1U]);
/* 0 and the embedded share id when text (len bytes) is exactly one well-formed token. */
int st_http_share_parse_token(const char *text, size_t len, char share_id[ST_HTTP_SHARE_ID_LEN + 1U]);
int st_http_share_valid_id(const char *text, size_t len);
/* Lower-case hex SHA-256 of the whole token string. */
void st_http_share_token_hash(const char *token, size_t len, char out[65]);
/* Constant-time comparison of a candidate token's hash with the stored one. */
int st_http_share_hash_matches(const char *token, const char *expected_hex);
/* YYYY-MM-DDTHH:MM:SSZ */
void st_http_share_format_time(long long epoch_seconds, char out[32]);

/* RFC 3986 syntax normalisation of a raw path, or NULL for a path outside ASCII pchar. */
char *st_http_share_normalize_path(const char *raw, size_t len);
/* 0 and the stored form of a pathPrefix, or -1 when it must be rejected with 400. */
int st_http_share_canonical_prefix(const char *value, size_t len, char out[ST_HTTP_SHARE_PREFIX_MAX_BYTES + 1U]);
int st_http_share_path_in_scope(const char *prefix, const char *relative_path, size_t len);

typedef struct {
    long long expires_in_seconds;
    char access[5];
    char path_prefix[ST_HTTP_SHARE_PREFIX_MAX_BYTES + 1U];
    char label[ST_HTTP_SHARE_LABEL_MAX_BYTES + 1U];
    int has_label;
} st_http_share_create_fields;

/* The create body of spec 4.1: 0 with the normalised fields, -1 for 400 SHARE_REQUEST_INVALID. */
int st_http_share_parse_create_body(const char *body, size_t body_len, st_http_share_create_fields *out);
/* The exchange body of spec 5.2: 0 with the token string (malloc'd, may hold any text), else -1. */
int st_http_share_parse_exchange_body(const char *body, size_t body_len, char **token, size_t *token_len);

/*
 * Values of the share cookie that name share_id, in order, at most four; cookie_headers are the
 * values of every Cookie header in order. Returns how many were written to out.
 */
size_t st_http_share_credential_candidates(char *const *cookie_headers,
                                           size_t count,
                                           const char *share_id,
                                           char out[ST_HTTP_SHARE_MAX_COOKIE_CANDIDATES][ST_HTTP_SHARE_TOKEN_LEN + 1U]);
/* The one Cookie header sent to the device without the share cookie; *out is NULL when none. */
int st_http_share_forwarded_cookie(char *const *cookie_headers, size_t count, char **out);
/* An upstream Set-Cookie value confined to the share path; 1 (and *out NULL) when it is dropped. */
int st_http_share_scope_set_cookie(const char *value, const char *share_id, char **out);
/* Spec 6.5 applied to "Name:value" headers; the result is a new array of new strings. */
int st_http_share_rewrite_response_headers(int status,
                                           char *const *headers,
                                           size_t count,
                                           const char *share_id,
                                           char ***out,
                                           size_t *out_len);
void st_http_share_free_strings(char **values, size_t count);

/* GCRA limiter (spec 9): one theoretical arrival time per key, in memory, per instance. */
typedef struct st_http_share_gcra st_http_share_gcra;
st_http_share_gcra *st_http_share_gcra_create(long long interval_ms, long long burst, size_t max_keys);
void st_http_share_gcra_free(st_http_share_gcra *limiter);
/* 0 when the request is admitted (and charged), otherwise the Retry-After seconds (>= 1). */
long long st_http_share_gcra_take(st_http_share_gcra *limiter, const char *key, long long now_ms);
void st_http_share_gcra_reset(st_http_share_gcra *limiter);
int st_http_share_gcra_set_tat(st_http_share_gcra *limiter, const char *key, long long tat_ms);
long long st_http_share_gcra_interval(const st_http_share_gcra *limiter);
long long st_http_share_gcra_tolerance(const st_http_share_gcra *limiter);
/* The two process-wide limiters: exchange per source address and requests per share id. */
st_http_share_gcra *st_http_share_exchange_limiter(void);
st_http_share_gcra *st_http_share_request_limiter(void);

#endif
