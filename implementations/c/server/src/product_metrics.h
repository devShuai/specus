#ifndef SPECUS_PRODUCT_METRICS_H
#define SPECUS_PRODUCT_METRICS_H

#include <stddef.h>

/*
 * Opt-in product metrics (protocol/spec/product-metrics.md): a per-tenant switch an ADMIN turns on
 * after acknowledging the disclosure, onboarding milestones the server observes on its own write
 * paths, transfer outcomes the sending browser reports with five closed-enum fields, daily
 * counters only, a retention sweep, a purge and the summary read API.
 *
 * This module owns the rules, the closed-schema parsers, the injectable clock, the per-process rate
 * limiter and every read and write of its four tables (created by st_storage_init). admin_http.c
 * routes the five endpoints here after the shared Bearer authentication and calls the milestone
 * hooks after its write paths succeed; main.c calls client_online and runs the hourly sweep.
 * Nothing here stores or logs credentials, file names, text, addresses or any identifier of a
 * room, device or visitor; logs carry only the tenant, the operation and an error class.
 */

#define ST_PRODUCT_METRICS_PATH_PREFIX "/api/admin/product-metrics/"

#define ST_PRODUCT_METRICS_SCHEMA_VERSION 1
#define ST_PRODUCT_METRICS_DISCLOSURE_VERSION 1
#define ST_PRODUCT_METRICS_RETENTION_DAYS 180
#define ST_PRODUCT_METRICS_WINDOW_DAYS 14
#define ST_PRODUCT_METRICS_MAX_BODY_BYTES 4096U
#define ST_PRODUCT_METRICS_MAX_EVENTS 20U
#define ST_PRODUCT_METRICS_MAX_RANGE_DAYS 180
#define ST_PRODUCT_METRICS_DEFAULT_PER_USER_EVENTS 120
#define ST_PRODUCT_METRICS_DEFAULT_PER_TENANT_EVENTS 3000
/* The hourly sweep's first run, after start; then every hour. */
#define ST_PRODUCT_METRICS_SWEEP_FIRST_DELAY_SECONDS 60
#define ST_PRODUCT_METRICS_SWEEP_INTERVAL_SECONDS 3600

#define ST_PRODUCT_METRICS_CODE_INVALID "PRODUCT_METRICS_INVALID"
#define ST_PRODUCT_METRICS_CODE_TOO_LARGE "PRODUCT_METRICS_TOO_LARGE"
#define ST_PRODUCT_METRICS_CODE_RATE_LIMITED "PRODUCT_METRICS_RATE_LIMITED"
#define ST_PRODUCT_METRICS_CODE_DISCLOSURE_REQUIRED "PRODUCT_METRICS_DISCLOSURE_REQUIRED"
#define ST_PRODUCT_METRICS_CODE_RANGE "PRODUCT_METRICS_RANGE"
#define ST_PRODUCT_METRICS_CODE_NOT_ALLOWED "PRODUCT_METRICS_NOT_ALLOWED"
#define ST_PRODUCT_METRICS_CODE_UNAVAILABLE "PRODUCT_METRICS_UNAVAILABLE"

/* Onboarding steps, in order. */
#define ST_PRODUCT_METRICS_STEP_ACCOUNT_CREATED "account_created"
#define ST_PRODUCT_METRICS_STEP_SIGNED_IN "signed_in"
#define ST_PRODUCT_METRICS_STEP_CREDENTIAL_CREATED "credential_created"
#define ST_PRODUCT_METRICS_STEP_CLIENT_ONLINE "client_online"
#define ST_PRODUCT_METRICS_STEP_SERVICE_PUBLISHED "service_published"

/* ---- Rules shared with the vector (sections 5 and 7.5) ---------------------------------------- */

/* The bucket of a file size in bytes, or NULL for an empty or negative size. */
const char *st_product_metrics_size_bucket(long long size_bytes);
/* The completion-time bucket (negative counts as zero), or NULL at or past the 14-day window. */
const char *st_product_metrics_duration_bucket(long long seconds);
/* Basis points rounded half up: 1 with *rate_bp set, or 0 (null) without a denominator. */
int st_product_metrics_rate_bp(long long numerator, long long denominator, long long *rate_bp);

/* ---- Configuration, clock and limiter -------------------------------------------------------- */

/*
 * The deployment flag productMetrics.allowed, read from SPECUS_PRODUCT_METRICS_ALLOWED on every
 * use (default true; "false", "0", "no" or any other text than a true value turns it off). When
 * off, no tenant can switch metrics on, settings show enabled false and nothing is collected.
 */
int st_product_metrics_allowed(void);

/* Milliseconds since the epoch from the product metrics clock. */
typedef long long (*st_product_metrics_clock)(void);
/* Replaces the clock (tests pin it to each vector op's time); NULL restores the system clock. */
void st_product_metrics_set_clock(st_product_metrics_clock clock);
long long st_product_metrics_now_ms(void);

/* Replaces the per-minute event budgets (section 8) and forgets every window. */
void st_product_metrics_set_limits(int per_user_events_per_minute, int per_tenant_events_per_minute);
/* Restores the contract's default budgets and forgets every window. */
void st_product_metrics_limiter_reset(void);

/* ---- Endpoints (section 7) -------------------------------------------------------------------- */

typedef enum {
    ST_PRODUCT_METRICS_NO_ENDPOINT = 0,
    ST_PRODUCT_METRICS_GET_SETTINGS,
    ST_PRODUCT_METRICS_PUT_SETTINGS,
    ST_PRODUCT_METRICS_PURGE,
    ST_PRODUCT_METRICS_INGEST,
    ST_PRODUCT_METRICS_SUMMARY
} st_product_metrics_endpoint;

/* Whether path (query ignored) lies under /api/admin/product-metrics/: every answer is private. */
int st_product_metrics_path(const char *path);
/* The endpoint method and path name, or ST_PRODUCT_METRICS_NO_ENDPOINT. */
st_product_metrics_endpoint st_product_metrics_match(const char *method, const char *path);

/* The authenticated management identity; tenant and username come from the session only. */
typedef struct {
    const char *tenant_id;
    const char *username;
    int admin;
} st_product_metrics_actor;

typedef struct {
    int status;
    /* malloc'd JSON; NULL for a 403 the caller answers with its usual error shape. */
    char *body;
} st_product_metrics_response;

/*
 * Runs one endpoint for an authenticated actor. raw_query is the text after '?' (or NULL); body
 * and body_len are the raw request body, which is never logged. The caller owns response->body.
 */
void st_product_metrics_handle(const char *database_path,
                               st_product_metrics_endpoint endpoint,
                               const st_product_metrics_actor *actor,
                               const char *raw_query,
                               const char *body,
                               size_t body_len,
                               st_product_metrics_response *response);
void st_product_metrics_response_free(st_product_metrics_response *response);

/* ---- Server-internal hooks (section 4.1) ----------------------------------------------------- */

/*
 * Records one onboarding milestone after the write path it belongs to succeeded. Returns the
 * effect for tests ("ignored", "started", "recorded", "completed" or "expired"); never fails the
 * caller: storage errors are logged with the tenant and the step only.
 */
const char *st_product_metrics_milestone(const char *database_path,
                                         const char *tenant_id,
                                         const char *username,
                                         const char *step);
/* Drops the account's progress row without folding it into any count: "deleted" or "ignored". */
const char *st_product_metrics_user_deleted(const char *database_path,
                                            const char *tenant_id,
                                            const char *username);
/* The four retention steps of section 9 at the clock's now; idempotent. 0 on success. */
int st_product_metrics_sweep(const char *database_path);

/*
 * Tests only: st_product_metrics_sweep calls hook(context) right after it read the switches, before
 * it reads the progress rows or deletes anything, so a test can change a switch in between. NULL
 * removes the hook.
 */
typedef void (*st_product_metrics_sweep_hook)(void *context);
void st_product_metrics_set_sweep_hook_for_testing(st_product_metrics_sweep_hook hook, void *context);

#endif
