#ifndef SPECUS_WORKBENCH_H
#define SPECUS_WORKBENCH_H

#include "storage.h"

/*
 * Service workbench (protocol/spec/service-workbench.md): the parts of the seven endpoints that do
 * not touch HTTP or storage -- route and reference validation, the injectable clock, the per
 * identity GCRA write limiter and the JSON document. admin_http.c runs the processing order and
 * storage.c keeps the rows.
 */

#define ST_WORKBENCH_PATH "/api/admin/workbench"
/* The largest id a browser holds exactly as a JSON number, 2^53 - 1. */
#define ST_WORKBENCH_MAX_OBJECT_ID 9007199254740991LL
/* GCRA for growth (adding a favourite, recording an open): one key per identity. */
#define ST_WORKBENCH_RATE_INTERVAL_MS 1000LL
#define ST_WORKBENCH_RATE_BURST 30LL
#define ST_WORKBENCH_RATE_MAX_KEYS 10000U

typedef enum {
    ST_WORKBENCH_GET = 0,
    ST_WORKBENCH_ADD_FAVORITE,
    ST_WORKBENCH_REMOVE_FAVORITE,
    ST_WORKBENCH_CLEAR_FAVORITES,
    ST_WORKBENCH_RECORD_VISIT,
    ST_WORKBENCH_REMOVE_RECENT,
    ST_WORKBENCH_CLEAR_RECENTS
} st_workbench_op;

typedef struct {
    st_workbench_op op;
    /* The path carries {kind}/{id}. */
    int has_reference;
    /* 0 when {kind} or {id} is not valid: the request answers 400 before anything else runs. */
    int reference_valid;
    char kind[16];
    long long object_id;
} st_workbench_request;

/*
 * 1 when method and path name a workbench endpoint, with request filled; 0 otherwise (the caller
 * answers as for any unknown path). {kind} and {id} are checked on the raw path text: kind exactly
 * one of http-route, tcp-mapping, peer-service; id decimal ASCII digits without sign or leading
 * zero, 1..2^53-1. A query string is ignored and a request body is never read.
 */
int st_workbench_match(const char *method, const char *path, st_workbench_request *request);
/* The operation name used in logs: get, add-favorite, remove-favorite, ... */
const char *st_workbench_op_name(st_workbench_op op);
int st_workbench_op_is_growth(st_workbench_op op);
st_storage_workbench_write_op st_workbench_storage_op(st_workbench_op op);

/* Milliseconds since the epoch from the workbench clock, shared by the service and the limiter. */
typedef long long (*st_workbench_clock)(void);
/* Replaces the clock (tests); NULL restores the system clock. */
void st_workbench_set_clock(st_workbench_clock clock);
long long st_workbench_now_ms(void);

/*
 * Charges one growth request of the identity at now_ms. Returns 0 when it is admitted (it costs
 * even if it then fails), otherwise how many milliseconds the caller must wait; a refused request
 * costs nothing. At most 10 000 keys are tracked: a new key first evicts entries whose TAT is not
 * after now, and is refused with a one second wait while every tracked key is still active.
 */
long long st_workbench_rate_limit_acquire(const char *tenant_id, const char *username, long long now_ms);
/* Retry-After for a refusal: whole seconds rounded up, at least 1. */
long long st_workbench_retry_after_seconds(long long wait_ms);
void st_workbench_rate_limit_reset(void);

/* The 200 document as a malloc'd JSON string, or NULL when it cannot be built. */
char *st_workbench_render_document(const st_storage_workbench_document *doc);

/* One run of the global retention sweep at the workbench clock's now. */
int st_workbench_sweep(const char *database_path);

#endif
