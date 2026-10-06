#ifndef SPECUS_CONNECTIVITY_CHECK_H
#define SPECUS_CONNECTIVITY_CHECK_H

#include <stddef.h>

/*
 * The service connectivity check of one HTTP route (protocol/spec/service-connectivity-check.md):
 * four stages -- configured, device online, target reachable, access succeeded -- decided in that
 * order by a bounded HEAD, and at most one GET, sent through the device's data connection. The
 * reference state machine is tools/protocol/generate_service_connectivity_vectors.py; the shared
 * vector protocol/test-vectors/service-connectivity-check-v1.json pins every outcome.
 */

#define ST_CONNECTIVITY_BUDGET_MS 10000LL
#define ST_CONNECTIVITY_MAX_BODY_BYTES 4096U
#define ST_CONNECTIVITY_MAX_PATH_BYTES 256U
#define ST_CONNECTIVITY_USER_AGENT "specus-connectivity-check/1"
/* RST value the server sends to end a probe stream; clients do not read it. */
#define ST_CONNECTIVITY_PROBE_RESET_CODE 1U

/* What the device did with one probe request. */
enum {
    ST_CONNECTIVITY_PROBE_RESPONSE = 1, /* relayed a response head: status_code */
    ST_CONNECTIVITY_PROBE_RESET,        /* RST before the head: failure, "" when absent */
    ST_CONNECTIVITY_PROBE_LINK_LOST,    /* the data connection closed or was replaced first */
    ST_CONNECTIVITY_PROBE_WRITE_FAILED, /* OPEN or the request FIN could not be written */
    ST_CONNECTIVITY_PROBE_STREAM_LIMIT, /* the data connection carries its maximum of streams */
    ST_CONNECTIVITY_PROBE_TIMEOUT       /* no answer within the time given */
};

typedef struct {
    int kind;
    int status_code;
    /* metadata.failure of an RST; "" when absent, "?" when too long to be a known name. */
    char failure[32];
    /* clientHttpRouteCapabilities.version of the session the probe was opened on. */
    int capability;
} st_connectivity_probe_answer;

typedef struct {
    /* Whether the client has a bound control connection and data connection in this process. */
    void (*presence)(void *ctx, const char *client_name, int *control_online, int *data_online);
    /*
     * Writes OPEN with metadata_json and the request FIN on the client's data connection and waits
     * at most timeout_ms for the first answer. On a response head the stream is reset unless it
     * already ended both ways; the body is never read and never credited back.
     */
    void (*probe)(void *ctx,
                  const char *client_name,
                  const char *metadata_json,
                  long long timeout_ms,
                  st_connectivity_probe_answer *answer);
    /* Monotonic milliseconds. */
    long long (*now_ms)(void *ctx);
    /* One log line; NULL prints it to stdout. */
    void (*log)(void *ctx, const char *line);
    void *ctx;
} st_connectivity_device;

typedef struct {
    long long id;
    char tenant_id[64];
    char client_name[256];
    char route[128];
    char target_base_url[512];
    int route_enabled;
    int client_enabled;
} st_connectivity_route;

#define ST_CONNECTIVITY_ROUTE_FOUND 0
/* Absent, another tenant's, or not the caller's: all answer the same 404. */
#define ST_CONNECTIVITY_ROUTE_ABSENT 1
/* The records could not be read: 503, never "not configured". */
#define ST_CONNECTIVITY_ROUTE_UNREADABLE (-1)

typedef int (*st_connectivity_route_loader)(void *ctx, long long route_id, st_connectivity_route *route);

typedef struct {
    int authenticated;
    const char *tenant_id;
    const char *username;
    /* The {routeId} path segment as received. */
    const char *route_id;
    const char *body;
    size_t body_len;
} st_connectivity_request;

typedef struct {
    int status;
    /* Seconds for Retry-After; 0 when the answer carries none. */
    int retry_after_seconds;
    /* malloc'd JSON body; NULL for 401, which the caller answers as it answers any. */
    char *body;
} st_connectivity_response;

typedef struct {
    int status;
    const char *code;
    int retry_after_seconds;
    /* "route" or "user" for CHECK_RATE_LIMITED, NULL otherwise. */
    const char *limited_by;
} st_connectivity_refusal;

typedef struct st_connectivity_checker st_connectivity_checker;

/* One checker serves the process: it owns the concurrency slots and the rate limiter. */
st_connectivity_checker *st_connectivity_checker_new(const st_connectivity_device *device);
void st_connectivity_checker_free(st_connectivity_checker *checker);

/*
 * Answers one request in the order of section 3.2: 401, 400, 503 (records unreadable), 404,
 * 429 (route in progress), 503 (process busy), 429 (rate), then the check itself (200).
 * Returns 0 when response is filled.
 */
int st_connectivity_handle(st_connectivity_checker *checker,
                           const st_connectivity_request *request,
                           st_connectivity_route_loader loader,
                           void *loader_ctx,
                           st_connectivity_response *response);
void st_connectivity_response_free(st_connectivity_response *response);

/* Request body: empty, {} or {"path":"..."}; writes the probe path ("/" by default). */
int st_connectivity_parse_body(const char *body, size_t body_len, char *path, size_t path_len);
int st_connectivity_valid_path(const char *path);
int st_connectivity_valid_target_base_url(const char *url);

/*
 * Steps 5 to 7 of section 3.2 at now_ms. Returns 0 when admitted -- the caller then owns a slot and
 * must call st_connectivity_release -- or -1 with refusal filled. Refusals consume nothing.
 */
int st_connectivity_admit(st_connectivity_checker *checker,
                          const char *tenant_id,
                          const char *username,
                          long long route_id,
                          long long now_ms,
                          st_connectivity_refusal *refusal);
void st_connectivity_release(st_connectivity_checker *checker, long long route_id);
/* Step 7 alone, consuming both keys when admitted; for replaying the vector's rate events. */
int st_connectivity_rate(st_connectivity_checker *checker,
                         const char *tenant_id,
                         const char *username,
                         long long route_id,
                         long long now_ms,
                         st_connectivity_refusal *refusal);

#endif
