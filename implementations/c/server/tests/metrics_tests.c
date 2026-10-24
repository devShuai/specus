#define _POSIX_C_SOURCE 200809L

/*
 * The meters of the Java server and its actuator metrics endpoint, in process: Java's
 * Double.toString, the exposure settings (MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE/_EXCLUDE),
 * content negotiation, the tag parameter, every answer of /actuator/metrics and
 * /actuator/metrics/{name}, and the reasons the control codec gives for a refused frame.
 *
 * The expected bodies were captured from the Java server (Spring Boot 4.1.1, actuator with
 * management.endpoints.web.exposure.include=health,metrics) on 2026-10-23 with raw HTTP requests.
 */

#include "metrics.h"
#include "protocol.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int failures;

#define EXPECT(condition, ...)                                   \
    do {                                                         \
        if (!(condition)) {                                      \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
            fprintf(stderr, __VA_ARGS__);                        \
            fprintf(stderr, "\n");                               \
            ++failures;                                          \
        }                                                        \
    } while (0)

typedef struct {
    int rc;
    int status;
    char headers[2048];
    char *raw;
    const char *body;
    size_t body_len;
} answer;

static void ask(const char *method, const char *path, const char *accept, answer *out)
{
    memset(out, 0, sizeof(*out));
    size_t len = 0U;
    out->rc = st_metrics_actuator_response(method, path, accept, &out->raw, &len);
    if (out->rc != 1 || out->raw == NULL) {
        return;
    }
    (void)sscanf(out->raw, "HTTP/1.1 %d", &out->status);
    const char *start = strstr(out->raw, "\r\n");
    const char *end = strstr(out->raw, "\r\n\r\n");
    if (start != NULL && end != NULL && end >= start) {
        size_t header_len = (size_t)(end - start) + 2U;
        if (header_len >= sizeof(out->headers)) header_len = sizeof(out->headers) - 1U;
        memcpy(out->headers, start, header_len);
        out->headers[header_len] = '\0';
        out->body = end + 4;
        out->body_len = len - (size_t)(out->body - out->raw);
    }
}

static void release(answer *value)
{
    free(value->raw);
    value->raw = NULL;
}

static int has_header(const answer *value, const char *line)
{
    char needle[512];
    snprintf(needle, sizeof(needle), "\r\n%s\r\n", line);
    return strstr(value->headers, needle) != NULL;
}

static int body_is(const answer *value, const char *expected)
{
    return value->body != NULL && value->body_len == strlen(expected)
        && memcmp(value->body, expected, value->body_len) == 0;
}

static void expect_body(const char *method, const char *path, const char *accept, int status,
                        const char *expected)
{
    answer value;
    ask(method, path, accept, &value);
    EXPECT(value.rc == 1 && value.status == status && body_is(&value, expected),
           "%s %s: rc %d status %d body %.*s, want %d %s", method, path, value.rc, value.status,
           (int)value.body_len, value.body == NULL ? "" : value.body, status, expected);
    release(&value);
}

/* ---- Java's Double.toString ------------------------------------------------------------------ */

static void test_format_double(void)
{
    static const struct {
        double value;
        const char *expected;
    } cases[] = {
        {0.0, "0.0"}, {-0.0, "-0.0"}, {1.0, "1.0"}, {512.0, "512.0"}, {33.0, "33.0"}, {100.0, "100.0"},
        {9999999.0, "9999999.0"}, {10000000.0, "1.0E7"}, {12345678.0, "1.2345678E7"},
        {1761234500.0, "1.7612345E9"}, {360843048.0, "3.60843048E8"}, {16.917, "16.917"},
        {0.0460936, "0.0460936"}, {0.001, "0.001"}, {0.0001, "1.0E-4"}, {1.234, "1.234"},
        {0.1 + 0.2, "0.30000000000000004"}, {9007199254740992.0, "9.007199254740992E15"},
        {9223372036854775807.0, "9.223372036854776E18"}, {1e23, "1.0E23"}, {4.9e-324, "4.9E-324"},
        {1.7976931348623157e308, "1.7976931348623157E308"}, {-2.5, "-2.5"}, {2.0e-3, "0.002"},
        {123456.789, "123456.789"}, {9.999999999999998e-4, "9.999999999999998E-4"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        char text[64];
        EXPECT(st_metrics_format_double(cases[i].value, text, sizeof(text)) == 0
                   && strcmp(text, cases[i].expected) == 0,
               "Double.toString(%.17g) is %s, want %s", cases[i].value, text, cases[i].expected);
    }
    char small[4];
    EXPECT(st_metrics_format_double(12345.0, small, sizeof(small)) == -1, "a short buffer was not refused");
}

/* ---- management.endpoints.web.exposure ------------------------------------------------------- */

static void test_exposure(void)
{
    static const struct {
        const char *include;
        const char *exclude;
        int expected;
        const char *error;
    } cases[] = {
        {NULL, NULL, 0, NULL},
        {"health", NULL, 0, NULL},
        {"", NULL, 0, NULL},
        {"metrics", NULL, 1, NULL},
        {"health,metrics", NULL, 1, NULL},
        {" mETRICS , health", NULL, 1, NULL},
        {"me-trics", NULL, 1, NULL},
        {"m.etrics", NULL, 1, NULL},
        {"*", NULL, 1, NULL},
        {"*", "me-trics", 0, NULL},
        {"metrics", "metrics", 0, NULL},
        {"metrics", "health", 1, NULL},
        {"metric", NULL, 0, NULL},
        {"metricsx", NULL, 0, NULL},
        {"prometheus", NULL, 0, NULL},
        {"Metrics", NULL, -1, "'value' must not start with an uppercase letter"},
        {"metrics,", NULL, -1, "'value' must not be empty"},
        {" ", NULL, -1, "'value' must not be empty"},
        {"-", NULL, -1, "'value' must not be empty"},
        {"1metrics", NULL, -1, "'value' must not start with a number"},
        {"met rics", NULL, -1, "'value' must only contain valid chars"},
        {"metrics_x", NULL, -1, "'value' must only contain valid chars"},
        {"metrics", "Health", -1, "'value' must not start with an uppercase letter"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        char error[128] = "";
        int exposed = st_metrics_exposure(cases[i].include, cases[i].exclude, error, sizeof(error));
        EXPECT(exposed == cases[i].expected
                   && (cases[i].error == NULL || strcmp(error, cases[i].error) == 0),
               "include \"%s\" exclude \"%s\": %d (%s), want %d (%s)",
               cases[i].include == NULL ? "(unset)" : cases[i].include,
               cases[i].exclude == NULL ? "(unset)" : cases[i].exclude, exposed, error, cases[i].expected,
               cases[i].error == NULL ? "" : cases[i].error);
    }

    answer value;
    unsetenv("MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE");
    unsetenv("MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_EXCLUDE");
    ask("GET", "/actuator/metrics", NULL, &value);
    EXPECT(value.rc == 0, "the endpoint answered without being exposed (Spring Boot exposes health alone)");
    release(&value);
    EXPECT(st_metrics_validate_current() == 0, "the default exposure was refused");
    setenv("MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE", "Metrics", 1);
    ask("GET", "/actuator/metrics", NULL, &value);
    EXPECT(value.rc == 0 && st_metrics_validate_current() == -1, "an invalid endpoint id was accepted");
    release(&value);
    setenv("MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE", "*", 1);
    setenv("MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_EXCLUDE", "metrics", 1);
    ask("GET", "/actuator/metrics/specus.control.tls.mode", NULL, &value);
    EXPECT(value.rc == 0, "an excluded endpoint answered");
    release(&value);
    unsetenv("MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_EXCLUDE");
    ask("GET", "/actuator/metrics", NULL, &value);
    EXPECT(value.rc == 1 && value.status == 200, "include=* did not expose the endpoint");
    release(&value);
}

/* ---- the two routes against the Java server's answers ---------------------------------------- */

static const char java_names[] =
    "{\"names\":[\"specus.control.plaintext.deployment.rejected\",\"specus.control.preauth.oversize.rejected\","
    "\"specus.control.protocol.rejected\",\"specus.control.tls.certificate.expiry.epoch.seconds\","
    "\"specus.control.tls.mode\",\"specus.peer_mesh.relay.traffic.flush.failures\","
    "\"specus.peer_mesh.relay.traffic.flush.lag.seconds\",\"specus.peer_mesh.relay.traffic.pending.bytes\","
    "\"specus.peer_mesh.turn.general_relay.bytes\",\"specus.peer_mesh.turn.general_relay.destination.forbidden\","
    "\"specus.peer_mesh.turn.general_relay.quota.closed\",\"specus.peer_mesh.turn.general_relay.quota.rejected\","
    "\"specus.peer_mesh.turn.relay.queue.depth\",\"specus.peer_mesh.turn.relay.queue.dropped\","
    "\"specus.peer_mesh.turn.relay.queue.high.water\",\"specus.peer_mesh.turn.relay.send.failures\"]}";

#define JAVA_COUNTER(name, description)                                                        \
    {name, "{\"availableTags\":[],\"description\":\"" description "\",\"measurements\":"        \
           "[{\"statistic\":\"COUNT\",\"value\":0.0}],\"name\":\"" name "\"}"}
#define JAVA_GAUGE(name, description)                                                          \
    {name, "{\"availableTags\":[],\"description\":\"" description "\",\"measurements\":"        \
           "[{\"statistic\":\"VALUE\",\"value\":0.0}],\"name\":\"" name "\"}"}

static const struct {
    const char *name;
    const char *body;
} java_bodies[] = {
    JAVA_COUNTER("specus.peer_mesh.turn.general_relay.bytes", "Bytes relayed on behalf of general TURN allocations"),
    JAVA_COUNTER("specus.peer_mesh.turn.relay.queue.dropped", "TURN relay tasks rejected by the bounded worker queue"),
    JAVA_COUNTER("specus.peer_mesh.turn.relay.send.failures", "TURN relay datagrams that failed during send"),
    JAVA_COUNTER("specus.peer_mesh.turn.general_relay.quota.rejected", "General TURN relay allocations rejected by quota"),
    JAVA_COUNTER("specus.peer_mesh.turn.general_relay.destination.forbidden",
                 "General TURN relay permissions rejected by the destination policy"),
    JAVA_COUNTER("specus.peer_mesh.turn.general_relay.quota.closed",
                 "General TURN allocations closed after exhausting the byte quota"),
    JAVA_GAUGE("specus.peer_mesh.turn.relay.queue.depth", "Current TURN relay worker queue depth"),
    JAVA_GAUGE("specus.peer_mesh.turn.relay.queue.high.water", "Maximum observed TURN relay worker queue depth"),
    JAVA_COUNTER("specus.peer_mesh.relay.traffic.flush.failures",
                 "Relay traffic batches restored after a persistence failure"),
    JAVA_GAUGE("specus.peer_mesh.relay.traffic.pending.bytes", "Relay traffic bytes waiting to be persisted"),
    JAVA_GAUGE("specus.peer_mesh.relay.traffic.flush.lag.seconds",
               "Seconds since the last successful relay traffic flush"),
    {"specus.control.protocol.rejected",
     "{\"availableTags\":[{\"tag\":\"reason\",\"values\":[\"invalid_length\",\"unknown_command\",\"invalid_magic\","
     "\"unsupported_version\",\"unsupported_serializer\",\"malformed_body\"]}],\"measurements\":"
     "[{\"statistic\":\"COUNT\",\"value\":0.0}],\"name\":\"specus.control.protocol.rejected\"}"},
    {"specus.control.preauth.oversize.rejected",
     "{\"availableTags\":[],\"measurements\":[{\"statistic\":\"COUNT\",\"value\":0.0}],"
     "\"name\":\"specus.control.preauth.oversize.rejected\"}"},
    {"specus.control.plaintext.deployment.rejected",
     "{\"availableTags\":[],\"measurements\":[{\"statistic\":\"COUNT\",\"value\":0.0}],"
     "\"name\":\"specus.control.plaintext.deployment.rejected\"}"},
    {"specus.control.tls.mode",
     "{\"availableTags\":[{\"tag\":\"mode\",\"values\":[\"disabled\"]}],\"measurements\":"
     "[{\"statistic\":\"VALUE\",\"value\":1.0}],\"name\":\"specus.control.tls.mode\"}"},
    {"specus.control.tls.certificate.expiry.epoch.seconds",
     "{\"availableTags\":[],\"measurements\":[{\"statistic\":\"VALUE\",\"value\":0.0}],"
     "\"name\":\"specus.control.tls.certificate.expiry.epoch.seconds\"}"},
};

static const char rejected_invalid_magic_zero[] =
    "{\"availableTags\":[],\"measurements\":[{\"statistic\":\"COUNT\",\"value\":0.0}],"
    "\"name\":\"specus.control.protocol.rejected\"}";

static void test_java_bodies(void)
{
    st_metrics_reset();
    st_metrics_set_relay_pending_bytes_source(NULL);
    answer value;
    ask("GET", "/actuator/metrics", NULL, &value);
    EXPECT(value.rc == 1 && value.status == 200 && body_is(&value, java_names)
               && has_header(&value, "Content-Type: application/vnd.spring-boot.actuator.v3+json")
               && strstr(value.headers, "Content-Disposition") == NULL,
           "names: %d %s %.*s", value.status, value.headers, (int)value.body_len, value.body);
    release(&value);
    for (size_t i = 0; i < sizeof(java_bodies) / sizeof(java_bodies[0]); ++i) {
        char path[160];
        snprintf(path, sizeof(path), "/actuator/metrics/%s", java_bodies[i].name);
        ask("GET", path, NULL, &value);
        EXPECT(value.rc == 1 && value.status == 200 && body_is(&value, java_bodies[i].body)
                   && has_header(&value, "Content-Type: application/vnd.spring-boot.actuator.v3+json")
                   && has_header(&value, "Content-Disposition: inline;filename=f.txt"),
               "%s: %d %s %.*s", java_bodies[i].name, value.status, value.headers, (int)value.body_len,
               value.body == NULL ? "" : value.body);
        release(&value);
    }
    /* The query of the names route is ignored. */
    expect_body("GET", "/actuator/metrics?x=1", NULL, 200, java_names);
}

static void test_tags(void)
{
    static const char base[] = "/actuator/metrics/specus.control.protocol.rejected";
    const char *full = java_bodies[11].body;
    char path[256];
    static const struct {
        const char *query;
        int status;
        int filtered;
    } cases[] = {
        {"?tag=reason:invalid_magic", 200, 1},
        {"?tag=reason%3Ainvalid_magic", 200, 1},
        {"?tag=+reason:invalid_magic+", 200, 1},
        {"?tag=%20reason:invalid_magic%09", 200, 1},
        {"?tag=reason:invalid_magic&tag=reason:invalid_magic", 200, 1},
        {"?tag=", 200, 0},
        {"?tag", 200, 0},
        {"?Tag=reason:invalid_magic", 200, 0},
        {"?tags=reason:invalid_magic", 200, 0},
        {"?tag=reason:nope", 404, 0},
        {"?tag=reason:invalid_magic&tag=reason:unknown_command", 404, 0},
        {"?tag=reason:invalid_magic,reason:unknown_command", 404, 0},
        {"?tag=reason:invalid_magic:extra", 404, 0},
        {"?tag=:x", 404, 0},
        {"?tag=reason:", 404, 0},
        {"?tag=REASON:invalid_magic", 404, 0},
        {"?tag=reason:INVALID_MAGIC", 404, 0},
        {"?tag=mode:disabled", 404, 0},
        {"?tag=bad", 400, 0},
        {"?tag=reason:invalid_magic,", 400, 0},
        {"?tag=,reason:invalid_magic", 400, 0},
        {"?tag=%20", 400, 0},
        {"?tag=reason:invalid_magic&tag=", 400, 0},
        {"?tag=a&tag=b:c", 400, 0},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(path, sizeof(path), "%s%s", base, cases[i].query);
        answer value;
        ask("GET", path, NULL, &value);
        int ok = value.rc == 1 && value.status == cases[i].status;
        if (ok && cases[i].status == 200) {
            ok = body_is(&value, cases[i].filtered ? rejected_invalid_magic_zero : full);
        } else if (ok && cases[i].status == 404) {
            /* The endpoint answered null: no body, no content type. */
            ok = value.body_len == 0U && has_header(&value, "Content-Length: 0")
                && strstr(value.headers, "\r\nContent-Type:") == NULL;
        } else if (ok) {
            ok = body_is(&value, "{\"error\":\"Bad Request\"}")
                && has_header(&value, "Content-Type: application/json")
                && has_header(&value, "Content-Disposition: inline;filename=f.txt");
        }
        EXPECT(ok, "%s: %d %s %.*s", cases[i].query, value.status, value.headers, (int)value.body_len,
               value.body == NULL ? "" : value.body);
        release(&value);
    }
    /* A tag key the request names leaves availableTags. */
    expect_body("GET", "/actuator/metrics/specus.control.tls.mode?tag=mode:disabled", NULL, 200,
                "{\"availableTags\":[],\"measurements\":[{\"statistic\":\"VALUE\",\"value\":1.0}],"
                "\"name\":\"specus.control.tls.mode\"}");
    answer value;
    static const char *const missing[] = {
        "/actuator/metrics/nonexistent.metric", "/actuator/metrics/Specus.control.tls.mode",
        "/actuator/metrics/specus.peer_mesh.turn.general_relay.bytes?tag=x:y",
        "/actuator/metrics/specus.control.tls.mode.json", "/actuator/metrics/jvm.memory.used",
    };
    for (size_t i = 0; i < sizeof(missing) / sizeof(missing[0]); ++i) {
        ask("GET", missing[i], NULL, &value);
        EXPECT(value.rc == 1 && value.status == 404 && value.body_len == 0U, "%s: %d", missing[i], value.status);
        release(&value);
    }
}

static void test_routes(void)
{
    static const char *const others[] = {
        "/actuator", "/actuator/", "/actuator/metrics/", "/actuator/metrics/a/b",
        "/actuator/metrics/specus.control.tls.mode/extra", "/actuator/metricsx", "/actuator/metrics.json",
        "/actuator/prometheus", "/actuator/health", "/Actuator/metrics", "/api/admin/metrics", "/x/actuator/metrics",
    };
    for (size_t i = 0; i < sizeof(others) / sizeof(others[0]); ++i) {
        answer value;
        ask("GET", others[i], NULL, &value);
        EXPECT(value.rc == 0, "%s was taken as a metrics route", others[i]);
        release(&value);
    }
    /* No Content-Disposition for a safe extension or none at all. */
    answer value;
    ask("GET", "/actuator/metrics/specus.json?tag=bad", NULL, &value);
    EXPECT(value.status == 400 && strstr(value.headers, "Content-Disposition") == NULL,
           "a .json name got Content-Disposition: %s", value.headers);
    release(&value);
    ask("GET", "/actuator/metrics/specus?tag=bad", NULL, &value);
    EXPECT(value.status == 400 && strstr(value.headers, "Content-Disposition") == NULL,
           "a name without extension got Content-Disposition: %s", value.headers);
    release(&value);
    ask("GET", "/actuator/metrics/specus.PNG?tag=bad", NULL, &value);
    EXPECT(value.status == 400 && strstr(value.headers, "Content-Disposition") == NULL,
           "a .PNG name got Content-Disposition: %s", value.headers);
    release(&value);
}

static void test_negotiation(void)
{
    static const struct {
        const char *accept;
        const char *type;
    } cases[] = {
        {NULL, "application/vnd.spring-boot.actuator.v3+json"},
        {"", "application/vnd.spring-boot.actuator.v3+json"},
        {"*/*", "application/vnd.spring-boot.actuator.v3+json"},
        {"application/json", "application/json"},
        {"Application/JSON", "application/json"},
        {"application/vnd.spring-boot.actuator.v2+json", "application/vnd.spring-boot.actuator.v2+json"},
        {"application/vnd.spring-boot.actuator.v3+json", "application/vnd.spring-boot.actuator.v3+json"},
        {"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
         "application/vnd.spring-boot.actuator.v3+json"},
        {"application/json;q=0.5, application/vnd.spring-boot.actuator.v2+json",
         "application/vnd.spring-boot.actuator.v2+json"},
        {"application/json, */*;q=0.1", "application/json"},
        {"application/*", "application/vnd.spring-boot.actuator.v3+json"},
        {"application/*+json", "application/vnd.spring-boot.actuator.v3+json"},
        {"text/plain, application/json;q=0.2", "application/json"},
        {"application/json;", "application/json"},
        {"application/json; charset ; q=0.4, text/plain", "application/json"},
        {"text/plain", NULL},
        {"text/html", NULL},
        {"text/*", NULL},
        {"application/xml", NULL},
        {"garbage", NULL},
        {"*/json", NULL},
        {"application/json;q=x", NULL},
        {"application/json;q=2", NULL},
        /* Measured on the Java server: Spring sorts the ranges by specificity (quality, then a
         * concrete type before a wildcard type or subtype) before pairing them with v3, v2, json,
         * and keeps the chosen range's parameters other than q in Content-Type. */
        {"*/*, application/json", "application/json"},
        {"application/*, application/json", "application/json"},
        {"application/*+json, application/json", "application/json"},
        {"*/*;q=0.5, application/*;q=0.5, application/json;q=0.5", "application/json"},
        {"application/*;q=0.9, application/json;q=0.9", "application/json"},
        {"application/json;q=0.5, */*", "application/vnd.spring-boot.actuator.v3+json"},
        {"application/vnd.spring-boot.actuator.v2+json, application/json",
         "application/vnd.spring-boot.actuator.v2+json"},
        {"application/json, application/vnd.spring-boot.actuator.v2+json", "application/json"},
        {"application/json; q=0.5 , application/vnd.spring-boot.actuator.v2+json ;q=0.5", "application/json"},
        {"text/plain;q=1, */*;q=0.1", "application/vnd.spring-boot.actuator.v3+json"},
        {",", "application/vnd.spring-boot.actuator.v3+json"},
        {" , ", "application/vnd.spring-boot.actuator.v3+json"},
        {"*;q=0.8", "application/vnd.spring-boot.actuator.v3+json"},
        {"application/json;q=\"0.5\", application/vnd.spring-boot.actuator.v2+json;q=0.4", "application/json"},
        {"application/json;q=.5", "application/json"},
        {"application/json;q=0", "application/json"},
        {"application/json;foo=\"a,b\"", "application/json;foo=\"a,b\""},
        {"application/json;foo=\"a,b\", text/plain", "application/json;foo=\"a,b\""},
        {"text/html, application/json;charset=utf-8", "application/json;charset=utf-8"},
        {"application/json;foo=bar, application/json", "application/json;foo=bar"},
        {"application/json;a b=c", NULL},
        {"application/json;charset=bogus", NULL},
        {"application/json;foo=", NULL},
        {"application/json;=x", NULL},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        char line[160];
        answer value;
        ask("GET", "/actuator/metrics", cases[i].accept, &value);
        if (cases[i].type != NULL) {
            snprintf(line, sizeof(line), "Content-Type: %s", cases[i].type);
            EXPECT(value.status == 200 && has_header(&value, line) && body_is(&value, java_names),
                   "Accept %s: %d %s", cases[i].accept == NULL ? "(none)" : cases[i].accept, value.status,
                   value.headers);
        } else {
            EXPECT(value.status == 406 && value.body_len == 0U
                       && has_header(&value, "Accept: application/vnd.spring-boot.actuator.v3+json, "
                                             "application/vnd.spring-boot.actuator.v2+json, application/json"),
                   "Accept %s: %d %s", cases[i].accept, value.status, value.headers);
        }
        release(&value);
    }
    /* MimeTypeUtils.sortBySpecificity refuses more than 50 media types. */
    char many[1024] = "";
    for (int i = 0; i < 51; ++i) {
        strcat(many, i == 0 ? "application/json" : ",application/json");
    }
    answer value;
    ask("GET", "/actuator/metrics", many, &value);
    EXPECT(value.status == 406, "51 media types: %d", value.status);
    release(&value);
    many[strlen(many) - strlen(",application/json")] = '\0';
    ask("GET", "/actuator/metrics", many, &value);
    EXPECT(value.status == 200, "50 media types: %d", value.status);
    release(&value);
    /* Negotiation comes before the handler: a missing metric or a bad tag is 406 as well. */
    ask("GET", "/actuator/metrics/nonexistent.metric", "text/plain", &value);
    EXPECT(value.status == 406, "a missing metric with Accept text/plain: %d", value.status);
    release(&value);
    ask("GET", "/actuator/metrics/specus.control.tls.mode?tag=bad", "text/plain", &value);
    EXPECT(value.status == 406, "a bad tag with Accept text/plain: %d", value.status);
    release(&value);
}

static void test_methods(void)
{
    answer value;
    ask("HEAD", "/actuator/metrics", NULL, &value);
    char length[64];
    snprintf(length, sizeof(length), "Content-Length: %zu", strlen(java_names));
    EXPECT(value.status == 200 && value.body_len == 0U && has_header(&value, length)
               && has_header(&value, "Content-Type: application/vnd.spring-boot.actuator.v3+json"),
           "HEAD: %d %s", value.status, value.headers);
    release(&value);
    ask("HEAD", "/actuator/metrics/specus.control.tls.mode", NULL, &value);
    EXPECT(value.status == 200 && value.body_len == 0U
               && has_header(&value, "Content-Disposition: inline;filename=f.txt"),
           "HEAD of a metric: %d %s", value.status, value.headers);
    release(&value);
    ask("OPTIONS", "/actuator/metrics/specus.control.tls.mode", "text/plain", &value);
    EXPECT(value.status == 200 && value.body_len == 0U && has_header(&value, "Allow: GET,HEAD,OPTIONS")
               && has_header(&value, "Accept-Patch: ") && has_header(&value, "Content-Length: 0"),
           "OPTIONS: %d %s", value.status, value.headers);
    release(&value);
    static const char *const refused[] = {"POST", "PUT", "DELETE", "PATCH"};
    for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); ++i) {
        ask(refused[i], "/actuator/metrics", "text/plain", &value);
        EXPECT(value.status == 405 && has_header(&value, "Allow: GET")
                   && body_is(&value, "{\"error\":\"Method Not Allowed\"}")
                   && strstr(value.headers, "Content-Disposition") == NULL,
               "%s: %d %s", refused[i], value.status, value.headers);
        release(&value);
        ask(refused[i], "/actuator/metrics/specus.control.tls.mode", NULL, &value);
        EXPECT(value.status == 405 && has_header(&value, "Content-Disposition: inline;filename=f.txt"),
               "%s of a metric: %d %s", refused[i], value.status, value.headers);
        release(&value);
    }
}

static double fake_pending_bytes(void)
{
    return 512.0;
}

static void sleep_ms(long milliseconds)
{
    struct timespec delay = {milliseconds / 1000L, (milliseconds % 1000L) * 1000000L};
    while (nanosleep(&delay, &delay) != 0) {
    }
}

static void test_values(void)
{
    st_metrics_reset();
    st_metrics_add(ST_METRIC_TURN_GENERAL_RELAY_BYTES, 12345678ULL);
    expect_body("GET", "/actuator/metrics/specus.peer_mesh.turn.general_relay.bytes", NULL, 200,
                "{\"availableTags\":[],\"description\":\"Bytes relayed on behalf of general TURN allocations\","
                "\"measurements\":[{\"statistic\":\"COUNT\",\"value\":1.2345678E7}],"
                "\"name\":\"specus.peer_mesh.turn.general_relay.bytes\"}");
    st_metrics_protocol_rejected(ST_PROTOCOL_REJECTION_INVALID_MAGIC);
    st_metrics_protocol_rejected(ST_PROTOCOL_REJECTION_INVALID_MAGIC);
    st_metrics_protocol_rejected(ST_PROTOCOL_REJECTION_MALFORMED_BODY);
    st_metrics_protocol_rejected(ST_PROTOCOL_REJECTION_NONE);
    double total = -1.0;
    double magic = -1.0;
    double body = -1.0;
    double length = -1.0;
    EXPECT(st_metrics_measure("specus.control.protocol.rejected", NULL, NULL, &total) == 0 && total == 3.0
               && st_metrics_measure("specus.control.protocol.rejected", "reason", "invalid_magic", &magic) == 0
               && magic == 2.0
               && st_metrics_measure("specus.control.protocol.rejected", "reason", "malformed_body", &body) == 0
               && body == 1.0
               && st_metrics_measure("specus.control.protocol.rejected", "reason", "invalid_length", &length) == 0
               && length == 0.0,
           "protocol rejections %g/%g/%g/%g", total, magic, body, length);
    expect_body("GET", "/actuator/metrics/specus.control.protocol.rejected?tag=reason:invalid_magic", NULL, 200,
                "{\"availableTags\":[],\"measurements\":[{\"statistic\":\"COUNT\",\"value\":2.0}],"
                "\"name\":\"specus.control.protocol.rejected\"}");
    double unknown = 0.0;
    EXPECT(st_metrics_measure("specus.control.protocol.rejected", "reason", "nope", &unknown) == -1
               && st_metrics_measure("nonexistent", NULL, NULL, &unknown) == -1,
           "a meter that does not exist was measured");

    st_metrics_set_control_tls("file", 1761234500LL);
    expect_body("GET", "/actuator/metrics/specus.control.tls.mode", NULL, 200,
                "{\"availableTags\":[{\"tag\":\"mode\",\"values\":[\"file\"]}],\"measurements\":"
                "[{\"statistic\":\"VALUE\",\"value\":1.0}],\"name\":\"specus.control.tls.mode\"}");
    answer value;
    ask("GET", "/actuator/metrics/specus.control.tls.mode?tag=mode:disabled", NULL, &value);
    EXPECT(value.status == 404, "the old TLS mode still matched: %d", value.status);
    release(&value);
    expect_body("GET", "/actuator/metrics/specus.control.tls.certificate.expiry.epoch.seconds", NULL, 200,
                "{\"availableTags\":[],\"measurements\":[{\"statistic\":\"VALUE\",\"value\":1.7612345E9}],"
                "\"name\":\"specus.control.tls.certificate.expiry.epoch.seconds\"}");

    st_metrics_set_relay_pending_bytes_source(fake_pending_bytes);
    double pending = 0.0;
    EXPECT(st_metrics_measure("specus.peer_mesh.relay.traffic.pending.bytes", NULL, NULL, &pending) == 0
               && pending == 512.0,
           "pending bytes %g, want the source's 512", pending);
    st_metrics_set_relay_pending_bytes_source(NULL);

    double lag = -1.0;
    EXPECT(st_metrics_measure("specus.peer_mesh.relay.traffic.flush.lag.seconds", NULL, NULL, &lag) == 0 && lag == 0.0,
           "flush lag %g before any flush, want 0 (Java)", lag);
    st_metrics_relay_traffic_flushed();
    sleep_ms(1100L);
    EXPECT(st_metrics_measure("specus.peer_mesh.relay.traffic.flush.lag.seconds", NULL, NULL, &lag) == 0
               && lag >= 1.1 && lag < 30.0,
           "flush lag %g 1.1 s after a flush", lag);
    st_metrics_relay_traffic_flushed();
    EXPECT(st_metrics_measure("specus.peer_mesh.relay.traffic.flush.lag.seconds", NULL, NULL, &lag) == 0
               && lag < 1.0,
           "flush lag %g right after a flush", lag);

    static const st_metric_counter counters[] = {
        ST_METRIC_CONTROL_PLAINTEXT_DEPLOYMENT_REJECTED, ST_METRIC_CONTROL_PREAUTH_OVERSIZE_REJECTED,
        ST_METRIC_TURN_RELAY_QUEUE_DROPPED, ST_METRIC_TURN_RELAY_SEND_FAILURES,
        ST_METRIC_TURN_GENERAL_RELAY_QUOTA_REJECTED, ST_METRIC_TURN_GENERAL_RELAY_DESTINATION_FORBIDDEN,
        ST_METRIC_TURN_GENERAL_RELAY_QUOTA_CLOSED, ST_METRIC_RELAY_TRAFFIC_FLUSH_FAILURES,
    };
    static const char *const names[] = {
        "specus.control.plaintext.deployment.rejected", "specus.control.preauth.oversize.rejected",
        "specus.peer_mesh.turn.relay.queue.dropped", "specus.peer_mesh.turn.relay.send.failures",
        "specus.peer_mesh.turn.general_relay.quota.rejected",
        "specus.peer_mesh.turn.general_relay.destination.forbidden",
        "specus.peer_mesh.turn.general_relay.quota.closed", "specus.peer_mesh.relay.traffic.flush.failures",
    };
    for (size_t i = 0; i < sizeof(counters) / sizeof(counters[0]); ++i) {
        st_metrics_increment(counters[i]);
        double counted = 0.0;
        EXPECT(st_metrics_measure(names[i], NULL, NULL, &counted) == 0 && counted == 1.0, "%s is %g after one",
               names[i], counted);
    }
    st_metrics_reset();
    EXPECT(st_metrics_measure("specus.control.protocol.rejected", NULL, NULL, &total) == 0 && total == 0.0,
           "reset left %g protocol rejections", total);
}

/* ---- the reasons the codec gives (Java PacketCodec) ------------------------------------------ */

static void header(uint8_t raw[ST_HEADER_SIZE], uint32_t magic, uint8_t version, uint8_t serializer,
                   uint8_t command, uint32_t length)
{
    raw[0] = (uint8_t)(magic >> 24U);
    raw[1] = (uint8_t)(magic >> 16U);
    raw[2] = (uint8_t)(magic >> 8U);
    raw[3] = (uint8_t)magic;
    raw[4] = version;
    raw[5] = serializer;
    raw[6] = command;
    raw[7] = (uint8_t)(length >> 24U);
    raw[8] = (uint8_t)(length >> 16U);
    raw[9] = (uint8_t)(length >> 8U);
    raw[10] = (uint8_t)length;
}

static void nat_body(uint8_t out[16], uint8_t type, uint8_t flags, uint16_t meta_len, uint32_t stream_id,
                     uint32_t value, uint32_t data_len)
{
    out[0] = type;
    out[1] = flags;
    out[2] = (uint8_t)(meta_len >> 8U);
    out[3] = (uint8_t)meta_len;
    for (int i = 0; i < 4; ++i) {
        out[4 + i] = (uint8_t)(stream_id >> (24U - 8U * (unsigned)i));
        out[8 + i] = (uint8_t)(value >> (24U - 8U * (unsigned)i));
        out[12 + i] = (uint8_t)(data_len >> (24U - 8U * (unsigned)i));
    }
}

static void test_protocol_reasons(void)
{
    static const struct {
        uint32_t magic;
        uint8_t version;
        uint8_t serializer;
        uint8_t command;
        uint32_t length;
        int rc;
        st_protocol_rejection reason;
    } headers[] = {
        {ST_MAGIC, 2, 4, 1, 10, 0, ST_PROTOCOL_REJECTION_NONE},
        {0, 2, 4, 1, 10, -1, ST_PROTOCOL_REJECTION_INVALID_MAGIC},
        {0, 9, 9, 99, 1U << 30U, -1, ST_PROTOCOL_REJECTION_INVALID_MAGIC},
        {ST_MAGIC, 1, 4, 1, 10, -1, ST_PROTOCOL_REJECTION_UNSUPPORTED_VERSION},
        {ST_MAGIC, 9, 9, 99, 10, -1, ST_PROTOCOL_REJECTION_UNSUPPORTED_VERSION},
        {ST_MAGIC, 2, 1, 1, 10, -1, ST_PROTOCOL_REJECTION_UNSUPPORTED_SERIALIZER},
        {ST_MAGIC, 2, 4, 5, 10, -1, ST_PROTOCOL_REJECTION_UNKNOWN_COMMAND},
        {ST_MAGIC, 2, 4, 0x80, 10, -1, ST_PROTOCOL_REJECTION_UNKNOWN_COMMAND},
        {ST_MAGIC, 2, 4, 1, 20000, -1, ST_PROTOCOL_REJECTION_INVALID_LENGTH},
        {ST_MAGIC, 2, 4, 2, 2U * 1024U * 1024U, -1, ST_PROTOCOL_REJECTION_INVALID_LENGTH},
        {ST_MAGIC, 2, 4, 6, 2U * 1024U * 1024U, 0, ST_PROTOCOL_REJECTION_NONE},
    };
    for (size_t i = 0; i < sizeof(headers) / sizeof(headers[0]); ++i) {
        uint8_t raw[ST_HEADER_SIZE];
        st_frame_header parsed;
        header(raw, headers[i].magic, headers[i].version, headers[i].serializer, headers[i].command,
               headers[i].length);
        int rc = st_protocol_read_header(raw, &parsed);
        EXPECT(rc == headers[i].rc && st_protocol_last_rejection() == headers[i].reason,
               "header case %zu: %d/%d, want %d/%d", i, rc, (int)st_protocol_last_rejection(), headers[i].rc,
               (int)headers[i].reason);
    }

    /* CompactBinary: string = varint(length + 1) and bytes, nullable long = 0 (null). */
    static const uint8_t login_ok[] = {2, 'c', 0, 2, 't', 8, 'c', 'o', 'n', 't', 'r', 'o', 'l'};
    static const uint8_t login_trailing[] = {2, 'c', 0, 2, 't', 8, 'c', 'o', 'n', 't', 'r', 'o', 'l', 0};
    static const uint8_t login_truncated[] = {2, 'c', 0, 9, 't'};
    static const uint8_t login_bad_role[] = {2, 'c', 0, 2, 't', 2, 'x'};
    static const uint8_t login_null_role[] = {2, 'c', 0, 2, 't', 0};
    st_login_request login;
    EXPECT(st_protocol_decode_login_request(login_ok, sizeof(login_ok), &login) == 0
               && st_protocol_last_rejection() == ST_PROTOCOL_REJECTION_NONE,
           "a valid login was refused");
    st_login_request_free(&login);
    EXPECT(st_protocol_decode_login_request(login_trailing, sizeof(login_trailing), &login) == -1
               && st_protocol_last_rejection() == ST_PROTOCOL_REJECTION_MALFORMED_BODY,
           "trailing login bytes are not MALFORMED_BODY");
    EXPECT(st_protocol_decode_login_request(login_truncated, sizeof(login_truncated), &login) == -1
               && st_protocol_last_rejection() == ST_PROTOCOL_REJECTION_MALFORMED_BODY,
           "a truncated login is not MALFORMED_BODY");
    /* Java's codec reads any role; the login handler refuses it, which is no codec rejection. */
    EXPECT(st_protocol_decode_login_request(login_bad_role, sizeof(login_bad_role), &login) == -1
               && st_protocol_last_rejection() == ST_PROTOCOL_REJECTION_NONE,
           "an unknown role was counted as a codec rejection");
    EXPECT(st_protocol_decode_login_request(login_null_role, sizeof(login_null_role), &login) == -1
               && st_protocol_last_rejection() == ST_PROTOCOL_REJECTION_NONE,
           "a null role was not refused as a role");

    static const uint8_t message_bad_type[] = {2, 'a', 2, 'b', 9, 2, 'm'};
    st_message_response message;
    EXPECT(st_protocol_decode_message_response(message_bad_type, sizeof(message_bad_type), &message) == -1
               && st_protocol_last_rejection() == ST_PROTOCOL_REJECTION_MALFORMED_BODY,
           "a message of an unknown type is not MALFORMED_BODY");

    static const struct {
        uint8_t type;
        uint8_t flags;
        uint16_t meta_len;
        uint32_t stream_id;
        uint32_t value;
        uint32_t data_len;
        size_t body_len;
        int rc;
        st_protocol_rejection reason;
    } nat[] = {
        {9, 0, 0, 7, 100, 0, 16, 0, ST_PROTOCOL_REJECTION_NONE},
        {9, 0, 0, 7, 100, 0, 15, -1, ST_PROTOCOL_REJECTION_INVALID_LENGTH},
        {0, 0, 0, 7, 100, 0, 16, -1, ST_PROTOCOL_REJECTION_MALFORMED_BODY},
        {10, 0, 0, 7, 100, 0, 16, -1, ST_PROTOCOL_REJECTION_MALFORMED_BODY},
        {5, 2, 0, 7, 0, 0, 16, -1, ST_PROTOCOL_REJECTION_MALFORMED_BODY},
        {5, 0, 0, 7, 0, 4, 16, -1, ST_PROTOCOL_REJECTION_INVALID_LENGTH},
        {5, 0, 4, 7, 0, 0, 16, -1, ST_PROTOCOL_REJECTION_INVALID_LENGTH},
        {9, 0, 0, 7, 0, 0, 16, -1, ST_PROTOCOL_REJECTION_MALFORMED_BODY},
        {9, 0, 0, 0, 100, 0, 16, -1, ST_PROTOCOL_REJECTION_MALFORMED_BODY},
        {4, 0, 0, 7, 1, 0, 16, -1, ST_PROTOCOL_REJECTION_MALFORMED_BODY},
    };
    for (size_t i = 0; i < sizeof(nat) / sizeof(nat[0]); ++i) {
        uint8_t body[16];
        nat_body(body, nat[i].type, nat[i].flags, nat[i].meta_len, nat[i].stream_id, nat[i].value,
                 nat[i].data_len);
        st_nat_message decoded;
        int rc = st_protocol_decode_nat_message(body, nat[i].body_len, &decoded);
        EXPECT(rc == nat[i].rc && st_protocol_last_rejection() == nat[i].reason, "NAT case %zu: %d/%d, want %d/%d",
               i, rc, (int)st_protocol_last_rejection(), nat[i].rc, (int)nat[i].reason);
        if (rc == 0) st_nat_message_free(&decoded);
    }

    /*
     * Java PacketCodec's verdict on each body, for the frames the server loop does not otherwise
     * read: heartbeats and LOGOUT_REQUEST (no fields), LOGOUT_RESPONSE (success, reason) and the
     * frames it refuses unhandled. Each was checked against Java's PacketCodec.decode.
     */
    static const uint8_t one_zero[] = {0};
    static const uint8_t logout_ok[] = {1, 0};
    static const uint8_t logout_reason[] = {0, 3, 'n', 'o'};
    static const uint8_t logout_no_reason_field[] = {1};
    static const uint8_t logout_bad_boolean[] = {2, 0};
    static const uint8_t logout_trailing[] = {1, 0, 0};
    static const uint8_t logout_truncated_reason[] = {1, 5, 'a'};
    static const uint8_t logout_long_varint[] = {1, 0x80, 0x80, 0x80, 0x80, 0x80};
    static const uint8_t login_response_ok[] = {2, 'c', 1, 0};
    static const uint8_t login_response_bad_boolean[] = {2, 'c', 7, 0};
    static const uint8_t message_null_type[] = {2, 'a', 2, 'b', 0, 2, 'm'};
    static const uint8_t message_bad_type_body[] = {2, 'a', 2, 'b', 6, 2, 'm'};
    static const uint8_t nat_short[] = {6, 0, 0, 0};
    /* One byte over the login body limit (16 KiB frames before login, header included). */
    static const uint8_t oversized_login[ST_PRE_AUTH_MAX_FRAME_SIZE - ST_HEADER_SIZE + 1U] = {0};
    static const struct {
        int8_t command;
        const uint8_t *body;
        size_t body_len;
        int rc;
        st_protocol_rejection reason;
    } bodies[] = {
        {ST_CMD_HEARTBEAT_REQUEST, one_zero, 0, 0, ST_PROTOCOL_REJECTION_NONE},
        {ST_CMD_HEARTBEAT_REQUEST, one_zero, 1, -1, ST_PROTOCOL_REJECTION_MALFORMED_BODY},
        {ST_CMD_HEARTBEAT_RESPONSE, one_zero, 1, -1, ST_PROTOCOL_REJECTION_MALFORMED_BODY},
        {ST_CMD_LOGOUT_REQUEST, one_zero, 1, -1, ST_PROTOCOL_REJECTION_MALFORMED_BODY},
        {ST_CMD_LOGOUT_REQUEST, logout_ok, 2, -1, ST_PROTOCOL_REJECTION_MALFORMED_BODY},
        {ST_CMD_LOGOUT_RESPONSE, logout_ok, sizeof(logout_ok), 0, ST_PROTOCOL_REJECTION_NONE},
        {ST_CMD_LOGOUT_RESPONSE, logout_reason, sizeof(logout_reason), 0, ST_PROTOCOL_REJECTION_NONE},
        {ST_CMD_LOGOUT_RESPONSE, one_zero, 0, -1, ST_PROTOCOL_REJECTION_MALFORMED_BODY},
        {ST_CMD_LOGOUT_RESPONSE, logout_no_reason_field, sizeof(logout_no_reason_field), -1,
         ST_PROTOCOL_REJECTION_MALFORMED_BODY},
        {ST_CMD_LOGOUT_RESPONSE, logout_bad_boolean, sizeof(logout_bad_boolean), -1,
         ST_PROTOCOL_REJECTION_MALFORMED_BODY},
        {ST_CMD_LOGOUT_RESPONSE, logout_trailing, sizeof(logout_trailing), -1, ST_PROTOCOL_REJECTION_MALFORMED_BODY},
        {ST_CMD_LOGOUT_RESPONSE, logout_truncated_reason, sizeof(logout_truncated_reason), -1,
         ST_PROTOCOL_REJECTION_MALFORMED_BODY},
        {ST_CMD_LOGOUT_RESPONSE, logout_long_varint, sizeof(logout_long_varint), -1,
         ST_PROTOCOL_REJECTION_MALFORMED_BODY},
        {ST_CMD_LOGIN_RESPONSE, login_response_ok, sizeof(login_response_ok), 0, ST_PROTOCOL_REJECTION_NONE},
        {ST_CMD_LOGIN_RESPONSE, login_response_bad_boolean, sizeof(login_response_bad_boolean), -1,
         ST_PROTOCOL_REJECTION_MALFORMED_BODY},
        /* The codec reads any role, null too; the login handler is what refuses those. */
        {ST_CMD_LOGIN_REQUEST, login_ok, sizeof(login_ok), 0, ST_PROTOCOL_REJECTION_NONE},
        {ST_CMD_LOGIN_REQUEST, login_bad_role, sizeof(login_bad_role), 0, ST_PROTOCOL_REJECTION_NONE},
        {ST_CMD_LOGIN_REQUEST, login_null_role, sizeof(login_null_role), 0, ST_PROTOCOL_REJECTION_NONE},
        {ST_CMD_LOGIN_REQUEST, login_trailing, sizeof(login_trailing), -1, ST_PROTOCOL_REJECTION_MALFORMED_BODY},
        {ST_CMD_LOGIN_REQUEST, login_truncated, sizeof(login_truncated), -1, ST_PROTOCOL_REJECTION_MALFORMED_BODY},
        /* MessageTypeCodec reads 0 as a null messageType. */
        {ST_CMD_MESSAGE_RESPONSE, message_null_type, sizeof(message_null_type), 0, ST_PROTOCOL_REJECTION_NONE},
        {ST_CMD_MESSAGE_REQUEST, message_bad_type_body, sizeof(message_bad_type_body), -1,
         ST_PROTOCOL_REJECTION_MALFORMED_BODY},
        {ST_CMD_NAT_MESSAGE, nat_short, sizeof(nat_short), -1, ST_PROTOCOL_REJECTION_INVALID_LENGTH},
        {ST_CMD_LOGIN_REQUEST, oversized_login, sizeof(oversized_login), -1, ST_PROTOCOL_REJECTION_INVALID_LENGTH},
        {5, one_zero, 0, -1, ST_PROTOCOL_REJECTION_UNKNOWN_COMMAND},
    };
    for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); ++i) {
        int rc = st_protocol_validate_body(bodies[i].command, bodies[i].body, bodies[i].body_len);
        EXPECT(rc == bodies[i].rc && st_protocol_last_rejection() == bodies[i].reason,
               "body case %zu (command %d): %d/%d, want %d/%d", i, (int)bodies[i].command, rc,
               (int)st_protocol_last_rejection(), bodies[i].rc, (int)bodies[i].reason);
        int empty_command = bodies[i].command == ST_CMD_HEARTBEAT_REQUEST
            || bodies[i].command == ST_CMD_HEARTBEAT_RESPONSE || bodies[i].command == ST_CMD_LOGOUT_REQUEST;
        if (empty_command) {
            rc = st_protocol_decode_empty_packet(bodies[i].body, bodies[i].body_len);
            EXPECT(rc == bodies[i].rc && st_protocol_last_rejection() == bodies[i].reason,
                   "empty body case %zu: %d/%d", i, rc, (int)st_protocol_last_rejection());
        }
        if (bodies[i].command == ST_CMD_LOGOUT_RESPONSE) {
            st_logout_response logout;
            rc = st_protocol_decode_logout_response(bodies[i].body, bodies[i].body_len, &logout);
            EXPECT(rc == bodies[i].rc && st_protocol_last_rejection() == bodies[i].reason,
                   "logout response case %zu: %d/%d", i, rc, (int)st_protocol_last_rejection());
            if (rc == 0) st_logout_response_free(&logout);
        }
    }
}

/* ---- the other management settings Java reads (each case measured on the Java server) -------- */

static const char *const management_names[] = {
    "MANAGEMENT_ENDPOINT_METRICS_ACCESS", "MANAGEMENT_ENDPOINT_METRICS_ENABLED",
    "MANAGEMENT_ENDPOINTS_ACCESS_DEFAULT", "MANAGEMENT_ENDPOINTS_ENABLEDBYDEFAULT",
    "MANAGEMENT_ENDPOINTS_ENABLED_BY_DEFAULT", "MANAGEMENT_ENDPOINTS_ACCESS_MAXPERMITTED",
    "MANAGEMENT_ENDPOINTS_ACCESS_MAX_PERMITTED", "MANAGEMENT_SERVER_PORT", "MANAGEMENT_SERVER_ADDRESS",
    "MANAGEMENT_ENDPOINTS_WEB_BASEPATH", "MANAGEMENT_ENDPOINTS_WEB_BASE_PATH",
    "MANAGEMENT_ENDPOINTS_WEB_PATHMAPPING_METRICS", "MANAGEMENT_ENDPOINTS_WEB_PATH_MAPPING_METRICS",
};

static void clear_management(void)
{
    for (size_t i = 0; i < sizeof(management_names) / sizeof(management_names[0]); ++i) {
        unsetenv(management_names[i]);
    }
}

static void test_management_settings(void)
{
    static const struct {
        const char *settings[3];
        int expected;
    } cases[] = {
        {{NULL}, 1},
        {{"MANAGEMENT_ENDPOINT_METRICS_ACCESS=none"}, 0},
        {{"MANAGEMENT_ENDPOINT_METRICS_ACCESS=READ_ONLY"}, 1},
        {{"MANAGEMENT_ENDPOINT_METRICS_ACCESS=Read-Only"}, 1},
        {{"MANAGEMENT_ENDPOINT_METRICS_ACCESS=readOnly"}, 1},
        {{"MANAGEMENT_ENDPOINT_METRICS_ACCESS= "}, 1},
        {{"MANAGEMENT_ENDPOINT_METRICS_ACCESS=bogus"}, -1},
        {{"MANAGEMENT_ENDPOINT_METRICS_ENABLED=false"}, 0},
        {{"MANAGEMENT_ENDPOINT_METRICS_ENABLED=maybe"}, -1},
        {{"MANAGEMENT_ENDPOINT_METRICS_ACCESS=read-only", "MANAGEMENT_ENDPOINT_METRICS_ENABLED=true"}, -1},
        {{"MANAGEMENT_ENDPOINTS_ACCESS_DEFAULT=none"}, 0},
        {{"MANAGEMENT_ENDPOINTS_ACCESS_DEFAULT=none", "MANAGEMENT_ENDPOINT_METRICS_ACCESS=read-only"}, 1},
        {{"MANAGEMENT_ENDPOINTS_ACCESS_DEFAULT=none", "MANAGEMENT_ENDPOINT_METRICS_ENABLED=yes"}, 1},
        {{"MANAGEMENT_ENDPOINTS_ENABLEDBYDEFAULT=false"}, 0},
        {{"MANAGEMENT_ENDPOINTS_ENABLED_BY_DEFAULT=off"}, 0},
        {{"MANAGEMENT_ENDPOINTS_ENABLEDBYDEFAULT=true", "MANAGEMENT_ENDPOINT_METRICS_ACCESS=none"}, 0},
        {{"MANAGEMENT_ENDPOINTS_ACCESS_DEFAULT=none", "MANAGEMENT_ENDPOINTS_ENABLEDBYDEFAULT=false"}, -1},
        {{"MANAGEMENT_ENDPOINTS_ACCESS_MAXPERMITTED=none"}, 0},
        {{"MANAGEMENT_ENDPOINTS_ACCESS_MAX_PERMITTED=none"}, 0},
        {{"MANAGEMENT_ENDPOINTS_ACCESS_MAXPERMITTED=read-only"}, 1},
        {{"MANAGEMENT_ENDPOINT_METRICS_ACCESS=unrestricted", "MANAGEMENT_ENDPOINTS_ACCESS_MAXPERMITTED=none"}, 0},
        {{"MANAGEMENT_SERVER_PORT=-1"}, 0},
        {{"MANAGEMENT_SERVER_PORT=0"}, 0},
        {{"MANAGEMENT_SERVER_PORT=9090"}, 0},
        {{"MANAGEMENT_SERVER_PORT=8088"}, 1},
        {{"MANAGEMENT_SERVER_PORT= 80 88 "}, 1},
        {{"MANAGEMENT_SERVER_PORT=0x1F98"}, 1},
        {{"MANAGEMENT_SERVER_PORT=x1"}, -1},
        {{"MANAGEMENT_SERVER_PORT=+0x1F98"}, -1},
        {{"MANAGEMENT_SERVER_ADDRESS=127.0.0.2"}, -1},
        {{"MANAGEMENT_SERVER_ADDRESS=127.0.0.2", "MANAGEMENT_SERVER_PORT=9090"}, 0},
        {{"MANAGEMENT_SERVER_ADDRESS= "}, 1},
        {{"MANAGEMENT_ENDPOINTS_WEB_BASEPATH=/manage/"}, 0},
        {{"MANAGEMENT_ENDPOINTS_WEB_BASE_PATH=/"}, 0},
        {{"MANAGEMENT_ENDPOINTS_WEB_BASEPATH="}, 0},
        {{"MANAGEMENT_ENDPOINTS_WEB_BASEPATH=/actuator/"}, 1},
        {{"MANAGEMENT_ENDPOINTS_WEB_BASEPATH=manage"}, -1},
        {{"MANAGEMENT_ENDPOINTS_WEB_PATHMAPPING_METRICS=stats"}, 0},
        {{"MANAGEMENT_ENDPOINTS_WEB_PATH_MAPPING_METRICS=stats"}, 0},
        {{"MANAGEMENT_ENDPOINTS_WEB_PATHMAPPING_METRICS=metrics"}, 1},
    };
    setenv("SPECUS_ADMIN_PORT", "8088", 1);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        clear_management();
        char label[256] = "";
        for (size_t s = 0; s < 3U && cases[i].settings[s] != NULL; ++s) {
            char assignment[160];
            snprintf(assignment, sizeof(assignment), "%s", cases[i].settings[s]);
            char *equals = strchr(assignment, '=');
            *equals = '\0';
            setenv(assignment, equals + 1, 1);
            strncat(label, cases[i].settings[s], sizeof(label) - strlen(label) - 2U);
            strcat(label, " ");
        }
        int valid = st_metrics_validate_current() == 0;
        int exposed = st_metrics_endpoint_exposed();
        answer value;
        ask("GET", "/actuator/metrics", NULL, &value);
        int expected_valid = cases[i].expected >= 0;
        int expected_exposed = cases[i].expected == 1;
        EXPECT(valid == expected_valid && exposed == expected_exposed && (value.rc == 1) == expected_exposed,
               "%s: valid %d exposed %d answered %d, want %d", label, valid, exposed, value.rc, cases[i].expected);
        release(&value);
    }
    clear_management();
    unsetenv("SPECUS_ADMIN_PORT");
}

int main(void)
{
    test_format_double();
    test_exposure();
    setenv("MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE", "metrics", 1);
    test_management_settings();
    setenv("MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE", "health,metrics", 1);
    unsetenv("MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_EXCLUDE");
    test_java_bodies();
    test_tags();
    test_routes();
    test_negotiation();
    test_methods();
    test_values();
    test_protocol_reasons();
    if (failures != 0) {
        fprintf(stderr, "%d metrics check(s) failed\n", failures);
        return 1;
    }
    printf("metrics tests passed\n");
    return 0;
}
