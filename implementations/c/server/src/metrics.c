#define _POSIX_C_SOURCE 200809L

#include "metrics.h"

#include <float.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
 * The Java server's custom Micrometer meters. Java registers them in its bean constructors and the
 * actuator endpoint reads them from a SimpleMeterRegistry (no Prometheus registry is on its
 * classpath); the JVM, Tomcat, HikariCP and Spring meters Spring Boot adds beside them have no C
 * counterpart. The table order is the order meters of one name are merged in, so the tag values of
 * specus.control.protocol.rejected come out in the order the Java server answered with (Java takes
 * them from a HashSet).
 */
typedef enum {
    METER_COUNTER,
    METER_GAUGE
} meter_kind;

typedef enum {
    GAUGE_NONE,
    GAUGE_TLS_EXPIRY,
    GAUGE_TLS_MODE,
    GAUGE_ZERO,
    GAUGE_RELAY_PENDING,
    GAUGE_FLUSH_LAG
} gauge_kind;

typedef struct {
    const char *name;
    const char *description;
    const char *base_unit;
    const char *tag_key;
    /* NULL with a tag key: the value is the current TLS mode. */
    const char *tag_value;
    meter_kind kind;
    /* A counter's slot: an st_metric_counter, or a protocol reason after them. */
    int slot;
    gauge_kind gauge;
} meter;

#define COUNTER_SLOTS (ST_METRIC_RELAY_TRAFFIC_FLUSH_FAILURES + 1)
#define PROTOCOL_SLOT(reason) (COUNTER_SLOTS + (int)(reason))
#define SLOT_COUNT (COUNTER_SLOTS + (int)ST_PROTOCOL_REJECTION_MALFORMED_BODY + 1)

static const meter meters[] = {
    /* NettyServer */
    {"specus.control.plaintext.deployment.rejected", NULL, NULL, NULL, NULL, METER_COUNTER,
     ST_METRIC_CONTROL_PLAINTEXT_DEPLOYMENT_REJECTED, GAUGE_NONE},
    {"specus.control.tls.certificate.expiry.epoch.seconds", NULL, NULL, NULL, NULL, METER_GAUGE, -1,
     GAUGE_TLS_EXPIRY},
    {"specus.control.tls.mode", NULL, NULL, "mode", NULL, METER_GAUGE, -1, GAUGE_TLS_MODE},
    /* ControlProtocolMetricsHandler: one counter per ProtocolException.Reason */
    {"specus.control.protocol.rejected", NULL, NULL, "reason", "invalid_length", METER_COUNTER,
     PROTOCOL_SLOT(ST_PROTOCOL_REJECTION_INVALID_LENGTH), GAUGE_NONE},
    {"specus.control.protocol.rejected", NULL, NULL, "reason", "unknown_command", METER_COUNTER,
     PROTOCOL_SLOT(ST_PROTOCOL_REJECTION_UNKNOWN_COMMAND), GAUGE_NONE},
    {"specus.control.protocol.rejected", NULL, NULL, "reason", "invalid_magic", METER_COUNTER,
     PROTOCOL_SLOT(ST_PROTOCOL_REJECTION_INVALID_MAGIC), GAUGE_NONE},
    {"specus.control.protocol.rejected", NULL, NULL, "reason", "unsupported_version", METER_COUNTER,
     PROTOCOL_SLOT(ST_PROTOCOL_REJECTION_UNSUPPORTED_VERSION), GAUGE_NONE},
    {"specus.control.protocol.rejected", NULL, NULL, "reason", "unsupported_serializer", METER_COUNTER,
     PROTOCOL_SLOT(ST_PROTOCOL_REJECTION_UNSUPPORTED_SERIALIZER), GAUGE_NONE},
    {"specus.control.protocol.rejected", NULL, NULL, "reason", "malformed_body", METER_COUNTER,
     PROTOCOL_SLOT(ST_PROTOCOL_REJECTION_MALFORMED_BODY), GAUGE_NONE},
    {"specus.control.preauth.oversize.rejected", NULL, NULL, NULL, NULL, METER_COUNTER,
     ST_METRIC_CONTROL_PREAUTH_OVERSIZE_REJECTED, GAUGE_NONE},
    /* StunTurnServer */
    {"specus.peer_mesh.turn.relay.queue.dropped", "TURN relay tasks rejected by the bounded worker queue", NULL,
     NULL, NULL, METER_COUNTER, ST_METRIC_TURN_RELAY_QUEUE_DROPPED, GAUGE_NONE},
    {"specus.peer_mesh.turn.relay.send.failures", "TURN relay datagrams that failed during send", NULL, NULL, NULL,
     METER_COUNTER, ST_METRIC_TURN_RELAY_SEND_FAILURES, GAUGE_NONE},
    {"specus.peer_mesh.turn.general_relay.quota.rejected", "General TURN relay allocations rejected by quota", NULL,
     NULL, NULL, METER_COUNTER, ST_METRIC_TURN_GENERAL_RELAY_QUOTA_REJECTED, GAUGE_NONE},
    {"specus.peer_mesh.turn.general_relay.destination.forbidden",
     "General TURN relay permissions rejected by the destination policy", NULL, NULL, NULL, METER_COUNTER,
     ST_METRIC_TURN_GENERAL_RELAY_DESTINATION_FORBIDDEN, GAUGE_NONE},
    {"specus.peer_mesh.turn.general_relay.bytes", "Bytes relayed on behalf of general TURN allocations", NULL, NULL,
     NULL, METER_COUNTER, ST_METRIC_TURN_GENERAL_RELAY_BYTES, GAUGE_NONE},
    {"specus.peer_mesh.turn.general_relay.quota.closed",
     "General TURN allocations closed after exhausting the byte quota", NULL, NULL, NULL, METER_COUNTER,
     ST_METRIC_TURN_GENERAL_RELAY_QUOTA_CLOSED, GAUGE_NONE},
    {"specus.peer_mesh.turn.relay.queue.depth", "Current TURN relay worker queue depth", NULL, NULL, NULL,
     METER_GAUGE, -1, GAUGE_ZERO},
    {"specus.peer_mesh.turn.relay.queue.high.water", "Maximum observed TURN relay worker queue depth", NULL, NULL,
     NULL, METER_GAUGE, -1, GAUGE_ZERO},
    /* PeerMeshService */
    {"specus.peer_mesh.relay.traffic.flush.failures", "Relay traffic batches restored after a persistence failure",
     NULL, NULL, NULL, METER_COUNTER, ST_METRIC_RELAY_TRAFFIC_FLUSH_FAILURES, GAUGE_NONE},
    {"specus.peer_mesh.relay.traffic.pending.bytes", "Relay traffic bytes waiting to be persisted", NULL, NULL, NULL,
     METER_GAUGE, -1, GAUGE_RELAY_PENDING},
    {"specus.peer_mesh.relay.traffic.flush.lag.seconds", "Seconds since the last successful relay traffic flush",
     NULL, NULL, NULL, METER_GAUGE, -1, GAUGE_FLUSH_LAG},
};

#define METER_COUNT (sizeof(meters) / sizeof(meters[0]))

static atomic_ullong counter_values[SLOT_COUNT];
static atomic_llong tls_certificate_expiry;
/* Monotonic milliseconds of the last written relay batch, 0 before the first. */
static atomic_llong relay_flush_success_ms;
static pthread_mutex_t metrics_lock = PTHREAD_MUTEX_INITIALIZER;
static char tls_mode[32] = "disabled";
static st_metrics_gauge_source relay_pending_source;

void st_metrics_add(st_metric_counter counter, unsigned long long amount)
{
    if ((int)counter < 0 || (int)counter >= COUNTER_SLOTS) {
        return;
    }
    atomic_fetch_add_explicit(&counter_values[counter], amount, memory_order_relaxed);
}

void st_metrics_increment(st_metric_counter counter)
{
    st_metrics_add(counter, 1ULL);
}

void st_metrics_protocol_rejected(st_protocol_rejection reason)
{
    if (reason <= ST_PROTOCOL_REJECTION_NONE || reason > ST_PROTOCOL_REJECTION_MALFORMED_BODY) {
        return;
    }
    atomic_fetch_add_explicit(&counter_values[PROTOCOL_SLOT(reason)], 1ULL, memory_order_relaxed);
}

void st_metrics_set_control_tls(const char *mode, long long certificate_expiry_epoch_seconds)
{
    pthread_mutex_lock(&metrics_lock);
    snprintf(tls_mode, sizeof(tls_mode), "%s", mode == NULL || *mode == '\0' ? "disabled" : mode);
    pthread_mutex_unlock(&metrics_lock);
    atomic_store(&tls_certificate_expiry, certificate_expiry_epoch_seconds);
}

void st_metrics_set_relay_pending_bytes_source(st_metrics_gauge_source source)
{
    pthread_mutex_lock(&metrics_lock);
    relay_pending_source = source;
    pthread_mutex_unlock(&metrics_lock);
}

static long long metrics_monotonic_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }
    return (long long)now.tv_sec * 1000LL + now.tv_nsec / 1000000L;
}

void st_metrics_relay_traffic_flushed(void)
{
    long long now = metrics_monotonic_ms();
    atomic_store(&relay_flush_success_ms, now > 0 ? now : 1);
}

void st_metrics_reset(void)
{
    for (int i = 0; i < SLOT_COUNT; ++i) {
        atomic_store(&counter_values[i], 0ULL);
    }
    atomic_store(&relay_flush_success_ms, 0LL);
    st_metrics_set_control_tls("disabled", 0);
}

static double meter_value(const meter *entry)
{
    if (entry->kind == METER_COUNTER) {
        return (double)atomic_load_explicit(&counter_values[entry->slot], memory_order_relaxed);
    }
    switch (entry->gauge) {
        case GAUGE_TLS_EXPIRY:
            return (double)atomic_load(&tls_certificate_expiry);
        case GAUGE_TLS_MODE:
            return 1.0;
        case GAUGE_RELAY_PENDING: {
            pthread_mutex_lock(&metrics_lock);
            st_metrics_gauge_source source = relay_pending_source;
            pthread_mutex_unlock(&metrics_lock);
            return source == NULL ? 0.0 : source();
        }
        case GAUGE_FLUSH_LAG: {
            /* Java: 0 before the first success, then the whole milliseconds since it, in seconds. */
            long long last = atomic_load(&relay_flush_success_ms);
            if (last <= 0) {
                return 0.0;
            }
            long long elapsed = metrics_monotonic_ms() - last;
            return (double)(elapsed < 0 ? 0 : elapsed) / 1000.0;
        }
        default:
            return 0.0;
    }
}

/* The meter's tag value; tls_mode is copied under the lock into buffer. */
static const char *meter_tag_value(const meter *entry, char *buffer, size_t buffer_len)
{
    if (entry->tag_key == NULL) {
        return NULL;
    }
    if (entry->tag_value != NULL) {
        return entry->tag_value;
    }
    pthread_mutex_lock(&metrics_lock);
    snprintf(buffer, buffer_len, "%s", tls_mode);
    pthread_mutex_unlock(&metrics_lock);
    return buffer;
}

int st_metrics_measure(const char *name, const char *tag_key, const char *tag_value, double *value)
{
    int found = 0;
    double total = 0.0;
    for (size_t i = 0; name != NULL && i < METER_COUNT; ++i) {
        const meter *entry = &meters[i];
        if (strcmp(entry->name, name) != 0) {
            continue;
        }
        if (tag_key != NULL) {
            char buffer[32];
            const char *own = meter_tag_value(entry, buffer, sizeof(buffer));
            if (entry->tag_key == NULL || strcmp(entry->tag_key, tag_key) != 0 || tag_value == NULL
                || strcmp(own, tag_value) != 0) {
                continue;
            }
        }
        total += meter_value(entry);
        found = 1;
    }
    if (found && value != NULL) {
        *value = total;
    }
    return found ? 0 : -1;
}

/* ---- Java's Double.toString ------------------------------------------------------------------ */

/*
 * The shortest decimal that reads back as value (Java 19+ picks the same one: the shortest that
 * rounds to the double, and among one- and two-digit candidates the closest), as its digits and
 * the decimal exponent of the first: value = 0.d1d2... * 10^(exponent + 1).
 */
static void shortest_digits(double value, char digits[24], int *exponent)
{
    char text[40];
    int precision = 1;
    for (; precision <= 17; ++precision) {
        snprintf(text, sizeof(text), "%.*e", precision - 1, value);
        if (strtod(text, NULL) == value) {
            break;
        }
    }
    if (precision == 1) {
        /* Java considers the two-digit decimals too when one digit suffices, and takes the closest. */
        char two[40];
        snprintf(two, sizeof(two), "%.1e", value);
        long double exact = (long double)value;
        long double one_error = strtold(text, NULL) - exact;
        long double two_error = strtold(two, NULL) - exact;
        if (one_error < 0) one_error = -one_error;
        if (two_error < 0) two_error = -two_error;
        if (strtod(two, NULL) == value && two_error < one_error) {
            memcpy(text, two, sizeof(two));
        }
    }
    size_t count = 0;
    const char *cursor = text;
    while (*cursor != '\0' && *cursor != 'e') {
        if (*cursor >= '0' && *cursor <= '9' && count < 23U) {
            digits[count++] = *cursor;
        }
        ++cursor;
    }
    while (count > 1U && digits[count - 1U] == '0') {
        --count;
    }
    digits[count] = '\0';
    *exponent = *cursor == 'e' ? atoi(cursor + 1) : 0;
}

int st_metrics_format_double(double value, char *out, size_t out_len)
{
    if (out == NULL || out_len == 0U) {
        return -1;
    }
    int written;
    if (value != value) {
        written = snprintf(out, out_len, "NaN");
    } else if (value > DBL_MAX || value < -DBL_MAX) {
        written = snprintf(out, out_len, "%sInfinity", value < 0 ? "-" : "");
    } else if (value == 0.0) {
        uint64_t bits = 0;
        memcpy(&bits, &value, sizeof(bits));
        written = snprintf(out, out_len, "%s0.0", (bits >> 63U) != 0U ? "-" : "");
    } else {
        const char *sign = value < 0 ? "-" : "";
        char digits[24];
        int exponent = 0;
        shortest_digits(value < 0 ? -value : value, digits, &exponent);
        size_t count = strlen(digits);
        char body[64];
        if (exponent >= -3 && exponent < 7) {
            /* Plain notation with at least one digit after the point: 100.0, 0.001, 16.917. */
            size_t used = 0;
            if (exponent < 0) {
                used += (size_t)snprintf(body, sizeof(body), "0.");
                for (int zero = -1; zero > exponent; --zero) body[used++] = '0';
                used += (size_t)snprintf(body + used, sizeof(body) - used, "%s", digits);
            } else {
                size_t whole = (size_t)exponent + 1U;
                for (size_t i = 0; i < whole; ++i) body[used++] = i < count ? digits[i] : '0';
                body[used++] = '.';
                if (count > whole) {
                    used += (size_t)snprintf(body + used, sizeof(body) - used, "%s", digits + whole);
                } else {
                    body[used++] = '0';
                    body[used] = '\0';
                }
            }
            body[used] = '\0';
        } else {
            /* Computerized scientific notation: 1.0E7, 3.60843048E8, 1.0E-4. */
            snprintf(body, sizeof(body), "%c.%sE%d", digits[0], count > 1U ? digits + 1 : "0", exponent);
        }
        written = snprintf(out, out_len, "%s%s", sign, body);
    }
    return written < 0 || (size_t)written >= out_len ? -1 : 0;
}

/* ---- management.endpoints.web.exposure ------------------------------------------------------- */

static void set_error(char *error, size_t error_len, const char *message)
{
    if (error != NULL && error_len > 0U) {
        snprintf(error, error_len, "%s", message);
    }
}

/*
 * One endpoint id as Spring's EndpointId.fromPropertyValue reads it: dashes dropped, then refused
 * when empty, with a character outside [a-zA-Z0-9.], or starting with a digit or an uppercase
 * letter. Ids are equal when their lowercase letters and digits are, so "me-trics" and "mETRICS"
 * name the metrics endpoint. Returns 1 when it is metrics, 0 when another id, -1 when refused.
 */
static int endpoint_id_is_metrics(const char *start, const char *end, char *error, size_t error_len)
{
    static const char metrics[] = "metrics";
    char first = '\0';
    int has_text = 0;
    int valid = 1;
    size_t matched = 0;
    int other = 0;
    for (const char *cursor = start; cursor < end; ++cursor) {
        char c = *cursor;
        if (c == '-') {
            continue;
        }
        if (first == '\0') {
            first = c;
        }
        if (!(c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v')) {
            has_text = 1;
        }
        int letter = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
        int digit = c >= '0' && c <= '9';
        if (!letter && !digit && c != '.') {
            valid = 0;
            continue;
        }
        if (c == '.') {
            continue;
        }
        char lower = (char)(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
        if (!other && matched < sizeof(metrics) - 1U && metrics[matched] == lower) {
            ++matched;
        } else {
            other = 1;
        }
    }
    if (first == '\0' || !has_text) {
        set_error(error, error_len, "'value' must not be empty");
        return -1;
    }
    if (!valid) {
        set_error(error, error_len, "'value' must only contain valid chars");
        return -1;
    }
    if (first >= '0' && first <= '9') {
        set_error(error, error_len, "'value' must not start with a number");
        return -1;
    }
    if (first >= 'A' && first <= 'Z') {
        set_error(error, error_len, "'value' must not start with an uppercase letter");
        return -1;
    }
    return !other && matched == sizeof(metrics) - 1U;
}

/*
 * A comma-separated property bound to a set as Spring Boot binds it: nothing for "", otherwise
 * every element trimmed (String.trim), an empty one included. *names is 1 when "*" or the metrics
 * id is among them. 0, or -1 for an id EndpointId refuses.
 */
static int exposure_list(const char *list, int *names, char *error, size_t error_len)
{
    *names = 0;
    if (list == NULL || *list == '\0') {
        return 0;
    }
    const char *cursor = list;
    for (;;) {
        size_t len = strcspn(cursor, ",");
        const char *start = cursor;
        const char *end = cursor + len;
        while (start < end && (unsigned char)*start <= ' ') ++start;
        while (end > start && (unsigned char)end[-1] <= ' ') --end;
        if (end - start == 1 && *start == '*') {
            *names = 1;
        } else {
            int metrics = endpoint_id_is_metrics(start, end, error, error_len);
            if (metrics < 0) {
                return -1;
            }
            *names = *names || metrics;
        }
        if (cursor[len] == '\0') {
            break;
        }
        cursor += len + 1U;
    }
    return 0;
}

int st_metrics_exposure(const char *include, const char *exclude, char *error, size_t error_len)
{
    int included = 0;
    int excluded = 0;
    /* Spring Boot's default web exposure is health alone, and an empty include falls back to it. */
    if (exposure_list(include, &included, error, error_len) != 0
        || exposure_list(exclude, &excluded, error, error_len) != 0) {
        return -1;
    }
    return included && !excluded;
}

int st_metrics_endpoint_exposed(void)
{
    return st_metrics_exposure(getenv("MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE"),
                               getenv("MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_EXCLUDE"), NULL, 0U) == 1;
}

int st_metrics_validate_current(void)
{
    static const char *const names[] = {
        "MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE", "MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_EXCLUDE"
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        char error[128];
        int ignored = 0;
        const char *value = getenv(names[i]);
        if (exposure_list(value, &ignored, error, sizeof(error)) != 0) {
            fprintf(stderr, "[metrics] %s=\"%s\" refused: %s\n", names[i], value, error);
            return -1;
        }
    }
    return 0;
}

/* ---- the actuator metrics endpoint ----------------------------------------------------------- */

typedef struct {
    char *data;
    size_t len;
    size_t cap;
    int failed;
} text_builder;

static void buffer_append(text_builder *out, const char *text, size_t len)
{
    if (out->failed) {
        return;
    }
    if (out->len + len + 1U > out->cap) {
        size_t cap = out->cap == 0U ? 512U : out->cap;
        while (out->len + len + 1U > cap) cap *= 2U;
        char *grown = (char *)realloc(out->data, cap);
        if (grown == NULL) {
            out->failed = 1;
            return;
        }
        out->data = grown;
        out->cap = cap;
    }
    memcpy(out->data + out->len, text, len);
    out->len += len;
    out->data[out->len] = '\0';
}

static void buffer_puts(text_builder *out, const char *text)
{
    buffer_append(out, text, strlen(text));
}

static void buffer_json_string(text_builder *out, const char *text)
{
    buffer_puts(out, "\"");
    for (const unsigned char *cursor = (const unsigned char *)text; *cursor != '\0'; ++cursor) {
        char escaped[8];
        if (*cursor == '"' || *cursor == '\\') {
            escaped[0] = '\\';
            escaped[1] = (char)*cursor;
            buffer_append(out, escaped, 2U);
        } else if (*cursor < 0x20U) {
            snprintf(escaped, sizeof(escaped), "\\u%04x", (unsigned)*cursor);
            buffer_puts(out, escaped);
        } else {
            buffer_append(out, (const char *)cursor, 1U);
        }
    }
    buffer_puts(out, "\"");
}

static int names_compare(const void *left, const void *right)
{
    return strcmp(*(const char *const *)left, *(const char *const *)right);
}

/* MetricsEndpoint.listNames: every name once, in TreeSet order. */
static void write_names(text_builder *out)
{
    const char *names[METER_COUNT];
    size_t count = 0;
    for (size_t i = 0; i < METER_COUNT; ++i) {
        int seen = 0;
        for (size_t j = 0; j < count && !seen; ++j) seen = strcmp(names[j], meters[i].name) == 0;
        if (!seen) names[count++] = meters[i].name;
    }
    qsort(names, count, sizeof(names[0]), names_compare);
    buffer_puts(out, "{\"names\":[");
    for (size_t i = 0; i < count; ++i) {
        if (i > 0U) buffer_puts(out, ",");
        buffer_json_string(out, names[i]);
    }
    buffer_puts(out, "]}");
}

typedef struct {
    char *key;
    char *value;
} requested_tag;

static void free_tags(requested_tag *tags, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        free(tags[i].key);
        free(tags[i].value);
    }
    free(tags);
}

static int hex_digit(char c)
{
    return c >= '0' && c <= '9' ? c - '0'
        : (c >= 'a' && c <= 'f' ? c - 'a' + 10 : (c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1));
}

/* A query name or value as Tomcat decodes it: escapes decoded, '+' a space, a broken escape literal. */
static char *query_decode(const char *text, size_t len)
{
    char *copy = (char *)malloc(len + 1U);
    if (copy == NULL) {
        return NULL;
    }
    size_t used = 0;
    for (size_t i = 0; i < len; ++i) {
        int high = 0;
        int low = 0;
        if (text[i] == '%' && i + 2U < len
            && (high = hex_digit(text[i + 1U])) >= 0 && (low = hex_digit(text[i + 2U])) >= 0) {
            copy[used++] = (char)((high << 4) | low);
            i += 2U;
        } else {
            copy[used++] = text[i] == '+' ? ' ' : text[i];
        }
    }
    copy[used] = '\0';
    return copy;
}

/* Appends one "key:value" as MetricsEndpoint.parseTag reads it; -2 when it has no colon. */
static int add_tag(requested_tag **tags, size_t *count, const char *text, size_t len)
{
    const char *colon = memchr(text, ':', len);
    if (colon == NULL) {
        return -2;
    }
    requested_tag *grown = (requested_tag *)realloc(*tags, (*count + 1U) * sizeof(**tags));
    if (grown == NULL) {
        return -1;
    }
    *tags = grown;
    size_t key_len = (size_t)(colon - text);
    requested_tag *tag = &(*tags)[*count];
    tag->key = (char *)malloc(key_len + 1U);
    tag->value = (char *)malloc(len - key_len);
    if (tag->key == NULL || tag->value == NULL) {
        free(tag->key);
        free(tag->value);
        return -1;
    }
    memcpy(tag->key, text, key_len);
    tag->key[key_len] = '\0';
    memcpy(tag->value, colon + 1, len - key_len - 1U);
    tag->value[len - key_len - 1U] = '\0';
    ++*count;
    return 0;
}

/*
 * The tag parameters of the request as the actuator binds List<String> tag: one value is split at
 * commas and every part trimmed ("" is no tag at all), several values are taken as they are. 0, -2
 * for a part that is not key:value (Java's 400), -1 when memory runs out.
 */
static int parse_tags(const char *path, requested_tag **tags, size_t *count)
{
    *tags = NULL;
    *count = 0;
    const char *query = strchr(path, '?');
    if (query == NULL) {
        return 0;
    }
    ++query;
    char **values = NULL;
    size_t value_count = 0;
    int rc = 0;
    while (*query != '\0' && rc == 0) {
        size_t part_len = strcspn(query, "&");
        size_t name_len = strcspn(query, "=&");
        char *name = part_len == 0U ? NULL : query_decode(query, name_len);
        if (part_len != 0U && name == NULL) {
            rc = -1;
        } else if (name != NULL && strcmp(name, "tag") == 0) {
            size_t value_start = name_len < part_len ? name_len + 1U : part_len;
            char *value = query_decode(query + value_start, part_len - value_start);
            char **grown = value == NULL ? NULL : (char **)realloc(values, (value_count + 1U) * sizeof(*values));
            if (grown == NULL) {
                free(value);
                rc = -1;
            } else {
                values = grown;
                values[value_count++] = value;
            }
        }
        free(name);
        query += part_len;
        if (*query == '&') ++query;
    }
    if (rc == 0 && value_count == 1U && values[0][0] != '\0') {
        const char *cursor = values[0];
        for (;;) {
            size_t len = strcspn(cursor, ",");
            const char *start = cursor;
            const char *end = cursor + len;
            while (start < end && (unsigned char)*start <= ' ') ++start;
            while (end > start && (unsigned char)end[-1] <= ' ') --end;
            rc = add_tag(tags, count, start, (size_t)(end - start));
            if (rc != 0 || cursor[len] == '\0') break;
            cursor += len + 1U;
        }
    } else if (rc == 0 && value_count > 1U) {
        for (size_t i = 0; i < value_count && rc == 0; ++i) {
            rc = add_tag(tags, count, values[i], strlen(values[i]));
        }
    }
    for (size_t i = 0; i < value_count; ++i) free(values[i]);
    free(values);
    if (rc != 0) {
        free_tags(*tags, *count);
        *tags = NULL;
        *count = 0;
    }
    return rc;
}

/* One tag key of availableTags with its values, both in the order they were first met. */
typedef struct {
    const char *key;
    char values[METER_COUNT][32];
    size_t value_count;
} available_tag;

/*
 * MetricsEndpoint.metric: the meters of name that carry every requested tag, their measurements
 * merged (summed, as COUNT and VALUE are) and the tags they have beyond the requested keys.
 * 1 when written, 0 when no meter matches (Java's 404).
 */
static int write_metric(text_builder *out, const char *name, const requested_tag *tags, size_t tag_count)
{
    const meter *first = NULL;
    double total = 0.0;
    available_tag available[METER_COUNT];
    size_t available_count = 0;
    for (size_t i = 0; i < METER_COUNT; ++i) {
        const meter *entry = &meters[i];
        if (strcmp(entry->name, name) != 0) {
            continue;
        }
        char buffer_value[32];
        const char *own = meter_tag_value(entry, buffer_value, sizeof(buffer_value));
        int matches = 1;
        for (size_t t = 0; t < tag_count && matches; ++t) {
            matches = entry->tag_key != NULL && strcmp(entry->tag_key, tags[t].key) == 0
                && strcmp(own, tags[t].value) == 0;
        }
        if (!matches) {
            continue;
        }
        if (first == NULL) {
            first = entry;
        }
        total += meter_value(entry);
        int requested = 0;
        for (size_t t = 0; entry->tag_key != NULL && t < tag_count && !requested; ++t) {
            requested = strcmp(entry->tag_key, tags[t].key) == 0;
        }
        if (entry->tag_key == NULL || requested) {
            continue;
        }
        available_tag *slot = NULL;
        for (size_t a = 0; a < available_count && slot == NULL; ++a) {
            if (strcmp(available[a].key, entry->tag_key) == 0) slot = &available[a];
        }
        if (slot == NULL) {
            slot = &available[available_count++];
            slot->key = entry->tag_key;
            slot->value_count = 0;
        }
        int seen = 0;
        for (size_t v = 0; v < slot->value_count && !seen; ++v) seen = strcmp(slot->values[v], own) == 0;
        if (!seen) {
            snprintf(slot->values[slot->value_count++], sizeof(slot->values[0]), "%s", own);
        }
    }
    if (first == NULL) {
        return 0;
    }
    /* Jackson writes the descriptor's properties in alphabetical order and leaves out the nulls. */
    buffer_puts(out, "{\"availableTags\":[");
    for (size_t a = 0; a < available_count; ++a) {
        if (a > 0U) buffer_puts(out, ",");
        buffer_puts(out, "{\"tag\":");
        buffer_json_string(out, available[a].key);
        buffer_puts(out, ",\"values\":[");
        for (size_t v = 0; v < available[a].value_count; ++v) {
            if (v > 0U) buffer_puts(out, ",");
            buffer_json_string(out, available[a].values[v]);
        }
        buffer_puts(out, "]}");
    }
    buffer_puts(out, "]");
    if (first->base_unit != NULL) {
        buffer_puts(out, ",\"baseUnit\":");
        buffer_json_string(out, first->base_unit);
    }
    if (first->description != NULL) {
        buffer_puts(out, ",\"description\":");
        buffer_json_string(out, first->description);
    }
    char value[40];
    if (st_metrics_format_double(total, value, sizeof(value)) != 0) {
        snprintf(value, sizeof(value), "0.0");
    }
    buffer_puts(out, ",\"measurements\":[{\"statistic\":\"");
    buffer_puts(out, first->kind == METER_COUNTER ? "COUNT" : "VALUE");
    buffer_puts(out, "\",\"value\":");
    /* Jackson writes NaN and the infinities as strings. */
    int number = strcmp(value, "NaN") != 0 && strstr(value, "Infinity") == NULL;
    if (!number) buffer_puts(out, "\"");
    buffer_puts(out, value);
    if (!number) buffer_puts(out, "\"");
    buffer_puts(out, "}],\"name\":");
    buffer_json_string(out, name);
    buffer_puts(out, "}");
    return 1;
}

static const char *const produced_types[] = {
    "application/vnd.spring-boot.actuator.v3+json",
    "application/vnd.spring-boot.actuator.v2+json",
    "application/json"
};
#define PRODUCED_COUNT (sizeof(produced_types) / sizeof(produced_types[0]))

static int token_char(char c)
{
    return c > ' ' && c < 0x7f && strchr("()<>@,;:\\\"/[]?={}", c) == NULL;
}

static int ascii_equal_ignore_case(const char *left, size_t left_len, const char *right, size_t right_len)
{
    if (left_len != right_len) {
        return 0;
    }
    for (size_t i = 0; i < left_len; ++i) {
        char a = left[i] >= 'A' && left[i] <= 'Z' ? (char)(left[i] - 'A' + 'a') : left[i];
        char b = right[i] >= 'A' && right[i] <= 'Z' ? (char)(right[i] - 'A' + 'a') : right[i];
        if (a != b) return 0;
    }
    return 1;
}

/* MimeType.isCompatibleWith for one Accept range and an application/... type the endpoint produces. */
static int range_accepts(const char *type, size_t type_len, const char *subtype, size_t subtype_len,
                         const char *produced)
{
    const char *produced_subtype = strchr(produced, '/') + 1;
    if (type_len == 1U && type[0] == '*') {
        return 1;
    }
    if (!ascii_equal_ignore_case(type, type_len, "application", 11U)) {
        return 0;
    }
    if ((subtype_len == 1U && subtype[0] == '*')
        || ascii_equal_ignore_case(subtype, subtype_len, produced_subtype, strlen(produced_subtype))) {
        return 1;
    }
    /* A suffix wildcard: the subtype *+json takes every +json subtype. */
    if (subtype_len > 2U && subtype[0] == '*' && subtype[1] == '+') {
        const char *suffix = strchr(produced_subtype, '+');
        return suffix != NULL
            && ascii_equal_ignore_case(subtype + 1, subtype_len - 1U, suffix, strlen(suffix));
    }
    return 0;
}

/*
 * The produced type Spring MVC picks for the Accept header: every (range, produced type) pair that
 * is compatible, ordered by the range's quality (stable, so the header's order and then the
 * endpoint's v3, v2, json order decide ties). -1 when none is acceptable or the header does not
 * parse (both 406 in Java).
 */
static int negotiate(const char *accept)
{
    if (accept == NULL) {
        return 0;
    }
    const char *cursor = accept;
    while (*cursor == ' ' || *cursor == '\t') ++cursor;
    if (*cursor == '\0') {
        return 0;
    }
    int best = -1;
    double best_quality = -1.0;
    for (;;) {
        size_t len = strcspn(cursor, ",");
        const char *start = cursor;
        const char *end = cursor + len;
        while (start < end && (*start == ' ' || *start == '\t')) ++start;
        while (end > start && (end[-1] == ' ' || end[-1] == '\t')) --end;
        if (start < end) {
            const char *params = memchr(start, ';', (size_t)(end - start));
            const char *type_end = params == NULL ? end : params;
            while (type_end > start && (type_end[-1] == ' ' || type_end[-1] == '\t')) --type_end;
            const char *slash = memchr(start, '/', (size_t)(type_end - start));
            if (slash == NULL || slash == start || slash + 1 >= type_end) {
                return -1;
            }
            for (const char *c = start; c < type_end; ++c) {
                if (c != slash && !token_char(*c)) return -1;
            }
            size_t type_len = (size_t)(slash - start);
            const char *subtype = slash + 1;
            size_t subtype_len = (size_t)(type_end - subtype);
            if (type_len == 1U && *start == '*' && !(subtype_len == 1U && *subtype == '*')) {
                return -1;
            }
            double quality = 1.0;
            while (params != NULL && params < end) {
                const char *param = params + 1;
                const char *next = memchr(param, ';', (size_t)(end - param));
                const char *param_end = next == NULL ? end : next;
                while (param < param_end && (*param == ' ' || *param == '\t')) ++param;
                const char *equals = memchr(param, '=', (size_t)(param_end - param));
                if (equals == NULL) {
                    /* MimeTypeUtils skips an empty parameter or one without '='. */
                    params = next;
                    continue;
                }
                if (equals == param) {
                    return -1;
                }
                size_t name_len = (size_t)(equals - param);
                while (name_len > 0U && (param[name_len - 1U] == ' ' || param[name_len - 1U] == '\t')) --name_len;
                if (ascii_equal_ignore_case(param, name_len, "q", 1U)) {
                    char number[32];
                    const char *value = equals + 1;
                    while (value < param_end && (*value == ' ' || *value == '\t')) ++value;
                    size_t value_len = (size_t)(param_end - value);
                    while (value_len > 0U && (value[value_len - 1U] == ' ' || value[value_len - 1U] == '\t')) {
                        --value_len;
                    }
                    if (value_len == 0U || value_len >= sizeof(number)) {
                        return -1;
                    }
                    memcpy(number, value, value_len);
                    number[value_len] = '\0';
                    char *number_end = NULL;
                    quality = strtod(number, &number_end);
                    if (number_end == number || *number_end != '\0' || !(quality >= 0.0 && quality <= 1.0)) {
                        return -1;
                    }
                }
                params = next;
            }
            for (size_t p = 0; p < PRODUCED_COUNT; ++p) {
                if (range_accepts(start, type_len, subtype, subtype_len, produced_types[p])
                    && quality > best_quality) {
                    best = (int)p;
                    best_quality = quality;
                }
            }
        }
        if (cursor[len] == '\0') {
            break;
        }
        cursor += len + 1U;
    }
    return best;
}

/*
 * Spring's guard against reflected file downloads: a body under a path whose last segment ends in
 * an extension it does not know to be safe gets Content-Disposition: inline;filename=f.txt, which
 * every meter name (specus.control.tls.mode ends in "mode") brings with it.
 */
static int needs_content_disposition(const char *segment, size_t segment_len)
{
    static const char *const safe[] = {
        "txt", "text", "yml", "properties", "csv", "json", "xml", "atom", "rss", "png", "jpe", "jpeg", "jpg",
        "gif", "wbmp", "bmp"
    };
    const char *dot = NULL;
    for (size_t i = 0; i < segment_len; ++i) {
        if (segment[i] == '.') dot = segment + i;
    }
    if (dot == NULL || dot + 1 >= segment + segment_len) {
        return 0;
    }
    size_t extension_len = (size_t)(segment + segment_len - dot - 1);
    for (size_t i = 0; i < sizeof(safe) / sizeof(safe[0]); ++i) {
        if (ascii_equal_ignore_case(dot + 1, extension_len, safe[i], strlen(safe[i]))) {
            return 0;
        }
    }
    return 1;
}

static int finish_response(int status, const char *reason, const char *headers, const char *body, size_t body_len,
                           int include_body, char **response, size_t *response_len)
{
    text_builder out = {NULL, 0U, 0U, 0};
    char line[128];
    snprintf(line, sizeof(line), "HTTP/1.1 %d %s\r\n", status, reason);
    buffer_puts(&out, line);
    buffer_puts(&out, headers);
    snprintf(line, sizeof(line), "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Length: %zu\r\n\r\n",
             body_len);
    buffer_puts(&out, line);
    if (include_body && body_len > 0U) {
        buffer_append(&out, body, body_len);
    }
    if (out.failed) {
        free(out.data);
        return -1;
    }
    *response = out.data;
    *response_len = out.len;
    return 1;
}

int st_metrics_actuator_response(const char *method,
                                 const char *path,
                                 const char *accept,
                                 char **response,
                                 size_t *response_len)
{
    static const char base[] = "/actuator/metrics";
    if (response == NULL || response_len == NULL) {
        return -1;
    }
    *response = NULL;
    *response_len = 0U;
    if (method == NULL || path == NULL) {
        return 0;
    }
    size_t path_len = strcspn(path, "?");
    const char *segment = NULL;
    size_t segment_len = 0U;
    if (path_len < sizeof(base) - 1U || memcmp(path, base, sizeof(base) - 1U) != 0) {
        return 0;
    }
    if (path_len > sizeof(base) - 1U) {
        /* /actuator/metrics/{requiredMetricName}: exactly one more, non-empty segment. */
        if (path[sizeof(base) - 1U] != '/') {
            return 0;
        }
        segment = path + sizeof(base);
        segment_len = path_len - sizeof(base);
        if (segment_len == 0U || memchr(segment, '/', segment_len) != NULL) {
            return 0;
        }
    }
    if (!st_metrics_endpoint_exposed()) {
        return 0;
    }
    int disposition = segment != NULL && needs_content_disposition(segment, segment_len);
    const char *disposition_header = disposition ? "Content-Disposition: inline;filename=f.txt\r\n" : "";
    int head = strcmp(method, "HEAD") == 0;
    if (strcmp(method, "OPTIONS") == 0) {
        return finish_response(200, "OK", "Allow: GET,HEAD,OPTIONS\r\nAccept-Patch: \r\n", NULL, 0U, 0,
                               response, response_len);
    }
    if (!head && strcmp(method, "GET") != 0) {
        static const char body[] = "{\"error\":\"Method Not Allowed\"}";
        char headers[160];
        snprintf(headers, sizeof(headers), "Allow: GET\r\n%sContent-Type: application/json\r\n", disposition_header);
        return finish_response(405, "Method Not Allowed", headers, body, sizeof(body) - 1U, 1, response, response_len);
    }
    int produced = negotiate(accept);
    if (produced < 0) {
        return finish_response(406, "Not Acceptable",
                               "Accept: application/vnd.spring-boot.actuator.v3+json, "
                               "application/vnd.spring-boot.actuator.v2+json, application/json\r\n",
                               NULL, 0U, 0, response, response_len);
    }
    text_builder body = {NULL, 0U, 0U, 0};
    if (segment == NULL) {
        write_names(&body);
    } else {
        requested_tag *tags = NULL;
        size_t tag_count = 0U;
        int parsed = parse_tags(path, &tags, &tag_count);
        if (parsed == -1) {
            return -1;
        }
        if (parsed == -2) {
            /* MetricsEndpoint.parseTag's InvalidEndpointRequestException: Spring Boot's 400. */
            static const char bad_request[] = "{\"error\":\"Bad Request\"}";
            char headers[160];
            snprintf(headers, sizeof(headers), "%sContent-Type: application/json\r\n", disposition_header);
            return finish_response(400, "Bad Request", headers, bad_request, sizeof(bad_request) - 1U, !head,
                                   response, response_len);
        }
        char *name = (char *)malloc(segment_len + 1U);
        if (name == NULL) {
            free_tags(tags, tag_count);
            return -1;
        }
        memcpy(name, segment, segment_len);
        name[segment_len] = '\0';
        int found = write_metric(&body, name, tags, tag_count);
        free(name);
        free_tags(tags, tag_count);
        if (!found) {
            free(body.data);
            /* The endpoint answered null: 404 without a body. */
            return finish_response(404, "Not Found", "", NULL, 0U, 0, response, response_len);
        }
    }
    if (body.failed) {
        free(body.data);
        return -1;
    }
    char headers[256];
    snprintf(headers, sizeof(headers), "Content-Type: %s\r\n%s", produced_types[produced], disposition_header);
    int rc = finish_response(200, "OK", headers, body.data, body.len, !head, response, response_len);
    free(body.data);
    return rc;
}
