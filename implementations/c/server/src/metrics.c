#define _POSIX_C_SOURCE 200809L

#include "metrics.h"

#include <float.h>
#include <iconv.h>
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

static void java_trim(const char **start, const char **end);
static int ascii_equal_ignore_case(const char *left, size_t left_len, const char *right, size_t right_len);
static int hex_digit(char c);

static int blank_text(const char *value)
{
    for (; value != NULL && *value != '\0'; ++value) {
        if ((unsigned char)*value > ' ') return 0;
    }
    return 1;
}

/* The variable Spring reads for a property: the canonical name (dashes dropped), else the one that
 * keeps a dash as '_', as the other Spring settings of this server are read. */
static const char *env_name(const char *canonical, const char *dashed)
{
    return getenv(canonical) != NULL || dashed == NULL ? canonical : dashed;
}

static void set_errorf(char *error, size_t error_len, const char *name, const char *value, const char *reason)
{
    if (error != NULL && error_len > 0U) {
        snprintf(error, error_len, "%s=\"%s\" refused: %s", name, value == NULL ? "" : value, reason);
    }
}

/* Endpoint Access by Spring's lenient enum conversion: 0 NONE, 1 READ_ONLY, 2 UNRESTRICTED, -2 not
 * set (absent or blank), -1 no such constant ("Read-Only" and "readOnly" are READ_ONLY). */
static int access_value(const char *value)
{
    if (value == NULL) {
        return -2;
    }
    char canonical[16];
    size_t len = 0U;
    int blank = 1;
    for (const char *cursor = value; *cursor != '\0'; ++cursor) {
        char c = *cursor;
        if ((unsigned char)c > ' ') blank = 0;
        int letter = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
        if (!letter && !(c >= '0' && c <= '9')) continue;
        if (len + 1U >= sizeof(canonical)) return -1;
        canonical[len++] = (char)(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
    }
    canonical[len] = '\0';
    if (blank) return -2;
    if (strcmp(canonical, "none") == 0) return 0;
    if (strcmp(canonical, "readonly") == 0) return 1;
    if (strcmp(canonical, "unrestricted") == 0) return 2;
    return -1;
}

/* Spring's StringToBooleanConverter: 1, 0, -2 when absent or blank, -1 for any other word. */
static int boolean_value(const char *value)
{
    if (value == NULL) {
        return -2;
    }
    const char *start = value;
    const char *end = value + strlen(value);
    java_trim(&start, &end);
    if (start == end) return -2;
    static const char *const truths[] = {"true", "on", "yes", "1"};
    static const char *const falsehoods[] = {"false", "off", "no", "0"};
    for (size_t i = 0; i < 4U; ++i) {
        if (ascii_equal_ignore_case(start, (size_t)(end - start), truths[i], strlen(truths[i]))) return 1;
        if (ascii_equal_ignore_case(start, (size_t)(end - start), falsehoods[i], strlen(falsehoods[i]))) return 0;
    }
    return -1;
}

/*
 * An Integer property as Spring's NumberUtils.parseNumber reads it: all whitespace removed, then
 * Integer.decode for 0x, 0X or # (after an optional '-'), Integer.valueOf otherwise. 1 with *out,
 * 0 when absent or blank, -1 when it does not convert.
 */
static int spring_integer(const char *value, long long *out)
{
    if (value == NULL) {
        return 0;
    }
    char text[32];
    size_t len = 0U;
    for (const char *cursor = value; *cursor != '\0'; ++cursor) {
        if (*cursor == ' ' || (*cursor >= '\t' && *cursor <= '\r') || (*cursor >= 0x1c && *cursor <= 0x1f)) continue;
        if (len + 1U >= sizeof(text)) return -1;
        text[len++] = *cursor;
    }
    text[len] = '\0';
    if (len == 0U) return 0;
    const char *digits = text;
    int negative = 0;
    if (*digits == '-' || *digits == '+') {
        negative = *digits == '-';
        ++digits;
    }
    int base = 10;
    /* NumberUtils.isHexNumber looks for the prefix after a '-' only; "+0x1" is no number. */
    if (text[0] != '+' && (strncmp(digits, "0x", 2U) == 0 || strncmp(digits, "0X", 2U) == 0)) {
        base = 16;
        digits += 2;
    } else if (text[0] != '+' && *digits == '#') {
        base = 16;
        ++digits;
    }
    if (*digits == '\0' || *digits == '-' || *digits == '+') return -1;
    long long parsed = 0;
    for (; *digits != '\0'; ++digits) {
        int digit = hex_digit(*digits);
        if (digit < 0 || digit >= base) return -1;
        parsed = parsed * base + digit;
        if (parsed > 2147483648LL) return -1;
    }
    parsed = negative ? -parsed : parsed;
    if (parsed > 2147483647LL || parsed < -2147483648LL) return -1;
    *out = parsed;
    return 1;
}

/*
 * Whether the metrics endpoint is available at all, as Spring Boot's PropertiesEndpointAccessResolver
 * decides: management.endpoint.metrics.access, else its deprecated .enabled, else
 * management.endpoints.access.default, else .enabled-by-default, else UNRESTRICTED; then capped by
 * management.endpoints.access.max-permitted. Read access is enough (the endpoint only reads).
 * 1 available, 0 not, -1 for a value or a pair of values Java refuses to start with.
 */
static int metrics_access(char *error, size_t error_len)
{
    const char *access_name = "MANAGEMENT_ENDPOINT_METRICS_ACCESS";
    const char *enabled_name = "MANAGEMENT_ENDPOINT_METRICS_ENABLED";
    const char *default_name = "MANAGEMENT_ENDPOINTS_ACCESS_DEFAULT";
    const char *by_default_name = env_name("MANAGEMENT_ENDPOINTS_ENABLEDBYDEFAULT", "MANAGEMENT_ENDPOINTS_ENABLED_BY_DEFAULT");
    const char *max_name = env_name("MANAGEMENT_ENDPOINTS_ACCESS_MAXPERMITTED", "MANAGEMENT_ENDPOINTS_ACCESS_MAX_PERMITTED");
    int access = access_value(getenv(access_name));
    int enabled = boolean_value(getenv(enabled_name));
    int fallback = access_value(getenv(default_name));
    int by_default = boolean_value(getenv(by_default_name));
    int max = access_value(getenv(max_name));
    static const char no_constant[] = "No enum constant org.springframework.boot.actuate.endpoint.Access";
    static const char not_boolean[] = "Failed to convert to type java.lang.Boolean";
    if (access == -1) return set_errorf(error, error_len, access_name, getenv(access_name), no_constant), -1;
    if (fallback == -1) return set_errorf(error, error_len, default_name, getenv(default_name), no_constant), -1;
    if (max == -1) return set_errorf(error, error_len, max_name, getenv(max_name), no_constant), -1;
    if (enabled == -1) return set_errorf(error, error_len, enabled_name, getenv(enabled_name), not_boolean), -1;
    if (by_default == -1) return set_errorf(error, error_len, by_default_name, getenv(by_default_name), not_boolean), -1;
    if (access >= 0 && enabled >= 0) {
        return set_errorf(error, error_len, access_name, getenv(access_name),
                          "management.endpoint.metrics.access and .enabled are mutually exclusive"), -1;
    }
    if (fallback >= 0 && by_default >= 0) {
        return set_errorf(error, error_len, default_name, getenv(default_name),
                          "management.endpoints.access.default and .enabled-by-default are mutually exclusive"), -1;
    }
    int resolved = access >= 0 ? access
        : enabled >= 0 ? (enabled ? 2 : 0)
        : fallback >= 0 ? fallback
        : by_default >= 0 ? (by_default ? 2 : 0)
        : 2;
    if (max >= 0 && resolved > max) resolved = max;
    return resolved > 0;
}

/*
 * Whether Java would serve the endpoint on this listener, under /actuator/metrics. A management
 * port other than the listener's (or negative, which turns the HTTP endpoints off), another
 * management.endpoints.web.base-path or another path mapping moves or removes it in Java, and C
 * serves it nowhere then rather than somewhere Java does not. 1 here, 0 not here, -1 for settings
 * Java refuses to start with (an unreadable port or base path, an address without a separate port).
 */
static int metrics_on_this_listener(char *error, size_t error_len)
{
    long long port = 0;
    long long listener = 0;
    const char *port_value = getenv("MANAGEMENT_SERVER_PORT");
    int port_set = spring_integer(port_value, &port);
    if (port_set < 0) {
        return set_errorf(error, error_len, "MANAGEMENT_SERVER_PORT", port_value,
                          "Failed to convert to type java.lang.Integer"), -1;
    }
    /* ManagementPortType: no port, or the server's own port (0 is a random one), is the same port. */
    if (port_set > 0 && port < 0) {
        return 0;
    }
    if (port_set > 0 && (port == 0 || spring_integer(getenv("SPECUS_ADMIN_PORT"), &listener) <= 0
                         || listener != port)) {
        return 0;
    }
    const char *address = getenv("MANAGEMENT_SERVER_ADDRESS");
    if (!blank_text(address)) {
        return set_errorf(error, error_len, "MANAGEMENT_SERVER_ADDRESS", address,
                          "Management-specific server address cannot be configured as the management server "
                          "is not listening on a separate port"), -1;
    }
    const char *base_name = env_name("MANAGEMENT_ENDPOINTS_WEB_BASEPATH", "MANAGEMENT_ENDPOINTS_WEB_BASE_PATH");
    const char *base = getenv(base_name);
    if (base != NULL) {
        size_t len = strlen(base);
        if (len > 0U && base[0] != '/') {
            return set_errorf(error, error_len, base_name, base, "'basePath' must start with '/' or be empty"), -1;
        }
        /* WebEndpointProperties.cleanBasePath drops one trailing '/'. */
        if (len > 0U && base[len - 1U] == '/') --len;
        if (len != strlen("/actuator") || memcmp(base, "/actuator", len) != 0) {
            return 0;
        }
    }
    const char *mapping = getenv(env_name("MANAGEMENT_ENDPOINTS_WEB_PATHMAPPING_METRICS",
                                          "MANAGEMENT_ENDPOINTS_WEB_PATH_MAPPING_METRICS"));
    if (mapping != NULL && strcmp(mapping, "metrics") != 0) {
        return 0;
    }
    return 1;
}

/* 1 when the endpoint answers on this listener, 0 when not, -1 when Java would not start. */
static int endpoint_state(char *error, size_t error_len)
{
    char exposure_error[128] = "";
    const char *include = getenv("MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE");
    const char *exclude = getenv("MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_EXCLUDE");
    int included = 0;
    int excluded = 0;
    if (exposure_list(include, &included, exposure_error, sizeof(exposure_error)) != 0) {
        return set_errorf(error, error_len, "MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE", include, exposure_error), -1;
    }
    if (exposure_list(exclude, &excluded, exposure_error, sizeof(exposure_error)) != 0) {
        return set_errorf(error, error_len, "MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_EXCLUDE", exclude, exposure_error), -1;
    }
    int available = metrics_access(error, error_len);
    if (available < 0) {
        return -1;
    }
    int here = metrics_on_this_listener(error, error_len);
    if (here < 0) {
        return -1;
    }
    return included && !excluded && available && here;
}

int st_metrics_endpoint_exposed(void)
{
    return endpoint_state(NULL, 0U) == 1;
}

int st_metrics_validate_current(void)
{
    char error[384];
    if (endpoint_state(error, sizeof(error)) < 0) {
        fprintf(stderr, "[metrics] %s\n", error);
        return -1;
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

/* String.trim: everything up to and including ' ' goes from both ends. */
static void java_trim(const char **start, const char **end)
{
    while (*start < *end && (unsigned char)**start <= ' ') ++*start;
    while (*end > *start && (unsigned char)(*end)[-1] <= ' ') --*end;
}

static int token_text(const char *text, size_t len)
{
    if (len == 0U) {
        return 0;
    }
    for (size_t i = 0; i < len; ++i) {
        if (!token_char(text[i])) return 0;
    }
    return 1;
}

/* MimeType.isQuotedString: two double or two single quotes around it. */
static int quoted_text(const char *text, size_t len)
{
    return len >= 2U && ((text[0] == '"' && text[len - 1U] == '"') || (text[0] == '\'' && text[len - 1U] == '\''));
}

/* The end of the parameter that starts at cursor: the next ';' outside double quotes, or end. */
static const char *parameter_end(const char *cursor, const char *end)
{
    int quoted = 0;
    for (; cursor < end; ++cursor) {
        if (*cursor == '"') quoted = !quoted;
        else if (*cursor == ';' && !quoted) break;
    }
    return cursor;
}

/* Spring's limit: MimeTypeUtils.sortBySpecificity refuses to sort more media types than this. */
#define ACCEPT_MAX_RANGES 50U

/* One media range of the Accept header as MimeTypeUtils.parseMimeType reads it (pointers into the header). */
typedef struct {
    const char *type;
    size_t type_len;
    const char *subtype;
    size_t subtype_len;
    double quality;
    int has_quality;
    /* Every attribute=value parameter, q included (MimeType.getParameters().size()). */
    size_t parameters;
    /* What follows the first ';', NULL when nothing does. */
    const char *params;
    const char *params_end;
} media_range;

/*
 * Parses one comma-separated element; 1 when it is a media range, 0 when it is blank (skipped, as
 * MediaType.parseMediaTypes skips it), -1 when Spring refuses it (406).
 */
static int parse_media_range(const char *start, const char *end, media_range *range)
{
    java_trim(&start, &end);
    if (start >= end) {
        return 0;
    }
    memset(range, 0, sizeof(*range));
    range->quality = 1.0;
    const char *semicolon = memchr(start, ';', (size_t)(end - start));
    const char *type_start = start;
    const char *type_end = semicolon == NULL ? end : semicolon;
    java_trim(&type_start, &type_end);
    if (type_end - type_start == 1 && *type_start == '*') {
        /* java.net.HttpURLConnection's "*; q=.2", read as all media types. */
        range->type = "*";
        range->type_len = 1U;
        range->subtype = "*";
        range->subtype_len = 1U;
    } else {
        const char *slash = memchr(type_start, '/', (size_t)(type_end - type_start));
        if (slash == NULL || slash == type_start || slash + 1 >= type_end
            || !token_text(type_start, (size_t)(slash - type_start))
            || !token_text(slash + 1, (size_t)(type_end - slash - 1))) {
            return -1;
        }
        range->type = type_start;
        range->type_len = (size_t)(slash - type_start);
        range->subtype = slash + 1;
        range->subtype_len = (size_t)(type_end - slash - 1);
        if (range->type_len == 1U && range->type[0] == '*'
            && !(range->subtype_len == 1U && range->subtype[0] == '*')) {
            return -1;
        }
    }
    if (semicolon == NULL) {
        return 1;
    }
    range->params = semicolon + 1;
    range->params_end = end;
    for (const char *cursor = range->params; cursor <= end;) {
        const char *next = parameter_end(cursor, end);
        const char *param = cursor;
        const char *param_end = next;
        java_trim(&param, &param_end);
        cursor = next + 1;
        const char *equals = param == param_end ? NULL : memchr(param, '=', (size_t)(param_end - param));
        if (equals == NULL) {
            /* An empty parameter, or one without '=', is skipped. */
            continue;
        }
        const char *name_end = equals;
        const char *value = equals + 1;
        const char *name = param;
        java_trim(&name, &name_end);
        java_trim(&value, &param_end);
        size_t name_len = (size_t)(name_end - name);
        size_t value_len = (size_t)(param_end - value);
        if (!token_text(name, name_len) || value_len == 0U) {
            return -1;
        }
        ++range->parameters;
        int quoted = quoted_text(value, value_len);
        const char *bare = quoted ? value + 1 : value;
        size_t bare_len = quoted ? value_len - 2U : value_len;
        if (ascii_equal_ignore_case(name, name_len, "q", 1U)) {
            /* MediaType: Double.parseDouble of the unquoted value, between 0 and 1. */
            char number[64];
            if (bare_len == 0U || bare_len >= sizeof(number)) {
                return -1;
            }
            memcpy(number, bare, bare_len);
            number[bare_len] = '\0';
            char *number_end = NULL;
            double quality = strtod(number, &number_end);
            while (number_end != NULL && (unsigned char)*number_end <= ' ' && *number_end != '\0') ++number_end;
            if (number_end == number || *number_end != '\0' || !(quality >= 0.0 && quality <= 1.0)) {
                return -1;
            }
            range->quality = quality;
            range->has_quality = 1;
        } else if (name_len == 7U && memcmp(name, "charset", 7U) == 0) {
            /* MimeType: Charset.forName of the unquoted value; iconv knows the same common names. */
            char charset[64];
            if (bare_len == 0U || bare_len >= sizeof(charset)) {
                return -1;
            }
            memcpy(charset, bare, bare_len);
            charset[bare_len] = '\0';
            iconv_t converter = iconv_open("UTF-8", charset);
            if (converter == (iconv_t)-1) {
                return -1;
            }
            iconv_close(converter);
        } else if (!quoted && !token_text(value, value_len)) {
            return -1;
        }
    }
    return 1;
}

static int range_wildcard_type(const media_range *range)
{
    return range->type_len == 1U && range->type[0] == '*';
}

/* MimeType.isWildcardSubtype: "*" or a suffix wildcard such as "*+json". */
static int range_wildcard_subtype(const media_range *range)
{
    return (range->subtype_len == 1U && range->subtype[0] == '*')
        || (range->subtype_len >= 2U && range->subtype[0] == '*' && range->subtype[1] == '+');
}

/* MediaType.isMoreSpecific: the quality first, then concrete over wildcard, then more parameters. */
static int range_more_specific(const media_range *a, const media_range *b)
{
    if (a->quality != b->quality) {
        return a->quality > b->quality;
    }
    int a_wild = range_wildcard_type(a);
    int b_wild = range_wildcard_type(b);
    if (a_wild != b_wild) {
        return !a_wild;
    }
    int a_wild_subtype = range_wildcard_subtype(a);
    int b_wild_subtype = range_wildcard_subtype(b);
    if (a_wild_subtype != b_wild_subtype) {
        return !a_wild_subtype;
    }
    return ascii_equal_ignore_case(a->type, a->type_len, b->type, b->type_len)
        && ascii_equal_ignore_case(a->subtype, a->subtype_len, b->subtype, b->subtype_len)
        && a->parameters > b->parameters;
}

/* MimeType.isCompatibleWith for one Accept range and an application/... type the endpoint produces. */
static int range_accepts(const media_range *range, const char *produced)
{
    const char *produced_subtype = strchr(produced, '/') + 1;
    if (range_wildcard_type(range)) {
        return 1;
    }
    if (!ascii_equal_ignore_case(range->type, range->type_len, "application", 11U)) {
        return 0;
    }
    if ((range->subtype_len == 1U && range->subtype[0] == '*')
        || ascii_equal_ignore_case(range->subtype, range->subtype_len, produced_subtype, strlen(produced_subtype))) {
        return 1;
    }
    /* A suffix wildcard: the subtype *+json takes every +json subtype. */
    if (range->subtype_len > 2U && range->subtype[0] == '*' && range->subtype[1] == '+') {
        const char *suffix = strchr(produced_subtype, '+');
        return suffix != NULL
            && ascii_equal_ignore_case(range->subtype + 1, range->subtype_len - 1U, suffix, strlen(suffix));
    }
    return 0;
}

/* A compatible (range, produced type) pair: AbstractMessageConverterMethodProcessor.getMostSpecificMediaType. */
typedef struct {
    size_t produced;
    /* The Accept range itself when it is the more specific of the two (its parameters are written
     * into Content-Type), NULL when the produced type is. */
    const media_range *range;
    double quality;
    size_t parameters;
} media_candidate;

static int candidate_more_specific(const media_candidate *a, const media_candidate *b)
{
    if (a->quality != b->quality) {
        return a->quality > b->quality;
    }
    /* Both are concrete; the same type tells them apart by the number of parameters only. */
    return a->produced == b->produced && a->parameters > b->parameters;
}

/*
 * Spring MVC's choice of the produced type for the Accept header, written into content_type: the
 * ranges are sorted by MimeTypeUtils.sortBySpecificity (a bubble sort that swaps a pair when the
 * later one is more specific: higher quality, then a concrete type before a wildcard type or subtype, then more
 * parameters), each compatible (range, produced type) pair in that order and v3, v2, json order
 * gives the more specific of the two with the range's quality, those are sorted again, and the
 * first wins. The range's parameters other than q stay in Content-Type, as Spring writes the
 * selected media type. A blank header is all media types. -1 when none is compatible or the header
 * does not parse (both 406 in Java), -2 when memory runs out.
 */
static int negotiate(const char *accept, text_builder *content_type)
{
    media_range ranges[ACCEPT_MAX_RANGES];
    size_t count = 0U;
    if (accept != NULL) {
        /* MimeTypeUtils.tokenize: commas inside double quotes do not split, a backslash escapes. */
        const char *start = accept;
        int quoted = 0;
        for (const char *cursor = accept;; ++cursor) {
            if (*cursor == '\\' && cursor[1] != '\0') {
                ++cursor;
                continue;
            }
            if (*cursor == '"') {
                quoted = !quoted;
            }
            if ((*cursor == ',' && !quoted) || *cursor == '\0') {
                media_range range;
                int parsed = parse_media_range(start, cursor, &range);
                if (parsed < 0) {
                    return -1;
                }
                if (parsed > 0) {
                    if (count == ACCEPT_MAX_RANGES) {
                        return -1;
                    }
                    ranges[count++] = range;
                }
                if (*cursor == '\0') break;
                start = cursor + 1;
            }
        }
    }
    if (count == 0U) {
        ranges[0] = (media_range){"*", 1U, "*", 1U, 1.0, 0, 0U, NULL, NULL};
        count = 1U;
    }
    for (size_t i = 0; i < count; ++i) {
        for (size_t j = 1; j < count - i; ++j) {
            if (range_more_specific(&ranges[j], &ranges[j - 1U])) {
                media_range swap = ranges[j];
                ranges[j] = ranges[j - 1U];
                ranges[j - 1U] = swap;
            }
        }
    }
    media_candidate candidates[ACCEPT_MAX_RANGES * PRODUCED_COUNT];
    size_t candidate_count = 0U;
    for (size_t i = 0; i < count; ++i) {
        const media_range *range = &ranges[i];
        for (size_t p = 0; p < PRODUCED_COUNT; ++p) {
            if (!range_accepts(range, produced_types[p])) continue;
            /* The produced type with the range's quality is the more specific one unless the range
             * is concrete: then it is the same type with at least as many parameters. */
            int produced_wins = range_wildcard_type(range) || range_wildcard_subtype(range);
            candidates[candidate_count++] = (media_candidate){
                p, produced_wins ? NULL : range, range->quality,
                produced_wins ? (size_t)range->has_quality : range->parameters
            };
        }
    }
    if (candidate_count == 0U) {
        return -1;
    }
    for (size_t i = 0; i < candidate_count; ++i) {
        for (size_t j = 1; j < candidate_count - i; ++j) {
            if (candidate_more_specific(&candidates[j], &candidates[j - 1U])) {
                media_candidate swap = candidates[j];
                candidates[j] = candidates[j - 1U];
                candidates[j - 1U] = swap;
            }
        }
    }
    const media_candidate *chosen = &candidates[0];
    buffer_puts(content_type, produced_types[chosen->produced]);
    const media_range *range = chosen->range;
    for (const char *cursor = range == NULL ? NULL : range->params; cursor != NULL && cursor <= range->params_end;) {
        const char *next = parameter_end(cursor, range->params_end);
        const char *param = cursor;
        const char *param_end = next;
        java_trim(&param, &param_end);
        cursor = next + 1;
        const char *equals = param == param_end ? NULL : memchr(param, '=', (size_t)(param_end - param));
        if (equals == NULL) continue;
        const char *name = param;
        const char *name_end = equals;
        const char *value = equals + 1;
        java_trim(&name, &name_end);
        java_trim(&value, &param_end);
        if (ascii_equal_ignore_case(name, (size_t)(name_end - name), "q", 1U)) continue;
        buffer_puts(content_type, ";");
        buffer_append(content_type, name, (size_t)(name_end - name));
        buffer_puts(content_type, "=");
        buffer_append(content_type, value, (size_t)(param_end - value));
    }
    return content_type->failed ? -2 : 0;
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
    text_builder content_type = {NULL, 0U, 0U, 0};
    int negotiated = negotiate(accept, &content_type);
    if (negotiated == -2) {
        free(content_type.data);
        return -1;
    }
    if (negotiated < 0) {
        free(content_type.data);
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
            free(content_type.data);
            return -1;
        }
        if (parsed == -2) {
            /* MetricsEndpoint.parseTag's InvalidEndpointRequestException: Spring Boot's 400. */
            static const char bad_request[] = "{\"error\":\"Bad Request\"}";
            char headers[160];
            snprintf(headers, sizeof(headers), "%sContent-Type: application/json\r\n", disposition_header);
            free(content_type.data);
            return finish_response(400, "Bad Request", headers, bad_request, sizeof(bad_request) - 1U, !head,
                                   response, response_len);
        }
        char *name = (char *)malloc(segment_len + 1U);
        if (name == NULL) {
            free_tags(tags, tag_count);
            free(content_type.data);
            return -1;
        }
        memcpy(name, segment, segment_len);
        name[segment_len] = '\0';
        int found = write_metric(&body, name, tags, tag_count);
        free(name);
        free_tags(tags, tag_count);
        if (!found) {
            free(body.data);
            free(content_type.data);
            /* The endpoint answered null: 404 without a body. */
            return finish_response(404, "Not Found", "", NULL, 0U, 0, response, response_len);
        }
    }
    text_builder headers = {NULL, 0U, 0U, 0};
    buffer_puts(&headers, "Content-Type: ");
    buffer_append(&headers, content_type.data, content_type.len);
    buffer_puts(&headers, "\r\n");
    buffer_puts(&headers, disposition_header);
    free(content_type.data);
    if (body.failed || headers.failed) {
        free(body.data);
        free(headers.data);
        return -1;
    }
    int rc = finish_response(200, "OK", headers.data, body.data, body.len, !head, response, response_len);
    free(body.data);
    free(headers.data);
    return rc;
}
