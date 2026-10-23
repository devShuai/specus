#ifndef SPECUS_METRICS_H
#define SPECUS_METRICS_H

#include "protocol.h"

#include <stddef.h>

/*
 * The meters the Java server registers with Micrometer (NettyServer, ControlProtocolMetricsHandler,
 * StunTurnServer, PeerMeshService), under the same names, tags and descriptions, and the Spring
 * Boot actuator metrics endpoint that shows them: GET /actuator/metrics and
 * /actuator/metrics/{requiredMetricName}, exposed only when management.endpoints.web.exposure
 * includes metrics (MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE / _EXCLUDE), as in Java.
 *
 * Every meter exists from the start, whether or not its feature runs, as Java registers them when
 * the beans are built. Counters only grow; st_metrics_reset is for tests.
 */
typedef enum {
    ST_METRIC_CONTROL_PLAINTEXT_DEPLOYMENT_REJECTED,
    ST_METRIC_CONTROL_PREAUTH_OVERSIZE_REJECTED,
    /* C forwards TURN datagrams synchronously on its STUN/TURN thread and has no relay worker
     * queue: the queue meters exist, as in Java, and stay 0. */
    ST_METRIC_TURN_RELAY_QUEUE_DROPPED,
    ST_METRIC_TURN_RELAY_SEND_FAILURES,
    ST_METRIC_TURN_GENERAL_RELAY_QUOTA_REJECTED,
    ST_METRIC_TURN_GENERAL_RELAY_DESTINATION_FORBIDDEN,
    ST_METRIC_TURN_GENERAL_RELAY_BYTES,
    ST_METRIC_TURN_GENERAL_RELAY_QUOTA_CLOSED,
    ST_METRIC_RELAY_TRAFFIC_FLUSH_FAILURES
} st_metric_counter;

void st_metrics_increment(st_metric_counter counter);
void st_metrics_add(st_metric_counter counter, unsigned long long amount);
/* specus.control.protocol.rejected with the reason's tag; ST_PROTOCOL_REJECTION_NONE counts nothing. */
void st_metrics_protocol_rejected(st_protocol_rejection reason);

/*
 * specus.control.tls.mode carries the effective mode as its tag (file, self_signed,
 * terminated_upstream or disabled, "disabled" until set), and
 * specus.control.tls.certificate.expiry.epoch.seconds the certificate's notAfter (0 when not known).
 */
void st_metrics_set_control_tls(const char *mode, long long certificate_expiry_epoch_seconds);

/* The value of specus.peer_mesh.relay.traffic.pending.bytes, asked for whenever it is shown. */
typedef double (*st_metrics_gauge_source)(void);
void st_metrics_set_relay_pending_bytes_source(st_metrics_gauge_source source);
/* A relay traffic batch was written: specus.peer_mesh.relay.traffic.flush.lag.seconds restarts at 0. */
void st_metrics_relay_traffic_flushed(void);

/*
 * The measurement the endpoint would show for name, narrowed to the meters with tag_key=tag_value
 * when tag_key is not NULL: 0 with *value filled, -1 when no meter matches.
 */
int st_metrics_measure(const char *name, const char *tag_key, const char *tag_value, double *value);
/* Counters, the flush lag and the TLS meters back to their initial values (tests). */
void st_metrics_reset(void);

/* Java's Double.toString, which the endpoint's JSON uses for every value: 0.0, 1.0E7, 4.9E-324. */
int st_metrics_format_double(double value, char *out, size_t out_len);

/*
 * Spring Boot's web exposure filter: 1 when the include list (NULL: the default "health") names
 * metrics or is "*" and the exclude list does not, 0 when not, -1 when an entry is not a valid
 * endpoint id, with Spring's message in error (Java does not start then).
 */
int st_metrics_exposure(const char *include, const char *exclude, char *error, size_t error_len);
/* st_metrics_exposure over MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE/_EXCLUDE; invalid is 0. */
int st_metrics_endpoint_exposed(void);
/* The startup check: 0, or -1 after printing why the exposure settings were refused. */
int st_metrics_validate_current(void);

/*
 * The answer of the actuator metrics endpoint to a request whose decoded path (with its raw query)
 * is path: 1 with a complete HTTP response in *response (caller frees), 0 when the path is not one
 * of the endpoint's routes or the endpoint is not exposed (the request is someone else's), -1 when
 * memory runs out. accept is the Accept header, NULL when there was none.
 */
int st_metrics_actuator_response(const char *method,
                                 const char *path,
                                 const char *accept,
                                 char **response,
                                 size_t *response_len);

#endif
