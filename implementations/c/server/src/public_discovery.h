#ifndef SPECUS_PUBLIC_DISCOVERY_H
#define SPECUS_PUBLIC_DISCOVERY_H

#include <stddef.h>

int st_public_discovery_initialize(void);
void st_public_discovery_shutdown(void);

int st_public_discovery_issue_ticket_response(const char *body,
                                              const char *remote_address,
                                              char *out,
                                              size_t out_len);
int st_public_discovery_name_availability_response(const char *path,
                                                   char *out,
                                                   size_t out_len);

/*
 * Java PublicTransferRateLimiter with the public transfer cluster enabled: the fixed window of an
 * anonymous entry point (pairing-code redemption, presign upload) lives in Redis and is shared by
 * every instance. Returns 1 when the call is allowed, 0 when it is rate limited and -1 when the
 * cluster is disabled or Redis is unavailable, in which case the caller fails closed.
 */
int st_public_discovery_shared_rate_allow(const char *bucket,
                                          const char *identity,
                                          long limit,
                                          long window_seconds);

/* Returns 1 when the request path belongs to discovery (handled or rejected), 0 otherwise. */
int st_public_discovery_handle_websocket(int fd,
                                         const char *method,
                                         const char *path,
                                         const char *request,
                                         const char *remote_address);

void st_public_discovery_reset_for_tests(void);

#endif
