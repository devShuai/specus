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

/* Returns 1 when the request path belongs to discovery (handled or rejected), 0 otherwise. */
int st_public_discovery_handle_websocket(int fd,
                                         const char *method,
                                         const char *path,
                                         const char *request,
                                         const char *remote_address);

void st_public_discovery_reset_for_tests(void);

#endif
