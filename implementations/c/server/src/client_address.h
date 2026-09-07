#ifndef SPECUS_CLIENT_ADDRESS_H
#define SPECUS_CLIENT_ADDRESS_H

#include <stddef.h>

#define ST_CLIENT_ADDRESS_MAX_LEN 64U

/*
 * Resolves a client IP without DNS. Forwarded headers are considered only when the direct peer
 * belongs to one of the comma-separated trusted proxy CIDRs.
 */
int st_client_address_resolve(const char *remote_address,
                              const char *forwarded_for,
                              const char *real_ip,
                              const char *trusted_proxies,
                              char *out,
                              size_t out_len);

#endif
