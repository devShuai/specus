#ifndef SPECUS_CLIENT_PACKAGE_H
#define SPECUS_CLIENT_PACKAGE_H

#include <stddef.h>
#include <stdint.h>

#include "storage.h"

/*
 * Parse, validate, hash and atomically publish one Java-compatible multipart
 * client package. HTTP status is populated for validation/storage failures.
 */
int st_client_package_upload(const char *database_path,
                             const char *content_type,
                             const uint8_t *body,
                             size_t body_len,
                             st_storage_client_download_link *out_link,
                             int *http_status,
                             char *error,
                             size_t error_len);

/*
 * Returns 1 when the public download route was handled, 0 for another route. Range and
 * If-None-Match (either may be NULL) follow Spring's handling of a ResponseEntity<Resource>:
 * single and multiple byte ranges (206), 416 for an unsatisfiable range, 304 for a matching ETag.
 */
int st_client_package_send_download(int fd,
                                    const char *method,
                                    const char *path,
                                    const char *database_path,
                                    const char *remote_address,
                                    const char *range_header,
                                    const char *if_none_match);

/* Shared anonymous read budget for catalogue, version-check and package bytes. */
int st_client_package_rate_limit(const char *remote_address,
                                 long long *retry_after_seconds);
void st_client_package_rate_limit_reset(void);

/* Quarantine a hosted file around its catalogue-row deletion. */
int st_client_package_delete(const char *database_path, long long id);

/* Validate that a hosted row still has a safe, readable package of the expected size. */
int st_client_package_is_readable(const st_storage_client_download_link *link);

size_t st_client_package_max_request_bytes(void);

#endif
