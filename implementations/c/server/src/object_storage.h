#ifndef SPECUS_OBJECT_STORAGE_H
#define SPECUS_OBJECT_STORAGE_H

#include <stddef.h>

typedef struct {
    const char *tenant_id;
    const char *username;
    int admin;
    int authenticated;
} st_object_storage_identity;

/* Returns 0 when the route does not belong to the attachment module. */
int st_object_storage_build_response(const char *method,
                                     const char *path,
                                     const char *body,
                                     const char *remote_address,
                                     const char *callback_authorization,
                                     const char *callback_public_key_url,
                                     const st_object_storage_identity *identity,
                                     char *out,
                                     size_t out_len);

int st_object_storage_enabled_current(void);
int st_object_storage_validate_current(void);
int st_object_storage_cleanup_expired(void);
void st_object_storage_reset_for_tests(void);

/*
 * Capability snapshot evaluated at a fixed instant, so tests can cross month and expiry
 * boundaries deterministically. Writes the same HTTP response as the live route.
 */
int st_object_storage_capabilities_for_tests(const st_object_storage_identity *identity,
                                             long long epoch_seconds,
                                             char *out,
                                             size_t out_len);

/*
 * Serves this PEM public key for every valid OSS callback key URL instead of fetching it from
 * gosspublic.alicdn.com, so callback signature verification can be tested offline. NULL restores
 * the real fetch.
 */
int st_object_storage_set_callback_key_for_tests(const char *pem);

/* Deterministic OSS V4 vector hook. Returned strings are owned by the caller. */
char *st_object_storage_presign_for_tests(const char *method,
                                          const char *object_key,
                                          const char *content_type,
                                          const char *grant_id,
                                          long long ttl_seconds,
                                          long long epoch_seconds,
                                          char expires_at[41],
                                          char **callback_header_out);

#endif
