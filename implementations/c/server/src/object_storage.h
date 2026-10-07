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
 * Replaces the HTTPS GET of the OSS callback public key, so callback signature verification can be
 * tested offline. The fetcher receives the pinned https://gosspublic.alicdn.com/callback_pub_key*
 * URL the server would request and returns the PEM body (malloc'ed, freed by the server) or NULL
 * for a failed fetch. NULL restores the real fetch; either call empties the key cache.
 */
typedef char *(*st_object_callback_key_fetcher)(const char *url, void *context);

/*
 * Hands out these IDs (at most 8) for the next attachments and download grants before random IDs
 * resume, so a test can make an attachment ID collide. NULL or 0 drops the queue.
 */
void st_object_storage_set_ids_for_tests(const long long *ids, size_t count);
void st_object_storage_set_callback_key_fetcher_for_tests(st_object_callback_key_fetcher fetcher,
                                                          void *context);

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
