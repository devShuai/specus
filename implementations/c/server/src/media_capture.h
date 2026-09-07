#ifndef SPECUS_MEDIA_CAPTURE_H
#define SPECUS_MEDIA_CAPTURE_H

#include <stddef.h>
#include <stdint.h>

typedef struct st_media_capture_session st_media_capture_session;

typedef struct {
    const char *tenant_id;
    const char *username;
    int admin;
    int authenticated;
} st_media_capture_identity;

/* Validates and initializes the optional RustFS/S3 media backend. */
int st_media_capture_validate_current(void);
int st_media_capture_ready_current(void);
int st_media_capture_cleanup_expired(const char *database_path);

/* Opens a route-scoped capture for an original upstream HTTP response. */
st_media_capture_session *st_media_capture_open(const char *database_path,
                                                const char *client_name,
                                                const char *route,
                                                const char *method,
                                                const char *source_url,
                                                int status_code,
                                                char *const *headers,
                                                size_t headers_len);
int st_media_capture_append(st_media_capture_session *session,
                            const uint8_t *data,
                            size_t data_len);
void st_media_capture_complete(st_media_capture_session *session);
void st_media_capture_fail(st_media_capture_session *session, const char *reason);
int st_media_capture_externalized(const st_media_capture_session *session);
void st_media_capture_free(st_media_capture_session *session);

/* Builds management/public list, ticket, manifest, and playback responses. */
int st_media_capture_build_response(const char *method,
                                    const char *path,
                                    const st_media_capture_identity *identity,
                                    const char *database_path,
                                    char *out,
                                    size_t out_len);

/* Variant used by the HTTP server to preserve the caller's Range header. */
int st_media_capture_build_response_with_range(const char *method,
                                               const char *path,
                                               const char *range_header,
                                               const st_media_capture_identity *identity,
                                               const char *database_path,
                                               char *out,
                                               size_t out_len);

#endif
