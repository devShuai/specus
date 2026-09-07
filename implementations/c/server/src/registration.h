#ifndef SPECUS_REGISTRATION_H
#define SPECUS_REGISTRATION_H

#include <stddef.h>

#include "storage.h"

typedef struct {
    char registration_id[65];
    char email_masked[320];
    char expires_at[64];
    long long resend_after_seconds;
} st_registration_challenge_response;

typedef int (*st_registration_turnstile_handler)(void *ctx,
                                                 const char *response_token,
                                                 const char *expected_action);
typedef int (*st_registration_email_handler)(void *ctx,
                                             const char *email,
                                             const char *username,
                                             const char *code,
                                             long long ttl_seconds);

/* Dependency injection for embedders and deterministic tests; NULL restores production handlers. */
void st_registration_set_handlers(st_registration_turnstile_handler turnstile,
                                  st_registration_email_handler email,
                                  void *ctx);

int st_registration_available(void);
int st_auth_turnstile_available(void);
int st_auth_turnstile_verify(const char *response_token,
                             const char *expected_action,
                             int *http_status,
                             char *error,
                             size_t error_len);

int st_registration_request(const char *database_path,
                            const char *json_body,
                            st_registration_challenge_response *response,
                            int *http_status,
                            char *error,
                            size_t error_len);

int st_registration_verify(const char *database_path,
                           const char *json_body,
                           st_storage_management_user *user,
                           int *http_status,
                           char *error,
                           size_t error_len);

#endif
