#ifndef SPECUS_HTTP_CLIENT_H
#define SPECUS_HTTP_CLIENT_H

#include <stddef.h>

typedef struct {
    long timeout_ms;
    size_t max_response_bytes;
    const char *ca_certificate_path;
} st_http_client_options;

/*
 * Sends an application/x-www-form-urlencoded POST request over HTTP or HTTPS.
 * HTTPS always verifies both the certificate chain and the endpoint hostname.
 * The caller owns *body_out and must release it with free().
 */
int st_http_post_form(const char *endpoint,
                      const char *basic_authorization_base64,
                      const char *form,
                      const st_http_client_options *options,
                      long *status_code_out,
                      char **body_out);

/* Strict-verification JSON GET with redirect refusal and a bounded body. */
int st_http_get_json(const char *endpoint,
                     const st_http_client_options *options,
                     long *status_code_out,
                     char **body_out);

#endif
