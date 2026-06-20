#include "security.h"

#include "json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *non_null(const char *value)
{
    return value == NULL ? "" : value;
}

int st_security_build_oidc_config(const char *client_id,
                                  const char *authorization_endpoint,
                                  const char *token_endpoint,
                                  const char *issuer,
                                  char *out,
                                  size_t out_len)
{
    int configured = client_id != NULL && *client_id != '\0';
    char *escaped_client_id = st_json_escape(non_null(client_id));
    char *escaped_auth = st_json_escape(non_null(authorization_endpoint));
    char *escaped_token = st_json_escape(non_null(token_endpoint));
    char *escaped_issuer = st_json_escape(non_null(issuer));
    if (escaped_client_id == NULL || escaped_auth == NULL || escaped_token == NULL || escaped_issuer == NULL) {
        free(escaped_client_id);
        free(escaped_auth);
        free(escaped_token);
        free(escaped_issuer);
        return -1;
    }
    int written = snprintf(out,
                           out_len,
                           "{\"configured\":%s,\"clientId\":\"%s\","
                           "\"authorizationEndpoint\":\"%s\",\"tokenEndpoint\":\"%s\",\"issuer\":\"%s\"}",
                           configured ? "true" : "false",
                           escaped_client_id,
                           escaped_auth,
                           escaped_token,
                           escaped_issuer);
    free(escaped_client_id);
    free(escaped_auth);
    free(escaped_token);
    free(escaped_issuer);
    return written < 0 || (size_t)written >= out_len ? -1 : written;
}

const char *st_security_tls_mode_label(const char *mode)
{
    if (mode == NULL || *mode == '\0' || strcmp(mode, "off") == 0) {
        return "off";
    }
    if (strcmp(mode, "pem") == 0 || strcmp(mode, "pkcs12") == 0 || strcmp(mode, "self-signed") == 0) {
        return mode;
    }
    return "invalid";
}

int st_security_build_tls_config(const char *mode,
                                 const char *certificate_path,
                                 const char *key_path,
                                 char *out,
                                 size_t out_len)
{
    const char *label = st_security_tls_mode_label(mode);
    char *escaped_cert = st_json_escape(non_null(certificate_path));
    char *escaped_key = st_json_escape(non_null(key_path));
    if (escaped_cert == NULL || escaped_key == NULL) {
        free(escaped_cert);
        free(escaped_key);
        return -1;
    }
    int written = snprintf(out,
                           out_len,
                           "{\"mode\":\"%s\",\"certificatePath\":\"%s\",\"keyPath\":\"%s\",\"wired\":false}",
                           label,
                           escaped_cert,
                           escaped_key);
    free(escaped_cert);
    free(escaped_key);
    return written < 0 || (size_t)written >= out_len ? -1 : written;
}
