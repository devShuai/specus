#ifndef SHUAI_TUNNEL_SECURITY_H
#define SHUAI_TUNNEL_SECURITY_H

#include <stddef.h>

#define ST_SECURITY_TOKEN_USERNAME_LEN 80
#define ST_SECURITY_TOKEN_TENANT_LEN 63
#define ST_SECURITY_TOKEN_ROLE_LEN 19

typedef struct {
    char username[ST_SECURITY_TOKEN_USERNAME_LEN + 1];
    char tenant_id[ST_SECURITY_TOKEN_TENANT_LEN + 1];
    char role[ST_SECURITY_TOKEN_ROLE_LEN + 1];
    long long expires_at;
} st_security_token_claims;

int st_security_build_oidc_config(const char *client_id,
                                  const char *authorization_endpoint,
                                  const char *end_session_endpoint,
                                  const char *redirect_uri,
                                  const char *scope,
                                  int password_login_enabled,
                                  char *out,
                                  size_t out_len);
const char *st_security_tls_mode_label(const char *mode);
int st_security_build_tls_config(const char *mode,
                                 const char *certificate_path,
                                 const char *key_path,
                                 char *out,
                                 size_t out_len);
long long st_security_token_ttl_seconds(const char *ttl_seconds);
int st_security_issue_local_token(const char *username,
                                  const char *tenant_id,
                                  const char *role,
                                  const char *jwt_secret,
                                  long long ttl_seconds,
                                  char *out,
                                  size_t out_len);
int st_security_validate_local_token(const char *token,
                                     const char *jwt_secret,
                                     const char *default_tenant_id,
                                     const char *admin_username,
                                     st_security_token_claims *claims);

#endif
