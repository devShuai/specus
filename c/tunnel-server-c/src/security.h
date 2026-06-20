#ifndef SHUAI_TUNNEL_SECURITY_H
#define SHUAI_TUNNEL_SECURITY_H

#include <stddef.h>

int st_security_build_oidc_config(const char *client_id,
                                  const char *authorization_endpoint,
                                  const char *token_endpoint,
                                  const char *issuer,
                                  char *out,
                                  size_t out_len);
const char *st_security_tls_mode_label(const char *mode);
int st_security_build_tls_config(const char *mode,
                                 const char *certificate_path,
                                 const char *key_path,
                                 char *out,
                                 size_t out_len);

#endif
