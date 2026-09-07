#define _POSIX_C_SOURCE 200809L

#include "security.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int contains(const char *haystack, const char *needle)
{
    return strstr(haystack, needle) != NULL;
}

int main(void)
{
    char buffer[1024];
    if (st_security_build_oidc_config("client-1",
                                      "https://idp.example/auth",
                                      "https://idp.example/logout",
                                      "http://127.0.0.1:8088/callback",
                                      "openid profile",
                                      0,
                                      buffer,
                                      sizeof(buffer)) <= 0
        || !contains(buffer, "\"configured\":true")
        || !contains(buffer, "\"authorizationEndpoint\":\"https://idp.example/auth\"")
        || !contains(buffer, "\"endSessionEndpoint\":\"https://idp.example/logout\"")
        || !contains(buffer, "\"clientId\":\"client-1\"")
        || !contains(buffer, "\"redirectUri\":\"http://127.0.0.1:8088/callback\"")
        || !contains(buffer, "\"scope\":\"openid profile\"")
        || !contains(buffer, "\"passwordLoginEnabled\":false")) {
        fprintf(stderr, "OIDC configured response mismatch\n");
        return 1;
    }
    if (st_security_build_oidc_config("", NULL, NULL, NULL, NULL, 1, buffer, sizeof(buffer)) <= 0
        || !contains(buffer, "\"configured\":false") || !contains(buffer, "\"passwordLoginEnabled\":true")) {
        fprintf(stderr, "OIDC disabled response mismatch\n");
        return 1;
    }
    if (st_security_build_oidc_config_extended(
            "client-2", "https://idp.example/auth", "https://idp.example/register",
            "https://idp.example/logout", "http://127.0.0.1:8088/", "openid email",
            1, 1, 1, "site-key", buffer, sizeof(buffer)) <= 0
        || !contains(buffer, "\"registrationEndpoint\":\"https://idp.example/register\"")
        || !contains(buffer, "\"registrationEnabled\":true")
        || !contains(buffer, "\"emailVerificationRequired\":true")
        || !contains(buffer, "\"turnstileEnabled\":true")
        || !contains(buffer, "\"turnstileSiteKey\":\"site-key\"")) {
        fprintf(stderr, "OIDC extended browser configuration mismatch\n");
        return 1;
    }
    if (st_security_token_ttl_seconds("30") != 60 || st_security_token_ttl_seconds("7200") != 7200) {
        fprintf(stderr, "token ttl normalization mismatch\n");
        return 1;
    }
    char pairing_hash[65];
    setenv("SPECUS_AUTH_JWT_SECRET", "c-room-test-jwt-secret-with-more-than-32-bytes", 1);
    if (st_security_pairing_code_hash("12345678", pairing_hash) != 0
        || strcmp(pairing_hash, "6a6fd5809887eba966a7b459a8e0a8d2278cf3cba661f6a7a4ec56f3857e8c5b") != 0) {
        fprintf(stderr, "pairing-code HMAC vector mismatch\n");
        return 1;
    }
    unsetenv("SPECUS_AUTH_JWT_SECRET");
    char token[2048];
    if (st_security_issue_local_token("alice",
                                      "tenant-a",
                                      "USER",
                                      "secret-1",
                                      3600,
                                      token,
                                      sizeof(token)) != 0
        || !contains(token, ".")) {
        fprintf(stderr, "local token issue mismatch\n");
        return 1;
    }
    st_security_token_claims claims;
    if (st_security_validate_local_token(token, "secret-1", "default", "admin", &claims) != 0
        || strcmp(claims.username, "alice") != 0
        || strcmp(claims.tenant_id, "tenant-a") != 0
        || strcmp(claims.role, "USER") != 0
        || claims.expires_at <= 0) {
        fprintf(stderr, "local token validation mismatch\n");
        return 1;
    }
    if (st_security_validate_local_token(token, "wrong-secret", "default", "admin", &claims) == 0) {
        fprintf(stderr, "local token accepted wrong secret\n");
        return 1;
    }
    if (st_security_issue_local_token("admin",
                                      "tenant-a",
                                      "USER",
                                      "secret-1",
                                      3600,
                                      token,
                                      sizeof(token)) != 0
        || st_security_validate_local_token(token, "secret-1", "default", "admin", &claims) != 0
        || strcmp(claims.role, "ADMIN") != 0) {
        fprintf(stderr, "local token admin role fallback mismatch\n");
        return 1;
    }
    if (strcmp(st_security_tls_mode_label("pem"), "pem") != 0
        || strcmp(st_security_tls_mode_label("bogus"), "invalid") != 0) {
        fprintf(stderr, "TLS mode label mismatch\n");
        return 1;
    }
    if (st_security_build_tls_config("pem", "/tmp/cert.pem", "/tmp/key.pem", buffer, sizeof(buffer)) <= 0
        || !contains(buffer, "\"mode\":\"pem\"")
        || !contains(buffer, "\"wired\":false")) {
        fprintf(stderr, "TLS config response mismatch\n");
        return 1;
    }
    return 0;
}
