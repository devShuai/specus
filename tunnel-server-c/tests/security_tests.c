#include "security.h"

#include <stdio.h>
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
                                      "https://idp.example/token",
                                      "https://idp.example",
                                      buffer,
                                      sizeof(buffer)) <= 0
        || !contains(buffer, "\"configured\":true")
        || !contains(buffer, "\"clientId\":\"client-1\"")) {
        fprintf(stderr, "OIDC configured response mismatch\n");
        return 1;
    }
    if (st_security_build_oidc_config("", NULL, NULL, NULL, buffer, sizeof(buffer)) <= 0
        || !contains(buffer, "\"configured\":false")) {
        fprintf(stderr, "OIDC disabled response mismatch\n");
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
