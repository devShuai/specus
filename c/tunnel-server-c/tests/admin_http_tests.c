#include "admin_http.h"

#include <stdio.h>
#include <string.h>

static int contains(const char *haystack, const char *needle)
{
    return strstr(haystack, needle) != NULL;
}

int main(void)
{
    char response[4096];
    int len = st_admin_build_response("GET", "/health", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, "{\"status\":\"ok\"}")) {
        fprintf(stderr, "health response mismatch\n");
        return 1;
    }

    len = st_admin_build_response("POST", "/auth/login", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, "local-dev-token")) {
        fprintf(stderr, "login response mismatch\n");
        return 1;
    }

    len = st_admin_build_response("GET", "/api/admin/overview", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, "\"server\":\"c\"")) {
        fprintf(stderr, "overview response mismatch\n");
        return 1;
    }

    len = st_admin_build_response("GET", "/missing", response, sizeof(response));
    if (len <= 0 || !contains(response, "404 Not Found")) {
        fprintf(stderr, "404 response mismatch\n");
        return 1;
    }
    return 0;
}
