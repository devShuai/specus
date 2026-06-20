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

    char path[512];
    const char *content_type = NULL;
    if (st_admin_resolve_static_path("../../tunnel-server/src/main/resources/static",
                                     "/",
                                     path,
                                     sizeof(path),
                                     &content_type) != 0
        || !contains(path, "index.html")
        || strcmp(content_type, "text/html; charset=utf-8") != 0) {
        fprintf(stderr, "static index path mismatch\n");
        return 1;
    }
    if (st_admin_resolve_static_path("../../tunnel-server/src/main/resources/static",
                                     "/app.js?cache=1",
                                     path,
                                     sizeof(path),
                                     &content_type) != 0
        || !contains(path, "app.js")
        || strcmp(content_type, "application/javascript; charset=utf-8") != 0) {
        fprintf(stderr, "static js path mismatch\n");
        return 1;
    }
    if (st_admin_resolve_static_path("../../tunnel-server/src/main/resources/static",
                                     "/../application.yml",
                                     path,
                                     sizeof(path),
                                     &content_type) == 0) {
        fprintf(stderr, "static traversal was allowed\n");
        return 1;
    }
    return 0;
}
