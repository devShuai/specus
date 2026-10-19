#ifndef ST_CONNECTIVITY_HTTP_TEST_SUPPORT_H
#define ST_CONNECTIVITY_HTTP_TEST_SUPPORT_H

#include <sqlite3.h>
#include <strings.h>
#include "admin_http.h"
#include "security.h"
#include "storage.h"
#include "connectivity_check_test_support.h"

static inline int exec_sql(const char *path, const char *sql)
{
    sqlite3 *db = NULL;
    int failed = sqlite3_open(path, &db) != SQLITE_OK;
    if (!failed && sqlite3_exec(db, sql, NULL, NULL, NULL) != SQLITE_OK) {
        fprintf(stderr, "fixture SQL: %s\n", sqlite3_errmsg(db));
        failed = 1;
    }
    sqlite3_close(db);
    return failed;
}

static inline int create_bearer_in_tenant(const char *db, const char *tenant, const char *user, const char *role,
                         char *out, size_t out_len)
{
    st_storage_management_user row;
    char token[2048];
    if (st_storage_create_management_user(db, user, tenant, "unused-password-hash", role, 1, &row) != 0
        || st_security_issue_local_token(user, tenant, role, getenv("SPECUS_AUTH_JWT_SECRET"),
                                         600, token, sizeof(token)) != 0) return 1;
    int written = snprintf(out, out_len, "Bearer %s", token);
    return written < 0 || (size_t)written >= out_len;
}

static inline int create_route(const char *db, long long id, const char *owner,
                        int client_enabled, int route_enabled, int target_valid)
{
    st_storage_client client;
    st_storage_http_route route;
    char client_name[64];
    snprintf(client_name, sizeof(client_name), "device-%lld", id);
    if (st_storage_upsert_client(db, 0, "t1", client_name, owner, client_enabled, 0, &client) != 0
        || st_storage_create_http_route_for_client(db, client.id, "api", "http://127.0.0.1:8080/base",
                route_enabled, 0, 0, 0, 0, 0, "", "", &route) != 0) return 1;
    /* Stable vector IDs, plus a legacy invalid target that the management creation API rejects. */
    char sql[512];
    snprintf(sql, sizeof(sql), "UPDATE http_route_mapping SET id=%lld,target_base_url='%s' WHERE id=%lld",
             id, target_valid ? "http://127.0.0.1:8080/base" : "ftp://127.0.0.1/", route.id);
    return exec_sql(db, sql);
}

/* Exactly one header, case-insensitive name, and exact value (or absent when value == NULL). */
static inline int assert_header(const char *raw, const char *name, const char *value)
{
    const char *p = strstr(raw, "\r\n");
    int count = 0;
    int match = 0;
    size_t name_len = strlen(name);
    while (p != NULL && p[2] != '\r' && p[2] != '\0') {
        p += 2;
        const char *end = strstr(p, "\r\n");
        if (end == NULL) return 1;
        if ((size_t)(end - p) > name_len && strncasecmp(p, name, name_len) == 0 && p[name_len] == ':') {
            const char *start = p + name_len + 1;
            while (start < end && (*start == ' ' || *start == '\t')) ++start;
            ++count;
            match = value != NULL && (size_t)(end - start) == strlen(value)
                && memcmp(start, value, strlen(value)) == 0;
        }
        p = end;
    }
    if (value == NULL ? count != 0 : count != 1 || !match) {
        fprintf(stderr, "HTTP header %s differs (want %s, count %d)\n", name, value ? value : "absent", count);
        return 1;
    }
    return 0;
}


static inline int create_bearer(const char *db, const char *user, const char *role,
                                char *out, size_t out_len)
{
    return create_bearer_in_tenant(db, "t1", user, role, out, out_len);
}

int run_connectivity_http_resource_tests(void);

#endif
