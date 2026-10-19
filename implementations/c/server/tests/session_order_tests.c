#define _POSIX_C_SOURCE 200809L
#include "json.h"
#include "storage.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef ST_SESSION_ORDER_VECTOR_FILE
#define ST_SESSION_ORDER_VECTOR_FILE "../../../protocol/test-vectors/peer-egress-session-order-v1.json"
#endif
#ifndef ST_SESSION_ORDER_EXPECTED_CASES
#define ST_SESSION_ORDER_EXPECTED_CASES 26U
#endif

static char *read_vector(void)
{
    FILE *file = fopen(ST_SESSION_ORDER_VECTOR_FILE, "rb");
    if (file == NULL) return NULL;
    if (fseek(file, 0, SEEK_END) != 0) { fclose(file); return NULL; }
    long length = ftell(file);
    if (length < 0) { fclose(file); return NULL; }
    rewind(file);
    char *text = malloc((size_t)length + 1U);
    if (text == NULL || fread(text, 1, (size_t)length, file) != (size_t)length) {
        free(text); fclose(file); return NULL;
    }
    text[length] = '\0';
    fclose(file);
    return text;
}

static int insert_session(sqlite3 *db, const char *json, long long account_id, long long vector_client_id)
{
    long long id = 0, client_id = 0;
    int version = 0, domain = 0, ipv6 = 0;
    char *tenant = st_json_get_top_level_string(json, "tenantId");
    char *status = st_json_get_top_level_string(json, "status");
    char *http = st_json_get_top_level_string(json, "httpLoginAt");
    char *connected = st_json_get_top_level_string(json, "connectedAt");
    sqlite3_stmt *statement = NULL;
    int rc = tenant != NULL && status != NULL && http != NULL
        && st_json_get_i64(json, "id", &id) == 0 && st_json_get_i64(json, "clientId", &client_id) == 0
        && st_json_get_int(json, "version", &version) == 0
        && st_json_get_bool(json, "domainTargetCapable", &domain) == 0
        && st_json_get_bool(json, "ipv6TargetCapable", &ipv6) == 0 ? 0 : -1;
    if (rc == 0 && sqlite3_prepare_v2(db,
        "INSERT INTO specus_client_session "
        "(id,tenant_id,credential_id,identity_id,client_id,client_name,token_hash,status,"
        "machine_fingerprint,os_user,http_login_at,netty_connected_at,expires_at,"
        "client_egress_version,client_egress_domain_targets,client_egress_ipv6_targets) "
        "VALUES(?1,?2,1,1,?3,'order-egress',?4,?5,'fixture-machine','fixture-user',?6,?7,"
        "'2026-10-19T00:00:00Z',?8,?9,?10)", -1, &statement, NULL) != SQLITE_OK) rc = -1;
    if (rc == 0) {
        char token[64];
        snprintf(token, sizeof(token), "order-session-%lld", id);
        sqlite3_bind_int64(statement, 1, id);
        sqlite3_bind_text(statement, 2, tenant, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(statement, 3, client_id == vector_client_id ? account_id : account_id + 1);
        sqlite3_bind_text(statement, 4, token, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 5, status, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 6, http, -1, SQLITE_TRANSIENT);
        if (connected != NULL) sqlite3_bind_text(statement, 7, connected, -1, SQLITE_TRANSIENT);
        else sqlite3_bind_null(statement, 7);
        sqlite3_bind_int(statement, 8, version);
        sqlite3_bind_int(statement, 9, domain);
        sqlite3_bind_int(statement, 10, ipv6);
        if (sqlite3_step(statement) != SQLITE_DONE) rc = -1;
    }
    if (rc != 0) fprintf(stderr, "session fixture insert failed: %s\n", sqlite3_errmsg(db));
    sqlite3_finalize(statement);
    free(tenant); free(status); free(http); free(connected);
    return rc;
}

static int matches(const st_storage_client *client, int version, int domain, int ipv6)
{
    int capable = client->client_egress_version >= 1;
    return (capable ? client->client_egress_version : 0) == version
        && (capable && client->client_egress_domain_targets) == domain
        && (capable && client->client_egress_ipv6_targets) == ipv6;
}

int main(void)
{
    char *root = read_vector();
    char **cases = NULL;
    size_t case_count = 0U;
    int consumer_ipv6 = 1;
    long long vector_client_id = 0;
    char *tenant = root == NULL ? NULL : st_json_get_top_level_string(root, "tenantId");
    if (root == NULL || st_json_get_bool(root, "consumerIpv6DataPlaneEnabled", &consumer_ipv6) != 0
        || consumer_ipv6 || tenant == NULL || st_json_get_i64(root, "clientId", &vector_client_id) != 0
        || st_json_get_raw_array(root, "cases", &cases, &case_count) != 0 || case_count != ST_SESSION_ORDER_EXPECTED_CASES) {
        fprintf(stderr, "shared session ordering contract missing or changed\n");
        free(tenant); free(root); st_json_free_string_array(cases, case_count); return 1;
    }
    char path[] = "/tmp/specus-session-order-XXXXXX";
    int descriptor = mkstemp(path);
    if (descriptor < 0) return 1;
    close(descriptor);
    st_storage_client client;
    if (st_storage_init(path, 0) != 0
        || st_storage_upsert_client(path, 0, tenant, "order-egress", "fixture-owner", 1, 60, &client) != 0) {
        fprintf(stderr, "owned session ordering database setup failed\n"); free(tenant); unlink(path); return 1;
    }
    free(tenant);
    sqlite3 *database = NULL;
    long long account_id = client.id;
    if (sqlite3_open(path, &database) != SQLITE_OK) { unlink(path); return 1; }
#ifdef ST_SESSION_SCOPE_NOCASE
    /* Recreate only this empty test-owned table with case-insensitive candidate
     * filtering, so exact identity cannot accidentally rely on SQLite's default. */
    sqlite3_stmt *schema = NULL;
    char *ddl = NULL;
    if (sqlite3_prepare_v2(database, "SELECT sql FROM sqlite_master WHERE type='table' AND name='specus_client_session'", -1, &schema, NULL) == SQLITE_OK
        && sqlite3_step(schema) == SQLITE_ROW) ddl = strdup((const char *)sqlite3_column_text(schema, 0));
    sqlite3_finalize(schema);
    if (ddl == NULL) { sqlite3_close(database); unlink(path); return 1; }
    /* SQLite ALTER cannot change a column collation. Insert the suffix into
     * the actual empty-table DDL, preserving every other column and constraint. */
    const char *columns[] = {"tenant_id TEXT", "status TEXT"};
    for (size_t column = 0; column < 2U; column++) {
        char *at = strstr(ddl, columns[column]);
        if (at == NULL) { free(ddl); sqlite3_close(database); unlink(path); return 1; }
        size_t prefix = (size_t)(at - ddl) + strlen(columns[column]);
        const char *collation = " COLLATE NOCASE";
        char *updated = malloc(strlen(ddl) + strlen(collation) + 1U);
        if (updated == NULL) { free(ddl); sqlite3_close(database); unlink(path); return 1; }
        memcpy(updated, ddl, prefix);
        strcpy(updated + prefix, collation);
        strcpy(updated + prefix + strlen(collation), ddl + prefix);
        free(ddl); ddl = updated;
    }
    int schema_ok = sqlite3_exec(database, "DROP TABLE specus_client_session", NULL, NULL, NULL) == SQLITE_OK
        && sqlite3_exec(database, ddl, NULL, NULL, NULL) == SQLITE_OK;
    free(ddl);
    if (!schema_ok) { sqlite3_close(database); unlink(path); return 1; }
#endif
    int failures = 0;
    for (size_t i = 0; i < case_count; ++i) {
        char *name = st_json_get_top_level_string(cases[i], "name");
        char *expected = st_json_get_top_level_raw(cases[i], "expected");
        char **sessions = NULL;
        size_t count = 0U;
        int version = -1, domain = -1, ipv6 = -1;
        int valid = expected != NULL && st_json_get_int(expected, "version", &version) == 0
            && st_json_get_bool(expected, "domainTargetCapable", &domain) == 0
            && st_json_get_bool(expected, "ipv6TargetCapable", &ipv6) == 0
            && st_json_get_raw_array(cases[i], "sessions", &sessions, &count) == 0
            && sqlite3_exec(database, "DELETE FROM specus_client_session", NULL, NULL, NULL) == SQLITE_OK;
        for (size_t j = 0; valid && j < count; ++j) valid = insert_session(database, sessions[j], account_id, vector_client_id) == 0;
        st_storage_client listed[4];
        st_storage_client *all = NULL;
        size_t listed_count = 0U, all_count = 0U;
        int passed = valid
            && st_storage_get_client(path, account_id, &client) == 0 && matches(&client, version, domain, ipv6)
            && st_storage_get_client_by_name(path, "order-egress", &client) == 0 && matches(&client, version, domain, ipv6)
            && st_storage_list_clients(path, listed, 4, &listed_count) == 0 && listed_count == 1U
            && matches(&listed[0], version, domain, ipv6)
            && st_storage_list_all_clients(path, &all, &all_count) == 0 && all_count == 1U
            && matches(&all[0], version, domain, ipv6);
        printf("session-order %s: %s\n", name == NULL ? "(missing)" : name, passed ? "PASS" : "FAIL");
        if (!passed) failures++;
        free(all); free(name); free(expected); st_json_free_string_array(sessions, count);
    }
    sqlite3_close(database); unlink(path);
    st_json_free_string_array(cases, case_count); free(root);
    printf("session-order cases=%zu failures=%d\n", case_count, failures);
    return failures == 0 ? 0 : 1;
}
