#define _POSIX_C_SOURCE 200809L
#include "owner_transfer.h"
#include "owner_transfer_internal.h"
#include "crypto.h"
#include "json.h"

#include <sqlite3.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SAFE_ID 9007199254740991LL
typedef struct { char *data; size_t len, cap; int failed; } owner_buffer;

static void append(owner_buffer *b, const char *format, ...)
{
    if (b->failed) return;
    va_list args, copy;
    va_start(args, format); va_copy(copy, args);
    int n = vsnprintf(NULL, 0, format, copy);
    va_end(copy);
    if (n < 0 || (size_t)n >= SIZE_MAX - b->len) { b->failed = 1; va_end(args); return; }
    size_t need = b->len + (size_t)n + 1U;
    if (need > b->cap) {
        size_t cap = b->cap == 0U ? 512U : b->cap;
        while (cap < need) {
            if (cap > SIZE_MAX / 2U) { b->failed = 1; va_end(args); return; }
            cap *= 2U;
        }
        char *next = realloc(b->data, cap);
        if (next == NULL) { b->failed = 1; va_end(args); return; }
        b->data = next; b->cap = cap;
    }
    if (vsnprintf(b->data + b->len, b->cap - b->len, format, args) != n) b->failed = 1;
    else b->len += (size_t)n;
    va_end(args);
}

static void text(owner_buffer *b, const char *value)
{
    if (value == NULL) { append(b, "null"); return; }
    char *escaped = st_json_escape(value);
    if (escaped == NULL) { b->failed = 1; return; }
    append(b, "\"%s\"", escaped); free(escaped);
}
static int equal(const char *a, const char *b) { return a != NULL && b != NULL && strcmp(a, b) == 0; }
static int problem(const char **code, int status, const char *value) { *code = value; return status; }
static int invalid(const char **code) { return problem(code, 400, "INVALID_TRANSFER_REQUEST"); }
static int inconsistent(const char **code) { return problem(code, 409, "INCONSISTENT_CREDENTIAL_GROUP"); }
static int valid_id(long long id) { return id > 0 && id <= MAX_SAFE_ID; }
static int authorize(int admin, long long id, const char **code)
{
    if (!admin) return problem(code, 403, "FORBIDDEN");
    return valid_id(id) ? 200 : invalid(code);
}

int st_owner_transfer_match(const char *path, int *group, long long *id, int *id_valid)
{
    static const char *const prefixes[] = {"/api/admin/clients/", "/api/admin/client-credentials/"};
    const char suffix[] = "/owner-transfer";
    if (path == NULL) return 0;
    const char *end = strchr(path, '?');
    if (end == NULL) end = path + strlen(path);
    for (int g = 0; g < 2; ++g) {
        size_t prefix = strlen(prefixes[g]), total = (size_t)(end - path);
        if (total < prefix + sizeof(suffix) - 1U || strncmp(path, prefixes[g], prefix) != 0
            || memcmp(end - (sizeof(suffix) - 1U), suffix, sizeof(suffix) - 1U) != 0) continue;
        size_t len = total - prefix - (sizeof(suffix) - 1U);
        *group = g; *id = 0; *id_valid = len > 0U && len <= 19U;
        for (size_t n = 0U; *id_valid && n < len; ++n) {
            char c = path[prefix + n];
            if (c < '0' || c > '9' || *id > (MAX_SAFE_ID - (c - '0')) / 10LL) *id_valid = 0;
            else *id = *id * 10LL + (c - '0');
        }
        if (!valid_id(*id)) *id_valid = 0;
        return 1;
    }
    return 0;
}

static void row_free(st_owner_row *row)
{
    free(row->tenant_id); free(row->client_name); free(row->owner_username);
}
void st_owner_snapshot_free(st_owner_snapshot *snapshot)
{
    st_owner_rows *lists[] = {&snapshot->clients, &snapshot->credentials, &snapshot->identities, &snapshot->peers};
    for (size_t n = 0; n < 4U; ++n) {
        for (size_t i = 0; i < lists[n]->len; ++i) row_free(&lists[n]->items[i]);
        free(lists[n]->items);
    }
    memset(snapshot, 0, sizeof(*snapshot));
}
int st_owner_rows_add(st_owner_rows *rows, st_owner_row row)
{
    if (rows->len == rows->cap) {
        size_t cap = rows->cap == 0U ? 16U : rows->cap * 2U;
        if (cap < rows->cap || cap > SIZE_MAX / sizeof(row)) return -1;
        st_owner_row *next = realloc(rows->items, cap * sizeof(row));
        if (next == NULL) return -1;
        rows->items = next; rows->cap = cap;
    }
    rows->items[rows->len++] = row;
    return 0;
}

static int column_text(sqlite3_stmt *stmt, int column, char **out)
{
    *out = NULL;
    if (sqlite3_column_type(stmt, column) == SQLITE_NULL) return 0;
    const char *value = (const char *)sqlite3_column_text(stmt, column);
    int len = sqlite3_column_bytes(stmt, column);
    if (value == NULL || len < 0 || memchr(value, '\0', (size_t)len) != NULL) return -1;
    *out = malloc((size_t)len + 1U);
    if (*out == NULL) return -1;
    memcpy(*out, value, (size_t)len); (*out)[len] = '\0';
    return 0;
}

/* C's native client table is client_account/rowid, not Java/Go specus_client_account.
 * Select all incident edges before validation, with no truncation or per-device bind list. */
static const char snapshot_sql[] =
    "WITH path_client AS (SELECT rowid AS id FROM client_account WHERE rowid=:id AND tenant_id=:tenant AND :scope=0),"
    " selected_credentials AS (SELECT id FROM specus_client_credential WHERE id=:id AND tenant_id=:tenant AND :scope=1"
    " UNION SELECT i.credential_id FROM specus_client_identity i WHERE i.client_id IN (SELECT id FROM path_client)),"
    " affected_clients AS (SELECT id FROM path_client UNION SELECT i.client_id FROM specus_client_identity i"
    " WHERE i.credential_id IN (SELECT id FROM selected_credentials))"
    " SELECT 0,c.rowid,c.tenant_id,c.client_name,c.owner_username,c.enabled,NULL,NULL FROM client_account c"
    " WHERE c.rowid IN (SELECT id FROM affected_clients)"
    " UNION ALL SELECT 1,c.id,c.tenant_id,NULL,c.owner_username,c.enabled,NULL,NULL FROM specus_client_credential c"
    " WHERE c.id IN (SELECT id FROM selected_credentials)"
    " UNION ALL SELECT 2,i.id,i.tenant_id,NULL,NULL,NULL,i.credential_id,i.client_id FROM specus_client_identity i"
    " WHERE i.credential_id IN (SELECT id FROM selected_credentials) OR i.client_id IN (SELECT id FROM affected_clients)"
    " UNION ALL SELECT 3,p.id,p.tenant_id,p.client_name,p.owner_username,p.enabled,NULL,p.client_id FROM peer_mesh_device p"
    " WHERE p.tenant_id=:tenant AND p.client_id IN (SELECT id FROM affected_clients)";

int st_owner_snapshot_load_on_db(sqlite3 *db, const char *tenant, int group, long long id, st_owner_snapshot *snapshot)
{
    memset(snapshot, 0, sizeof(*snapshot));
    sqlite3_stmt *stmt = NULL;
    int status = -1;
    if (db == NULL || tenant == NULL) goto done;
    if (sqlite3_prepare_v2(db, snapshot_sql, -1, &stmt, NULL) != SQLITE_OK
        || sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":id"), id) != SQLITE_OK
        || sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":tenant"), tenant, -1, SQLITE_STATIC) != SQLITE_OK
        || sqlite3_bind_int(stmt, sqlite3_bind_parameter_index(stmt, ":scope"), group) != SQLITE_OK) goto done;
    st_owner_rows *lists[] = {&snapshot->clients, &snapshot->credentials, &snapshot->identities, &snapshot->peers};
    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        st_owner_row row = {0};
        int kind = sqlite3_column_int(stmt, 0);
        row.id = sqlite3_column_int64(stmt, 1); row.enabled = sqlite3_column_int(stmt, 5) != 0;
        row.credential_id = sqlite3_column_int64(stmt, 6); row.client_id = sqlite3_column_int64(stmt, 7);
        if (kind < 0 || kind > 3 || column_text(stmt, 2, &row.tenant_id) != 0
            || column_text(stmt, 3, &row.client_name) != 0 || column_text(stmt, 4, &row.owner_username) != 0
            || st_owner_rows_add(lists[kind], row) != 0) { row_free(&row); goto done; }
    }
    if (rc == SQLITE_DONE) status = 0;
done:
    sqlite3_finalize(stmt);
    if (status != 0) st_owner_snapshot_free(snapshot);
    return status;
}

int st_owner_snapshot_load(const char *path, const char *tenant, int group, long long id, st_owner_snapshot *snapshot)
{
    memset(snapshot, 0, sizeof(*snapshot));
    sqlite3 *db = NULL;
    if (path == NULL || tenant == NULL || sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        sqlite3_close(db); return -1;
    }
    sqlite3_busy_timeout(db, 5000);
    int rc = st_owner_snapshot_load_on_db(db, tenant, group, id, snapshot);
    sqlite3_close(db);
    return rc;
}

/* Compare every real schema column except the explicitly mutable ones. Private TEMP
 * snapshots include secrets only inside this connection; none reach JSON or audit. */
int st_owner_transfer_rows_preserved(sqlite3 *db, const char *table, const char *before,
    const char *where, const char *const *ignored, size_t ignored_count)
{
    owner_buffer columns = {0}, sql = {0};
    sqlite3_stmt *stmt = NULL;
    char *pragma = sqlite3_mprintf("PRAGMA table_info(\"%w\")", table);
    int rc = pragma != NULL && sqlite3_prepare_v2(db, pragma, -1, &stmt, NULL) == SQLITE_OK ? 0 : -1;
    sqlite3_free(pragma);
    int first = 1, step = SQLITE_DONE;
    while (rc == 0 && (step = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(stmt, 1);
        if (name == NULL) { rc = -1; break; }
        int skip = 0;
        for (size_t i = 0; i < ignored_count; ++i) if (strcmp(name, ignored[i]) == 0) skip = 1;
        if (skip) continue;
        char *quoted = sqlite3_mprintf("\"%w\"", name);
        if (quoted == NULL) { rc = -1; break; }
        append(&columns, "%s%s", first ? "" : ",", quoted); first = 0;
        sqlite3_free(quoted);
    }
    sqlite3_finalize(stmt); stmt = NULL;
    if (rc != 0 || step != SQLITE_DONE || first || columns.failed) { rc = -1; goto done; }
    /* table/before/where are internal, compile-time identifiers/clauses, never requests. */
    append(&sql, "SELECT EXISTS(SELECT %s FROM %s EXCEPT SELECT %s FROM %s WHERE %s) OR "
                 "EXISTS(SELECT %s FROM %s WHERE %s EXCEPT SELECT %s FROM %s)",
           columns.data, before, columns.data, table, where,
           columns.data, table, where, columns.data, before);
    rc = !sql.failed && sqlite3_prepare_v2(db, sql.data, -1, &stmt, NULL) == SQLITE_OK
        && sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_int(stmt, 0) == 0 ? 0 : -1;
done:
    sqlite3_finalize(stmt); free(columns.data); free(sql.data); return rc;
}

int st_owner_transfer_encode_result(const char *tenant, const char *actor, int group, long long id,
    const char *target, long long credential_id, const st_owner_snapshot *before, const char *preview,
    const long long *client_ids, size_t client_count, int changed,
    const st_storage_peer_close *closed, size_t closed_count, char **response, char **audit)
{
    *response = NULL; *audit = NULL;
    owner_buffer result = {0}, record = {0};
    append(&result, "{\"scope\":\"%s\",\"targetUsername\":", group ? "credential-group" : "single"); text(&result, target);
    append(&result, ",\"credentialId\":");
    if (credential_id == 0) append(&result, "null"); else append(&result, "%lld", credential_id);
    append(&result, ",\"affectedClientIds\":[");
    for (size_t i = 0; i < client_count; ++i) append(&result, "%s%lld", i ? "," : "", client_ids[i]);
    append(&result, "],\"changed\":%s,\"accessRetained\":true}", changed ? "true" : "false");
    if (changed) {
        append(&record, "{\"tenantId\":"); text(&record, tenant);
        append(&record, ",\"actorUsername\":"); text(&record, actor);
        append(&record, ",\"scope\":\"%s\",\"resourceId\":%lld,\"targetUsername\":", group ? "credential-group" : "single", id); text(&record, target);
        append(&record, ",\"before\":%s,\"result\":%s,\"peerOwnersBefore\":[", preview, result.data == NULL ? "null" : result.data);
        for (size_t i = 0; i < before->peers.len; ++i) {
            const st_owner_row *peer = &before->peers.items[i];
            append(&record, "%s{\"id\":%lld,\"clientId\":%lld,\"ownerUsername\":", i ? "," : "", peer->id, peer->client_id); text(&record, peer->owner_username); append(&record, "}");
        }
        append(&record, "],\"closedPeerSessions\":[");
        for (size_t i = 0; i < closed_count; ++i) {
            append(&record, "%s{\"id\":%lld,\"sourceClientId\":%lld,\"sourceClientName\":", i ? "," : "", closed[i].id, closed[i].source_client_id); text(&record, closed[i].source_client_name);
            append(&record, ",\"targetClientId\":%lld,\"targetClientName\":", closed[i].target_client_id); text(&record, closed[i].target_client_name); append(&record, "}");
        }
        append(&record, "]}");
    }
    if (result.failed || record.failed) { free(result.data); free(record.data); return -1; }
    *response = result.data; *audit = record.data; return 0;
}

static int compare_id(const void *a, const void *b)
{
    long long x = *(const long long *)a, y = *(const long long *)b;
    return (x > y) - (x < y);
}
static int compare_row(const void *a, const void *b)
{
    const st_owner_row *x = *(const st_owner_row *const *)a, *y = *(const st_owner_row *const *)b;
    return (x->id > y->id) - (x->id < y->id);
}
static int contains(const long long *ids, size_t count, long long id)
{
    return count > 0U && bsearch(&id, ids, count, sizeof(*ids), compare_id) != NULL;
}
static int require_resource(const char *tenant, int group, long long id, const st_owner_snapshot *s, const char **code)
{
    const st_owner_rows *rows = group ? &s->credentials : &s->clients;
    for (size_t i = 0; i < rows->len; ++i) if (rows->items[i].id == id && equal(rows->items[i].tenant_id, tenant)) return 200;
    return problem(code, 404, "RESOURCE_NOT_FOUND");
}
static void client_json(owner_buffer *b, const st_owner_row *row)
{
    append(b, "{\"id\":%lld,\"clientName\":", row->id); text(b, row->client_name);
    append(b, ",\"ownerUsername\":"); text(b, row->owner_username);
    append(b, ",\"enabled\":%s}", row->enabled ? "true" : "false");
}

int st_owner_transfer_preview(const char *tenant, int admin, int group, long long id,
                              const st_owner_snapshot *s, char **json, char revision[65], const char **code)
{
    *json = NULL; revision[0] = '\0'; *code = NULL;
    int status = authorize(admin, id, code);
    if (status != 200) return status;
    if ((status = require_resource(tenant, group, id, s, code)) != 200) return status;
    long long credential_id = group ? id : 0;
    if (!group) for (size_t i = 0; i < s->identities.len; ++i) {
        const st_owner_row *edge = &s->identities.items[i];
        if (edge->client_id != id) continue;
        if (!equal(edge->tenant_id, tenant) || (credential_id != 0 && credential_id != edge->credential_id)) return inconsistent(code);
        credential_id = edge->credential_id;
        if (!valid_id(credential_id)) return inconsistent(code);
    }
    const st_owner_row *credential = NULL;
    if (credential_id != 0) {
        for (size_t i = 0; i < s->credentials.len; ++i) if (s->credentials.items[i].id == credential_id) {
            if (credential != NULL || !equal(s->credentials.items[i].tenant_id, tenant)) return inconsistent(code);
            credential = &s->credentials.items[i];
        }
        if (credential == NULL) return inconsistent(code);
    }
    size_t edge_cap = s->identities.len + 1U, peer_cap = s->peers.len + 1U;
    if (edge_cap == 0U || peer_cap == 0U || edge_cap > SIZE_MAX / sizeof(st_owner_row *)
        || peer_cap > SIZE_MAX / sizeof(st_owner_row *) || edge_cap > SIZE_MAX / sizeof(long long)
        || peer_cap > SIZE_MAX / sizeof(long long)) return problem(code, 500, "INTERNAL_SERVER_ERROR");
    long long *ids = calloc(edge_cap, sizeof(*ids)), *peer_clients = calloc(peer_cap, sizeof(*peer_clients));
    const st_owner_row **edges = calloc(edge_cap, sizeof(*edges)), **clients = calloc(edge_cap, sizeof(*clients)),
                       **peers = calloc(peer_cap, sizeof(*peers));
    size_t count = 0U, edge_count = 0U, peer_count = 0U;
    owner_buffer canonical = {0}, response = {0};
    status = 409;
    if (ids == NULL || peer_clients == NULL || edges == NULL || clients == NULL || peers == NULL) { status = 500; goto done; }
    if (credential != NULL) {
        for (size_t i = 0; i < s->identities.len; ++i) {
            const st_owner_row *edge = &s->identities.items[i];
            if (edge->credential_id != credential_id) continue;
            if (!equal(edge->tenant_id, tenant) || !valid_id(edge->client_id)) goto done;
            edges[edge_count++] = edge; ids[count++] = edge->client_id;
        }
        qsort(edges, edge_count, sizeof(*edges), compare_row);
        for (size_t i = 1; i < edge_count; ++i) if (edges[i-1]->id == edges[i]->id) goto done;
        qsort(ids, count, sizeof(*ids), compare_id);
        size_t unique = 0U;
        for (size_t i = 0; i < count; ++i) if (i == 0U || ids[i] != ids[i-1]) ids[unique++] = ids[i];
        count = unique;
    } else ids[count++] = id;
    /* No arbitrary bound: validate exactly one account for every full-group id. */
    for (size_t n = 0; n < s->clients.len; ++n) {
        const st_owner_row *row = &s->clients.items[n];
        if (!contains(ids, count, row->id)) continue;
        if (!equal(row->tenant_id, tenant)) goto done;
        const long long *position = bsearch(&row->id, ids, count, sizeof(*ids), compare_id);
        size_t index = (size_t)(position - ids);
        if (clients[index] != NULL) goto done;
        clients[index] = row;
    }
    for (size_t i = 0; i < count; ++i) if (clients[i] == NULL) goto done;
    for (size_t i = 0; i < s->identities.len; ++i) {
        const st_owner_row *edge = &s->identities.items[i];
        if (contains(ids, count, edge->client_id) && (!equal(edge->tenant_id, tenant)
            || credential == NULL || edge->credential_id != credential_id)) goto done;
    }
    for (size_t i = 0; i < s->peers.len; ++i) {
        const st_owner_row *row = &s->peers.items[i];
        if (equal(row->tenant_id, tenant) && contains(ids, count, row->client_id)) {
            peer_clients[peer_count] = row->client_id; peers[peer_count++] = row;
        }
    }
    qsort(peers, peer_count, sizeof(*peers), compare_row);
    qsort(peer_clients, peer_count, sizeof(*peer_clients), compare_id);
    for (size_t i = 1; i < peer_count; ++i) if (peers[i-1]->id == peers[i]->id || peer_clients[i-1] == peer_clients[i]) goto done;
    const char *scope = group ? "credential-group" : "single";
    int shared = !group && count > 1U;
    if (!shared) {
        append(&canonical, "[\"specus-owner-transfer-c-v1\","); text(&canonical, tenant);
        append(&canonical, ",\"%s\",%lld,", scope, id);
        if (credential == NULL) append(&canonical, "null");
        else { append(&canonical, "[%lld,", credential_id); text(&canonical, credential->owner_username); append(&canonical, ",%d]", !!credential->enabled); }
        append(&canonical, ",[");
        for (size_t i = 0; i < count; ++i) { if (i) append(&canonical, ","); client_json(&canonical, clients[i]); }
        append(&canonical, "],[");
        for (size_t i = 0; i < edge_count; ++i) append(&canonical, "%s[%lld,%lld,%lld]", i ? "," : "", edges[i]->id, edges[i]->credential_id, edges[i]->client_id);
        append(&canonical, "],[");
        for (size_t i = 0; i < peer_count; ++i) {
            append(&canonical, "%s[%lld,%lld,", i ? "," : "", peers[i]->id, peers[i]->client_id);
            client_json(&canonical, peers[i]); append(&canonical, "]");
        }
        append(&canonical, "]]");
        if (canonical.failed) { status = 500; goto done; }
        uint8_t hash[ST_SHA256_LEN]; st_sha256((const uint8_t *)canonical.data, canonical.len, hash);
        st_hex_encode(hash, sizeof(hash), revision);
    }
    append(&response, "{\"scope\":\"%s\",\"clientId\":", scope);
    if (group) append(&response, "null"); else append(&response, "%lld", id);
    append(&response, ",\"credentialId\":");
    if (credential == NULL) append(&response, "null"); else append(&response, "%lld", credential_id);
    append(&response, ",\"credentialOwnerUsername\":"); text(&response, credential == NULL ? NULL : credential->owner_username);
    append(&response, ",\"credentialEnabled\":%s,\"affectedClients\":[", credential == NULL ? "null" : credential->enabled ? "true" : "false");
    for (size_t i = 0; i < count; ++i) { if (i) append(&response, ","); client_json(&response, clients[i]); }
    append(&response, "],\"affectedClientCount\":%zu,\"canTransfer\":%s,\"conflictCode\":%s,\"revision\":", count,
           shared ? "false" : "true", shared ? "\"CREDENTIAL_SHARED\"" : "null");
    if (shared) append(&response, "null"); else text(&response, revision);
    append(&response, ",\"accessRetained\":true}");
    if (response.failed) { status = 500; goto done; }
    *json = response.data; response.data = NULL; status = 200;
done:
    free(ids); free(peer_clients); free(edges); free(clients); free(peers); free(canonical.data); free(response.data);
    if (status == 409) return inconsistent(code);
    if (status == 500) return problem(code, 500, "INTERNAL_SERVER_ERROR");
    return status;
}

/* Decode with the actual length so embedded NUL cannot match a prefix of scope/revision. */
static char *request_text(const char *request, const char *field, size_t *len, int *present)
{
    char *raw = st_json_get_top_level_raw(request, field);
    *present = raw != NULL;
    char *value = raw == NULL ? NULL : st_json_decode_string(raw, len);
    free(raw); return value;
}
int st_owner_transfer_prepare(const char *tenant, int admin, int group, long long id,
                              const st_owner_snapshot *s, const char *request,
                              char **json, char **target, const char **code)
{
    *json = NULL; *target = NULL; *code = NULL;
    int status = authorize(admin, id, code);
    if (status != 200) return status;
    if (request == NULL || !st_json_is_valid_object(request)) return invalid(code);
    if ((status = require_resource(tenant, group, id, s, code)) != 200) return status;
    size_t scope_len = 0U, target_len = 0U, revision_len = 0U;
    int scope_present = 0, target_present = 0, revision_present = 0;
    char *scope = request_text(request, "scope", &scope_len, &scope_present);
    char *requested_target = request_text(request, "targetUsername", &target_len, &target_present);
    char *requested_revision = request_text(request, "expectedRevision", &revision_len, &revision_present);
    const char *expected_scope = group ? "credential-group" : "single";
    if (scope == NULL || scope_len != strlen(expected_scope) || memcmp(scope, expected_scope, scope_len) != 0
        || (target_present && requested_target == NULL) || (revision_present && requested_revision == NULL)) { status = invalid(code); goto done; }
    char revision[65];
    status = st_owner_transfer_preview(tenant, admin, group, id, s, json, revision, code);
    if (status != 200) goto done;
    if (revision[0] == '\0') { status = problem(code, 409, "CREDENTIAL_SHARED"); goto done; }
    size_t first = 0U, last = target_len;
    while (first < last && (unsigned char)requested_target[first] <= 32U) ++first;
    while (last > first && (unsigned char)requested_target[last-1] <= 32U) --last;
    size_t nonblank = 0U;
    while (nonblank < revision_len && (unsigned char)requested_revision[nonblank] <= 32U) ++nonblank;
    if (!target_present || !revision_present || first == last || nonblank == revision_len) { status = invalid(code); goto done; }
    if (revision_len != strlen(revision) || memcmp(requested_revision, revision, revision_len) != 0) { status = problem(code, 409, "TRANSFER_PREVIEW_CHANGED"); goto done; }
    if (memchr(requested_target + first, '\0', last - first) != NULL) { status = invalid(code); goto done; }
    memmove(requested_target, requested_target + first, last - first); requested_target[last-first] = '\0';
    *target = requested_target; requested_target = NULL;
done:
    free(scope); free(requested_target); free(requested_revision);
    if (status != 200) { free(*json); *json = NULL; }
    return status;
}
