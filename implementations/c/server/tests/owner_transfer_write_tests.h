/* Real SQLite writer acceptance. No HTTP POST or runtime delivery is implied. */
#ifndef SPECUS_OWNER_TRANSFER_WRITE_TESTS_H
#define SPECUS_OWNER_TRANSFER_WRITE_TESTS_H
#include <unistd.h>

typedef struct {
    char dir[128], path[180];
    sqlite3 *db;
    st_storage_management_user admin, bob;
} owner_write_fixture;

static int ow_sql(sqlite3 *db, const char *sql)
{
    char *error = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &error);
    if (rc != SQLITE_OK) fprintf(stderr, "ownership fixture SQL: %s\n", error == NULL ? sqlite3_errmsg(db) : error);
    sqlite3_free(error); return rc == SQLITE_OK ? 0 : -1;
}
static long long ow_scalar(sqlite3 *db, const char *sql)
{
    sqlite3_stmt *stmt = NULL; long long value = -1;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW)
        value = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt); return value;
}
static int ow_fresh(owner_write_fixture *f, const char *snapshot)
{
    CHECK(f != NULL, "fixture output required");
    memset(f, 0, sizeof(*f)); snprintf(f->dir, sizeof(f->dir), "/tmp/specus-owner-write-XXXXXX");
    CHECK(mkdtemp(f->dir) != NULL, "owned directory");
    snprintf(f->path, sizeof(f->path), "%s/test.db", f->dir);
    CHECK(st_storage_init(f->path, 0) == 0, "real schema");
    CHECK(st_storage_create_management_user(f->path, "operator", "default", "private-admin-hash", "ADMIN", 1, &f->admin) == 0
        && st_storage_create_management_user(f->path, "Bob", "default", "private-bob-hash", "USER", 1, &f->bob) == 0, "current accounts");
    CHECK(sqlite3_open(f->path, &f->db) == SQLITE_OK, "fixture connection");
    sqlite3_busy_timeout(f->db, 5000);
    st_owner_snapshot s = {0};
    CHECK(read_snapshot(snapshot, &s) == 0 && seed_snapshot(f->db, &s) == 0, "seed %s", snapshot);
    st_owner_snapshot_free(&s);
    CHECK(ow_sql(f->db, "UPDATE client_account SET created_at='client-created',updated_at='client-before';"
        "UPDATE specus_client_credential SET created_at='credential-created',updated_at='credential-before',max_online_instances=17;"
        "UPDATE peer_mesh_device SET updated_at='peer-before';") == 0, "distinct immutable stamps");
    return 0;
}
static void ow_finish(owner_write_fixture *f)
{
    sqlite3_close(f->db); unlink(f->path); rmdir(f->dir);
}
static int ow_request(owner_write_fixture *f, int group, long long id, const char *target, char **request)
{
    st_owner_snapshot s = {0}; char *preview = NULL, revision[65]; const char *code = NULL;
    CHECK(st_owner_snapshot_load(f->path, "default", group, id, &s) == 0, "actual current snapshot");
    CHECK(st_owner_transfer_preview("default", 1, group, id, &s, &preview, revision, &code) == 200, "actual preview %s", code == NULL ? "" : code);
    free(preview); st_owner_snapshot_free(&s);
    char *escaped = st_json_escape(target); CHECK(escaped != NULL, "escaped target");
    *request = malloc(strlen(escaped) + 200U); CHECK(*request != NULL, "request allocation");
    sprintf(*request, "{\"scope\":\"%s\",\"targetUsername\":\"%s\",\"expectedRevision\":\"%s\"}", group ? "credential-group" : "single", escaped, revision);
    free(escaped); return 0;
}
static int ow_transfer(owner_write_fixture *f, int group, long long id, const char *request,
    st_storage_owner_transfer_result *result, const char **code)
{
    st_storage_management_actor actor = {f->admin.username, f->admin.tenant_id, f->admin.account_key};
    return st_storage_transfer_owner(f->path, &actor, NULL, group, id, request, 1791979966000LL, result, code);
}
static int ow_unchanged(owner_write_fixture *f)
{
    CHECK(ow_scalar(f->db, "SELECT COUNT(*) FROM client_owner_transfer_audit") == 0, "failed transfer persisted audit");
    CHECK(ow_scalar(f->db, "SELECT COUNT(*) FROM client_account WHERE owner_username='Bob' OR updated_at<>'client-before' OR enabled<>CASE id WHEN 1001 THEN 1 ELSE 0 END") == 0, "partial client write");
    CHECK(ow_scalar(f->db, "SELECT COUNT(*) FROM specus_client_credential WHERE owner_username<>'alice' OR updated_at<>'credential-before' OR api_key<>'secret-key-501' OR secret_hash<>'secret-hash' OR max_online_instances<>17 OR enabled<>0") == 0, "partial credential write");
    CHECK(ow_scalar(f->db, "SELECT COUNT(*) FROM peer_mesh_device WHERE owner_username='Bob' OR updated_at<>'peer-before'") == 0, "partial Peer write");
    return 0;
}
static int ow_success(const char *snapshot, int group, long long id, size_t count, int has_credential)
{
    owner_write_fixture f; CHECK(ow_fresh(&f, snapshot) == 0, "fixture");
    char *request = NULL; CHECK(ow_request(&f, group, id, "  bOB  ", &request) == 0, "request");
    st_storage_owner_transfer_result result = {0}; const char *code = "old";
    int status = ow_transfer(&f, group, id, request, &result, &code); free(request);
    CHECK(status == 200 && code == NULL && result.changed && result.audit_id > 0 && result.client_count == count
        && strcmp(result.target_username, "Bob") == 0 && strcmp(result.tenant_id, "default") == 0, "%s real write status%d/%s", snapshot, status, code == NULL ? "" : code);
    CHECK(st_json_is_valid_object(result.json) && strstr(result.json, "\"accessRetained\":true") != NULL
        && strstr(result.json, "\"changed\":true") != NULL, "committed response");
    if (count) CHECK(result.client_ids[0] == 1001 && result.client_ids[count - 1] == 1000 + (long long)count, "complete sorted ids");
    CHECK(ow_scalar(f.db, "SELECT COUNT(*) FROM client_account WHERE owner_username='Bob'") == (long long)count, "exact client scope");
    CHECK(ow_scalar(f.db, "SELECT COUNT(*) FROM client_account WHERE enabled<>CASE id WHEN 1001 THEN 1 ELSE 0 END OR connection_limit_per_minute<>60 OR created_at<>'client-created'") == 0, "client switches/limit/time retained");
    CHECK(ow_scalar(f.db, "SELECT COUNT(*) FROM specus_client_credential WHERE api_key<>'secret-key-501' OR secret_hash<>'secret-hash' OR max_online_instances<>17 OR enabled<>0 OR created_at<>'credential-created'") == 0, "credential access retained");
    CHECK(ow_scalar(f.db, "SELECT COUNT(*) FROM specus_client_credential WHERE owner_username='Bob'") == has_credential, "credential scope");
    CHECK(ow_scalar(f.db, "SELECT COUNT(*) FROM specus_client_identity WHERE machine_fingerprint<>'secret-fingerprint-'||id") == 0, "identity untouched");
    CHECK(ow_scalar(f.db, "SELECT COUNT(*) FROM peer_mesh_device WHERE public_key<>'secret-key'") == 0, "Peer keys retained");
    if (strcmp(snapshot, "foreign-peer") == 0)
        CHECK(ow_scalar(f.db, "SELECT COUNT(*) FROM peer_mesh_device WHERE id=802 AND owner_username='secret-other-owner' AND updated_at='peer-before'") == 1, "foreign Peer modified");
    sqlite3_stmt *stmt = NULL;
    CHECK(sqlite3_prepare_v2(f.db, "SELECT payload_json FROM client_owner_transfer_audit", -1, &stmt, NULL) == SQLITE_OK
        && sqlite3_step(stmt) == SQLITE_ROW, "one durable audit");
    const char *audit = (const char *)sqlite3_column_text(stmt, 0);
    CHECK(audit != NULL && st_json_is_valid_object(audit) && strstr(audit, "\"before\":") != NULL
        && strstr(audit, "\"result\":") != NULL && strstr(audit, "\"peerOwnersBefore\":") != NULL
        && strstr(audit, "secret-key") == NULL && strstr(audit, "secret-hash") == NULL
        && strstr(audit, "secret-fingerprint") == NULL && strstr(audit, "private-") == NULL, "audit content/privacy");
    CHECK(sqlite3_step(stmt) == SQLITE_DONE, "duplicate audit"); sqlite3_finalize(stmt);
    st_storage_owner_transfer_result_free(&result);
    /* A fresh preview of an already-owned group is a no-op, including timestamps/audit. */
    CHECK(ow_sql(f.db, "UPDATE client_account SET updated_at='no-op'; UPDATE specus_client_credential SET updated_at='no-op'; UPDATE peer_mesh_device SET updated_at='no-op';"
        "CREATE TRIGGER no_update BEFORE UPDATE ON client_account BEGIN SELECT RAISE(ABORT,'no-op must not write'); END;"
        "CREATE TRIGGER no_audit BEFORE INSERT ON client_owner_transfer_audit BEGIN SELECT RAISE(ABORT,'no-op must not audit'); END;") == 0, "no-op stamps/guards");
    CHECK(ow_request(&f, group, id, "Bob", &request) == 0, "fresh no-op revision");
    CHECK(ow_transfer(&f, group, id, request, &result, &code) == 200 && !result.changed && result.audit_id == 0
        && result.closed_count == 0 && result.client_count == count && strstr(result.json, "\"changed\":false") != NULL, "no-op response");
    CHECK(ow_scalar(f.db, "SELECT COUNT(*) FROM client_owner_transfer_audit") == 1
        && ow_scalar(f.db, "SELECT COUNT(*) FROM client_account WHERE updated_at<>'no-op'") == 0
        && ow_scalar(f.db, "SELECT COUNT(*) FROM specus_client_credential WHERE updated_at<>'no-op'") == 0
        && ow_scalar(f.db, "SELECT COUNT(*) FROM peer_mesh_device WHERE updated_at<>'no-op'") == 0, "no-op performed DML");
    free(request); st_storage_owner_transfer_result_free(&result); ow_finish(&f); return 0;
}
static int ow_fault(const char *label, const char *trigger, int null_output)
{
    owner_write_fixture f; CHECK(ow_fresh(&f, "foreign-peer") == 0, "fixture");
    CHECK(ow_sql(f.db, "INSERT INTO specus_client_session(id,tenant_id,credential_id,identity_id,client_id,client_name,token_hash,status,machine_fingerprint,os_user,expires_at) VALUES(901,'default',501,701,1001,'laptop','access-token-stays','ACTIVE','secret-fingerprint-701','user','2099-01-01');") == 0, "access fixture");
    char *request = NULL; CHECK(ow_request(&f, 1, 501, "Bob", &request) == 0, "request");
    CHECK(ow_sql(f.db, trigger) == 0, "trigger %s", label);
    st_storage_owner_transfer_result result = {0}; const char *code = NULL;
    int status = ow_transfer(&f, 1, 501, request, null_output ? NULL : &result, &code); free(request);
    CHECK(status == 500 && code != NULL && strcmp(code, "INTERNAL_SERVER_ERROR") == 0
        && result.json == NULL && result.client_ids == NULL && result.closed == NULL && result.client_count == 0 && result.audit_id == 0, "fault %s returned%d/%s or published output", label, status, code == NULL ? "" : code);
    CHECK(ow_unchanged(&f) == 0, "rollback %s", label);
    CHECK(ow_scalar(f.db, "SELECT COUNT(*) FROM peer_mesh_device WHERE id=802 AND owner_username='secret-other-owner'") == 1
        && ow_scalar(f.db, "SELECT COUNT(*) FROM specus_client_identity") == 2
        && ow_scalar(f.db, "SELECT COUNT(*) FROM specus_management_user WHERE login_name='Bob' AND enabled=1") == 1
        && ow_scalar(f.db, "SELECT COUNT(*) FROM specus_management_user WHERE login_name='operator' AND role='ADMIN'") == 1, "rollback did not restore related state");
    CHECK(ow_scalar(f.db, "SELECT COUNT(*) FROM specus_client_session WHERE token_hash='access-token-stays' AND status='ACTIVE'") == 1, "access invalidated by failed write");
    ow_finish(&f); return 0;
}
static int ow_errors(void)
{
    owner_write_fixture f; CHECK(ow_fresh(&f, "shared") == 0, "fixture");
    st_storage_owner_transfer_result result = {0}; const char *code = NULL;
    CHECK(ow_transfer(&f, 0, 1001, "{\"scope\":\"single\"}", &result, &code) == 409
        && strcmp(code, "CREDENTIAL_SHARED") == 0 && ow_unchanged(&f) == 0, "single shared conflict priority");
    char *request = NULL; CHECK(ow_request(&f, 1, 501, "missing", &request) == 0, "request");
    CHECK(ow_transfer(&f, 1, 501, request, &result, &code) == 400 && strcmp(code, "INVALID_TARGET_OWNER") == 0, "missing target"); free(request);
    CHECK(ow_sql(f.db, "UPDATE specus_management_user SET enabled=0 WHERE login_name='Bob'") == 0, "disable target");
    CHECK(ow_request(&f, 1, 501, "Bob", &request) == 0, "request");
    CHECK(ow_transfer(&f, 1, 501, request, &result, &code) == 400 && strcmp(code, "INVALID_TARGET_OWNER") == 0, "disabled target");
    CHECK(ow_sql(f.db, "UPDATE specus_management_user SET enabled=1 WHERE login_name='Bob'; UPDATE client_account SET owner_username='elsewhere' WHERE id=1002") == 0, "stale preview");
    CHECK(ow_transfer(&f, 1, 501, request, &result, &code) == 409 && strcmp(code, "TRANSFER_PREVIEW_CHANGED") == 0, "revision before target"); free(request);
    CHECK(ow_request(&f, 1, 501, "Bob", &request) == 0, "request");
    CHECK(ow_sql(f.db, "UPDATE specus_management_user SET role='USER' WHERE login_name='operator'") == 0, "demote actor");
    CHECK(ow_transfer(&f, 1, 501, request, &result, &code) == 403 && strcmp(code, "FORBIDDEN") == 0, "fresh actor role");
    CHECK(ow_sql(f.db, "UPDATE specus_management_user SET role='ADMIN',username='replacement-account' WHERE login_name='operator'") == 0, "replace actor key");
    CHECK(ow_transfer(&f, 1, 501, request, &result, &code) == 403 && strcmp(code, "FORBIDDEN") == 0, "fresh actor key"); free(request);
    CHECK(result.json == NULL && result.client_ids == NULL && ow_scalar(f.db, "SELECT COUNT(*) FROM client_owner_transfer_audit") == 0, "error output/audit");
    ow_finish(&f); return 0;
}
static int ow_peer_sessions(void)
{
    owner_write_fixture f; CHECK(ow_fresh(&f, "unique") == 0, "fixture");
    CHECK(ow_sql(f.db,
        "INSERT INTO client_account(id,tenant_id,client_name,owner_username) VALUES(1100,'default','old-owner','alice'),(1101,'default','explicit','alice'),(1102,'default','new-owner','Bob');"
        "INSERT INTO peer_mesh_device(id,tenant_id,client_id,client_name,owner_username,public_key,enabled) VALUES(900,'default',1100,'old-owner','alice','old-key',1),(901,'default',1101,'explicit','alice','explicit-key',1),(902,'default',1102,'new-owner','Bob','new-key',1);"
        "INSERT INTO peer_mesh_acl(tenant_id,owner_username,source_client_id,source_client_name,target_client_id,target_client_name,allowed,direction) VALUES('default','alice',1001,'laptop',1101,'explicit',1,'OUTBOUND');"
        "INSERT INTO peer_mesh_session(id,tenant_id,source_client_id,source_client_name,target_client_id,target_client_name,status,token_hash,updated_at) VALUES"
        "(1,'default',1001,'laptop',1100,'old-owner','DIRECT','peer-secret-1','session-before'),"
        "(2,'default',1001,'laptop',1101,'explicit','RELAY','peer-secret-2','session-before'),"
        "(3,'default',1100,'old-owner',1001,'laptop','DIRECT','peer-secret-3','session-before'),"
        "(4,'default',1001,'laptop',1102,'new-owner','NEGOTIATING','peer-secret-4','session-before'),"
        "(5,'default',1001,'laptop',1100,'old-owner','CLOSED','peer-secret-5','session-before'),"
        "(6,'other',1001,'foreign-laptop',1100,'foreign-old','DIRECT','peer-secret-6','session-before'),"
        "(7,'default',1101,'explicit',1001,'laptop','DIRECT','peer-secret-7','session-before');"
        "INSERT INTO specus_client_session(id,tenant_id,credential_id,identity_id,client_id,client_name,token_hash,status,machine_fingerprint,os_user,expires_at) VALUES(901,'default',501,701,1001,'laptop','access-token-stays','ACTIVE','secret-fingerprint-701','user','2099-01-01');") == 0, "sessions/ACL fixture");
    char *request = NULL; CHECK(ow_request(&f, 0, 1001, "Bob", &request) == 0, "request");
    st_storage_owner_transfer_result result = {0}; const char *code = NULL;
    int status = ow_transfer(&f, 0, 1001, request, &result, &code); free(request);
    CHECK(status == 200 && result.closed_count == 3 && result.closed[0].id == 1 && result.closed[1].id == 3 && result.closed[2].id == 7, "selective closures status%d/%s count%zu", status, code == NULL ? "" : code, result.closed_count);
    CHECK(ow_scalar(f.db, "SELECT COUNT(*) FROM peer_mesh_session WHERE id IN(1,3,7) AND status='CLOSED' AND closed_at IS NOT NULL") == 3, "lost/reverse-only grants not closed");
    CHECK(ow_scalar(f.db, "SELECT COUNT(*) FROM peer_mesh_session WHERE id IN(2,4,5,6) AND updated_at='session-before'") == 4, "explicit/new owner/already closed/foreign session modified");
    CHECK(ow_scalar(f.db, "SELECT COUNT(*) FROM specus_client_session WHERE token_hash='access-token-stays' AND status='ACTIVE'") == 1, "client access revoked");
    CHECK(ow_scalar(f.db, "SELECT COUNT(*) FROM peer_mesh_acl WHERE owner_username='alice' AND allowed=1 AND direction='OUTBOUND'") == 1, "independent ACL changed");
    st_storage_owner_transfer_result_free(&result); ow_finish(&f); return 0;
}
static int ow_large(void)
{
    owner_write_fixture f; CHECK(ow_fresh(&f, "empty") == 0, "fixture");
    CHECK(ow_sql(f.db, "DELETE FROM peer_mesh_device; DELETE FROM client_account;"
        "WITH RECURSIVE n(i) AS(VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<1050) INSERT INTO client_account(id,tenant_id,client_name,owner_username,enabled) SELECT 1000+i,'default','quoted\"中文-'||i,'alice',i%2 FROM n;"
        "INSERT INTO specus_client_identity(id,tenant_id,credential_id,client_id,client_name,machine_fingerprint,os_user) SELECT 10000+id,'default',501,id,client_name,'private-fingerprint-'||id,'user' FROM client_account;") == 0, "large real group");
    char *request = NULL; CHECK(ow_request(&f, 1, 501, "Bob", &request) == 0, "request");
    st_storage_owner_transfer_result result = {0}; const char *code = NULL;
    int status = ow_transfer(&f, 1, 501, request, &result, &code); free(request);
    CHECK(status == 200 && result.changed && result.client_count == 1050 && result.client_ids[1049] == 2050
        && ow_scalar(f.db, "SELECT COUNT(*) FROM client_account WHERE owner_username='Bob'") == 1050, "large write truncated status%d/%s", status, code == NULL ? "" : code);
    CHECK(ow_scalar(f.db, "SELECT length(payload_json)>65536 FROM client_owner_transfer_audit") == 1, "audit truncated");
    st_storage_owner_transfer_result_free(&result); ow_finish(&f); return 0;
}
static int ow_builtin_and_scope(void)
{
    owner_write_fixture f; CHECK(ow_fresh(&f, "unique") == 0, "fixture");
    st_storage_management_user foreign = {0};
    CHECK(st_storage_create_management_user(f.path, "Bob", "other", "private-foreign", "USER", 1, &foreign) == 0, "foreign namesake");
    CHECK(ow_sql(f.db, "UPDATE specus_management_user SET enabled=0 WHERE tenant_id='default' AND login_name='Bob'") == 0, "local target disabled");
    char *request = NULL; CHECK(ow_request(&f, 0, 1001, "Bob", &request) == 0, "request");
    st_storage_owner_transfer_result result = {0}; const char *code = NULL;
    CHECK(ow_transfer(&f, 0, 1001, request, &result, &code) == 400 && strcmp(code, "INVALID_TARGET_OWNER") == 0 && ow_unchanged(&f) == 0, "foreign target fallback"); free(request);
    st_storage_management_actor actor = {f.admin.username, f.admin.tenant_id, f.admin.account_key};
    st_storage_share_builtin_admin builtin = {"Root", "default", 1};
    CHECK(ow_request(&f, 0, 1001, "ROOT", &request) == 0, "builtin request");
    CHECK(st_storage_transfer_owner(f.path, &actor, &builtin, 0, 1001, request, 1, &result, &code) == 200
        && strcmp(result.target_username, "Root") == 0, "canonical builtin target");
    st_storage_owner_transfer_result_free(&result);
    CHECK(st_storage_transfer_owner(f.path, &actor, &builtin, 0, 1001, request, 2, &result, &code) == 409
        && strcmp(code, "TRANSFER_PREVIEW_CHANGED") == 0 && result.json == NULL, "stale successful request replay"); free(request);
    CHECK(ow_sql(f.db, "UPDATE specus_management_user SET enabled=1 WHERE tenant_id='default' AND login_name='Bob'") == 0, "enable target");
    st_storage_management_actor root = {"Root", "default", ""};
    CHECK(ow_request(&f, 0, 1001, "Bob", &request) == 0, "builtin actor request");
    builtin.accepted = 0;
    CHECK(st_storage_transfer_owner(f.path, &root, &builtin, 0, 1001, request, 3, NULL, &code) == 403, "rejected builtin actor");
    builtin.accepted = 1;
    CHECK(st_storage_transfer_owner(f.path, &root, &builtin, 0, 1001, request, 4, NULL, &code) == 200
        && ow_scalar(f.db, "SELECT COUNT(*) FROM client_owner_transfer_audit") == 2
        && ow_scalar(f.db, "SELECT COUNT(*) FROM client_account WHERE id=1001 AND owner_username='Bob'") == 1, "builtin actor/null-output committed write"); free(request);
    ow_finish(&f); return 0;
}
static int ow_structural_errors(void)
{
    const char *snapshots_to_check[] = {"orphan", "foreign-client", "foreign-identity", "multiple-credentials"};
    for (size_t i = 0; i < sizeof(snapshots_to_check)/sizeof(snapshots_to_check[0]); ++i) {
        owner_write_fixture f; CHECK(ow_fresh(&f, snapshots_to_check[i]) == 0, "fixture");
        st_storage_owner_transfer_result result = {0}; const char *code = NULL;
        CHECK(ow_transfer(&f, 1, 501, "{\"scope\":\"credential-group\",\"targetUsername\":\"missing\",\"expectedRevision\":\"stale\"}", &result, &code) == 409
            && strcmp(code, "INCONSISTENT_CREDENTIAL_GROUP") == 0 && result.json == NULL
            && ow_scalar(f.db, "SELECT COUNT(*) FROM client_owner_transfer_audit") == 0
            && ow_scalar(f.db, "SELECT COUNT(*) FROM client_account WHERE owner_username='Bob'") == 0, "structural error priority %s", snapshots_to_check[i]);
        ow_finish(&f);
    }
    return 0;
}
static int ownership_writer_tests(void)
{
    CHECK(ow_success("legacy", 0, 1001, 1, 0) == 0, "legacy");
    CHECK(ow_success("unique", 0, 1001, 1, 1) == 0, "exclusive");
    CHECK(ow_success("shared", 1, 501, 2, 1) == 0, "group");
    CHECK(ow_success("empty", 1, 501, 0, 1) == 0, "empty group");
    CHECK(ow_success("duplicate-identities", 0, 1001, 1, 1) == 0, "duplicate edges deduplicate");
    CHECK(ow_success("foreign-peer", 1, 501, 2, 1) == 0, "foreign Peer");
    CHECK(ow_errors() == 0 && ow_peer_sessions() == 0 && ow_large() == 0
        && ow_builtin_and_scope() == 0 && ow_structural_errors() == 0, "writer behavior");
    const struct { const char *label, *sql; } faults[] = {
        {"late owner write", "CREATE TRIGGER owner_fault BEFORE UPDATE ON peer_mesh_device WHEN NEW.id=801 BEGIN SELECT RAISE(ABORT,'injected late owner failure'); END"},
        {"audit insert", "CREATE TRIGGER owner_fault BEFORE INSERT ON client_owner_transfer_audit BEGIN SELECT RAISE(ABORT,'injected audit failure'); END"},
        {"audit deletion", "CREATE TRIGGER owner_fault AFTER INSERT ON client_owner_transfer_audit BEGIN DELETE FROM client_owner_transfer_audit WHERE id=NEW.id; END"},
        {"audit tampering", "CREATE TRIGGER owner_fault AFTER INSERT ON client_owner_transfer_audit BEGIN UPDATE client_owner_transfer_audit SET payload_json='{}' WHERE id=NEW.id; END"},
        {"duplicate audit", "CREATE TRIGGER owner_fault AFTER INSERT ON client_owner_transfer_audit BEGIN INSERT INTO client_owner_transfer_audit(tenant_id,actor_username,scope,resource_id,target_username,payload_json,occurred_at_ms) VALUES('default','operator','single',1,'Bob','{}',1); END"},
        {"key mutation", "CREATE TRIGGER owner_fault AFTER UPDATE ON specus_client_credential BEGIN UPDATE specus_client_credential SET secret_hash='rotated' WHERE id=NEW.id; END"},
        {"client disable", "CREATE TRIGGER owner_fault AFTER UPDATE ON client_account BEGIN UPDATE client_account SET enabled=0 WHERE id=NEW.id; END"},
        {"identity mutation", "CREATE TRIGGER owner_fault AFTER INSERT ON client_owner_transfer_audit BEGIN DELETE FROM specus_client_identity WHERE id=701; END"},
        {"access revocation", "CREATE TRIGGER owner_fault AFTER INSERT ON client_owner_transfer_audit BEGIN UPDATE specus_client_session SET status='REVOKED'; END"},
        {"foreign owner mutation", "CREATE TRIGGER owner_fault AFTER INSERT ON client_owner_transfer_audit BEGIN UPDATE peer_mesh_device SET owner_username='intruder' WHERE id=802; END"},
        {"late target disabled", "CREATE TRIGGER owner_fault AFTER INSERT ON client_owner_transfer_audit BEGIN UPDATE specus_management_user SET enabled=0 WHERE login_name='Bob'; END"},
        {"late target replaced", "CREATE TRIGGER owner_fault AFTER INSERT ON client_owner_transfer_audit BEGIN UPDATE specus_management_user SET username='replacement' WHERE login_name='Bob'; END"},
        {"late actor demoted", "CREATE TRIGGER owner_fault AFTER INSERT ON client_owner_transfer_audit BEGIN UPDATE specus_management_user SET role='USER' WHERE login_name='operator'; END"}
    };
    for (size_t i = 0; i < sizeof(faults)/sizeof(faults[0]); ++i)
        CHECK(ow_fault(faults[i].label, faults[i].sql, 0) == 0 && ow_fault(faults[i].label, faults[i].sql, 1) == 0, "fault %s", faults[i].label);
    puts("40 real ownership writer scenarios passed (6 success/no-op, error order/current actors, selective sessions, 1050-member group, builtin/tenant scope, 4 corrupt groups, 26 fault/output variants)");
    return 0;
}
#endif
