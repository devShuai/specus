/*
 * The management endpoints the C inventory (docs/cross-language/alignment/c-server-api-inventory.md)
 * listed as not yet compared with Java, each against the Java controller and service it mirrors:
 * self-registration (AuthController, RegistrationService), /api/admin/me (currentUser), client
 * credentials (ClientCredentialService), the TCP mapping list, update and delete (NatControlService),
 * client name availability (ClientAccountService), database/initialize (DatabaseInitializer) and the
 * two traffic usage lists (TrafficViewService); and the Peer service import's target de-duplication
 * (PeerServiceDiscoveryService.importCandidates). Every request goes over real HTTP to an
 * in-process admin listener with real management tokens.
 *
 *   management_crud_tests
 */
#define _POSIX_C_SOURCE 200809L

#include "admin_http.h"
#include "crypto.h"
#include "json.h"
#include "registration.h"
#include "security.h"
#include "server_harness.h"
#include "storage.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/in.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define JWT_SECRET "management-crud-jwt-secret-long-enough-2026"
#define BUILT_IN "crud-root"
#define TENANT "t-crud"
#define OTHER_TENANT "t-crud-other"

static char db_path[320];
static int port = 0;
static char root_token[1024];  /* the built-in administrator, default tenant */
static char admin_token[1024]; /* crud-admin, ADMIN of t-crud */
static char user_token[1024];  /* crud-user, USER of t-crud */
static char other_token[1024]; /* other-admin, ADMIN of t-crud-other */

/* The last answer, kept for the failure message. */
static int last_status = 0;
static char *last_body = NULL;

static int call(const char *method, const char *path, const char *body, const char *token)
{
    free(last_body);
    last_body = NULL;
    last_status = 0;
    if (http_request(port, method, path, body, token, &last_status, &last_body) != 0) {
        last_status = -1;
    }
    return last_status;
}

/* method path answers status, and the body holds needle (NULL: anything). */
static int expect(const char *method, const char *path, const char *body, const char *token, int status,
                  const char *needle)
{
    int answered = call(method, path, body, token);
    if (answered == status && (needle == NULL || (last_body != NULL && strstr(last_body, needle) != NULL))) {
        return 0;
    }
    fprintf(stderr, "FAIL %s %s %s: expected %d%s%s, got %d %s\n", method, path, body == NULL ? "" : body, status,
            needle == NULL ? "" : " with ", needle == NULL ? "" : needle, answered,
            last_body == NULL ? "" : last_body);
    return -1;
}

static int exec_sql(const char *sql)
{
    sqlite3 *db = NULL;
    char *error = NULL;
    int rc = sqlite3_open(db_path, &db) == SQLITE_OK && sqlite3_busy_timeout(db, 5000) == SQLITE_OK
        && sqlite3_exec(db, sql, NULL, NULL, &error) == SQLITE_OK ? 0 : -1;
    if (rc != 0) fprintf(stderr, "sql failed: %s: %s\n", sql, error == NULL ? "sqlite error" : error);
    sqlite3_free(error);
    sqlite3_close(db);
    return rc;
}

/* The JSON string member key of the last answer, as text (empty when absent). */
static void last_member(const char *key, char *out, size_t out_len)
{
    char *value = last_body == NULL ? NULL : st_json_get_string(last_body, key);
    snprintf(out, out_len, "%s", value == NULL ? "" : value);
    free(value);
}

/* Java Instant.toString of a whole second: "YYYY-MM-DDTHH:MM:SSZ". */
static int is_instant(const char *text)
{
    static const char pattern[] = "dddd-dd-ddTdd:dd:ddZ";
    if (strlen(text) != sizeof(pattern) - 1U) return 0;
    for (size_t i = 0; i < sizeof(pattern) - 1U; ++i) {
        if (pattern[i] == 'd' ? !isdigit((unsigned char)text[i]) : text[i] != pattern[i]) return 0;
    }
    return 1;
}

static int repeat_into(char *out, size_t out_len, const char *unit, size_t times)
{
    size_t unit_len = strlen(unit);
    if (unit_len * times + 1U > out_len) return -1;
    for (size_t i = 0; i < times; ++i) memcpy(out + i * unit_len, unit, unit_len);
    out[unit_len * times] = '\0';
    return 0;
}

/* ---- self-registration -------------------------------------------------------------------- */

typedef struct {
    char code[7];
    char username[400];
} mailbox;

static int fake_turnstile(void *ctx, const char *token, const char *action)
{
    (void)ctx;
    if (token == NULL || strcmp(action, "register") != 0) return -1;
    if (strcmp(token, "down") == 0) return -2;
    return strcmp(token, "ok") == 0 ? 0 : -1;
}

static int fake_email(void *ctx, const char *email, const char *username, const char *code, long long ttl)
{
    (void)email;
    (void)ttl;
    mailbox *box = ctx;
    snprintf(box->code, sizeof(box->code), "%s", code);
    snprintf(box->username, sizeof(box->username), "%s", username);
    return 0;
}

static int register_with(const char *username, const char *email, const char *password, const char *token,
                         int status, const char *needle)
{
    char body[2048];
    snprintf(body, sizeof(body),
             "{\"username\":\"%s\",\"email\":\"%s\",\"password\":\"%s\",\"turnstileToken\":\"%s\"}",
             username, email, password, token);
    return expect("POST", "/auth/register", body, NULL, status, needle);
}

/*
 * AuthController.register runs the Turnstile check before RegistrationService.requestRegistration,
 * whose checks come in this order: username, reserved name, password, email, existing login name,
 * existing email. Lengths are Java's, in UTF-16 code units.
 */
static int test_registration(void)
{
    mailbox box;
    memset(&box, 0, sizeof(box));
    st_registration_set_handlers(fake_turnstile, fake_email, &box);
    char long_name[400];
    char wide_name[400];
    char long_password[200];
    int failed = repeat_into(long_name, sizeof(long_name), "u", 81U) != 0
        || repeat_into(wide_name, sizeof(wide_name), "\xc3\xa9", 80U) != 0
        || repeat_into(long_password, sizeof(long_password), "p", 121U) != 0;
    /* The challenge comes first: a blank username with a failing token is a Turnstile refusal. */
    failed = failed || register_with(" ", "a@example.com", "pw", "bad", 400, "\"error\":\"人机验证失败，请重试\"") != 0
        || register_with(" ", "a@example.com", "pw", "down", 503, "\"error\":\"人机验证服务暂不可用\"") != 0
        || register_with(" ", "a@example.com", "pw", "ok", 400, "\"error\":\"username cannot be blank\"") != 0
        || register_with(long_name, "a@example.com", "pw", "ok", 400, "\"error\":\"username is too long\"") != 0
        || register_with(" Crud-Root ", "a@example.com", "pw", "ok", 400, "\"error\":\"该用户名不可用\"") != 0
        || register_with("fresh", "a@example.com", " ", "ok", 400, "\"error\":\"password cannot be blank\"") != 0
        || register_with("fresh", "a@example.com", long_password, "ok", 400,
                         "\"error\":\"password is too long\"") != 0
        || register_with("fresh", " ", "pw", "ok", 400, "\"error\":\"邮箱不能为空\"") != 0;
    static const char *const bad_emails[] = {
        "a@b@example.com", "a@.example.com", "a@example.", "a..b@example.com", ".a@example.com",
        "a@exam ple.com", "a<b>@example.com", "a@example", "@example.com"
    };
    for (size_t i = 0; !failed && i < sizeof(bad_emails) / sizeof(bad_emails[0]); ++i) {
        failed = register_with("fresh", bad_emails[i], "pw", "ok", 400, "\"error\":\"邮箱格式无效\"") != 0;
    }
    /*
     * 80 two-byte characters are within Java's 80 UTF-16 code units, but C stores a login name in
     * 80 bytes (as POST /api/admin/users does): refused here, not after the email went out. 40 of
     * them, 80 bytes, pass.
     */
    failed = failed || register_with(wide_name, "wide@example.com", "pw", "ok", 400, "\"error\":\"username is too long\"") != 0;
    wide_name[80] = '\0';
    failed = failed || register_with(wide_name, "Wide@Example.com", "pw", "ok", 202, "\"emailMasked\":\"wi***@example.com\"") != 0;
    /* An existing login name of the default tenant is named in the refusal. */
    st_storage_management_user user;
    failed = failed || st_storage_create_management_user(db_path, "Taken", "default", "unused-hash", "USER", 1,
                                                         &user) != 0
        || register_with("taken", "taken@example.com", "pw", "ok", 400, "\"error\":\"用户名已存在: taken\"") != 0;
    printf("%s registration request checks in Java's order\n", failed ? "FAIL" : "ok  ");
    if (failed) return 1;

    /* verify: the id as sent is at most 64 characters; the login name is checked before the email. */
    char registration_id[128] = "";
    failed = register_with("late-user", "late@example.com", "pw", "ok", 202, "\"registrationId\"") != 0;
    last_member("registrationId", registration_id, sizeof(registration_id));
    char body[512];
    char padded[256];
    snprintf(padded, sizeof(padded), "%40s%s", "", registration_id);
    snprintf(body, sizeof(body), "{\"registrationId\":\"%s\",\"code\":\"%s\"}", padded, box.code);
    failed = failed || strlen(registration_id) != 32U
        || expect("POST", "/auth/register/verify", body, NULL, 400, "\"error\":\"验证码无效或已过期\"") != 0;
    failed = failed || st_storage_create_management_user(db_path, "Late-User", "default", "unused-hash", "USER", 1,
                                                         &user) != 0
        || exec_sql("INSERT INTO specus_management_user_email(username, email, verified_at, created_at, updated_at) "
                    "VALUES('someone-else', 'late@example.com', '2026-01-01T00:00:00Z', "
                    "'2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')") != 0;
    snprintf(body, sizeof(body), "{\"registrationId\":\"  %s \",\"code\":\" %s \"}", registration_id, box.code);
    failed = failed || expect("POST", "/auth/register/verify", body, NULL, 400,
                              "\"error\":\"用户名已存在: late-user\"") != 0;
    printf("%s registration verify checks in Java's order\n", failed ? "FAIL" : "ok  ");
    st_registration_set_handlers(NULL, NULL, NULL);
    return failed;
}

/* ---- /api/admin/me ------------------------------------------------------------------------ */

static int test_me(void)
{
    char created[64];
    int failed = expect("GET", "/api/admin/me", NULL, root_token, 200, "\"username\":\"" BUILT_IN "\"") != 0
        || strstr(last_body, "\"builtIn\":true") == NULL || strstr(last_body, "\"role\":\"ADMIN\"") == NULL;
    if (!failed) {
        last_member("createdAt", created, sizeof(created));
        failed = !is_instant(created);
    }
    st_storage_management_user user;
    failed = failed || st_storage_get_management_user_in_tenant(db_path, TENANT, "crud-user", &user) != 0
        || expect("GET", "/api/admin/me", NULL, user_token, 200, "\"username\":\"crud-user\"") != 0
        || strstr(last_body, "\"builtIn\":false") == NULL || strstr(last_body, "\"admin\":false") == NULL;
    if (!failed) {
        char expected[160];
        snprintf(expected, sizeof(expected), "\"createdAt\":\"%s\"", user.created_at);
        failed = user.created_at[0] == '\0' || strstr(last_body, expected) == NULL;
    }
    if (failed) fprintf(stderr, "me: %s\n", last_body == NULL ? "" : last_body);
    printf("%s /api/admin/me as Java currentUser\n", failed ? "FAIL" : "ok  ");
    return failed;
}

/* ---- client credentials ------------------------------------------------------------------- */

static int test_credentials(void)
{
    char api_key[160];
    char secret[160];
    char created[64];
    int failed = expect("POST", "/api/admin/client-credentials", NULL, admin_token, 400, "\"error\":\"Bad Request\"") != 0
        || expect("POST", "/api/admin/client-credentials", "[1]", admin_token, 400, "\"error\":\"Bad Request\"") != 0
        || expect("POST", "/api/admin/client-credentials", "{}", admin_token, 201, "\"ownerUsername\":\"crud-admin\"") != 0;
    long long generated_id = 0;
    if (!failed) {
        /* "ck_" + a version 4 UUID's hex digits; 18 characters of PasswordService's alphabet. */
        const char *credential = strstr(last_body, "\"credential\":");
        char *view = credential == NULL ? NULL : st_json_get_top_level_raw(last_body, "credential");
        last_member("secret", secret, sizeof(secret));
        api_key[0] = '\0';
        created[0] = '\0';
        if (view != NULL) {
            char *key = st_json_get_string(view, "apiKey");
            char *at = st_json_get_string(view, "createdAt");
            snprintf(api_key, sizeof(api_key), "%s", key == NULL ? "" : key);
            snprintf(created, sizeof(created), "%s", at == NULL ? "" : at);
            (void)st_json_get_i64(view, "id", &generated_id);
            free(key);
            free(at);
        }
        free(view);
        failed = strlen(api_key) != 35U || strncmp(api_key, "ck_", 3U) != 0 || api_key[3 + 12] != '4'
            || strspn(api_key + 3, "0123456789abcdef") != 32U
            || strlen(secret) != 18U
            || strspn(secret, "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789") != 18U
            || !is_instant(created) || generated_id <= 0;
        if (failed) fprintf(stderr, "generated credential: %s\n", last_body);
    }
    char wide_key[400];
    char long_key[200];
    char body[1024];
    failed = failed || repeat_into(wide_key, sizeof(wide_key), "\xc3\xa9", 120U) != 0
        || repeat_into(long_key, sizeof(long_key), "k", 121U) != 0;
    snprintf(body, sizeof(body), "{\"apiKey\":\"%s\"}", long_key);
    failed = failed
        || expect("POST", "/api/admin/client-credentials", "{\"apiKey\":\"  ab  \"}", admin_token, 400,
                  "\"error\":\"apiKey length must be between 3 and 120\"") != 0
        || expect("POST", "/api/admin/client-credentials", body, admin_token, 400,
                  "\"error\":\"apiKey length must be between 3 and 120\"") != 0;
    snprintf(body, sizeof(body), "{\"apiKey\":\"%s\",\"secret\":\" s3cret \",\"maxOnlineInstances\":10000}", wide_key);
    failed = failed
        || expect("POST", "/api/admin/client-credentials", body, admin_token, 201, "\"secret\":\"s3cret\"") != 0
        || strstr(last_body, "\"maxOnlineInstances\":10000") == NULL;
    snprintf(body, sizeof(body), "{\"apiKey\":\" %s \"}", api_key);
    failed = failed
        || expect("POST", "/api/admin/client-credentials", body, admin_token, 400,
                  "\"error\":\"apiKey already exists\"") != 0
        || expect("POST", "/api/admin/client-credentials", "{\"apiKey\":\"ck-max-0\",\"maxOnlineInstances\":0}",
                  admin_token, 400, "\"error\":\"maxOnlineInstances must be between 1 and 10000\"") != 0
        || expect("POST", "/api/admin/client-credentials", "{\"apiKey\":\"ck-max-big\",\"maxOnlineInstances\":10001}",
                  admin_token, 400, "\"error\":\"maxOnlineInstances must be between 1 and 10000\"") != 0
        || expect("POST", "/api/admin/client-credentials", "{\"apiKey\":\"ck-max-text\",\"maxOnlineInstances\":\"x\"}",
                  admin_token, 400, "\"error\":\"Bad Request\"") != 0;
    /* A create that loses the race for an api key does not replace the winner's credential. */
    st_storage_client_credential raced;
    failed = failed
        || st_storage_insert_client_credential(db_path, OTHER_TENANT, "other-admin", api_key,
                                               "0000000000000000000000000000000000000000000000000000000000000000",
                                               1, 2, &raced) != 1
        || st_storage_get_client_credential_by_api_key(db_path, api_key, &raced) != 0
        || strcmp(raced.tenant_id, TENANT) != 0;
    printf("%s credential create as Java\n", failed ? "FAIL" : "ok  ");
    if (failed) return 1;

    /* update: only what the request carries; the secret is null unless it changed. */
    char path[160];
    snprintf(path, sizeof(path), "/api/admin/client-credentials/%lld", generated_id);
    char missing[160];
    snprintf(missing, sizeof(missing), "\"error\":\"credential not found: %lld\"", generated_id);
    failed = expect("PUT", path, "{\"enabled\":false}", admin_token, 200, "\"secret\":null") != 0
        || strstr(last_body, "\"enabled\":false") == NULL
        || expect("PUT", path, "{\"maxOnlineInstances\":0}", admin_token, 400,
                  "\"error\":\"maxOnlineInstances must be between 1 and 10000\"") != 0
        || expect("PUT", path, "{\"secret\":\"  next-secret \",\"maxOnlineInstances\":7}", admin_token, 200,
                  "\"secret\":\"next-secret\"") != 0
        || strstr(last_body, "\"maxOnlineInstances\":7") == NULL || strstr(last_body, "\"enabled\":false") == NULL
        || expect("PUT", path, "{\"apiKey\":\"ab\"}", admin_token, 400,
                  "\"error\":\"apiKey length must be between 3 and 120\"") != 0
        || expect("PUT", path, NULL, admin_token, 400, "\"error\":\"Bad Request\"") != 0
        /* The tenant's USER and another tenant's administrator do not see it: Java's 400. */
        || expect("PUT", path, "{\"enabled\":true}", user_token, 400, missing) != 0
        || expect("DELETE", path, NULL, other_token, 400, missing) != 0
        || expect("PUT", "/api/admin/client-credentials/987654321", "{}", admin_token, 400,
                  "\"error\":\"credential not found: 987654321\"") != 0;
    char stored[80];
    uint8_t digest[ST_SHA256_LEN];
    char expected_hash[ST_SHA256_HEX_LEN + 1];
    st_sha256((const uint8_t *)"next-secret", strlen("next-secret"), digest);
    st_hex_encode(digest, sizeof(digest), expected_hash);
    failed = failed || db_scalar(db_path, "SELECT secret_hash FROM specus_client_credential WHERE id = ?", NULL,
                                 generated_id, stored, sizeof(stored)) != 0
        || strcmp(stored, expected_hash) != 0;
    /* The USER's own credential is the only one it lists. */
    failed = failed
        || expect("POST", "/api/admin/client-credentials", "{\"apiKey\":\"ck-user-own\"}", user_token, 201, NULL) != 0
        || expect("GET", "/api/admin/client-credentials", NULL, user_token, 200, "\"apiKey\":\"ck-user-own\"") != 0
        || strstr(last_body, api_key) != NULL
        || expect("DELETE", path, NULL, admin_token, 204, NULL) != 0
        || expect("DELETE", path, NULL, admin_token, 400, missing) != 0;
    printf("%s credential update, delete and visibility as Java\n", failed ? "FAIL" : "ok  ");
    return failed;
}

/* ---- TCP mappings ------------------------------------------------------------------------- */

static long long client_a = 0; /* t-crud, owned by crud-admin */
static long long client_b = 0; /* t-crud, owned by crud-user */
static long long client_c = 0; /* t-crud-other */
static st_storage_mapping mapping_a;

static int test_mappings(void)
{
    st_storage_mapping mapping_b;
    st_storage_mapping mapping_c;
    int failed = st_storage_create_mapping_for_client(db_path, client_a, 21001, "127.0.0.1", 8001, 0, 1, &mapping_a) != 0
        || st_storage_create_mapping_for_client(db_path, client_b, 21002, "127.0.0.1", 8002, 1, 0, &mapping_b) != 0
        || st_storage_create_mapping_for_client(db_path, client_c, 21003, "127.0.0.1", 8003, 1, 0, &mapping_c) != 0;
    char path[200];
    /* The list: clientId 0, negative or not visible is empty; one that is no number is 400. */
    failed = failed
        || expect("GET", "/api/admin/specus-mappings?clientId=0", NULL, admin_token, 200, NULL) != 0
        || strcmp(last_body, "[]") != 0
        || expect("GET", "/api/admin/specus-mappings?clientId=-3", NULL, admin_token, 200, NULL) != 0
        || strcmp(last_body, "[]") != 0
        || expect("GET", "/api/admin/specus-mappings?clientId=abc", NULL, admin_token, 400, "\"error\":\"Bad Request\"") != 0
        || expect("GET", "/api/admin/specus-mappings?clientId=", NULL, admin_token, 200, "\"listenPort\":21002") != 0
        || strstr(last_body, "\"listenPort\":21001") == NULL || strstr(last_body, "\"listenPort\":21003") != NULL;
    snprintf(path, sizeof(path), "/api/admin/specus-mappings?clientId=%%20%lld%%20", client_a);
    failed = failed || expect("GET", path, NULL, admin_token, 200, "\"listenPort\":21001") != 0
        || strstr(last_body, "\"listenPort\":21002") != NULL;
    snprintf(path, sizeof(path), "/api/admin/specus-mappings?clientId=0x%llx", client_a);
    failed = failed || expect("GET", path, NULL, admin_token, 200, "\"listenPort\":21001") != 0;
    snprintf(path, sizeof(path), "/api/admin/specus-mappings?clientId=%lld", client_c);
    failed = failed || expect("GET", path, NULL, admin_token, 200, NULL) != 0 || strcmp(last_body, "[]") != 0;
    snprintf(path, sizeof(path), "/api/admin/specus-mappings?clientId=%lld", client_a);
    failed = failed || expect("GET", path, NULL, user_token, 200, NULL) != 0 || strcmp(last_body, "[]") != 0
        || expect("GET", "/api/admin/specus-mappings", NULL, user_token, 200, "\"listenPort\":21002") != 0
        || strstr(last_body, "\"listenPort\":21001") != NULL;
    if (!failed) {
        char *first = st_json_get_string(last_body, "createdAt");
        failed = first == NULL || !is_instant(first);
        if (failed) fprintf(stderr, "mapping createdAt: %s\n", last_body);
        free(first);
    }
    printf("%s mapping list as Java\n", failed ? "FAIL" : "ok  ");
    if (failed) return 1;

    /* update: every field required, the public port is the server's, enabled defaults to true. */
    char missing[160];
    char long_address[300];
    char body[600];
    snprintf(path, sizeof(path), "/api/admin/specus-mappings/%lld", mapping_a.id);
    snprintf(missing, sizeof(missing), "\"error\":\"mapping not found: %lld\"", mapping_a.id);
    failed = repeat_into(long_address, sizeof(long_address), "a", 256U) != 0;
    snprintf(body, sizeof(body), "{\"listenPort\":21001,\"targetPort\":80,\"targetAddress\":\"%s\"}", long_address);
    failed = failed
        || expect("PUT", path, "{}", admin_token, 400, "\"error\":\"listenPort must be between 1 and 65535\"") != 0
        || expect("PUT", path, "{\"listenPort\":70000}", admin_token, 400,
                  "\"error\":\"listenPort must be between 1 and 65535\"") != 0
        || expect("PUT", path, "{\"listenPort\":21001}", admin_token, 400,
                  "\"error\":\"targetPort must be between 1 and 65535\"") != 0
        || expect("PUT", path, "{\"listenPort\":21001,\"targetPort\":80,\"targetAddress\":\" \"}", admin_token, 400,
                  "\"error\":\"targetAddress cannot be blank\"") != 0
        || expect("PUT", path, body, admin_token, 400, "\"error\":\"targetAddress is too long\"") != 0
        || expect("PUT", path, "{\"listenPort\":\"x\",\"targetPort\":80,\"targetAddress\":\"h\"}", admin_token, 400,
                  "\"error\":\"Bad Request\"") != 0
        /* Another client's port, in this tenant or another, is taken. */
        || expect("PUT", path, "{\"listenPort\":21002,\"targetPort\":80,\"targetAddress\":\"h\"}", admin_token, 400,
                  "\"error\":\"公网端口 21002 已被占用\"") != 0
        || expect("PUT", path, "{\"listenPort\":21003,\"targetPort\":80,\"targetAddress\":\"h\"}", admin_token, 400,
                  "\"error\":\"公网端口 21003 已被占用\"") != 0
        /* mapping_a was disabled; a request without "enabled" enables it, the detail capture stays. */
        || expect("PUT", path, "{\"listenPort\":21011,\"targetPort\":81,\"targetAddress\":\" 10.0.0.5 \"}",
                  admin_token, 200, "\"enabled\":true") != 0
        || strstr(last_body, "\"targetAddress\":\"10.0.0.5\"") == NULL
        || strstr(last_body, "\"detailCaptureEnabled\":true") == NULL
        || strstr(last_body, "\"listenPort\":21011") == NULL
        || expect("PUT", path, "{\"listenPort\":21011,\"targetPort\":81,\"targetAddress\":\"h\"}", user_token, 400,
                  missing) != 0
        || expect("PUT", path, NULL, admin_token, 400, "\"error\":\"Bad Request\"") != 0
        || expect("PUT", "/api/admin/specus-mappings/987654321", "{}", admin_token, 400,
                  "\"error\":\"mapping not found: 987654321\"") != 0
        || expect("DELETE", path, NULL, other_token, 400, missing) != 0
        || expect("DELETE", path, NULL, admin_token, 204, NULL) != 0
        || expect("DELETE", path, NULL, admin_token, 400, missing) != 0;
    printf("%s mapping update and delete as Java\n", failed ? "FAIL" : "ok  ");
    return failed;
}

/* ---- client name availability ------------------------------------------------------------- */

static int test_name_availability(void)
{
    char path[200];
    char missing[120];
    snprintf(path, sizeof(path), "/api/admin/clients/name-availability?clientName=crud-a&excludeClientId=%lld",
             client_c);
    snprintf(missing, sizeof(missing), "\"error\":\"client not found: %lld\"", client_c);
    int failed = expect("GET", "/api/admin/clients/name-availability", NULL, admin_token, 400,
                        "\"error\":\"Bad Request\"") != 0
        || expect("GET", "/api/admin/clients/name-availability?clientName=%20", NULL, admin_token, 400,
                  "\"error\":\"clientName cannot be blank\"") != 0
        || expect("GET", "/api/admin/clients/name-availability?clientName=x&excludeClientId=abc", NULL, admin_token,
                  400, "\"error\":\"Bad Request\"") != 0
        || expect("GET", "/api/admin/clients/name-availability?clientName=x&excludeClientId=0", NULL, admin_token,
                  400, "\"error\":\"client not found: 0\"") != 0
        || expect("GET", path, NULL, admin_token, 400, missing) != 0
        || expect("GET", "/api/admin/clients/name-availability?clientName=crud-a&excludeClientId=", NULL, admin_token,
                  200, "{\"clientName\":\"crud-a\",\"available\":false}") != 0;
    snprintf(path, sizeof(path), "/api/admin/clients/name-availability?clientName=crud-a&excludeClientId=%lld",
             client_a);
    failed = failed || expect("GET", path, NULL, admin_token, 200, "\"available\":true") != 0;
    printf("%s client name availability as Java\n", failed ? "FAIL" : "ok  ");
    return failed;
}

/* ---- traffic usage ------------------------------------------------------------------------ */

static int record_usage(long long client_id, const char *client_name, const char *date, long long bytes)
{
    char key[32];
    snprintf(key, sizeof(key), "tcp:%lld", 30000 + bytes);
    return st_storage_record_traffic_usage(db_path, client_id, client_name, date, bytes, bytes)
        | st_storage_record_resource_traffic_usage(db_path, client_id, client_name, "TCP_SPECUS", key, 0,
                                                   "tcp resource", date, bytes, bytes)
        | st_storage_record_resource_traffic_usage(db_path, client_id, client_name, "HTTP_ROUTE", "http:web", 0,
                                                   "web", date, bytes, bytes);
}

static int test_traffic_usage(void)
{
    st_storage_client gone;
    int failed = st_storage_upsert_client(db_path, 0, TENANT, "crud-gone", "crud-admin", 1, 30, &gone) != 0
        || record_usage(client_a, "crud-a", "2026-10-01", 101) != 0
        || record_usage(client_b, "crud-b", "2026-10-02", 202) != 0
        || record_usage(client_c, "crud-c", "2026-10-03", 303) != 0
        || record_usage(gone.id, "crud-gone", "2026-10-04", 404) != 0;
    /* Rows written before the tenant column existed take their client's tenant when it is added,
     * and keep it once the client is deleted. */
    failed = failed || exec_sql("ALTER TABLE traffic_usage DROP COLUMN tenant_id") != 0
        || st_storage_init(db_path, 0) != 0
        || st_storage_delete_client(db_path, gone.id) != 0;
    char path[200];
    failed = failed
        /* The administrator sees the tenant's rows, the deleted client's included. */
        || expect("GET", "/api/admin/traffic", NULL, admin_token, 200, "\"uploadBytes\":404") != 0
        || strstr(last_body, "\"uploadBytes\":101") == NULL || strstr(last_body, "\"uploadBytes\":202") == NULL
        || strstr(last_body, "\"uploadBytes\":303") != NULL
        || expect("GET", "/api/admin/traffic", NULL, other_token, 200, "\"uploadBytes\":303") != 0
        || strstr(last_body, "\"uploadBytes\":404") != NULL
        || expect("GET", "/api/admin/traffic", NULL, user_token, 200, "\"uploadBytes\":202") != 0
        || strstr(last_body, "\"uploadBytes\":101") != NULL || strstr(last_body, "\"uploadBytes\":404") != NULL
        || expect("GET", "/api/admin/traffic?limit=0", NULL, admin_token, 200, "\"uploadBytes\":404") != 0
        || strstr(last_body, "\"uploadBytes\":202") != NULL
        || expect("GET", "/api/admin/traffic?clientId=0", NULL, admin_token, 200, NULL) != 0
        || strcmp(last_body, "[]") != 0
        || expect("GET", "/api/admin/traffic?clientId=abc", NULL, admin_token, 400, "\"error\":\"Bad Request\"") != 0
        || expect("GET", "/api/admin/traffic?limit=1.5", NULL, admin_token, 400, "\"error\":\"Bad Request\"") != 0
        || expect("GET", "/api/admin/traffic/resources?limit=x", NULL, admin_token, 400,
                  "\"error\":\"Bad Request\"") != 0;
    /* A clientId the caller cannot see is empty: another tenant's, a deleted client's, another owner's. */
    long long hidden[] = {client_c, gone.id};
    for (size_t i = 0; !failed && i < sizeof(hidden) / sizeof(hidden[0]); ++i) {
        snprintf(path, sizeof(path), "/api/admin/traffic?clientId=%lld", hidden[i]);
        failed = expect("GET", path, NULL, admin_token, 200, NULL) != 0 || strcmp(last_body, "[]") != 0;
    }
    snprintf(path, sizeof(path), "/api/admin/traffic/resources?clientId=%lld", client_a);
    failed = failed || expect("GET", path, NULL, user_token, 200, NULL) != 0 || strcmp(last_body, "[]") != 0;
    /* The type is trimmed and upper-cased. */
    failed = failed
        || expect("GET", "/api/admin/traffic/resources?type=%20tcp_specus%20", NULL, admin_token, 200,
                  "\"resourceType\":\"TCP_SPECUS\"") != 0
        || strstr(last_body, "HTTP_ROUTE") != NULL || strstr(last_body, "\"clientName\":\"crud-gone\"") == NULL;
    if (!failed) {
        char *updated = st_json_get_string(last_body, "updatedAt");
        failed = updated == NULL || !is_instant(updated);
        if (failed) fprintf(stderr, "usage updatedAt: %s\n", last_body);
        free(updated);
    }
    printf("%s traffic usage lists as Java\n", failed ? "FAIL" : "ok  ");
    return failed;
}

/* ---- Peer service import ------------------------------------------------------------------ */

static int test_peer_import_targets(void)
{
    /* crud-b already publishes 127.0.0.1:8002; crud-b's target does not stop crud-a importing it. */
    st_storage_peer_mesh_service definition;
    st_storage_peer_mesh_service saved;
    memset(&definition, 0, sizeof(definition));
    snprintf(definition.tenant_id, sizeof(definition.tenant_id), TENANT);
    definition.client_id = client_b;
    snprintf(definition.client_name, sizeof(definition.client_name), "crud-b");
    snprintf(definition.service_id, sizeof(definition.service_id), "svc-crud-b");
    snprintf(definition.name, sizeof(definition.name), "b-web");
    snprintf(definition.transport, sizeof(definition.transport), "tcp");
    snprintf(definition.application, sizeof(definition.application), "tcp");
    snprintf(definition.target_host, sizeof(definition.target_host), "127.0.0.1");
    definition.target_port = 8002;
    definition.published_port = 8002;
    snprintf(definition.visibility, sizeof(definition.visibility), "OWNER");
    st_storage_mapping mapping;
    int failed = st_storage_upsert_peer_mesh_service(db_path, &definition, &saved) != 0
        || st_storage_create_mapping_for_client(db_path, client_a, 21021, "127.0.0.1", 8002, 1, 0, &mapping) != 0;
    char body[96];
    snprintf(body, sizeof(body), "{\"clientId\":%lld}", client_a);
    failed = failed
        || expect("POST", "/api/admin/peer-mesh/services/import", body, admin_token, 200, "\"created\":1") != 0
        || strstr(last_body, "\"skipped\":0") == NULL
        /* Imported once, the target is now crud-a's own and a second import skips it. */
        || expect("POST", "/api/admin/peer-mesh/services/import", body, admin_token, 200, "\"created\":0") != 0
        || strstr(last_body, "\"skipped\":1") == NULL;
    printf("%s peer service import skips only the client's own targets\n", failed ? "FAIL" : "ok  ");
    return failed;
}

/* ---- database/initialize ------------------------------------------------------------------ */

static int test_database_initialize(void)
{
    /* Seeding off: nothing is created, the answer counts the tenant's clients. */
    setenv("SPECUS_DB_SEED_DEMO_CLIENT", "false", 1);
    int failed = expect("POST", "/api/admin/database/initialize", NULL, user_token, 403,
                        "\"error\":\"需要 admin 权限\"") != 0
        || expect("POST", "/api/admin/database/initialize", NULL, admin_token, 200,
                  "{\"initialized\":true,\"tenantId\":\"" TENANT "\",\"orm\":\"sqlite3\",\"dialect\":\"sqlite\",") != 0;
    /* Seeding on: startup's seed goes to SPECUS_AUTH_TENANT_ID, owned by the built-in administrator;
     * another tenant's initialize then finds the name taken, as Java's unique client_name does. */
    setenv("SPECUS_DB_SEED_DEMO_CLIENT", "true", 1);
    st_storage_client demo;
    failed = failed
        || expect("POST", "/api/admin/database/initialize", NULL, root_token, 200, "\"tenantId\":\"default\"") != 0
        || st_storage_get_client_by_name(db_path, "Demo client", &demo) != 0
        || strcmp(demo.tenant_id, "default") != 0 || strcmp(demo.owner_username, BUILT_IN) != 0
        || expect("POST", "/api/admin/database/initialize", NULL, admin_token, 400,
                  "\"error\":\"客户端名称已存在或数据不符合约束\"") != 0;
    /* Without one anywhere, the caller's tenant gets it. */
    failed = failed || st_storage_delete_client(db_path, demo.id) != 0;
    setenv("SPECUS_AUTH_TENANT_ID", OTHER_TENANT, 1);
    failed = failed
        || st_storage_init(db_path, 1) != 0
        || st_storage_get_client_by_name(db_path, "Demo client", &demo) != 0
        || strcmp(demo.tenant_id, OTHER_TENANT) != 0;
    unsetenv("SPECUS_AUTH_TENANT_ID");
    failed = failed || st_storage_delete_client(db_path, demo.id) != 0;
    setenv("SPECUS_DB_SEED_DEMO_CLIENT", "false", 1);
    failed = failed || st_storage_seed_demo_client(db_path, TENANT, BUILT_IN) != 0
        || st_storage_get_client_by_name(db_path, "Demo client", &demo) != 0
        || strcmp(demo.tenant_id, TENANT) != 0
        || st_storage_seed_demo_client(db_path, TENANT, BUILT_IN) != 0
        || st_storage_seed_demo_client(db_path, OTHER_TENANT, BUILT_IN) != 1;
    printf("%s database/initialize seeds the caller's tenant as Java\n", failed ? "FAIL" : "ok  ");
    return failed;
}

static int seed(void)
{
    st_storage_management_user user;
    st_storage_client client;
    int failed = st_storage_create_management_user(db_path, "crud-admin", TENANT, "unused-hash", "ADMIN", 1, &user) != 0
        || st_storage_create_management_user(db_path, "crud-user", TENANT, "unused-hash", "USER", 1, &user) != 0
        || st_storage_create_management_user(db_path, "other-admin", OTHER_TENANT, "unused-hash", "ADMIN", 1,
                                             &user) != 0;
    failed = failed || st_storage_upsert_client(db_path, 0, TENANT, "crud-a", "crud-admin", 1, 30, &client) != 0;
    client_a = client.id;
    failed = failed || st_storage_upsert_client(db_path, 0, TENANT, "crud-b", "crud-user", 1, 30, &client) != 0;
    client_b = client.id;
    failed = failed || st_storage_upsert_client(db_path, 0, OTHER_TENANT, "crud-c", "other-admin", 1, 30,
                                                &client) != 0;
    client_c = client.id;
    return failed
        || st_security_issue_local_token(BUILT_IN, "default", "ADMIN", JWT_SECRET, 600, root_token,
                                         sizeof(root_token)) != 0
        || st_security_issue_local_token("crud-admin", TENANT, "ADMIN", JWT_SECRET, 600, admin_token,
                                         sizeof(admin_token)) != 0
        || st_security_issue_local_token("crud-user", TENANT, "USER", JWT_SECRET, 600, user_token,
                                         sizeof(user_token)) != 0
        || st_security_issue_local_token("other-admin", OTHER_TENANT, "ADMIN", JWT_SECRET, 600, other_token,
                                         sizeof(other_token)) != 0 ? -1 : 0;
}

int main(void)
{
    const char *tmp = getenv("TMPDIR");
    char dir[256];
    snprintf(dir, sizeof(dir), "%s/specus-c-crud-XXXXXX", tmp != NULL && *tmp != '\0' ? tmp : "/tmp");
    if (mkdtemp(dir) == NULL) {
        perror("mkdtemp");
        return 1;
    }
    snprintf(db_path, sizeof(db_path), "%s/crud.db", dir);
    setenv("SPECUS_ENV", "test", 1);
    setenv("SPECUS_DB_SEED_DEMO_CLIENT", "false", 1);
    setenv("SPECUS_DATABASE_PATH", db_path, 1);
    setenv("SPECUS_AUTH_JWT_SECRET", JWT_SECRET, 1);
    setenv("SPECUS_AUTH_USERNAME", BUILT_IN, 1);
    setenv("SPECUS_AUTH_PASSWORD", "crud-root-password-2026", 1);
    unsetenv("SPECUS_AUTH_TENANT_ID");
    /* Self-registration needs all of this (Java RegistrationService.isAvailable). */
    setenv("SPECUS_AUTH_REGISTRATION_ENABLED", "true", 1);
    setenv("SPECUS_AUTH_EMAIL_VERIFICATION_ENABLED", "true", 1);
    setenv("SPECUS_AUTH_EMAIL_FROM_ADDRESS", "noreply@example.com", 1);
    setenv("SPECUS_AUTH_SMTP_HOST", "smtp.example.com", 1);
    setenv("SPECUS_AUTH_TURNSTILE_ENABLED", "true", 1);
    setenv("SPECUS_AUTH_TURNSTILE_SITE_KEY", "site-key", 1);
    setenv("SPECUS_AUTH_TURNSTILE_SECRET_KEY", "secret-key", 1);
    setenv("SPECUS_AUTH_TURNSTILE_VERIFY_URL", "https://verify.example.com", 1);
    setenv("SPECUS_AUTH_TURNSTILE_ALLOWED_HOSTNAMES", "specus.example.com", 1);

    int failed = st_storage_init(db_path, 0) != 0 || seed() != 0;
    if (failed) fprintf(stderr, "seeding failed\n");
    st_admin_server server;
    memset(&server, 0, sizeof(server));
    server.fd = -1;
    struct sockaddr_in address;
    socklen_t address_len = sizeof(address);
    if (!failed && (st_admin_server_start(&server, 0, "") != 0
                    || getsockname(server.fd, (struct sockaddr *)&address, &address_len) != 0)) {
        fprintf(stderr, "listener start failed\n");
        failed = 1;
    }
    if (!failed) {
        port = ntohs(address.sin_port);
        failed = test_registration() != 0;
        failed = test_me() != 0 || failed;
        failed = test_credentials() != 0 || failed;
        failed = test_mappings() != 0 || failed;
        failed = test_name_availability() != 0 || failed;
        failed = test_traffic_usage() != 0 || failed;
        failed = test_peer_import_targets() != 0 || failed;
        failed = test_database_initialize() != 0 || failed;
    }
    free(last_body);
    unlink(db_path);
    char journal[400];
    snprintf(journal, sizeof(journal), "%s-journal", db_path);
    unlink(journal);
    rmdir(dir);
    if (failed) return 1;
    printf("management CRUD tests passed\n");
    return 0;
}
