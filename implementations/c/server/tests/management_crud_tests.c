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
#include <utf8proc.h>

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
    char email[1024];
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
    (void)ttl;
    mailbox *box = ctx;
    snprintf(box->code, sizeof(box->code), "%s", code);
    snprintf(box->username, sizeof(box->username), "%s", username);
    snprintf(box->email, sizeof(box->email), "%s", email);
    return 0;
}

static int register_with(const char *username, const char *email, const char *password, const char *token,
                         int status, const char *needle)
{
    char body[2048];
    char *escaped_email = st_json_escape(email);
    if (escaped_email == NULL) return -1;
    snprintf(body, sizeof(body),
             "{\"username\":\"%s\",\"email\":\"%s\",\"password\":\"%s\",\"turnstileToken\":\"%s\"}",
             username, escaped_email, password, token);
    free(escaped_email);
    return expect("POST", "/auth/register", body, NULL, status, needle);
}

static int valid_utf8(const char *text)
{
    if (text == NULL) return 0;
    size_t length = strlen(text), offset = 0U;
    while (offset < length) {
        utf8proc_int32_t point;
        utf8proc_ssize_t width = utf8proc_iterate((const utf8proc_uint8_t *)text + offset,
                                                (utf8proc_ssize_t)(length - offset), &point);
        if (width <= 0) return 0;
        offset += (size_t)width;
    }
    return 1;
}

static int test_registration_mailbox_vectors(const char *path, int mask_only)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL) return 1;
    char json[32768];
    size_t bytes = fread(json, 1U, sizeof(json) - 1U, file);
    int failed = ferror(file) || bytes == sizeof(json) - 1U;
    fclose(file);
    json[bytes] = '\0';
    char **cases = NULL;
    size_t count = 0U;
    int version = 0;
    if (failed || !st_json_is_valid_object(json) || st_json_get_int(json, "version", &version) != 0
        || version != 1 || st_json_get_raw_array(json, "cases", &cases, &count) != 0
        || count != (mask_only == 2 ? 14U : mask_only ? 24U : 36U)) return 1;
    mailbox box = {{0}, {0}, {0}};
    st_registration_set_handlers(fake_turnstile, fake_email, &box);
    for (size_t i = 0U; i < count; ++i) {
        char *name = st_json_get_string(cases[i], "name");
        char *email = st_json_get_string(cases[i], "email");
        char *normalized = mask_only == 1 && email != NULL ? strdup(email) : st_json_get_string(cases[i], "normalized");
        char *masked = st_json_get_string(cases[i], "masked");
        int accepted = mask_only == 1;
        int valid = name != NULL && email != NULL
            && (mask_only == 1 || st_json_get_bool(cases[i], "accepted", &accepted) == 0);
        char username[80];
        snprintf(username, sizeof(username), "mailbox-%s-%zu", mask_only == 2 ? "nul" : mask_only ? "mask" : "form", i);
        int result = !valid || (accepted && (normalized == NULL || masked == NULL));
        if (!result && mask_only == 2) {
            /* Keep escaped NUL and its suffix in the HTTP request, not in a C string
             * which would lose bytes when st_json_escape reads it. */
            char *raw_email = st_json_get_top_level_raw(cases[i], "email");
            char body[4096];
            memset(&box, 0, sizeof(box));
            if (raw_email == NULL) result = 1;
            else {
                snprintf(body, sizeof(body), "{\"username\":\"%s\",\"email\":%s,\"password\":\"pw\",\"turnstileToken\":\"ok\"}", username, raw_email);
                result = expect("POST", "/auth/register", body, NULL, accepted ? 202 : 400,
                                accepted ? "\"registrationId\"" : "\"error\":\"邮箱格式无效\"") != 0;
            }
            free(raw_email);
            if (!accepted) {
                st_storage_registration_challenge pending;
                result = box.email[0] != '\0' || st_storage_find_registration_challenge(db_path, username, "", &pending) == 0 || result;
            }
        } else if (!result) result = register_with(username, email, "pw", "ok", accepted ? 202 : 400,
                                                   accepted ? "\"registrationId\"" : "\"error\":\"邮箱格式无效\"") != 0;
        if (!result && accepted) {
            char actual_masked[1024];
            last_member("emailMasked", actual_masked, sizeof(actual_masked));
            st_storage_registration_challenge stored;
            result = !valid_utf8(last_body) || !st_json_is_valid_object(last_body)
                || !valid_utf8(actual_masked) || strcmp(box.email, normalized) != 0 || strcmp(actual_masked, masked) != 0
                || st_storage_find_registration_challenge(db_path, username, normalized, &stored) != 0
                || strcmp(stored.email, normalized) != 0;
        }
        /* Each corpus owns its challenge; repeated addresses in another corpus must not
         * turn mask assertions into a pending-registration conflict. Clean up even if the
         * expected mask fails, so the negative control tests each address independently. */
        if (accepted && last_status == 202) {
            char registration_id[128];
            last_member("registrationId", registration_id, sizeof(registration_id));
            result = st_storage_delete_registration_challenge(db_path, registration_id) != 0 || result;
        }
        printf("%s shared registration %s %s\n", result ? "FAIL" : "ok  ",
               mask_only == 2 ? "NUL raw HTTP/no-mail/no-challenge" : mask_only ? "Unicode mask HTTP/UTF8" : "mailbox form", name == NULL ? "missing-name" : name);
        failed = result || failed;
        free(name); free(email); free(normalized); free(masked);
    }
    st_registration_set_handlers(NULL, NULL, NULL);
    st_json_free_string_array(cases, count);
    return failed;
}

/* Java limits the normalized address to 254 UTF-16 units, not 254 UTF-8 bytes.
 * Keep an ASCII mask prefix here: Unicode masking has its own contract/tests. */
static int test_registration_email_storage(void)
{
    mailbox box = {{0}, {0}, {0}};
    st_registration_set_handlers(fake_turnstile, fake_email, &box);
    static const char *const units[] = {"a", "\xe7\x94\xa8", "\xf0\x9f\x98\x80", "\xe7\x94\xa8"};
    static const size_t repeats[] = {245U, 245U, 122U, 243U};
    static const size_t byte_lengths[] = {254U, 744U, 500U, 740U};
    int failed = 0;
    for (size_t i = 0; i < sizeof(repeats) / sizeof(repeats[0]); ++i) {
        char repeated[1024];
        char email[1100];
        char username[80];
        int result = repeat_into(repeated, sizeof(repeated), units[i], repeats[i]) != 0;
        if (result) { failed = 1; continue; }
        snprintf(email, sizeof(email), "%sab%s%s@e.test", i == 3U ? "\"" : "", repeated,
                 i == 2U ? "\xe7\x94\xa8" : i == 3U ? "\"" : "");
        snprintf(username, sizeof(username), "mailbox-storage-%zu", i);
        result = strlen(email) != byte_lengths[i]
            || register_with(username, email, "pw", "ok", 202, "\"registrationId\"") != 0;
        char registration_id[128];
        last_member("registrationId", registration_id, sizeof(registration_id));
        st_storage_registration_challenge stored;
        int loaded = st_storage_get_registration_challenge(db_path, registration_id, &stored);
        int complete_email = loaded == 0 && strcmp(stored.email, email) == 0;
        result = result || strcmp(box.email, email) != 0 || !complete_email;
        printf("%s registration email storage case=%zu bytes=%zu stored=%zu exact=%d\n",
               result ? "FAIL" : "ok  ", i, strlen(email), loaded == 0 ? strlen(stored.email) : 0U,
               complete_email);

        /* A new SQLite connection reads the challenge; then verify the real code over HTTP.
         * The verified full address must survive and prevent another account claiming it. */
        char body[256];
        snprintf(body, sizeof(body), "{\"registrationId\":\"%s\",\"code\":\"%s\"}", registration_id, box.code);
        int verified = expect("POST", "/auth/register/verify", body, NULL, 200, NULL) == 0;
        st_storage_management_user user;
        int registered = verified && st_storage_get_management_user_in_tenant(db_path, "default", username, &user) == 0
            && st_storage_management_email_exists(db_path, email) == 1
            && st_storage_get_registration_challenge(db_path, registration_id, &stored) != 0;
        snprintf(username, sizeof(username), "mailbox-storage-duplicate-%zu", i);
        int duplicate_refused = register_with(username, email, "pw", "ok", 400, "该邮箱已注册") == 0;
        printf("%s registration email verification case=%zu registered=%d duplicateRefused=%d\n",
               registered && duplicate_refused ? "ok  " : "FAIL", i, registered, duplicate_refused);
        result = result || !registered || !duplicate_refused;

        /* One extra BMP unit crosses the same reference limit, without sending email. */
        char too_long[1104];
        if (i == 3U) snprintf(too_long, sizeof(too_long), "\"x%s", email + 1);
        else snprintf(too_long, sizeof(too_long), "x%s", email);
        box.email[0] = '\0';
        int refused = register_with("mailbox-storage-over-limit", too_long, "pw", "ok", 400,
                                    "邮箱格式无效") == 0 && box.email[0] == '\0';
        printf("%s registration email UTF16 limit case=%zu refusedWithoutMail=%d\n",
               refused ? "ok  " : "FAIL", i, refused);
        failed = result || !refused || failed;
    }
    st_registration_set_handlers(NULL, NULL, NULL);
    return failed;
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
        "a@exam ple.com", "a<b>@example.com", "a@example", "@example.com",
        /* Actual Java RegistrationService + Jakarta Mail reject these domain characters. */
        "alice@bad_domain.example", "alice@bad+domain.example", "alice@bad!domain.example",
        "alice@bad{domain.example", "alice@bad/domain.example", "alice@bad%domain.example",
        "alice@bad=domain.example", "alice@bad*domain.example"
    };
    for (size_t i = 0; !failed && i < sizeof(bad_emails) / sizeof(bad_emails[0]); ++i) {
        failed = register_with("fresh", bad_emails[i], "pw", "ok", 400, "\"error\":\"邮箱格式无效\"") != 0;
    }
    /* The stricter domain grammar must not reject punctuation in the local part or punycode. */
    failed = failed || register_with("local-punctuation", "a_b+tag@mx-1.example.test", "pw", "ok", 202,
                                     "\"emailMasked\":\"a_***@mx-1.example.test\"") != 0;
    failed = failed || register_with("punycode", "alice@xn--fsqu00a.example", "pw", "ok", 202,
                                     "\"emailMasked\":\"al***@xn--fsqu00a.example\"") != 0;
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
        /* The account row's time, shown as Java's Instant.toString shows it. */
        char instant[64];
        snprintf(instant, sizeof(instant), "%s", user.created_at);
        if (strlen(instant) == 19U && instant[10] == ' ') {
            instant[10] = 'T';
            instant[19] = 'Z';
            instant[20] = '\0';
        }
        char expected[160];
        snprintf(expected, sizeof(expected), "\"createdAt\":\"%s\"", instant);
        failed = user.created_at[0] == '\0' || !is_instant(instant) || strstr(last_body, expected) == NULL;
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
        || expect("GET", "/api/admin/specus-mappings?clientId=abc", NULL, admin_token, 400,
                  "{\"error\":\"For input string: \\\"abc\\\"\"}") != 0
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

/* ---- path variables ----------------------------------------------------------------------- */

/*
 * The @PathVariable long of every management endpoint outside Peer Mesh (which peer_mesh_api_tests
 * covers): a segment Spring cannot convert is its 400, any long it can (0, negative, hex, padded,
 * percent-encoded, with ";" parameters) reaches the service, which answers as for an id it does not
 * have. The C server used to take only positive decimals and answer 404 for the rest.
 */
static int test_path_variables(void)
{
    static const struct {
        const char *method;
        const char *prefix;
        const char *suffix;
        const char *body;
    } endpoints[] = {
        {"PUT", "/api/admin/client-downloads/", "", "{\"platform\":\"linux\",\"name\":\"n\",\"url\":\"https://x\"}"},
        {"POST", "/api/admin/client-downloads/", "/latest", NULL},
        {"DELETE", "/api/admin/client-downloads/", "", NULL},
        {"PUT", "/api/admin/client-credentials/", "", "{\"enabled\":true}"},
        {"DELETE", "/api/admin/client-credentials/", "", NULL},
        {"GET", "/api/admin/clients/", "", NULL},
        {"PUT", "/api/admin/clients/", "", "{\"clientName\":\"path-var\"}"},
        {"DELETE", "/api/admin/clients/", "", NULL},
        {"POST", "/api/admin/clients/", "/force-refresh-port-mapping", NULL},
        {"POST", "/api/admin/clients/", "/nat-control", NULL},
        {"POST", "/api/admin/clients/", "/specus-mappings",
         "{\"listenPort\":21901,\"targetPort\":80,\"targetAddress\":\"127.0.0.1\"}"},
        {"POST", "/api/admin/clients/", "/http-routes", "{\"routeKey\":\"pv\",\"targetBaseUrl\":\"http://127.0.0.1:1\"}"},
        {"PUT", "/api/admin/specus-mappings/", "", "{\"listenPort\":21901,\"targetPort\":80,\"targetAddress\":\"h\"}"},
        {"DELETE", "/api/admin/specus-mappings/", "", NULL},
        {"PUT", "/api/admin/http-routes/", "", "{\"routeKey\":\"pv\",\"targetBaseUrl\":\"http://127.0.0.1:1\"}"},
        {"DELETE", "/api/admin/http-routes/", "", NULL},
        {"GET", "/api/admin/traffic/http-exchanges/", "", NULL},
        {"GET", "/api/admin/traffic/tcp-frames/", "", NULL},
        {"GET", "/api/admin/diagrams/", "", NULL},
        {"PUT", "/api/admin/diagrams/", "", "{\"title\":\"t\",\"content\":\"{}\"}"},
        {"DELETE", "/api/admin/diagrams/", "", NULL},
    };
    /*
     * Segments Spring cannot bind to a long, and the answer Java gives (probed on the Java server):
     * the NumberFormatException's message, or Spring's generic 400 where the request firewall or
     * Tomcat refuses the path first.
     */
    static const struct {
        const char *segment;
        const char *answer;
    } refused[] = {
        {"abc", "{\"error\":\"For input string: \\\"abc\\\"\"}"},
        {"1.5", "{\"error\":\"For input string: \\\"1.5\\\"\"}"},
        {"%20abc%20", "{\"error\":\"For input string: \\\"abc\\\"\"}"},
        {"%20", "{\"error\":\"For input string: \\\"\\\"\"}"},
        {"--1", "{\"error\":\"For input string: \\\"--1\\\"\"}"},
        {"+0x1", "{\"error\":\"For input string: \\\"+0x1\\\"\"}"},
        {"9223372036854775808", "{\"error\":\"For input string: \\\"9223372036854775808\\\"\"}"},
        {"-9223372036854775809", "{\"error\":\"For input string: \\\"-9223372036854775809\\\"\"}"},
        {"%E4%B8%AD", "{\"error\":\"For input string: \\\"中\\\"\"}"},
        {"0x", "{\"error\":\"For input string: \\\"\\\" under radix 16\"}"},
        {"-0x", "{\"error\":\"For input string: \\\"-\\\" under radix 16\"}"},
        {"-0xZZ", "{\"error\":\"For input string: \\\"-ZZ\\\" under radix 16\"}"},
        {"%23ZZ", "{\"error\":\"For input string: \\\"ZZ\\\" under radix 16\"}"},
        {"0x8000000000000000", "{\"error\":\"For input string: \\\"8000000000000000\\\" under radix 16\"}"},
        {"0x-5", "{\"error\":\"Sign character in wrong position\"}"},
        {"0;v=1", "{\"error\":\"Bad Request\"}"},
        {"1%2E", "{\"error\":\"Bad Request\"}"},
        {"1%252", "{\"error\":\"Bad Request\"}"},
        {"1%00", "{\"error\":\"Bad Request\"}"},
    };
    /* Segments that bind to a long no row has, and that long. */
    static const struct {
        const char *segment;
        const char *value;
    } unknown[] = {
        {"0", "0"}, {"-1", "-1"}, {"-0x5", "-5"}, {"%2D7", "-7"}, {"%200%20", "0"}, {"%230", "0"}, {"%09-3", "-3"},
        {"0X3ADE68B1", "987654321"}, {"%EF%BC%90", "0"},
        {"9223372036854775807", "9223372036854775807"}, {"-9223372036854775808", "-9223372036854775808"},
    };
    int failed = 0;
    char path[256];
    char reference[512];
    for (size_t e = 0; e < sizeof(endpoints) / sizeof(endpoints[0]) && !failed; ++e) {
        for (size_t r = 0; r < sizeof(refused) / sizeof(refused[0]) && !failed; ++r) {
            snprintf(path, sizeof(path), "%s%s%s", endpoints[e].prefix, refused[r].segment, endpoints[e].suffix);
            failed = expect(endpoints[e].method, path, endpoints[e].body, admin_token, 400, NULL) != 0
                || strcmp(last_body, refused[r].answer) != 0;
            if (failed) fprintf(stderr, "FAIL %s %s: expected %s, got %s\n", endpoints[e].method, path,
                                refused[r].answer, last_body == NULL ? "" : last_body);
        }
        snprintf(path, sizeof(path), "%s987654321%s", endpoints[e].prefix, endpoints[e].suffix);
        int reference_status = call(endpoints[e].method, path, endpoints[e].body, admin_token);
        snprintf(reference, sizeof(reference), "%s", last_body == NULL ? "" : last_body);
        if (!failed && reference_status <= 0) {
            fprintf(stderr, "FAIL %s %s: the unknown id answered %d %s\n", endpoints[e].method, path,
                    reference_status, reference);
            failed = 1;
        }
        for (size_t u = 0; u < sizeof(unknown) / sizeof(unknown[0]) && !failed; ++u) {
            /* The answer for 987654321 with the id it names, if any, being this one. */
            char expected[600];
            const char *named = strstr(reference, "987654321");
            if (named == NULL) {
                snprintf(expected, sizeof(expected), "%s", reference);
            } else {
                snprintf(expected, sizeof(expected), "%.*s%s%s", (int)(named - reference), reference,
                         unknown[u].value, named + strlen("987654321"));
            }
            snprintf(path, sizeof(path), "%s%s%s", endpoints[e].prefix, unknown[u].segment, endpoints[e].suffix);
            int status = call(endpoints[e].method, path, endpoints[e].body, admin_token);
            if (status != reference_status || last_body == NULL || strcmp(last_body, expected) != 0) {
                fprintf(stderr, "FAIL %s %s: expected %d %s as for 987654321, got %d %s\n", endpoints[e].method,
                        path, reference_status, expected, status, last_body == NULL ? "" : last_body);
                failed = 1;
            }
        }
    }
    /* A known id written the ways Spring also binds it reaches the same row. */
    char plain[256];
    snprintf(plain, sizeof(plain), "/api/admin/clients/%lld", client_a);
    failed = failed || expect("GET", plain, NULL, admin_token, 200, NULL) != 0;
    char *known = failed ? NULL : strdup(last_body);
    failed = failed || known == NULL;
    /* The fullwidth digits of the id (U+FF10..U+FF19), which Java's Character.digit reads too. */
    char fullwidth[96] = "/api/admin/clients/";
    char digits[24];
    snprintf(digits, sizeof(digits), "%lld", client_a);
    for (const char *d = digits; *d != '\0'; ++d) {
        size_t used = strlen(fullwidth);
        snprintf(fullwidth + used, sizeof(fullwidth) - used, "%%EF%%BC%%%X", 0x90 + (*d - '0'));
    }
    const char *const forms[] = {"/api/admin/clients/%%20%lld%%20", "/api/admin/clients/0x%llx",
                                 "/api/admin/clients/%%09+%lld"};
    for (size_t f = 0; f <= sizeof(forms) / sizeof(forms[0]) && !failed; ++f) {
        if (f < sizeof(forms) / sizeof(forms[0])) {
            snprintf(path, sizeof(path), forms[f], client_a);
        } else {
            snprintf(path, sizeof(path), "%s", fullwidth);
        }
        failed = expect("GET", path, NULL, admin_token, 200, NULL) != 0 || strcmp(last_body, known) != 0;
        if (failed) fprintf(stderr, "FAIL GET %s: expected the body of %s\n", path, plain);
    }
    free(known);
    /* Spring Security's firewall refuses a path with ";" before any binding. */
    snprintf(path, sizeof(path), "/api/admin/clients/%lld;jsessionid=abc", client_a);
    failed = failed || expect("GET", path, NULL, admin_token, 400, "{\"error\":\"Bad Request\"}") != 0;
    /* No segment, or a path Java does not map past it, is no match: 404 as in Spring. */
    failed = failed || expect("GET", "/api/admin/clients/", NULL, admin_token, 404, NULL) != 0
        || expect("GET", "/api/admin/clients/1/unknown", NULL, admin_token, 404, NULL) != 0;
    printf("%s path variables bind as Spring's long\n", failed ? "FAIL" : "ok  ");
    return failed;
}

/* ---- typed request parameters ------------------------------------------------------------- */

/*
 * A request parameter that does not convert answers what Java's GlobalExceptionHandler makes of
 * the conversion's cause (probed on the Java server): the NumberFormatException's message for a
 * Long or int, CustomBooleanEditor's for a boolean. A blank value is absent for a wrapper (Long
 * clientId, Boolean success) and fails for a primitive (int page, boolean flush); an empty one is
 * absent for both. Parameters are resolved in their declared order.
 */
static int test_query_parameters(void)
{
    static const struct {
        const char *path;
        const char *answer; /* NULL: 200 */
    } cases[] = {
        {"/api/admin/specus-mappings?clientId=%20%20", NULL},
        {"/api/admin/specus-mappings?clientId=%E4%B8%AD", "{\"error\":\"For input string: \\\"中\\\"\"}"},
        {"/api/admin/specus-mappings?clientId=%22a%5C", "{\"error\":\"For input string: \\\"\\\"a\\\\\\\"\"}"},
        {"/api/admin/connections?page=%20", "{\"error\":\"For input string: \\\"\\\"\"}"},
        {"/api/admin/connections?page=", NULL},
        {"/api/admin/connections?page=1.0", "{\"error\":\"For input string: \\\"1.0\\\"\"}"},
        {"/api/admin/connections?page=2147483648", "{\"error\":\"For input string: \\\"2147483648\\\"\"}"},
        {"/api/admin/connections?page=0x80000000", "{\"error\":\"For input string: \\\"80000000\\\" under radix 16\"}"},
        {"/api/admin/connections?success=%20", NULL},
        {"/api/admin/connections?page=x&success=y", "{\"error\":\"Invalid boolean value [y]\"}"},
        {"/api/admin/traffic?flush=%20maybe%20", "{\"error\":\"Invalid boolean value [ maybe ]\"}"},
        {"/api/admin/traffic?flush=MAYBE", "{\"error\":\"Invalid boolean value [MAYBE]\"}"},
        {"/api/admin/traffic?flush=%20", "{\"error\":\"Invalid boolean value [ ]\"}"},
        {"/api/admin/traffic?flush=", NULL},
        {"/api/admin/traffic?flush=YES", NULL},
        {"/api/admin/traffic?limit=99999999999", "{\"error\":\"For input string: \\\"99999999999\\\"\"}"},
        {"/api/admin/peer-mesh/sessions?page=%20&limit=%20", "{\"error\":\"For input string: \\\"\\\"\"}"},
        {"/api/admin/peer-mesh/sessions?page=%20", NULL},
    };
    int failed = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]) && !failed; ++i) {
        failed = expect("GET", cases[i].path, NULL, admin_token, cases[i].answer == NULL ? 200 : 400, NULL) != 0
            || (cases[i].answer != NULL && strcmp(last_body, cases[i].answer) != 0);
        if (failed) fprintf(stderr, "FAIL GET %s: expected %s, got %d %s\n", cases[i].path,
                            cases[i].answer == NULL ? "200" : cases[i].answer, last_status,
                            last_body == NULL ? "" : last_body);
    }
    printf("%s request parameters convert as Spring's editors\n", failed ? "FAIL" : "ok  ");
    return failed;
}

/*
 * A parameter given more than once, as the Java server answers it (measured over real HTTP): a
 * String gets the values comma-joined; a number or boolean converts the first value alone, and when
 * that fails the property editor gets them all joined and names them in its message. Names are
 * percent-decoded, and a name without '=' is an empty value.
 */
static int test_repeated_query_parameters(void)
{
    static const struct {
        const char *path;
        int status;
        const char *answer; /* NULL: anything */
    } cases[] = {
        {"/api/admin/specus-mappings?clientId=a&clientId=1", 400, "{\"error\":\"For input string: \\\"a,1\\\"\"}"},
        {"/api/admin/specus-mappings?clientId=%20&clientId=%20", 400, "{\"error\":\"For input string: \\\",\\\"\"}"},
        {"/api/admin/specus-mappings?clientId=1%2C2", 400, "{\"error\":\"For input string: \\\"1,2\\\"\"}"},
        {"/api/admin/specus-mappings?%63lientId=x", 400, "{\"error\":\"For input string: \\\"x\\\"\"}"},
        {"/api/admin/specus-mappings?clientId=&clientId=", 200, NULL},
        {"/api/admin/specus-mappings?clientId=&clientId=5", 200, NULL},
        {"/api/admin/specus-mappings?clientId", 200, NULL},
        {"/api/admin/specus-mappings?clientId&clientId=3", 200, NULL},
        {"/api/admin/specus-mappings?clientId=1&&clientId=2", 200, NULL},
        {"/api/admin/connections?page=&page=", 400, "{\"error\":\"For input string: \\\",\\\"\"}"},
        {"/api/admin/connections?page=0&page=x", 200, "\"page\":0"},
        {"/api/admin/connections?page=x&page=0", 400, "{\"error\":\"For input string: \\\"x,0\\\"\"}"},
        {"/api/admin/connections?success=true&success=false", 200, NULL},
        {"/api/admin/connections?success=&success=", 200, NULL},
        {"/api/admin/connections?success=maybe&success=true", 400, "{\"error\":\"Invalid boolean value [maybe,true]\"}"},
        {"/api/admin/traffic?flush=&flush=", 400, "{\"error\":\"Invalid boolean value [,]\"}"},
        {"/api/admin/traffic?flush=true&flush=true", 200, NULL},
        {"/api/admin/clients/name-availability?clientName=a&clientName=b", 200, "\"clientName\":\"a,b\""},
        {"/api/admin/clients/name-availability?clientName=crud-a&clientName=", 200, "\"clientName\":\"crud-a,\""},
        {"/api/admin/clients/name-availability?clientName", 400, "{\"error\":\"clientName cannot be blank\"}"},
        /* Java names the allowed values in an order that changes between JVMs; see client_package_tests. */
        {"/api/public/client-version-check?implementation=go&implementation=java&platform=linux&arch=x64"
         "&current=1.0.0", 400, "{\"error\":\"implementation must be one of [java go csharp android]\"}"},
    };
    int failed = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]) && !failed; ++i) {
        failed = expect("GET", cases[i].path, NULL, admin_token, cases[i].status, NULL) != 0
            || (cases[i].answer != NULL
                && (cases[i].answer[0] == '{' ? strcmp(last_body, cases[i].answer) != 0
                                              : strstr(last_body, cases[i].answer) == NULL));
        if (failed) fprintf(stderr, "FAIL GET %s: expected %d %s, got %d %s\n", cases[i].path, cases[i].status,
                            cases[i].answer == NULL ? "" : cases[i].answer, last_status,
                            last_body == NULL ? "" : last_body);
    }
    /* The first value that converts is the one the list filters by. */
    char path[200];
    char owner_a[64];
    char owner_b[64];
    snprintf(owner_a, sizeof(owner_a), "\"clientId\":%lld,", client_a);
    snprintf(owner_b, sizeof(owner_b), "\"clientId\":%lld,", client_b);
    snprintf(path, sizeof(path), "/api/admin/specus-mappings?clientId=%lld&clientId=%lld", client_a, client_b);
    failed = failed || expect("GET", path, NULL, admin_token, 200, owner_a) != 0 || strstr(last_body, owner_b) != NULL;
    snprintf(path, sizeof(path), "/api/admin/specus-mappings?clientId=%lld&clientId=x", client_b);
    failed = failed || expect("GET", path, NULL, admin_token, 200, owner_b) != 0 || strstr(last_body, owner_a) != NULL;
    printf("%s repeated request parameters bind as Spring binds them\n", failed ? "FAIL" : "ok  ");
    return failed;
}

/* ---- request firewall ---------------------------------------------------------------------- */

/* The status the listener answers request (a whole request head) with; -1 when there is none. */
static int raw_status(const char *request)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((uint16_t)port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    char answer[512] = "";
    size_t used = 0U;
    if (fd >= 0 && connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0
        && send(fd, request, strlen(request), 0) == (ssize_t)strlen(request)) {
        ssize_t got = 0;
        while (used < sizeof(answer) - 1U && (got = recv(fd, answer + used, sizeof(answer) - 1U - used, 0)) > 0) {
            used += (size_t)got;
        }
    }
    if (fd >= 0) close(fd);
    answer[used] = '\0';
    int status = -1;
    return sscanf(answer, "HTTP/1.1 %d", &status) == 1 ? status : -1;
}

/*
 * What the Java server refuses before any handler and before authentication, measured over real
 * HTTP: Tomcat's request-line, decoding and header checks and Spring Security's StrictHttpFirewall
 * are a 400 for an administrator and an anonymous caller alike. What they let through is decoded
 * before it is routed. The C server used to route the raw path, so "//api/admin/clients" was a 404
 * for an administrator and a 401 for anyone else, and "/api/admin/cli%65nts" was a 404.
 */
static int test_request_firewall(void)
{
    static const char *const refused[] = {
        "//api/admin/clients", "/api/admin//clients", "/api/admin/clients//", "/api/admin/./clients",
        "/api/admin/../admin/clients", "/api/admin/clients/.", "/api/admin/clients/..", "/api/admin/clients/./1",
        "/api/admin/clients;x", "/api/admin/clients%3Bx", "/api/admin/clients%3bx", "/;/api/admin/clients",
        "/api/admin/clients/1%3B", "/api/admin/%2e/clients", "/api/admin/%2E%2E/admin/clients",
        "/api/admin/clients/%2e", "/api/admin/clients%25", "/api/admin/clients%0a", "/api/admin/clients%0d",
        "/api/admin/clients%E2%80%A8", "/api/admin/clients%E2%80%A9", "/api/admin/clients\\",
        "/api/admin/clients%5C", "/api/admin/clients%5c", "/api/admin/clients%2F1", "/api/admin/cli%2Fents",
        "/api/admin/clients/1%2F", "/api/admin/clients%00", "/api/admin/clients\xc3\xa4", "/api/admin/clients\x7f",
        "/api/admin/clients%FF", "/api/admin/clients%", "/api/admin/clients%zz", "/api/admin/clients%2",
        "/api/admin/clients?x=1#y", "*", "api/admin/clients", "http://localhost/api/admin/clients", "//health",
        /* Of the printable ASCII characters Tomcat refuses ";<>[\]^`{|} in the path and "<>[\]^`| in the query. */
        "/api/admin/clients/1[", "/api/admin/clients/1]", "/api/admin/clients{", "/api/admin/clients}",
        "/api/admin/clients^", "/api/admin/clients`", "/api/admin/clients|", "/api/admin/clients\"",
        "/api/admin/clients<", "/api/admin/clients?x=[", "/api/admin/clients?x=]", "/api/admin/clients?x=|",
        "/api/admin/clients?x=\\", "/api/admin/clients?x=^", "/api/admin/clients?x=`", "/api/admin/clients?x=\"",
        "/api/admin/clients?x=>",
    };
    int failed = 0;
    for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]) && !failed; ++i) {
        failed = expect("GET", refused[i], NULL, admin_token, 400, NULL) != 0
            || strcmp(last_body, "{\"error\":\"Bad Request\"}") != 0
            || expect("GET", refused[i], NULL, NULL, 400, "{\"error\":\"Bad Request\"}") != 0;
        if (failed) fprintf(stderr, "FAIL GET %s: expected 400, got %d %s\n", refused[i], last_status,
                            last_body == NULL ? "" : last_body);
    }
    /* Let through and decoded: the same answers as the plain spelling. */
    char path[200];
    snprintf(path, sizeof(path), "/api/admin/cl%%69ents/%lld", client_a);
    failed = failed
        || expect("GET", "/api/admin/cli%65nts", NULL, admin_token, 200, "\"clientName\":\"crud-a\"") != 0
        || expect("GET", "/api/admin/cli%65nts", NULL, NULL, 401, NULL) != 0
        || expect("GET", path, NULL, admin_token, 200, "\"clientName\":\"crud-a\"") != 0
        || expect("GET", "/api/admin/clients?a=1;b=2", NULL, admin_token, 200, "\"clientName\":\"crud-a\"") != 0
        || expect("GET", "/api/admin/clients?x={}&y=%&z=?/", NULL, admin_token, 200, "\"clientName\":\"crud-a\"") != 0
        || expect("GET", "/api/admin/clients/%3F", NULL, admin_token, 400,
                  "{\"error\":\"For input string: \\\"?\\\"\"}") != 0
        || expect("GET", "/api/admin/clients%3F", NULL, admin_token, 404, NULL) != 0
        || expect("GET", "/api/admin/clients/..x", NULL, admin_token, 400,
                  "{\"error\":\"For input string: \\\"..x\\\"\"}") != 0
        || expect("GET", "/api/admin/clients/.x", NULL, admin_token, 400,
                  "{\"error\":\"For input string: \\\".x\\\"\"}") != 0
        || expect("POST", "/auth//login", "{\"username\":\"crud-root\",\"password\":\"crud-root-password-2026\"}",
                  NULL, 400, "{\"error\":\"Bad Request\"}") != 0;
    /* The login route decoded: the same answer as the plain spelling (here Turnstile's refusal). */
    char plain[256] = "";
    failed = failed
        || expect("POST", "/auth/login", "{\"username\":\"crud-root\",\"password\":\"crud-root-password-2026\"}",
                  NULL, 400, NULL) != 0;
    if (!failed) snprintf(plain, sizeof(plain), "%s", last_body);
    failed = failed
        || expect("POST", "/auth/l%6fgin", "{\"username\":\"crud-root\",\"password\":\"crud-root-password-2026\"}",
                  NULL, 400, NULL) != 0
        || strcmp(last_body, plain) != 0 || strcmp(plain, "{\"error\":\"Bad Request\"}") == 0;
    static const char *const unmatched[] = {
        "/api/admin/clients%20", "/api/admin/clients%09", "/api/admin/clients%7F", "/api/admin/clients%C3%A4",
        "/api/admin/clients+", "/api/admin/.clients", "/api/admin/clients/",
    };
    for (size_t i = 0; i < sizeof(unmatched) / sizeof(unmatched[0]) && !failed; ++i) {
        failed = expect("GET", unmatched[i], NULL, admin_token, 404, NULL) != 0
            || expect("GET", unmatched[i], NULL, NULL, 401, NULL) != 0;
    }
    /* Methods: StrictHttpFirewall's seven, spelled exactly; Tomcat's own answers to TRACE and CONNECT. */
    failed = failed
        || expect("get", "/api/admin/clients", NULL, admin_token, 400, "{\"error\":\"Bad Request\"}") != 0
        || expect("FOO", "/api/admin/clients", NULL, admin_token, 400, "{\"error\":\"Bad Request\"}") != 0
        || expect("FOO", "/api/admin/clients", NULL, NULL, 400, "{\"error\":\"Bad Request\"}") != 0
        || expect("TRACE", "/api/admin/clients", NULL, admin_token, 405, NULL) != 0
        || expect("CONNECT", "/api/admin/clients", NULL, admin_token, 501, NULL) != 0;
    /* Header lines: a name that is no token or a value with a control character. */
    char request[1400];
    snprintf(request, sizeof(request), "GET /api/admin/clients HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\n"
             "X-Probe: a\x01" "b\r\nConnection: close\r\n\r\n", admin_token);
    int status = raw_status(request);
    snprintf(request, sizeof(request), "GET /api/admin/clients HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\n"
             "X-Pr\xc3\xa4" "be: ab\r\nConnection: close\r\n\r\n", admin_token);
    int name_status = raw_status(request);
    snprintf(request, sizeof(request), "GET /api/admin/clients HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\n"
             "X-Probe: \xc3\xa4\r\nConnection: close\r\n\r\n", admin_token);
    int text_status = raw_status(request);
    if (!failed && (status != 400 || name_status != 400 || text_status != 200)) {
        fprintf(stderr, "FAIL header lines: control %d, name %d, non-ASCII value %d\n", status, name_status,
                text_status);
        failed = 1;
    }
    printf("%s the request firewall refuses what Java's does, before authentication\n", failed ? "FAIL" : "ok  ");
    return failed;
}

/* ---- management user request body --------------------------------------------------------- */

/*
 * POST /api/admin/users and PUT /api/admin/users/{username} bind UserMutation(String username,
 * String password, ManagementRole role, Boolean enabled) with Jackson before the service checks the
 * caller: an "enabled" that is no Boolean, a String member given an object or array, and a missing
 * or non-object body are Spring's 400, even for a caller who is not an administrator. The C server
 * used to read "enabled" leniently and ignore a value of another type.
 */
static int test_user_mutation_binding(void)
{
    static const char *const refused[] = {
        "{\"username\":\"bind-u\",\"password\":\"bind-secret\",\"enabled\":\"yes\"}",
        "{\"username\":\"bind-u\",\"password\":\"bind-secret\",\"enabled\":\"1\"}",
        "{\"username\":\"bind-u\",\"password\":\"bind-secret\",\"enabled\":{}}",
        "{\"username\":\"bind-u\",\"password\":\"bind-secret\",\"enabled\":[true]}",
        "{\"username\":{\"name\":\"bind-u\"},\"password\":\"bind-secret\"}",
        "{\"username\":\"bind-u\",\"password\":[\"bind-secret\"]}",
        "{\"username\":\"bind-u\",\"password\":\"bind-secret\",\"role\":{}}",
        /* ManagementRole binds its constant names exactly, or their ordinals 0 and 1. */
        "{\"username\":\"bind-u\",\"password\":\"bind-secret\",\"role\":\"admin\"}",
        "{\"username\":\"bind-u\",\"password\":\"bind-secret\",\"role\":\"User\"}",
        "{\"username\":\"bind-u\",\"password\":\"bind-secret\",\"role\":\"\"}",
        "{\"username\":\"bind-u\",\"password\":\"bind-secret\",\"role\":\"  \"}",
        "{\"username\":\"bind-u\",\"password\":\"bind-secret\",\"role\":\"bogus\"}",
        "{\"username\":\"bind-u\",\"password\":\"bind-secret\",\"role\":5}",
        "{\"username\":\"bind-u\",\"password\":\"bind-secret\",\"role\":-1}",
        "{\"username\":\"bind-u\",\"password\":\"bind-secret\",\"role\":1.0}",
        "{\"username\":\"bind-u\",\"password\":\"bind-secret\",\"role\":true}",
        "[]",
        "\"bind-u\"",
    };
    int failed = 0;
    for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]) && !failed; ++i) {
        failed = expect("POST", "/api/admin/users", refused[i], admin_token, 400, "{\"error\":\"Bad Request\"}") != 0
            || expect("POST", "/api/admin/users", refused[i], user_token, 400, "{\"error\":\"Bad Request\"}") != 0;
    }
    failed = failed || expect("POST", "/api/admin/users", NULL, admin_token, 400, "{\"error\":\"Bad Request\"}") != 0
        || expect("GET", "/api/admin/users", NULL, admin_token, 200, NULL) != 0
        || strstr(last_body, "bind-u") != NULL
        /* What binds still meets the service's administrator check. */
        || expect("POST", "/api/admin/users", "{\"username\":\"bind-u\",\"password\":\"bind-secret\"}", user_token,
                  403, NULL) != 0
        /* The Boolean coercions Jackson allows: case variants of true/false and integers. */
        || expect("POST", "/api/admin/users",
                  "{\"username\":\"bind-u\",\"password\":\"bind-secret\",\"enabled\":\"FALSE\"}", admin_token, 201,
                  "\"enabled\":false") != 0
        || expect("POST", "/api/admin/users", "{\"username\":\"bind-v\",\"password\":\"bind-secret\",\"enabled\":0}",
                  admin_token, 201, "\"enabled\":false") != 0
        || expect("POST", "/api/admin/users", "{\"username\":\"bind-w\",\"password\":\"bind-secret\",\"enabled\":null}",
                  admin_token, 201, "\"enabled\":true") != 0
        /* The role spellings Jackson binds: the name trimmed, the ordinal as a number or digit string. */
        || expect("POST", "/api/admin/users", "{\"username\":\"role-a\",\"password\":\"bind-secret\",\"role\":\" ADMIN\\t\"}",
                  admin_token, 201, "\"role\":\"ADMIN\"") != 0
        || expect("POST", "/api/admin/users", "{\"username\":\"role-b\",\"password\":\"bind-secret\",\"role\":0}",
                  admin_token, 201, "\"role\":\"ADMIN\"") != 0
        || expect("POST", "/api/admin/users", "{\"username\":\"role-c\",\"password\":\"bind-secret\",\"role\":\"1\"}",
                  admin_token, 201, "\"role\":\"USER\"") != 0
        || expect("POST", "/api/admin/users", "{\"username\":\"role-d\",\"password\":\"bind-secret\",\"role\":null}",
                  admin_token, 201, "\"role\":\"USER\"") != 0
        || expect("PUT", "/api/admin/users/role-d", "{\"role\":\"ADMIN\"}", admin_token, 200, "\"role\":\"ADMIN\"") != 0
        || expect("PUT", "/api/admin/users/role-d", "{\"role\":null}", admin_token, 200, "\"role\":\"ADMIN\"") != 0
        /* A number given for a String member is its text. */
        || expect("POST", "/api/admin/users", "{\"username\":20261019,\"password\":\"bind-secret\"}", admin_token,
                  201, "\"username\":\"20261019\"") != 0;
    for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]) && !failed; ++i) {
        failed = expect("PUT", "/api/admin/users/bind-u", refused[i], admin_token, 400, "{\"error\":\"Bad Request\"}")
            != 0;
    }
    failed = failed || expect("PUT", "/api/admin/users/bind-u", NULL, admin_token, 400, "{\"error\":\"Bad Request\"}") != 0
        || expect("PUT", "/api/admin/users/bind-u", "{\"enabled\":\"no\"}", user_token, 400,
                  "{\"error\":\"Bad Request\"}") != 0
        /* The refused updates changed nothing: bind-u is still disabled. */
        || expect("PUT", "/api/admin/users/bind-u", "{}", admin_token, 200, "\"enabled\":false") != 0
        || expect("PUT", "/api/admin/users/bind-u", "{\"enabled\":\"True\"}", admin_token, 200, "\"enabled\":true") != 0
        || expect("PUT", "/api/admin/users/bind-u", "{\"enabled\":7}", admin_token, 200, "\"enabled\":true") != 0;
    printf("%s management user body binds as Jackson's UserMutation\n", failed ? "FAIL" : "ok  ");
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
                  400, "{\"error\":\"For input string: \\\"abc\\\"\"}") != 0
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
        || expect("GET", "/api/admin/traffic?clientId=abc", NULL, admin_token, 400,
                  "{\"error\":\"For input string: \\\"abc\\\"\"}") != 0
        || expect("GET", "/api/admin/traffic?limit=1.5", NULL, admin_token, 400,
                  "{\"error\":\"For input string: \\\"1.5\\\"\"}") != 0
        || expect("GET", "/api/admin/traffic/resources?limit=x", NULL, admin_token, 400,
                  "{\"error\":\"For input string: \\\"x\\\"\"}") != 0;
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
        failed = test_registration_mailbox_vectors(ST_MAILBOX_VECTOR_FILE, 0) != 0 || failed;
        failed = test_registration_mailbox_vectors(ST_EMAIL_MASK_VECTOR_FILE, 1) != 0 || failed;
        failed = test_registration_mailbox_vectors(ST_EMAIL_NUL_VECTOR_FILE, 2) != 0 || failed;
        failed = test_registration_email_storage() != 0 || failed;
        failed = test_me() != 0 || failed;
        failed = test_credentials() != 0 || failed;
        failed = test_mappings() != 0 || failed;
        failed = test_name_availability() != 0 || failed;
        failed = test_traffic_usage() != 0 || failed;
        failed = test_peer_import_targets() != 0 || failed;
        failed = test_path_variables() != 0 || failed;
        failed = test_user_mutation_binding() != 0 || failed;
        failed = test_query_parameters() != 0 || failed;
        failed = test_repeated_query_parameters() != 0 || failed;
        failed = test_request_firewall() != 0 || failed;
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
