#define _POSIX_C_SOURCE 200809L
#include "registration.h"
#include "security.h"
#include "storage.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define CHECK(ok) do { if (!(ok)) { fprintf(stderr, "registration expiry failed line %d: %s\n", __LINE__, #ok); exit(1); } } while (0)
static char database[] = "/tmp/specus-registration-expiry-XXXXXX";
static const time_t seconds = 1789473600;

time_t __wrap_time(time_t *out)
{
    if (out != NULL) *out = seconds;
    return seconds;
}
int __real_clock_gettime(clockid_t id, struct timespec *out);
int __wrap_clock_gettime(clockid_t id, struct timespec *out)
{
    if (id != CLOCK_REALTIME) return __real_clock_gettime(id, out);
    out->tv_sec = seconds;
    out->tv_nsec = 500000000L;
    return 0;
}
static void cleanup(void) { unlink(database); }

static void verify_boundary(unsigned index, const char *expiry, int accepted)
{
    st_storage_registration_challenge challenge = {0};
    snprintf(challenge.registration_id, sizeof(challenge.registration_id), "expiry-%u", index);
    snprintf(challenge.username, sizeof(challenge.username), "expiry-user-%u", index);
    snprintf(challenge.email, sizeof(challenge.email), "expiry-%u@example.test", index);
    strcpy(challenge.password_hash, "already-hashed-by-registration-request");
    strcpy(challenge.created_at, "2026-09-15T11:00:00Z");
    strcpy(challenge.updated_at, challenge.created_at);
    snprintf(challenge.expires_at, sizeof(challenge.expires_at), "%s", expiry);
    challenge.attempts_remaining = 5;
    CHECK(st_security_registration_code_hash(challenge.registration_id, "123456", challenge.code_hash) == 0);
    CHECK(st_storage_create_registration_challenge(database, &challenge) == 0);
    char body[160], error[256];
    snprintf(body, sizeof(body), "{\"registrationId\":\"%s\",\"code\":\"123456\"}", challenge.registration_id);
    st_storage_management_user user;
    int status = 0;
    int result = st_registration_verify(database, body, &user, &status, error, sizeof(error));
    printf("registration expiry boundary %u: result=%d status=%d expected-accepted=%d\n", index, result, status, accepted);
    fflush(stdout);
    CHECK(accepted ? result == 0 && status == 200 : result == -1 && status == 400);
    int found = st_storage_get_management_user_in_tenant(database, "default", challenge.username, &user) == 0;
    CHECK(found == accepted);
    st_storage_registration_challenge after;
    CHECK(st_storage_get_registration_challenge(database, challenge.registration_id, &after) != 0);
    printf("registration verification: expires %s at now 12:00:00.500Z -> %d, account-created=%d\n", expiry, status, found);
}

int main(void)
{
    static const char *const settings[][2] = {
        {"SPECUS_DB_SEED_DEMO_CLIENT", "0"}, {"SPECUS_AUTH_TENANT_ID", "default"},
        {"SPECUS_AUTH_PASSWORD", "registration-expiry-fixture"},
        {"SPECUS_AUTH_JWT_SECRET", "registration-expiry-fixture-key"},
        {"SPECUS_AUTH_REGISTRATION_ENABLED", "true"}, {"SPECUS_AUTH_PASSWORD_LOGIN_ENABLED", "true"},
        {"SPECUS_AUTH_EMAIL_VERIFICATION_ENABLED", "true"},
        {"SPECUS_AUTH_EMAIL_FROM_ADDRESS", "noreply@example.test"}, {"SPECUS_AUTH_SMTP_HOST", "smtp.example.test"},
        {"SPECUS_AUTH_TURNSTILE_ENABLED", "true"}, {"SPECUS_AUTH_TURNSTILE_SITE_KEY", "fixture-site"},
        {"SPECUS_AUTH_TURNSTILE_SECRET_KEY", "fixture-secret"},
        {"SPECUS_AUTH_TURNSTILE_VERIFY_URL", "https://verify.example.test"},
        {"SPECUS_AUTH_TURNSTILE_ALLOWED_HOSTNAMES", "example.test"}
    };
    for (size_t i = 0; i < sizeof(settings) / sizeof(settings[0]); ++i)
        CHECK(setenv(settings[i][0], settings[i][1], 1) == 0);
    CHECK(atexit(cleanup) == 0);
    int fd = mkstemp(database); CHECK(fd >= 0); close(fd);
    CHECK(st_storage_init(database, 0) == 0 && st_registration_available());
    verify_boundary(0U, "2026-09-15T12:00:00.4999999Z", 0);
    verify_boundary(1U, "2026-09-15T12:00:00.5000000Z", 0);
    verify_boundary(2U, "2026-09-15T12:00:00.5000001Z", 1);
    return 0;
}
