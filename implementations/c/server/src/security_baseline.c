#include "security_baseline.h"

#include "object_storage.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int ascii_case_equal_trimmed(const char *value, const char *expected)
{
    if (value == NULL || expected == NULL) {
        return 0;
    }
    const unsigned char *start = (const unsigned char *)value;
    while (*start != '\0' && isspace(*start)) {
        ++start;
    }
    const unsigned char *end = start + strlen((const char *)start);
    while (end > start && isspace(end[-1])) {
        --end;
    }
    size_t len = (size_t)(end - start);
    if (len != strlen(expected)) {
        return 0;
    }
    for (size_t i = 0; i < len; ++i) {
        if (tolower(start[i]) != (unsigned char)expected[i]) {
            return 0;
        }
    }
    return 1;
}

static int text_present(const char *value)
{
    if (value == NULL) {
        return 0;
    }
    for (const unsigned char *cursor = (const unsigned char *)value; *cursor != '\0'; ++cursor) {
        if (!isspace(*cursor)) {
            return 1;
        }
    }
    return 0;
}

static int env_bool(const char *name, int fallback)
{
    const char *value = getenv(name);
    if (value == NULL || *value == '\0') {
        return fallback;
    }
    return strcmp(value, "0") != 0
        && strcmp(value, "false") != 0
        && strcmp(value, "FALSE") != 0
        && strcmp(value, "no") != 0
        && strcmp(value, "NO") != 0;
}

st_deployment_environment st_deployment_environment_parse(const char *value)
{
    if (ascii_case_equal_trimmed(value, "dev")
        || ascii_case_equal_trimmed(value, "development")
        || ascii_case_equal_trimmed(value, "local")) {
        return ST_DEPLOYMENT_DEV;
    }
    if (ascii_case_equal_trimmed(value, "test")
        || ascii_case_equal_trimmed(value, "testing")) {
        return ST_DEPLOYMENT_TEST;
    }
    return ST_DEPLOYMENT_PROD;
}

int st_deployment_environment_allows_demo_data(const char *value)
{
    return st_deployment_environment_parse(value) != ST_DEPLOYMENT_PROD;
}

static int known_default_password(const char *password)
{
    static const char *values[] = {
        "admin", "password", "123456", "12345678", "changeme", "change-me",
        "change_me_admin_password", "change-me-before-exposure", "specus", "test1234", "demo"
    };
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
        if (ascii_case_equal_trimmed(password, values[i])) {
            return 1;
        }
    }
    return 0;
}

st_security_baseline_result st_security_baseline_validate(const char *environment,
                                                          int password_login_enabled,
                                                          const char *password,
                                                          const char *jwt_secret)
{
    if (st_deployment_environment_parse(environment) != ST_DEPLOYMENT_PROD) {
        return ST_SECURITY_BASELINE_OK;
    }
    if (password_login_enabled && text_present(password) && known_default_password(password)) {
        return ST_SECURITY_BASELINE_KNOWN_DEFAULT_PASSWORD;
    }
    if (text_present(jwt_secret)
        && ascii_case_equal_trimmed(jwt_secret, "replace-with-a-long-random-secret")) {
        return ST_SECURITY_BASELINE_KNOWN_DEFAULT_JWT_SECRET;
    }
    return ST_SECURITY_BASELINE_OK;
}

int st_security_baseline_message(st_security_baseline_result result,
                                 st_deployment_environment environment,
                                 char *out,
                                 size_t out_len)
{
    /* Java prints the DeploymentEnvironment constant's name. */
    const char *name = environment == ST_DEPLOYMENT_DEV ? "DEV" : environment == ST_DEPLOYMENT_TEST ? "TEST" : "PROD";
    int written;
    if (out == NULL || out_len == 0U) {
        return -1;
    }
    if (result == ST_SECURITY_BASELINE_KNOWN_DEFAULT_PASSWORD) {
        written = snprintf(out, out_len,
                           "specus.auth.password 使用了已知默认口令，禁止在 %s 环境启动；"
                           "请设置 SPECUS_AUTH_PASSWORD 或置空以关闭密码登录", name);
    } else if (result == ST_SECURITY_BASELINE_KNOWN_DEFAULT_JWT_SECRET) {
        written = snprintf(out, out_len,
                           "specus.auth.jwt-secret 使用了公开占位值，禁止在 %s 环境启动；"
                           "请设置随机 SPECUS_AUTH_JWT_SECRET 或置空以使用临时密钥", name);
    } else {
        return -1;
    }
    return written < 0 || (size_t)written >= out_len ? -1 : 0;
}

int st_security_baseline_validate_current(void)
{
    const char *environment = getenv("SPECUS_ENV");
    const char *password = getenv("SPECUS_AUTH_PASSWORD");
    const char *jwt_secret = getenv("SPECUS_AUTH_JWT_SECRET");
    int password_login_enabled = env_bool("SPECUS_AUTH_PASSWORD_LOGIN_ENABLED", 1);
    st_deployment_environment deployment = st_deployment_environment_parse(environment);
    int weak_password = password_login_enabled && text_present(password)
        && known_default_password(password);
    int weak_jwt_secret = text_present(jwt_secret)
        && ascii_case_equal_trimmed(jwt_secret, "replace-with-a-long-random-secret");
    if (env_bool("SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED", 0)
        && !text_present(getenv("SPECUS_PUBLIC_TRANSFER_REDIS_URI"))) {
        fprintf(stderr,
                "security baseline rejected SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED=true; "
                "SPECUS_PUBLIC_TRANSFER_REDIS_URI is required and local fallback is disabled\n");
        return -1;
    }
    if (st_object_storage_validate_current() != 0) {
        return -1;
    }
    char message[256];
    if (deployment != ST_DEPLOYMENT_PROD) {
        if (weak_password
            && st_security_baseline_message(ST_SECURITY_BASELINE_KNOWN_DEFAULT_PASSWORD, deployment, message,
                                            sizeof(message)) == 0) {
            fprintf(stderr, "[security-baseline] %s\n", message);
        }
        if (weak_jwt_secret
            && st_security_baseline_message(ST_SECURITY_BASELINE_KNOWN_DEFAULT_JWT_SECRET, deployment, message,
                                            sizeof(message)) == 0) {
            fprintf(stderr, "[security-baseline] %s\n", message);
        }
    }
    st_security_baseline_result result = st_security_baseline_validate(environment,
                                                                      password_login_enabled,
                                                                      password,
                                                                      jwt_secret);
    if (result != ST_SECURITY_BASELINE_OK) {
        /* Java throws IllegalStateException with this message and the context never starts. */
        if (st_security_baseline_message(result, deployment, message, sizeof(message)) == 0) {
            fprintf(stderr, "security baseline rejected startup: %s\n", message);
        }
        return -1;
    }
    if (deployment == ST_DEPLOYMENT_PROD
        && env_bool("SPECUS_DB_SEED_DEMO_CLIENT", 1)) {
        fprintf(stderr,
                "[security-baseline] production ignores SPECUS_DB_SEED_DEMO_CLIENT=true; "
                "demo data will not be created\n");
    }
    if (deployment == ST_DEPLOYMENT_PROD && (!password_login_enabled || !text_present(password))) {
        fprintf(stderr,
                "[security-baseline] built-in password login is disabled; configure OIDC or SPECUS_AUTH_PASSWORD\n");
    }
    return 0;
}

int st_security_baseline_demo_seed_enabled_current(void)
{
    return st_deployment_environment_allows_demo_data(getenv("SPECUS_ENV"))
        && env_bool("SPECUS_DB_SEED_DEMO_CLIENT", 1);
}
