#define _POSIX_C_SOURCE 200809L

#include "security_baseline.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int expect_environment(const char *value, st_deployment_environment expected)
{
    st_deployment_environment actual = st_deployment_environment_parse(value);
    if (actual != expected) {
        fprintf(stderr, "deployment environment mismatch: value=%s actual=%d expected=%d\n",
                value == NULL ? "(null)" : value,
                (int)actual,
                (int)expected);
        return 1;
    }
    return 0;
}

int main(void)
{
    if (expect_environment(NULL, ST_DEPLOYMENT_PROD) != 0
        || expect_environment("", ST_DEPLOYMENT_PROD) != 0
        || expect_environment("staging", ST_DEPLOYMENT_PROD) != 0
        || expect_environment("  DEV ", ST_DEPLOYMENT_DEV) != 0
        || expect_environment("Test", ST_DEPLOYMENT_TEST) != 0) {
        return 1;
    }

    const char *weak_passwords[] = {
        "admin", "password", "123456", "12345678", "test1234", " ChangeMe ", "change-me",
        "CHANGE_ME_ADMIN_PASSWORD", "change-me-before-exposure", "specus", "demo"
    };
    for (size_t i = 0; i < sizeof(weak_passwords) / sizeof(weak_passwords[0]); ++i) {
        if (st_security_baseline_validate("prod", 1, weak_passwords[i], NULL)
            != ST_SECURITY_BASELINE_KNOWN_DEFAULT_PASSWORD) {
            fprintf(stderr, "production accepted known default password: %s\n", weak_passwords[i]);
            return 1;
        }
    }
    if (st_security_baseline_validate("prod", 1, "8Qb!x2s7Lm#4pTz", NULL)
            != ST_SECURITY_BASELINE_OK
        || st_security_baseline_validate("prod", 1, "", NULL) != ST_SECURITY_BASELINE_OK
        || st_security_baseline_validate("prod", 0, "admin", NULL) != ST_SECURITY_BASELINE_OK
        || st_security_baseline_validate("dev", 1, "admin", NULL) != ST_SECURITY_BASELINE_OK
        || st_security_baseline_validate("test", 1, "admin", NULL) != ST_SECURITY_BASELINE_OK
        || st_security_baseline_validate("prod",
                                         0,
                                         "",
                                         " Replace-With-A-Long-Random-Secret ")
            != ST_SECURITY_BASELINE_KNOWN_DEFAULT_JWT_SECRET
        || st_security_baseline_validate("dev",
                                         0,
                                         "",
                                         "replace-with-a-long-random-secret")
            != ST_SECURITY_BASELINE_OK) {
        fprintf(stderr, "security baseline credential policy mismatch\n");
        return 1;
    }

    /* onlyNonProdEnvironmentsAllowDemoData */
    if (st_deployment_environment_allows_demo_data("prod")
        || !st_deployment_environment_allows_demo_data("dev")
        || !st_deployment_environment_allows_demo_data("test")) {
        fprintf(stderr, "demo data policy does not follow the deployment environment\n");
        return 1;
    }
    /* prodRefusesPublishedJwtPlaceholderEvenWhenPasswordLoginIsDisabled: a real secret starts. */
    if (st_security_baseline_validate("prod", 0, "", "unique-random-deployment-secret") != ST_SECURITY_BASELINE_OK) {
        fprintf(stderr, "production refused a non-placeholder JWT secret\n");
        return 1;
    }
    /* The refusal text is Java's, so an operator reads the same reason from either runtime. */
    char message[256];
    if (st_security_baseline_message(ST_SECURITY_BASELINE_KNOWN_DEFAULT_PASSWORD, ST_DEPLOYMENT_PROD, message,
                                     sizeof(message)) != 0
        || strcmp(message, "specus.auth.password 使用了已知默认口令，禁止在 PROD 环境启动；"
                           "请设置 SPECUS_AUTH_PASSWORD 或置空以关闭密码登录") != 0
        || st_security_baseline_message(ST_SECURITY_BASELINE_KNOWN_DEFAULT_JWT_SECRET, ST_DEPLOYMENT_DEV, message,
                                        sizeof(message)) != 0
        || strcmp(message, "specus.auth.jwt-secret 使用了公开占位值，禁止在 DEV 环境启动；"
                           "请设置随机 SPECUS_AUTH_JWT_SECRET 或置空以使用临时密钥") != 0
        || st_security_baseline_message(ST_SECURITY_BASELINE_OK, ST_DEPLOYMENT_PROD, message, sizeof(message)) == 0) {
        fprintf(stderr, "security baseline message is not Java's text\n");
        return 1;
    }

    unsetenv("SPECUS_ENV");
    unsetenv("SPECUS_DB_SEED_DEMO_CLIENT");
    if (st_security_baseline_demo_seed_enabled_current()) {
        fprintf(stderr, "unset environment unexpectedly allowed demo data\n");
        return 1;
    }
    setenv("SPECUS_ENV", "dev", 1);
    if (!st_security_baseline_demo_seed_enabled_current()) {
        fprintf(stderr, "development environment unexpectedly disabled demo data\n");
        return 1;
    }
    setenv("SPECUS_ENV", "Test", 1);
    if (!st_security_baseline_demo_seed_enabled_current()) {
        fprintf(stderr, "test environment unexpectedly disabled demo data\n");
        return 1;
    }
    setenv("SPECUS_DB_SEED_DEMO_CLIENT", "false", 1);
    if (st_security_baseline_demo_seed_enabled_current()) {
        fprintf(stderr, "explicit demo seed disable was ignored\n");
        return 1;
    }
    unsetenv("SPECUS_ENV");
    unsetenv("SPECUS_DB_SEED_DEMO_CLIENT");
    setenv("SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED", "true", 1);
    if (st_security_baseline_validate_current() == 0) {
        fprintf(stderr, "cluster mode without Redis URI did not fail closed\n");
        return 1;
    }
    setenv("SPECUS_PUBLIC_TRANSFER_REDIS_URI", "redis://127.0.0.1:6379/0", 1);
    if (st_security_baseline_validate_current() != 0) {
        fprintf(stderr, "configured public-transfer cluster mode was rejected\n");
        return 1;
    }
    setenv("SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED", "false", 1);
    if (st_security_baseline_validate_current() != 0) {
        fprintf(stderr, "disabled public-transfer cluster mode was rejected\n");
        return 1;
    }
    unsetenv("SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED");
    unsetenv("SPECUS_PUBLIC_TRANSFER_REDIS_URI");
    return 0;
}
