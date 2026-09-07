#define _POSIX_C_SOURCE 200809L

#include "security_baseline.h"

#include <stdio.h>
#include <stdlib.h>

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
