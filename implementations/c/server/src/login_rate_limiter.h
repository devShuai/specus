#ifndef SPECUS_LOGIN_RATE_LIMITER_H
#define SPECUS_LOGIN_RATE_LIMITER_H

#include <stdint.h>

typedef struct {
    int enabled;
    unsigned int per_ip;
    unsigned int per_account;
    int64_t window_seconds;
} st_login_rate_limit_config;

/* Records both dimensions. Returns 0 when allowed and 1 when the attempt must be rejected. */
int st_login_rate_limiter_check(const char *client_ip,
                                const char *account,
                                const st_login_rate_limit_config *config,
                                int64_t now_seconds,
                                int64_t *retry_after_seconds);

/* A successful login clears only the account budget; the source-IP budget intentionally remains. */
void st_login_rate_limiter_record_success(const char *account);

/* Intended for deterministic tests and orderly process teardown. */
void st_login_rate_limiter_reset(void);

#endif
