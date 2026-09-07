#include "login_rate_limiter.h"

#include <stdio.h>

static int expect_allowed(const char *ip,
                          const char *account,
                          const st_login_rate_limit_config *config,
                          int64_t now)
{
    int64_t retry_after = -1;
    if (st_login_rate_limiter_check(ip, account, config, now, &retry_after) != 0
        || retry_after != 0) {
        fprintf(stderr, "login attempt was unexpectedly rate limited: ip=%s account=%s\n", ip, account);
        return 1;
    }
    return 0;
}

static int expect_limited(const char *ip,
                          const char *account,
                          const st_login_rate_limit_config *config,
                          int64_t now,
                          int64_t expected_retry_after)
{
    int64_t retry_after = 0;
    if (st_login_rate_limiter_check(ip, account, config, now, &retry_after) != 1
        || retry_after != expected_retry_after) {
        fprintf(stderr,
                "login attempt limit mismatch: ip=%s account=%s retry=%lld expected=%lld\n",
                ip,
                account,
                (long long)retry_after,
                (long long)expected_retry_after);
        return 1;
    }
    return 0;
}

int main(void)
{
    st_login_rate_limit_config config = {
        .enabled = 1,
        .per_ip = 2U,
        .per_account = 2U,
        .window_seconds = 300
    };
    st_login_rate_limiter_reset();
    if (expect_allowed(" 192.0.2.1 ", " Alice ", &config, 1000) != 0
        || expect_allowed("192.0.2.1", "alice", &config, 1000) != 0
        || expect_limited("192.0.2.1", "ALICE", &config, 1000, 300) != 0) {
        return 1;
    }

    st_login_rate_limiter_reset();
    config.per_ip = 100U;
    config.per_account = 1U;
    if (expect_allowed("192.0.2.1", "target", &config, 2000) != 0
        || expect_limited("192.0.2.2", "TARGET", &config, 2000, 300) != 0) {
        return 1;
    }
    st_login_rate_limiter_record_success(" target ");
    if (expect_allowed("192.0.2.3", "target", &config, 2000) != 0) {
        fprintf(stderr, "successful login did not clear account budget\n");
        return 1;
    }

    st_login_rate_limiter_reset();
    config.per_ip = 1U;
    config.per_account = 100U;
    if (expect_allowed("198.51.100.4", "first", &config, 3000) != 0
        || expect_limited("198.51.100.4", "second", &config, 3000, 300) != 0) {
        return 1;
    }
    st_login_rate_limiter_record_success("first");
    if (expect_limited("198.51.100.4", "third", &config, 3000, 300) != 0) {
        fprintf(stderr, "successful login incorrectly cleared IP budget\n");
        return 1;
    }

    st_login_rate_limiter_reset();
    config.per_ip = 1U;
    config.per_account = 1U;
    if (expect_allowed("203.0.113.7", "window", &config, 4000) != 0
        || expect_allowed("203.0.113.7", "window", &config, 4300) != 0) {
        fprintf(stderr, "expired fixed window was not reset\n");
        return 1;
    }

    st_login_rate_limiter_reset();
    config.enabled = 0;
    for (int i = 0; i < 10; ++i) {
        if (expect_allowed("203.0.113.9", "disabled", &config, 5000) != 0) {
            return 1;
        }
    }
    st_login_rate_limiter_reset();
    return 0;
}
