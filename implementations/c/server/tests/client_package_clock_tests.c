#define _POSIX_C_SOURCE 200809L
#include "client_package.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* Executable-local clock: the production core still calls the normal time() API.
 * No host clock changes, linker-specific --wrap option or runtime testing knob. */
static time_t test_now;
time_t time(time_t *out)
{
    if (out != NULL) *out = test_now;
    return test_now;
}

static int check(const char *source, time_t at, int expected, long long expected_retry)
{
    test_now = at;
    long long retry = -1;
    int actual = st_client_package_rate_limit(source, &retry);
    if (actual != expected || (expected != 0 && retry != expected_retry)) {
        fprintf(stderr, "package-clock time=%lld source=%s expected%d/retry%lld actual%d/retry%lld\n",
                (long long)at, source == NULL ? "NULL" : source, expected, expected_retry, actual, retry);
        return 1;
    }
    return 0;
}

int main(void)
{
    if (setenv("SPECUS_CLIENT_PACKAGE_PUBLIC_RATE_LIMIT_PER_IP", "2", 1) != 0
        || setenv("SPECUS_CLIENT_PACKAGE_PUBLIC_RATE_LIMIT_WINDOW_SECONDS", "60", 1) != 0) {
        perror("configure package rate limit");
        return 1;
    }
    st_client_package_rate_limit_reset();
    int failed = check(NULL, 1000, 0, 0) || check("", 1000, 0, 0)
        || check("unknown", 999, 1, 60) || check("   ", 500, 1, 60)
        || check("192.0.2.2", 999, 0, 0) || check("192.0.2.2", 998, 0, 0)
        || check("192.0.2.2", 998, 1, 60)
        || check("unknown", 1059, 1, 1)
        || check(NULL, 1060, 0, 0) || check("", 1060, 0, 0) || check("unknown", 1060, 1, 60)
        || check("unknown", 5000, 0, 0) || check("unknown", 5000, 0, 0)
        || check("unknown", 4999, 1, 60);
    st_client_package_rate_limit_reset();
    if (!failed) puts("client package clock: rollback never refills,unknown aliases,independent sources,exact expiry and forward jump passed");
    return failed;
}
