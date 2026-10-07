/*
 * Java SemanticVersionTests for the SemVer rules behind client package versions and the client
 * version check (admin_http.c parse_admin_semver/compare_admin_semver), plus the SemVer 2.0
 * precedence chain and the malformed forms around empty identifiers and the 32-character cap.
 */
#include "admin_http.h"

#include <stdio.h>

static int failures = 0;

/* expected is -1, 0 or 1. */
static void expect_order(const char *left, const char *right, int expected)
{
    int result = 0;
    if (st_admin_semver_compare_for_testing(left, right, &result) != 0) {
        fprintf(stderr, "\"%s\" or \"%s\" did not parse\n", left, right);
        ++failures;
        return;
    }
    int sign = result < 0 ? -1 : (result > 0 ? 1 : 0);
    int reverse = 0;
    (void)st_admin_semver_compare_for_testing(right, left, &reverse);
    int reverse_sign = reverse < 0 ? -1 : (reverse > 0 ? 1 : 0);
    if (sign != expected || reverse_sign != -expected) {
        fprintf(stderr, "\"%s\" vs \"%s\": %d (expected %d), reversed %d\n", left, right, sign, expected,
                reverse_sign);
        ++failures;
    }
}

static void expect_valid(const char *value, int valid)
{
    int result = 0;
    int parsed = st_admin_semver_compare_for_testing(value, "1.0.0", &result) == 0;
    if (parsed != valid) {
        fprintf(stderr, "\"%s\" was %s\n", value, parsed ? "accepted" : "refused");
        ++failures;
    }
}

int main(void)
{
    /* implementsSemverPrecedenceIncludingEqualityAndBuildMetadata */
    expect_order("1.0.0", "1.0.0", 0);
    expect_order("v1.2.3", "1.2.3", 0);
    expect_order("1.0.0+build.2", "1.0.0+build.1", 0);
    expect_order("v1.2.3-alpha.1+build.01", "1.2.3-alpha.1", 0);
    expect_order("1.0.0", "1.0.0-rc.1", 1);
    expect_order("1.0.0-alpha.2", "1.0.0-alpha.10", -1);
    expect_order("2.0.0", "1.9999999999.9999999999", 1);

    /* SemVer 2.0 section 11: each one precedes the next. */
    static const char *const chain[] = {
        "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2",
        "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.1.0", "2.0.0", "10.0.0"
    };
    for (size_t i = 0; i + 1U < sizeof(chain) / sizeof(chain[0]); ++i) {
        expect_order(chain[i], chain[i + 1U], -1);
    }
    expect_order("1.0.0-1", "1.0.0-a", -1);
    expect_order("1.0.0-a-b", "1.0.0-a", 1);

    /* rejectsLooseOrAmbiguousVersions */
    static const char *const refused[] = {
        "V1.0.0", "1.0", "1.0.0-01", "1.0.0+build..1", "1.0.0+",
        "", "   ", "v", "vv1.0.0", "1", "1.0.0.0", "1..0.0", ".1.0.0", "1.0.0.", "01.0.0", "1.00.0",
        "1.0.0-", "1.0.0-alpha..1", "1.0.0-.alpha", "1.0.0-alpha.", "1.0.0-alpha_1", "1.0.0+.build",
        "1.0.0+build.", "1.0.0+build+1", "1.0.0 -alpha", "1.0.0-aaaaaaaaaaaaaaaaaaaaaaaaaaa", "-1.0.0"
    };
    for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); ++i) expect_valid(refused[i], 0);
    static const char *const accepted[] = {
        " v1.0.0 ", "\t1.0.0\n", "0.0.0", "1.0.0+001", "1.0.0+build.-x", "1.0.0-0", "1.0.0-x-y-z.--",
        "1.0.0-alpha+build-1.2", "1.0.0-aaaaaaaaaaaaaaaaaaaaaaaaaa", "v1.0.0-aaaaaaaaaaaaaaaaaaaaaaaaaa"
    };
    for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); ++i) expect_valid(accepted[i], 1);

    if (failures != 0) {
        fprintf(stderr, "%d semantic version check(s) failed\n", failures);
        return 1;
    }
    printf("semantic version tests passed\n");
    return 0;
}
