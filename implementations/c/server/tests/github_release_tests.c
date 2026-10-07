#define _POSIX_C_SOURCE 200809L

#include "github_release.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char cached_release_json[] =
    "{\"tag_name\":\"v1.2.3\",\"assets\":[{\"id\":201,\"name\":\"specus-client-java-v1.2.3.jar\","
    "\"browser_download_url\":\"https://github.com/devShuai/specus/releases/download/v1.2.3/specus-client-java-v1.2.3.jar\","
    "\"digest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"size\":2048}]}";

static int fake_calls = 0;
static long fake_status = 200L;
static char fake_endpoint[256];
static long fake_timeout_ms = 0L;
static size_t fake_max_response_bytes = 0U;

/* Stands in for the HTTPS GET, as Java's test mocks HttpClient.send. */
static int fake_fetch(const char *endpoint,
                      const st_http_client_options *options,
                      long *status_code_out,
                      char **body_out)
{
    ++fake_calls;
    snprintf(fake_endpoint, sizeof(fake_endpoint), "%s", endpoint);
    fake_timeout_ms = options->timeout_ms;
    fake_max_response_bytes = options->max_response_bytes;
    *status_code_out = fake_status;
    *body_out = strdup(cached_release_json);
    return *body_out == NULL ? -1 : 0;
}

/*
 * Java GitHubReleaseCatalogTests.cachesSuccessfulReleaseResponse: two reads, one request to the
 * fixed endpoint. Also Java's other cache rules: a failed refresh is not retried for five
 * minutes, and a disabled fallback never asks.
 */
static int test_release_cache(void)
{
    st_storage_client_download_link packages[ST_GITHUB_RELEASE_MAX_PACKAGES];
    size_t count = 0U;
    unsetenv("SPECUS_CLIENT_PACKAGE_GITHUB_RELEASE_FALLBACK_ENABLED");
    unsetenv("SPECUS_CLIENT_PACKAGE_GITHUB_RELEASE_REQUEST_TIMEOUT_SECONDS");
    st_github_release_set_fetcher_for_testing(fake_fetch);
    st_github_release_cache_reset();
    fake_calls = 0;
    fake_status = 200L;
    int first = st_github_release_latest(packages, ST_GITHUB_RELEASE_MAX_PACKAGES, &count) == 0 && count == 1U
        && packages[0].id == 201 && strcmp(packages[0].version, "1.2.3") == 0 && packages[0].file_size == 2048;
    count = 0U;
    int second = st_github_release_latest(packages, ST_GITHUB_RELEASE_MAX_PACKAGES, &count) == 0 && count == 1U
        && packages[0].id == 201;
    if (!first || !second || fake_calls != 1
        || strcmp(fake_endpoint, "https://api.github.com/repos/devShuai/specus/releases/latest") != 0
        || fake_timeout_ms != 8000L || fake_max_response_bytes != 1024U * 1024U) {
        fprintf(stderr, "successful GitHub release response was not cached (calls %d, endpoint %s)\n",
                fake_calls, fake_endpoint);
        return 1;
    }

    st_github_release_cache_reset();
    fake_calls = 0;
    fake_status = 503L;
    count = 99U;
    int failed_first = st_github_release_latest(packages, ST_GITHUB_RELEASE_MAX_PACKAGES, &count) == 0 && count == 0U;
    count = 99U;
    int failed_second = st_github_release_latest(packages, ST_GITHUB_RELEASE_MAX_PACKAGES, &count) == 0 && count == 0U;
    if (!failed_first || !failed_second || fake_calls != 1) {
        fprintf(stderr, "a failed GitHub release refresh was retried at once (calls %d)\n", fake_calls);
        return 1;
    }

    setenv("SPECUS_CLIENT_PACKAGE_GITHUB_RELEASE_FALLBACK_ENABLED", "false", 1);
    st_github_release_cache_reset();
    fake_calls = 0;
    fake_status = 200L;
    count = 99U;
    if (st_github_release_latest(packages, ST_GITHUB_RELEASE_MAX_PACKAGES, &count) != 0 || count != 0U
        || fake_calls != 0) {
        fprintf(stderr, "a disabled GitHub release fallback still asked GitHub\n");
        return 1;
    }
    unsetenv("SPECUS_CLIENT_PACKAGE_GITHUB_RELEASE_FALLBACK_ENABLED");
    st_github_release_set_fetcher_for_testing(NULL);
    st_github_release_cache_reset();
    return 0;
}

int main(void)
{
    if (test_release_cache() != 0) {
        return 1;
    }
    static const char release_json[] =
        "{\"tag_name\":\"v1.2.3-rc.1\",\"published_at\":\"2026-08-28T01:02:03Z\",\"assets\":["
        "{\"id\":101,\"name\":\"specus-client-java-v1.2.3-rc.1.jar\","
        "\"size\":1234,\"digest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
        "\"browser_download_url\":\"https://github.com/devShuai/specus/releases/download/v1.2.3-rc.1/specus-client-java-v1.2.3-rc.1.jar\","
        "\"created_at\":\"2026-08-28T00:00:00Z\"},"
        "{\"id\":102,\"name\":\"specus-client-go-v1.2.3-rc.1-linux-x64.tar.gz\","
        "\"size\":2345,\"digest\":\"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\","
        "\"browser_download_url\":\"https://evil.example/specus.tar.gz\"},"
        "{\"id\":103,\"name\":\"specus-client-android-v1.2.3-rc.1.apk\","
        "\"size\":3456,\"digest\":\"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC\","
        "\"browser_download_url\":\"https://github.com/devShuai/specus/releases/download/v1.2.3-rc.1/specus-client-android-v1.2.3-rc.1.apk\"}]}";
    st_storage_client_download_link packages[ST_GITHUB_RELEASE_MAX_PACKAGES];
    size_t count = 0U;
    if (st_github_release_map(release_json, packages, ST_GITHUB_RELEASE_MAX_PACKAGES, &count) != 0
        || count != 2U
        || strcmp(packages[0].implementation, "java") != 0
        || strcmp(packages[0].version, "1.2.3-rc.1") != 0
        || packages[0].id != 101 || packages[0].file_size != 1234
        || !packages[0].enabled || !packages[0].is_latest || packages[0].hosted
        || strcmp(packages[0].sha256,
                  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") != 0
        || strcmp(packages[0].created_at, "2026-08-28T00:00:00Z") != 0
        || strcmp(packages[1].implementation, "android") != 0
        || strcmp(packages[1].sha256,
                  "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc") != 0) {
        fprintf(stderr, "trusted GitHub release mapping mismatch\n");
        return 1;
    }
    count = 99U;
    if (st_github_release_map("{\"tag_name\":\"not-semver\",\"assets\":[]}",
                              packages, ST_GITHUB_RELEASE_MAX_PACKAGES, &count) != 0
        || count != 0U) {
        fprintf(stderr, "invalid GitHub release tag was accepted\n");
        return 1;
    }
    /* Java SemanticVersion.parse on the trimmed tag: one lowercase "v", 32 characters, no empty identifier. */
    static const char *const refused_tags[] = {
        "V1.2.3", "v1..2.3", "v.1.2.3", "v1.2.3.", "v1.2.3-a..b", "v1.2.3-rc.", "v1.2.3+", "v1.2.3-alpha.beta.gamma.delta.epsil"
    };
    for (size_t i = 0U; i < sizeof(refused_tags) / sizeof(refused_tags[0]); ++i) {
        char json[1024];
        snprintf(json, sizeof(json),
                 "{\"tag_name\":\"%s\",\"assets\":[{\"id\":7,\"name\":\"specus-client-java-%s.jar\","
                 "\"size\":10,\"digest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
                 "\"browser_download_url\":\"https://github.com/devShuai/specus/releases/download/%s/specus-client-java-%s.jar\"}]}",
                 refused_tags[i], refused_tags[i], refused_tags[i], refused_tags[i]);
        count = 99U;
        if (st_github_release_map(json, packages, ST_GITHUB_RELEASE_MAX_PACKAGES, &count) != 0 || count != 0U) {
            fprintf(stderr, "GitHub release tag %s was accepted\n", refused_tags[i]);
            return 1;
        }
    }
    count = 0U;
    if (st_github_release_map(
            "{\"tag_name\":\" v1.2.3 \",\"assets\":[{\"id\":7,\"name\":\"specus-client-java-v1.2.3.jar\","
            "\"size\":10,\"digest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
            "\"browser_download_url\":\"https://github.com/devShuai/specus/releases/download/v1.2.3/specus-client-java-v1.2.3.jar\"}]}",
            packages, ST_GITHUB_RELEASE_MAX_PACKAGES, &count) != 0
        || count != 1U || strcmp(packages[0].version, "1.2.3") != 0
        || strcmp(packages[0].changelog_url, "https://github.com/devShuai/specus/releases/tag/v1.2.3") != 0) {
        fprintf(stderr, "a GitHub release tag with surrounding spaces was not read trimmed\n");
        return 1;
    }
    printf("github release tests passed\n");
    return 0;
}
