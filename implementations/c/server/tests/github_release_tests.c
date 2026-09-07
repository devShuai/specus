#include "github_release.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
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
    printf("github release tests passed\n");
    return 0;
}
