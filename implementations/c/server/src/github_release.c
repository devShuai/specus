#define _POSIX_C_SOURCE 200809L

#include "github_release.h"

#include "http_client.h"
#include "json.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#define ST_GITHUB_RELEASE_URI "https://api.github.com/repos/devShuai/specus/releases/latest"
#define ST_GITHUB_RELEASE_MAX_RESPONSE_BYTES (1024U * 1024U)
#define ST_GITHUB_RELEASE_FAILURE_RETRY_SECONDS 300LL

typedef struct {
    const char *implementation;
    const char *platform;
    const char *arch;
    const char *display_name;
    const char *description;
    int display_order;
    char asset_name[256];
} st_release_descriptor;

static pthread_mutex_t release_cache_lock = PTHREAD_MUTEX_INITIALIZER;
static st_storage_client_download_link release_cache[ST_GITHUB_RELEASE_MAX_PACKAGES];
static size_t release_cache_count = 0U;
static time_t release_refresh_after = 0;

static long long release_env_i64(const char *name, long long fallback)
{
    const char *value = getenv(name);
    if (value == NULL || *value == '\0') return fallback;
    errno = 0;
    char *end = NULL;
    long long parsed = strtoll(value, &end, 10);
    return errno == 0 && end != value && *end == '\0' ? parsed : fallback;
}

static int release_env_enabled(void)
{
    const char *value = getenv("SPECUS_CLIENT_PACKAGE_GITHUB_RELEASE_FALLBACK_ENABLED");
    if (value == NULL || *value == '\0') return 1;
    return strcasecmp(value, "true") == 0 || strcmp(value, "1") == 0
        || strcasecmp(value, "yes") == 0 || strcasecmp(value, "on") == 0;
}

static int release_numeric_identifier(const char *value)
{
    if (value == NULL || *value == '\0' || (value[0] == '0' && value[1] != '\0')) return 0;
    for (const unsigned char *p = (const unsigned char *)value; *p != '\0'; ++p) {
        if (!isdigit(*p)) return 0;
    }
    return 1;
}

static int release_validate_identifiers(char *value, int reject_numeric_leading_zero)
{
    if (value == NULL || *value == '\0') return -1;
    char *save = NULL;
    for (char *part = strtok_r(value, ".", &save); part != NULL;
         part = strtok_r(NULL, ".", &save)) {
        if (*part == '\0') return -1;
        int numeric = 1;
        for (const unsigned char *p = (const unsigned char *)part; *p != '\0'; ++p) {
            if (!isalnum(*p) && *p != '-') return -1;
            if (!isdigit(*p)) numeric = 0;
        }
        if (reject_numeric_leading_zero && numeric && !release_numeric_identifier(part)) return -1;
    }
    return 0;
}

static int release_normalize_version(const char *tag, char out[81])
{
    if (tag == NULL || *tag == '\0') return -1;
    const char *normalized = (*tag == 'v' || *tag == 'V') ? tag + 1 : tag;
    size_t len = strlen(normalized);
    if (len == 0U || len >= 81U) return -1;
    char copy[81];
    snprintf(copy, sizeof(copy), "%s", normalized);
    char *build = strchr(copy, '+');
    if (build != NULL) {
        *build++ = '\0';
        if (release_validate_identifiers(build, 0) != 0) return -1;
    }
    char *pre = strchr(copy, '-');
    if (pre != NULL) {
        *pre++ = '\0';
        if (release_validate_identifiers(pre, 1) != 0) return -1;
    }
    char *save = NULL;
    char *major = strtok_r(copy, ".", &save);
    char *minor = strtok_r(NULL, ".", &save);
    char *patch = strtok_r(NULL, ".", &save);
    if (!release_numeric_identifier(major) || !release_numeric_identifier(minor)
        || !release_numeric_identifier(patch) || strtok_r(NULL, ".", &save) != NULL) return -1;
    snprintf(out, 81U, "%s", normalized);
    return 0;
}

static int release_raw_positive_i64(const char *json, const char *key, long long *out)
{
    char *raw = st_json_get_top_level_raw(json, key);
    if (raw == NULL || *raw == '\0') {
        free(raw);
        return -1;
    }
    for (const unsigned char *p = (const unsigned char *)raw; *p != '\0'; ++p) {
        if (!isdigit(*p)) {
            free(raw);
            return -1;
        }
    }
    errno = 0;
    char *end = NULL;
    long long parsed = strtoll(raw, &end, 10);
    int valid = errno == 0 && end != raw && *end == '\0' && parsed > 0;
    free(raw);
    if (!valid) return -1;
    *out = parsed;
    return 0;
}

static int release_digest(const char *value, char out[65])
{
    if (value == NULL) return -1;
    while (isspace((unsigned char)*value)) ++value;
    if (strncasecmp(value, "sha256:", 7U) == 0) value += 7U;
    if (strlen(value) != 64U) return -1;
    for (size_t i = 0U; i < 64U; ++i) {
        if (!isxdigit((unsigned char)value[i])) return -1;
        out[i] = (char)tolower((unsigned char)value[i]);
    }
    out[64] = '\0';
    return 0;
}

static size_t release_descriptors(const char *tag,
                                  st_release_descriptor out[ST_GITHUB_RELEASE_MAX_PACKAGES])
{
    size_t count = 0U;
#define ADD_DESCRIPTOR(impl, plat, architecture, title, detail, order, format, ...) do { \
        st_release_descriptor *item = &out[count++]; \
        item->implementation = (impl); item->platform = (plat); item->arch = (architecture); \
        item->display_name = (title); item->description = (detail); item->display_order = (order); \
        (void)snprintf(item->asset_name, sizeof(item->asset_name), (format), __VA_ARGS__); \
    } while (0)
    ADD_DESCRIPTOR("java", "any", "any", "Java 21 可执行 JAR",
                   "适用于已安装 JDK 21 或更高版本的系统。", 200,
                   "specus-client-java-%s.jar", tag);
    static const char *const go_targets[][3] = {
        {"macos", "arm64", "macOS Apple Silicon"}, {"macos", "x64", "macOS Intel"},
        {"windows", "x64", "Windows x86_64"}, {"windows", "arm64", "Windows ARM64"},
        {"linux", "x64", "Linux x86_64"}, {"linux", "arm64", "Linux ARM64"}
    };
    for (size_t i = 0U; i < sizeof(go_targets) / sizeof(go_targets[0]); ++i) {
        const char *extension = strcmp(go_targets[i][0], "windows") == 0 ? "zip" : "tar.gz";
        ADD_DESCRIPTOR("go", go_targets[i][0], go_targets[i][1], go_targets[i][2],
                       "静态单文件客户端，无需安装运行时。", 100 + (int)i,
                       "specus-client-go-%s-%s-%s.%s", tag, go_targets[i][0], go_targets[i][1], extension);
    }
    ADD_DESCRIPTOR("csharp", "windows", "x64", "Windows 桌面版",
                   "自包含图形客户端，无需单独安装 .NET Runtime。", 300,
                   "specus-desktop-%s-win-x64.zip", tag);
    ADD_DESCRIPTOR("csharp", "any", "any", ".NET 命令行客户端",
                   "跨平台程序集，需要 .NET 10 Runtime。", 310,
                   "specus-client-csharp-%s.tar.gz", tag);
    ADD_DESCRIPTOR("android", "android", "any", "Android 应用",
                   "适用于 Android 8.0 或更高版本。", 400,
                   "specus-client-android-%s.apk", tag);
#undef ADD_DESCRIPTOR
    return count;
}

int st_github_release_map(const char *json,
                          st_storage_client_download_link *out,
                          size_t capacity,
                          size_t *out_count)
{
    if (json == NULL || out == NULL || out_count == NULL) return -1;
    *out_count = 0U;
    char *tag = st_json_get_top_level_string(json, "tag_name");
    char version[81];
    if (tag == NULL || release_normalize_version(tag, version) != 0) {
        free(tag);
        return 0;
    }
    char **assets = NULL;
    size_t asset_count = 0U;
    if (st_json_get_raw_array(json, "assets", &assets, &asset_count) != 0) {
        free(tag);
        return 0;
    }
    char *published = st_json_get_top_level_string(json, "published_at");
    char *created = st_json_get_top_level_string(json, "created_at");
    const char *release_time = published != NULL && *published != '\0'
        ? published : (created == NULL ? "" : created);
    st_release_descriptor descriptors[ST_GITHUB_RELEASE_MAX_PACKAGES];
    size_t descriptor_count = release_descriptors(tag, descriptors);
    for (size_t descriptor_index = 0U;
         descriptor_index < descriptor_count && *out_count < capacity;
         ++descriptor_index) {
        const char *asset = NULL;
        for (size_t asset_index = 0U; asset_index < asset_count; ++asset_index) {
            char *name = st_json_get_top_level_string(assets[asset_index], "name");
            if (name != NULL && strcmp(name, descriptors[descriptor_index].asset_name) == 0) {
                asset = assets[asset_index];
            }
            free(name);
        }
        if (asset == NULL) continue;
        long long id = 0, size = 0;
        char *url = st_json_get_top_level_string(asset, "browser_download_url");
        char *digest = st_json_get_top_level_string(asset, "digest");
        char expected_url[1400];
        int expected_len = snprintf(expected_url, sizeof(expected_url),
            "https://github.com/devShuai/specus/releases/download/%s/%s",
            tag, descriptors[descriptor_index].asset_name);
        char normalized_digest[65];
        if (release_raw_positive_i64(asset, "id", &id) != 0
            || release_raw_positive_i64(asset, "size", &size) != 0
            || expected_len <= 0 || (size_t)expected_len >= sizeof(expected_url)
            || url == NULL || strcasecmp(url, expected_url) != 0
            || release_digest(digest, normalized_digest) != 0) {
            free(url);
            free(digest);
            continue;
        }
        st_storage_client_download_link *link = &out[(*out_count)++];
        memset(link, 0, sizeof(*link));
        link->id = id;
        snprintf(link->implementation, sizeof(link->implementation), "%s", descriptors[descriptor_index].implementation);
        snprintf(link->platform, sizeof(link->platform), "%s", descriptors[descriptor_index].platform);
        snprintf(link->arch, sizeof(link->arch), "%s", descriptors[descriptor_index].arch);
        snprintf(link->display_name, sizeof(link->display_name), "%s", descriptors[descriptor_index].display_name);
        snprintf(link->download_url, sizeof(link->download_url), "%s", url);
        snprintf(link->description, sizeof(link->description), "%s", descriptors[descriptor_index].description);
        link->display_order = descriptors[descriptor_index].display_order;
        link->enabled = 1;
        snprintf(link->version, sizeof(link->version), "%s", version);
        snprintf(link->sha256, sizeof(link->sha256), "%s", normalized_digest);
        link->file_size = size;
        link->is_latest = 1;
        snprintf(link->changelog_url, sizeof(link->changelog_url),
                 "https://github.com/devShuai/specus/releases/tag/%s", tag);
        char *asset_created = st_json_get_top_level_string(asset, "created_at");
        char *asset_updated = st_json_get_top_level_string(asset, "updated_at");
        snprintf(link->created_at, sizeof(link->created_at), "%s",
                 asset_created != NULL && *asset_created != '\0' ? asset_created : release_time);
        snprintf(link->updated_at, sizeof(link->updated_at), "%s",
                 asset_updated != NULL && *asset_updated != '\0' ? asset_updated : release_time);
        free(asset_created);
        free(asset_updated);
        free(url);
        free(digest);
    }
    free(published);
    free(created);
    st_json_free_string_array(assets, asset_count);
    free(tag);
    return 0;
}

void st_github_release_cache_reset(void)
{
    pthread_mutex_lock(&release_cache_lock);
    memset(release_cache, 0, sizeof(release_cache));
    release_cache_count = 0U;
    release_refresh_after = 0;
    pthread_mutex_unlock(&release_cache_lock);
}

int st_github_release_latest(st_storage_client_download_link *out,
                             size_t capacity,
                             size_t *out_count)
{
    if (out == NULL || out_count == NULL) return -1;
    *out_count = 0U;
    if (!release_env_enabled()) return 0;
    pthread_mutex_lock(&release_cache_lock);
    time_t now = time(NULL);
    if (release_refresh_after > now) {
        size_t count = release_cache_count < capacity ? release_cache_count : capacity;
        memcpy(out, release_cache, count * sizeof(*out));
        *out_count = count;
        pthread_mutex_unlock(&release_cache_lock);
        return 0;
    }
    long long timeout_seconds = release_env_i64(
        "SPECUS_CLIENT_PACKAGE_GITHUB_RELEASE_REQUEST_TIMEOUT_SECONDS", 8);
    if (timeout_seconds < 1) timeout_seconds = 1;
    if (timeout_seconds > 30) timeout_seconds = 30;
    st_http_client_options options = {
        .timeout_ms = (long)(timeout_seconds * 1000LL),
        .max_response_bytes = ST_GITHUB_RELEASE_MAX_RESPONSE_BYTES,
        .ca_certificate_path = getenv("SPECUS_CLIENT_PACKAGE_GITHUB_RELEASE_CA_CERTIFICATE_PATH")
    };
    long status = 0L;
    char *body = NULL;
    st_storage_client_download_link fetched[ST_GITHUB_RELEASE_MAX_PACKAGES];
    size_t fetched_count = 0U;
    int fetch_ok = st_http_get_json(ST_GITHUB_RELEASE_URI, &options, &status, &body) == 0
        && status >= 200L && status < 300L && body != NULL && *body != '\0'
        && st_github_release_map(body, fetched, ST_GITHUB_RELEASE_MAX_PACKAGES, &fetched_count) == 0
        && fetched_count > 0U;
    free(body);
    if (fetch_ok) {
        memcpy(release_cache, fetched, fetched_count * sizeof(*fetched));
        release_cache_count = fetched_count;
        long long cache_seconds = release_env_i64(
            "SPECUS_CLIENT_PACKAGE_GITHUB_RELEASE_CACHE_SECONDS", 1800);
        if (cache_seconds < 60) cache_seconds = 60;
        if (cache_seconds > 86400) cache_seconds = 86400;
        release_refresh_after = now + (time_t)cache_seconds;
    } else {
        release_refresh_after = now + (time_t)ST_GITHUB_RELEASE_FAILURE_RETRY_SECONDS;
    }
    size_t count = release_cache_count < capacity ? release_cache_count : capacity;
    memcpy(out, release_cache, count * sizeof(*out));
    *out_count = count;
    pthread_mutex_unlock(&release_cache_lock);
    return 0;
}
