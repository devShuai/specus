#define _XOPEN_SOURCE 700
#define _POSIX_C_SOURCE 200809L

#include "client_package.h"

#include "crypto.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define ST_PACKAGE_DEFAULT_MAX_BYTES (512ULL * 1024ULL * 1024ULL)
#define ST_PACKAGE_DEFAULT_MAX_REQUEST_BYTES (513ULL * 1024ULL * 1024ULL)
#define ST_PACKAGE_BOUNDARY_MAX 200U
#define ST_PACKAGE_PART_HEADERS_MAX 8192U
#define ST_PACKAGE_RATE_TABLE_CAPACITY 100003U
#define ST_PACKAGE_RATE_SOURCE_MAX 127U

typedef struct {
    char source[ST_PACKAGE_RATE_SOURCE_MAX + 1U];
    time_t started_at;
    unsigned int count;
} st_package_rate_window;

static pthread_mutex_t package_rate_lock = PTHREAD_MUTEX_INITIALIZER;
static st_package_rate_window *package_rate_windows = NULL;

typedef struct {
    char implementation[33];
    char platform[33];
    char arch[33];
    char version[81];
    char display_name[121];
    char description[513];
    char changelog_url[1025];
    char min_supported_version[81];
    char display_order[32];
    char enabled[16];
    char is_latest[16];
    const uint8_t *file;
    size_t file_len;
    unsigned int seen;
} st_package_form;

enum {
    ST_PACKAGE_SEEN_IMPLEMENTATION = 1U << 0,
    ST_PACKAGE_SEEN_PLATFORM = 1U << 1,
    ST_PACKAGE_SEEN_ARCH = 1U << 2,
    ST_PACKAGE_SEEN_VERSION = 1U << 3,
    ST_PACKAGE_SEEN_DISPLAY_NAME = 1U << 4,
    ST_PACKAGE_SEEN_DESCRIPTION = 1U << 5,
    ST_PACKAGE_SEEN_CHANGELOG_URL = 1U << 6,
    ST_PACKAGE_SEEN_MIN_VERSION = 1U << 7,
    ST_PACKAGE_SEEN_DISPLAY_ORDER = 1U << 8,
    ST_PACKAGE_SEEN_ENABLED = 1U << 9,
    ST_PACKAGE_SEEN_LATEST = 1U << 10,
    ST_PACKAGE_SEEN_FILE = 1U << 11
};

static void package_error(char *error, size_t error_len, const char *message)
{
    if (error != NULL && error_len > 0U) {
        snprintf(error, error_len, "%s", message == NULL ? "client package failed" : message);
    }
}

static unsigned long long package_env_u64(const char *name,
                                           unsigned long long fallback,
                                           unsigned long long minimum,
                                           unsigned long long maximum)
{
    const char *value = getenv(name);
    if (value == NULL || *value == '\0') return fallback;
    errno = 0;
    char *end = NULL;
    unsigned long long parsed = strtoull(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed < minimum || parsed > maximum) {
        return fallback;
    }
    return parsed;
}

static uint64_t package_rate_hash(const char *value)
{
    uint64_t hash = UINT64_C(1469598103934665603);
    for (const unsigned char *cursor = (const unsigned char *)value; *cursor != '\0'; ++cursor) {
        hash ^= *cursor;
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

void st_client_package_rate_limit_reset(void)
{
    pthread_mutex_lock(&package_rate_lock);
    free(package_rate_windows);
    package_rate_windows = NULL;
    pthread_mutex_unlock(&package_rate_lock);
}

int st_client_package_rate_limit(const char *remote_address,
                                 long long *retry_after_seconds)
{
    unsigned int limit = (unsigned int)package_env_u64(
        "SPECUS_CLIENT_PACKAGE_PUBLIC_RATE_LIMIT_PER_IP", 120ULL, 1ULL, UINT_MAX);
    time_t window_seconds = (time_t)package_env_u64(
        "SPECUS_CLIENT_PACKAGE_PUBLIC_RATE_LIMIT_WINDOW_SECONDS", 60ULL, 1ULL, INT_MAX);
    const char *source = remote_address;
    if (source == NULL || *source == '\0' || strlen(source) > ST_PACKAGE_RATE_SOURCE_MAX) {
        source = "unknown";
    }
    time_t now = time(NULL);
    if (retry_after_seconds != NULL) *retry_after_seconds = 1;

    pthread_mutex_lock(&package_rate_lock);
    if (package_rate_windows == NULL) {
        package_rate_windows = (st_package_rate_window *)calloc(
            ST_PACKAGE_RATE_TABLE_CAPACITY, sizeof(*package_rate_windows));
        if (package_rate_windows == NULL) {
            pthread_mutex_unlock(&package_rate_lock);
            return -1;
        }
    }
    size_t start = (size_t)(package_rate_hash(source) % ST_PACKAGE_RATE_TABLE_CAPACITY);
    size_t reusable = SIZE_MAX;
    st_package_rate_window *matched = NULL;
    for (size_t probe = 0U; probe < ST_PACKAGE_RATE_TABLE_CAPACITY; ++probe) {
        size_t index = (start + probe) % ST_PACKAGE_RATE_TABLE_CAPACITY;
        st_package_rate_window *candidate = &package_rate_windows[index];
        if (candidate->source[0] == '\0') {
            if (reusable == SIZE_MAX) reusable = index;
            break;
        }
        int expired = now < candidate->started_at
            || now - candidate->started_at >= window_seconds;
        if (strcmp(candidate->source, source) == 0) {
            matched = candidate;
            if (expired) {
                candidate->started_at = now;
                candidate->count = 0U;
            }
            break;
        }
        if (expired && reusable == SIZE_MAX) reusable = index;
    }
    if (matched == NULL && reusable != SIZE_MAX) {
        matched = &package_rate_windows[reusable];
        snprintf(matched->source, sizeof(matched->source), "%s", source);
        matched->started_at = now;
        matched->count = 0U;
    }
    if (matched == NULL) {
        if (retry_after_seconds != NULL) *retry_after_seconds = (long long)window_seconds;
        pthread_mutex_unlock(&package_rate_lock);
        return 1;
    }
    ++matched->count;
    if (matched->count > limit) {
        time_t elapsed = now >= matched->started_at ? now - matched->started_at : 0;
        time_t retry = window_seconds > elapsed ? window_seconds - elapsed : 1;
        if (retry_after_seconds != NULL) *retry_after_seconds = retry > 0 ? (long long)retry : 1;
        pthread_mutex_unlock(&package_rate_lock);
        return 1;
    }
    pthread_mutex_unlock(&package_rate_lock);
    return 0;
}

static size_t package_max_bytes(void)
{
    unsigned long long value = package_env_u64("SPECUS_CLIENT_PACKAGE_MAX_BYTES",
                                               ST_PACKAGE_DEFAULT_MAX_BYTES,
                                               1ULL,
                                               (unsigned long long)SIZE_MAX);
    return (size_t)value;
}

size_t st_client_package_max_request_bytes(void)
{
    unsigned long long value = package_env_u64("SPECUS_CLIENT_PACKAGE_MULTIPART_MAX_REQUEST_BYTES",
                                               ST_PACKAGE_DEFAULT_MAX_REQUEST_BYTES,
                                               1ULL,
                                               (unsigned long long)SIZE_MAX);
    return (size_t)value;
}

static const uint8_t *package_memmem(const uint8_t *haystack,
                                     size_t haystack_len,
                                     const uint8_t *needle,
                                     size_t needle_len)
{
    if (needle_len == 0U) return haystack;
    if (haystack == NULL || needle == NULL || haystack_len < needle_len) return NULL;
    size_t last = haystack_len - needle_len;
    for (size_t i = 0U; i <= last; ++i) {
        if (haystack[i] == needle[0] && memcmp(haystack + i, needle, needle_len) == 0) {
            return haystack + i;
        }
    }
    return NULL;
}

static int package_boundary(const char *content_type, char *out, size_t out_len)
{
    static const char multipart[] = "multipart/form-data";
    if (content_type == NULL || strncasecmp(content_type, multipart, sizeof(multipart) - 1U) != 0) {
        return -1;
    }
    const char *cursor = content_type + sizeof(multipart) - 1U;
    while (*cursor != '\0') {
        while (*cursor == ';' || isspace((unsigned char)*cursor)) ++cursor;
        const char *name = cursor;
        while (*cursor != '\0' && *cursor != '=' && *cursor != ';') ++cursor;
        const char *name_end = cursor;
        while (name_end > name && isspace((unsigned char)name_end[-1])) --name_end;
        if (*cursor != '=') {
            while (*cursor != '\0' && *cursor != ';') ++cursor;
            continue;
        }
        ++cursor;
        while (isspace((unsigned char)*cursor)) ++cursor;
        const char *value = cursor;
        const char *value_end = NULL;
        if (*cursor == '"') {
            value = ++cursor;
            while (*cursor != '\0' && *cursor != '"') ++cursor;
            if (*cursor != '"') return -1;
            value_end = cursor++;
        } else {
            while (*cursor != '\0' && *cursor != ';' && !isspace((unsigned char)*cursor)) ++cursor;
            value_end = cursor;
        }
        if ((size_t)(name_end - name) == 8U && strncasecmp(name, "boundary", 8U) == 0) {
            size_t len = (size_t)(value_end - value);
            if (len == 0U || len > ST_PACKAGE_BOUNDARY_MAX || len >= out_len) return -1;
            for (size_t i = 0U; i < len; ++i) {
                unsigned char c = (unsigned char)value[i];
                if (c <= 0x20U || c == 0x7fU) return -1;
            }
            memcpy(out, value, len);
            out[len] = '\0';
            return 0;
        }
    }
    return -1;
}

static int package_disposition_name(const uint8_t *headers,
                                    size_t headers_len,
                                    char *name,
                                    size_t name_len)
{
    if (headers_len == 0U || headers_len > ST_PACKAGE_PART_HEADERS_MAX) return -1;
    char copy[ST_PACKAGE_PART_HEADERS_MAX + 1U];
    memcpy(copy, headers, headers_len);
    copy[headers_len] = '\0';
    char *line = copy;
    while (line != NULL && *line != '\0') {
        char *next = strstr(line, "\r\n");
        if (next != NULL) *next = '\0';
        if (strncasecmp(line, "Content-Disposition:", 20U) == 0) {
            char *cursor = line + 20U;
            while (*cursor != '\0') {
                while (*cursor == ';' || isspace((unsigned char)*cursor)) ++cursor;
                if (strncmp(cursor, "name=\"", 6U) == 0) {
                    cursor += 6U;
                    char *end = strchr(cursor, '"');
                    if (end == NULL || end == cursor || (size_t)(end - cursor) >= name_len) return -1;
                    memcpy(name, cursor, (size_t)(end - cursor));
                    name[end - cursor] = '\0';
                    return 0;
                }
                char *semicolon = strchr(cursor, ';');
                if (semicolon == NULL) break;
                cursor = semicolon + 1;
            }
            return -1;
        }
        line = next == NULL ? NULL : next + 2U;
    }
    return -1;
}

static int package_copy_text(const uint8_t *value, size_t value_len, char *out, size_t out_len)
{
    if (value_len >= out_len) return -1;
    for (size_t i = 0U; i < value_len; ++i) {
        if (value[i] == '\0' || value[i] == '\r' || value[i] == '\n') return -1;
    }
    memcpy(out, value, value_len);
    out[value_len] = '\0';
    return 0;
}

static int package_store_part(st_package_form *form,
                              const char *name,
                              const uint8_t *value,
                              size_t value_len)
{
#define PACKAGE_TEXT_PART(part_name, member, bit) \
    if (strcmp(name, part_name) == 0) { \
        if ((form->seen & (bit)) != 0U || package_copy_text(value, value_len, form->member, sizeof(form->member)) != 0) return -1; \
        form->seen |= (bit); \
        return 0; \
    }
    PACKAGE_TEXT_PART("implementation", implementation, ST_PACKAGE_SEEN_IMPLEMENTATION)
    PACKAGE_TEXT_PART("platform", platform, ST_PACKAGE_SEEN_PLATFORM)
    PACKAGE_TEXT_PART("arch", arch, ST_PACKAGE_SEEN_ARCH)
    PACKAGE_TEXT_PART("version", version, ST_PACKAGE_SEEN_VERSION)
    PACKAGE_TEXT_PART("displayName", display_name, ST_PACKAGE_SEEN_DISPLAY_NAME)
    PACKAGE_TEXT_PART("description", description, ST_PACKAGE_SEEN_DESCRIPTION)
    PACKAGE_TEXT_PART("changelogUrl", changelog_url, ST_PACKAGE_SEEN_CHANGELOG_URL)
    PACKAGE_TEXT_PART("minSupportedVersion", min_supported_version, ST_PACKAGE_SEEN_MIN_VERSION)
    PACKAGE_TEXT_PART("displayOrder", display_order, ST_PACKAGE_SEEN_DISPLAY_ORDER)
    PACKAGE_TEXT_PART("enabled", enabled, ST_PACKAGE_SEEN_ENABLED)
    PACKAGE_TEXT_PART("isLatest", is_latest, ST_PACKAGE_SEEN_LATEST)
#undef PACKAGE_TEXT_PART
    if (strcmp(name, "file") == 0) {
        if ((form->seen & ST_PACKAGE_SEEN_FILE) != 0U) return -1;
        form->file = value;
        form->file_len = value_len;
        form->seen |= ST_PACKAGE_SEEN_FILE;
    }
    return 0;
}

static int package_parse_form(const char *content_type,
                              const uint8_t *body,
                              size_t body_len,
                              st_package_form *form)
{
    char boundary[ST_PACKAGE_BOUNDARY_MAX + 1U];
    if (package_boundary(content_type, boundary, sizeof(boundary)) != 0) return -1;
    char delimiter[ST_PACKAGE_BOUNDARY_MAX + 3U];
    int delimiter_len = snprintf(delimiter, sizeof(delimiter), "--%s", boundary);
    if (delimiter_len <= 0 || (size_t)delimiter_len >= sizeof(delimiter)) return -1;
    char marker[ST_PACKAGE_BOUNDARY_MAX + 5U];
    int marker_len = snprintf(marker, sizeof(marker), "\r\n--%s", boundary);
    if (marker_len <= 0 || (size_t)marker_len >= sizeof(marker)) return -1;
    if (body_len < (size_t)delimiter_len + 2U
        || memcmp(body, delimiter, (size_t)delimiter_len) != 0) return -1;
    memset(form, 0, sizeof(*form));
    const uint8_t *cursor = body + delimiter_len;
    const uint8_t *end = body + body_len;
    for (;;) {
        if ((size_t)(end - cursor) >= 2U && cursor[0] == '-' && cursor[1] == '-') {
            cursor += 2U;
            return cursor == end || ((size_t)(end - cursor) == 2U
                                     && cursor[0] == '\r' && cursor[1] == '\n') ? 0 : -1;
        }
        if ((size_t)(end - cursor) < 2U || cursor[0] != '\r' || cursor[1] != '\n') return -1;
        cursor += 2U;
        static const uint8_t separator[] = "\r\n\r\n";
        const uint8_t *headers_end = package_memmem(cursor, (size_t)(end - cursor),
                                                     separator, sizeof(separator) - 1U);
        if (headers_end == NULL || (size_t)(headers_end - cursor) > ST_PACKAGE_PART_HEADERS_MAX) return -1;
        const uint8_t *value = headers_end + sizeof(separator) - 1U;
        const uint8_t *part_end = package_memmem(value, (size_t)(end - value),
                                                 (const uint8_t *)marker, (size_t)marker_len);
        if (part_end == NULL) return -1;
        char name[64];
        if (package_disposition_name(cursor, (size_t)(headers_end - cursor), name, sizeof(name)) != 0
            || package_store_part(form, name, value, (size_t)(part_end - value)) != 0) return -1;
        cursor = part_end + 2U + (size_t)delimiter_len;
    }
}

static char *package_trim(char *value)
{
    while (isspace((unsigned char)*value)) ++value;
    char *end = value + strlen(value);
    while (end > value && isspace((unsigned char)end[-1])) --end;
    *end = '\0';
    return value;
}

static int package_lower_enum(char *value,
                              char *out,
                              size_t out_len,
                              const char *const *allowed,
                              size_t allowed_len)
{
    char *trimmed = package_trim(value);
    size_t len = strlen(trimmed);
    if (len == 0U || len >= out_len) return -1;
    for (size_t i = 0U; i < len; ++i) out[i] = (char)tolower((unsigned char)trimmed[i]);
    out[len] = '\0';
    for (size_t i = 0U; i < allowed_len; ++i) if (strcmp(out, allowed[i]) == 0) return 0;
    return -1;
}

static int package_numeric_identifier(const char *value)
{
    if (value == NULL || *value == '\0' || (value[0] == '0' && value[1] != '\0')) return 0;
    for (const unsigned char *p = (const unsigned char *)value; *p != '\0'; ++p) {
        if (!isdigit(*p)) return 0;
    }
    return 1;
}

static int package_semver(const char *value)
{
    if (value == NULL || *value == '\0' || strlen(value) > 32U) return -1;
    char copy[33];
    snprintf(copy, sizeof(copy), "%s", value);
    char *build = strchr(copy, '+');
    if (build != NULL) {
        if (build[1] == '\0') return -1;
        for (char *p = build + 1; *p != '\0'; ++p) {
            if (!isalnum((unsigned char)*p) && *p != '-' && *p != '.') return -1;
        }
        *build = '\0';
    }
    char *pre = strchr(copy, '-');
    if (pre != NULL) {
        *pre++ = '\0';
        if (*pre == '\0') return -1;
        char *save = NULL;
        for (char *part = strtok_r(pre, ".", &save); part != NULL; part = strtok_r(NULL, ".", &save)) {
            if (*part == '\0') return -1;
            int numeric = 1;
            for (char *p = part; *p != '\0'; ++p) {
                if (!isalnum((unsigned char)*p) && *p != '-') return -1;
                if (!isdigit((unsigned char)*p)) numeric = 0;
            }
            if (numeric && !package_numeric_identifier(part)) return -1;
        }
    }
    char *save = NULL;
    char *major = strtok_r(copy, ".", &save);
    char *minor = strtok_r(NULL, ".", &save);
    char *patch = strtok_r(NULL, ".", &save);
    return package_numeric_identifier(major) && package_numeric_identifier(minor)
        && package_numeric_identifier(patch) && strtok_r(NULL, ".", &save) == NULL ? 0 : -1;
}

static int package_compare_numeric(const char *left, const char *right)
{
    size_t left_len = strlen(left), right_len = strlen(right);
    if (left_len != right_len) return left_len < right_len ? -1 : 1;
    int compared = strcmp(left, right);
    return compared < 0 ? -1 : (compared > 0 ? 1 : 0);
}

static int package_semver_compare(const char *left, const char *right)
{
    char left_copy[33], right_copy[33];
    snprintf(left_copy, sizeof(left_copy), "%s", left);
    snprintf(right_copy, sizeof(right_copy), "%s", right);
    char *special = strchr(left_copy, '+');
    if (special != NULL) *special = '\0';
    special = strchr(right_copy, '+');
    if (special != NULL) *special = '\0';
    char *left_pre = strchr(left_copy, '-');
    if (left_pre != NULL) *left_pre++ = '\0';
    char *right_pre = strchr(right_copy, '-');
    if (right_pre != NULL) *right_pre++ = '\0';
    char *ls = NULL, *rs = NULL;
    char *lp = strtok_r(left_copy, ".", &ls), *rp = strtok_r(right_copy, ".", &rs);
    while (lp != NULL && rp != NULL) {
        int compared = package_compare_numeric(lp, rp);
        if (compared != 0) return compared;
        lp = strtok_r(NULL, ".", &ls);
        rp = strtok_r(NULL, ".", &rs);
    }
    if (left_pre == NULL || right_pre == NULL) {
        return left_pre == right_pre ? 0 : (left_pre == NULL ? 1 : -1);
    }
    char *left_save = NULL, *right_save = NULL;
    char *left_part = strtok_r(left_pre, ".", &left_save);
    char *right_part = strtok_r(right_pre, ".", &right_save);
    while (left_part != NULL && right_part != NULL) {
        int left_numeric = package_numeric_identifier(left_part);
        int right_numeric = package_numeric_identifier(right_part);
        int compared = 0;
        if (left_numeric && right_numeric) compared = package_compare_numeric(left_part, right_part);
        else if (left_numeric != right_numeric) compared = left_numeric ? -1 : 1;
        else {
            compared = strcmp(left_part, right_part);
            compared = compared < 0 ? -1 : (compared > 0 ? 1 : 0);
        }
        if (compared != 0) return compared;
        left_part = strtok_r(NULL, ".", &left_save);
        right_part = strtok_r(NULL, ".", &right_save);
    }
    return left_part == right_part ? 0 : (left_part == NULL ? -1 : 1);
}

static int package_parse_bool(char *value, int fallback, int *out)
{
    if (value == NULL || *value == '\0') {
        *out = fallback;
        return 0;
    }
    char *trimmed = package_trim(value);
    if (strcasecmp(trimmed, "true") == 0) *out = 1;
    else if (strcasecmp(trimmed, "false") == 0) *out = 0;
    else return -1;
    return 0;
}

static int package_http_url(char *value)
{
    if (value == NULL || *value == '\0') return 0;
    char *trimmed = package_trim(value);
    const char *authority = NULL;
    if (strncasecmp(trimmed, "http://", 7U) == 0) authority = trimmed + 7U;
    else if (strncasecmp(trimmed, "https://", 8U) == 0) authority = trimmed + 8U;
    else return -1;
    if (*authority == '\0' || *authority == '/' || strchr(authority, '@') != NULL) return -1;
    for (const unsigned char *p = (const unsigned char *)trimmed; *p != '\0'; ++p) {
        if (*p <= 0x20U || *p == 0x7fU || *p == '\\') return -1;
    }
    return 0;
}

static int package_validate_form(st_package_form *form,
                                 st_storage_client_download_link *metadata,
                                 int *latest,
                                 char *error,
                                 size_t error_len)
{
    static const char *const implementations[] = {"java", "go", "csharp", "android"};
    static const char *const platforms[] = {"windows", "linux", "macos", "android", "any"};
    static const char *const arches[] = {"x64", "arm64", "any"};
    unsigned int required = ST_PACKAGE_SEEN_IMPLEMENTATION | ST_PACKAGE_SEEN_PLATFORM
        | ST_PACKAGE_SEEN_ARCH | ST_PACKAGE_SEEN_VERSION | ST_PACKAGE_SEEN_DISPLAY_NAME
        | ST_PACKAGE_SEEN_FILE;
    if ((form->seen & required) != required || form->file_len == 0U) {
        package_error(error, error_len, "file and required package metadata are required");
        return -1;
    }
    memset(metadata, 0, sizeof(*metadata));
    if (package_lower_enum(form->implementation, metadata->implementation, sizeof(metadata->implementation),
                           implementations, 4U) != 0
        || package_lower_enum(form->platform, metadata->platform, sizeof(metadata->platform),
                              platforms, 5U) != 0
        || package_lower_enum(form->arch, metadata->arch, sizeof(metadata->arch), arches, 3U) != 0) {
        package_error(error, error_len, "invalid implementation, platform or arch");
        return -1;
    }
    char *display_name = package_trim(form->display_name);
    char *version = package_trim(form->version);
    if (*version == 'v') ++version;
    char *minimum = package_trim(form->min_supported_version);
    if (*minimum == 'v') ++minimum;
    if (*display_name == '\0' || strlen(display_name) > 120U || package_semver(version) != 0
        || (*minimum != '\0' && (package_semver(minimum) != 0
                                 || package_semver_compare(minimum, version) > 0))) {
        package_error(error, error_len, "invalid displayName, version or minSupportedVersion");
        return -1;
    }
    if ((strcmp(metadata->implementation, "android") == 0
         && (strcmp(metadata->platform, "android") != 0 || strcmp(metadata->arch, "any") != 0))
        || (strcmp(metadata->platform, "android") == 0
            && (strcmp(metadata->implementation, "android") != 0 || strcmp(metadata->arch, "any") != 0))) {
        package_error(error, error_len, "android packages require android/any");
        return -1;
    }
    if (package_http_url(form->changelog_url) != 0) {
        package_error(error, error_len, "changelogUrl must be an absolute http(s) URL");
        return -1;
    }
    int enabled = 1;
    if (package_parse_bool(form->enabled, 1, &enabled) != 0
        || package_parse_bool(form->is_latest, 0, latest) != 0 || (!enabled && *latest)) {
        package_error(error, error_len, "invalid enabled/isLatest combination");
        return -1;
    }
    int display_order = 0;
    if (form->display_order[0] != '\0') {
        errno = 0;
        char *end = NULL;
        long parsed = strtol(package_trim(form->display_order), &end, 10);
        if (errno != 0 || end == form->display_order || *end != '\0'
            || parsed < INT_MIN || parsed > INT_MAX) {
            package_error(error, error_len, "displayOrder must be an integer");
            return -1;
        }
        display_order = (int)parsed;
    }
    snprintf(metadata->display_name, sizeof(metadata->display_name), "%s", display_name);
    snprintf(metadata->version, sizeof(metadata->version), "%s", version);
    snprintf(metadata->description, sizeof(metadata->description), "%s", package_trim(form->description));
    snprintf(metadata->changelog_url, sizeof(metadata->changelog_url), "%s", package_trim(form->changelog_url));
    snprintf(metadata->min_supported_version, sizeof(metadata->min_supported_version), "%s", minimum);
    metadata->display_order = display_order;
    metadata->enabled = enabled;
    return 0;
}

static int package_mkdir_tree(const char *path)
{
    if (path == NULL || *path == '\0' || strlen(path) >= PATH_MAX) return -1;
    char copy[PATH_MAX];
    snprintf(copy, sizeof(copy), "%s", path);
    size_t len = strlen(copy);
    while (len > 1U && copy[len - 1U] == '/') copy[--len] = '\0';
    for (char *p = copy + (copy[0] == '/' ? 1 : 0); ; ++p) {
        if (*p != '/' && *p != '\0') continue;
        char saved = *p;
        *p = '\0';
        if (*copy != '\0') {
            struct stat st;
            if (lstat(copy, &st) != 0) {
                if (errno != ENOENT || mkdir(copy, 0700) != 0) return -1;
                if (lstat(copy, &st) != 0) return -1;
            }
            if (!S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode)) return -1;
        }
        *p = saved;
        if (saved == '\0') break;
    }
    return 0;
}

static int package_root(char out[PATH_MAX])
{
    const char *data = getenv("SPECUS_CLIENT_PACKAGE_DATA_DIRECTORY");
    if (data == NULL || *data == '\0') data = "./data";
    char configured[PATH_MAX];
    int written = snprintf(configured, sizeof(configured), "%s/packages", data);
    if (written <= 0 || (size_t)written >= sizeof(configured)
        || package_mkdir_tree(configured) != 0 || realpath(configured, out) == NULL) return -1;
    struct stat st;
    return lstat(out, &st) == 0 && S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode) ? 0 : -1;
}

static int package_path_for(long long id, char out[PATH_MAX])
{
    char root[PATH_MAX];
    if (id <= 0 || package_root(root) != 0) return -1;
    int written = snprintf(out, PATH_MAX, "%s/%lld", root, id);
    return written > 0 && written < PATH_MAX ? 0 : -1;
}

static void package_download_name(const st_storage_client_download_link *link, char out[256])
{
    size_t written = 0U;
    const char *source = link->display_name[0] == '\0' ? "specus-client" : link->display_name;
    for (const unsigned char *p = (const unsigned char *)source; *p != '\0' && written < 160U; ++p) {
        if (*p < 0x20U || *p == 0x7fU) continue;
        out[written++] = strchr("\\/:*?\"<>|", (char)*p) == NULL ? (char)*p : '_';
    }
    while (written > 0U && (out[written - 1U] == '.' || isspace((unsigned char)out[written - 1U]))) --written;
    if (written == 0U) written = (size_t)snprintf(out, 256U, "specus-client-%lld", link->id);
    out[written] = '\0';
    if (strcmp(link->implementation, "android") == 0 && strcmp(link->platform, "android") == 0
        && strcmp(link->arch, "any") == 0) {
        size_t len = strlen(out);
        if ((len < 4U || strcasecmp(out + len - 4U, ".apk") != 0) && len + 4U < 256U) strcat(out, ".apk");
    }
}

static int package_write_all(int fd, const uint8_t *data, size_t len)
{
    size_t offset = 0U;
    while (offset < len) {
        ssize_t written = write(fd, data + offset, len - offset);
        if (written < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (written == 0) return -1;
        offset += (size_t)written;
    }
    return 0;
}

int st_client_package_upload(const char *database_path,
                             const char *content_type,
                             const uint8_t *body,
                             size_t body_len,
                             st_storage_client_download_link *out_link,
                             int *http_status,
                             char *error,
                             size_t error_len)
{
    if (http_status != NULL) *http_status = 400;
    st_package_form form;
    if (body == NULL || package_parse_form(content_type, body, body_len, &form) != 0) {
        package_error(error, error_len, "invalid multipart client package request");
        return -1;
    }
    st_storage_client_download_link metadata;
    int latest = 0;
    if (package_validate_form(&form, &metadata, &latest, error, error_len) != 0) return -1;
    if (form.file_len > package_max_bytes()) {
        if (http_status != NULL) *http_status = 413;
        package_error(error, error_len, "file exceeds max package size");
        return -1;
    }
    if (database_path == NULL || st_storage_init(database_path, 0) != 0) {
        if (http_status != NULL) *http_status = 500;
        package_error(error, error_len, "client package database unavailable");
        return -1;
    }
    char root[PATH_MAX];
    if (package_root(root) != 0) {
        if (http_status != NULL) *http_status = 500;
        package_error(error, error_len, "cannot prepare client package directory");
        return -1;
    }
    char temporary[PATH_MAX];
    int temp_written = snprintf(temporary, sizeof(temporary), "%s/.upload-XXXXXX", root);
    if (temp_written <= 0 || (size_t)temp_written >= sizeof(temporary)) return -1;
    int file_fd = mkstemp(temporary);
    if (file_fd < 0 || fchmod(file_fd, 0600) != 0
        || package_write_all(file_fd, form.file, form.file_len) != 0 || fsync(file_fd) != 0) {
        if (file_fd >= 0) close(file_fd);
        unlink(temporary);
        if (http_status != NULL) *http_status = 500;
        package_error(error, error_len, "cannot stage client package");
        return -1;
    }
    if (close(file_fd) != 0) {
        unlink(temporary);
        if (http_status != NULL) *http_status = 500;
        package_error(error, error_len, "cannot stage client package");
        return -1;
    }
    uint8_t digest[ST_SHA256_LEN];
    st_sha256(form.file, form.file_len, digest);
    st_hex_encode(digest, sizeof(digest), metadata.sha256);
    metadata.file_size = (long long)form.file_len;
    package_download_name(&metadata, metadata.package_file_name);
    st_storage_client_download_link pending;
    if (st_storage_upsert_client_download_link_extended(database_path, 0,
            metadata.implementation, metadata.platform, metadata.arch, metadata.display_name,
            "pending", metadata.description, metadata.display_order, 0, metadata.version,
            metadata.sha256, metadata.file_size, 0, metadata.changelog_url,
            metadata.min_supported_version, 1, NULL, metadata.package_file_name, &pending) != 0) {
        unlink(temporary);
        if (http_status != NULL) *http_status = 409;
        package_error(error, error_len, "client package catalogue create failed");
        return -1;
    }
    char final_path[PATH_MAX];
    char download_url[128];
    int final_written = snprintf(final_path, sizeof(final_path), "%s/%lld", root, pending.id);
    int url_written = snprintf(download_url, sizeof(download_url),
                               "/api/public/client-packages/%lld/download", pending.id);
    struct stat existing;
    if (final_written <= 0 || (size_t)final_written >= sizeof(final_path)
        || url_written <= 0 || (size_t)url_written >= sizeof(download_url)
        || (lstat(final_path, &existing) == 0 || errno != ENOENT)
        || rename(temporary, final_path) != 0) {
        unlink(temporary);
        (void)st_storage_delete_client_download_link(database_path, pending.id);
        if (http_status != NULL) *http_status = 500;
        package_error(error, error_len, "cannot publish client package");
        return -1;
    }
    st_storage_client_download_link published;
    if (st_storage_upsert_client_download_link_extended(database_path, pending.id,
            metadata.implementation, metadata.platform, metadata.arch, metadata.display_name,
            download_url, metadata.description, metadata.display_order, metadata.enabled,
            metadata.version, metadata.sha256, metadata.file_size, latest,
            metadata.changelog_url, metadata.min_supported_version, 1, final_path,
            metadata.package_file_name, &published) != 0) {
        unlink(final_path);
        (void)st_storage_delete_client_download_link(database_path, pending.id);
        if (http_status != NULL) *http_status = 409;
        package_error(error, error_len, "client package publish failed");
        return -1;
    }
    if (out_link != NULL) *out_link = published;
    if (http_status != NULL) *http_status = 201;
    return 0;
}

int st_client_package_is_readable(const st_storage_client_download_link *link)
{
    if (link == NULL || !link->hosted || link->id <= 0 || link->file_size <= 0) return 0;
    char path[PATH_MAX];
    if (package_path_for(link->id, path) != 0) return 0;
    struct stat before;
    if (lstat(path, &before) != 0 || !S_ISREG(before.st_mode) || S_ISLNK(before.st_mode)
        || before.st_size != link->file_size) return 0;
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return 0;
    struct stat after;
    int ok = fstat(fd, &after) == 0 && S_ISREG(after.st_mode)
        && after.st_dev == before.st_dev && after.st_ino == before.st_ino
        && after.st_size == link->file_size;
    close(fd);
    return ok;
}

static int package_send_all(int fd, const void *buffer, size_t len)
{
    const uint8_t *bytes = (const uint8_t *)buffer;
    size_t offset = 0U;
    while (offset < len) {
        ssize_t sent = send(fd, bytes + offset, len - offset, 0);
        if (sent < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (sent == 0) return -1;
        offset += (size_t)sent;
    }
    return 0;
}

static void package_send_error(int fd, int status, const char *reason, const char *message)
{
    char body[512];
    int body_len = snprintf(body, sizeof(body), "{\"error\":\"%s\"}", message);
    char header[512];
    int header_len = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nCache-Control: no-store\r\n"
        "X-Content-Type-Options: nosniff\r\nContent-Length: %d\r\n\r\n",
        status, reason, body_len);
    if (body_len > 0 && (size_t)body_len < sizeof(body)
        && header_len > 0 && (size_t)header_len < sizeof(header)) {
        (void)package_send_all(fd, header, (size_t)header_len);
        (void)package_send_all(fd, body, (size_t)body_len);
    }
}

static int package_parse_download_path(const char *path, long long *id)
{
    static const char prefix[] = "/api/public/client-packages/";
    static const char suffix[] = "/download";
    if (strncmp(path, prefix, sizeof(prefix) - 1U) != 0) return -1;
    char *end = NULL;
    long long parsed = strtoll(path + sizeof(prefix) - 1U, &end, 10);
    if (end == path + sizeof(prefix) - 1U || parsed <= 0
        || strncmp(end, suffix, sizeof(suffix) - 1U) != 0) return -1;
    end += sizeof(suffix) - 1U;
    if (*end != '\0' && *end != '?') return -1;
    *id = parsed;
    return 0;
}

int st_client_package_send_download(int fd,
                                    const char *method,
                                    const char *path,
                                    const char *database_path,
                                    const char *remote_address)
{
    long long id = 0;
    if ((strcmp(method, "GET") != 0 && strcmp(method, "HEAD") != 0)
        || package_parse_download_path(path, &id) != 0) return 0;
    long long retry_after = 1;
    if (st_client_package_rate_limit(remote_address, &retry_after) != 0) {
        const char *body = "{\"error\":\"请求过于频繁,请稍后再试\"}";
        char header[512];
        int header_len = snprintf(header, sizeof(header),
            "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\n"
            "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n"
            "Retry-After: %lld\r\nContent-Length: %zu\r\n\r\n",
            retry_after > 0 ? retry_after : 1, strlen(body));
        if (header_len > 0 && (size_t)header_len < sizeof(header)) {
            (void)package_send_all(fd, header, (size_t)header_len);
            (void)package_send_all(fd, body, strlen(body));
        }
        return 1;
    }
    st_storage_client_download_link link;
    if (database_path == NULL || st_storage_get_client_download_link(database_path, id, &link) != 0
        || !link.enabled || !link.hosted || !st_client_package_is_readable(&link)) {
        package_send_error(fd, 404, "Not Found", "client package not found");
        return 1;
    }
    char path_buffer[PATH_MAX];
    if (package_path_for(id, path_buffer) != 0) {
        package_send_error(fd, 404, "Not Found", "client package not found");
        return 1;
    }
    int file_fd = open(path_buffer, O_RDONLY | O_NOFOLLOW);
    if (file_fd < 0) {
        package_send_error(fd, 404, "Not Found", "client package not found");
        return 1;
    }
    char file_name[256];
    snprintf(file_name, sizeof(file_name), "%s", link.package_file_name);
    if (file_name[0] == '\0') package_download_name(&link, file_name);
    char header[1024];
    int header_len = snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
        "Content-Length: %lld\r\nCache-Control: no-store\r\n"
        "Content-Disposition: attachment; filename=\"%s\"\r\n"
        "ETag: \"sha256-%s\"\r\nX-Checksum-SHA256: %s\r\n"
        "X-Content-Type-Options: nosniff\r\n\r\n",
        link.file_size, file_name, link.sha256, link.sha256);
    int ok = header_len > 0 && (size_t)header_len < sizeof(header)
        && package_send_all(fd, header, (size_t)header_len) == 0;
    if (ok && strcmp(method, "HEAD") != 0) {
        uint8_t buffer[64U * 1024U];
        for (;;) {
            ssize_t read_len = read(file_fd, buffer, sizeof(buffer));
            if (read_len == 0) break;
            if (read_len < 0) {
                if (errno == EINTR) continue;
                ok = 0;
                break;
            }
            if (package_send_all(fd, buffer, (size_t)read_len) != 0) {
                ok = 0;
                break;
            }
        }
    }
    close(file_fd);
    return ok ? 1 : -1;
}

int st_client_package_delete(const char *database_path, long long id)
{
    st_storage_client_download_link link;
    if (database_path == NULL || st_storage_get_client_download_link(database_path, id, &link) != 0) return -1;
    if (!link.hosted) return st_storage_delete_client_download_link(database_path, id);
    char source[PATH_MAX];
    if (package_path_for(id, source) != 0) return -2;
    struct stat st;
    int has_file = lstat(source, &st) == 0;
    if (has_file && (!S_ISREG(st.st_mode) || S_ISLNK(st.st_mode))) return -2;
    if (!has_file && errno != ENOENT) return -2;
    char quarantine[PATH_MAX];
    quarantine[0] = '\0';
    if (has_file) {
        char root[PATH_MAX];
        if (package_root(root) != 0) return -2;
        int written = snprintf(quarantine, sizeof(quarantine), "%s/.delete-%lld-%ld-%lld.tmp",
                               root, id, (long)getpid(), (long long)time(NULL));
        if (written <= 0 || (size_t)written >= sizeof(quarantine)
            || lstat(quarantine, &st) == 0 || errno != ENOENT || rename(source, quarantine) != 0) return -2;
    }
    if (st_storage_delete_client_download_link(database_path, id) != 0) {
        if (quarantine[0] != '\0') (void)rename(quarantine, source);
        return -1;
    }
    if (quarantine[0] != '\0') (void)unlink(quarantine);
    return 0;
}
