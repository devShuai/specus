#define _POSIX_C_SOURCE 200809L

#include "workbench.h"

#include "json.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#define ST_WORKBENCH_RATE_BUCKETS 1024U
/* tenant_id and username come from the authenticated context, both bounded well below this. */
#define ST_WORKBENCH_RATE_KEY_MAX 256U

static const char *const workbench_kinds[] = {"http-route", "tcp-mapping", "peer-service"};

static int workbench_kind_valid(const char *text, size_t len)
{
    for (size_t i = 0; i < sizeof(workbench_kinds) / sizeof(workbench_kinds[0]); ++i) {
        if (strlen(workbench_kinds[i]) == len && memcmp(workbench_kinds[i], text, len) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Decimal ASCII digits, no sign, no leading zero, 1..2^53-1 -- taken from the raw path text. */
static int workbench_parse_id(const char *text, size_t len, long long *out)
{
    if (len == 0U || len > 16U || text[0] == '0') {
        return -1;
    }
    long long value = 0;
    for (size_t i = 0; i < len; ++i) {
        if (text[i] < '0' || text[i] > '9') {
            return -1;
        }
        value = value * 10 + (text[i] - '0');
    }
    if (value > ST_WORKBENCH_MAX_OBJECT_ID) {
        return -1;
    }
    *out = value;
    return 0;
}

int st_workbench_match(const char *method, const char *path, st_workbench_request *request)
{
    size_t prefix_len = strlen(ST_WORKBENCH_PATH);
    if (method == NULL || path == NULL || request == NULL || strncmp(path, ST_WORKBENCH_PATH, prefix_len) != 0) {
        return 0;
    }
    const char *query = strchr(path, '?');
    const char *end = query == NULL ? path + strlen(path) : query;
    const char *rest = path + prefix_len;
    memset(request, 0, sizeof(*request));
    if (rest == end) {
        if (strcmp(method, "GET") != 0) {
            return 0;
        }
        request->op = ST_WORKBENCH_GET;
        request->reference_valid = 1;
        return 1;
    }
    if (*rest != '/') {
        return 0;
    }
    const char *segments[3];
    size_t lengths[3];
    size_t count = 0U;
    const char *cursor = rest + 1;
    for (;;) {
        const char *slash = memchr(cursor, '/', (size_t)(end - cursor));
        const char *segment_end = slash == NULL ? end : slash;
        if (count == 3U) {
            return 0;
        }
        segments[count] = cursor;
        lengths[count] = (size_t)(segment_end - cursor);
        ++count;
        if (slash == NULL) {
            break;
        }
        cursor = slash + 1;
    }
    int favorites = lengths[0] == strlen("favorites") && memcmp(segments[0], "favorites", lengths[0]) == 0;
    int recents = lengths[0] == strlen("recents") && memcmp(segments[0], "recents", lengths[0]) == 0;
    if (count == 1U) {
        if (strcmp(method, "DELETE") != 0 || (!favorites && !recents)) {
            return 0;
        }
        request->op = favorites ? ST_WORKBENCH_CLEAR_FAVORITES : ST_WORKBENCH_CLEAR_RECENTS;
        request->reference_valid = 1;
        return 1;
    }
    if (count != 3U) {
        return 0;
    }
    if (favorites && strcmp(method, "PUT") == 0) {
        request->op = ST_WORKBENCH_ADD_FAVORITE;
    } else if (favorites && strcmp(method, "DELETE") == 0) {
        request->op = ST_WORKBENCH_REMOVE_FAVORITE;
    } else if (recents && strcmp(method, "POST") == 0) {
        request->op = ST_WORKBENCH_RECORD_VISIT;
    } else if (recents && strcmp(method, "DELETE") == 0) {
        request->op = ST_WORKBENCH_REMOVE_RECENT;
    } else {
        return 0;
    }
    request->has_reference = 1;
    if (workbench_kind_valid(segments[1], lengths[1])
        && workbench_parse_id(segments[2], lengths[2], &request->object_id) == 0) {
        memcpy(request->kind, segments[1], lengths[1]);
        request->kind[lengths[1]] = '\0';
        request->reference_valid = 1;
    }
    return 1;
}

const char *st_workbench_op_name(st_workbench_op op)
{
    switch (op) {
    case ST_WORKBENCH_GET: return "get";
    case ST_WORKBENCH_ADD_FAVORITE: return "add-favorite";
    case ST_WORKBENCH_REMOVE_FAVORITE: return "remove-favorite";
    case ST_WORKBENCH_CLEAR_FAVORITES: return "clear-favorites";
    case ST_WORKBENCH_RECORD_VISIT: return "record-visit";
    case ST_WORKBENCH_REMOVE_RECENT: return "remove-recent";
    case ST_WORKBENCH_CLEAR_RECENTS: return "clear-recents";
    }
    return "unknown";
}

int st_workbench_op_is_growth(st_workbench_op op)
{
    return op == ST_WORKBENCH_ADD_FAVORITE || op == ST_WORKBENCH_RECORD_VISIT;
}

st_storage_workbench_write_op st_workbench_storage_op(st_workbench_op op)
{
    switch (op) {
    case ST_WORKBENCH_ADD_FAVORITE: return ST_STORAGE_WORKBENCH_ADD_FAVORITE;
    case ST_WORKBENCH_REMOVE_FAVORITE: return ST_STORAGE_WORKBENCH_REMOVE_FAVORITE;
    case ST_WORKBENCH_CLEAR_FAVORITES: return ST_STORAGE_WORKBENCH_CLEAR_FAVORITES;
    case ST_WORKBENCH_RECORD_VISIT: return ST_STORAGE_WORKBENCH_RECORD_VISIT;
    case ST_WORKBENCH_REMOVE_RECENT: return ST_STORAGE_WORKBENCH_REMOVE_RECENT;
    case ST_WORKBENCH_CLEAR_RECENTS: return ST_STORAGE_WORKBENCH_CLEAR_RECENTS;
    case ST_WORKBENCH_GET: break;
    }
    return (st_storage_workbench_write_op)0;
}

/* ---- Clock ------------------------------------------------------------------------------------- */

static pthread_mutex_t workbench_clock_lock = PTHREAD_MUTEX_INITIALIZER;
static st_workbench_clock workbench_clock = NULL;

void st_workbench_set_clock(st_workbench_clock clock)
{
    pthread_mutex_lock(&workbench_clock_lock);
    workbench_clock = clock;
    pthread_mutex_unlock(&workbench_clock_lock);
}

long long st_workbench_now_ms(void)
{
    pthread_mutex_lock(&workbench_clock_lock);
    st_workbench_clock clock = workbench_clock;
    pthread_mutex_unlock(&workbench_clock_lock);
    if (clock != NULL) {
        return clock();
    }
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000LL + (long long)tv.tv_usec / 1000LL;
}

/* ---- Rate limit -------------------------------------------------------------------------------- */

typedef struct st_workbench_rate_entry {
    struct st_workbench_rate_entry *next;
    long long tat_ms;
    char key[];
} st_workbench_rate_entry;

static pthread_mutex_t workbench_rate_lock = PTHREAD_MUTEX_INITIALIZER;
static st_workbench_rate_entry *workbench_rate_buckets[ST_WORKBENCH_RATE_BUCKETS];
static size_t workbench_rate_count = 0U;

static uint32_t workbench_rate_hash(const char *key)
{
    uint32_t hash = 2166136261U;
    for (const unsigned char *p = (const unsigned char *)key; *p != '\0'; ++p) {
        hash ^= *p;
        hash *= 16777619U;
    }
    return hash;
}

/* Entries whose TAT is not after now are as good as absent and may go at any time. */
static void workbench_rate_evict_idle(long long now_ms)
{
    for (size_t i = 0; i < ST_WORKBENCH_RATE_BUCKETS; ++i) {
        st_workbench_rate_entry **cursor = &workbench_rate_buckets[i];
        while (*cursor != NULL) {
            st_workbench_rate_entry *entry = *cursor;
            if (entry->tat_ms <= now_ms) {
                *cursor = entry->next;
                free(entry);
                --workbench_rate_count;
            } else {
                cursor = &entry->next;
            }
        }
    }
}

long long st_workbench_rate_limit_acquire(const char *tenant_id, const char *username, long long now_ms)
{
    char key[ST_WORKBENCH_RATE_KEY_MAX];
    int key_len = snprintf(key, sizeof(key), "%s\n%s",
                           tenant_id == NULL ? "" : tenant_id, username == NULL ? "" : username);
    if (key_len < 0 || (size_t)key_len >= sizeof(key)) {
        return ST_WORKBENCH_RATE_INTERVAL_MS;
    }
    const long long tolerance = (ST_WORKBENCH_RATE_BURST - 1LL) * ST_WORKBENCH_RATE_INTERVAL_MS;
    uint32_t bucket = workbench_rate_hash(key) % ST_WORKBENCH_RATE_BUCKETS;
    pthread_mutex_lock(&workbench_rate_lock);
    st_workbench_rate_entry *entry = workbench_rate_buckets[bucket];
    while (entry != NULL && strcmp(entry->key, key) != 0) {
        entry = entry->next;
    }
    long long wait_ms = 0;
    if (entry != NULL) {
        wait_ms = entry->tat_ms - tolerance - now_ms;
        if (wait_ms <= 0) {
            wait_ms = 0;
            entry->tat_ms = (entry->tat_ms > now_ms ? entry->tat_ms : now_ms) + ST_WORKBENCH_RATE_INTERVAL_MS;
        }
    } else {
        /* A new key starts at TAT = now, which always conforms. */
        if (workbench_rate_count >= ST_WORKBENCH_RATE_MAX_KEYS) {
            workbench_rate_evict_idle(now_ms);
        }
        entry = workbench_rate_count < ST_WORKBENCH_RATE_MAX_KEYS
            ? (st_workbench_rate_entry *)malloc(sizeof(*entry) + (size_t)key_len + 1U)
            : NULL;
        if (entry == NULL) {
            wait_ms = ST_WORKBENCH_RATE_INTERVAL_MS;
        } else {
            memcpy(entry->key, key, (size_t)key_len + 1U);
            entry->tat_ms = now_ms + ST_WORKBENCH_RATE_INTERVAL_MS;
            entry->next = workbench_rate_buckets[bucket];
            workbench_rate_buckets[bucket] = entry;
            ++workbench_rate_count;
        }
    }
    pthread_mutex_unlock(&workbench_rate_lock);
    return wait_ms;
}

long long st_workbench_retry_after_seconds(long long wait_ms)
{
    long long seconds = wait_ms <= 0 ? 0 : (wait_ms + 999LL) / 1000LL;
    return seconds < 1 ? 1 : seconds;
}

void st_workbench_rate_limit_reset(void)
{
    pthread_mutex_lock(&workbench_rate_lock);
    for (size_t i = 0; i < ST_WORKBENCH_RATE_BUCKETS; ++i) {
        st_workbench_rate_entry *entry = workbench_rate_buckets[i];
        while (entry != NULL) {
            st_workbench_rate_entry *next = entry->next;
            free(entry);
            entry = next;
        }
        workbench_rate_buckets[i] = NULL;
    }
    workbench_rate_count = 0U;
    pthread_mutex_unlock(&workbench_rate_lock);
}

/* ---- Document ---------------------------------------------------------------------------------- */

/* RFC 3339 UTC with exactly three fractional digits, e.g. 2026-10-06T08:00:00.123Z. */
static int workbench_format_time(long long at_ms, char *out, size_t out_len)
{
    long long seconds = at_ms / 1000LL;
    long long millis = at_ms % 1000LL;
    if (millis < 0) {
        millis += 1000LL;
        seconds -= 1LL;
    }
    time_t value = (time_t)seconds;
    struct tm utc;
    if (gmtime_r(&value, &utc) == NULL) {
        return -1;
    }
    size_t len = strftime(out, out_len, "%Y-%m-%dT%H:%M:%S", &utc);
    if (len == 0U) {
        return -1;
    }
    int written = snprintf(out + len, out_len - len, ".%03lldZ", millis);
    return written < 0 || (size_t)written >= out_len - len ? -1 : 0;
}

static int workbench_append_entries(char *out,
                                    size_t out_len,
                                    size_t *used,
                                    const st_storage_workbench_entry *entries,
                                    size_t count,
                                    const char *time_field)
{
    for (size_t i = 0; i < count; ++i) {
        char stamp[64];
        char *kind = st_json_escape(entries[i].kind);
        if (kind == NULL || workbench_format_time(entries[i].at_ms, stamp, sizeof(stamp)) != 0) {
            free(kind);
            return -1;
        }
        int written = snprintf(out + *used, out_len - *used, "%s{\"kind\":\"%s\",\"id\":%lld,\"%s\":\"%s\"}",
                               i == 0U ? "" : ",", kind, entries[i].object_id, time_field, stamp);
        free(kind);
        if (written < 0 || (size_t)written >= out_len - *used) {
            return -1;
        }
        *used += (size_t)written;
    }
    return 0;
}

char *st_workbench_render_document(const st_storage_workbench_document *doc)
{
    if (doc == NULL || (doc->favorites_len > 0U && doc->favorites == NULL)
        || doc->recents_len > ST_STORAGE_WORKBENCH_MAX_RECENTS) {
        return NULL;
    }
    /* An entry needs well under 256 bytes even with an escaped kind of 15 characters. */
    size_t entries = doc->favorites_len + doc->recents_len;
    if (entries > (SIZE_MAX - 512U) / 256U) {
        return NULL;
    }
    size_t out_len = 512U + entries * 256U;
    char *out = (char *)malloc(out_len);
    if (out == NULL) {
        return NULL;
    }
    int written = snprintf(out, out_len,
                           "{\"schemaVersion\":1,\"limits\":{\"maxFavorites\":%d,\"maxRecents\":%d,"
                           "\"recentRetentionDays\":%d},\"favorites\":[",
                           ST_STORAGE_WORKBENCH_MAX_FAVORITES,
                           ST_STORAGE_WORKBENCH_MAX_RECENTS,
                           ST_STORAGE_WORKBENCH_RECENT_RETENTION_DAYS);
    size_t used = written < 0 ? out_len : (size_t)written;
    int rc = used < out_len ? 0 : -1;
    if (rc == 0) {
        rc = workbench_append_entries(out, out_len, &used, doc->favorites, doc->favorites_len, "addedAt");
    }
    if (rc == 0) {
        written = snprintf(out + used, out_len - used, "],\"recents\":[");
        rc = written < 0 || (size_t)written >= out_len - used ? -1 : 0;
        if (rc == 0) {
            used += (size_t)written;
        }
    }
    if (rc == 0) {
        rc = workbench_append_entries(out, out_len, &used, doc->recents, doc->recents_len, "visitedAt");
    }
    if (rc == 0) {
        written = snprintf(out + used, out_len - used, "]}");
        rc = written < 0 || (size_t)written >= out_len - used ? -1 : 0;
    }
    if (rc != 0) {
        free(out);
        return NULL;
    }
    return out;
}

int st_workbench_sweep(const char *database_path)
{
    return st_storage_workbench_sweep(database_path, st_workbench_now_ms());
}
