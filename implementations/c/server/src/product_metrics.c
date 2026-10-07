#define _POSIX_C_SOURCE 200809L

#include "product_metrics.h"

#include "json.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

/*
 * Opt-in product metrics; see product_metrics.h and protocol/spec/product-metrics.md. The rules
 * mirror the reference engine of tools/protocol/generate_product_metrics_vectors.py and the Go
 * server (implementations/go/server/internal/productmetrics): the switch is read from the database
 * on every use, every count is an atomic upsert, and only the rate limiter lives in the process.
 */

#define PM_DAY_MS 86400000LL
#define PM_WINDOW_MS ((long long)ST_PRODUCT_METRICS_WINDOW_DAYS * PM_DAY_MS)
#define PM_NAME_CAP 128U
#define PM_DAY_CAP 64U
#define PM_INSTANT_CAP 128U
#define PM_NO_DURATION "none"
#define PM_COUNT(array) (sizeof(array) / sizeof((array)[0]))

static const char *const pm_steps[] = {
    ST_PRODUCT_METRICS_STEP_ACCOUNT_CREATED,
    ST_PRODUCT_METRICS_STEP_SIGNED_IN,
    ST_PRODUCT_METRICS_STEP_CREDENTIAL_CREATED,
    ST_PRODUCT_METRICS_STEP_CLIENT_ONLINE,
    ST_PRODUCT_METRICS_STEP_SERVICE_PUBLISHED
};
static const char *const pm_modes[] = {"device", "link"};
static const char *const pm_paths[] = {"direct", "turn", "cloud", "unestablished"};
static const char *const pm_size_buckets[] = {"lt1m", "1m-16m", "16m-128m", "128m-512m", "gt512m"};
static const char *const pm_attempts[] = {"first", "retry_after_failure", "retry_after_cancel"};
static const char *const pm_outcomes[] = {"success", "failure", "cancelled"};
static const char *const pm_duration_buckets[] = {"lt10m", "10m-30m", "30m-2h", "2h-24h", "1d-3d", "3d-14d"};
static const long long pm_duration_upper_seconds[] = {
    600LL, 1800LL, 7200LL, 86400LL, 259200LL, (long long)ST_PRODUCT_METRICS_WINDOW_DAYS * 86400LL
};

enum { PM_STEP_ACCOUNT = 0, PM_STEP_SIGNED_IN, PM_STEP_CREDENTIAL, PM_STEP_ONLINE, PM_STEP_PUBLISHED };
enum { PM_PATH_DIRECT = 0, PM_PATH_TURN, PM_PATH_CLOUD, PM_PATH_UNESTABLISHED };
enum { PM_OUTCOME_SUCCESS = 0, PM_OUTCOME_FAILURE, PM_OUTCOME_CANCELLED };
enum { PM_MODE_DEVICE = 0, PM_MODE_LINK };

/* ---- Small helpers ---------------------------------------------------------------------------- */

static long long pm_floor_div(long long value, long long divisor)
{
    long long quotient = value / divisor;
    if (value % divisor != 0 && (value < 0) != (divisor < 0)) {
        --quotient;
    }
    return quotient;
}

static int pm_lookup(const char *const *names, size_t count, const char *value, size_t value_len)
{
    for (size_t i = 0; i < count; ++i) {
        if (strlen(names[i]) == value_len && memcmp(names[i], value, value_len) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static int pm_lookup_text(const char *const *names, size_t count, const char *value)
{
    return value == NULL ? -1 : pm_lookup(names, count, value, strlen(value));
}

static int pm_blank(const char *value)
{
    if (value == NULL) {
        return 1;
    }
    for (const char *p = value; *p != '\0'; ++p) {
        if (*p != ' ' && *p != '\t' && *p != '\n' && *p != '\r' && *p != '\f' && *p != '\v') {
            return 0;
        }
    }
    return 1;
}

/* A blank tenant is the default one, as everywhere else in the management API. */
static const char *pm_tenant(const char *tenant_id)
{
    return pm_blank(tenant_id) ? "default" : tenant_id;
}

/*
 * The only log line of this module: the operation, the tenant (printable ASCII only, bounded) and
 * an error class. Never a username, a request body, a credential or an address.
 */
static void pm_log(const char *operation, const char *tenant_id, const char *error_class)
{
    char safe[96];
    size_t used = 0U;
    const char *tenant = tenant_id == NULL ? "-" : tenant_id;
    for (const unsigned char *p = (const unsigned char *)tenant; *p != '\0' && used + 1U < sizeof(safe); ++p) {
        safe[used++] = *p >= 0x21U && *p <= 0x7eU ? (char)*p : '?';
    }
    safe[used] = '\0';
    fprintf(stderr, "[product-metrics] operation=%s tenant=%s error=%s\n", operation, safe, error_class);
    fflush(stderr);
}

/* ---- Dates ------------------------------------------------------------------------------------ */

/* Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's days_from_civil). */
static long long pm_days_from_civil(long long year, unsigned month, unsigned day)
{
    year -= month <= 2U;
    long long era = (year >= 0 ? year : year - 399) / 400;
    unsigned year_of_era = (unsigned)(year - era * 400);
    unsigned shifted_month = month > 2U ? month - 3U : month + 9U;
    unsigned day_of_year = (153U * shifted_month + 2U) / 5U + day - 1U;
    unsigned day_of_era = year_of_era * 365U + year_of_era / 4U - year_of_era / 100U + day_of_year;
    return era * 146097LL + (long long)day_of_era - 719468LL;
}

static void pm_civil_from_days(long long days, long long *year, unsigned *month, unsigned *day)
{
    days += 719468LL;
    long long era = (days >= 0 ? days : days - 146096LL) / 146097LL;
    unsigned day_of_era = (unsigned)(days - era * 146097LL);
    unsigned year_of_era = (day_of_era - day_of_era / 1460U + day_of_era / 36524U - day_of_era / 146096U) / 365U;
    unsigned day_of_year = day_of_era - (365U * year_of_era + year_of_era / 4U - year_of_era / 100U);
    unsigned shifted_month = (5U * day_of_year + 2U) / 153U;
    *day = day_of_year - (153U * shifted_month + 2U) / 5U + 1U;
    *month = shifted_month < 10U ? shifted_month + 3U : shifted_month - 9U;
    *year = (long long)year_of_era + era * 400LL + (*month <= 2U);
}

/* The UTC calendar date of a day number, "YYYY-MM-DD". */
static void pm_day_text(long long day_number, char out[PM_DAY_CAP])
{
    long long year = 0;
    unsigned month = 1U;
    unsigned day = 1U;
    pm_civil_from_days(day_number, &year, &month, &day);
    snprintf(out, PM_DAY_CAP, "%04lld-%02u-%02u", year, month, day);
}

static long long pm_day_number_of_ms(long long ms)
{
    return pm_floor_div(ms, PM_DAY_MS);
}

static void pm_day_of_ms(long long ms, char out[PM_DAY_CAP])
{
    pm_day_text(pm_day_number_of_ms(ms), out);
}

/* An instant rendered to the second, as the contract's examples do: "YYYY-MM-DDTHH:MM:SSZ". */
static void pm_instant_text(long long ms, char out[PM_INSTANT_CAP])
{
    long long seconds = pm_floor_div(ms, 1000LL);
    long long day_number = pm_floor_div(seconds, 86400LL);
    long long of_day = seconds - day_number * 86400LL;
    long long year = 0;
    unsigned month = 1U;
    unsigned day = 1U;
    pm_civil_from_days(day_number, &year, &month, &day);
    snprintf(out, PM_INSTANT_CAP, "%04lld-%02u-%02uT%02lld:%02lld:%02lldZ", year, month, day,
             of_day / 3600LL, (of_day / 60LL) % 60LL, of_day % 60LL);
}

static int pm_leap_year(long long year)
{
    return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
}

/* Strictly "YYYY-MM-DD" with a real calendar date; 0 with the day number, -1 otherwise. */
static int pm_parse_day(const char *text, long long *day_number)
{
    if (text == NULL || strlen(text) != 10U || text[4] != '-' || text[7] != '-') {
        return -1;
    }
    for (size_t i = 0; i < 10U; ++i) {
        if (i != 4U && i != 7U && (text[i] < '0' || text[i] > '9')) {
            return -1;
        }
    }
    long long year = (text[0] - '0') * 1000LL + (text[1] - '0') * 100LL + (text[2] - '0') * 10LL + (text[3] - '0');
    unsigned month = (unsigned)((text[5] - '0') * 10 + (text[6] - '0'));
    unsigned day = (unsigned)((text[8] - '0') * 10 + (text[9] - '0'));
    static const unsigned month_days[] = {31U, 28U, 31U, 30U, 31U, 30U, 31U, 31U, 30U, 31U, 30U, 31U};
    if (month < 1U || month > 12U || day < 1U) {
        return -1;
    }
    unsigned last = month_days[month - 1U] + (month == 2U && pm_leap_year(year) ? 1U : 0U);
    if (day > last) {
        return -1;
    }
    *day_number = pm_days_from_civil(year, month, day);
    return 0;
}

/* ---- Rules (section 5) ------------------------------------------------------------------------ */

const char *st_product_metrics_size_bucket(long long size_bytes)
{
    const long long mib = 1LL << 20;
    if (size_bytes < 1) {
        return NULL;
    }
    if (size_bytes < mib) {
        return pm_size_buckets[0];
    }
    if (size_bytes < 16LL * mib) {
        return pm_size_buckets[1];
    }
    if (size_bytes <= 128LL * mib) {
        return pm_size_buckets[2];
    }
    if (size_bytes <= 512LL * mib) {
        return pm_size_buckets[3];
    }
    return pm_size_buckets[4];
}

const char *st_product_metrics_duration_bucket(long long seconds)
{
    if (seconds < 0) {
        seconds = 0;
    }
    for (size_t i = 0; i < PM_COUNT(pm_duration_upper_seconds); ++i) {
        if (seconds < pm_duration_upper_seconds[i]) {
            return pm_duration_buckets[i];
        }
    }
    return NULL;
}

int st_product_metrics_rate_bp(long long numerator, long long denominator, long long *rate_bp)
{
    if (denominator == 0) {
        return 0;
    }
    *rate_bp = (20000LL * numerator + denominator) / (2LL * denominator);
    return 1;
}

/* ---- Configuration and clock ------------------------------------------------------------------ */

static int pm_ascii_equal_nocase(const char *left, const char *right)
{
    for (;; ++left, ++right) {
        char a = *left >= 'A' && *left <= 'Z' ? (char)(*left + ('a' - 'A')) : *left;
        char b = *right >= 'A' && *right <= 'Z' ? (char)(*right + ('a' - 'A')) : *right;
        if (a != b) {
            return 0;
        }
        if (a == '\0') {
            return 1;
        }
    }
}

int st_product_metrics_allowed(void)
{
    const char *value = getenv("SPECUS_PRODUCT_METRICS_ALLOWED");
    if (value == NULL || *value == '\0') {
        return 1;
    }
    return strcmp(value, "1") == 0 || pm_ascii_equal_nocase(value, "true") || pm_ascii_equal_nocase(value, "yes");
}

static pthread_mutex_t pm_clock_lock = PTHREAD_MUTEX_INITIALIZER;
static st_product_metrics_clock pm_clock = NULL;

void st_product_metrics_set_clock(st_product_metrics_clock clock)
{
    pthread_mutex_lock(&pm_clock_lock);
    pm_clock = clock;
    pthread_mutex_unlock(&pm_clock_lock);
}

long long st_product_metrics_now_ms(void)
{
    pthread_mutex_lock(&pm_clock_lock);
    st_product_metrics_clock clock = pm_clock;
    pthread_mutex_unlock(&pm_clock_lock);
    if (clock != NULL) {
        return clock();
    }
    struct timeval tv;
    if (gettimeofday(&tv, NULL) != 0) {
        return 0;
    }
    return (long long)tv.tv_sec * 1000LL + (long long)tv.tv_usec / 1000LL;
}

/* ---- Rate limiter (section 8) ----------------------------------------------------------------- */

/*
 * Fixed UTC-minute windows counted in events, per tenant+username and per tenant, per process like
 * the other limiters. Only the current minute is kept: a new minute forgets every entry. A batch
 * that would exceed either budget is refused without charging anything.
 */
#define PM_LIMITER_BUCKETS 256U
#define PM_LIMITER_MAX_KEYS 65536U

typedef struct pm_limit_entry {
    struct pm_limit_entry *next;
    long long used;
    size_t key_len;
    char key[];
} pm_limit_entry;

static struct {
    pthread_mutex_t lock;
    long long per_user;
    long long per_tenant;
    int has_minute;
    long long minute;
    size_t keys;
    pm_limit_entry *buckets[PM_LIMITER_BUCKETS];
} pm_limiter = {
    PTHREAD_MUTEX_INITIALIZER,
    ST_PRODUCT_METRICS_DEFAULT_PER_USER_EVENTS,
    ST_PRODUCT_METRICS_DEFAULT_PER_TENANT_EVENTS,
    0,
    0,
    0U,
    {NULL}
};

static void pm_limiter_clear_locked(void)
{
    for (size_t i = 0; i < PM_LIMITER_BUCKETS; ++i) {
        pm_limit_entry *entry = pm_limiter.buckets[i];
        while (entry != NULL) {
            pm_limit_entry *next = entry->next;
            free(entry);
            entry = next;
        }
        pm_limiter.buckets[i] = NULL;
    }
    pm_limiter.keys = 0U;
    pm_limiter.has_minute = 0;
}

static size_t pm_limiter_hash(const char *key, size_t key_len)
{
    uint32_t hash = 2166136261U;
    for (size_t i = 0; i < key_len; ++i) {
        hash ^= (uint8_t)key[i];
        hash *= 16777619U;
    }
    return (size_t)(hash % PM_LIMITER_BUCKETS);
}

static pm_limit_entry *pm_limiter_find_locked(const char *key, size_t key_len, int create)
{
    size_t bucket = pm_limiter_hash(key, key_len);
    for (pm_limit_entry *entry = pm_limiter.buckets[bucket]; entry != NULL; entry = entry->next) {
        if (entry->key_len == key_len && memcmp(entry->key, key, key_len) == 0) {
            return entry;
        }
    }
    if (!create || pm_limiter.keys >= PM_LIMITER_MAX_KEYS) {
        return NULL;
    }
    pm_limit_entry *entry = (pm_limit_entry *)malloc(sizeof(*entry) + key_len);
    if (entry == NULL) {
        return NULL;
    }
    entry->used = 0;
    entry->key_len = key_len;
    memcpy(entry->key, key, key_len);
    entry->next = pm_limiter.buckets[bucket];
    pm_limiter.buckets[bucket] = entry;
    ++pm_limiter.keys;
    return entry;
}

/* Keys are length-prefixed so that no tenant/username pair can collide with another. */
static int pm_limiter_keys(const char *tenant_id,
                           const char *username,
                           char *user_key,
                           size_t *user_key_len,
                           char *tenant_key,
                           size_t *tenant_key_len)
{
    int user_written = snprintf(user_key, 512U, "u%zu:%s|%s", strlen(tenant_id), tenant_id, username);
    int tenant_written = snprintf(tenant_key, 256U, "t%s", tenant_id);
    if (user_written < 0 || user_written >= 512 || tenant_written < 0 || tenant_written >= 256) {
        return -1;
    }
    *user_key_len = (size_t)user_written;
    *tenant_key_len = (size_t)tenant_written;
    return 0;
}

static int pm_limiter_admit(const char *tenant_id, const char *username, long long count, long long now_ms)
{
    char user_key[512];
    char tenant_key[256];
    size_t user_key_len = 0U;
    size_t tenant_key_len = 0U;
    if (pm_limiter_keys(tenant_id, username, user_key, &user_key_len, tenant_key, &tenant_key_len) != 0) {
        return 0;
    }
    pthread_mutex_lock(&pm_limiter.lock);
    long long minute = pm_floor_div(now_ms, 60000LL);
    if (!pm_limiter.has_minute || minute != pm_limiter.minute) {
        pm_limiter_clear_locked();
        pm_limiter.has_minute = 1;
        pm_limiter.minute = minute;
    }
    pm_limit_entry *user = pm_limiter_find_locked(user_key, user_key_len, 0);
    pm_limit_entry *tenant = pm_limiter_find_locked(tenant_key, tenant_key_len, 0);
    long long user_used = user == NULL ? 0 : user->used;
    long long tenant_used = tenant == NULL ? 0 : tenant->used;
    int admitted = user_used + count <= pm_limiter.per_user && tenant_used + count <= pm_limiter.per_tenant;
    if (admitted) {
        user = user == NULL ? pm_limiter_find_locked(user_key, user_key_len, 1) : user;
        tenant = tenant == NULL ? pm_limiter_find_locked(tenant_key, tenant_key_len, 1) : tenant;
        admitted = user != NULL && tenant != NULL;
    }
    if (admitted) {
        user->used += count;
        tenant->used += count;
    }
    pthread_mutex_unlock(&pm_limiter.lock);
    return admitted;
}

void st_product_metrics_set_limits(int per_user_events_per_minute, int per_tenant_events_per_minute)
{
    pthread_mutex_lock(&pm_limiter.lock);
    pm_limiter.per_user = per_user_events_per_minute;
    pm_limiter.per_tenant = per_tenant_events_per_minute;
    pm_limiter_clear_locked();
    pthread_mutex_unlock(&pm_limiter.lock);
}

void st_product_metrics_limiter_reset(void)
{
    st_product_metrics_set_limits(ST_PRODUCT_METRICS_DEFAULT_PER_USER_EVENTS,
                                  ST_PRODUCT_METRICS_DEFAULT_PER_TENANT_EVENTS);
}

/* ---- Closed-schema JSON (sections 7.2 and 7.4) ------------------------------------------------ */

/*
 * A strict reader for the two request bodies: exactly the listed keys, each at most once, values of
 * the right JSON type, nothing after the closing brace but whitespace, and valid UTF-8 throughout.
 * Unknown keys reject the request at once, so there is no path that skips an unknown field.
 */
typedef struct {
    const unsigned char *p;
    const unsigned char *end;
} pm_cursor;

static int pm_utf8_valid(const unsigned char *text, size_t len)
{
    size_t i = 0U;
    while (i < len) {
        unsigned char c = text[i];
        if (c < 0x80U) {
            ++i;
            continue;
        }
        size_t need;
        unsigned char lower = 0x80U;
        unsigned char upper = 0xbfU;
        if (c >= 0xc2U && c <= 0xdfU) {
            need = 1U;
        } else if (c >= 0xe0U && c <= 0xefU) {
            need = 2U;
            if (c == 0xe0U) {
                lower = 0xa0U;
            } else if (c == 0xedU) {
                upper = 0x9fU;
            }
        } else if (c >= 0xf0U && c <= 0xf4U) {
            need = 3U;
            if (c == 0xf0U) {
                lower = 0x90U;
            } else if (c == 0xf4U) {
                upper = 0x8fU;
            }
        } else {
            return 0;
        }
        if (len - i - 1U < need) {
            return 0;
        }
        for (size_t k = 1U; k <= need; ++k) {
            unsigned char continuation = text[i + k];
            unsigned char low = k == 1U ? lower : 0x80U;
            unsigned char high = k == 1U ? upper : 0xbfU;
            if (continuation < low || continuation > high) {
                return 0;
            }
        }
        i += need + 1U;
    }
    return 1;
}

static void pm_skip_ws(pm_cursor *cursor)
{
    while (cursor->p < cursor->end
           && (*cursor->p == ' ' || *cursor->p == '\t' || *cursor->p == '\n' || *cursor->p == '\r')) {
        ++cursor->p;
    }
}

/* The next significant byte, or -1 at the end. */
static int pm_peek(pm_cursor *cursor)
{
    pm_skip_ws(cursor);
    return cursor->p < cursor->end ? *cursor->p : -1;
}

static int pm_expect(pm_cursor *cursor, unsigned char expected)
{
    if (pm_peek(cursor) != expected) {
        return -1;
    }
    ++cursor->p;
    return 0;
}

static int pm_hex_digit(unsigned char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static int pm_read_hex4(pm_cursor *cursor, unsigned int *value)
{
    if (cursor->end - cursor->p < 4) {
        return -1;
    }
    unsigned int result = 0U;
    for (int i = 0; i < 4; ++i) {
        int digit = pm_hex_digit(*cursor->p++);
        if (digit < 0) {
            return -1;
        }
        result = (result << 4U) | (unsigned int)digit;
    }
    *value = result;
    return 0;
}

static int pm_append_byte(char *out, size_t out_cap, size_t *len, unsigned char byte)
{
    if (*len + 1U >= out_cap) {
        return -1;
    }
    out[(*len)++] = (char)byte;
    return 0;
}

static int pm_append_code_point(char *out, size_t out_cap, size_t *len, unsigned int cp)
{
    unsigned char bytes[4];
    size_t count;
    if (cp <= 0x7fU) {
        bytes[0] = (unsigned char)cp;
        count = 1U;
    } else if (cp <= 0x7ffU) {
        bytes[0] = (unsigned char)(0xc0U | (cp >> 6));
        bytes[1] = (unsigned char)(0x80U | (cp & 0x3fU));
        count = 2U;
    } else if (cp <= 0xffffU) {
        bytes[0] = (unsigned char)(0xe0U | (cp >> 12));
        bytes[1] = (unsigned char)(0x80U | ((cp >> 6) & 0x3fU));
        bytes[2] = (unsigned char)(0x80U | (cp & 0x3fU));
        count = 3U;
    } else {
        bytes[0] = (unsigned char)(0xf0U | (cp >> 18));
        bytes[1] = (unsigned char)(0x80U | ((cp >> 12) & 0x3fU));
        bytes[2] = (unsigned char)(0x80U | ((cp >> 6) & 0x3fU));
        bytes[3] = (unsigned char)(0x80U | (cp & 0x3fU));
        count = 4U;
    }
    for (size_t i = 0; i < count; ++i) {
        if (pm_append_byte(out, out_cap, len, bytes[i]) != 0) {
            return -1;
        }
    }
    return 0;
}

/*
 * Reads one JSON string and decodes it into out (NUL-terminated, decoded length in *out_len). A
 * value that is not a string, is malformed, or decodes to out_cap bytes or more fails: every key
 * and value these schemas accept is a short ASCII word, so a longer one is invalid anyway.
 */
static int pm_read_string(pm_cursor *cursor, char *out, size_t out_cap, size_t *out_len)
{
    if (pm_peek(cursor) != '"') {
        return -1;
    }
    ++cursor->p;
    size_t len = 0U;
    while (cursor->p < cursor->end) {
        unsigned char c = *cursor->p++;
        if (c == '"') {
            out[len] = '\0';
            *out_len = len;
            return 0;
        }
        if (c < 0x20U) {
            return -1;
        }
        if (c != '\\') {
            if (pm_append_byte(out, out_cap, &len, c) != 0) {
                return -1;
            }
            continue;
        }
        if (cursor->p >= cursor->end) {
            return -1;
        }
        unsigned char escape = *cursor->p++;
        unsigned int cp;
        switch (escape) {
        case '"': cp = '"'; break;
        case '\\': cp = '\\'; break;
        case '/': cp = '/'; break;
        case 'b': cp = '\b'; break;
        case 'f': cp = '\f'; break;
        case 'n': cp = '\n'; break;
        case 'r': cp = '\r'; break;
        case 't': cp = '\t'; break;
        case 'u':
            if (pm_read_hex4(cursor, &cp) != 0) {
                return -1;
            }
            if (cp >= 0xd800U && cp <= 0xdbffU) {
                unsigned int low = 0U;
                if (cursor->end - cursor->p < 2 || cursor->p[0] != '\\' || cursor->p[1] != 'u') {
                    return -1;
                }
                cursor->p += 2;
                if (pm_read_hex4(cursor, &low) != 0 || low < 0xdc00U || low > 0xdfffU) {
                    return -1;
                }
                cp = 0x10000U + ((cp - 0xd800U) << 10U) + (low - 0xdc00U);
            } else if (cp >= 0xdc00U && cp <= 0xdfffU) {
                return -1;
            }
            break;
        default:
            return -1;
        }
        if (pm_append_code_point(out, out_cap, &len, cp) != 0) {
            return -1;
        }
    }
    return -1;
}

/*
 * Reads one JSON number token: start and len span its text, integer says whether it was written as
 * an integer (no fraction, no exponent).
 */
static int pm_read_number(pm_cursor *cursor, const unsigned char **start, size_t *len, int *integer)
{
    pm_skip_ws(cursor);
    const unsigned char *p = cursor->p;
    const unsigned char *end = cursor->end;
    *start = p;
    *integer = 1;
    if (p < end && *p == '-') {
        ++p;
    }
    if (p < end && *p == '0') {
        ++p;
    } else if (p < end && *p >= '1' && *p <= '9') {
        while (p < end && *p >= '0' && *p <= '9') {
            ++p;
        }
    } else {
        return -1;
    }
    if (p < end && *p == '.') {
        *integer = 0;
        ++p;
        if (p >= end || *p < '0' || *p > '9') {
            return -1;
        }
        while (p < end && *p >= '0' && *p <= '9') {
            ++p;
        }
    }
    if (p < end && (*p == 'e' || *p == 'E')) {
        *integer = 0;
        ++p;
        if (p < end && (*p == '+' || *p == '-')) {
            ++p;
        }
        if (p >= end || *p < '0' || *p > '9') {
            return -1;
        }
        while (p < end && *p >= '0' && *p <= '9') {
            ++p;
        }
    }
    *len = (size_t)(p - *start);
    cursor->p = p;
    return 0;
}

/* After a member: 1 for another one, 0 at the closing delimiter, -1 for anything else. */
static int pm_next_member(pm_cursor *cursor, unsigned char closing)
{
    int next = pm_peek(cursor);
    if (next == ',') {
        ++cursor->p;
        return 1;
    }
    if (next == closing) {
        ++cursor->p;
        return 0;
    }
    return -1;
}

static int pm_at_end(pm_cursor *cursor)
{
    pm_skip_ws(cursor);
    return cursor->p == cursor->end;
}

typedef struct {
    int mode;
    int path;
    int size_bucket;
    int attempt;
    int outcome;
} pm_event;

/* One transfer event: exactly the five fields, each a string of its closed vocabulary. */
static int pm_parse_event(pm_cursor *cursor, pm_event *event)
{
    static const char *const keys[] = {"mode", "path", "sizeBucket", "attempt", "outcome"};
    static const char *const *const vocabularies[] = {pm_modes, pm_paths, pm_size_buckets, pm_attempts, pm_outcomes};
    static const size_t vocabulary_sizes[] = {
        PM_COUNT(pm_modes), PM_COUNT(pm_paths), PM_COUNT(pm_size_buckets), PM_COUNT(pm_attempts), PM_COUNT(pm_outcomes)
    };
    int values[5] = {-1, -1, -1, -1, -1};
    if (pm_expect(cursor, '{') != 0 || pm_peek(cursor) == '}') {
        return -1;
    }
    int more = 1;
    while (more == 1) {
        char key[16];
        char value[32];
        size_t key_len = 0U;
        size_t value_len = 0U;
        if (pm_read_string(cursor, key, sizeof(key), &key_len) != 0) {
            return -1;
        }
        int field = pm_lookup(keys, PM_COUNT(keys), key, key_len);
        if (field < 0 || values[field] >= 0 || pm_expect(cursor, ':') != 0
            || pm_read_string(cursor, value, sizeof(value), &value_len) != 0) {
            return -1;
        }
        values[field] = pm_lookup(vocabularies[field], vocabulary_sizes[field], value, value_len);
        if (values[field] < 0) {
            return -1;
        }
        more = pm_next_member(cursor, '}');
    }
    if (more < 0) {
        return -1;
    }
    for (size_t i = 0; i < PM_COUNT(values); ++i) {
        if (values[i] < 0) {
            return -1;
        }
    }
    event->mode = values[0];
    event->path = values[1];
    event->size_bucket = values[2];
    event->attempt = values[3];
    event->outcome = values[4];
    if (event->mode == PM_MODE_LINK && event->path != PM_PATH_CLOUD && event->path != PM_PATH_UNESTABLISHED) {
        return -1;
    }
    return event->outcome == PM_OUTCOME_SUCCESS && event->path == PM_PATH_UNESTABLISHED ? -1 : 0;
}

/*
 * The ingest body of section 7.4: {"schemaVersion": 1, "events": [1..20 events]} and nothing else.
 * schemaVersion must be the integer literal 1 (not 1.0, 1e0, "1" or true).
 */
static int pm_parse_ingest(const char *body, size_t body_len, pm_event *events, size_t *count)
{
    *count = 0U;
    if (body == NULL || !pm_utf8_valid((const unsigned char *)body, body_len)) {
        return -1;
    }
    pm_cursor cursor = {(const unsigned char *)body, (const unsigned char *)body + body_len};
    if (pm_expect(&cursor, '{') != 0 || pm_peek(&cursor) == '}') {
        return -1;
    }
    int seen_version = 0;
    int seen_events = 0;
    int more = 1;
    while (more == 1) {
        char key[16];
        size_t key_len = 0U;
        if (pm_read_string(&cursor, key, sizeof(key), &key_len) != 0 || pm_expect(&cursor, ':') != 0) {
            return -1;
        }
        if (key_len == strlen("schemaVersion") && memcmp(key, "schemaVersion", key_len) == 0 && !seen_version) {
            const unsigned char *number = NULL;
            size_t number_len = 0U;
            int integer = 0;
            if (pm_read_number(&cursor, &number, &number_len, &integer) != 0
                || !integer || number_len != 1U || number[0] != '1') {
                return -1;
            }
            seen_version = 1;
        } else if (key_len == strlen("events") && memcmp(key, "events", key_len) == 0 && !seen_events) {
            if (pm_expect(&cursor, '[') != 0 || pm_peek(&cursor) == ']') {
                return -1;
            }
            int more_events = 1;
            while (more_events == 1) {
                if (*count == ST_PRODUCT_METRICS_MAX_EVENTS || pm_parse_event(&cursor, &events[*count]) != 0) {
                    return -1;
                }
                ++*count;
                more_events = pm_next_member(&cursor, ']');
            }
            if (more_events < 0) {
                return -1;
            }
            seen_events = 1;
        } else {
            return -1;
        }
        more = pm_next_member(&cursor, '}');
    }
    return more == 0 && pm_at_end(&cursor) && seen_version && seen_events ? 0 : -1;
}

typedef struct {
    int enabled;
    int has_disclosure;
    int disclosure_current;
} pm_settings_update;

/* The PUT body of section 7.2: enabled (boolean, required) and disclosureVersion (integer). */
static int pm_parse_settings(const char *body, size_t body_len, pm_settings_update *update)
{
    memset(update, 0, sizeof(*update));
    if (body == NULL || body_len > ST_PRODUCT_METRICS_MAX_BODY_BYTES
        || !pm_utf8_valid((const unsigned char *)body, body_len)) {
        return -1;
    }
    pm_cursor cursor = {(const unsigned char *)body, (const unsigned char *)body + body_len};
    if (pm_expect(&cursor, '{') != 0) {
        return -1;
    }
    int seen_enabled = 0;
    int more = pm_peek(&cursor) == '}' ? 0 : 1;
    if (more == 0) {
        ++cursor.p;
    }
    while (more == 1) {
        char key[32];
        size_t key_len = 0U;
        if (pm_read_string(&cursor, key, sizeof(key), &key_len) != 0 || pm_expect(&cursor, ':') != 0) {
            return -1;
        }
        if (key_len == strlen("enabled") && memcmp(key, "enabled", key_len) == 0 && !seen_enabled) {
            pm_skip_ws(&cursor);
            size_t left = (size_t)(cursor.end - cursor.p);
            if (left >= 4U && memcmp(cursor.p, "true", 4U) == 0) {
                update->enabled = 1;
                cursor.p += 4;
            } else if (left >= 5U && memcmp(cursor.p, "false", 5U) == 0) {
                update->enabled = 0;
                cursor.p += 5;
            } else {
                return -1;
            }
            seen_enabled = 1;
        } else if (key_len == strlen("disclosureVersion") && memcmp(key, "disclosureVersion", key_len) == 0
                   && !update->has_disclosure) {
            const unsigned char *number = NULL;
            size_t number_len = 0U;
            int integer = 0;
            if (pm_read_number(&cursor, &number, &number_len, &integer) != 0 || !integer) {
                return -1;
            }
            update->has_disclosure = 1;
            update->disclosure_current = number_len == 1U && number[0] == '0' + ST_PRODUCT_METRICS_DISCLOSURE_VERSION;
        } else {
            return -1;
        }
        more = pm_next_member(&cursor, '}');
    }
    return more == 0 && pm_at_end(&cursor) && seen_enabled ? 0 : -1;
}

/* ---- String builder --------------------------------------------------------------------------- */

typedef struct {
    char *data;
    size_t len;
    size_t cap;
    int failed;
} pm_sb;

static void pm_sb_appendf(pm_sb *sb, const char *format, ...)
{
    if (sb->failed) {
        return;
    }
    for (;;) {
        size_t room = sb->cap - sb->len;
        va_list args;
        va_start(args, format);
        int written = sb->data == NULL ? -2 : vsnprintf(sb->data + sb->len, room, format, args);
        va_end(args);
        if (written == -1) {
            sb->failed = 1;
            return;
        }
        if (written >= 0 && (size_t)written < room) {
            sb->len += (size_t)written;
            return;
        }
        size_t next = sb->cap == 0U ? 1024U : sb->cap * 2U;
        while (written >= 0 && next - sb->len <= (size_t)written) {
            next *= 2U;
        }
        char *grown = (char *)realloc(sb->data, next);
        if (grown == NULL) {
            sb->failed = 1;
            return;
        }
        sb->data = grown;
        sb->cap = next;
    }
}

static char *pm_sb_finish(pm_sb *sb)
{
    if (sb->failed || sb->data == NULL) {
        free(sb->data);
        return NULL;
    }
    return sb->data;
}

static void pm_sb_rate(pm_sb *sb, long long numerator, long long denominator)
{
    long long rate = 0;
    if (st_product_metrics_rate_bp(numerator, denominator, &rate)) {
        pm_sb_appendf(sb, "%lld", rate);
    } else {
        pm_sb_appendf(sb, "null");
    }
}

/* ---- Storage ---------------------------------------------------------------------------------- */

static int pm_open(const char *path, sqlite3 **db)
{
    *db = NULL;
    if (path == NULL || *path == '\0') {
        return -1;
    }
    if (sqlite3_open(path, db) != SQLITE_OK || sqlite3_busy_timeout(*db, 5000) != SQLITE_OK) {
        sqlite3_close(*db);
        *db = NULL;
        return -1;
    }
    return 0;
}

static int pm_exec(sqlite3 *db, const char *sql)
{
    return sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
}

static void pm_rollback(sqlite3 *db)
{
    (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
}

/* Runs one statement with up to three text parameters (NULL entries end the list). */
static int pm_run(sqlite3 *db, const char *sql, const char *first, const char *second, const char *third, int *changes)
{
    sqlite3_stmt *stmt = NULL;
    const char *texts[] = {first, second, third};
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK ? 0 : -1;
    for (int i = 0; rc == 0 && i < 3 && texts[i] != NULL; ++i) {
        rc = sqlite3_bind_text(stmt, i + 1, texts[i], -1, SQLITE_TRANSIENT) == SQLITE_OK ? 0 : -1;
    }
    if (rc == 0) {
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    }
    if (rc == 0 && changes != NULL) {
        *changes = sqlite3_changes(db);
    }
    sqlite3_finalize(stmt);
    return rc;
}

typedef struct {
    int found;
    char tenant_id[PM_NAME_CAP];
    int enabled;
    int has_updated_by;
    char updated_by[PM_NAME_CAP];
    int has_updated_at;
    long long updated_at_ms;
    int has_purged_at;
    long long purged_at_ms;
} pm_switch;

static void pm_copy_column(sqlite3_stmt *stmt, int column, char *out, size_t out_cap)
{
    const unsigned char *text = sqlite3_column_text(stmt, column);
    snprintf(out, out_cap, "%s", text == NULL ? "" : (const char *)text);
}

static void pm_scan_switch(sqlite3_stmt *stmt, pm_switch *row)
{
    memset(row, 0, sizeof(*row));
    row->found = 1;
    pm_copy_column(stmt, 0, row->tenant_id, sizeof(row->tenant_id));
    row->enabled = sqlite3_column_int64(stmt, 1) != 0;
    row->has_updated_by = sqlite3_column_type(stmt, 2) != SQLITE_NULL;
    if (row->has_updated_by) {
        pm_copy_column(stmt, 2, row->updated_by, sizeof(row->updated_by));
    }
    row->has_updated_at = sqlite3_column_type(stmt, 3) != SQLITE_NULL;
    row->updated_at_ms = row->has_updated_at ? sqlite3_column_int64(stmt, 3) : 0;
    row->has_purged_at = sqlite3_column_type(stmt, 4) != SQLITE_NULL;
    row->purged_at_ms = row->has_purged_at ? sqlite3_column_int64(stmt, 4) : 0;
}

#define PM_SWITCH_COLUMNS "tenant_id, enabled, updated_by, updated_at, purged_at"

/* The tenant's switch row; row->found is 0 when the tenant never had one. */
static int pm_read_switch(sqlite3 *db, const char *tenant_id, pm_switch *row)
{
    memset(row, 0, sizeof(*row));
    snprintf(row->tenant_id, sizeof(row->tenant_id), "%s", tenant_id);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "SELECT " PM_SWITCH_COLUMNS " FROM product_metrics_switch WHERE tenant_id = ?",
                           -1, &stmt, NULL) != SQLITE_OK
        || sqlite3_bind_text(stmt, 1, tenant_id, -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return -1;
    }
    int step = sqlite3_step(stmt);
    if (step == SQLITE_ROW) {
        pm_scan_switch(stmt, row);
    }
    sqlite3_finalize(stmt);
    return step == SQLITE_ROW || step == SQLITE_DONE ? 0 : -1;
}

/* Writes the whole switch row, inserting it when absent. */
static int pm_save_switch(sqlite3 *db, const pm_switch *row)
{
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT INTO product_metrics_switch (" PM_SWITCH_COLUMNS ") VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT (tenant_id) DO UPDATE SET enabled = excluded.enabled, updated_by = excluded.updated_by, "
        "updated_at = excluded.updated_at, purged_at = excluded.purged_at",
        -1, &stmt, NULL) == SQLITE_OK ? 0 : -1;
    if (rc == 0) {
        rc = sqlite3_bind_text(stmt, 1, row->tenant_id, -1, SQLITE_TRANSIENT) == SQLITE_OK
            && sqlite3_bind_int(stmt, 2, row->enabled ? 1 : 0) == SQLITE_OK
            && (row->has_updated_by ? sqlite3_bind_text(stmt, 3, row->updated_by, -1, SQLITE_TRANSIENT)
                                    : sqlite3_bind_null(stmt, 3)) == SQLITE_OK
            && (row->has_updated_at ? sqlite3_bind_int64(stmt, 4, row->updated_at_ms)
                                    : sqlite3_bind_null(stmt, 4)) == SQLITE_OK
            && (row->has_purged_at ? sqlite3_bind_int64(stmt, 5, row->purged_at_ms)
                                   : sqlite3_bind_null(stmt, 5)) == SQLITE_OK
            ? 0 : -1;
    }
    if (rc == 0) {
        rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    }
    sqlite3_finalize(stmt);
    return rc;
}

static int pm_collecting(const pm_switch *row)
{
    return st_product_metrics_allowed() && row->found && row->enabled;
}

typedef struct {
    char tenant_id[PM_NAME_CAP];
    char username[PM_NAME_CAP];
    long long started_at_ms;
    int has_step[PM_STEP_PUBLISHED];
    long long step_at_ms[PM_STEP_PUBLISHED];
} pm_progress;

#define PM_PROGRESS_COLUMNS "tenant_id, username, started_at, signed_in_at, credential_created_at, client_online_at"

/* The progress column of a milestone, by step index; NULL for steps without a column. */
static const char *pm_progress_column(int step)
{
    switch (step) {
    case PM_STEP_SIGNED_IN: return "signed_in_at";
    case PM_STEP_CREDENTIAL: return "credential_created_at";
    case PM_STEP_ONLINE: return "client_online_at";
    default: return NULL;
    }
}

static void pm_scan_progress(sqlite3_stmt *stmt, pm_progress *row)
{
    memset(row, 0, sizeof(*row));
    pm_copy_column(stmt, 0, row->tenant_id, sizeof(row->tenant_id));
    pm_copy_column(stmt, 1, row->username, sizeof(row->username));
    row->started_at_ms = sqlite3_column_int64(stmt, 2);
    for (int step = PM_STEP_SIGNED_IN; step <= PM_STEP_ONLINE; ++step) {
        int column = 3 + step - PM_STEP_SIGNED_IN;
        row->has_step[step] = sqlite3_column_type(stmt, column) != SQLITE_NULL;
        row->step_at_ms[step] = row->has_step[step] ? sqlite3_column_int64(stmt, column) : 0;
    }
}

/* 1 with the row, 0 when the account has none, -1 on error. */
static int pm_read_progress(sqlite3 *db, const char *tenant_id, const char *username, pm_progress *row)
{
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT " PM_PROGRESS_COLUMNS " FROM product_metrics_onboarding_progress "
            "WHERE tenant_id = ? AND username = ?",
            -1, &stmt, NULL) != SQLITE_OK
        || sqlite3_bind_text(stmt, 1, tenant_id, -1, SQLITE_TRANSIENT) != SQLITE_OK
        || sqlite3_bind_text(stmt, 2, username, -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return -1;
    }
    int step = sqlite3_step(stmt);
    if (step == SQLITE_ROW) {
        pm_scan_progress(stmt, row);
    }
    sqlite3_finalize(stmt);
    return step == SQLITE_ROW ? 1 : (step == SQLITE_DONE ? 0 : -1);
}

/* The progress rows of one tenant, or of every tenant when tenant_id is NULL, by tenant and name. */
static int pm_list_progress(sqlite3 *db, const char *tenant_id, pm_progress **rows, size_t *count)
{
    *rows = NULL;
    *count = 0U;
    sqlite3_stmt *stmt = NULL;
    const char *sql = tenant_id == NULL
        ? "SELECT " PM_PROGRESS_COLUMNS " FROM product_metrics_onboarding_progress ORDER BY tenant_id, username"
        : "SELECT " PM_PROGRESS_COLUMNS " FROM product_metrics_onboarding_progress WHERE tenant_id = ? "
          "ORDER BY tenant_id, username";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK
        || (tenant_id != NULL && sqlite3_bind_text(stmt, 1, tenant_id, -1, SQLITE_TRANSIENT) != SQLITE_OK)) {
        sqlite3_finalize(stmt);
        return -1;
    }
    size_t capacity = 0U;
    int step;
    while ((step = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (*count == capacity) {
            size_t next = capacity == 0U ? 16U : capacity * 2U;
            pm_progress *grown = (pm_progress *)realloc(*rows, next * sizeof(pm_progress));
            if (grown == NULL) {
                step = SQLITE_NOMEM;
                break;
            }
            *rows = grown;
            capacity = next;
        }
        pm_scan_progress(stmt, &(*rows)[(*count)++]);
    }
    sqlite3_finalize(stmt);
    if (step != SQLITE_DONE) {
        free(*rows);
        *rows = NULL;
        *count = 0U;
        return -1;
    }
    return 0;
}

/* The furthest milestone recorded; later milestones imply the earlier ones (section 4.1). */
static int pm_reached_step(const pm_progress *row)
{
    for (int step = PM_STEP_ONLINE; step >= PM_STEP_SIGNED_IN; --step) {
        if (row->has_step[step]) {
            return step;
        }
    }
    return PM_STEP_ACCOUNT;
}

static int pm_add_onboarding(sqlite3 *db,
                             const char *tenant_id,
                             const char *cohort_day,
                             const char *reached_step,
                             const char *duration_bucket,
                             long long users)
{
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT INTO product_metrics_onboarding_daily (tenant_id, cohort_day, reached_step, duration_bucket, users) "
        "VALUES (?, ?, ?, ?, ?) ON CONFLICT (tenant_id, cohort_day, reached_step, duration_bucket) "
        "DO UPDATE SET users = users + excluded.users",
        -1, &stmt, NULL) == SQLITE_OK
        && sqlite3_bind_text(stmt, 1, tenant_id, -1, SQLITE_TRANSIENT) == SQLITE_OK
        && sqlite3_bind_text(stmt, 2, cohort_day, -1, SQLITE_TRANSIENT) == SQLITE_OK
        && sqlite3_bind_text(stmt, 3, reached_step, -1, SQLITE_STATIC) == SQLITE_OK
        && sqlite3_bind_text(stmt, 4, duration_bucket, -1, SQLITE_STATIC) == SQLITE_OK
        && sqlite3_bind_int64(stmt, 5, users) == SQLITE_OK
        && sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    sqlite3_finalize(stmt);
    return rc;
}

/* One transfer counter key by vocabulary indexes. */
typedef struct {
    int mode;
    int path;
    int size_bucket;
    int attempt;
    int outcome;
    long long count;
} pm_transfer_count;

/* Adds to one transfer counter with an atomic upsert; never read-then-write. */
static int pm_add_transfer(sqlite3 *db, const char *tenant_id, const char *day, const pm_transfer_count *key)
{
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT INTO product_metrics_transfer_daily "
        "(tenant_id, day, mode, path, size_bucket, attempt, outcome, count) VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT (tenant_id, day, mode, path, size_bucket, attempt, outcome) "
        "DO UPDATE SET count = count + excluded.count",
        -1, &stmt, NULL) == SQLITE_OK
        && sqlite3_bind_text(stmt, 1, tenant_id, -1, SQLITE_TRANSIENT) == SQLITE_OK
        && sqlite3_bind_text(stmt, 2, day, -1, SQLITE_TRANSIENT) == SQLITE_OK
        && sqlite3_bind_text(stmt, 3, pm_modes[key->mode], -1, SQLITE_STATIC) == SQLITE_OK
        && sqlite3_bind_text(stmt, 4, pm_paths[key->path], -1, SQLITE_STATIC) == SQLITE_OK
        && sqlite3_bind_text(stmt, 5, pm_size_buckets[key->size_bucket], -1, SQLITE_STATIC) == SQLITE_OK
        && sqlite3_bind_text(stmt, 6, pm_attempts[key->attempt], -1, SQLITE_STATIC) == SQLITE_OK
        && sqlite3_bind_text(stmt, 7, pm_outcomes[key->outcome], -1, SQLITE_STATIC) == SQLITE_OK
        && sqlite3_bind_int64(stmt, 8, key->count) == SQLITE_OK
        && sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    sqlite3_finalize(stmt);
    return rc;
}

static int pm_delete_tenant_progress(sqlite3 *db, const char *tenant_id)
{
    return pm_run(db, "DELETE FROM product_metrics_onboarding_progress WHERE tenant_id = ?",
                  tenant_id, NULL, NULL, NULL);
}

static int pm_delete_tenant_counts(sqlite3 *db, const char *tenant_id)
{
    return pm_run(db, "DELETE FROM product_metrics_onboarding_daily WHERE tenant_id = ?", tenant_id, NULL, NULL, NULL) == 0
        && pm_run(db, "DELETE FROM product_metrics_transfer_daily WHERE tenant_id = ?", tenant_id, NULL, NULL, NULL) == 0
        ? 0 : -1;
}

/*
 * Folds one progress row into the daily cohort counter, in one transaction: completed at
 * completed_at_ms when completed, otherwise at the furthest recorded step. The row must be deleted
 * (exactly one row) before the counter moves, so a completion racing the sweep or another instance
 * is counted once. 1 when this call folded the row, 0 when it was already gone, -1 on error.
 */
static int pm_close_progress(sqlite3 *db,
                             const char *tenant_id,
                             const char *username,
                             int completed,
                             long long completed_at_ms)
{
    if (pm_exec(db, "BEGIN IMMEDIATE") != 0) {
        return -1;
    }
    pm_progress row;
    int found = pm_read_progress(db, tenant_id, username, &row);
    int removed = 0;
    if (found == 1 && pm_run(db,
            "DELETE FROM product_metrics_onboarding_progress WHERE tenant_id = ? AND username = ?",
            tenant_id, username, NULL, &removed) != 0) {
        found = -1;
    }
    int folded = 0;
    if (found == 1 && removed == 1) {
        const char *reached = pm_steps[pm_reached_step(&row)];
        const char *bucket = PM_NO_DURATION;
        int countable = 1;
        if (completed) {
            long long elapsed_ms = completed_at_ms - row.started_at_ms;
            bucket = st_product_metrics_duration_bucket((elapsed_ms < 0 ? 0 : elapsed_ms) / 1000LL);
            reached = pm_steps[PM_STEP_PUBLISHED];
            countable = bucket != NULL; /* unreachable: callers expire such rows instead */
        }
        if (countable) {
            char cohort_day[PM_DAY_CAP];
            pm_day_of_ms(row.started_at_ms, cohort_day);
            if (pm_add_onboarding(db, tenant_id, cohort_day, reached, bucket, 1) != 0) {
                found = -1;
            } else {
                folded = 1;
            }
        }
    }
    if (found < 0 || pm_exec(db, "COMMIT") != 0) {
        pm_rollback(db);
        return -1;
    }
    return folded;
}

/* ---- Responses -------------------------------------------------------------------------------- */

static void pm_respond(st_product_metrics_response *response, int status, char *body)
{
    response->status = body == NULL && status != 403 ? 500 : status;
    response->body = body;
}

static char *pm_dup(const char *text)
{
    size_t len = strlen(text);
    char *copy = (char *)malloc(len + 1U);
    if (copy != NULL) {
        memcpy(copy, text, len + 1U);
    }
    return copy;
}

static void pm_respond_code(st_product_metrics_response *response, int status, const char *code)
{
    char body[96];
    snprintf(body, sizeof(body), "{\"code\":\"%s\"}", code);
    pm_respond(response, status, pm_dup(body));
}

static void pm_respond_unavailable(st_product_metrics_response *response, const char *operation, const char *tenant_id)
{
    pm_log(operation, tenant_id, "storage-unavailable");
    pm_respond_code(response, 503, ST_PRODUCT_METRICS_CODE_UNAVAILABLE);
}

void st_product_metrics_response_free(st_product_metrics_response *response)
{
    if (response != NULL) {
        free(response->body);
        response->body = NULL;
    }
}

/* ---- Settings (7.1, 7.2) ---------------------------------------------------------------------- */

static char *pm_render_settings(const pm_switch *row, int admin)
{
    pm_sb sb = {0};
    pm_sb_appendf(&sb, "{\"schemaVersion\":%d,\"enabled\":%s,\"disclosureVersion\":%d,\"retentionDays\":%d,"
                       "\"onboardingWindowDays\":%d,\"updatedAt\":",
                  ST_PRODUCT_METRICS_SCHEMA_VERSION, pm_collecting(row) ? "true" : "false",
                  ST_PRODUCT_METRICS_DISCLOSURE_VERSION, ST_PRODUCT_METRICS_RETENTION_DAYS,
                  ST_PRODUCT_METRICS_WINDOW_DAYS);
    if (row->found && row->has_updated_at) {
        char instant[PM_INSTANT_CAP];
        pm_instant_text(row->updated_at_ms, instant);
        pm_sb_appendf(&sb, "\"%s\"", instant);
    } else {
        pm_sb_appendf(&sb, "null");
    }
    if (admin) {
        if (row->found && row->has_updated_by) {
            char *escaped = st_json_escape(row->updated_by);
            if (escaped == NULL) {
                sb.failed = 1;
            } else {
                pm_sb_appendf(&sb, ",\"updatedBy\":\"%s\"", escaped);
                free(escaped);
            }
        } else {
            pm_sb_appendf(&sb, ",\"updatedBy\":null");
        }
    }
    pm_sb_appendf(&sb, "}");
    return pm_sb_finish(&sb);
}

static void pm_get_settings(const char *database_path,
                            const st_product_metrics_actor *actor,
                            st_product_metrics_response *response)
{
    const char *tenant = pm_tenant(actor->tenant_id);
    sqlite3 *db = NULL;
    pm_switch row;
    int rc = pm_open(database_path, &db) == 0 ? pm_read_switch(db, tenant, &row) : -1;
    sqlite3_close(db);
    if (rc != 0) {
        pm_respond_unavailable(response, "settings", tenant);
        return;
    }
    pm_respond(response, 200, pm_render_settings(&row, actor->admin));
}

/*
 * Switching off drops the tenant's progress rows (they are not folded into counts). Any change of
 * state clears the purge mark, so while the switch is off the mark only stands for a purge made
 * after switching off. An unchanged state keeps updatedAt, updatedBy and the mark.
 */
static void pm_put_settings(const char *database_path,
                            const st_product_metrics_actor *actor,
                            const char *body,
                            size_t body_len,
                            st_product_metrics_response *response)
{
    if (!actor->admin) {
        pm_respond(response, 403, NULL);
        return;
    }
    pm_settings_update update;
    if (pm_parse_settings(body, body_len, &update) != 0) {
        pm_respond_code(response, 400, ST_PRODUCT_METRICS_CODE_INVALID);
        return;
    }
    if (update.enabled && (!update.has_disclosure || !update.disclosure_current)) {
        pm_respond_code(response, 400, ST_PRODUCT_METRICS_CODE_DISCLOSURE_REQUIRED);
        return;
    }
    if (update.enabled && !st_product_metrics_allowed()) {
        pm_respond_code(response, 409, ST_PRODUCT_METRICS_CODE_NOT_ALLOWED);
        return;
    }
    const char *tenant = pm_tenant(actor->tenant_id);
    long long now = st_product_metrics_now_ms();
    sqlite3 *db = NULL;
    pm_switch row;
    int rc = pm_open(database_path, &db) == 0 && pm_exec(db, "BEGIN IMMEDIATE") == 0 ? 0 : -1;
    if (rc == 0) {
        rc = pm_read_switch(db, tenant, &row);
    }
    if (rc == 0) {
        if (row.enabled != update.enabled) {
            row.enabled = update.enabled;
            row.has_updated_by = 1;
            snprintf(row.updated_by, sizeof(row.updated_by), "%s", actor->username == NULL ? "" : actor->username);
            row.has_updated_at = 1;
            row.updated_at_ms = now;
            row.has_purged_at = 0;
            row.purged_at_ms = 0;
        }
        rc = pm_save_switch(db, &row);
    }
    if (rc == 0 && !update.enabled) {
        rc = pm_delete_tenant_progress(db, tenant);
    }
    if (rc == 0) {
        rc = pm_exec(db, "COMMIT");
    }
    if (rc != 0 && db != NULL) {
        pm_rollback(db);
    }
    sqlite3_close(db);
    if (rc != 0) {
        pm_respond_unavailable(response, "put-settings", tenant);
        return;
    }
    row.found = 1;
    pm_respond(response, 200, pm_render_settings(&row, 1));
}

/* ---- Purge (7.3) ------------------------------------------------------------------------------ */

static void pm_purge(const char *database_path,
                     const st_product_metrics_actor *actor,
                     st_product_metrics_response *response)
{
    if (!actor->admin) {
        pm_respond(response, 403, NULL);
        return;
    }
    const char *tenant = pm_tenant(actor->tenant_id);
    long long now = st_product_metrics_now_ms();
    sqlite3 *db = NULL;
    pm_switch row;
    int rc = pm_open(database_path, &db) == 0 && pm_exec(db, "BEGIN IMMEDIATE") == 0 ? 0 : -1;
    if (rc == 0) {
        rc = pm_delete_tenant_progress(db, tenant);
    }
    if (rc == 0) {
        rc = pm_delete_tenant_counts(db, tenant);
    }
    if (rc == 0) {
        rc = pm_read_switch(db, tenant, &row);
    }
    if (rc == 0) {
        row.has_purged_at = 1;
        row.purged_at_ms = now;
        rc = pm_save_switch(db, &row);
    }
    if (rc == 0) {
        rc = pm_exec(db, "COMMIT");
    }
    if (rc != 0 && db != NULL) {
        pm_rollback(db);
    }
    sqlite3_close(db);
    if (rc != 0) {
        pm_respond_unavailable(response, "purge", tenant);
        return;
    }
    row.found = 1;
    char body[64];
    snprintf(body, sizeof(body), "{\"purged\":true,\"enabled\":%s}", pm_collecting(&row) ? "true" : "false");
    pm_respond(response, 200, pm_dup(body));
}

/* ---- Ingest (7.4) ----------------------------------------------------------------------------- */

/*
 * The order of section 7.4 after authentication: size (raw bytes, before parsing), closed schema,
 * switch, limiter, count. A refusal at any step leaves the limiter untouched; the switch read, the
 * limiter and the atomic upserts run in one transaction.
 */
static void pm_ingest(const char *database_path,
                      const st_product_metrics_actor *actor,
                      const char *body,
                      size_t body_len,
                      st_product_metrics_response *response)
{
    if (body_len > ST_PRODUCT_METRICS_MAX_BODY_BYTES) {
        pm_respond_code(response, 413, ST_PRODUCT_METRICS_CODE_TOO_LARGE);
        return;
    }
    pm_event events[ST_PRODUCT_METRICS_MAX_EVENTS];
    size_t event_count = 0U;
    if (pm_parse_ingest(body, body_len, events, &event_count) != 0) {
        pm_respond_code(response, 400, ST_PRODUCT_METRICS_CODE_INVALID);
        return;
    }
    pm_transfer_count counts[ST_PRODUCT_METRICS_MAX_EVENTS];
    size_t key_count = 0U;
    for (size_t i = 0; i < event_count; ++i) {
        size_t k = 0U;
        while (k < key_count
               && !(counts[k].mode == events[i].mode && counts[k].path == events[i].path
                    && counts[k].size_bucket == events[i].size_bucket && counts[k].attempt == events[i].attempt
                    && counts[k].outcome == events[i].outcome)) {
            ++k;
        }
        if (k == key_count) {
            counts[k].mode = events[i].mode;
            counts[k].path = events[i].path;
            counts[k].size_bucket = events[i].size_bucket;
            counts[k].attempt = events[i].attempt;
            counts[k].outcome = events[i].outcome;
            counts[k].count = 0;
            ++key_count;
        }
        ++counts[k].count;
    }
    const char *tenant = pm_tenant(actor->tenant_id);
    long long now = st_product_metrics_now_ms();
    char day[PM_DAY_CAP];
    pm_day_of_ms(now, day);
    int status = 200;
    int collecting = 1;
    sqlite3 *db = NULL;
    pm_switch row;
    int rc = pm_open(database_path, &db) == 0 && pm_exec(db, "BEGIN IMMEDIATE") == 0 ? 0 : -1;
    if (rc == 0) {
        rc = pm_read_switch(db, tenant, &row);
    }
    if (rc == 0 && !pm_collecting(&row)) {
        collecting = 0;
    } else if (rc == 0 && !pm_limiter_admit(tenant, actor->username == NULL ? "" : actor->username,
                                            (long long)event_count, now)) {
        status = 429;
    } else {
        for (size_t k = 0; rc == 0 && k < key_count; ++k) {
            rc = pm_add_transfer(db, tenant, day, &counts[k]);
        }
    }
    if (rc == 0 && status == 200 && collecting) {
        rc = pm_exec(db, "COMMIT");
    }
    if (db != NULL && (rc != 0 || status != 200 || !collecting)) {
        pm_rollback(db);
    }
    sqlite3_close(db);
    if (rc != 0) {
        pm_respond_unavailable(response, "ingest", tenant);
        return;
    }
    if (status == 429) {
        pm_respond_code(response, 429, ST_PRODUCT_METRICS_CODE_RATE_LIMITED);
        return;
    }
    char answer[64];
    snprintf(answer, sizeof(answer), "{\"collecting\":%s,\"accepted\":%zu}",
             collecting ? "true" : "false", collecting ? event_count : (size_t)0U);
    pm_respond(response, 200, pm_dup(answer));
}

/* ---- Onboarding hooks (4.1) ------------------------------------------------------------------- */

static const char *pm_milestone(const char *database_path, const char *tenant, const char *username, int step)
{
    sqlite3 *db = NULL;
    if (pm_open(database_path, &db) != 0) {
        pm_log("milestone", tenant, "storage-unavailable");
        return "ignored";
    }
    const char *effect = "ignored";
    int failed = 0;
    pm_switch row;
    if (pm_read_switch(db, tenant, &row) != 0) {
        failed = 1;
    } else if (pm_collecting(&row)) {
        long long now = st_product_metrics_now_ms();
        if (step == PM_STEP_ACCOUNT) {
            /* The only milestone that starts a row; an existing row of the account stays as it is. */
            sqlite3_stmt *stmt = NULL;
            int rc = sqlite3_prepare_v2(db,
                "INSERT INTO product_metrics_onboarding_progress (" PM_PROGRESS_COLUMNS ") "
                "VALUES (?, ?, ?, NULL, NULL, NULL) ON CONFLICT (tenant_id, username) DO NOTHING",
                -1, &stmt, NULL) == SQLITE_OK
                && sqlite3_bind_text(stmt, 1, tenant, -1, SQLITE_TRANSIENT) == SQLITE_OK
                && sqlite3_bind_text(stmt, 2, username, -1, SQLITE_TRANSIENT) == SQLITE_OK
                && sqlite3_bind_int64(stmt, 3, now) == SQLITE_OK
                && sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
            sqlite3_finalize(stmt);
            if (rc != 0) {
                failed = 1;
            } else if (sqlite3_changes(db) == 1) {
                effect = "started";
            }
        } else {
            pm_progress progress;
            int found = pm_read_progress(db, tenant, username, &progress);
            if (found < 0) {
                failed = 1;
            } else if (found == 1 && now >= progress.started_at_ms + PM_WINDOW_MS) {
                /* Past the window: close as expired first, then drop the milestone. */
                if (pm_close_progress(db, tenant, username, 0, 0) < 0) {
                    failed = 1;
                } else {
                    effect = "expired";
                }
            } else if (found == 1 && step == PM_STEP_PUBLISHED) {
                int folded = pm_close_progress(db, tenant, username, 1, now);
                if (folded < 0) {
                    failed = 1;
                } else if (folded == 1) {
                    effect = "completed";
                }
            } else if (found == 1) {
                /* Only the first occurrence is kept, also between instances. */
                char sql[160];
                snprintf(sql, sizeof(sql),
                         "UPDATE product_metrics_onboarding_progress SET %s = ? "
                         "WHERE tenant_id = ? AND username = ? AND %s IS NULL",
                         pm_progress_column(step), pm_progress_column(step));
                sqlite3_stmt *stmt = NULL;
                int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK
                    && sqlite3_bind_int64(stmt, 1, now) == SQLITE_OK
                    && sqlite3_bind_text(stmt, 2, tenant, -1, SQLITE_TRANSIENT) == SQLITE_OK
                    && sqlite3_bind_text(stmt, 3, username, -1, SQLITE_TRANSIENT) == SQLITE_OK
                    && sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
                sqlite3_finalize(stmt);
                if (rc != 0) {
                    failed = 1;
                } else if (sqlite3_changes(db) == 1) {
                    effect = "recorded";
                }
            }
        }
    }
    sqlite3_close(db);
    if (failed) {
        pm_log("milestone", tenant, "storage-unavailable");
        return "ignored";
    }
    return effect;
}

const char *st_product_metrics_milestone(const char *database_path,
                                         const char *tenant_id,
                                         const char *username,
                                         const char *step)
{
    int index = pm_lookup_text(pm_steps, PM_COUNT(pm_steps), step);
    if (database_path == NULL || *database_path == '\0' || index < 0 || pm_blank(username)
        || !st_product_metrics_allowed()) {
        return "ignored";
    }
    return pm_milestone(database_path, pm_tenant(tenant_id), username, index);
}

const char *st_product_metrics_user_deleted(const char *database_path, const char *tenant_id, const char *username)
{
    if (database_path == NULL || *database_path == '\0' || pm_blank(username)) {
        return "ignored";
    }
    const char *tenant = pm_tenant(tenant_id);
    sqlite3 *db = NULL;
    int removed = 0;
    int rc = pm_open(database_path, &db) == 0
        ? pm_run(db, "DELETE FROM product_metrics_onboarding_progress WHERE tenant_id = ? AND username = ?",
                 tenant, username, NULL, &removed)
        : -1;
    sqlite3_close(db);
    if (rc != 0) {
        pm_log("user-deleted", tenant, "storage-unavailable");
        return "ignored";
    }
    return removed > 0 ? "deleted" : "ignored";
}

/* ---- Retention (9) ---------------------------------------------------------------------------- */

static int pm_list_switches(sqlite3 *db, pm_switch **rows, size_t *count)
{
    *rows = NULL;
    *count = 0U;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "SELECT " PM_SWITCH_COLUMNS " FROM product_metrics_switch ORDER BY tenant_id",
                           -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    size_t capacity = 0U;
    int step;
    while ((step = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (*count == capacity) {
            size_t next = capacity == 0U ? 8U : capacity * 2U;
            pm_switch *grown = (pm_switch *)realloc(*rows, next * sizeof(pm_switch));
            if (grown == NULL) {
                step = SQLITE_NOMEM;
                break;
            }
            *rows = grown;
            capacity = next;
        }
        pm_scan_switch(stmt, &(*rows)[(*count)++]);
    }
    sqlite3_finalize(stmt);
    if (step != SQLITE_DONE) {
        free(*rows);
        *rows = NULL;
        *count = 0U;
        return -1;
    }
    return 0;
}

/*
 * Step 1 for one row of a tenant that was not collecting when the sweep read the switches. The
 * delete checks the switch again, so a tenant switched on since keeps the row; when the deployment
 * does not allow metrics no tenant collects and the row goes regardless.
 */
static int pm_drop_progress(sqlite3 *db, const pm_progress *row)
{
    if (!st_product_metrics_allowed()) {
        return pm_run(db, "DELETE FROM product_metrics_onboarding_progress WHERE tenant_id = ? AND username = ?",
                      row->tenant_id, row->username, NULL, NULL);
    }
    return pm_run(db,
                  "DELETE FROM product_metrics_onboarding_progress WHERE tenant_id = ?1 AND username = ?2 "
                  "AND NOT EXISTS (SELECT 1 FROM product_metrics_switch WHERE tenant_id = ?1 AND enabled <> 0)",
                  row->tenant_id, row->username, NULL, NULL);
}

/*
 * Step 4: deletes both daily tables' rows and the progress rows of a tenant, each table only while
 * the tenant's switch is off with a purge mark when that statement runs. Switching on clears the
 * mark, so a tenant switched back on since the sweep read the switches keeps what it collected.
 */
#define PM_PURGED_WHILE_OFF \
    " AND EXISTS (SELECT 1 FROM product_metrics_switch WHERE tenant_id = ?1 AND enabled = 0 AND purged_at IS NOT NULL)"

static int pm_delete_purged_tenant_rows(sqlite3 *db, const char *tenant_id)
{
    static const char *const statements[] = {
        "DELETE FROM product_metrics_onboarding_daily WHERE tenant_id = ?1" PM_PURGED_WHILE_OFF,
        "DELETE FROM product_metrics_transfer_daily WHERE tenant_id = ?1" PM_PURGED_WHILE_OFF,
        "DELETE FROM product_metrics_onboarding_progress WHERE tenant_id = ?1" PM_PURGED_WHILE_OFF
    };
    for (size_t i = 0; i < sizeof(statements) / sizeof(statements[0]); ++i) {
        if (pm_run(db, statements[i], tenant_id, NULL, NULL, NULL) != 0) {
            return -1;
        }
    }
    return 0;
}

static pthread_mutex_t pm_sweep_hook_lock = PTHREAD_MUTEX_INITIALIZER;
static st_product_metrics_sweep_hook pm_sweep_hook = NULL;
static void *pm_sweep_hook_context = NULL;

void st_product_metrics_set_sweep_hook_for_testing(st_product_metrics_sweep_hook hook, void *context)
{
    pthread_mutex_lock(&pm_sweep_hook_lock);
    pm_sweep_hook = hook;
    pm_sweep_hook_context = context;
    pthread_mutex_unlock(&pm_sweep_hook_lock);
}

static void pm_run_sweep_hook(void)
{
    pthread_mutex_lock(&pm_sweep_hook_lock);
    st_product_metrics_sweep_hook hook = pm_sweep_hook;
    void *context = pm_sweep_hook_context;
    pthread_mutex_unlock(&pm_sweep_hook_lock);
    if (hook != NULL) {
        hook(context);
    }
}

/*
 * The four steps of section 9: progress of tenants that are off goes (no fold); progress past the
 * window closes as expired; daily rows older than the retention go; tenants that are off and were
 * purged since switching off lose every daily and progress row (stragglers written within the
 * switch cache period). Switching off clears the mark a purge made while collecting.
 * Idempotent, independent of when it runs, safe on any number of instances.
 */
int st_product_metrics_sweep(const char *database_path)
{
    long long now = st_product_metrics_now_ms();
    sqlite3 *db = NULL;
    pm_switch *switches = NULL;
    size_t switch_count = 0U;
    pm_progress *progress = NULL;
    size_t progress_count = 0U;
    int rc = pm_open(database_path, &db) == 0 ? 0 : -1;
    if (rc == 0) {
        rc = pm_list_switches(db, &switches, &switch_count);
    }
    if (rc == 0) {
        pm_run_sweep_hook();
        rc = pm_list_progress(db, NULL, &progress, &progress_count);
    }
    for (size_t i = 0; rc == 0 && i < progress_count; ++i) {
        const pm_progress *row = &progress[i];
        int collecting = 0;
        for (size_t s = 0; s < switch_count; ++s) {
            if (strcmp(switches[s].tenant_id, row->tenant_id) == 0) {
                collecting = pm_collecting(&switches[s]);
                break;
            }
        }
        if (!collecting) {
            rc = pm_drop_progress(db, row);
        } else if (now >= row->started_at_ms + PM_WINDOW_MS) {
            rc = pm_close_progress(db, row->tenant_id, row->username, 0, 0) < 0 ? -1 : 0;
        }
    }
    if (rc == 0) {
        char cutoff[PM_DAY_CAP];
        pm_day_text(pm_day_number_of_ms(now) - (ST_PRODUCT_METRICS_RETENTION_DAYS - 1), cutoff);
        rc = pm_run(db, "DELETE FROM product_metrics_onboarding_daily WHERE cohort_day < ?", cutoff, NULL, NULL, NULL) == 0
            && pm_run(db, "DELETE FROM product_metrics_transfer_daily WHERE day < ?", cutoff, NULL, NULL, NULL) == 0
            ? 0 : -1;
    }
    for (size_t s = 0; rc == 0 && s < switch_count; ++s) {
        if (!switches[s].enabled && switches[s].has_purged_at) {
            rc = pm_delete_purged_tenant_rows(db, switches[s].tenant_id);
        }
    }
    free(switches);
    free(progress);
    sqlite3_close(db);
    if (rc != 0) {
        pm_log("sweep", "-", "storage-unavailable");
    }
    return rc;
}

/* ---- Summary (7.5) ---------------------------------------------------------------------------- */

/*
 * Percent-decodes text[0..len) ('+' is a space) into out; the decoded length goes to *out_len.
 * -1 for a broken escape or when out_cap is too small.
 */
static int pm_percent_decode(const char *text, size_t len, char *out, size_t out_cap, size_t *out_len)
{
    size_t used = 0U;
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)text[i];
        if (c == '%') {
            if (i + 2U >= len) {
                return -1;
            }
            int high = pm_hex_digit((unsigned char)text[i + 1U]);
            int low = pm_hex_digit((unsigned char)text[i + 2U]);
            if (high < 0 || low < 0) {
                return -1;
            }
            c = (unsigned char)((high << 4) | low);
            i += 2U;
        } else if (c == '+') {
            c = ' ';
        }
        if (used + 1U >= out_cap) {
            return -1;
        }
        out[used++] = (char)c;
    }
    out[used] = '\0';
    *out_len = used;
    return 0;
}

/*
 * The first value of key in a raw query string: 1 with a malloc'd, percent-decoded *value ("" for
 * a bare key) and its decoded length, 0 when absent. A pair whose escapes do not decode is
 * skipped, as Go's url.Values parsing drops it.
 */
static int pm_query_value(const char *raw_query, const char *key, char **value, size_t *value_len)
{
    *value = NULL;
    *value_len = 0U;
    const char *part = raw_query;
    while (part != NULL && *part != '\0') {
        const char *amp = strchr(part, '&');
        size_t part_len = amp == NULL ? strlen(part) : (size_t)(amp - part);
        const char *equals = (const char *)memchr(part, '=', part_len);
        size_t key_len = equals == NULL ? part_len : (size_t)(equals - part);
        char decoded_key[32];
        size_t decoded_key_len = 0U;
        char *decoded = (char *)malloc(part_len + 1U);
        if (decoded == NULL) {
            return 0;
        }
        size_t decoded_len = 0U;
        if (pm_percent_decode(part, key_len, decoded_key, sizeof(decoded_key), &decoded_key_len) == 0
            && decoded_key_len == strlen(key) && memcmp(decoded_key, key, decoded_key_len) == 0
            && pm_percent_decode(equals == NULL ? part + part_len : equals + 1,
                                 equals == NULL ? 0U : part_len - key_len - 1U,
                                 decoded, part_len + 1U, &decoded_len) == 0) {
            *value = decoded;
            *value_len = decoded_len;
            return 1;
        }
        free(decoded);
        part = amp == NULL ? NULL : amp + 1;
    }
    return 0;
}

typedef struct {
    long long counts[PM_COUNT(pm_modes)][PM_COUNT(pm_paths)][PM_COUNT(pm_size_buckets)][PM_COUNT(pm_attempts)]
                    [PM_COUNT(pm_outcomes)];
} pm_transfer_table;

typedef struct {
    long long outcome[PM_COUNT(pm_outcomes)];
} pm_tally;

/* Sums the cells matching the given indexes (-1 matches any value). */
static pm_tally pm_tally_of(const pm_transfer_table *table, int mode, int path, int size_bucket, int attempt)
{
    pm_tally tally;
    memset(&tally, 0, sizeof(tally));
    for (size_t m = 0; m < PM_COUNT(pm_modes); ++m) {
        for (size_t p = 0; p < PM_COUNT(pm_paths); ++p) {
            for (size_t s = 0; s < PM_COUNT(pm_size_buckets); ++s) {
                for (size_t a = 0; a < PM_COUNT(pm_attempts); ++a) {
                    if ((mode >= 0 && (size_t)mode != m) || (path >= 0 && (size_t)path != p)
                        || (size_bucket >= 0 && (size_t)size_bucket != s) || (attempt >= 0 && (size_t)attempt != a)) {
                        continue;
                    }
                    for (size_t o = 0; o < PM_COUNT(pm_outcomes); ++o) {
                        tally.outcome[o] += table->counts[m][p][s][a][o];
                    }
                }
            }
        }
    }
    return tally;
}

static void pm_sb_tally(pm_sb *sb, const pm_tally *tally)
{
    long long success = tally->outcome[PM_OUTCOME_SUCCESS];
    long long failure = tally->outcome[PM_OUTCOME_FAILURE];
    pm_sb_appendf(sb, "\"success\":%lld,\"failure\":%lld,\"cancelled\":%lld,\"successRateBp\":",
                  success, failure, tally->outcome[PM_OUTCOME_CANCELLED]);
    pm_sb_rate(sb, success, success + failure);
}

typedef struct {
    long long reached[PM_COUNT(pm_steps)];
    long long durations[PM_COUNT(pm_duration_buckets)];
    long long pending;
} pm_onboarding_totals;

/* Reads everything the summary needs inside one read transaction, so it sees one state. */
static int pm_summary_read(sqlite3 *db,
                           const char *tenant,
                           const char *low,
                           const char *high,
                           long long low_day,
                           long long high_day,
                           long long now,
                           pm_switch *row,
                           pm_onboarding_totals *onboarding,
                           pm_transfer_table *transfers)
{
    if (pm_exec(db, "BEGIN") != 0) {
        return -1;
    }
    int rc = pm_read_switch(db, tenant, row);
    sqlite3_stmt *stmt = NULL;
    int step = SQLITE_DONE;
    if (rc == 0 && (sqlite3_prepare_v2(db,
            "SELECT reached_step, duration_bucket, users FROM product_metrics_onboarding_daily "
            "WHERE tenant_id = ? AND cohort_day >= ? AND cohort_day <= ?",
            -1, &stmt, NULL) != SQLITE_OK
        || sqlite3_bind_text(stmt, 1, tenant, -1, SQLITE_TRANSIENT) != SQLITE_OK
        || sqlite3_bind_text(stmt, 2, low, -1, SQLITE_TRANSIENT) != SQLITE_OK
        || sqlite3_bind_text(stmt, 3, high, -1, SQLITE_TRANSIENT) != SQLITE_OK)) {
        rc = -1;
    }
    while (rc == 0 && (step = sqlite3_step(stmt)) == SQLITE_ROW) {
        int reached = pm_lookup_text(pm_steps, PM_COUNT(pm_steps), (const char *)sqlite3_column_text(stmt, 0));
        const char *bucket_text = (const char *)sqlite3_column_text(stmt, 1);
        int bucket = pm_lookup_text(pm_duration_buckets, PM_COUNT(pm_duration_buckets), bucket_text);
        long long users = sqlite3_column_int64(stmt, 2);
        if (reached >= 0) {
            onboarding->reached[reached] += users;
        }
        if (bucket >= 0) {
            onboarding->durations[bucket] += users;
        }
    }
    sqlite3_finalize(stmt);
    stmt = NULL;
    if (rc == 0 && step != SQLITE_DONE) {
        rc = -1;
    }
    pm_progress *progress = NULL;
    size_t progress_count = 0U;
    if (rc == 0) {
        rc = pm_list_progress(db, tenant, &progress, &progress_count);
    }
    for (size_t i = 0; rc == 0 && i < progress_count; ++i) {
        long long cohort = pm_day_number_of_ms(progress[i].started_at_ms);
        if (cohort < low_day || cohort > high_day) {
            continue;
        }
        ++onboarding->reached[pm_reached_step(&progress[i])];
        if (now < progress[i].started_at_ms + PM_WINDOW_MS) {
            ++onboarding->pending;
        }
    }
    free(progress);
    if (rc == 0 && (sqlite3_prepare_v2(db,
            "SELECT mode, path, size_bucket, attempt, outcome, count FROM product_metrics_transfer_daily "
            "WHERE tenant_id = ? AND day >= ? AND day <= ?",
            -1, &stmt, NULL) != SQLITE_OK
        || sqlite3_bind_text(stmt, 1, tenant, -1, SQLITE_TRANSIENT) != SQLITE_OK
        || sqlite3_bind_text(stmt, 2, low, -1, SQLITE_TRANSIENT) != SQLITE_OK
        || sqlite3_bind_text(stmt, 3, high, -1, SQLITE_TRANSIENT) != SQLITE_OK)) {
        rc = -1;
    }
    while (rc == 0 && (step = sqlite3_step(stmt)) == SQLITE_ROW) {
        int mode = pm_lookup_text(pm_modes, PM_COUNT(pm_modes), (const char *)sqlite3_column_text(stmt, 0));
        int path = pm_lookup_text(pm_paths, PM_COUNT(pm_paths), (const char *)sqlite3_column_text(stmt, 1));
        int size = pm_lookup_text(pm_size_buckets, PM_COUNT(pm_size_buckets), (const char *)sqlite3_column_text(stmt, 2));
        int attempt = pm_lookup_text(pm_attempts, PM_COUNT(pm_attempts), (const char *)sqlite3_column_text(stmt, 3));
        int outcome = pm_lookup_text(pm_outcomes, PM_COUNT(pm_outcomes), (const char *)sqlite3_column_text(stmt, 4));
        if (mode >= 0 && path >= 0 && size >= 0 && attempt >= 0 && outcome >= 0) {
            transfers->counts[mode][path][size][attempt][outcome] += sqlite3_column_int64(stmt, 5);
        }
    }
    sqlite3_finalize(stmt);
    if (rc == 0 && step != SQLITE_DONE) {
        rc = -1;
    }
    if (rc == 0) {
        rc = pm_exec(db, "COMMIT");
    }
    if (rc != 0) {
        pm_rollback(db);
    }
    return rc;
}

static char *pm_render_summary(const pm_switch *row,
                               const char *low,
                               const char *high,
                               long long now,
                               const pm_onboarding_totals *onboarding,
                               const pm_transfer_table *transfers)
{
    char generated_at[PM_INSTANT_CAP];
    pm_instant_text(now, generated_at);
    pm_sb sb = {0};
    pm_sb_appendf(&sb, "{\"schemaVersion\":%d,\"enabled\":%s,\"from\":\"%s\",\"to\":\"%s\",\"generatedAt\":\"%s\",",
                  ST_PRODUCT_METRICS_SCHEMA_VERSION, pm_collecting(row) ? "true" : "false", low, high, generated_at);

    long long users_at[PM_COUNT(pm_steps)];
    for (size_t step = 0; step < PM_COUNT(pm_steps); ++step) {
        users_at[step] = 0;
        for (size_t later = step; later < PM_COUNT(pm_steps); ++later) {
            users_at[step] += onboarding->reached[later];
        }
    }
    long long cohort_users = users_at[PM_STEP_ACCOUNT];
    long long completed = users_at[PM_STEP_PUBLISHED];
    pm_sb_appendf(&sb, "\"onboarding\":{\"windowDays\":%d,\"cohortUsers\":%lld,\"pendingUsers\":%lld,\"final\":%s,"
                       "\"steps\":[",
                  ST_PRODUCT_METRICS_WINDOW_DAYS, cohort_users, onboarding->pending,
                  onboarding->pending == 0 ? "true" : "false");
    for (size_t step = 0; step < PM_COUNT(pm_steps); ++step) {
        pm_sb_appendf(&sb, "%s{\"step\":\"%s\",\"users\":%lld,\"fromPreviousRateBp\":",
                      step == 0 ? "" : ",", pm_steps[step], users_at[step]);
        if (step == 0) {
            pm_sb_appendf(&sb, "null");
        } else {
            pm_sb_rate(&sb, users_at[step], users_at[step - 1U]);
        }
        pm_sb_appendf(&sb, "}");
    }
    pm_sb_appendf(&sb, "],\"completed\":%lld,\"completionRateBp\":", completed);
    pm_sb_rate(&sb, completed, cohort_users);
    pm_sb_appendf(&sb, ",\"durations\":[");
    long long completers = 0;
    for (size_t bucket = 0; bucket < PM_COUNT(pm_duration_buckets); ++bucket) {
        pm_sb_appendf(&sb, "%s{\"bucket\":\"%s\",\"users\":%lld}", bucket == 0 ? "" : ",",
                      pm_duration_buckets[bucket], onboarding->durations[bucket]);
        completers += onboarding->durations[bucket];
    }
    pm_sb_appendf(&sb, "],\"medianDurationBucket\":");
    const char *median = NULL;
    long long position = (completers + 1) / 2; /* the ceil(n/2)-th completer, counted from 1 */
    for (size_t bucket = 0; completers > 0 && bucket < PM_COUNT(pm_duration_buckets); ++bucket) {
        if (position <= onboarding->durations[bucket]) {
            median = pm_duration_buckets[bucket];
            break;
        }
        position -= onboarding->durations[bucket];
    }
    if (median == NULL) {
        pm_sb_appendf(&sb, "null");
    } else {
        pm_sb_appendf(&sb, "\"%s\"", median);
    }

    pm_sb_appendf(&sb, "},\"transfers\":{\"cells\":[");
    int first_cell = 1;
    for (size_t path = 0; path < PM_COUNT(pm_paths); ++path) {
        for (size_t size = 0; size < PM_COUNT(pm_size_buckets); ++size) {
            pm_tally tally = pm_tally_of(transfers, -1, (int)path, (int)size, -1);
            if (tally.outcome[0] + tally.outcome[1] + tally.outcome[2] == 0) {
                continue;
            }
            pm_sb_appendf(&sb, "%s{\"path\":\"%s\",\"sizeBucket\":\"%s\",", first_cell ? "" : ",",
                          pm_paths[path], pm_size_buckets[size]);
            pm_sb_tally(&sb, &tally);
            pm_sb_appendf(&sb, "}");
            first_cell = 0;
        }
    }
    pm_sb_appendf(&sb, "],\"byMode\":[");
    for (size_t mode = 0; mode < PM_COUNT(pm_modes); ++mode) {
        pm_tally tally = pm_tally_of(transfers, (int)mode, -1, -1, -1);
        pm_sb_appendf(&sb, "%s{\"mode\":\"%s\",", mode == 0 ? "" : ",", pm_modes[mode]);
        pm_sb_tally(&sb, &tally);
        pm_sb_appendf(&sb, "}");
    }
    pm_sb_appendf(&sb, "],\"byAttempt\":[");
    for (size_t attempt = 0; attempt < PM_COUNT(pm_attempts); ++attempt) {
        pm_tally tally = pm_tally_of(transfers, -1, -1, -1, (int)attempt);
        pm_sb_appendf(&sb, "%s{\"attempt\":\"%s\",", attempt == 0 ? "" : ",", pm_attempts[attempt]);
        pm_sb_tally(&sb, &tally);
        pm_sb_appendf(&sb, "}");
    }
    pm_tally total = pm_tally_of(transfers, -1, -1, -1, -1);
    pm_sb_appendf(&sb, "],\"total\":{");
    pm_sb_tally(&sb, &total);
    pm_sb_appendf(&sb, "}}}");
    return pm_sb_finish(&sb);
}

static void pm_summary(const char *database_path,
                       const st_product_metrics_actor *actor,
                       const char *raw_query,
                       st_product_metrics_response *response)
{
    if (!actor->admin) {
        pm_respond(response, 403, NULL);
        return;
    }
    long long now = st_product_metrics_now_ms();
    long long today = pm_day_number_of_ms(now);
    long long to_day = today;
    long long from_day = 0;
    char *value = NULL;
    size_t value_len = 0U;
    int bad = 0;
    /* A decoded NUL would hide the rest of the value from the format check: refuse it. */
    if (pm_query_value(raw_query, "to", &value, &value_len)) {
        bad = strlen(value) != value_len || pm_parse_day(value, &to_day) != 0;
        free(value);
    }
    from_day = to_day - 29;
    if (!bad && pm_query_value(raw_query, "from", &value, &value_len)) {
        bad = strlen(value) != value_len || pm_parse_day(value, &from_day) != 0;
        free(value);
    }
    if (bad || from_day > to_day || to_day - from_day + 1 > ST_PRODUCT_METRICS_MAX_RANGE_DAYS || to_day > today
        || from_day < today - (ST_PRODUCT_METRICS_RETENTION_DAYS - 1)) {
        pm_respond_code(response, 400, ST_PRODUCT_METRICS_CODE_RANGE);
        return;
    }
    const char *tenant = pm_tenant(actor->tenant_id);
    char low[PM_DAY_CAP];
    char high[PM_DAY_CAP];
    pm_day_text(from_day, low);
    pm_day_text(to_day, high);
    pm_switch row;
    pm_onboarding_totals onboarding;
    pm_transfer_table *transfers = (pm_transfer_table *)calloc(1U, sizeof(pm_transfer_table));
    memset(&onboarding, 0, sizeof(onboarding));
    sqlite3 *db = NULL;
    int rc = transfers != NULL && pm_open(database_path, &db) == 0
        ? pm_summary_read(db, tenant, low, high, from_day, to_day, now, &row, &onboarding, transfers)
        : -1;
    sqlite3_close(db);
    if (rc != 0) {
        free(transfers);
        pm_respond_unavailable(response, "summary", tenant);
        return;
    }
    char *body = pm_render_summary(&row, low, high, now, &onboarding, transfers);
    free(transfers);
    pm_respond(response, 200, body);
}

/* ---- Routing ---------------------------------------------------------------------------------- */

int st_product_metrics_path(const char *path)
{
    return path != NULL
        && strncmp(path, ST_PRODUCT_METRICS_PATH_PREFIX, strlen(ST_PRODUCT_METRICS_PATH_PREFIX)) == 0;
}

st_product_metrics_endpoint st_product_metrics_match(const char *method, const char *path)
{
    if (method == NULL || !st_product_metrics_path(path)) {
        return ST_PRODUCT_METRICS_NO_ENDPOINT;
    }
    const char *rest = path + strlen(ST_PRODUCT_METRICS_PATH_PREFIX);
    size_t rest_len = strcspn(rest, "?");
    static const struct {
        const char *method;
        const char *name;
        st_product_metrics_endpoint endpoint;
    } routes[] = {
        {"GET", "settings", ST_PRODUCT_METRICS_GET_SETTINGS},
        {"PUT", "settings", ST_PRODUCT_METRICS_PUT_SETTINGS},
        {"DELETE", "data", ST_PRODUCT_METRICS_PURGE},
        {"POST", "transfer-outcomes", ST_PRODUCT_METRICS_INGEST},
        {"GET", "summary", ST_PRODUCT_METRICS_SUMMARY}
    };
    for (size_t i = 0; i < PM_COUNT(routes); ++i) {
        if (strcmp(method, routes[i].method) == 0 && strlen(routes[i].name) == rest_len
            && memcmp(rest, routes[i].name, rest_len) == 0) {
            return routes[i].endpoint;
        }
    }
    return ST_PRODUCT_METRICS_NO_ENDPOINT;
}

void st_product_metrics_handle(const char *database_path,
                               st_product_metrics_endpoint endpoint,
                               const st_product_metrics_actor *actor,
                               const char *raw_query,
                               const char *body,
                               size_t body_len,
                               st_product_metrics_response *response)
{
    response->status = 500;
    response->body = NULL;
    switch (endpoint) {
    case ST_PRODUCT_METRICS_GET_SETTINGS:
        pm_get_settings(database_path, actor, response);
        break;
    case ST_PRODUCT_METRICS_PUT_SETTINGS:
        pm_put_settings(database_path, actor, body, body_len, response);
        break;
    case ST_PRODUCT_METRICS_PURGE:
        pm_purge(database_path, actor, response);
        break;
    case ST_PRODUCT_METRICS_INGEST:
        pm_ingest(database_path, actor, body, body_len, response);
        break;
    case ST_PRODUCT_METRICS_SUMMARY:
        pm_summary(database_path, actor, raw_query, response);
        break;
    default:
        break;
    }
}
