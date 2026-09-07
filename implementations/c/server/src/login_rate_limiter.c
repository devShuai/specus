#include "login_rate_limiter.h"

#include <ctype.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define ST_LOGIN_RATE_LIMIT_MAX_TRACKED_KEYS 100000U

typedef struct st_login_rate_window {
    char *key;
    int64_t start_seconds;
    unsigned int count;
    struct st_login_rate_window *next;
} st_login_rate_window;

static pthread_mutex_t login_rate_limit_lock = PTHREAD_MUTEX_INITIALIZER;
static st_login_rate_window *login_ip_windows = NULL;
static st_login_rate_window *login_account_windows = NULL;
static size_t login_ip_window_count = 0U;
static size_t login_account_window_count = 0U;

static char *login_normalize_key(const char *value, int lowercase)
{
    const char *source = value == NULL ? "" : value;
    while (*source != '\0' && isspace((unsigned char)*source)) {
        ++source;
    }
    const char *end = source + strlen(source);
    while (end > source && isspace((unsigned char)end[-1])) {
        --end;
    }
    if (end == source) {
        source = "unknown";
        end = source + strlen(source);
    }
    size_t len = (size_t)(end - source);
    char *normalized = malloc(len + 1U);
    if (normalized == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < len; ++i) {
        unsigned char ch = (unsigned char)source[i];
        normalized[i] = lowercase ? (char)tolower(ch) : (char)ch;
    }
    normalized[len] = '\0';
    return normalized;
}

static void login_free_windows(st_login_rate_window **head, size_t *count)
{
    st_login_rate_window *window = *head;
    while (window != NULL) {
        st_login_rate_window *next = window->next;
        free(window->key);
        free(window);
        window = next;
    }
    *head = NULL;
    *count = 0U;
}

static void login_purge_expired(st_login_rate_window **head,
                                size_t *count,
                                int64_t now_seconds,
                                int64_t window_seconds)
{
    st_login_rate_window **cursor = head;
    while (*cursor != NULL) {
        st_login_rate_window *window = *cursor;
        int expired = now_seconds >= window->start_seconds
            && now_seconds - window->start_seconds >= window_seconds;
        if (!expired) {
            cursor = &window->next;
            continue;
        }
        *cursor = window->next;
        free(window->key);
        free(window);
        if (*count > 0U) {
            --*count;
        }
    }
}

static void login_record_window(st_login_rate_window **head,
                                size_t *tracked_count,
                                const char *key,
                                int64_t now_seconds,
                                int64_t window_seconds,
                                unsigned int *attempt_count,
                                int64_t *start_seconds)
{
    for (st_login_rate_window *window = *head; window != NULL; window = window->next) {
        if (strcmp(window->key, key) != 0) {
            continue;
        }
        if (now_seconds >= window->start_seconds
            && now_seconds - window->start_seconds >= window_seconds) {
            window->start_seconds = now_seconds;
            window->count = 1U;
        } else if (window->count < UINT_MAX) {
            ++window->count;
        }
        *attempt_count = window->count;
        *start_seconds = window->start_seconds;
        return;
    }

    if (*tracked_count >= ST_LOGIN_RATE_LIMIT_MAX_TRACKED_KEYS) {
        *attempt_count = UINT_MAX;
        *start_seconds = now_seconds;
        return;
    }
    st_login_rate_window *created = calloc(1U, sizeof(*created));
    if (created == NULL) {
        *attempt_count = UINT_MAX;
        *start_seconds = now_seconds;
        return;
    }
    size_t key_len = strlen(key);
    created->key = malloc(key_len + 1U);
    if (created->key == NULL) {
        free(created);
        *attempt_count = UINT_MAX;
        *start_seconds = now_seconds;
        return;
    }
    memcpy(created->key, key, key_len + 1U);
    created->start_seconds = now_seconds;
    created->count = 1U;
    created->next = *head;
    *head = created;
    ++*tracked_count;
    *attempt_count = created->count;
    *start_seconds = created->start_seconds;
}

static void login_remove_window(st_login_rate_window **head, size_t *count, const char *key)
{
    st_login_rate_window **cursor = head;
    while (*cursor != NULL) {
        st_login_rate_window *window = *cursor;
        if (strcmp(window->key, key) != 0) {
            cursor = &window->next;
            continue;
        }
        *cursor = window->next;
        free(window->key);
        free(window);
        if (*count > 0U) {
            --*count;
        }
        return;
    }
}

static unsigned int login_positive_limit(unsigned int value)
{
    return value == 0U ? 1U : value;
}

int st_login_rate_limiter_check(const char *client_ip,
                                const char *account,
                                const st_login_rate_limit_config *config,
                                int64_t now_seconds,
                                int64_t *retry_after_seconds)
{
    if (retry_after_seconds != NULL) {
        *retry_after_seconds = 0;
    }
    if (config == NULL || !config->enabled) {
        return 0;
    }
    int64_t window_seconds = config->window_seconds < 1 ? 1 : config->window_seconds;
    char *ip_key = login_normalize_key(client_ip, 0);
    char *account_key = login_normalize_key(account, 1);
    if (ip_key == NULL || account_key == NULL) {
        free(ip_key);
        free(account_key);
        if (retry_after_seconds != NULL) {
            *retry_after_seconds = window_seconds;
        }
        return 1;
    }

    pthread_mutex_lock(&login_rate_limit_lock);
    login_purge_expired(&login_ip_windows,
                        &login_ip_window_count,
                        now_seconds,
                        window_seconds);
    login_purge_expired(&login_account_windows,
                        &login_account_window_count,
                        now_seconds,
                        window_seconds);
    unsigned int ip_attempts = 0U;
    unsigned int account_attempts = 0U;
    int64_t ip_start = now_seconds;
    int64_t account_start = now_seconds;
    login_record_window(&login_ip_windows,
                        &login_ip_window_count,
                        ip_key,
                        now_seconds,
                        window_seconds,
                        &ip_attempts,
                        &ip_start);
    login_record_window(&login_account_windows,
                        &login_account_window_count,
                        account_key,
                        now_seconds,
                        window_seconds,
                        &account_attempts,
                        &account_start);
    int ip_exceeded = ip_attempts > login_positive_limit(config->per_ip);
    int account_exceeded = account_attempts > login_positive_limit(config->per_account);
    int64_t blocking_start = ip_exceeded ? ip_start : account_start;
    pthread_mutex_unlock(&login_rate_limit_lock);
    free(ip_key);
    free(account_key);

    if (!ip_exceeded && !account_exceeded) {
        return 0;
    }
    int64_t elapsed = now_seconds >= blocking_start ? now_seconds - blocking_start : 0;
    int64_t retry_after = window_seconds - elapsed;
    if (retry_after < 1) {
        retry_after = 1;
    }
    if (retry_after_seconds != NULL) {
        *retry_after_seconds = retry_after;
    }
    return 1;
}

void st_login_rate_limiter_record_success(const char *account)
{
    char *key = login_normalize_key(account, 1);
    if (key == NULL) {
        return;
    }
    pthread_mutex_lock(&login_rate_limit_lock);
    login_remove_window(&login_account_windows, &login_account_window_count, key);
    pthread_mutex_unlock(&login_rate_limit_lock);
    free(key);
}

void st_login_rate_limiter_reset(void)
{
    pthread_mutex_lock(&login_rate_limit_lock);
    login_free_windows(&login_ip_windows, &login_ip_window_count);
    login_free_windows(&login_account_windows, &login_account_window_count);
    pthread_mutex_unlock(&login_rate_limit_lock);
}
