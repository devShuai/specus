#define _POSIX_C_SOURCE 200809L
#include "instant.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

static int leap(int year)
{
    return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
}

static int month_days(int year, int month)
{
    static const int days[] = {31,28,31,30,31,30,31,31,30,31,30,31};
    return days[month - 1] + (month == 2 && leap(year));
}

/* Count from proleptic Gregorian year0000, including its leap day. */
static long long year_days(int year)
{
    return 365LL * year + (year + 3) / 4 - (year + 99) / 100 + (year + 399) / 400;
}

static long long date_days(int year, int month, int day)
{
    long long days = year_days(year) - year_days(1970) + day - 1;
    for (int m = 1; m < month; ++m) days += month_days(year, m);
    return days;
}

int st_instant_format(long long epoch_seconds, long nanoseconds, char out[ST_INSTANT_CAPACITY])
{
    if (out == NULL || nanoseconds < 0 || nanoseconds >= 1000000000L
        || epoch_seconds < date_days(0, 1, 1) * 86400LL
        || epoch_seconds >= year_days(10000) * 86400LL - year_days(1970) * 86400LL) return -1;
    long long day = epoch_seconds / 86400LL;
    long long within = epoch_seconds % 86400LL;
    if (within < 0) { within += 86400LL; --day; }
    day += year_days(1970);
    int low = 0, high = 10000;
    while (low + 1 < high) {
        int mid = low + (high - low) / 2;
        if (year_days(mid) <= day) low = mid; else high = mid;
    }
    int month = 1;
    day -= year_days(low);
    while (month < 12 && day >= month_days(low, month)) { day -= month_days(low, month); ++month; }
    int n = snprintf(out, ST_INSTANT_CAPACITY, "%04d-%02d-%02dT%02d:%02d:%02d.%07ldZ",
                     low, month, (int)day + 1, (int)(within / 3600LL),
                     (int)(within / 60LL % 60LL), (int)(within % 60LL), nanoseconds / 100L);
    return n == 28 ? 0 : -1;
}

int st_instant_format_millis(long long epoch_millis, char out[ST_INSTANT_CAPACITY])
{
    long long seconds = epoch_millis / 1000LL;
    long remainder = (long)(epoch_millis % 1000LL);
    if (remainder < 0) { --seconds; remainder += 1000; }
    return st_instant_format(seconds, remainder * 1000000L, out);
}

int st_instant_now(char out[ST_INSTANT_CAPACITY])
{
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0) return -1;
    return st_instant_format((long long)now.tv_sec, now.tv_nsec, out);
}

static int digits(const char *text, size_t at, size_t count)
{
    int value = 0;
    for (size_t i = 0; i < count; ++i) {
        unsigned char c = (unsigned char)text[at + i];
        if (c < '0' || c > '9') return -1;
        value = value * 10 + (c - '0');
    }
    return value;
}

int st_instant_normalize(const char *input, char out[ST_INSTANT_CAPACITY])
{
    if (input == NULL || out == NULL) return -1;
    size_t len = strnlen(input, 48U);
    if (len < 19U || len >= 48U || input[4] != '-' || input[7] != '-'
        || (input[10] != 'T' && input[10] != 't' && input[10] != ' ')
        || input[13] != ':' || input[16] != ':') return -1;
    int year = digits(input, 0, 4), month = digits(input, 5, 2), day = digits(input, 8, 2);
    int hour = digits(input, 11, 2), minute = digits(input, 14, 2), second = digits(input, 17, 2);
    if (year < 0 || month < 1 || month > 12 || day < 1 || day > month_days(year, month)
        || hour < 0 || hour > 24 || minute < 0 || minute > 59 || second < 0 || second > 60) return -1;
    size_t at = 19U; long nanos = 0;
    if (at < len && input[at] == '.') {
        ++at; size_t start = at;
        while (at < len && input[at] >= '0' && input[at] <= '9') {
            if (at - start >= 9U) return -1;
            nanos = nanos * 10L + input[at++] - '0';
        }
        if (at == start) return -1;
        for (size_t i = at - start; i < 9U; ++i) nanos *= 10L;
    }
    int offset = 0;
    if (at < len && (input[at] == 'Z' || input[at] == 'z')) ++at;
    else if (at < len && (input[at] == '+' || input[at] == '-')) {
        int sign = input[at] == '+' ? 1 : -1;
        if (len - at != 6U || input[at + 3U] != ':') return -1;
        int h = digits(input, at + 1U, 2), m = digits(input, at + 4U, 2);
        if (h < 0 || h > 18 || m < 0 || m > 59 || (h == 18 && m != 0)) return -1;
        offset = sign * (h * 3600 + m * 60); at += 6U;
    } else if (input[10] != ' ') return -1;
    if (at != len || (hour == 24 && (minute != 0 || second != 0 || nanos != 0))
        || (second == 60 && (hour != 23 || minute != 59 || offset != 0))) return -1;
    /* Instant.parse represents an accepted UTC leap second as the preceding second. */
    if (second == 60) second = 59;
    long long seconds = date_days(year, month, day) * 86400LL + hour * 3600 + minute * 60 + second - offset;
    return st_instant_format(seconds, nanos, out);
}

int st_instant_add_seconds(const char *input, long long delta, char out[ST_INSTANT_CAPACITY])
{
    char normal[ST_INSTANT_CAPACITY];
    if (out == NULL || st_instant_normalize(input, normal) != 0) return -1;
    long long seconds = date_days(digits(normal, 0, 4), digits(normal, 5, 2), digits(normal, 8, 2)) * 86400LL
        + digits(normal, 11, 2) * 3600LL + digits(normal, 14, 2) * 60LL + digits(normal, 17, 2);
    long long minimum = date_days(0, 1, 1) * 86400LL;
    long long maximum = date_days(9999, 12, 31) * 86400LL + 86399LL;
    /* Check before addition, including LLONG_MIN/MAX: neither difference can overflow. */
    if (delta < minimum - seconds || delta > maximum - seconds) return -1;
    return st_instant_format(seconds + delta, (long)digits(normal, 20, 7) * 100L, out);
}

int st_instant_public(const char *input, char *out, size_t capacity)
{
    if (input == NULL || out == NULL || capacity == 0U) return -1;
    char normal[ST_INSTANT_CAPACITY];
    if (st_instant_normalize(input, normal) != 0) {
        size_t len = strnlen(input, capacity);
        if (len >= capacity) return -1;
        memmove(out, input, len + 1U); return 0;
    }
    int fraction = digits(normal, 20U, 7U);
    int width = fraction == 0 ? 0 : fraction % 10000 == 0 ? 3 : fraction % 10 == 0 ? 6 : 9;
    int n = width == 0 ? snprintf(out, capacity, "%.19sZ", normal)
        : snprintf(out, capacity, "%.19s.%0*dZ", normal, width,
                   width == 3 ? fraction / 10000 : width == 6 ? fraction / 10 : fraction * 100);
    return n >= 0 && (size_t)n < capacity ? 0 : -1;
}
