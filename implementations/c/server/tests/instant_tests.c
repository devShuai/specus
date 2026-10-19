#include "instant.h"
#include <stdio.h>
#include <string.h>
#include <limits.h>

#define CHECK(ok) do { if (!(ok)) { fprintf(stderr, "instant failed line%d\n", __LINE__); return 1; } } while (0)

int main(void)
{
    const struct { const char *input; const char *stored; const char *view; } cases[] = {
        {"2026-09-15T12:00:00Z", "2026-09-15T12:00:00.0000000Z", "2026-09-15T12:00:00Z"},
        {"2026-09-15T12:00:00.500Z", "2026-09-15T12:00:00.5000000Z", "2026-09-15T12:00:00.500Z"},
        {"2026-09-15T12:00:00.500001Z", "2026-09-15T12:00:00.5000010Z", "2026-09-15T12:00:00.500001Z"},
        {"2026-09-15T12:00:00.000000123Z", "2026-09-15T12:00:00.0000001Z", "2026-09-15T12:00:00.000000100Z"},
        {"2026-09-15T12:00:00.123456799Z", "2026-09-15T12:00:00.1234567Z", "2026-09-15T12:00:00.123456700Z"},
        {"2026-09-15 12:00:00", "2026-09-15T12:00:00.0000000Z", "2026-09-15T12:00:00Z"},
        {"2026-09-15T20:00:00.5+08:00", "2026-09-15T12:00:00.5000000Z", "2026-09-15T12:00:00.500Z"},
        {"2026-01-01T01:00:00+02:00", "2025-12-31T23:00:00.0000000Z", "2025-12-31T23:00:00Z"},
        {"2026-12-31T23:00:00-02:00", "2027-01-01T01:00:00.0000000Z", "2027-01-01T01:00:00Z"},
        {"2000-02-29T24:00:00Z", "2000-03-01T00:00:00.0000000Z", "2000-03-01T00:00:00Z"},
        {"1969-12-31T23:59:59.999Z", "1969-12-31T23:59:59.9990000Z", "1969-12-31T23:59:59.999Z"},
        {"0000-01-01T00:00:00Z", "0000-01-01T00:00:00.0000000Z", "0000-01-01T00:00:00Z"},
        {"9999-12-31T23:59:59Z", "9999-12-31T23:59:59.0000000Z", "9999-12-31T23:59:59Z"},
        {"2016-12-31T23:59:60Z", "2016-12-31T23:59:59.0000000Z", "2016-12-31T23:59:59Z"}
    };
    char normal[ST_INSTANT_CAPACITY], view[ST_INSTANT_CAPACITY], again[ST_INSTANT_CAPACITY];
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        CHECK(st_instant_normalize(cases[i].input, normal) == 0 && strcmp(normal, cases[i].stored) == 0);
        CHECK(st_instant_normalize(normal, again) == 0 && strcmp(again, normal) == 0);
        CHECK(st_instant_public(normal, view, sizeof(view)) == 0 && strcmp(view, cases[i].view) == 0);
    }
    const char *invalid[] = {"", "not-an-instant", "2026-02-29T00:00:00Z", "1900-02-29T00:00:00Z",
        "2026-01-01T00:00:00", "2026-01-01T00:00:00.Z", "2026-01-01T00:00:00.1234567890Z",
        "2026-01-01T24:00:00.1Z", "2026-01-01T23:00:60Z", "2026-01-01T00:00:00+18:01",
        "2026-01-01T00:00:00Zsuffix", "0000-01-01T00:00:00+01:00", "9999-12-31T24:00:00Z"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        CHECK(st_instant_normalize(invalid[i], normal) == -1);
        CHECK(st_instant_public(invalid[i], view, sizeof(view)) == 0 && strcmp(view, invalid[i]) == 0);
    }
    CHECK(st_instant_format_millis(-1, normal) == 0 && strcmp(normal, "1969-12-31T23:59:59.9990000Z") == 0);
    CHECK(st_instant_format_millis(0, normal) == 0 && strcmp(normal, "1970-01-01T00:00:00.0000000Z") == 0);
    CHECK(st_instant_format(0, 1000000000L, normal) == -1);
    CHECK(st_instant_public("not-an-instant", view, 4U) == -1);
    CHECK(st_instant_now(normal) == 0 && strlen(normal) == 28U && st_instant_normalize(normal, again) == 0);
    const struct { const char *from; long long delta; const char *to; } additions[] = {
        {"2026-09-15T12:00:00.1234567Z", 45, "2026-09-15T12:00:45.1234567Z"},
        {"2026-09-15T20:00:00.000000123+08:00", 45, "2026-09-15T12:00:45.0000001Z"},
        {"2026-09-15 12:00:00", 45, "2026-09-15T12:00:45.0000000Z"},
        {"1999-12-31T23:59:59.9999999Z", 1, "2000-01-01T00:00:00.9999999Z"},
        {"2000-02-29T23:59:59.125Z", 1, "2000-03-01T00:00:00.1250000Z"},
        {"1970-01-01T00:00:00.0000001Z", -1, "1969-12-31T23:59:59.0000001Z"},
        {"0000-01-01T00:00:01.123Z", -1, "0000-01-01T00:00:00.1230000Z"},
        {"9999-12-31T23:59:58.123Z", 1, "9999-12-31T23:59:59.1230000Z"},
        {"2026-09-15T12:00:00.1234567Z", 0, "2026-09-15T12:00:00.1234567Z"}
    };
    for (size_t i = 0; i < sizeof(additions) / sizeof(additions[0]); ++i) {
        CHECK(st_instant_add_seconds(additions[i].from, additions[i].delta, normal) == 0 && strcmp(normal, additions[i].to) == 0);
        CHECK(st_instant_add_seconds(normal, -additions[i].delta, normal) == 0
            && st_instant_normalize(additions[i].from, again) == 0 && strcmp(normal, again) == 0);
    }
    CHECK(st_instant_add_seconds("0000-01-01T00:00:00Z", -1, normal) == -1);
    CHECK(st_instant_add_seconds("9999-12-31T23:59:59Z", 1, normal) == -1);
    CHECK(st_instant_add_seconds("2026-09-15T12:00:00Z", LLONG_MIN, normal) == -1);
    CHECK(st_instant_add_seconds("2026-09-15T12:00:00Z", LLONG_MAX, normal) == -1);
    CHECK(st_instant_add_seconds(NULL, 45, normal) == -1 && st_instant_add_seconds("bad", 45, normal) == -1);
    CHECK(st_instant_add_seconds("2026-09-15T12:00:00Z", 45, NULL) == -1);
    puts("instant:14 normalize/public/idempotence cases,13 invalid preserved,negative epoch/clock/bounds passed; not storage integration");
    puts("instant addition:9 precise reversible cases,alias,year/leap/negative epoch and bounded integer-overflow refusal passed");
    return 0;
}
