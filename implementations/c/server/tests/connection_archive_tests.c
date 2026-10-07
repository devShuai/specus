/*
 * Java ConnectionArchiveServiceTests against a real specus-server-c process.
 *
 * ConnectionArchiveService runs every SPECUS_CONNECTION_ARCHIVE_INTERVAL_MS, first one interval
 * after start, and rolls connection detail older than SPECUS_CONNECTION_DETAIL_RETENTION_DAYS
 * (60) UTC days into per-month totals before deleting it. These scenarios write detail into the
 * server's database relative to today, let the server's own maintenance thread archive it, and
 * read the totals back through GET /api/admin/connection-stats. The exact cutoff arithmetic, with
 * a fixed clock, is in storage_tests.
 */
#define _POSIX_C_SOURCE 200809L

#include "server_harness.h"

#include "json.h"
#include "storage.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static char *admin_token(const test_server *server)
{
    int status = 0;
    char *response = NULL;
    char body[256];
    snprintf(body, sizeof(body), "{\"username\":\"%s\",\"password\":\"%s\"}", ADMIN_USERNAME, ADMIN_PASSWORD);
    if (http_request(server->admin_port, "POST", "/auth/login", body, NULL, &status, &response) != 0) {
        return NULL;
    }
    char *token = status == 200 ? st_json_get_top_level_string(response, "accessToken") : NULL;
    free(response);
    return token;
}

static long long detail_count(const test_server *server)
{
    char value[32];
    if (db_scalar(server->db_path, "SELECT COUNT(*) FROM connection_record WHERE client_name = ?",
                  "Demo client", 0, value, sizeof(value)) != 0) {
        return -1;
    }
    return strtoll(value, NULL, 10);
}

static int count_occurrences(const char *haystack, const char *needle)
{
    int count = 0;
    for (const char *cursor = strstr(haystack, needle); cursor != NULL; cursor = strstr(cursor + 1, needle)) {
        ++count;
    }
    return count;
}

/* "yyyy-MM-dd" of the UTC day `days` before now. */
static int days_ago(int days, char out[11])
{
    return st_storage_connection_archive_cutoff(days, (long long)time(NULL), out);
}

static int record_detail(const test_server *server, const char *day, const char *clock, int success)
{
    char at[40];
    snprintf(at, sizeof(at), "%sT%s.000Z", day, clock);
    return st_storage_record_connection(server->db_path, "Demo client", success,
                                        success ? NULL : "LOGIN_FAILURE", at);
}

/*
 * rollsUpDetailOlderThan60DaysIntoMonthlyTotalsThenPurges: two old months (150 and 90 days back,
 * so always two different months) and recent detail (5 days back). Nothing is archived before the
 * first interval has passed; then only the recent detail stays, and the stats list exactly the
 * two old months with their totals.
 */
static int scenario_scheduled_archive(test_server *server)
{
    char month_a_day[11];
    char month_b_day[11];
    char recent_day[11];
    CHECK(days_ago(150, month_a_day) == 0 && days_ago(90, month_b_day) == 0 && days_ago(5, recent_day) == 0,
          "cannot compute test dates");
    CHECK(record_detail(server, month_a_day, "08:00:00", 1) == 0
              && record_detail(server, month_a_day, "09:00:00", 1) == 0
              && record_detail(server, month_a_day, "10:00:00", 0) == 0
              && record_detail(server, month_b_day, "08:00:00", 1) == 0
              && record_detail(server, recent_day, "08:00:00", 1) == 0
              && record_detail(server, recent_day, "09:00:00", 0) == 0,
          "cannot write connection detail");
    /* The first run comes one interval (3 s here) after start, as Java's initialDelay. */
    CHECK(detail_count(server) == 6, "connection detail was archived before the first interval");

    long long deadline = monotonic_ms() + 20000;
    while (detail_count(server) != 2 && monotonic_ms() < deadline) {
        sleep_ms(200);
    }
    CHECK(detail_count(server) == 2, "the scheduled archive did not run (detail rows: %lld)", detail_count(server));
    char remaining[16];
    CHECK(db_scalar(server->db_path,
                    "SELECT COUNT(*) FROM connection_record WHERE client_name = 'Demo client' "
                    "AND substr(connected_at, 1, 10) = ?",
                    recent_day, 0, remaining, sizeof(remaining)) == 0
              && strcmp(remaining, "2") == 0,
          "the detail left is not the recent detail");

    char *token = admin_token(server);
    CHECK(token != NULL, "admin login failed");
    int status = 0;
    char *response = NULL;
    int rc = http_request(server->admin_port, "GET", "/api/admin/connection-stats?clientName=Demo+client&limit=100",
                          NULL, token, &status, &response);
    free(token);
    CHECK(rc == 0 && status == 200 && response != NULL, "connection stats request failed (status %d)", status);
    char month_a[8];
    char month_b[8];
    char recent_month[8];
    snprintf(month_a, sizeof(month_a), "%.7s", month_a_day);
    snprintf(month_b, sizeof(month_b), "%.7s", month_b_day);
    snprintf(recent_month, sizeof(recent_month), "%.7s", recent_day);
    char expected_a[160];
    char expected_b[160];
    char unexpected_recent[64];
    snprintf(expected_a, sizeof(expected_a),
             "\"clientName\":\"Demo client\",\"month\":\"%s\",\"total\":3,\"success\":2,\"failure\":1,", month_a);
    snprintf(expected_b, sizeof(expected_b),
             "\"clientName\":\"Demo client\",\"month\":\"%s\",\"total\":1,\"success\":1,\"failure\":0,", month_b);
    snprintf(unexpected_recent, sizeof(unexpected_recent), "\"month\":\"%s\"", recent_month);
    int matches = strstr(response, expected_a) != NULL && strstr(response, expected_b) != NULL
        && strstr(response, unexpected_recent) == NULL && count_occurrences(response, "\"month\":") == 2;
    if (!matches) {
        fprintf(stderr, "connection stats: %s\n", response);
    }
    free(response);
    CHECK(matches, "monthly totals mismatch");
    return 0;
}

/* A retention of 0 or less turns the archive off, as in Java. */
static int scenario_archive_disabled(test_server *server)
{
    char old_day[11];
    CHECK(days_ago(150, old_day) == 0 && record_detail(server, old_day, "08:00:00", 1) == 0,
          "cannot write connection detail");
    sleep_ms(3500);
    CHECK(detail_count(server) == 1, "the archive ran with a retention of 0");
    char stats[16];
    CHECK(db_scalar(server->db_path, "SELECT COUNT(*) FROM connection_stat", NULL, 0, stats, sizeof(stats)) == 0
              && strcmp(stats, "0") == 0,
          "connection totals were written with a retention of 0");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <specus-server-c>\n", argv[0]);
        return 2;
    }
    server_binary = argv[1];
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGPIPE, SIG_IGN);

    static const char *const scheduled[] = {
        "SPECUS_CONNECTION_ARCHIVE_INTERVAL_MS=3000", "SPECUS_CONNECTION_DETAIL_RETENTION_DAYS=60", NULL
    };
    static const char *const disabled[] = {
        "SPECUS_CONNECTION_ARCHIVE_INTERVAL_MS=1000", "SPECUS_CONNECTION_DETAIL_RETENTION_DAYS=0", NULL
    };
    int failures = 0;
    failures += run_on_fresh_server("scheduled archive keeps 60 days of detail and totals older months",
                                    scenario_scheduled_archive, scheduled);
    failures += run_on_fresh_server("retention 0 turns the archive off", scenario_archive_disabled, disabled);
    if (failures != 0) {
        fprintf(stderr, "%d connection archive scenario(s) failed\n", failures);
        return 1;
    }
    printf("connection archive tests passed\n");
    return 0;
}
