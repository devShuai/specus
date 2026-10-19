#define _POSIX_C_SOURCE 200809L
#include "instant.h"
#include "storage.h"
#include "instant_reference_cases.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(ok) do { if (!(ok)) { fprintf(stderr, "auth expiry failed line%d\n", __LINE__); return 1; } } while (0)
static int scalar(sqlite3 *db, const char *sql, long long expected)
{
    sqlite3_stmt *stmt = NULL;
    int ok = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW
        && sqlite3_column_int64(stmt, 0) == expected && sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt); return ok;
}

static int run(int family, int fractional, int legacy)
{
    char path[] = "/tmp/specus-auth-expiry-XXXXXX";
    int fd = mkstemp(path); CHECK(fd >= 0); close(fd);
    CHECK(st_storage_init(path, 0) == 0);
    sqlite3 *db = NULL; CHECK(sqlite3_open(path, &db) == SQLITE_OK);
    for (int i = 0; i < 7; ++i) {
        char id[8]; snprintf(id, sizeof(id), "%c%d", family == 0 ? 'n' : 'r', i + 1);
        if (family == 0) {
            /* The C auth writer takes epoch milliseconds; this schema fixture also supplies
             * microsecond expiries like the reference repository, not an HTTP auth claim. */
            char stored[ST_INSTANT_CAPACITY]; CHECK(st_instant_normalize(values[fractional][i], stored) == 0);
            sqlite3_stmt *stmt = NULL;
            CHECK(sqlite3_prepare_v2(db, "INSERT INTO specus_client_auth_nonce VALUES(?1,'hash',?2)", -1, &stmt, NULL) == SQLITE_OK
                && sqlite3_bind_text(stmt, 1, id, -1, SQLITE_TRANSIENT) == SQLITE_OK
                && sqlite3_bind_text(stmt, 2, legacy ? values[fractional][i] : stored, -1, SQLITE_TRANSIENT) == SQLITE_OK
                && sqlite3_step(stmt) == SQLITE_DONE);
            sqlite3_finalize(stmt);
        } else {
            st_storage_registration_challenge challenge = {0};
            snprintf(challenge.registration_id, sizeof(challenge.registration_id), "%s", id);
            snprintf(challenge.username, sizeof(challenge.username), "user%d", i + 1);
            snprintf(challenge.email, sizeof(challenge.email), "user%d@example.test", i + 1);
            snprintf(challenge.password_hash, sizeof(challenge.password_hash), "unused");
            snprintf(challenge.code_hash, sizeof(challenge.code_hash), "unused");
            snprintf(challenge.expires_at, sizeof(challenge.expires_at), "%s", values[fractional][i]);
            challenge.attempts_remaining = 5;
            CHECK(st_storage_create_registration_challenge(path, &challenge) == 0);
            if (legacy) {
                sqlite3_stmt *stmt = NULL;
                CHECK(sqlite3_prepare_v2(db, "UPDATE specus_management_registration_challenge SET expires_at=?1 WHERE registration_id=?2", -1, &stmt, NULL) == SQLITE_OK
                    && sqlite3_bind_text(stmt, 1, values[fractional][i], -1, SQLITE_STATIC) == SQLITE_OK
                    && sqlite3_bind_text(stmt, 2, id, -1, SQLITE_TRANSIENT) == SQLITE_OK
                    && sqlite3_step(stmt) == SQLITE_DONE);
                sqlite3_finalize(stmt);
            }
        }
    }
    const char *table = family == 0 ? "specus_client_auth_nonce" : "specus_management_registration_challenge";
    const char *key = family == 0 ? "id" : "registration_id";
    char sql[256]; snprintf(sql, sizeof(sql), "SELECT count(*) FROM %s WHERE length(expires_at)=28", table);
    CHECK(scalar(db, sql, legacy ? 0 : 7)); sqlite3_close(db);
    CHECK(st_storage_init(path, 0) == 0 && st_storage_init(path, 0) == 0);
    CHECK(sqlite3_open(path, &db) == SQLITE_OK && scalar(db, sql, 7)); sqlite3_close(db);
    int deleted = -1;
    if (family == 0) CHECK(st_storage_delete_expired_client_auth_nonces(path, cutoffs[fractional], &deleted) == 0 && deleted == 3);
    else CHECK(st_storage_delete_expired_registration_challenges(path, cutoffs[fractional]) == 0);
    CHECK(sqlite3_open(path, &db) == SQLITE_OK);
    snprintf(sql, sizeof(sql), "SELECT count(*) FROM %s", table); CHECK(scalar(db, sql, 4));
    char prefix = family == 0 ? 'n' : 'r';
    snprintf(sql, sizeof(sql), "SELECT count(*) FROM %s WHERE %s IN('%c4','%c5','%c6','%c7')", table, key, prefix, prefix, prefix, prefix);
    CHECK(scalar(db, sql, 4)); sqlite3_close(db);
    if (family == 0) {
        long long now_ms = 1789473600000LL + fractional * 500LL;
        CHECK(st_storage_consume_client_auth_nonce(path, "n4", "hash", now_ms, 120000) == 1);
        CHECK(st_storage_consume_client_auth_nonce(path, "fresh", "hash", now_ms, 120000) == 0);
        CHECK(sqlite3_open(path, &db) == SQLITE_OK);
        snprintf(sql, sizeof(sql), "SELECT count(*) FROM specus_client_auth_nonce WHERE id='fresh' AND expires_at='2026-09-15T12:02:00.%sZ'", fractional ? "5000000" : "0000000");
        CHECK(scalar(db, sql, 1)); sqlite3_close(db);
        CHECK(st_storage_consume_client_auth_nonce(path, "n4", "hash", now_ms + 1LL, 120000) == 0);
    }
    unlink(path);
    printf("auth expiry: family%d fractional%d legacy%d strict purge/kept exact expiry and microseconds/real initialization passed\n", family, fractional, legacy);
    return 0;
}

int main(void)
{
    CHECK(setenv("SPECUS_DB_SEED_DEMO_CLIENT", "0", 1) == 0);
    for (int family = 0; family < 2; ++family) for (int fractional = 0; fractional < 2; ++fractional)
        for (int legacy = 0; legacy < 2; ++legacy) CHECK(run(family, fractional, legacy) == 0);
    puts("auth expiry:8 isolated nonce/challenge storage scenarios passed; no network auth or other expiry acceptance");
    return 0;
}
