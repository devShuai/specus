#include "password_hash.h"

#include "crypto.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int expect_rejected(const char *stored_hash)
{
    st_password_verification verification;
    if (st_password_verify("password", stored_hash, &verification) != 0
        || verification.matches
        || verification.needs_upgrade) {
        fprintf(stderr, "malformed password hash was accepted: %s\n", stored_hash);
        return 1;
    }
    return 0;
}

static int verifies(const char *plaintext, const char *stored_hash)
{
    st_password_verification verification;
    return st_password_verify(plaintext, stored_hash, &verification) == 0 && verification.matches;
}

static size_t count_dollars(const char *text)
{
    size_t count = 0U;
    for (; *text != '\0'; ++text) {
        count += *text == '$' ? 1U : 0U;
    }
    return count;
}

/* The remaining Java PasswordServiceTests cases, with Java's inputs. */
static int test_password_service_parity(void)
{
    /* hashesAreSaltedAndCarryTheirOwnParameters */
    char first[ST_PASSWORD_HASH_MAX_LEN + 1U];
    char second[ST_PASSWORD_HASH_MAX_LEN + 1U];
    if (st_password_hash("correct horse battery staple", first) != 0
        || st_password_hash("correct horse battery staple", second) != 0
        || strcmp(first, second) == 0
        || strncmp(first, "$pbkdf2-sha256$v=1$i=210000$", strlen("$pbkdf2-sha256$v=1$i=210000$")) != 0
        || count_dollars(first) != 5U
        || !verifies("correct horse battery staple", first)
        || verifies("correct horse battery stapl", first)) {
        fprintf(stderr, "fresh password hashes are not salted, self-describing and verifiable\n");
        return 1;
    }

    /* currentCostHashesAreNotRewritten */
    st_password_verification verification;
    if (st_password_hash("s3cret", first) != 0
        || st_password_verify("s3cret", first, &verification) != 0
        || !verification.matches || verification.needs_upgrade || verification.stored_is_legacy
        || verification.upgraded_hash[0] != '\0') {
        fprintf(stderr, "a current-cost hash was scheduled for rewrite\n");
        return 1;
    }

    /* legacyHashesVerifyAndAreScheduledForUpgrade: the upgrade is final, hex case is ignored. */
    uint8_t digest[ST_SHA256_LEN];
    char legacy[ST_SHA256_HEX_LEN + 1U];
    char legacy_upper[ST_SHA256_HEX_LEN + 1U];
    st_sha256((const uint8_t *)"legacy-password", strlen("legacy-password"), digest);
    st_hex_encode(digest, sizeof(digest), legacy);
    for (size_t i = 0U; i <= ST_SHA256_HEX_LEN; ++i) {
        legacy_upper[i] = (char)toupper((unsigned char)legacy[i]);
    }
    if (st_password_verify("legacy-password", legacy, &verification) != 0
        || !verification.matches || !verification.needs_upgrade || !verification.stored_is_legacy) {
        fprintf(stderr, "legacy digest did not verify for upgrade\n");
        return 1;
    }
    char upgraded[ST_PASSWORD_HASH_MAX_LEN + 1U];
    memcpy(upgraded, verification.upgraded_hash, sizeof(upgraded));
    if (st_password_verify("legacy-password", upgraded, &verification) != 0
        || !verification.matches || verification.needs_upgrade) {
        fprintf(stderr, "the upgraded legacy hash is not final\n");
        return 1;
    }
    if (strcmp(legacy, legacy_upper) == 0 || !verifies("legacy-password", legacy_upper)
        || verifies("wrong", legacy)) {
        fprintf(stderr, "legacy digest comparison mismatch (uppercase or wrong password)\n");
        return 1;
    }

    /* malformedStoredHashesNeverVerify: the cases the shared list above does not hold. */
    char repeated_a[64];
    char repeated_z[65];
    memset(repeated_a, 'a', sizeof(repeated_a) - 1U);
    repeated_a[sizeof(repeated_a) - 1U] = '\0';
    memset(repeated_z, 'z', sizeof(repeated_z) - 1U);
    repeated_z[sizeof(repeated_z) - 1U] = '\0';
    const char *never[] = { "", "   ", "$", "$argon2id$v=1$i=210000$c2FsdA$a2V5", repeated_a, repeated_z, NULL };
    for (size_t i = 0U; i < sizeof(never) / sizeof(never[0]); ++i) {
        if (verifies("anything", never[i])) {
            fprintf(stderr, "malformed stored hash verified: %s\n", never[i] == NULL ? "(null)" : never[i]);
            return 1;
        }
    }
    if (st_password_verify(NULL, "anything", &verification) == 0 && verification.matches) {
        fprintf(stderr, "a NULL password verified\n");
        return 1;
    }

    /* sharedCrossLanguageVectorVerifies: one extra character must fail against either vector. */
    const char *vectors[] = {
        "$pbkdf2-sha256$v=1$i=1000$AAECAwQFBgcICQoLDA0ODw$vnwYtUA8UXxNgCLy7OdAY+f7T+TtG4qdlahTjY1KU5g",
        "$pbkdf2-sha256$v=1$i=210000$AAECAwQFBgcICQoLDA0ODw$BiTFCvEUdO2zrZt0s1Zd0ipbGH5+WaSosMi6WavHxbI",
    };
    for (size_t i = 0U; i < sizeof(vectors) / sizeof(vectors[0]); ++i) {
        if (!verifies("specus-shared-password", vectors[i]) || verifies("specus-shared-passwordx", vectors[i])) {
            fprintf(stderr, "shared vector %zu mismatch\n", i);
            return 1;
        }
    }
    return 0;
}

int main(void)
{
    const char *shared_password = "specus-shared-password";
    const char *current_vector =
        "$pbkdf2-sha256$v=1$i=210000$AAECAwQFBgcICQoLDA0ODw$"
        "BiTFCvEUdO2zrZt0s1Zd0ipbGH5+WaSosMi6WavHxbI";
    st_password_verification verification;
    if (st_password_verify(shared_password, current_vector, &verification) != 0
        || !verification.matches
        || verification.needs_upgrade
        || verification.stored_is_legacy) {
        fprintf(stderr, "shared current password vector mismatch\n");
        return 1;
    }

    const char *under_cost_vector =
        "$pbkdf2-sha256$v=1$i=1000$AAECAwQFBgcICQoLDA0ODw$"
        "vnwYtUA8UXxNgCLy7OdAY+f7T+TtG4qdlahTjY1KU5g";
    if (st_password_verify(shared_password, under_cost_vector, &verification) != 0
        || !verification.matches
        || !verification.needs_upgrade
        || verification.stored_is_legacy
        || strncmp(verification.upgraded_hash,
                   "$pbkdf2-sha256$v=1$i=210000$",
                   strlen("$pbkdf2-sha256$v=1$i=210000$")) != 0) {
        fprintf(stderr, "under-cost password hash was not upgraded\n");
        return 1;
    }

    const char *legacy_hash =
        "2bb80d537b1da3e38bd30361aa855686"
        "bde0eacd7162fef6a25fe97bf527a25b";
    int legacy_rc = st_password_verify("secret", legacy_hash, &verification);
    if (legacy_rc != 0
        || !verification.matches
        || !verification.needs_upgrade
        || !verification.stored_is_legacy
        || strncmp(verification.upgraded_hash,
                   "$pbkdf2-sha256$v=1$i=210000$",
                   strlen("$pbkdf2-sha256$v=1$i=210000$")) != 0
        || !st_password_is_legacy_hash(legacy_hash)
        || st_password_is_legacy_hash(verification.upgraded_hash)) {
        fprintf(stderr,
                "legacy password hash migration mismatch: rc=%d matches=%d upgrade=%d legacy=%d hash=%s\n",
                legacy_rc,
                verification.matches,
                verification.needs_upgrade,
                verification.stored_is_legacy,
                verification.upgraded_hash);
        return 1;
    }

    if (st_password_verify("wrong", under_cost_vector, &verification) != 0
        || verification.matches
        || verification.needs_upgrade) {
        fprintf(stderr, "wrong password matched\n");
        return 1;
    }

    const char *malformed[] = {
        "$pbkdf2-sha256$v=1$i=210000$onlythree",
        "$pbkdf2-sha256$v=2$i=210000$c2FsdA$a2V5",
        "$pbkdf2-sha256$v=1$i=1$c2FsdA$a2V5",
        "$pbkdf2-sha256$v=1$i=notanumber$c2FsdA$a2V5",
        "$pbkdf2-sha256$v=1$i=210000$!!!$a2V5",
        "$pbkdf2-sha256$v=1$i=210000$c2FsdA$!!!",
        "$pbkdf2-sha256$v=1$i=210000$$a2V5",
        "not-a-sha256-hash"
    };
    for (size_t i = 0; i < sizeof(malformed) / sizeof(malformed[0]); ++i) {
        if (expect_rejected(malformed[i]) != 0) {
            return 1;
        }
    }

    return test_password_service_parity();
}
