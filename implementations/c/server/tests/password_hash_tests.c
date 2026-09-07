#include "password_hash.h"

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

    return 0;
}
