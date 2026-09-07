#ifndef SPECUS_PASSWORD_HASH_H
#define SPECUS_PASSWORD_HASH_H

#define ST_PASSWORD_HASH_DEFAULT_ITERATIONS 210000U
#define ST_PASSWORD_HASH_MIN_ITERATIONS 1000U
#define ST_PASSWORD_HASH_MAX_LEN 127U

typedef struct {
    int matches;
    int needs_upgrade;
    int stored_is_legacy;
    char upgraded_hash[ST_PASSWORD_HASH_MAX_LEN + 1U];
} st_password_verification;

int st_password_hash(const char *plaintext,
                     char out[ST_PASSWORD_HASH_MAX_LEN + 1U]);
int st_password_verify(const char *plaintext,
                       const char *stored_hash,
                       st_password_verification *verification);
int st_password_is_legacy_hash(const char *stored_hash);

#endif
