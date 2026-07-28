#ifndef SPECUS_CRYPTO_H
#define SPECUS_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define ST_SHA256_LEN 32
#define ST_SHA256_HEX_LEN 64
#define ST_SHA1_LEN 20

void st_sha1(const uint8_t *data, size_t len, uint8_t out[ST_SHA1_LEN]);
void st_hmac_sha1(const uint8_t *key, size_t key_len,
                  const uint8_t *data, size_t len,
                  uint8_t out[ST_SHA1_LEN]);
void st_sha256(const uint8_t *data, size_t len, uint8_t out[ST_SHA256_LEN]);
void st_hmac_sha256(const uint8_t *key, size_t key_len,
                    const uint8_t *data, size_t len,
                    uint8_t out[ST_SHA256_LEN]);

int st_hex_decode_32(const char *hex, uint8_t out[ST_SHA256_LEN]);
void st_hex_encode(const uint8_t *data, size_t len, char *out);
int st_constant_time_eq(const uint8_t *a, const uint8_t *b, size_t len);

#endif
