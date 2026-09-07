#include "crypto.h"

#include <stdio.h>
#include <string.h>

static int expect_hex(const char *name, const uint8_t *bytes, size_t len, const char *expected)
{
    char actual[129];
    st_hex_encode(bytes, len, actual);
    if (strcmp(actual, expected) != 0) {
        fprintf(stderr, "%s mismatch\nexpected: %s\nactual:   %s\n", name, expected, actual);
        return 1;
    }
    return 0;
}

int main(void)
{
    uint8_t sha1_digest[ST_SHA1_LEN];
    st_sha1((const uint8_t *)"abc", 3, sha1_digest);
    if (expect_hex("sha1", sha1_digest, sizeof(sha1_digest),
                   "a9993e364706816aba3e25717850c26c9cd0d89d") != 0) {
        return 1;
    }

    uint8_t digest[ST_SHA256_LEN];
    st_sha256((const uint8_t *)"abc", 3, digest);
    if (expect_hex("sha256", digest, sizeof(digest),
                   "ba7816bf8f01cfea414140de5dae2223"
                   "b00361a396177a9cb410ff61f20015ad") != 0) {
        return 1;
    }

    uint8_t key[20];
    memset(key, 0x0b, sizeof(key));
    uint8_t sha1_mac[ST_SHA1_LEN];
    st_hmac_sha1(key, sizeof(key), (const uint8_t *)"Hi There", 8, sha1_mac);
    if (expect_hex("hmac-sha1", sha1_mac, sizeof(sha1_mac),
                   "b617318655057264e28bc0b6fb378c8ef146be00") != 0) {
        return 1;
    }
    uint8_t mac[ST_SHA256_LEN];
    st_hmac_sha256(key, sizeof(key), (const uint8_t *)"Hi There", 8, mac);
    if (expect_hex("hmac", mac, sizeof(mac),
                   "b0344c61d8db38535ca8afceaf0bf12b"
                   "881dc200c9833da726e9376c2e32cff7") != 0) {
        return 1;
    }

    uint8_t decoded[ST_SHA256_LEN];
    if (st_hex_decode_32("ba7816bf8f01cfea414140de5dae2223"
                         "b00361a396177a9cb410ff61f20015ad",
                         decoded) != 0
        || !st_constant_time_eq(decoded, digest, sizeof(digest))) {
        fprintf(stderr, "hex decode mismatch\n");
        return 1;
    }

    uint8_t derived[40];
    if (st_pbkdf2_hmac_sha256((const uint8_t *)"password",
                              strlen("password"),
                              (const uint8_t *)"salt",
                              strlen("salt"),
                              1U,
                              derived,
                              32U) != 0
        || expect_hex("pbkdf2-sha256-1",
                      derived,
                      32U,
                      "120fb6cffcf8b32c43e7225256c4f837"
                      "a86548c92ccc35480805987cb70be17b") != 0) {
        return 1;
    }
    if (st_pbkdf2_hmac_sha256((const uint8_t *)"password",
                              strlen("password"),
                              (const uint8_t *)"salt",
                              strlen("salt"),
                              2U,
                              derived,
                              32U) != 0
        || expect_hex("pbkdf2-sha256-2",
                      derived,
                      32U,
                      "ae4d0c95af6b46d32d0adff928f06dd0"
                      "2a303f8ef3c251dfd6e2d85a95474c43") != 0) {
        return 1;
    }
    if (st_pbkdf2_hmac_sha256((const uint8_t *)"passwordPASSWORDpassword",
                              strlen("passwordPASSWORDpassword"),
                              (const uint8_t *)"saltSALTsaltSALTsaltSALTsaltSALTsalt",
                              strlen("saltSALTsaltSALTsaltSALTsaltSALTsalt"),
                              4096U,
                              derived,
                              sizeof(derived)) != 0
        || expect_hex("pbkdf2-sha256-multi-block",
                      derived,
                      sizeof(derived),
                      "348c89dbcbd32b2f32d814b8116e84cf"
                      "2b17347ebc1800181c4e2a1fb8dd53e1"
                      "c635518c7dac47e9") != 0) {
        return 1;
    }

    return 0;
}
