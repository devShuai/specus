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

    return 0;
}
