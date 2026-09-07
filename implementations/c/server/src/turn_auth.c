#define _POSIX_C_SOURCE 200809L

#include "turn_auth.h"

#include "crypto.h"

#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static pthread_once_t turn_auth_once = PTHREAD_ONCE_INIT;
static uint8_t turn_secret[512];
static size_t turn_secret_len;
static char turn_nonce[64];
static char turn_realm[128];

static int turn_base64url(const uint8_t *data, size_t len, char *out, size_t out_len)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t needed = (len * 8U + 5U) / 6U;
    if (out_len <= needed) return -1;
    size_t input = 0U;
    size_t output = 0U;
    while (input + 3U <= len) {
        uint32_t value = ((uint32_t)data[input] << 16U)
            | ((uint32_t)data[input + 1U] << 8U) | data[input + 2U];
        out[output++] = alphabet[(value >> 18U) & 63U];
        out[output++] = alphabet[(value >> 12U) & 63U];
        out[output++] = alphabet[(value >> 6U) & 63U];
        out[output++] = alphabet[value & 63U];
        input += 3U;
    }
    if (input < len) {
        uint32_t value = (uint32_t)data[input] << 16U;
        out[output++] = alphabet[(value >> 18U) & 63U];
        if (input + 1U < len) {
            value |= (uint32_t)data[input + 1U] << 8U;
            out[output++] = alphabet[(value >> 12U) & 63U];
            out[output++] = alphabet[(value >> 6U) & 63U];
        } else {
            out[output++] = alphabet[(value >> 12U) & 63U];
        }
    }
    out[output] = '\0';
    return 0;
}

static void turn_auth_initialize(void)
{
    const char *configured = getenv("SPECUS_PEER_MESH_TURN_SHARED_SECRET");
    if (configured != NULL && *configured != '\0') {
        turn_secret_len = strlen(configured);
        if (turn_secret_len > sizeof(turn_secret)) turn_secret_len = sizeof(turn_secret);
        memcpy(turn_secret, configured, turn_secret_len);
    } else {
        turn_secret_len = 32U;
        if (RAND_bytes(turn_secret, (int)turn_secret_len) != 1) {
            static const char fallback[] = "specus-turn-runtime-secret";
            turn_secret_len = sizeof(fallback) - 1U;
            memcpy(turn_secret, fallback, turn_secret_len);
        }
    }
    const char *realm = getenv("SPECUS_PEER_MESH_TURN_REALM");
    snprintf(turn_realm, sizeof(turn_realm), "%s",
             realm == NULL || *realm == '\0' ? "specus" : realm);
    uint8_t nonce[18];
    if (RAND_bytes(nonce, sizeof(nonce)) != 1
        || turn_base64url(nonce, sizeof(nonce), turn_nonce, sizeof(turn_nonce)) != 0) {
        snprintf(turn_nonce, sizeof(turn_nonce), "specus-runtime-nonce");
    }
}

static void turn_auth_ready(void)
{
    pthread_once(&turn_auth_once, turn_auth_initialize);
}

const char *st_turn_auth_realm(void)
{
    turn_auth_ready();
    return turn_realm;
}

const char *st_turn_auth_nonce(void)
{
    turn_auth_ready();
    return turn_nonce;
}

static long long turn_auth_ttl(void)
{
    const char *value = getenv("SPECUS_PEER_MESH_TURN_CREDENTIAL_TTL_SECONDS");
    char *end = NULL;
    long long ttl = value == NULL ? 3600 : strtoll(value, &end, 10);
    if (value != NULL && (end == value || *end != '\0')) ttl = 3600;
    return ttl < 60 ? 60 : ttl;
}

int st_turn_auth_credential_for(const char *username, char *out, size_t out_len)
{
    if (username == NULL || *username == '\0') return -1;
    turn_auth_ready();
    uint8_t mac[ST_SHA1_LEN];
    st_hmac_sha1(turn_secret, turn_secret_len,
                 (const uint8_t *)username, strlen(username), mac);
    return turn_base64url(mac, sizeof(mac), out, out_len);
}

int st_turn_auth_issue(const char *subject,
                       char *username,
                       size_t username_len,
                       char *credential,
                       size_t credential_len)
{
    if (username == NULL || credential == NULL) return -1;
    char safe_subject[128];
    size_t written = 0U;
    const unsigned char *cursor = (const unsigned char *)(subject == NULL ? "peer" : subject);
    while (*cursor != '\0' && written + 1U < sizeof(safe_subject)) {
        safe_subject[written++] = isalnum(*cursor) || strchr("_.-", *cursor) != NULL
            ? (char)*cursor : '_';
        ++cursor;
    }
    if (written == 0U) memcpy(safe_subject + written++, "peer", 4U), written = 4U;
    safe_subject[written] = '\0';
    uint8_t random[4];
    if (RAND_bytes(random, sizeof(random)) != 1) return -1;
    long long expires = (long long)time(NULL) + turn_auth_ttl();
    int rc = snprintf(username, username_len, "%lld:%s:%02x%02x%02x%02x",
                      expires, safe_subject, random[0], random[1], random[2], random[3]);
    return rc > 0 && (size_t)rc < username_len
        ? st_turn_auth_credential_for(username, credential, credential_len) : -1;
}

int st_turn_auth_username_valid(const char *username)
{
    if (username == NULL || *username == '\0') return 0;
    char *end = NULL;
    long long expires = strtoll(username, &end, 10);
    if (end == username || *end != ':') return 0;
    long long now = (long long)time(NULL);
    long long remaining = expires - now;
    return remaining > 0 && remaining <= turn_auth_ttl() + 60;
}

int st_turn_auth_long_term_key(const char *username, uint8_t out[16])
{
    if (!st_turn_auth_username_valid(username) || out == NULL) return -1;
    char credential[64];
    if (st_turn_auth_credential_for(username, credential, sizeof(credential)) != 0) return -1;
    char material[512];
    int written = snprintf(material, sizeof(material), "%s:%s:%s",
                           username, st_turn_auth_realm(), credential);
    if (written < 0 || (size_t)written >= sizeof(material)) return -1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int digest_len = 0U;
    int ok = ctx != NULL
        && EVP_DigestInit_ex(ctx, EVP_md5(), NULL) == 1
        && EVP_DigestUpdate(ctx, material, (size_t)written) == 1
        && EVP_DigestFinal_ex(ctx, out, &digest_len) == 1
        && digest_len == 16U;
    EVP_MD_CTX_free(ctx);
    return ok ? 0 : -1;
}
