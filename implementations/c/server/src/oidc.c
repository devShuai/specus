#define _POSIX_C_SOURCE 200809L

#include "oidc.h"

#include "crypto.h"
#include "http_client.h"
#include "json.h"

#include <ctype.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Spring's JwtTimestampValidator default leeway. */
#define ST_OIDC_CLOCK_SKEW_SECONDS 60LL
/* Nimbus JWKSourceBuilder's default cache lifetime. */
#define ST_OIDC_JWKS_TTL_MS (5LL * 60LL * 1000LL)
#define ST_OIDC_JWKS_DEFAULT_COOLDOWN_MS 10000LL
#define ST_OIDC_JWKS_TIMEOUT_MS 10000L
#define ST_OIDC_JWKS_MAX_BYTES (1024U * 1024U)
#define ST_OIDC_JWKS_MAX_KEYS 64U
#define ST_OIDC_MAX_KID_BYTES 256U
#define ST_OIDC_MIN_RSA_BITS 2048
#define ST_OIDC_MAX_RSA_BITS 16384

typedef struct {
    char *kid; /* NULL when the JWK has no kid member */
    EVP_PKEY *key;
} oidc_jwk;

typedef struct {
    oidc_jwk *keys;
    size_t count;
} oidc_jwk_set;

typedef struct {
    char *header;
    char *payload;
    uint8_t *signature;
    size_t signature_len;
    const char *signing_input; /* points into the token */
    size_t signing_input_len;
} oidc_jws;

/*
 * One JWK Set for the process, like Java's single decoder bean. The lock is held across a fetch,
 * as Spring's JWK source holds its own, so concurrent misses wait for one request instead of each
 * issuing their own.
 */
static pthread_mutex_t oidc_jwks_lock = PTHREAD_MUTEX_INITIALIZER;
static oidc_jwk_set oidc_jwks;
static char *oidc_jwks_uri;
static int oidc_jwks_loaded;
static long long oidc_jwks_loaded_ms;
static int oidc_jwks_attempted;
static long long oidc_jwks_attempted_ms;
static long long oidc_jwks_cooldown_ms = ST_OIDC_JWKS_DEFAULT_COOLDOWN_MS;

const char *st_oidc_setting(const char *name, const char *fallback)
{
    const char *value = name == NULL ? NULL : getenv(name);
    return value != NULL ? value : fallback;
}

int st_oidc_has_text(const char *value)
{
    if (value == NULL) {
        return 0;
    }
    for (const unsigned char *cursor = (const unsigned char *)value; *cursor != '\0'; ++cursor) {
        if (!isspace(*cursor)) {
            return 1;
        }
    }
    return 0;
}

static char *oidc_decode_raw_string(const char *raw)
{
    size_t len = 0U;
    char *value = st_json_decode_string(raw, &len);
    if (value != NULL && strlen(value) != len) {
        free(value);
        return NULL;
    }
    return value;
}

char *st_oidc_json_text(const char *json, const char *name)
{
    if (json == NULL || name == NULL) {
        return NULL;
    }
    char *raw = st_json_get_top_level_raw(json, name);
    char *value = raw != NULL && raw[0] == '"' ? oidc_decode_raw_string(raw) : NULL;
    free(raw);
    return value;
}

/* 1 with *out set for a string member, 0 when the member is absent or null, -1 for anything else. */
static int oidc_string_member(const char *json, const char *name, char **out)
{
    *out = NULL;
    char *raw = st_json_get_top_level_raw(json, name);
    if (raw == NULL) {
        return 0;
    }
    int result = -1;
    if (strcmp(raw, "null") == 0) {
        result = 0;
    } else if (raw[0] == '"') {
        *out = oidc_decode_raw_string(raw);
        result = *out != NULL ? 1 : -1;
    }
    free(raw);
    return result;
}

/*
 * Java's claimAsString: a string claim as it is, any other non-null value as its JSON text, ""
 * when absent. NULL only when memory runs out or a string carries an escaped NUL.
 */
static char *oidc_claim_text(const char *json, const char *name)
{
    char *raw = st_json_get_top_level_raw(json, name);
    if (raw == NULL || strcmp(raw, "null") == 0) {
        free(raw);
        return strdup("");
    }
    if (raw[0] != '"') {
        return raw;
    }
    char *value = oidc_decode_raw_string(raw);
    free(raw);
    return value;
}

/* A NumericDate claim: 1 with *seconds set for a JSON number, 0 when absent or null, -1 otherwise. */
static int oidc_numeric_date(const char *json, const char *name, long long *seconds)
{
    char *raw = st_json_get_top_level_raw(json, name);
    if (raw == NULL) {
        return 0;
    }
    int result = -1;
    if (strcmp(raw, "null") == 0) {
        result = 0;
    } else if (raw[0] == '-' || isdigit((unsigned char)raw[0])) {
        char *end = NULL;
        double value = strtod(raw, &end);
        if (end != raw && *end == '\0' && value > -9.0e15 && value < 9.0e15) {
            /* Number.longValue(), as Nimbus converts it: fractions are truncated. */
            *seconds = (long long)value;
            result = 1;
        }
    }
    free(raw);
    return result;
}

/* The elements of a JSON array, each as raw JSON text. */
static int oidc_raw_array(const char *raw_array, char ***items, size_t *count)
{
    size_t wrapped_len = strlen(raw_array) + sizeof("{\"a\":}");
    char *wrapped = (char *)malloc(wrapped_len);
    if (wrapped == NULL) {
        return -1;
    }
    snprintf(wrapped, wrapped_len, "{\"a\":%s}", raw_array);
    int rc = st_json_get_raw_array(wrapped, "a", items, count);
    free(wrapped);
    return rc;
}

/* aud as Nimbus reads it: one string or an array of strings. 0 with the list set, -1 otherwise. */
static int oidc_audiences(const char *json, char ***out, size_t *count)
{
    *out = NULL;
    *count = 0U;
    char *raw = st_json_get_top_level_raw(json, "aud");
    if (raw == NULL || strcmp(raw, "null") == 0) {
        free(raw);
        return 0;
    }
    char **items = NULL;
    size_t item_count = 0U;
    int rc = -1;
    if (raw[0] == '"') {
        items = (char **)calloc(1U, sizeof(*items));
        if (items != NULL) {
            item_count = 1U;
            items[0] = oidc_decode_raw_string(raw);
            rc = items[0] != NULL ? 0 : -1;
        }
    } else if (raw[0] == '[' && oidc_raw_array(raw, &items, &item_count) == 0) {
        rc = 0;
        for (size_t i = 0U; i < item_count; ++i) {
            char *value = items[i][0] == '"' ? oidc_decode_raw_string(items[i]) : NULL;
            free(items[i]);
            items[i] = value;
            if (value == NULL) {
                rc = -1;
            }
        }
    }
    free(raw);
    if (rc != 0) {
        st_json_free_string_array(items, item_count);
        return -1;
    }
    *out = items;
    *count = item_count;
    return 0;
}

static int oidc_base64url_value(unsigned char ch)
{
    if (ch >= 'A' && ch <= 'Z') {
        return ch - 'A';
    }
    if (ch >= 'a' && ch <= 'z') {
        return ch - 'a' + 26;
    }
    if (ch >= '0' && ch <= '9') {
        return ch - '0' + 52;
    }
    if (ch == '-') {
        return 62;
    }
    if (ch == '_') {
        return 63;
    }
    return -1;
}

/* Unpadded base64url, as JWS segments and JWK members are written. */
static int oidc_base64url_decode(const char *value, size_t len, uint8_t **out, size_t *out_len)
{
    *out = NULL;
    *out_len = 0U;
    if (len % 4U == 1U) {
        return -1;
    }
    uint8_t *buffer = (uint8_t *)malloc(len / 4U * 3U + 3U);
    if (buffer == NULL) {
        return -1;
    }
    uint32_t acc = 0U;
    int bits = 0;
    size_t written = 0U;
    for (size_t i = 0U; i < len; ++i) {
        int sextet = oidc_base64url_value((unsigned char)value[i]);
        if (sextet < 0) {
            free(buffer);
            return -1;
        }
        acc = (acc << 6U) | (uint32_t)sextet;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            buffer[written++] = (uint8_t)((acc >> (unsigned int)bits) & 0xffU);
        }
    }
    *out = buffer;
    *out_len = written;
    return 0;
}

/* A JOSE header or claims segment: base64url of one JSON object without repeated member names. */
static char *oidc_decode_json_segment(const char *segment, size_t len)
{
    uint8_t *bytes = NULL;
    size_t bytes_len = 0U;
    if (oidc_base64url_decode(segment, len, &bytes, &bytes_len) != 0) {
        return NULL;
    }
    if (bytes_len == 0U || memchr(bytes, '\0', bytes_len) != NULL) {
        free(bytes);
        return NULL;
    }
    char *text = (char *)realloc(bytes, bytes_len + 1U);
    if (text == NULL) {
        free(bytes);
        return NULL;
    }
    text[bytes_len] = '\0';
    if (!st_json_object_keys_unique(text)) {
        free(text);
        return NULL;
    }
    return text;
}

static void oidc_jws_free(oidc_jws *jws)
{
    free(jws->header);
    free(jws->payload);
    free(jws->signature);
    memset(jws, 0, sizeof(*jws));
}

static int oidc_jws_parse(const char *token, oidc_jws *jws)
{
    memset(jws, 0, sizeof(*jws));
    if (token == NULL) {
        return -1;
    }
    size_t token_len = strnlen(token, ST_OIDC_MAX_TOKEN_BYTES + 1U);
    if (token_len == 0U || token_len > ST_OIDC_MAX_TOKEN_BYTES) {
        return -1;
    }
    const char *end = token + token_len;
    const char *first = (const char *)memchr(token, '.', token_len);
    const char *second = first == NULL ? NULL : (const char *)memchr(first + 1, '.', (size_t)(end - first - 1));
    if (second == NULL || memchr(second + 1, '.', (size_t)(end - second - 1)) != NULL
        || first == token || second == first + 1 || second + 1 == end) {
        return -1;
    }
    jws->header = oidc_decode_json_segment(token, (size_t)(first - token));
    jws->payload = oidc_decode_json_segment(first + 1, (size_t)(second - first - 1));
    if (jws->header == NULL || jws->payload == NULL
        || oidc_base64url_decode(second + 1, (size_t)(end - second - 1), &jws->signature, &jws->signature_len) != 0) {
        oidc_jws_free(jws);
        return -1;
    }
    jws->signing_input = token;
    jws->signing_input_len = (size_t)(second - token);
    return 0;
}

/*
 * RS256 is the only algorithm Java admits: Spring's JWK-set decoder defaults to it, so ES256,
 * HS256 (the classic confusion with the public key as an HMAC secret) and "none" all fail here.
 * Nimbus also refuses critical header parameters nobody deferred. *kid_present tells a header
 * without kid, which may use any key, from one whose kid must match exactly, "" included.
 */
static int oidc_header_check(const char *header, char **kid, int *kid_present)
{
    *kid = NULL;
    *kid_present = 0;
    char *alg = NULL;
    int alg_ok = oidc_string_member(header, "alg", &alg) == 1 && strcmp(alg, "RS256") == 0;
    free(alg);
    char *crit = st_json_get_top_level_raw(header, "crit");
    int crit_present = crit != NULL;
    free(crit);
    if (!alg_ok || crit_present) {
        return -1;
    }
    int kid_state = oidc_string_member(header, "kid", kid);
    if (kid_state < 0 || (kid_state == 1 && strlen(*kid) > ST_OIDC_MAX_KID_BYTES)) {
        free(*kid);
        *kid = NULL;
        return -1;
    }
    *kid_present = kid_state == 1;
    return 0;
}

/* An RSA public key from JWK n and e. Keys under 2048 bits are ignored, as the Go and .NET servers do. */
static EVP_PKEY *oidc_rsa_public_key(const char *jwk)
{
    char *n_text = st_oidc_json_text(jwk, "n");
    char *e_text = st_oidc_json_text(jwk, "e");
    uint8_t *n = NULL;
    uint8_t *e = NULL;
    size_t n_len = 0U;
    size_t e_len = 0U;
    BIGNUM *modulus = NULL;
    BIGNUM *exponent = NULL;
    if (n_text != NULL && e_text != NULL
        && oidc_base64url_decode(n_text, strlen(n_text), &n, &n_len) == 0
        && oidc_base64url_decode(e_text, strlen(e_text), &e, &e_len) == 0
        && n_len > 0U && n_len <= (size_t)(ST_OIDC_MAX_RSA_BITS / 8) && e_len > 0U && e_len <= 4U) {
        modulus = BN_bin2bn(n, (int)n_len, NULL);
        exponent = BN_bin2bn(e, (int)e_len, NULL);
    }
    free(n_text);
    free(e_text);
    free(n);
    free(e);
    EVP_PKEY *key = NULL;
    OSSL_PARAM_BLD *builder = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *context = NULL;
    if (modulus != NULL && exponent != NULL
        && BN_num_bits(modulus) >= ST_OIDC_MIN_RSA_BITS && BN_num_bits(modulus) <= ST_OIDC_MAX_RSA_BITS
        && BN_is_odd(exponent) && BN_num_bits(exponent) >= 2) {
        builder = OSSL_PARAM_BLD_new();
    }
    if (builder != NULL
        && OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_RSA_N, modulus) == 1
        && OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_RSA_E, exponent) == 1) {
        params = OSSL_PARAM_BLD_to_param(builder);
    }
    if (params != NULL) {
        context = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    }
    if (context != NULL && EVP_PKEY_fromdata_init(context) == 1
        && EVP_PKEY_fromdata(context, &key, EVP_PKEY_PUBLIC_KEY, params) != 1) {
        key = NULL;
    }
    EVP_PKEY_CTX_free(context);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(builder);
    BN_free(modulus);
    BN_free(exponent);
    if (key == NULL) {
        ERR_clear_error();
    }
    return key;
}

static void oidc_jwk_set_clear(oidc_jwk_set *set)
{
    for (size_t i = 0U; i < set->count; ++i) {
        free(set->keys[i].kid);
        EVP_PKEY_free(set->keys[i].key);
    }
    free(set->keys);
    set->keys = NULL;
    set->count = 0U;
}

/*
 * The keys Nimbus' JWKMatcher would offer for an RS256 header: kty RSA, alg absent or RS256, use
 * absent or sig. Other entries are skipped rather than failing the whole set; a set without one
 * usable key is an error.
 */
static int oidc_jwk_set_parse(const char *body, oidc_jwk_set *set)
{
    memset(set, 0, sizeof(*set));
    if (body == NULL || !st_json_is_valid_object(body)) {
        return -1;
    }
    char *raw_keys = st_json_get_top_level_raw(body, "keys");
    char **entries = NULL;
    size_t entry_count = 0U;
    int rc = raw_keys != NULL && raw_keys[0] == '[' ? oidc_raw_array(raw_keys, &entries, &entry_count) : -1;
    free(raw_keys);
    if (rc != 0) {
        return -1;
    }
    set->keys = (oidc_jwk *)calloc(ST_OIDC_JWKS_MAX_KEYS, sizeof(*set->keys));
    for (size_t i = 0U; set->keys != NULL && i < entry_count && set->count < ST_OIDC_JWKS_MAX_KEYS; ++i) {
        const char *entry = entries[i];
        if (entry[0] != '{') {
            continue;
        }
        char *kty = NULL;
        char *alg = NULL;
        char *use = NULL;
        char *kid = NULL;
        int kty_state = oidc_string_member(entry, "kty", &kty);
        int alg_state = oidc_string_member(entry, "alg", &alg);
        int use_state = oidc_string_member(entry, "use", &use);
        int kid_state = oidc_string_member(entry, "kid", &kid);
        int usable = kty_state == 1 && strcmp(kty, "RSA") == 0
            && (alg_state == 0 || (alg_state == 1 && strcmp(alg, "RS256") == 0))
            && (use_state == 0 || (use_state == 1 && strcmp(use, "sig") == 0))
            && kid_state >= 0 && (kid == NULL || strlen(kid) <= ST_OIDC_MAX_KID_BYTES);
        EVP_PKEY *key = usable ? oidc_rsa_public_key(entry) : NULL;
        if (key != NULL) {
            set->keys[set->count].kid = kid;
            set->keys[set->count].key = key;
            ++set->count;
            kid = NULL;
        }
        free(kty);
        free(alg);
        free(use);
        free(kid);
    }
    st_json_free_string_array(entries, entry_count);
    if (set->count == 0U) {
        oidc_jwk_set_clear(set);
        return -1;
    }
    return 0;
}

static int oidc_jwk_set_fetch(const char *uri, oidc_jwk_set *set)
{
    st_http_client_options options = {
        .timeout_ms = ST_OIDC_JWKS_TIMEOUT_MS,
        .max_response_bytes = ST_OIDC_JWKS_MAX_BYTES,
        .ca_certificate_path = getenv("SPECUS_OIDC_CA_CERTIFICATE_PATH")
    };
    long status_code = 0L;
    char *body = NULL;
    if (st_http_get_json(uri, &options, &status_code, &body) != 0) {
        return -1;
    }
    int rc = status_code >= 200L && status_code < 300L ? oidc_jwk_set_parse(body, set) : -1;
    free(body);
    return rc;
}

static long long oidc_monotonic_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0LL;
    }
    return (long long)now.tv_sec * 1000LL + (long long)(now.tv_nsec / 1000000L);
}

static void oidc_jwks_reset_locked(void)
{
    oidc_jwk_set_clear(&oidc_jwks);
    free(oidc_jwks_uri);
    oidc_jwks_uri = NULL;
    oidc_jwks_loaded = 0;
    oidc_jwks_loaded_ms = 0LL;
    oidc_jwks_attempted = 0;
    oidc_jwks_attempted_ms = 0LL;
}

static int oidc_jwks_may_fetch_locked(void)
{
    return !oidc_jwks_attempted || oidc_monotonic_ms() - oidc_jwks_attempted_ms >= oidc_jwks_cooldown_ms;
}

/* The cached set is replaced only by a fetch that yields usable keys. */
static void oidc_jwks_refresh_locked(const char *uri)
{
    oidc_jwk_set fresh;
    int rc = oidc_jwk_set_fetch(uri, &fresh);
    /* Spacing counts from completion, so a slow identity provider still gets a full pause. */
    oidc_jwks_attempted = 1;
    oidc_jwks_attempted_ms = oidc_monotonic_ms();
    if (rc != 0) {
        return;
    }
    oidc_jwk_set_clear(&oidc_jwks);
    oidc_jwks = fresh;
    oidc_jwks_loaded = 1;
    oidc_jwks_loaded_ms = oidc_jwks_attempted_ms;
}

static int oidc_rs256_verify(EVP_PKEY *key, const oidc_jws *jws)
{
    int size = EVP_PKEY_get_size(key);
    if (size <= 0 || (size_t)size != jws->signature_len) {
        return 0;
    }
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    int verified = context != NULL
        && EVP_DigestVerifyInit(context, NULL, EVP_sha256(), NULL, key) == 1
        && EVP_DigestVerify(context,
                            jws->signature,
                            jws->signature_len,
                            (const unsigned char *)jws->signing_input,
                            jws->signing_input_len) == 1;
    EVP_MD_CTX_free(context);
    if (!verified) {
        ERR_clear_error();
    }
    return verified;
}

static int oidc_jwks_verify_locked(const oidc_jws *jws, const char *kid, int kid_present)
{
    for (size_t i = 0U; i < oidc_jwks.count; ++i) {
        const oidc_jwk *jwk = &oidc_jwks.keys[i];
        if (kid_present && (jwk->kid == NULL || strcmp(jwk->kid, kid) != 0)) {
            continue;
        }
        if (oidc_rs256_verify(jwk->key, jws)) {
            return 1;
        }
    }
    return 0;
}

/*
 * Keys are fetched on first use and kept for five minutes. An expired set is dropped rather than
 * trusted while the identity provider is unreachable. When no cached key verifies the token, which
 * is how a key rotation shows, the set is fetched again once, but never twice within the cooldown,
 * so tokens with random kids cannot turn into a request flood against the identity provider.
 */
static int oidc_verify_signature(const char *uri, const oidc_jws *jws, const char *kid, int kid_present)
{
    pthread_mutex_lock(&oidc_jwks_lock);
    if (oidc_jwks_uri == NULL || strcmp(oidc_jwks_uri, uri) != 0) {
        oidc_jwks_reset_locked();
        oidc_jwks_uri = strdup(uri);
    }
    if (oidc_jwks_loaded && oidc_monotonic_ms() - oidc_jwks_loaded_ms > ST_OIDC_JWKS_TTL_MS) {
        oidc_jwk_set_clear(&oidc_jwks);
        oidc_jwks_loaded = 0;
    }
    int fetched = 0;
    if (!oidc_jwks_loaded && oidc_jwks_may_fetch_locked()) {
        oidc_jwks_refresh_locked(uri);
        fetched = 1;
    }
    int verified = oidc_jwks_verify_locked(jws, kid, kid_present);
    if (!verified && !fetched && oidc_jwks_may_fetch_locked()) {
        oidc_jwks_refresh_locked(uri);
        verified = oidc_jwks_verify_locked(jws, kid, kid_present);
    }
    pthread_mutex_unlock(&oidc_jwks_lock);
    return verified;
}

/*
 * The validators SecurityConfig puts on both decoders: JwtTimestampValidator (exp and nbf with
 * 60 s of skew; iat is not checked), JwtIssuerValidator (exact iss), the audience validator and,
 * for ID tokens, the azp validator. Registered claims must also have the types Nimbus requires.
 * Spring lets a token without exp through; C refuses it, as the Go and .NET servers do, since such
 * a token would never expire.
 */
static int oidc_claims_valid(const char *payload, const char *issuer, const char *audience, int check_authorized_party)
{
    long long now = (long long)time(NULL);
    long long exp = 0LL;
    long long nbf = 0LL;
    long long iat = 0LL;
    if (oidc_numeric_date(payload, "exp", &exp) != 1 || now - ST_OIDC_CLOCK_SKEW_SECONDS > exp) {
        return 0;
    }
    int nbf_state = oidc_numeric_date(payload, "nbf", &nbf);
    if (nbf_state < 0 || (nbf_state == 1 && now + ST_OIDC_CLOCK_SKEW_SECONDS < nbf)
        || oidc_numeric_date(payload, "iat", &iat) < 0) {
        return 0;
    }
    char *iss = NULL;
    char *sub = NULL;
    char *jti = NULL;
    int iss_state = oidc_string_member(payload, "iss", &iss);
    int sub_state = oidc_string_member(payload, "sub", &sub);
    int jti_state = oidc_string_member(payload, "jti", &jti);
    int valid = iss_state == 1 && strcmp(iss, issuer) == 0 && sub_state >= 0 && jti_state >= 0;
    free(iss);
    free(sub);
    free(jti);
    char **audiences = NULL;
    size_t audience_count = 0U;
    if (!valid || oidc_audiences(payload, &audiences, &audience_count) != 0) {
        return 0;
    }
    int contains = 0;
    for (size_t i = 0U; i < audience_count; ++i) {
        if (strcmp(audiences[i], audience) == 0) {
            contains = 1;
        }
    }
    st_json_free_string_array(audiences, audience_count);
    if (!contains) {
        return 0;
    }
    if (check_authorized_party) {
        /* azp must name this client when present, and must be present when aud lists several. */
        char *azp = oidc_claim_text(payload, "azp");
        valid = azp != NULL
            && !(audience_count > 1U && strcmp(azp, audience) != 0)
            && !(st_oidc_has_text(azp) && strcmp(azp, audience) != 0);
        free(azp);
    }
    return valid;
}

static int oidc_text_equal_constant_time(const char *expected, const char *actual)
{
    if (expected == NULL || actual == NULL) {
        return 0;
    }
    size_t len = strlen(expected);
    return len == strlen(actual)
        && st_constant_time_eq((const uint8_t *)expected, (const uint8_t *)actual, len);
}

/* OidcController's checks after decoding: a subject with text and, for an ID token, the nonce. */
static int oidc_identity_from_claims(const char *payload,
                                     int id_token,
                                     const char *expected_nonce,
                                     st_oidc_identity *identity)
{
    int rejected = id_token ? ST_OIDC_IDENTITY_REJECTED : ST_OIDC_TOKEN_REJECTED;
    char *issuer = NULL;
    char *subject = NULL;
    (void)oidc_string_member(payload, "iss", &issuer);
    (void)oidc_string_member(payload, "sub", &subject);
    int result = issuer != NULL && st_oidc_has_text(subject) ? ST_OIDC_OK : rejected;
    if (result == ST_OIDC_OK && id_token) {
        /* The browser's nonce binds this ID token to the login it started; compared byte for byte. */
        char *nonce = oidc_claim_text(payload, "nonce");
        if (!st_oidc_has_text(expected_nonce) || !oidc_text_equal_constant_time(expected_nonce, nonce)) {
            result = ST_OIDC_IDENTITY_REJECTED;
        }
        free(nonce);
    }
    char *preferred_username = NULL;
    if (result == ST_OIDC_OK) {
        preferred_username = oidc_claim_text(payload, "preferred_username");
        if (preferred_username == NULL) {
            preferred_username = strdup("");
        }
        if (preferred_username == NULL) {
            result = ST_OIDC_TOKEN_REJECTED;
        }
    }
    if (result != ST_OIDC_OK) {
        free(issuer);
        free(subject);
        free(preferred_username);
        return result;
    }
    identity->issuer = issuer;
    identity->subject = subject;
    identity->preferred_username = preferred_username;
    return ST_OIDC_OK;
}

static int oidc_validate(const char *token, int id_token, const char *expected_nonce, st_oidc_identity *identity)
{
    if (identity == NULL) {
        return ST_OIDC_TOKEN_REJECTED;
    }
    memset(identity, 0, sizeof(*identity));
    const char *jwk_set_uri = st_oidc_setting("SPECUS_OIDC_JWK_SET_URI", ST_OIDC_DEFAULT_JWK_SET_URI);
    if (!st_oidc_has_text(jwk_set_uri)) {
        return ST_OIDC_UNAVAILABLE;
    }
    const char *issuer = st_oidc_setting("SPECUS_OIDC_ISSUER", ST_OIDC_DEFAULT_ISSUER);
    /* ID tokens are bound to this client; direct bearer tokens to the separate resource audience. */
    const char *audience = id_token
        ? st_oidc_setting("SPECUS_OIDC_CLIENT_ID", "")
        : st_oidc_setting("SPECUS_OIDC_AUDIENCE", "");
    /* Java adds a validator that fails every token when one of these is blank. */
    if (!st_oidc_has_text(issuer) || !st_oidc_has_text(audience)) {
        return ST_OIDC_TOKEN_REJECTED;
    }
    oidc_jws jws;
    if (oidc_jws_parse(token, &jws) != 0) {
        return ST_OIDC_TOKEN_REJECTED;
    }
    char *kid = NULL;
    int kid_present = 0;
    int result = ST_OIDC_TOKEN_REJECTED;
    if (oidc_header_check(jws.header, &kid, &kid_present) == 0
        && oidc_verify_signature(jwk_set_uri, &jws, kid, kid_present)
        && oidc_claims_valid(jws.payload, issuer, audience, id_token)) {
        result = oidc_identity_from_claims(jws.payload, id_token, expected_nonce, identity);
    }
    free(kid);
    oidc_jws_free(&jws);
    return result;
}

int st_oidc_validate_id_token(const char *token, const char *expected_nonce, st_oidc_identity *identity)
{
    return oidc_validate(token, 1, expected_nonce, identity);
}

int st_oidc_validate_bearer_token(const char *token, st_oidc_identity *identity)
{
    return oidc_validate(token, 0, NULL, identity);
}

int st_oidc_token_is_hmac(const char *token)
{
    const char *dot = token == NULL ? NULL : strchr(token, '.');
    if (dot == NULL || dot == token || (size_t)(dot - token) > ST_OIDC_MAX_TOKEN_BYTES) {
        return 0;
    }
    char *header = oidc_decode_json_segment(token, (size_t)(dot - token));
    char *alg = st_oidc_json_text(header, "alg");
    int hmac = alg != NULL && strncmp(alg, "HS", 2U) == 0;
    free(alg);
    free(header);
    return hmac;
}

void st_oidc_identity_free(st_oidc_identity *identity)
{
    if (identity == NULL) {
        return;
    }
    free(identity->issuer);
    free(identity->subject);
    free(identity->preferred_username);
    memset(identity, 0, sizeof(*identity));
}

int st_oidc_identity_key(const char *issuer, const char *subject, char out[65])
{
    if (issuer == NULL || subject == NULL || out == NULL) {
        return -1;
    }
    size_t issuer_len = strlen(issuer);
    size_t subject_len = strlen(subject);
    uint8_t *material = (uint8_t *)malloc(issuer_len + subject_len + 1U);
    if (material == NULL) {
        return -1;
    }
    memcpy(material, issuer, issuer_len);
    material[issuer_len] = 0U;
    memcpy(material + issuer_len + 1U, subject, subject_len);
    uint8_t digest[ST_SHA256_LEN];
    st_sha256(material, issuer_len + subject_len + 1U, digest);
    free(material);
    st_hex_encode(digest, sizeof(digest), out);
    return 0;
}

int st_oidc_unusable_password_hash(char out[ST_PASSWORD_HASH_MAX_LEN + 1U])
{
    uint8_t random[32];
    char password[sizeof(random) * 2U + 1U];
    if (RAND_bytes(random, (int)sizeof(random)) != 1) {
        return -1;
    }
    st_hex_encode(random, sizeof(random), password);
    int rc = st_password_hash(password, out);
    OPENSSL_cleanse(random, sizeof(random));
    OPENSSL_cleanse(password, sizeof(password));
    return rc == 0 ? 0 : -1;
}

void st_oidc_jwks_reset(void)
{
    pthread_mutex_lock(&oidc_jwks_lock);
    oidc_jwks_reset_locked();
    pthread_mutex_unlock(&oidc_jwks_lock);
}

void st_oidc_jwks_set_refresh_cooldown_ms(long long cooldown_ms)
{
    pthread_mutex_lock(&oidc_jwks_lock);
    oidc_jwks_cooldown_ms = cooldown_ms < 0LL ? 0LL : cooldown_ms;
    pthread_mutex_unlock(&oidc_jwks_lock);
}
