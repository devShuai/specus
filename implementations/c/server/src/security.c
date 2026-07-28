#include "security.h"

#include "crypto.h"
#include "json.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

static const char *non_null(const char *value)
{
    return value == NULL ? "" : value;
}

static void copy_text(char *out, size_t out_len, const char *value, const char *fallback)
{
    if (value == NULL || *value == '\0') {
        value = fallback == NULL ? "" : fallback;
    }
    snprintf(out, out_len, "%s", value);
}

static const char *normalize_role(const char *role)
{
    if (role == NULL) {
        return "USER";
    }
    while (*role != '\0' && isspace((unsigned char)*role)) {
        ++role;
    }
    return (role[0] == 'A' || role[0] == 'a')
        && (role[1] == 'D' || role[1] == 'd')
        && (role[2] == 'M' || role[2] == 'm')
        && (role[3] == 'I' || role[3] == 'i')
        && (role[4] == 'N' || role[4] == 'n')
        ? "ADMIN" : "USER";
}

static void build_token_key(const char *jwt_secret, uint8_t key[ST_SHA256_LEN])
{
    static int initialized = 0;
    static uint8_t fallback_key[ST_SHA256_LEN];
    if (jwt_secret != NULL && *jwt_secret != '\0') {
        st_sha256((const uint8_t *)jwt_secret, strlen(jwt_secret), key);
        return;
    }
    if (!initialized) {
        char seed[128];
        int written = snprintf(seed,
                               sizeof(seed),
                               "specus-c-local-token:%lld:%ld:%p",
                               (long long)time(NULL),
                               (long)getpid(),
                               (void *)&initialized);
        if (written < 0) {
            const char *fallback = "specus-c-local-token";
            st_sha256((const uint8_t *)fallback, strlen(fallback), fallback_key);
        } else {
            st_sha256((const uint8_t *)seed, strlen(seed), fallback_key);
        }
        initialized = 1;
    }
    memcpy(key, fallback_key, ST_SHA256_LEN);
}

static size_t base64url_encoded_len(size_t len)
{
    size_t full = len / 3U;
    size_t rem = len % 3U;
    return full * 4U + (rem == 0U ? 0U : rem + 1U);
}

static int base64url_encode(const uint8_t *data, size_t len, char *out, size_t out_len)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t need = base64url_encoded_len(len);
    if (out_len <= need) {
        return -1;
    }
    size_t r = 0;
    size_t w = 0;
    while (r + 3U <= len) {
        uint32_t n = ((uint32_t)data[r] << 16) | ((uint32_t)data[r + 1U] << 8) | data[r + 2U];
        out[w++] = alphabet[(n >> 18) & 0x3fU];
        out[w++] = alphabet[(n >> 12) & 0x3fU];
        out[w++] = alphabet[(n >> 6) & 0x3fU];
        out[w++] = alphabet[n & 0x3fU];
        r += 3U;
    }
    if (r < len) {
        uint32_t n = (uint32_t)data[r] << 16;
        out[w++] = alphabet[(n >> 18) & 0x3fU];
        if (r + 1U < len) {
            n |= (uint32_t)data[r + 1U] << 8;
            out[w++] = alphabet[(n >> 12) & 0x3fU];
            out[w++] = alphabet[(n >> 6) & 0x3fU];
        } else {
            out[w++] = alphabet[(n >> 12) & 0x3fU];
        }
    }
    out[w] = '\0';
    return 0;
}

static int base64url_value(char ch)
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

static int base64url_decode(const char *value, uint8_t **out, size_t *out_len)
{
    *out = NULL;
    *out_len = 0;
    if (value == NULL) {
        return -1;
    }
    size_t len = strlen(value);
    if (len % 4U == 1U) {
        return -1;
    }
    size_t cap = (len / 4U) * 3U + 3U;
    uint8_t *buffer = (uint8_t *)malloc(cap == 0U ? 1U : cap);
    if (buffer == NULL) {
        return -1;
    }
    uint32_t acc = 0;
    int bits = 0;
    size_t w = 0;
    for (size_t i = 0; i < len; ++i) {
        int v = base64url_value(value[i]);
        if (v < 0) {
            free(buffer);
            return -1;
        }
        acc = (acc << 6U) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            buffer[w++] = (uint8_t)((acc >> bits) & 0xffU);
        }
    }
    *out = buffer;
    *out_len = w;
    return 0;
}

static int split_token(const char *token,
                       char **header,
                       char **payload,
                       char **signature,
                       char **signing_input)
{
    *header = NULL;
    *payload = NULL;
    *signature = NULL;
    *signing_input = NULL;
    const char *first = token == NULL ? NULL : strchr(token, '.');
    const char *second = first == NULL ? NULL : strchr(first + 1, '.');
    if (first == NULL || second == NULL || strchr(second + 1, '.') != NULL) {
        return -1;
    }
    size_t header_len = (size_t)(first - token);
    size_t payload_len = (size_t)(second - first - 1);
    size_t signature_len = strlen(second + 1);
    if (header_len == 0U || payload_len == 0U || signature_len == 0U) {
        return -1;
    }
    *header = (char *)malloc(header_len + 1U);
    *payload = (char *)malloc(payload_len + 1U);
    *signature = (char *)malloc(signature_len + 1U);
    *signing_input = (char *)malloc(header_len + 1U + payload_len + 1U);
    if (*header == NULL || *payload == NULL || *signature == NULL || *signing_input == NULL) {
        free(*header);
        free(*payload);
        free(*signature);
        free(*signing_input);
        *header = NULL;
        *payload = NULL;
        *signature = NULL;
        *signing_input = NULL;
        return -1;
    }
    memcpy(*header, token, header_len);
    (*header)[header_len] = '\0';
    memcpy(*payload, first + 1, payload_len);
    (*payload)[payload_len] = '\0';
    memcpy(*signature, second + 1, signature_len);
    (*signature)[signature_len] = '\0';
    memcpy(*signing_input, token, header_len + 1U + payload_len);
    (*signing_input)[header_len + 1U + payload_len] = '\0';
    return 0;
}

long long st_security_token_ttl_seconds(const char *ttl_seconds)
{
    if (ttl_seconds == NULL || *ttl_seconds == '\0') {
        return 28800;
    }
    char *end = NULL;
    long long parsed = strtoll(ttl_seconds, &end, 10);
    if (end == ttl_seconds || *end != '\0') {
        return 28800;
    }
    return parsed < 60 ? 60 : parsed;
}

int st_security_issue_local_token(const char *username,
                                  const char *tenant_id,
                                  const char *role,
                                  const char *jwt_secret,
                                  long long ttl_seconds,
                                  char *out,
                                  size_t out_len)
{
    if (username == NULL || *username == '\0' || out == NULL || out_len == 0U) {
        return -1;
    }
    if (ttl_seconds < 60) {
        ttl_seconds = 60;
    }
    long long now = (long long)time(NULL);
    char *escaped_user = st_json_escape(username);
    char *escaped_tenant = st_json_escape(tenant_id == NULL || *tenant_id == '\0' ? "default" : tenant_id);
    if (escaped_user == NULL || escaped_tenant == NULL) {
        free(escaped_user);
        free(escaped_tenant);
        return -1;
    }
    char header_json[] = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    char payload_json[512];
    int payload_len = snprintf(payload_json,
                               sizeof(payload_json),
                               "{\"iss\":\"specus\",\"sub\":\"%s\",\"tenant_id\":\"%s\","
                               "\"role\":\"%s\",\"iat\":%lld,\"exp\":%lld}",
                               escaped_user,
                               escaped_tenant,
                               normalize_role(role),
                               now,
                               now + ttl_seconds);
    free(escaped_user);
    free(escaped_tenant);
    if (payload_len < 0 || (size_t)payload_len >= sizeof(payload_json)) {
        return -1;
    }
    char header_segment[128];
    char payload_segment[768];
    if (base64url_encode((const uint8_t *)header_json, strlen(header_json), header_segment, sizeof(header_segment)) != 0
        || base64url_encode((const uint8_t *)payload_json, (size_t)payload_len, payload_segment, sizeof(payload_segment)) != 0) {
        return -1;
    }
    char signing_input[1024];
    int signing_len = snprintf(signing_input, sizeof(signing_input), "%s.%s", header_segment, payload_segment);
    if (signing_len < 0 || (size_t)signing_len >= sizeof(signing_input)) {
        return -1;
    }
    uint8_t key[ST_SHA256_LEN];
    uint8_t mac[ST_SHA256_LEN];
    build_token_key(jwt_secret, key);
    st_hmac_sha256(key, sizeof(key), (const uint8_t *)signing_input, (size_t)signing_len, mac);
    char signature_segment[64];
    if (base64url_encode(mac, sizeof(mac), signature_segment, sizeof(signature_segment)) != 0) {
        return -1;
    }
    int written = snprintf(out, out_len, "%s.%s", signing_input, signature_segment);
    return written < 0 || (size_t)written >= out_len ? -1 : 0;
}

int st_security_validate_local_token(const char *token,
                                     const char *jwt_secret,
                                     const char *default_tenant_id,
                                     const char *admin_username,
                                     st_security_token_claims *claims)
{
    if (claims == NULL) {
        return -1;
    }
    memset(claims, 0, sizeof(*claims));
    char *header_segment = NULL;
    char *payload_segment = NULL;
    char *signature_segment = NULL;
    char *signing_input = NULL;
    if (split_token(token, &header_segment, &payload_segment, &signature_segment, &signing_input) != 0) {
        return -1;
    }
    uint8_t key[ST_SHA256_LEN];
    uint8_t expected_mac[ST_SHA256_LEN];
    build_token_key(jwt_secret, key);
    st_hmac_sha256(key,
                   sizeof(key),
                   (const uint8_t *)signing_input,
                   strlen(signing_input),
                   expected_mac);
    uint8_t *actual_mac = NULL;
    size_t actual_mac_len = 0;
    int ok = base64url_decode(signature_segment, &actual_mac, &actual_mac_len) == 0
        && actual_mac_len == sizeof(expected_mac)
        && st_constant_time_eq(expected_mac, actual_mac, sizeof(expected_mac));
    uint8_t *header_json = NULL;
    uint8_t *payload_json = NULL;
    size_t header_len = 0;
    size_t payload_len = 0;
    if (ok) {
        ok = base64url_decode(header_segment, &header_json, &header_len) == 0
            && base64url_decode(payload_segment, &payload_json, &payload_len) == 0;
    }
    if (ok) {
        char *header_text = (char *)malloc(header_len + 1U);
        char *payload_text = (char *)malloc(payload_len + 1U);
        if (header_text == NULL || payload_text == NULL) {
            ok = 0;
        } else {
            memcpy(header_text, header_json, header_len);
            header_text[header_len] = '\0';
            memcpy(payload_text, payload_json, payload_len);
            payload_text[payload_len] = '\0';
            char *alg = st_json_get_string(header_text, "alg");
            char *iss = st_json_get_string(payload_text, "iss");
            char *sub = st_json_get_string(payload_text, "sub");
            char *tenant = st_json_get_string(payload_text, "tenant_id");
            char *role = st_json_get_string(payload_text, "role");
            int exp = 0;
            ok = alg != NULL && strcmp(alg, "HS256") == 0
                && iss != NULL && strcmp(iss, "specus") == 0
                && sub != NULL && *sub != '\0'
                && st_json_get_int(payload_text, "exp", &exp) == 0
                && (long long)time(NULL) < (long long)exp;
            if (ok) {
                copy_text(claims->username, sizeof(claims->username), sub, "");
                copy_text(claims->tenant_id, sizeof(claims->tenant_id), tenant, default_tenant_id);
                copy_text(claims->role, sizeof(claims->role), normalize_role(role), "USER");
                if (admin_username != NULL && strcasecmp(claims->username, admin_username) == 0) {
                    copy_text(claims->role, sizeof(claims->role), "ADMIN", "ADMIN");
                }
                claims->expires_at = exp;
            }
            free(alg);
            free(iss);
            free(sub);
            free(tenant);
            free(role);
        }
        free(header_text);
        free(payload_text);
    }
    free(actual_mac);
    free(header_json);
    free(payload_json);
    free(header_segment);
    free(payload_segment);
    free(signature_segment);
    free(signing_input);
    return ok ? 0 : -1;
}

int st_security_build_oidc_config(const char *client_id,
                                  const char *authorization_endpoint,
                                  const char *end_session_endpoint,
                                  const char *redirect_uri,
                                  const char *scope,
                                  int password_login_enabled,
                                  char *out,
                                  size_t out_len)
{
    int configured = client_id != NULL && *client_id != '\0';
    char *escaped_client_id = st_json_escape(non_null(client_id));
    char *escaped_auth = st_json_escape(non_null(authorization_endpoint));
    char *escaped_logout = st_json_escape(non_null(end_session_endpoint));
    char *escaped_redirect = st_json_escape(non_null(redirect_uri));
    char *escaped_scope = st_json_escape(non_null(scope));
    if (escaped_client_id == NULL || escaped_auth == NULL || escaped_logout == NULL || escaped_redirect == NULL
        || escaped_scope == NULL) {
        free(escaped_client_id);
        free(escaped_auth);
        free(escaped_logout);
        free(escaped_redirect);
        free(escaped_scope);
        return -1;
    }
    int written = snprintf(out,
                           out_len,
                           "{\"configured\":%s,\"authorizationEndpoint\":\"%s\","
                           "\"endSessionEndpoint\":\"%s\",\"clientId\":\"%s\","
                           "\"redirectUri\":\"%s\",\"scope\":\"%s\",\"passwordLoginEnabled\":%s}",
                           configured ? "true" : "false",
                           escaped_auth,
                           escaped_logout,
                           escaped_client_id,
                           escaped_redirect,
                           escaped_scope,
                           password_login_enabled ? "true" : "false");
    free(escaped_client_id);
    free(escaped_auth);
    free(escaped_logout);
    free(escaped_redirect);
    free(escaped_scope);
    return written < 0 || (size_t)written >= out_len ? -1 : written;
}

const char *st_security_tls_mode_label(const char *mode)
{
    if (mode == NULL || *mode == '\0' || strcmp(mode, "off") == 0) {
        return "off";
    }
    if (strcmp(mode, "pem") == 0 || strcmp(mode, "pkcs12") == 0 || strcmp(mode, "self-signed") == 0) {
        return mode;
    }
    return "invalid";
}

int st_security_build_tls_config(const char *mode,
                                 const char *certificate_path,
                                 const char *key_path,
                                 char *out,
                                 size_t out_len)
{
    const char *label = st_security_tls_mode_label(mode);
    char *escaped_cert = st_json_escape(non_null(certificate_path));
    char *escaped_key = st_json_escape(non_null(key_path));
    if (escaped_cert == NULL || escaped_key == NULL) {
        free(escaped_cert);
        free(escaped_key);
        return -1;
    }
    int written = snprintf(out,
                           out_len,
                           "{\"mode\":\"%s\",\"certificatePath\":\"%s\",\"keyPath\":\"%s\",\"wired\":false}",
                           label,
                           escaped_cert,
                           escaped_key);
    free(escaped_cert);
    free(escaped_key);
    return written < 0 || (size_t)written >= out_len ? -1 : written;
}
