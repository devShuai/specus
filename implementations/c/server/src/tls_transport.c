#define _POSIX_C_SOURCE 200809L

#include "tls_transport.h"

#include "security_baseline.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct st_tls_server_context {
    SSL_CTX *ssl_ctx;
    st_tls_mode mode;
};

struct st_tls_connection {
    SSL *ssl;
};

static int env_bool(const char *name, int fallback)
{
    const char *value = getenv(name);
    if (value == NULL || *value == '\0') {
        return fallback;
    }
    return strcmp(value, "0") != 0
        && strcmp(value, "false") != 0
        && strcmp(value, "FALSE") != 0
        && strcmp(value, "no") != 0
        && strcmp(value, "NO") != 0;
}

static int ascii_case_equal_trimmed(const char *value, const char *expected)
{
    if (value == NULL) {
        return 0;
    }
    while (*value != '\0' && isspace((unsigned char)*value)) {
        ++value;
    }
    size_t len = strlen(value);
    while (len > 0U && isspace((unsigned char)value[len - 1U])) {
        --len;
    }
    if (len != strlen(expected)) {
        return 0;
    }
    for (size_t i = 0; i < len; ++i) {
        if (tolower((unsigned char)value[i]) != (unsigned char)expected[i]) {
            return 0;
        }
    }
    return 1;
}

static st_tls_mode parse_mode(const char *value)
{
    if (ascii_case_equal_trimmed(value, "file")) {
        return ST_TLS_FILE;
    }
    if (ascii_case_equal_trimmed(value, "self-signed")
        || ascii_case_equal_trimmed(value, "selfsigned")
        || ascii_case_equal_trimmed(value, "self_signed")) {
        return ST_TLS_SELF_SIGNED;
    }
    return ST_TLS_DISABLED;
}

void st_tls_config_from_env(st_tls_config *config)
{
    if (config == NULL) {
        return;
    }
    memset(config, 0, sizeof(*config));
    config->mode = parse_mode(getenv("SPECUS_TLS_MODE"));
    config->keystore_path = getenv("SPECUS_TLS_KEYSTORE");
    config->keystore_password = getenv("SPECUS_TLS_KEYSTORE_PASSWORD");
    config->key_password = getenv("SPECUS_TLS_KEY_PASSWORD");
    config->certificate_path = getenv("SPECUS_TLS_CERTIFICATE");
    config->private_key_path = getenv("SPECUS_TLS_PRIVATE_KEY");
    config->require_encryption = env_bool("SPECUS_TLS_REQUIRE_ENCRYPTION", 0);
    config->terminated_upstream = env_bool("SPECUS_TLS_TERMINATED_UPSTREAM", 0);
}

const char *st_tls_mode_name(st_tls_mode mode)
{
    switch (mode) {
        case ST_TLS_FILE: return "file";
        case ST_TLS_SELF_SIGNED: return "self-signed";
        default: return "disabled";
    }
}

static int private_bind_address(const char *value)
{
    if (value == NULL || *value == '\0') {
        return 0;
    }
    struct in_addr ipv4;
    if (inet_pton(AF_INET, value, &ipv4) == 1) {
        const uint8_t *bytes = (const uint8_t *)&ipv4;
        return bytes[0] == 10U
            || bytes[0] == 127U
            || (bytes[0] == 172U && bytes[1] >= 16U && bytes[1] <= 31U)
            || (bytes[0] == 192U && bytes[1] == 168U)
            || (bytes[0] == 169U && bytes[1] == 254U);
    }
    struct in6_addr ipv6;
    if (inet_pton(AF_INET6, value, &ipv6) == 1) {
        const uint8_t *bytes = ipv6.s6_addr;
        return IN6_IS_ADDR_LOOPBACK(&ipv6)
            || (bytes[0] & 0xfeU) == 0xfcU
            || (bytes[0] == 0xfeU && (bytes[1] & 0xc0U) == 0x80U);
    }
    return 0;
}

static int set_error(char *error, size_t error_len, const char *message)
{
    if (error != NULL && error_len > 0U) {
        snprintf(error, error_len, "%s", message == NULL ? "TLS error" : message);
    }
    return -1;
}

int st_tls_validate_deployment(const st_tls_config *config,
                               const char *environment,
                               const char *bind_address,
                               char *error,
                               size_t error_len)
{
    if (config == NULL) {
        return set_error(error, error_len, "TLS configuration is required");
    }
    int production = config->require_encryption
        || st_deployment_environment_parse(environment) == ST_DEPLOYMENT_PROD;
    if (!production) {
        return 0;
    }
    if (config->mode == ST_TLS_SELF_SIGNED) {
        return set_error(error, error_len,
                         "production control channel cannot use a self-signed certificate");
    }
    if (config->mode == ST_TLS_DISABLED
        && (!config->terminated_upstream || !private_bind_address(bind_address))) {
        return set_error(error,
                         error_len,
                         "production control channel requires TLS, or trusted upstream TLS with a private/loopback bind address");
    }
    return 0;
}

static void openssl_error(char *error, size_t error_len, const char *prefix)
{
    unsigned long code = ERR_get_error();
    char detail[256] = "unknown OpenSSL error";
    if (code != 0UL) {
        ERR_error_string_n(code, detail, sizeof(detail));
    }
    if (error != NULL && error_len > 0U) {
        snprintf(error, error_len, "%s: %s", prefix, detail);
    }
}

static int configure_context(SSL_CTX *ctx, char *error, size_t error_len)
{
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1) {
        openssl_error(error, error_len, "failed to set TLS 1.2 minimum");
        return -1;
    }
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION | SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
    return 0;
}

static int create_self_signed(SSL_CTX *ctx, char *error, size_t error_len)
{
    EVP_PKEY_CTX *keygen = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *key = NULL;
    X509 *certificate = NULL;
    if (keygen == NULL
        || EVP_PKEY_keygen_init(keygen) <= 0
        || EVP_PKEY_CTX_set_rsa_keygen_bits(keygen, 2048) <= 0
        || EVP_PKEY_keygen(keygen, &key) <= 0) {
        openssl_error(error, error_len, "failed to generate TLS private key");
        EVP_PKEY_CTX_free(keygen);
        EVP_PKEY_free(key);
        return -1;
    }
    EVP_PKEY_CTX_free(keygen);
    certificate = X509_new();
    X509_NAME *name = certificate == NULL ? NULL : X509_get_subject_name(certificate);
    if (certificate == NULL
        || X509_set_version(certificate, 2L) != 1
        || ASN1_INTEGER_set(X509_get_serialNumber(certificate), 1L) != 1
        || X509_gmtime_adj(X509_get_notBefore(certificate), -60L) == NULL
        || X509_gmtime_adj(X509_get_notAfter(certificate), 24L * 60L * 60L) == NULL
        || X509_set_pubkey(certificate, key) != 1
        || name == NULL
        || X509_NAME_add_entry_by_txt(name,
                                      "CN",
                                      MBSTRING_ASC,
                                      (const unsigned char *)"localhost",
                                      -1,
                                      -1,
                                      0) != 1
        || X509_set_issuer_name(certificate, name) != 1
        || X509_sign(certificate, key, EVP_sha256()) <= 0
        || SSL_CTX_use_certificate(ctx, certificate) != 1
        || SSL_CTX_use_PrivateKey(ctx, key) != 1
        || SSL_CTX_check_private_key(ctx) != 1) {
        openssl_error(error, error_len, "failed to build self-signed TLS certificate");
        X509_free(certificate);
        EVP_PKEY_free(key);
        return -1;
    }
    X509_free(certificate);
    EVP_PKEY_free(key);
    return 0;
}

static int has_suffix_case(const char *value, const char *suffix)
{
    if (value == NULL || suffix == NULL) {
        return 0;
    }
    size_t value_len = strlen(value);
    size_t suffix_len = strlen(suffix);
    if (value_len < suffix_len) {
        return 0;
    }
    return ascii_case_equal_trimmed(value + value_len - suffix_len, suffix);
}

static int load_pkcs12(SSL_CTX *ctx,
                       const char *path,
                       const char *password,
                       char *error,
                       size_t error_len)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        return set_error(error, error_len, "TLS PKCS#12 keystore could not be opened");
    }
    PKCS12 *bundle = d2i_PKCS12_fp(file, NULL);
    fclose(file);
    EVP_PKEY *key = NULL;
    X509 *certificate = NULL;
    STACK_OF(X509) *chain = NULL;
    if (bundle == NULL
        || PKCS12_parse(bundle, password == NULL ? "" : password, &key, &certificate, &chain) != 1
        || SSL_CTX_use_certificate(ctx, certificate) != 1
        || SSL_CTX_use_PrivateKey(ctx, key) != 1) {
        openssl_error(error, error_len, "failed to load TLS PKCS#12 keystore");
        PKCS12_free(bundle);
        EVP_PKEY_free(key);
        X509_free(certificate);
        sk_X509_pop_free(chain, X509_free);
        return -1;
    }
    for (int index = 0; chain != NULL && index < sk_X509_num(chain); ++index) {
        if (SSL_CTX_add1_chain_cert(ctx, sk_X509_value(chain, index)) != 1) {
            openssl_error(error, error_len, "failed to load TLS certificate chain");
            PKCS12_free(bundle);
            EVP_PKEY_free(key);
            X509_free(certificate);
            sk_X509_pop_free(chain, X509_free);
            return -1;
        }
    }
    int valid = SSL_CTX_check_private_key(ctx) == 1;
    PKCS12_free(bundle);
    EVP_PKEY_free(key);
    X509_free(certificate);
    sk_X509_pop_free(chain, X509_free);
    if (!valid) {
        openssl_error(error, error_len, "TLS certificate/private key mismatch");
        return -1;
    }
    return 0;
}

static int load_file_credentials(SSL_CTX *ctx,
                                 const st_tls_config *config,
                                 char *error,
                                 size_t error_len)
{
    const char *keystore = config->keystore_path;
    const char *certificate = config->certificate_path;
    const char *private_key = config->private_key_path;
    if (keystore != NULL && *keystore != '\0'
        && (has_suffix_case(keystore, ".p12") || has_suffix_case(keystore, ".pfx"))) {
        return load_pkcs12(ctx, keystore, config->keystore_password, error, error_len);
    }
    if ((certificate == NULL || *certificate == '\0') && keystore != NULL && *keystore != '\0') {
        certificate = keystore;
    }
    if ((private_key == NULL || *private_key == '\0') && keystore != NULL && *keystore != '\0') {
        private_key = keystore;
    }
    if (certificate == NULL || *certificate == '\0' || private_key == NULL || *private_key == '\0') {
        return set_error(error,
                         error_len,
                         "file TLS mode requires a PKCS#12 keystore or PEM certificate/private key paths");
    }
    const char *password = config->key_password == NULL
        ? config->keystore_password
        : config->key_password;
    SSL_CTX_set_default_passwd_cb_userdata(ctx, (void *)(password == NULL ? "" : password));
    if (SSL_CTX_use_certificate_chain_file(ctx, certificate) != 1
        || SSL_CTX_use_PrivateKey_file(ctx, private_key, SSL_FILETYPE_PEM) != 1
        || SSL_CTX_check_private_key(ctx) != 1) {
        openssl_error(error, error_len, "failed to load TLS PEM certificate/private key");
        return -1;
    }
    return 0;
}

int st_tls_server_context_create(const st_tls_config *config,
                                 st_tls_server_context **out,
                                 char *error,
                                 size_t error_len)
{
    if (config == NULL || out == NULL) {
        return set_error(error, error_len, "TLS context output is required");
    }
    *out = NULL;
    st_tls_server_context *context = (st_tls_server_context *)calloc(1, sizeof(*context));
    if (context == NULL) {
        return set_error(error, error_len, "out of memory creating TLS context");
    }
    context->mode = config->mode;
    if (config->mode == ST_TLS_DISABLED) {
        *out = context;
        return 0;
    }
    context->ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (context->ssl_ctx == NULL || configure_context(context->ssl_ctx, error, error_len) != 0) {
        st_tls_server_context_free(context);
        return -1;
    }
    int rc = config->mode == ST_TLS_SELF_SIGNED
        ? create_self_signed(context->ssl_ctx, error, error_len)
        : load_file_credentials(context->ssl_ctx, config, error, error_len);
    if (rc != 0) {
        st_tls_server_context_free(context);
        return -1;
    }
    *out = context;
    return 0;
}

void st_tls_server_context_free(st_tls_server_context *context)
{
    if (context != NULL) {
        SSL_CTX_free(context->ssl_ctx);
        free(context);
    }
}

int st_tls_server_context_enabled(const st_tls_server_context *context)
{
    return context != NULL && context->ssl_ctx != NULL;
}

int st_tls_connection_accept(st_tls_server_context *context,
                             int fd,
                             st_tls_connection **out,
                             char *error,
                             size_t error_len)
{
    if (out == NULL) {
        return set_error(error, error_len, "TLS connection output is required");
    }
    *out = NULL;
    if (!st_tls_server_context_enabled(context)) {
        return 0;
    }
    st_tls_connection *connection = (st_tls_connection *)calloc(1, sizeof(*connection));
    if (connection == NULL) {
        return set_error(error, error_len, "out of memory creating TLS connection");
    }
    connection->ssl = SSL_new(context->ssl_ctx);
    if (connection->ssl == NULL
        || SSL_set_fd(connection->ssl, fd) != 1
        || SSL_accept(connection->ssl) != 1) {
        openssl_error(error, error_len, "TLS handshake failed");
        st_tls_connection_free(connection);
        return -1;
    }
    *out = connection;
    return 0;
}

ssize_t st_tls_connection_read(st_tls_connection *connection, uint8_t *buffer, size_t len)
{
    if (connection == NULL || connection->ssl == NULL || buffer == NULL || len == 0U) {
        return -1;
    }
    size_t read_len = 0U;
    if (SSL_read_ex(connection->ssl, buffer, len, &read_len) == 1) {
        return (ssize_t)read_len;
    }
    int ssl_error = SSL_get_error(connection->ssl, 0);
    if (ssl_error == SSL_ERROR_ZERO_RETURN) {
        return 0;
    }
    if ((ssl_error == SSL_ERROR_SYSCALL || ssl_error == SSL_ERROR_WANT_READ)
        && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        return -2;
    }
    if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
        return -2;
    }
    return -1;
}

int st_tls_connection_write_all(st_tls_connection *connection, const uint8_t *buffer, size_t len)
{
    if (connection == NULL || connection->ssl == NULL || (buffer == NULL && len != 0U)) {
        return -1;
    }
    size_t offset = 0U;
    while (offset < len) {
        size_t written = 0U;
        if (SSL_write_ex(connection->ssl, buffer + offset, len - offset, &written) == 1) {
            offset += written;
            continue;
        }
        int ssl_error = SSL_get_error(connection->ssl, 0);
        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
            continue;
        }
        return -1;
    }
    return 0;
}

void st_tls_connection_free(st_tls_connection *connection)
{
    if (connection != NULL) {
        if (connection->ssl != NULL) {
            (void)SSL_shutdown(connection->ssl);
            SSL_free(connection->ssl);
        }
        free(connection);
    }
}
