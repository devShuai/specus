#define _POSIX_C_SOURCE 200809L

#include "tls_transport.h"

#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct {
    st_tls_server_context *context;
    int fd;
    int result;
} tls_server_fixture;

static void *tls_server_run(void *arg)
{
    tls_server_fixture *fixture = (tls_server_fixture *)arg;
    char error[512];
    st_tls_connection *connection = NULL;
    fixture->result = 1;
    if (st_tls_connection_accept(fixture->context,
                                 fixture->fd,
                                 &connection,
                                 error,
                                 sizeof(error)) != 0) {
        fprintf(stderr, "test TLS server handshake failed: %s\n", error);
        return NULL;
    }
    uint8_t request[4];
    ssize_t read_len = st_tls_connection_read(connection, request, sizeof(request));
    if (read_len == (ssize_t)sizeof(request)
        && memcmp(request, "ping", sizeof(request)) == 0
        && st_tls_connection_write_all(connection, (const uint8_t *)"pong", 4U) == 0) {
        fixture->result = 0;
    }
    st_tls_connection_free(connection);
    return NULL;
}

static int test_self_signed_handshake(void)
{
    st_tls_config config;
    memset(&config, 0, sizeof(config));
    config.mode = ST_TLS_SELF_SIGNED;
    st_tls_server_context *context = NULL;
    char error[512];
    if (st_tls_server_context_create(&config, &context, error, sizeof(error)) != 0
        || !st_tls_server_context_enabled(context)) {
        fprintf(stderr, "self-signed context creation failed: %s\n", error);
        return 1;
    }
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
        st_tls_server_context_free(context);
        return 1;
    }
    tls_server_fixture fixture = {.context = context, .fd = sockets[0], .result = 1};
    pthread_t server_thread;
    if (pthread_create(&server_thread, NULL, tls_server_run, &fixture) != 0) {
        close(sockets[0]);
        close(sockets[1]);
        st_tls_server_context_free(context);
        return 1;
    }

    SSL_CTX *client_context = SSL_CTX_new(TLS_client_method());
    SSL *client = client_context == NULL ? NULL : SSL_new(client_context);
    int client_ok = client != NULL
        && SSL_CTX_set_min_proto_version(client_context, TLS1_2_VERSION) == 1
        && SSL_set_fd(client, sockets[1]) == 1
        && SSL_connect(client) == 1
        && SSL_version(client) >= TLS1_2_VERSION
        && SSL_write(client, "ping", 4) == 4;
    uint8_t response[4];
    if (client_ok) {
        client_ok = SSL_read(client, response, sizeof(response)) == (int)sizeof(response)
            && memcmp(response, "pong", sizeof(response)) == 0;
    }
    if (client != NULL) {
        (void)SSL_shutdown(client);
        SSL_free(client);
    }
    SSL_CTX_free(client_context);
    close(sockets[1]);
    pthread_join(server_thread, NULL);
    close(sockets[0]);
    st_tls_server_context_free(context);
    if (!client_ok || fixture.result != 0) {
        fprintf(stderr, "self-signed TLS 1.2+ round trip failed\n");
        return 1;
    }
    return 0;
}

static int write_pkcs12_fixture(const char *path, const char *password)
{
    EVP_PKEY_CTX *keygen = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *key = NULL;
    X509 *certificate = NULL;
    PKCS12 *bundle = NULL;
    FILE *file = NULL;
    int result = -1;
    if (keygen == NULL
        || EVP_PKEY_keygen_init(keygen) <= 0
        || EVP_PKEY_CTX_set_rsa_keygen_bits(keygen, 2048) <= 0
        || EVP_PKEY_keygen(keygen, &key) <= 0) {
        goto cleanup;
    }
    certificate = X509_new();
    X509_NAME *name = certificate == NULL ? NULL : X509_get_subject_name(certificate);
    if (certificate == NULL
        || X509_set_version(certificate, 2L) != 1
        || ASN1_INTEGER_set(X509_get_serialNumber(certificate), 2L) != 1
        || X509_gmtime_adj(X509_get_notBefore(certificate), -60L) == NULL
        || X509_gmtime_adj(X509_get_notAfter(certificate), 3600L) == NULL
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
        || X509_sign(certificate, key, EVP_sha256()) <= 0) {
        goto cleanup;
    }
    bundle = PKCS12_create(password, "specus-test", key, certificate, NULL, 0, 0, 0, 0, 0);
    file = bundle == NULL ? NULL : fopen(path, "wb");
    if (file != NULL && i2d_PKCS12_fp(file, bundle) == 1) {
        result = 0;
    }

cleanup:
    if (file != NULL) {
        fclose(file);
    }
    PKCS12_free(bundle);
    X509_free(certificate);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(keygen);
    return result;
}

static int test_pkcs12_file_context(void)
{
    char path[256];
    snprintf(path, sizeof(path), "/tmp/specus-c-tls-%ld.p12", (long)getpid());
    unlink(path);
    if (write_pkcs12_fixture(path, "fixture-password") != 0) {
        fprintf(stderr, "PKCS#12 TLS fixture creation failed\n");
        return 1;
    }
    st_tls_config config;
    memset(&config, 0, sizeof(config));
    config.mode = ST_TLS_FILE;
    config.keystore_path = path;
    config.keystore_password = "fixture-password";
    st_tls_server_context *context = NULL;
    char error[512];
    int failed = st_tls_server_context_create(&config, &context, error, sizeof(error)) != 0
        || !st_tls_server_context_enabled(context);
    st_tls_server_context_free(context);
    unlink(path);
    if (failed) {
        fprintf(stderr, "PKCS#12 TLS context load failed: %s\n", error);
        return 1;
    }
    return 0;
}

static int expect_deployment(const char *name,
                             st_tls_mode mode,
                             int require_encryption,
                             int terminated_upstream,
                             const char *environment,
                             const char *bind_address,
                             int expected_ok)
{
    st_tls_config config;
    memset(&config, 0, sizeof(config));
    config.mode = mode;
    config.require_encryption = require_encryption;
    config.terminated_upstream = terminated_upstream;
    char error[512];
    int ok = st_tls_validate_deployment(&config,
                                        environment,
                                        bind_address,
                                        error,
                                        sizeof(error)) == 0;
    if (ok != expected_ok) {
        fprintf(stderr, "%s: deployment validation mismatch: %s\n", name, error);
        return 1;
    }
    return 0;
}

int main(void)
{
    if (expect_deployment("prod public plaintext",
                          ST_TLS_DISABLED, 0, 0, "prod", "0.0.0.0", 0) != 0
        || expect_deployment("unknown environment fails safe",
                             ST_TLS_DISABLED, 0, 0, "staging", "0.0.0.0", 0) != 0
        || expect_deployment("dev plaintext",
                             ST_TLS_DISABLED, 0, 0, "dev", "0.0.0.0", 1) != 0
        || expect_deployment("require encryption overrides dev",
                             ST_TLS_DISABLED, 1, 0, "dev", "0.0.0.0", 0) != 0
        || expect_deployment("terminated loopback",
                             ST_TLS_DISABLED, 0, 1, "prod", "127.0.0.1", 1) != 0
        || expect_deployment("terminated private ipv4",
                             ST_TLS_DISABLED, 0, 1, "prod", "10.1.2.3", 1) != 0
        || expect_deployment("terminated private ipv6",
                             ST_TLS_DISABLED, 0, 1, "prod", "fd00::1", 1) != 0
        || expect_deployment("terminated public rejected",
                             ST_TLS_DISABLED, 0, 1, "prod", "8.8.8.8", 0) != 0
        || expect_deployment("prod self signed rejected",
                             ST_TLS_SELF_SIGNED, 0, 0, "prod", "0.0.0.0", 0) != 0
        || expect_deployment("dev self signed",
                             ST_TLS_SELF_SIGNED, 0, 0, "dev", "0.0.0.0", 1) != 0
        || expect_deployment("prod file",
                             ST_TLS_FILE, 0, 0, "prod", "0.0.0.0", 1) != 0) {
        return 1;
    }

    setenv("SPECUS_TLS_MODE", "self_signed", 1);
    setenv("SPECUS_TLS_REQUIRE_ENCRYPTION", "true", 1);
    setenv("SPECUS_TLS_TERMINATED_UPSTREAM", "true", 1);
    st_tls_config environment_config;
    st_tls_config_from_env(&environment_config);
    unsetenv("SPECUS_TLS_MODE");
    unsetenv("SPECUS_TLS_REQUIRE_ENCRYPTION");
    unsetenv("SPECUS_TLS_TERMINATED_UPSTREAM");
    if (environment_config.mode != ST_TLS_SELF_SIGNED
        || !environment_config.require_encryption
        || !environment_config.terminated_upstream
        || strcmp(st_tls_mode_name(environment_config.mode), "self-signed") != 0) {
        fprintf(stderr, "TLS environment parsing mismatch\n");
        return 1;
    }
    return test_self_signed_handshake() != 0 || test_pkcs12_file_context() != 0 ? 1 : 0;
}
