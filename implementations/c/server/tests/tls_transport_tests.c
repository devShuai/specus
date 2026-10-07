#define _POSIX_C_SOURCE 200809L

#include "tls_transport.h"

#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct {
    st_tls_server_context *context;
    int fd;
    int result;
    /* Set when the client is expected to abort the handshake. */
    int quiet;
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
        if (!fixture->quiet) {
            fprintf(stderr, "test TLS server handshake failed: %s\n", error);
        }
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

/* ------------------------------------------------------------------------------------------- */
/* PEM certificate/private key mode: SPECUS_TLS_CERTIFICATE + SPECUS_TLS_PRIVATE_KEY, or one PEM */
/* SPECUS_TLS_KEYSTORE that holds both, served to a client that verifies chain and host name.    */

#define PEM_HOST_NAME "specus-c.test"

static EVP_PKEY *generate_rsa_key(void)
{
    EVP_PKEY_CTX *keygen = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *key = NULL;
    if (keygen == NULL
        || EVP_PKEY_keygen_init(keygen) <= 0
        || EVP_PKEY_CTX_set_rsa_keygen_bits(keygen, 2048) <= 0
        || EVP_PKEY_keygen(keygen, &key) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(keygen);
    return key;
}

static int add_extension(X509 *certificate, X509 *issuer, int nid, const char *value)
{
    X509V3_CTX context;
    X509V3_set_ctx_nodb(&context);
    X509V3_set_ctx(&context, issuer, certificate, NULL, NULL, 0);
    X509_EXTENSION *extension = X509V3_EXT_conf_nid(NULL, &context, nid, value);
    int ok = extension != NULL && X509_add_ext(certificate, extension, -1) == 1;
    X509_EXTENSION_free(extension);
    return ok ? 0 : -1;
}

/* A self-signed CA when issuer is NULL; otherwise a server certificate for dns_name it signs. */
static X509 *issue_certificate(const char *common_name,
                               const char *dns_name,
                               EVP_PKEY *key,
                               X509 *issuer,
                               EVP_PKEY *issuer_key,
                               long serial)
{
    X509 *certificate = X509_new();
    X509_NAME *name = certificate == NULL ? NULL : X509_get_subject_name(certificate);
    int ok = certificate != NULL
        && X509_set_version(certificate, 2L) == 1
        && ASN1_INTEGER_set(X509_get_serialNumber(certificate), serial) == 1
        && X509_gmtime_adj(X509_get_notBefore(certificate), -60L) != NULL
        && X509_gmtime_adj(X509_get_notAfter(certificate), 3600L) != NULL
        && X509_set_pubkey(certificate, key) == 1
        && name != NULL
        && X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                      (const unsigned char *)common_name, -1, -1, 0) == 1
        && X509_set_issuer_name(certificate,
                                issuer == NULL ? name : X509_get_subject_name(issuer)) == 1;
    if (ok && issuer == NULL) {
        ok = add_extension(certificate, certificate, NID_basic_constraints, "critical,CA:TRUE") == 0
            && add_extension(certificate, certificate, NID_key_usage, "critical,keyCertSign,cRLSign") == 0;
    } else if (ok) {
        char alt_name[256];
        snprintf(alt_name, sizeof(alt_name), "DNS:%s", dns_name);
        ok = add_extension(certificate, issuer, NID_basic_constraints, "CA:FALSE") == 0
            && add_extension(certificate, issuer, NID_key_usage, "critical,digitalSignature,keyEncipherment") == 0
            && add_extension(certificate, issuer, NID_ext_key_usage, "serverAuth") == 0
            && add_extension(certificate, issuer, NID_subject_alt_name, alt_name) == 0;
    }
    if (!ok || X509_sign(certificate, issuer_key == NULL ? key : issuer_key, EVP_sha256()) <= 0) {
        X509_free(certificate);
        return NULL;
    }
    return certificate;
}

/* Writes an optional private key (encrypted when password is set) followed by certificates. */
static int write_pem(const char *path, EVP_PKEY *key, const char *password, X509 *first, X509 *second)
{
    FILE *file = fopen(path, "w");
    if (file == NULL) {
        return -1;
    }
    int ok = 1;
    if (key != NULL) {
        ok = password == NULL
            ? PEM_write_PrivateKey(file, key, NULL, NULL, 0, NULL, NULL) == 1
            : PEM_write_PrivateKey(file, key, EVP_aes_256_cbc(), NULL, 0, NULL, (void *)password) == 1;
    }
    if (ok && first != NULL) {
        ok = PEM_write_X509(file, first) == 1;
    }
    if (ok && second != NULL) {
        ok = PEM_write_X509(file, second) == 1;
    }
    return fclose(file) == 0 && ok ? 0 : -1;
}

typedef struct {
    int connected;
    long verify_result;
    int round_trip;
} handshake_outcome;

/*
 * One handshake over a socket pair against an OpenSSL client that trusts only trust_anchor and
 * checks host_name, then a ping/pong when it connected.
 */
static int verified_handshake(st_tls_server_context *context,
                              X509 *trust_anchor,
                              const char *host_name,
                              handshake_outcome *outcome)
{
    memset(outcome, 0, sizeof(*outcome));
    outcome->verify_result = -1;
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
        return -1;
    }
    tls_server_fixture fixture = {.context = context, .fd = sockets[0], .result = 1, .quiet = 1};
    pthread_t server_thread;
    if (pthread_create(&server_thread, NULL, tls_server_run, &fixture) != 0) {
        close(sockets[0]);
        close(sockets[1]);
        return -1;
    }
    SSL_CTX *client_context = SSL_CTX_new(TLS_client_method());
    SSL *client = NULL;
    if (client_context != NULL
        && SSL_CTX_set_min_proto_version(client_context, TLS1_2_VERSION) == 1
        && X509_STORE_add_cert(SSL_CTX_get_cert_store(client_context), trust_anchor) == 1) {
        SSL_CTX_set_verify(client_context, SSL_VERIFY_PEER, NULL);
        client = SSL_new(client_context);
    }
    if (client != NULL
        && SSL_set_tlsext_host_name(client, host_name) == 1
        && SSL_set1_host(client, host_name) == 1
        && SSL_set_fd(client, sockets[1]) == 1) {
        outcome->connected = SSL_connect(client) == 1;
        outcome->verify_result = SSL_get_verify_result(client);
        uint8_t response[4];
        outcome->round_trip = outcome->connected
            && SSL_write(client, "ping", 4) == 4
            && SSL_read(client, response, sizeof(response)) == (int)sizeof(response)
            && memcmp(response, "pong", sizeof(response)) == 0;
    }
    if (client != NULL) {
        if (outcome->connected) {
            (void)SSL_shutdown(client);
        }
        SSL_free(client);
    }
    SSL_CTX_free(client_context);
    close(sockets[1]);
    pthread_join(server_thread, NULL);
    close(sockets[0]);
    outcome->round_trip = outcome->round_trip && fixture.result == 0;
    return 0;
}

static int expect_verified(const char *name, st_tls_server_context *context, X509 *trust_anchor)
{
    handshake_outcome outcome;
    if (verified_handshake(context, trust_anchor, PEM_HOST_NAME, &outcome) != 0
        || !outcome.connected
        || outcome.verify_result != X509_V_OK
        || !outcome.round_trip) {
        fprintf(stderr, "%s: verified PEM handshake failed (connected=%d verify=%ld round trip=%d)\n",
                name, outcome.connected, outcome.verify_result, outcome.round_trip);
        return 1;
    }
    return 0;
}

static int expect_rejected(const char *name,
                           st_tls_server_context *context,
                           X509 *trust_anchor,
                           const char *host_name,
                           long expected_verify_result)
{
    handshake_outcome outcome;
    if (verified_handshake(context, trust_anchor, host_name, &outcome) != 0
        || outcome.connected
        || outcome.verify_result != expected_verify_result) {
        fprintf(stderr, "%s: expected verify error %ld, got connected=%d verify=%ld (%s)\n",
                name, expected_verify_result, outcome.connected, outcome.verify_result,
                X509_verify_cert_error_string(outcome.verify_result));
        return 1;
    }
    return 0;
}

/* Builds an enabled context from config into *out; returns non-zero when that fails. */
static int expect_pem_context(const char *name,
                              const st_tls_config *config,
                              st_tls_server_context **out)
{
    char error[512] = "";
    *out = NULL;
    if (st_tls_server_context_create(config, out, error, sizeof(error)) != 0
        || !st_tls_server_context_enabled(*out)) {
        fprintf(stderr, "%s: PEM TLS context load failed: %s\n", name, error);
        st_tls_server_context_free(*out);
        *out = NULL;
        return 1;
    }
    return 0;
}

static int expect_pem_load_failure(const char *name, const st_tls_config *config, const char *expected_error)
{
    char error[512] = "";
    st_tls_server_context *context = NULL;
    int rc = st_tls_server_context_create(config, &context, error, sizeof(error));
    st_tls_server_context_free(context);
    if (rc == 0 || strstr(error, expected_error) == NULL) {
        fprintf(stderr, "%s: expected a load failure mentioning \"%s\", got rc=%d error=\"%s\"\n",
                name, expected_error, rc, error);
        return 1;
    }
    return 0;
}

static int test_pem_file_context(void)
{
    char dir[256];
    snprintf(dir, sizeof(dir), "/tmp/specus-c-tls-pem-%ld", (long)getpid());
    const char *names[] = {"leaf.pem", "key.pem", "chain.pem", "combined.pem", "encrypted-key.pem", "other-key.pem"};
    char paths[6][320];
    for (size_t i = 0; i < 6U; ++i) {
        snprintf(paths[i], sizeof(paths[i]), "%s-%s", dir, names[i]);
    }
    const char *leaf_path = paths[0];
    const char *key_path = paths[1];
    const char *chain_path = paths[2];
    const char *combined_path = paths[3];
    const char *encrypted_key_path = paths[4];
    const char *other_key_path = paths[5];

    EVP_PKEY *ca_key = generate_rsa_key();
    EVP_PKEY *other_ca_key = generate_rsa_key();
    EVP_PKEY *server_key = generate_rsa_key();
    EVP_PKEY *unrelated_key = generate_rsa_key();
    X509 *ca = ca_key == NULL ? NULL : issue_certificate("Specus C test CA", NULL, ca_key, NULL, NULL, 10L);
    X509 *other_ca = other_ca_key == NULL
        ? NULL : issue_certificate("Specus C other CA", NULL, other_ca_key, NULL, NULL, 11L);
    X509 *leaf = ca == NULL || server_key == NULL
        ? NULL : issue_certificate(PEM_HOST_NAME, PEM_HOST_NAME, server_key, ca, ca_key, 12L);
    int failed = ca == NULL || other_ca == NULL || leaf == NULL || unrelated_key == NULL
        || write_pem(leaf_path, NULL, NULL, leaf, NULL) != 0
        || write_pem(key_path, server_key, NULL, NULL, NULL) != 0
        || write_pem(chain_path, NULL, NULL, leaf, ca) != 0
        || write_pem(combined_path, server_key, NULL, leaf, ca) != 0
        || write_pem(encrypted_key_path, server_key, "pem-key-password", NULL, NULL) != 0
        || write_pem(other_key_path, unrelated_key, NULL, NULL, NULL) != 0;
    if (failed) {
        fprintf(stderr, "PEM TLS fixture creation failed\n");
    }

    st_tls_config config;
    st_tls_server_context *context = NULL;
    if (!failed) {
        /* SPECUS_TLS_CERTIFICATE + SPECUS_TLS_PRIVATE_KEY: verified chain and host name, and a
         * client that trusts another CA or expects another name is refused. */
        memset(&config, 0, sizeof(config));
        config.mode = ST_TLS_FILE;
        config.certificate_path = leaf_path;
        config.private_key_path = key_path;
        failed = expect_pem_context("certificate + key", &config, &context)
            || expect_verified("certificate + key", context, ca)
            || expect_rejected("wrong host name", context, ca, "wrong." PEM_HOST_NAME,
                               X509_V_ERR_HOSTNAME_MISMATCH)
            || expect_rejected("untrusted CA", context, other_ca, PEM_HOST_NAME,
                               X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);
        st_tls_server_context_free(context);
        context = NULL;
    }
    if (!failed) {
        /* A certificate file with the chain behind the leaf. */
        config.certificate_path = chain_path;
        failed = expect_pem_context("certificate chain + key", &config, &context)
            || expect_verified("certificate chain + key", context, ca);
        st_tls_server_context_free(context);
        context = NULL;
    }
    if (!failed) {
        /* One PEM as SPECUS_TLS_KEYSTORE that holds the key and the chain. */
        memset(&config, 0, sizeof(config));
        config.mode = ST_TLS_FILE;
        config.keystore_path = combined_path;
        failed = expect_pem_context("combined PEM keystore", &config, &context)
            || expect_verified("combined PEM keystore", context, ca);
        st_tls_server_context_free(context);
        context = NULL;
    }
    if (!failed) {
        /* An encrypted key opens with SPECUS_TLS_KEY_PASSWORD, or the keystore password. */
        memset(&config, 0, sizeof(config));
        config.mode = ST_TLS_FILE;
        config.certificate_path = leaf_path;
        config.private_key_path = encrypted_key_path;
        config.key_password = "pem-key-password";
        failed = expect_pem_context("encrypted key", &config, &context)
            || expect_verified("encrypted key", context, ca);
        st_tls_server_context_free(context);
        context = NULL;
        config.key_password = NULL;
        config.keystore_password = "pem-key-password";
        failed = failed || expect_pem_context("encrypted key, keystore password", &config, &context);
        st_tls_server_context_free(context);
        context = NULL;
    }
    if (!failed) {
        memset(&config, 0, sizeof(config));
        config.mode = ST_TLS_FILE;
        config.certificate_path = leaf_path;
        config.private_key_path = encrypted_key_path;
        config.key_password = "wrong-password";
        failed = expect_pem_load_failure("wrong key password", &config, "PEM certificate/private key");
        config.private_key_path = other_key_path;
        config.key_password = NULL;
        failed = failed
            || expect_pem_load_failure("key of another certificate", &config, "PEM certificate/private key");
        config.private_key_path = NULL;
        failed = failed || expect_pem_load_failure("certificate without a key", &config, "requires");
    }

    for (size_t i = 0; i < 6U; ++i) {
        unlink(paths[i]);
    }
    X509_free(leaf);
    X509_free(other_ca);
    X509_free(ca);
    EVP_PKEY_free(unrelated_key);
    EVP_PKEY_free(server_key);
    EVP_PKEY_free(other_ca_key);
    EVP_PKEY_free(ca_key);
    return failed ? 1 : 0;
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
    /* The server thread's close_notify can land after the client has closed its end of the pair. */
    (void)signal(SIGPIPE, SIG_IGN);
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
    return test_self_signed_handshake() != 0
        || test_pkcs12_file_context() != 0
        || test_pem_file_context() != 0 ? 1 : 0;
}
