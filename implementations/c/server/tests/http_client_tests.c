#define _POSIX_C_SOURCE 200809L

#include "http_client.h"

#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct {
    int listener;
    const char *certificate_path;
    const char *private_key_path;
    int handshake_ok;
    char request[4096];
} https_fixture;

static int add_extension(X509 *certificate, int nid, const char *value)
{
    X509V3_CTX context;
    X509V3_set_ctx_nodb(&context);
    X509V3_set_ctx(&context, certificate, certificate, NULL, NULL, 0);
    X509_EXTENSION *extension = X509V3_EXT_conf_nid(NULL, &context, nid, (char *)value);
    if (extension == NULL) {
        return -1;
    }
    int result = X509_add_ext(certificate, extension, -1) == 1 ? 0 : -1;
    X509_EXTENSION_free(extension);
    return result;
}

static int write_https_fixture(const char *certificate_path, const char *private_key_path)
{
    EVP_PKEY_CTX *keygen = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *key = NULL;
    X509 *certificate = NULL;
    FILE *certificate_file = NULL;
    FILE *private_key_file = NULL;
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
        || ASN1_INTEGER_set(X509_get_serialNumber(certificate), 7L) != 1
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
        || add_extension(certificate, NID_basic_constraints, "critical,CA:TRUE") != 0
        || add_extension(certificate, NID_key_usage, "critical,digitalSignature,keyEncipherment,keyCertSign") != 0
        || add_extension(certificate, NID_subject_alt_name, "DNS:localhost") != 0
        || X509_sign(certificate, key, EVP_sha256()) <= 0) {
        goto cleanup;
    }
    certificate_file = fopen(certificate_path, "wb");
    private_key_file = fopen(private_key_path, "wb");
    if (certificate_file == NULL || private_key_file == NULL
        || PEM_write_X509(certificate_file, certificate) != 1
        || PEM_write_PrivateKey(private_key_file, key, NULL, NULL, 0, NULL, NULL) != 1) {
        goto cleanup;
    }
    result = 0;

cleanup:
    if (certificate_file != NULL) fclose(certificate_file);
    if (private_key_file != NULL) fclose(private_key_file);
    X509_free(certificate);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(keygen);
    return result;
}

static void *https_server_run(void *arg)
{
    https_fixture *fixture = (https_fixture *)arg;
    fixture->handshake_ok = 0;
    int client = accept(fixture->listener, NULL, NULL);
    if (client < 0) {
        return NULL;
    }
    SSL_CTX *context = SSL_CTX_new(TLS_server_method());
    SSL *ssl = NULL;
    if (context != NULL
        && SSL_CTX_use_certificate_file(context, fixture->certificate_path, SSL_FILETYPE_PEM) == 1
        && SSL_CTX_use_PrivateKey_file(context, fixture->private_key_path, SSL_FILETYPE_PEM) == 1
        && (ssl = SSL_new(context)) != NULL
        && SSL_set_fd(ssl, client) == 1
        && SSL_accept(ssl) == 1) {
        fixture->handshake_ok = 1;
        int got = SSL_read(ssl, fixture->request, (int)sizeof(fixture->request) - 1);
        if (got > 0) {
            fixture->request[got] = '\0';
        }
        const char body[] = "{\"access_token\":\"verified\"}";
        char response[512];
        int response_len = snprintf(response,
                                    sizeof(response),
                                    "HTTP/1.1 200 OK\r\n"
                                    "Content-Type: application/json\r\n"
                                    "Content-Length: %zu\r\n"
                                    "Connection: close\r\n\r\n%s",
                                    strlen(body),
                                    body);
        if (response_len > 0 && (size_t)response_len < sizeof(response)) {
            (void)SSL_write(ssl, response, response_len);
        }
        (void)SSL_shutdown(ssl);
    }
    SSL_free(ssl);
    SSL_CTX_free(context);
    close(client);
    return NULL;
}

static int start_https_server(https_fixture *fixture, pthread_t *thread, int *port_out)
{
    fixture->listener = socket(AF_INET, SOCK_STREAM, 0);
    if (fixture->listener < 0) return -1;
    int reuse = 1;
    (void)setsockopt(fixture->listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fixture->listener, (struct sockaddr *)&address, sizeof(address)) != 0
        || listen(fixture->listener, 1) != 0) {
        close(fixture->listener);
        return -1;
    }
    socklen_t address_len = sizeof(address);
    if (getsockname(fixture->listener, (struct sockaddr *)&address, &address_len) != 0) {
        close(fixture->listener);
        return -1;
    }
    *port_out = ntohs(address.sin_port);
    if (pthread_create(thread, NULL, https_server_run, fixture) != 0) {
        close(fixture->listener);
        return -1;
    }
    return 0;
}

static int run_request(https_fixture *fixture,
                       const char *host,
                       const char *ca_path,
                       int expected_success,
                       int expected_handshake)
{
    pthread_t thread;
    int port = 0;
    memset(fixture->request, 0, sizeof(fixture->request));
    if (start_https_server(fixture, &thread, &port) != 0) return 1;
    char endpoint[256];
    snprintf(endpoint, sizeof(endpoint), "https://%s:%d/token", host, port);
    st_http_client_options options = {
        .timeout_ms = 3000L,
        .max_response_bytes = 65536U,
        .ca_certificate_path = ca_path
    };
    long status = 0L;
    char *body = NULL;
    int success = st_http_post_form(endpoint, "dXNlcjpwYXNz", "code=abc", &options, &status, &body) == 0;
    pthread_join(thread, NULL);
    close(fixture->listener);
    int failed = success != expected_success || fixture->handshake_ok != expected_handshake;
    if (expected_success && (status != 200L || body == NULL
        || strstr(body, "verified") == NULL
        || strstr(fixture->request, "Authorization: Basic dXNlcjpwYXNz") == NULL
        || strstr(fixture->request, "code=abc") == NULL)) {
        failed = 1;
    }
    if (failed) {
        fprintf(stderr,
                "HTTPS request mismatch host=%s ca=%s success=%d/%d handshake=%d/%d status=%ld body=%s request=%s\n",
                host,
                ca_path == NULL ? "system" : "fixture",
                success,
                expected_success,
                fixture->handshake_ok,
                expected_handshake,
                status,
                body == NULL ? "(null)" : body,
                fixture->request);
    }
    free(body);
    return failed;
}

int main(void)
{
    (void)signal(SIGPIPE, SIG_IGN);
    char certificate_path[256];
    char private_key_path[256];
    snprintf(certificate_path, sizeof(certificate_path), "/tmp/specus-http-client-%ld.crt", (long)getpid());
    snprintf(private_key_path, sizeof(private_key_path), "/tmp/specus-http-client-%ld.key", (long)getpid());
    unlink(certificate_path);
    unlink(private_key_path);
    if (write_https_fixture(certificate_path, private_key_path) != 0) {
        fprintf(stderr, "HTTPS certificate fixture creation failed\n");
        return 1;
    }
    https_fixture fixture = {
        .certificate_path = certificate_path,
        .private_key_path = private_key_path
    };
    int failed = run_request(&fixture, "localhost", NULL, 0, 0) != 0
        || run_request(&fixture, "localhost", certificate_path, 1, 1) != 0
        || run_request(&fixture, "127.0.0.1", certificate_path, 0, 1) != 0;
    unlink(certificate_path);
    unlink(private_key_path);
    if (failed) {
        fprintf(stderr, "HTTPS verification, CA trust, or hostname verification test failed\n");
        return 1;
    }

    st_http_client_options options = {.timeout_ms = 100L, .max_response_bytes = 1024U};
    long status = 0L;
    char *body = NULL;
    if (st_http_post_form("ftp://localhost/token", NULL, "a=b", &options, &status, &body) == 0) {
        free(body);
        fprintf(stderr, "non-HTTP URL was accepted\n");
        return 1;
    }
    return 0;
}
