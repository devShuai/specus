#define _POSIX_C_SOURCE 200809L

#include "tls_transport.h"

#include "security_baseline.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

struct st_tls_server_context {
    SSL_CTX *ssl_ctx;
    st_tls_mode mode;
};

struct st_tls_connection {
    SSL *ssl;
    pthread_mutex_t io_lock;
    pthread_mutex_t writer_lock;
    pthread_cond_t changed;
    pthread_t worker;
    int worker_started;
    int fd;
    int wake[2];
    int failed;
    int stopping;
    int read_eof;
    uint8_t received[32768];
    size_t received_len;
    const uint8_t *write_buffer;
    size_t write_len;
    size_t write_offset;
    int writing;
    int64_t write_deadline;
};

static void *tls_io_run(void *arg);
static void wake_tls(st_tls_connection *connection);

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
    connection->fd = fd;
    connection->wake[0] = connection->wake[1] = -1;
    connection->failed = 1;
    if (pthread_mutex_init(&connection->io_lock, NULL) != 0) {
        free(connection);
        return set_error(error, error_len, "failed to create TLS I/O lock");
    }
    if (pthread_mutex_init(&connection->writer_lock, NULL) != 0) {
        pthread_mutex_destroy(&connection->io_lock);
        free(connection);
        return set_error(error, error_len, "failed to create TLS writer lock");
    }
    pthread_condattr_t attr;
    int attr_ok = pthread_condattr_init(&attr) == 0;
    int cond_ok = attr_ok && pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) == 0
        && pthread_cond_init(&connection->changed, &attr) == 0;
    if (attr_ok) pthread_condattr_destroy(&attr);
    if (!cond_ok) {
        pthread_mutex_destroy(&connection->writer_lock);
        pthread_mutex_destroy(&connection->io_lock);
        free(connection);
        return set_error(error, error_len, "failed to create TLS condition variable");
    }
    if (pipe(connection->wake) != 0) {
        st_tls_connection_free(connection);
        return set_error(error, error_len, "failed to create TLS reader wakeup");
    }
    for (int i = 0; i < 2; ++i) {
        if (fcntl(connection->wake[i], F_SETFL, O_NONBLOCK) < 0
            || fcntl(connection->wake[i], F_SETFD, FD_CLOEXEC) < 0) {
            st_tls_connection_free(connection);
            return set_error(error, error_len, "failed to configure TLS reader wakeup");
        }
    }
    ERR_clear_error();
    connection->ssl = SSL_new(context->ssl_ctx);
    if (connection->ssl == NULL
        || SSL_set_fd(connection->ssl, fd) != 1
        || SSL_accept(connection->ssl) != 1) {
        openssl_error(error, error_len, "TLS handshake failed");
        st_tls_connection_free(connection);
        return -1;
    }
    /* Handshake first, then transfer exclusive SSL ownership to the I/O worker. Memory BIOs
     * separate TLS state transitions from socket backpressure: a pending ciphertext send must
     * not block inbound TLS records (nor violate SSL_write WANT_WRITE retry ownership). */
    BIO *input = BIO_new(BIO_s_mem());
    BIO *output = BIO_new(BIO_s_mem());
    if (input == NULL || output == NULL) {
        BIO_free(input);
        BIO_free(output);
        st_tls_connection_free(connection);
        return set_error(error, error_len, "failed to create TLS transport buffers");
    }
    BIO_set_mem_eof_return(input, -1);
    SSL_set_bio(connection->ssl, input, output);
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        st_tls_connection_free(connection);
        return set_error(error, error_len, "failed to configure nonblocking TLS socket");
    }
    connection->failed = 0;
    if (pthread_create(&connection->worker, NULL, tls_io_run, connection) != 0) {
        connection->failed = 1;
        st_tls_connection_free(connection);
        return set_error(error, error_len, "failed to start TLS I/O worker");
    }
    connection->worker_started = 1;
    *out = connection;
    return 0;
}

static int64_t monotonic_millis(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int64_t socket_deadline(int fd, int option)
{
    struct timeval timeout = {0};
    socklen_t len = sizeof(timeout);
    if (getsockopt(fd, SOL_SOCKET, option, &timeout, &len) != 0) {
        return monotonic_millis();
    }
    if (timeout.tv_sec == 0 && timeout.tv_usec == 0) {
        return -1;
    }
    return monotonic_millis() + (int64_t)timeout.tv_sec * 1000 + (timeout.tv_usec + 999) / 1000;
}

static void wake_tls(st_tls_connection *connection)
{
    const uint8_t byte = 1;
    ssize_t rc;
    do { rc = write(connection->wake[1], &byte, 1); } while (rc < 0 && errno == EINTR);
    /* EAGAIN means the worker already has a queued wakeup. */
}

static void fail_tls_locked(st_tls_connection *connection)
{
    connection->failed = 1;
    shutdown(connection->fd, SHUT_RDWR);
    pthread_cond_broadcast(&connection->changed);
}

/* Only the I/O worker touches SSL/BIO after accept. The mutex protects API queues, not a
 * blocking SSL call. Ciphertext output is bounded to a few records even for very large writes. */
static void *tls_io_run(void *arg)
{
    st_tls_connection *connection = arg;
    BIO *input = SSL_get_rbio(connection->ssl), *output = SSL_get_wbio(connection->ssl);
    uint8_t encrypted[32768], outgoing[32768];
    size_t outgoing_len = 0, outgoing_offset = 0;
    int transport_eof = 0;
    for (;;) {
        pthread_mutex_lock(&connection->io_lock);
        uint8_t wake_bytes[128];
        while (read(connection->wake[0], wake_bytes, sizeof(wake_bytes)) > 0) {}
        if (connection->failed || connection->stopping) {
            /* Best-effort nonblocking close_notify. Never perform TLS I/O after a fatal error. */
            if (!connection->failed) {
                ERR_clear_error();
                SSL_shutdown(connection->ssl);
                int n = BIO_read(output, encrypted, sizeof(encrypted));
                if (n > 0) (void)send(connection->fd, encrypted, (size_t)n, 0);
            }
            pthread_mutex_unlock(&connection->io_lock);
            break;
        }
        if (connection->writing && connection->write_deadline >= 0
            && monotonic_millis() >= connection->write_deadline) {
            fail_tls_locked(connection);
            pthread_mutex_unlock(&connection->io_lock);
            continue;
        }
        int progress = 0;
        if (outgoing_offset == outgoing_len) {
            int n = BIO_read(output, outgoing, sizeof(outgoing));
            outgoing_offset = 0;
            outgoing_len = n > 0 ? (size_t)n : 0;
        }
        if (outgoing_offset < outgoing_len) {
            ssize_t n = send(connection->fd, outgoing + outgoing_offset,
                             outgoing_len - outgoing_offset, 0);
            if (n > 0) {
                outgoing_offset += (size_t)n;
                progress = 1;
            } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                fail_tls_locked(connection);
            }
        }
        int can_read = !connection->read_eof && !transport_eof
            && connection->received_len < sizeof(connection->received)
            && BIO_ctrl_pending(output) < sizeof(outgoing);
        if (!connection->failed && can_read && BIO_ctrl_pending(input) < sizeof(encrypted)) {
            ssize_t n = recv(connection->fd, encrypted, sizeof(encrypted), 0);
            if (n > 0) {
                if (BIO_write(input, encrypted, (int)n) != n) fail_tls_locked(connection);
                progress = 1;
            } else if (n == 0) {
                transport_eof = 1;
                BIO_set_mem_eof_return(input, 0);
                progress = 1;
            } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                fail_tls_locked(connection);
            }
        }
        if (!connection->failed && !connection->read_eof
            && connection->received_len < sizeof(connection->received)
            && BIO_ctrl_pending(output) < sizeof(outgoing)) {
            size_t n = 0;
            ERR_clear_error();
            int rc = SSL_read_ex(connection->ssl, connection->received + connection->received_len,
                                 sizeof(connection->received) - connection->received_len, &n);
            int ssl_error = rc == 1 ? SSL_ERROR_NONE : SSL_get_error(connection->ssl, rc);
            if (rc == 1) {
                connection->received_len += n;
                progress = 1;
                pthread_cond_broadcast(&connection->changed);
            } else if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                connection->read_eof = 1;
                pthread_cond_broadcast(&connection->changed);
            } else if (ssl_error != SSL_ERROR_WANT_READ) {
                fail_tls_locked(connection);
            }
        }
        if (!connection->failed && connection->writing && outgoing_offset == outgoing_len
            && BIO_ctrl_pending(output) == 0) {
            if (connection->write_offset == connection->write_len) {
                connection->writing = 0;
                pthread_cond_broadcast(&connection->changed);
            } else {
                size_t n = 0, chunk = connection->write_len - connection->write_offset;
                if (chunk > 16384) chunk = 16384;
                ERR_clear_error();
                int rc = SSL_write_ex(connection->ssl, connection->write_buffer + connection->write_offset,
                                      chunk, &n);
                int ssl_error = rc == 1 ? SSL_ERROR_NONE : SSL_get_error(connection->ssl, rc);
                if (rc == 1) {
                    connection->write_offset += n;
                    progress = 1;
                } else if (ssl_error != SSL_ERROR_WANT_READ) {
                    /* Memory BIO writes never WANT_WRITE. WANT_READ may be satisfied on the
                     * next iteration; offset/chunk stay unchanged for the SSL_write retry. */
                    fail_tls_locked(connection);
                }
            }
        }
        struct pollfd fds[2] = {{.fd = connection->fd}, {.fd = connection->wake[0], .events = POLLIN}};
        if (can_read && !transport_eof) fds[0].events |= POLLIN;
        if (outgoing_offset < outgoing_len || BIO_ctrl_pending(output) > 0) fds[0].events |= POLLOUT;
        /* A full application queue must wait on its consumer, not spin on socket POLLHUP. */
        if (fds[0].events == 0) fds[0].fd = -1;
        int timed = connection->writing && connection->write_deadline >= 0;
        int64_t remaining = timed ? connection->write_deadline - monotonic_millis() : -1;
        int timeout = !timed ? -1 : remaining > INT_MAX ? INT_MAX : remaining <= 0 ? 0 : (int)remaining;
        int failed = connection->failed;
        pthread_mutex_unlock(&connection->io_lock);
        if (!progress && !failed && poll(fds, 2, timeout) < 0 && errno != EINTR) {
            pthread_mutex_lock(&connection->io_lock);
            fail_tls_locked(connection);
            pthread_mutex_unlock(&connection->io_lock);
        }
    }
    return NULL;
}

ssize_t st_tls_connection_read(st_tls_connection *connection, uint8_t *buffer, size_t len)
{
    if (connection == NULL || buffer == NULL || len == 0U) return -1;
    int64_t deadline = socket_deadline(connection->fd, SO_RCVTIMEO);
    struct timespec until = {.tv_sec = deadline / 1000, .tv_nsec = (deadline % 1000) * 1000000};
    ssize_t result = -1;
    pthread_mutex_lock(&connection->io_lock);
    while (!connection->received_len && !connection->failed && !connection->read_eof) {
        int rc = deadline < 0 ? pthread_cond_wait(&connection->changed, &connection->io_lock)
            : pthread_cond_timedwait(&connection->changed, &connection->io_lock, &until);
        if (rc == ETIMEDOUT) {
            result = -2;
            break;
        }
        if (rc != 0) break;
    }
    if (connection->received_len > 0) {
        size_t n = len < connection->received_len ? len : connection->received_len;
        memcpy(buffer, connection->received, n);
        connection->received_len -= n;
        memmove(connection->received, connection->received + n, connection->received_len);
        result = (ssize_t)n;
        wake_tls(connection);
    } else if (connection->failed) {
        result = -1;
    } else if (connection->read_eof) {
        result = 0;
    }
    pthread_mutex_unlock(&connection->io_lock);
    return result;
}

int st_tls_connection_write_all(st_tls_connection *connection, const uint8_t *buffer, size_t len)
{
    if (connection == NULL || (buffer == NULL && len != 0U)) return -1;
    pthread_mutex_lock(&connection->writer_lock);
    pthread_mutex_lock(&connection->io_lock);
    if (!connection->failed && len > 0) {
        connection->write_buffer = buffer;
        connection->write_len = len;
        connection->write_offset = 0;
        connection->write_deadline = socket_deadline(connection->fd, SO_SNDTIMEO);
        connection->writing = 1;
        wake_tls(connection);
        while (connection->writing && !connection->failed) {
            if (pthread_cond_wait(&connection->changed, &connection->io_lock) != 0) {
                fail_tls_locked(connection);
            }
        }
    }
    int result = connection->failed ? -1 : 0;
    connection->write_buffer = NULL;
    pthread_mutex_unlock(&connection->io_lock);
    pthread_mutex_unlock(&connection->writer_lock);
    return result;
}

void st_tls_connection_free(st_tls_connection *connection)
{
    if (connection != NULL) {
        if (connection->worker_started) {
            pthread_mutex_lock(&connection->io_lock);
            connection->stopping = 1;
            wake_tls(connection);
            pthread_mutex_unlock(&connection->io_lock);
            pthread_join(connection->worker, NULL);
        }
        if (connection->ssl != NULL) {
            SSL_free(connection->ssl);
        }
        pthread_cond_destroy(&connection->changed);
        pthread_mutex_destroy(&connection->writer_lock);
        for (int i = 0; i < 2; ++i) {
            if (connection->wake[i] >= 0) {
                close(connection->wake[i]);
            }
        }
        pthread_mutex_destroy(&connection->io_lock);
        free(connection);
    }
}
