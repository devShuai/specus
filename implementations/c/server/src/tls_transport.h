#ifndef SPECUS_TLS_TRANSPORT_H
#define SPECUS_TLS_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef enum {
    ST_TLS_DISABLED = 0,
    ST_TLS_FILE = 1,
    ST_TLS_SELF_SIGNED = 2
} st_tls_mode;

typedef struct {
    st_tls_mode mode;
    const char *keystore_path;
    const char *keystore_password;
    const char *key_password;
    const char *certificate_path;
    const char *private_key_path;
    int require_encryption;
    int terminated_upstream;
} st_tls_config;

typedef struct st_tls_server_context st_tls_server_context;
typedef struct st_tls_connection st_tls_connection;

void st_tls_config_from_env(st_tls_config *config);
const char *st_tls_mode_name(st_tls_mode mode);

/* Production is inferred from SPECUS_ENV using the shared fail-safe deployment parser. */
int st_tls_validate_deployment(const st_tls_config *config,
                               const char *environment,
                               const char *bind_address,
                               char *error,
                               size_t error_len);

int st_tls_server_context_create(const st_tls_config *config,
                                 st_tls_server_context **out,
                                 char *error,
                                 size_t error_len);
void st_tls_server_context_free(st_tls_server_context *context);
int st_tls_server_context_enabled(const st_tls_server_context *context);

int st_tls_connection_accept(st_tls_server_context *context,
                             int fd,
                             st_tls_connection **out,
                             char *error,
                             size_t error_len);

/* Read result: positive bytes, 0 clean close, -2 socket timeout, -1 other failure. */
ssize_t st_tls_connection_read(st_tls_connection *connection, uint8_t *buffer, size_t len);
int st_tls_connection_write_all(st_tls_connection *connection, const uint8_t *buffer, size_t len);
void st_tls_connection_free(st_tls_connection *connection);

#endif
