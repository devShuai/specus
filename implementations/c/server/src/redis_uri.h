#ifndef SPECUS_REDIS_URI_H
#define SPECUS_REDIS_URI_H

#include <stddef.h>

#define ST_REDIS_URI_HOST_BYTES 256U
#define ST_REDIS_URI_MAX_SENTINELS 16U

/* Lettuce SslVerifyMode: NONE trusts any certificate, CA checks the chain, FULL also the host name. */
typedef enum {
    ST_REDIS_VERIFY_NONE = 0,
    ST_REDIS_VERIFY_CA = 1,
    ST_REDIS_VERIFY_FULL = 2
} st_redis_verify_mode;

typedef struct {
    char host[ST_REDIS_URI_HOST_BYTES]; /* the brackets of an IPv6 literal removed */
    int port;
} st_redis_endpoint;

/*
 * What Lettuce's RedisURI.create(uri) keeps of a URI that the Java server can use:
 *   redis://, rediss:// and redis+ssl://   one Redis node (TLS for the last two)
 *   redis-sentinel:// and rediss-sentinel://  the master named by #id or sentinelMasterId, found
 *                                           through the listed Sentinels (TLS to all of them)
 *   redis-socket:// and redis+socket://     a Unix domain socket path
 * The user information authenticates the data nodes only (never a Sentinel), the path or the
 * database/db parameter selects the database, clientName names the connections, verifyPeer picks
 * NONE/CA/FULL (FULL by default). timeout is validated as Lettuce parses it and then ignored: Java
 * replaces it with SPECUS_PUBLIC_TRANSFER_REDIS_COMMAND_TIMEOUT_MS.
 */
typedef struct {
    int tls;
    st_redis_verify_mode verify;
    int sentinel;
    char socket_path[108];
    st_redis_endpoint server;
    st_redis_endpoint sentinels[ST_REDIS_URI_MAX_SENTINELS];
    size_t sentinel_count;
    char master_id[256];
    char username[256];
    char password[512]; /* empty: no AUTH, as for Lettuce (a user name alone is ignored) */
    int database;
    char client_name[256];
    char library_name[128];
    char library_version[128];
} st_redis_uri;

/*
 * Parses text (already trimmed, as Java trims it) the way java.net.URI and Lettuce's
 * RedisURI.create do. 0 on success; -1 when Java would refuse to start with it, or C cannot
 * represent it, with a reason in error that never repeats the URI (it may hold a password).
 * redis+tls:// (STARTTLS, which Redis servers do not negotiate) is refused.
 */
int st_redis_uri_parse(const char *text, st_redis_uri *uri, char *error, size_t error_len);

#endif
