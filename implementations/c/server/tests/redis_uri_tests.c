#define _POSIX_C_SOURCE 200809L

#include "redis_uri.h"

#include <stdio.h>
#include <string.h>

/*
 * SPECUS_PUBLIC_TRANSFER_REDIS_URI as the Java server reads it: RedisURI.create (Lettuce 7.5) on
 * top of java.net.URI. Each case is the outcome Java has with the same text: what it connects to,
 * or that startup fails. The expected form is
 *   [tls(MODE) ]node db=N[ user=U][ pass=P][ client=C][ lib=NAME/VERSION]
 * where node is host:port, "socket PATH" or "sentinel[h:p,...] master=ID".
 * The expectations were checked against RedisURI.create of lettuce-core 7.5.2 itself; the only
 * differences are the two C refusals marked below and IPv6 hosts, which Lettuce keeps in brackets.
 */
typedef struct {
    const char *uri;
    const char *expected; /* NULL: Java fails startup, so C refuses */
} uri_case;

static const uri_case cases[] = {
    /* redis:// as before, plus what Lettuce accepts that the old C parser refused. */
    {"redis://127.0.0.1:6379/0", "127.0.0.1:6379 db=0"},
    {"redis://localhost", "localhost:6379 db=0"},
    {"redis://redis.internal:6380/", "redis.internal:6380 db=0"},
    {"redis://h:0", "h:6379 db=0"},          /* getPort() > 0 or the default */
    {"redis://h:", "h:6379 db=0"},           /* java.net.URI: an empty port is no port */
    {"redis://[::1]:6390/3", "::1:6390 db=3"},
    {"redis://h:70000", NULL},               /* Port out of range */
    {"redis://user:p%40ss@h:6380/2", "h:6380 db=2 user=user pass=p@ss"},
    {"redis://:secret@h", "h:6379 db=0 pass=secret"},
    {"redis://secret@h", "h:6379 db=0 pass=secret"},
    {"redis://user:@h", "h:6379 db=0"},      /* an empty password means no AUTH, user name or not */
    {"redis://user:a:b@h", "h:6379 db=0 user=user pass=a:b"},
    /*
     * Not a server authority for java.net.URI: Lettuce takes what follows the last '@' as host, so
     * these connect only without a port. C logs such hosts masked: they may hold password text.
     */
    {"redis://a@b@h:6380", "h:6380:6379 db=0 pass=a@b unparsed hidden"},
    {"redis://redis_1/0", "redis_1:6379 db=0 unparsed hidden"},
    {"redis://redis_1:6380/0", "redis_1:6380:6379 db=0 unparsed hidden"},
    {"redis://::1/0", "::1:6379 db=0 unparsed hidden"},
    /* An unescaped '#' or '?' in the password ends the authority there. */
    {"redis://:abc#def@host:6379/0", ":abc:6379 db=0 unparsed hidden"},
    {"redis://pass#word@h", "pass:6379 db=0 hidden"},
    {"redis://:pa?ss@h:6379", ":pa:6379 db=0 unparsed hidden"},
    /* Escapes: UTF-8 with U+FFFD for ill-formed bytes, as Java's decoder replaces them. */
    {"redis://:%C3%A9t%C3%A9@h", "h:6379 db=0 pass=\xC3\xA9t\xC3\xA9"},
    {"redis://:%FF@h", "h:6379 db=0 pass=\xEF\xBF\xBD"},
    {"redis://:a%FFb@h", "h:6379 db=0 pass=a\xEF\xBF\xBD" "b"},
    {"redis://:%E2%82@h", "h:6379 db=0 pass=\xEF\xBF\xBD"},
    {"redis://:%E2%28x@h", "h:6379 db=0 pass=\xEF\xBF\xBD(x"},
    {"redis://:%C0%80@h", "h:6379 db=0 pass=\xEF\xBF\xBD\xEF\xBF\xBD"},
    {"redis://:%ED%A0%80@h", "h:6379 db=0 pass=\xEF\xBF\xBD"},  /* an encoded surrogate: one U+FFFD */
    {"redis://:%ED%A0A@h", "h:6379 db=0 pass=\xEF\xBF\xBD" "A"},
    {"redis://:%F0%9F%98%80@h", "h:6379 db=0 pass=\xF0\x9F\x98\x80"},
    {"redis://:%F0%9F%98@h", "h:6379 db=0 pass=\xEF\xBF\xBD"},
    /* getQuery and getFragment decode escapes inside [...] too; the path keeps them. */
    {"redis://h?clientName=a[&database=%31", "h:6379 db=1 client=a["},
    {"redis-sentinel://s1#a[%41]", "sentinel[s1:26379] master=a[A] db=0"},
    /* The database: the path (Integer.parseInt), then database= or db= in the query. */
    {"redis://h/16", "h:6379 db=16"},
    {"redis://h/+1", "h:6379 db=1"},
    {"redis://h/-0", "h:6379 db=0"},
    {"redis://h/-1", NULL},
    {"redis://h/x", NULL},
    {"redis://h/1/", NULL},
    {"redis://h/2147483648", NULL},
    {"redis://h/1?database=3", "h:6379 db=3"},
    {"redis://h?Database=5", "h:6379 db=5"},
    {"redis://h?db=4", "h:6379 db=4"},
    {"redis://h?DB=4", "h:6379 db=0"},       /* db= is matched case-sensitively */
    {"redis://h?database=7abc", "h:6379 db=7"},
    {"redis://h?database=abc", "h:6379 db=0"},
    {"redis://h?database=99999999999", NULL},
    {"redis://h?database=00000000000000000001", "h:6379 db=1"},
    /* Other parameters: & or ; separate them, unknown ones are ignored. */
    {"redis://h/0?timeout=5s&clientName=specus-a;foo=bar", "h:6379 db=0 client=specus-a"},
    {"redis://h?clientname=", "h:6379 db=0"},
    {"redis://h?libraryName=specus&libraryVersion=1.2", "h:6379 db=0 lib=specus/1.2"},
    {"redis://h?libraryName=a%20b", NULL},   /* Library name must not contain spaces */
    {"redis://h?timeout=-1", "h:6379 db=0"},
    {"redis://h?timeout=10us", "h:6379 db=0"},
    {"redis://h?timeout=abc", "h:6379 db=0"},
    {"redis://h?timeout=99999999999999999999", NULL},  /* Long.parseLong */
    {"redis://h?timeout=999999999999999d", NULL},      /* Duration.ofDays overflows */
    {"redis://h?timeout=9223372036854775807us", NULL}, /* a negative Duration */
    {"redis://h/0#ignored", "h:6379 db=0"},
    /* TLS: rediss:// or redis+ssl://, verifyPeer NONE/CA/FULL in any case, FULL by default. */
    {"rediss://h:6390", "tls(FULL) h:6390 db=0"},
    {"redis+ssl://h:6390", "tls(FULL) h:6390 db=0"},
    {"rediss://h?verifyPeer=none", "tls(NONE) h:6379 db=0"},
    {"rediss://h?VERIFYPEER=Ca", "tls(CA) h:6379 db=0"},
    {"rediss://h?verifyPeer=", "tls(FULL) h:6379 db=0"},
    {"rediss://h?verifyPeer=yes", NULL},
    {"redis://h?verifyPeer=NONE", "h:6379 db=0"},
    /* C only: Lettuce accepts STARTTLS, but no Redis server negotiates it, so Java cannot connect. */
    {"redis+tls://h", NULL},
    /* Sentinel: the fragment or sentinelMasterId names the master; it is required. */
    {"redis-sentinel://s1:26380,s2,10.0.0.3:26381/1#mymaster",
     "sentinel[s1:26380,s2:26379,10.0.0.3:26381] master=mymaster db=1"},
    /* A list is no server authority; java.net.URI then refuses brackets, so IPv6 goes unbracketed. */
    {"redis-sentinel://s1,[::1]:26381#m", NULL},
    {"redis-sentinel://s1,::1#m", "sentinel[s1:26379,::1:26379] master=m db=0"},
    {"redis-sentinel://s1?sentinelMasterId=mm", "sentinel[s1:26379] master=mm db=0"},
    {"redis-sentinel://s1#a?b", "sentinel[s1:26379] master=a?b db=0"},
    {"redis-sentinel://s1?sentinelMasterId=q#f", "sentinel[s1:26379] master=q db=0"},
    {"redis-sentinel://[::1]#m", "sentinel[::1:26379] master=m db=0"},
    {"redis-sentinel://pw@s1:26380#m", "sentinel[s1:26380] master=m db=0 pass=pw"},
    {"redis-sentinel://user:pw@s1,s2#m", "sentinel[s1:26379,s2:26379] master=m db=0 user=user pass=pw"},
    {"redis-sentinel://s1,s2,#m", "sentinel[s1:26379,s2:26379] master=m db=0"},
    {"redis-sentinel://s1:0,s2#m", "sentinel[s1:0,s2:26379] master=m db=0"},
    {"rediss-sentinel://s1:26380?verifyPeer=CA#m", "tls(CA) sentinel[s1:26380] master=m db=0"},
    {"redis-sentinel://s1", NULL},
    {"redis-sentinel://s1#", NULL},
    {"redis-sentinel://s1,,s2#m", NULL},
    {"redis-sentinel://s1:+5,s2#m", NULL},
    {"redis-sentinel://s1:70000,s2#m", NULL},
    {"redis-sentinel://s1:x,s2#m", NULL},
    /* Unix domain sockets: the path is the socket, the database comes from the query. */
    {"redis-socket:///tmp/redis.sock?database=2", "socket /tmp/redis.sock db=2"},
    {"redis+socket:///tmp/redis.sock", "socket /tmp/redis.sock db=0"},
    {"redis-socket://", NULL},
    /* What java.net.URI or Lettuce refuses outright. */
    {"", NULL},
    {"REDIS://h", NULL},                     /* schemes are case-sensitive */
    {"http://h", NULL},
    {"redis:h", NULL},                       /* opaque: no host */
    {"redis://", NULL},
    {"redis:///0", NULL},
    {"redis://h h", NULL},
    {"redis://h/%zz", NULL},
    {"redis://p%00@h", NULL},                /* C only: C strings cannot carry an escaped NUL */
    {"127.0.0.1:6379", NULL},
};

static const char *verify_name(st_redis_verify_mode mode)
{
    return mode == ST_REDIS_VERIFY_NONE ? "NONE" : mode == ST_REDIS_VERIFY_CA ? "CA" : "FULL";
}

static void describe(const st_redis_uri *uri, char *out, size_t out_len)
{
    size_t used = 0U;
#define APPEND(...) \
    do { \
        int written = snprintf(out + used, out_len - used, __VA_ARGS__); \
        if (written > 0) used += (size_t)written < out_len - used ? (size_t)written : out_len - used - 1U; \
    } while (0)
    out[0] = '\0';
    if (uri->tls) APPEND("tls(%s) ", verify_name(uri->verify));
    if (uri->sentinel) {
        APPEND("sentinel[");
        for (size_t i = 0U; i < uri->sentinel_count; ++i)
            APPEND("%s%s:%d", i == 0U ? "" : ",", uri->sentinels[i].host, uri->sentinels[i].port);
        APPEND("] master=%s", uri->master_id);
    } else if (uri->socket_path[0] != '\0') {
        APPEND("socket %s", uri->socket_path);
    } else {
        APPEND("%s:%d", uri->server.host, uri->server.port);
    }
    APPEND(" db=%d", uri->database);
    if (uri->username[0] != '\0') APPEND(" user=%s", uri->username);
    if (uri->password[0] != '\0') APPEND(" pass=%s", uri->password);
    if (uri->client_name[0] != '\0') APPEND(" client=%s", uri->client_name);
    if (uri->library_name[0] != '\0' || uri->library_version[0] != '\0')
        APPEND(" lib=%s/%s", uri->library_name, uri->library_version);
    /* C only, not compared with Java: how the host is treated in the logs. */
    if (uri->host_unparsed) APPEND(" unparsed");
    if (uri->host_hidden) APPEND(" hidden");
#undef APPEND
}

/*
 * --print: one "URI<TAB>description" line per case, the flags left out, non-ASCII written as
 * <U+XXXX> and refusals as REFUSED, the form a small Java program around RedisURI.create prints,
 * so the two outputs can be compared line by line when Lettuce changes.
 */
static void print_cases(void)
{
    for (size_t i = 0U; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        st_redis_uri uri;
        char error[256];
        char actual[1024];
        if (st_redis_uri_parse(cases[i].uri, &uri, error, sizeof(error)) != 0) {
            printf("%s\tREFUSED\n", cases[i].uri);
            continue;
        }
        uri.host_unparsed = 0;
        uri.host_hidden = 0;
        describe(&uri, actual, sizeof(actual));
        printf("%s\t", cases[i].uri);
        for (const unsigned char *c = (const unsigned char *)actual; *c != '\0';) {
            unsigned int point = *c;
            int extra = point >= 0xF0U ? 3 : point >= 0xE0U ? 2 : point >= 0xC0U ? 1 : 0;
            if (extra == 0) {
                putchar((int)*c++);
                continue;
            }
            point &= 0x3FU >> extra;
            ++c;
            for (int k = 0; k < extra && *c != '\0'; ++k) point = (point << 6) | (*c++ & 0x3FU);
            if (point >= 0x10000U)
                printf("<U+%04X><U+%04X>", 0xD800U + ((point - 0x10000U) >> 10), 0xDC00U + ((point - 0x10000U) & 0x3FFU));
            else
                printf("<U+%04X>", point);
        }
        putchar('\n');
    }
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "--print") == 0) {
        print_cases();
        return 0;
    }
    int failed = 0;
    for (size_t i = 0U; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        st_redis_uri uri;
        char error[256];
        char actual[1024];
        int rc = st_redis_uri_parse(cases[i].uri, &uri, error, sizeof(error));
        if (cases[i].expected == NULL) {
            if (rc == 0) {
                describe(&uri, actual, sizeof(actual));
                fprintf(stderr, "accepted %s as %s; Java refuses it\n", cases[i].uri, actual);
                failed = 1;
            } else if (error[0] == '\0') {
                fprintf(stderr, "refused %s without a reason\n", cases[i].uri);
                failed = 1;
            }
            continue;
        }
        if (rc != 0) {
            fprintf(stderr, "refused %s: %s\n", cases[i].uri, error);
            failed = 1;
            continue;
        }
        describe(&uri, actual, sizeof(actual));
        if (strcmp(actual, cases[i].expected) != 0) {
            fprintf(stderr, "%s\n  parsed   %s\n  expected %s\n", cases[i].uri, actual, cases[i].expected);
            failed = 1;
        }
    }
    /* A refusal explains itself without repeating the URI, which may carry the password. */
    static const char *const secret_uris[] = {
        "redis://user:hunter2secret@h h", "redis://user:hunter2secret@h/x", "redis+tls://user:hunter2secret@h"
    };
    for (size_t i = 0U; i < sizeof(secret_uris) / sizeof(secret_uris[0]); ++i) {
        st_redis_uri uri;
        char error[256];
        if (st_redis_uri_parse(secret_uris[i], &uri, error, sizeof(error)) == 0 || strstr(error, "hunter2") != NULL) {
            fprintf(stderr, "the refusal of URI %zu leaked the password or did not happen: %s\n", i, error);
            failed = 1;
        }
    }
    if (failed) return 1;
    printf("redis uri tests passed (%zu cases)\n", sizeof(cases) / sizeof(cases[0]));
    return 0;
}
