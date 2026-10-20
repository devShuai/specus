#ifndef ST_JAVA_URI_H
#define ST_JAVA_URI_H

/*
 * java.net.URI(String) as the Java server's validators use it: the parse of RFC 2396 with the
 * JDK's deviations (RFC 2732 IPv6 literals, empty authority before a path), and on failure the
 * URISyntaxException message, "<reason>[ at index <i>]: <input>", whose index counts UTF-16 units.
 * Components are the raw UTF-8 substrings; a member is NULL where Java's getter returns null (a
 * registry-based authority has no host and no user information).
 */
typedef struct {
    char *error;         /* URISyntaxException.getMessage(), or NULL when it parses */
    char *scheme;        /* getScheme() */
    char *user_info;     /* getRawUserInfo() */
    char *host;          /* getHost() */
    char *raw_authority; /* getRawAuthority() */
    char *raw_path;      /* getRawPath(): NULL for an opaque URI */
    char *raw_query;     /* getRawQuery() */
    char *raw_fragment;  /* getRawFragment() */
} st_java_uri;

/* 0 when text (UTF-8) parses, -1 with uri->error set when it does not or memory runs out. */
int st_java_uri_parse(const char *text, st_java_uri *uri);
void st_java_uri_free(st_java_uri *uri);

#endif
