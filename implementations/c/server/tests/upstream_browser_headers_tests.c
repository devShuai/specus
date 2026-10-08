/*
 * Java UpstreamBrowserHeadersTests (its three cases first), plus the origin and Referer edges of
 * java.net.URI that the C parser has to reproduce. The relay of the rewritten headers to the
 * device is checked end to end by nat_stream_tests, admin_http_tests and http_share_tests.
 */
#define _POSIX_C_SOURCE 200809L

#include "upstream_browser_headers.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

static void expect_headers(const char *name,
                           const char *const *input,
                           size_t count,
                           const char *target,
                           const char *const *expected)
{
    char *headers[8];
    for (size_t i = 0; i < count; ++i) headers[i] = strdup(input[i]);
    int rc = st_upstream_browser_headers_rewrite(headers, count, target);
    int ok = rc == 0;
    for (size_t i = 0; i < count; ++i) {
        if (headers[i] == NULL || strcmp(headers[i], expected[i]) != 0) {
            fprintf(stderr, "%s: header %zu is \"%s\", expected \"%s\"\n", name, i,
                    headers[i] == NULL ? "(null)" : headers[i], expected[i]);
            ok = 0;
        }
        free(headers[i]);
    }
    if (!ok) ++failures;
}

static void expect_origin(const char *target, const char *expected)
{
    char origin[ST_UPSTREAM_ORIGIN_MAX];
    int rc = st_upstream_origin_of(target, origin, sizeof(origin));
    if (expected == NULL ? rc != -1 : (rc != 0 || strcmp(origin, expected) != 0)) {
        fprintf(stderr, "origin of \"%s\": rc %d \"%s\", expected %s\n", target == NULL ? "(null)" : target,
                rc, origin, expected == NULL ? "none" : expected);
        ++failures;
    }
}

static void expect_referer(const char *referer, const char *origin, const char *expected)
{
    char *rewritten = st_upstream_rewrite_referer(referer, origin);
    if (rewritten == NULL || strcmp(rewritten, expected) != 0) {
        fprintf(stderr, "Referer \"%s\" became \"%s\", expected \"%s\"\n", referer,
                rewritten == NULL ? "(null)" : rewritten, expected);
        ++failures;
    }
    free(rewritten);
}

int main(void)
{
    /* publicOriginIsRewrittenToLoopbackTarget */
    {
        const char *const input[] = {
            "Origin:https://specus.devshuai.com",
            "Referer:https://specus.devshuai.com/http/client/dsh/",
            "Sec-Fetch-Site:same-origin",
            "Content-Type:application/json"
        };
        const char *const expected[] = {
            "Origin:http://127.0.0.1:3210",
            "Referer:http://127.0.0.1:3210/http/client/dsh/",
            "Sec-Fetch-Site:same-origin",
            "Content-Type:application/json"
        };
        expect_headers("public origin to loopback target", input, 4U, "http://127.0.0.1:3210/app", expected);
    }
    /* crossSiteFetchMetadataBecomesSameOrigin */
    {
        const char *const input[] = {"Origin:https://evil.example", "Sec-Fetch-Site:cross-site"};
        const char *const expected[] = {"Origin:http://127.0.0.1:8080", "Sec-Fetch-Site:same-origin"};
        expect_headers("cross-site fetch metadata", input, 2U, "http://127.0.0.1:8080", expected);
    }
    /* missingTargetLeavesHeadersUnchanged, and every target without an origin */
    {
        const char *const input[] = {"Origin:https://specus.devshuai.com", "Sec-Fetch-Site:cross-site"};
        const char *const targets[] = {NULL, "", "   ", "ftp://files.example/", "not a url", "http:///path",
                                       "http://my_host:8080/", "http://host/a b"};
        for (size_t i = 0; i < sizeof(targets) / sizeof(targets[0]); ++i) {
            expect_headers(targets[i] == NULL ? "missing target" : targets[i], input, 2U, targets[i], input);
        }
    }
    /* Header names match in any case and keep their spelling; only cross-site fetch metadata moves. */
    {
        const char *const input[] = {
            "origin:null",
            "REFERER:https://specus.example/http/c/app/page?q=1#top",
            "sec-fetch-site:Cross-Site",
            "Sec-Fetch-Site:same-site",
            "Sec-Fetch-Site:none",
            "Origin-Agent-Cluster:?1",
            "no separator",
            ":leading separator"
        };
        const char *const expected[] = {
            "origin:https://app.internal:8443",
            "REFERER:https://app.internal:8443/http/c/app/page?q=1#top",
            "sec-fetch-site:same-origin",
            "Sec-Fetch-Site:same-site",
            "Sec-Fetch-Site:none",
            "Origin-Agent-Cluster:?1",
            "no separator",
            ":leading separator"
        };
        expect_headers("names, values and other headers", input, 8U, "wss://app.internal:8443/socket", expected);
    }

    expect_origin("http://127.0.0.1:3210/app", "http://127.0.0.1:3210");
    expect_origin("  https://Example.COM/base  ", "https://Example.COM");
    expect_origin("WS://example.com:81/socket", "http://example.com:81");
    expect_origin("wss://example.com/socket", "https://example.com");
    expect_origin("https://user:secret@example.com:8443/p", "https://example.com:8443");
    expect_origin("http://[::1]:3000/", "http://[::1]:3000");
    expect_origin("http://example.com:/x", "http://example.com");
    expect_origin("http://example.com:0/x", "http://example.com");
    expect_origin("http://example.com?x=1", "http://example.com");
    expect_origin("mailto:someone@example.com", NULL);
    expect_origin("http://example.com:80a/", NULL);
    expect_origin("http://[::1/", NULL);

    const char *origin = "http://127.0.0.1:3210";
    expect_referer("https://specus.example", origin, "http://127.0.0.1:3210");
    expect_referer("https://specus.example/p?q=1&r=%2F#frag", origin, "http://127.0.0.1:3210/p?q=1&r=%2F#frag");
    expect_referer("https://user:secret@specus.example/p", origin, "http://127.0.0.1:3210/p");
    expect_referer("  https://specus.example/trimmed  ", origin, "http://127.0.0.1:3210/trimmed");
    expect_referer("/relative/path", origin, "http://127.0.0.1:3210/");
    expect_referer("", origin, "http://127.0.0.1:3210/");
    expect_referer("about:blank", origin, "http://127.0.0.1:3210/");
    expect_referer("https://specus.example/bad%zzescape", origin, "http://127.0.0.1:3210/");
    expect_referer("https://specus.example/with space", origin, "http://127.0.0.1:3210/");
    expect_referer("https://bad_host.example/p", origin, "http://127.0.0.1:3210/");

    if (failures != 0) {
        fprintf(stderr, "%d upstream browser header check(s) failed\n", failures);
        return 1;
    }
    printf("upstream browser header tests passed\n");
    return 0;
}
