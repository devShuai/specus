#ifndef SPECUS_UPSTREAM_BROWSER_HEADERS_H
#define SPECUS_UPSTREAM_BROWSER_HEADERS_H

#include <stddef.h>

/* "https://" + a bracketed IPv6 host + ":65535" fits with room to spare. */
#define ST_UPSTREAM_ORIGIN_MAX 320U

/*
 * Java UpstreamBrowserHeaders.originOf: the scheme://host[:port] origin of an http, https, ws or
 * wss route target (ws becomes http, wss https; the port only when the target names one).
 * Returns 0 with the origin in out, or -1 when the target has no usable origin.
 */
int st_upstream_origin_of(const char *target_base_url, char *out, size_t out_len);

/*
 * Java UpstreamBrowserHeaders.rewriteReferer: the browser's Referer with its scheme and authority
 * replaced by origin (path, query and fragment kept as they came), or origin + "/" when the
 * Referer is not an absolute URL. Returns a malloc'd string, NULL only when allocation fails.
 */
char *st_upstream_rewrite_referer(const char *referer, const char *origin);

/*
 * Java UpstreamBrowserHeaders.rewrite, applied in place to "Name:value" header lines before they
 * are relayed to the device: Origin becomes the route target's origin, Referer is moved onto it,
 * and Sec-Fetch-Site: cross-site becomes same-origin, so the target's own CSRF and Host fences do
 * not see the public ingress as another site. Every other line, and every line when the target
 * has no origin, stays as it is. Returns 0, or -1 when an allocation failed (the array is then
 * still valid, with the lines rewritten so far).
 */
int st_upstream_browser_headers_rewrite(char **headers, size_t headers_len, const char *target_base_url);

#endif
