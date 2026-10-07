#ifndef SPECUS_GITHUB_RELEASE_H
#define SPECUS_GITHUB_RELEASE_H

#include <stddef.h>

#include "http_client.h"
#include "storage.h"

#define ST_GITHUB_RELEASE_MAX_PACKAGES 10U

/* Fetch the fixed official latest-release endpoint, retaining a bounded stale cache on failure. */
int st_github_release_latest(st_storage_client_download_link *out,
                             size_t capacity,
                             size_t *out_count);

/*
 * Java GitHubReleaseCatalog.maySupplyMissingTarget: 1 when the fallback is enabled and at least
 * one release target has no row of the given catalogue, enabled or not.
 */
int st_github_release_may_supply_missing_target(const st_storage_client_download_link *catalogue,
                                                size_t catalogue_count);

/*
 * Replaces the HTTPS GET the release fetch makes (st_http_get_json; NULL restores it), as Java's
 * tests hand GitHubReleaseCatalog a mocked HttpClient. The endpoint stays the fixed official one.
 */
typedef int (*st_github_release_fetcher)(const char *endpoint,
                                         const st_http_client_options *options,
                                         long *status_code_out,
                                         char **body_out);
void st_github_release_set_fetcher_for_testing(st_github_release_fetcher fetcher);

/* Deterministic mapper used by tests; release JSON is treated as untrusted input. */
int st_github_release_map(const char *json,
                          st_storage_client_download_link *out,
                          size_t capacity,
                          size_t *out_count);

void st_github_release_cache_reset(void);

#endif
