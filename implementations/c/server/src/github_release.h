#ifndef SPECUS_GITHUB_RELEASE_H
#define SPECUS_GITHUB_RELEASE_H

#include <stddef.h>

#include "storage.h"

#define ST_GITHUB_RELEASE_MAX_PACKAGES 10U

/* Fetch the fixed official latest-release endpoint, retaining a bounded stale cache on failure. */
int st_github_release_latest(st_storage_client_download_link *out,
                             size_t capacity,
                             size_t *out_count);

/* Deterministic mapper used by tests; release JSON is treated as untrusted input. */
int st_github_release_map(const char *json,
                          st_storage_client_download_link *out,
                          size_t capacity,
                          size_t *out_count);

void st_github_release_cache_reset(void);

#endif
