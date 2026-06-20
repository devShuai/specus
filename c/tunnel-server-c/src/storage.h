#ifndef SHUAI_TUNNEL_STORAGE_H
#define SHUAI_TUNNEL_STORAGE_H

#include <stddef.h>
#include <stdint.h>

#include "crypto.h"

typedef struct {
    int listen_port;
    char target_address[256];
    int target_port;
} st_storage_mapping;

int st_storage_init(const char *path, int seed_demo_client);
int st_storage_load_client_hash(const char *path, const char *client_name, uint8_t hash[ST_SHA256_LEN]);
int st_storage_load_mappings(const char *path,
                             const char *client_name,
                             st_storage_mapping *mappings,
                             size_t max_mappings,
                             size_t *mapping_count);
int st_storage_upsert_mapping(const char *path,
                              const char *client_name,
                              int listen_port,
                              const char *target_address,
                              int target_port,
                              int enabled);

#endif
