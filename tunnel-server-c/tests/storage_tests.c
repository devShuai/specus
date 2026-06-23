#include "storage.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
    char path[256];
    snprintf(path, sizeof(path), "/tmp/shuai-tunnel-c-storage-%ld.db", (long)getpid());
    unlink(path);

    if (st_storage_init(path, 1) != 0) {
        fprintf(stderr, "storage init failed\n");
        unlink(path);
        return 1;
    }

    if (st_storage_client_enabled(path, "Demo client") != 0) {
        fprintf(stderr, "seeded client enabled check failed\n");
        unlink(path);
        return 1;
    }

    if (st_storage_upsert_mapping(path, "Demo client", 18080, "127.0.0.1", 8080, 1) != 0) {
        fprintf(stderr, "mapping upsert failed\n");
        unlink(path);
        return 1;
    }
    st_storage_mapping mappings[4];
    size_t count = 0;
    if (st_storage_load_mappings(path, "Demo client", mappings, 4, &count) != 0
        || count != 1U
        || mappings[0].listen_port != 18080
        || strcmp(mappings[0].target_address, "127.0.0.1") != 0
        || mappings[0].target_port != 8080) {
        fprintf(stderr, "mapping load mismatch\n");
        unlink(path);
        return 1;
    }

    if (st_storage_record_connection(path, "Demo client", 1, NULL, "2026-06-20T00:00:00Z") != 0
        || st_storage_record_connection(path, "Demo client", 0, "LOGIN_FAILURE", "2026-06-20T01:00:00Z") != 0
        || st_storage_archive_connections(path, "2026-06-21T00:00:00Z") != 0) {
        fprintf(stderr, "connection archive setup failed\n");
        unlink(path);
        return 1;
    }
    int successes = 0;
    int failures = 0;
    if (st_storage_load_connection_stat(path, "Demo client", "2026-06-20", &successes, &failures) != 0
        || successes != 1
        || failures != 1) {
        fprintf(stderr, "connection archive mismatch\n");
        unlink(path);
        return 1;
    }

    unlink(path);
    return 0;
}
