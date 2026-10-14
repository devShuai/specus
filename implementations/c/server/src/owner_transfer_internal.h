#ifndef SPECUS_OWNER_TRANSFER_INTERNAL_H
#define SPECUS_OWNER_TRANSFER_INTERNAL_H

#include "owner_transfer.h"
#include "storage.h"
#include <sqlite3.h>

/* Internal connection-taking operations: never open/close/commit the caller's transaction. */
int st_owner_snapshot_load_on_db(sqlite3 *db, const char *tenant, int group, long long id,
                                 st_owner_snapshot *snapshot);
int st_owner_transfer_rows_preserved(sqlite3 *db, const char *table, const char *before,
                                      const char *where, const char *const *ignored, size_t ignored_count);
int st_owner_transfer_encode_result(const char *tenant, const char *actor, int group, long long id,
    const char *target, long long credential_id, const st_owner_snapshot *before, const char *preview,
    const long long *client_ids, size_t client_count, int changed,
    const st_storage_peer_close *closed, size_t closed_count, char **response, char **audit);

#endif
