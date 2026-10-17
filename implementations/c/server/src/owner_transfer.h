#ifndef SPECUS_OWNER_TRANSFER_H
#define SPECUS_OWNER_TRANSFER_H

#include <stddef.h>

/* Minimal owned snapshot rows: no passwords, keys, tokens or fingerprints. Text is unbounded,
 * nullable UTF-8, not the fixed-size runtime client structs. All incident identity edges must
 * be present, even foreign/corrupt ones. This is not a transfer writer or locking boundary. */
typedef struct {
    long long id, credential_id, client_id;
    char *tenant_id, *client_name, *owner_username;
    int enabled;
} st_owner_row;
typedef struct {
    st_owner_row *items;
    size_t len, cap;
} st_owner_rows;
typedef struct {
    st_owner_rows clients, credentials, identities, peers;
} st_owner_snapshot;

void st_owner_snapshot_free(st_owner_snapshot *snapshot);
/* Transfers ownership of row's strings on success, leaves row owned by caller on failure. */
int st_owner_rows_add(st_owner_rows *rows, st_owner_row row);
/* One bound statement on an independent read-only SQLite connection. No init/repair/writes. */
int st_owner_snapshot_load(const char *path, const char *tenant, int group, long long id,
                           st_owner_snapshot *snapshot);

/* Recognizes the two GET path shapes, even with an invalid id; ignores the query string.
 * id_valid is separate so the authenticated role can be checked before invalid-path errors. */
int st_owner_transfer_match(const char *path, int *group, long long *id, int *id_valid);
/* Returns HTTP status and a stable code on failure. On 200 caller owns *json; revision is empty
 * for a shared single-device preview. Never mutates the snapshot or writes ownership. */
int st_owner_transfer_preview(const char *tenant, int admin, int group, long long id,
                              const st_owner_snapshot *snapshot, char **json,
                              char revision[65], const char **code);
/* Pure contract steps 1–8 only. No target lookup, authorization token, lock, audit or write.
 * Caller owns both outputs on success. No POST is exposed until every writer is coordinated. */
int st_owner_transfer_prepare(const char *tenant, int admin, int group, long long id,
                              const st_owner_snapshot *snapshot, const char *request,
                              char **json, char **target, const char **code);
#endif
