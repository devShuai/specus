#ifndef SPECUS_PEER_MESH_H
#define SPECUS_PEER_MESH_H

#include <stddef.h>
#include "storage.h"

typedef int (*st_peer_mesh_send_fn)(void *ctx,
                                    const char *target_client_name,
                                    const char *source_client_name,
                                    const char *message);
typedef int (*st_peer_mesh_online_fn)(void *ctx,
                                      long long client_id,
                                      const char *client_name);

typedef struct {
    /* send/online are invoked under the snapshot delivery fence. They must not
     * re-enter control/login/logout/refresh or ownership-drain dispatch. */
    const char *database_path;
    st_peer_mesh_send_fn send;
    st_peer_mesh_online_fn online;
    void *ctx;
    long long publisher_session_id;
    int peer_service_discovery_version;
    /* Network callers pin the original immutable identity. NULL/0 are explicit trusted service
     * calls (management/maintenance/tests), not a network authentication fallback. */
    long long authenticated_client_id;
    const char *authenticated_tenant;
    int (*source_active)(void *ctx); /* registry-only, no SQL; cancellation while waiting. */
    int (*source_current)(void *ctx); /* fresh native epoch check after acquiring dispatch. */
} st_peer_mesh_runtime;

typedef struct {
    char name[81];
    char transport[8];
    char application[8];
    char target_host[256];
    int target_port;
} st_peer_mesh_mdns_candidate;

typedef struct {
    long long publisher_session_id;
    char instance_id[65];
    int online;
    int advertised;
    long long revision;
    char last_reported_at[32];
    char expires_at[32];
    long long bytes_in;
    long long bytes_out;
    int active_connections;
    long long total_connections;
} st_peer_mesh_service_instance;

int st_peer_mesh_handle_control(const st_peer_mesh_runtime *runtime,
                                const char *authenticated_client_name,
                                const char *target_client_name,
                                const char *message);
int st_peer_mesh_push_on_login(const st_peer_mesh_runtime *runtime,
                               const char *client_name);
/* Tell the tenant's online peers that a client has left; call after it is no longer active. */
int st_peer_mesh_push_on_logout(const st_peer_mesh_runtime *runtime,
                                const char *client_name);
/* Rebuild config/roster and re-publish active catalogues after an admin mutation. */
int st_peer_mesh_refresh_tenant(const st_peer_mesh_runtime *runtime,
                                const char *tenant_id);
/* Queue only after successful deletion commit; arguments are copied. Maintenance retries writes. */
int st_peer_mesh_queue_client_deleted(const st_storage_client *client,
                                      const st_storage_peer_close *closed, size_t closed_count);
int st_peer_mesh_drain_client_deletions(const st_peer_mesh_runtime *runtime);
typedef struct {
    char database_path[512];
    long long after_id;
    int initialized;
} st_peer_mesh_owner_cursor;
/* Initialize BEFORE accepting any local clients. Historical events are already
 * reflected in their fresh login snapshots. Caller serializes each instance's cursor. */
int st_peer_mesh_owner_changes_init(const char *database_path, st_peer_mesh_owner_cursor *cursor);
/* At-least-once delivery; advance only after all local close/config/catalog sends
 * succeed. No deletion or withdrawal of the transferred publisher's live catalogue. */
int st_peer_mesh_owner_changes_drain(const st_peer_mesh_runtime *runtime, st_peer_mesh_owner_cursor *cursor);
int st_peer_mesh_handle_disconnect(const st_peer_mesh_runtime *runtime,
                                   const char *client_name);
int st_peer_mesh_expire_catalogs(const st_peer_mesh_runtime *runtime);
int st_peer_mesh_list_mdns_candidates(const char *tenant_id,
                                      long long client_id,
                                      st_peer_mesh_mdns_candidate *out,
                                      size_t capacity,
                                      size_t *out_count);
int st_peer_mesh_list_service_instances(const char *tenant_id,
                                        long long client_id,
                                        const char *service_id,
                                        st_peer_mesh_service_instance *out,
                                        size_t capacity,
                                        size_t *out_count);
char *st_peer_mesh_build_login_config(const char *database_path,
                                      const char *client_name,
                                      int client_peer_service_version);

/*
 * Normalises a peer service target to a numeric local address, as Java
 * PeerServiceDiscovery.requireTargetHost does: localhost, or a loopback, private, link-local or
 * unique-local unicast IP. 0 with the address in out, -1 when the host is anything else.
 */
int st_peer_mesh_normalize_local_host(const char *value, char out[256]);
/* The same check with Java's refusal message: NULL with the address in out, else the message. */
const char *st_peer_mesh_local_host_refusal(const char *value, char out[256]);

/*
 * Test hooks for the two bounded tables of client-driven session ids: placeholder entries that fill
 * the egress-report rate table and the service catalogue table, and their removal.
 */
int st_peer_mesh_egress_report_rate_occupy_for_testing(size_t count);
size_t st_peer_mesh_egress_report_rate_sessions_for_testing(void);
void st_peer_mesh_egress_report_rate_release_for_testing(void);
int st_peer_mesh_catalogs_occupy_for_testing(size_t count);
void st_peer_mesh_catalogs_release_for_testing(void);

#endif
