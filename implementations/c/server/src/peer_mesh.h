#ifndef SPECUS_PEER_MESH_H
#define SPECUS_PEER_MESH_H

#include <stddef.h>

typedef int (*st_peer_mesh_send_fn)(void *ctx,
                                    const char *target_client_name,
                                    const char *source_client_name,
                                    const char *message);
typedef int (*st_peer_mesh_online_fn)(void *ctx,
                                      long long client_id,
                                      const char *client_name);

typedef struct {
    const char *database_path;
    st_peer_mesh_send_fn send;
    st_peer_mesh_online_fn online;
    void *ctx;
    long long publisher_session_id;
    int peer_service_discovery_version;
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
/* Rebuild config/roster and re-publish active catalogues after an admin mutation. */
int st_peer_mesh_refresh_tenant(const st_peer_mesh_runtime *runtime,
                                const char *tenant_id);
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

#endif
