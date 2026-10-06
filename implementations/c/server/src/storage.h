#ifndef SPECUS_STORAGE_H
#define SPECUS_STORAGE_H

#include <stddef.h>
#include <stdint.h>

#include "password_hash.h"

typedef struct {
    long long id;
    char tenant_id[64];
    char client_name[256];
    char owner_username[128];
    int enabled;
    int connection_rate_limit_per_minute;
    int message_send_capable;
    int message_receive_capable;
    int message_attachments_capable;
    int message_media_preview_capable;
    long long message_max_attachment_bytes;
    int peer_service_discovery_version;
    char peer_service_applications[128];
    /* Peer egress split routing; 0 or absent means the client cannot take part. */
    int client_egress_version;
    /*
     * Whether the current online session announced domainTargetCapable. Read from that session
     * like the version above, so an offline device reads as 0 rather than as its last login.
     */
    int client_egress_domain_targets;
    char client_version[81];
    long long upload_bytes;
    long long download_bytes;
    char created_at[64];
    char updated_at[64];
} st_storage_client;

typedef struct {
    char username[81];
    char tenant_id[64];
    char password_hash[ST_PASSWORD_HASH_MAX_LEN + 1U];
    char role[20];
    int enabled;
    char created_at[64];
    char updated_at[64];
} st_storage_management_user;

typedef struct {
    char registration_id[65];
    char username[81];
    char email[255];
    char password_hash[ST_PASSWORD_HASH_MAX_LEN + 1U];
    char code_hash[65];
    int attempts_remaining;
    char expires_at[64];
    char resend_available_at[64];
    char created_at[64];
    char updated_at[64];
} st_storage_registration_challenge;

typedef struct {
    long long id;
    char tenant_id[64];
    char owner_username[128];
    char api_key[128];
    char secret_hash[65];
    int enabled;
    int max_online_instances;
    char created_at[64];
    char updated_at[64];
} st_storage_client_credential;

typedef struct {
    long long id;
    char implementation[33];
    char platform[33];
    char arch[33];
    char display_name[121];
    char download_url[1025];
    char description[513];
    int display_order;
    int enabled;
    char version[81];
    char sha256[65];
    long long file_size;
    int is_latest;
    char changelog_url[1025];
    char min_supported_version[81];
    int hosted;
    char package_path[1025];
    char package_file_name[256];
    char created_at[64];
    char updated_at[64];
} st_storage_client_download_link;

typedef struct {
    long long id;
    char tenant_id[81];
    char owner_username[161];
    char name[121];
    uint8_t *snapshot_data;
    size_t snapshot_len;
    long long size_bytes;
    long long revision;
    char created_at[64];
    char updated_at[64];
} st_storage_user_diagram;

typedef struct {
    long long id;
    char tenant_id[64];
    long long credential_id;
    long long client_id;
    char client_name[256];
    char machine_fingerprint[161];
    char os_user[121];
    char hostname[161];
    char first_seen_at[64];
    char last_seen_at[64];
} st_storage_client_identity;

typedef struct {
    long long id;
    char tenant_id[64];
    long long credential_id;
    long long identity_id;
    long long client_id;
    char client_name[256];
    char token_hash[65];
    char status[41];
    char machine_fingerprint[161];
    char os_user[121];
    char hostname[161];
    char os_name[121];
    char os_version[81];
    char os_arch[61];
    char client_version[81];
    char java_version[81];
    char local_addresses[2001];
    int message_send_capable;
    int message_receive_capable;
    int message_attachments_capable;
    int message_media_preview_capable;
    long long message_max_attachment_bytes;
    int peer_service_discovery_version;
    char peer_service_applications[128];
    char http_login_at[64];
    char netty_connected_at[64];
    char disconnected_at[64];
    char expires_at[64];
    char channel_id[161];
    char remote_address[256];
    /* Peer egress split routing; 0 or absent means the client cannot take part. */
    int client_egress_version;
    /* domainTargetCapable as declared at login; 0 when absent or when the version is 0. */
    int client_egress_domain_targets;
    /*
     * environment.clientHttpRouteCapabilities.version; from 1 the client classifies an HTTP stream
     * RST in metadata.failure, which the connectivity check trusts only then.
     */
    int client_http_route_version;
} st_storage_client_session;

typedef struct {
    long long id;
    long long client_id;
    char client_name[256];
    int listen_port;
    char target_address[256];
    int target_port;
    int enabled;
    int detail_capture_enabled;
    char created_at[64];
    char updated_at[64];
} st_storage_mapping;

typedef struct {
    long long id;
    long long client_id;
    char client_name[256];
    char route[128];
    char target_base_url[512];
    int enabled;
    int detail_capture_enabled;
    int media_capture_enabled;
    int path_rewrite_enabled;
    int insecure_skip_verify;
    int auth_enabled;
    char auth_username[121];
    char auth_password_hash[65];
    char created_at[64];
    char updated_at[64];
} st_storage_http_route;

typedef struct {
    long long id;
    char tenant_id[64];
    long long client_id;
    char client_name[256];
    char channel_id[128];
    char remote_address[128];
    char connected_at[64];
    char disconnected_at[64];
    int success;
    char failure_reason[256];
    char disconnect_reason[64];
} st_storage_connection;

typedef struct {
    long long id;
    long long client_id;
    char client_name[256];
    char month[16];
    long long total;
    long long success;
    long long failure;
    char updated_at[64];
} st_storage_connection_stat;

typedef struct {
    long long id;
    long long client_id;
    char client_name[256];
    char usage_date[16];
    long long upload_bytes;
    long long download_bytes;
    char updated_at[64];
} st_storage_traffic_usage;

typedef struct {
    long long id;
    long long client_id;
    char client_name[256];
    char resource_type[16];
    char resource_key[256];
    long long resource_id;
    char resource_name[512];
    char usage_date[16];
    long long upload_bytes;
    long long download_bytes;
    char updated_at[64];
} st_storage_resource_traffic_usage;

typedef struct {
    long long id;
    char tenant_id[64];
    char owner_username[128];
    long long client_id;
    char client_name[256];
    int enabled;
    char virtual_ip[64];
    char cidr[64];
    char public_key[257];
    char nat_type[64];
    char nat_mapping_behavior[64];
    char nat_filtering_behavior[64];
    char nat_behavior_discovery[41];
    char last_endpoint[128];
    char virtual_device_mode[32];
    char virtual_device_name[128];
    char virtual_device_status[32];
    char virtual_device_error[256];
    char virtual_device_updated_at[64];
    char last_seen_at[64];
    char updated_at[64];
    int message_send_capable;
    int message_receive_capable;
    int message_attachments_capable;
    int message_media_preview_capable;
    long long message_max_attachment_bytes;
} st_storage_peer_mesh_device;

typedef struct {
    long long id;
    char tenant_id[64];
    char owner_username[128];
    long long source_client_id;
    char source_client_name[256];
    long long target_client_id;
    char target_client_name[256];
    int allowed;
    char direction[16];
    char created_at[64];
    char updated_at[64];
} st_storage_peer_mesh_acl;

typedef struct {
    long long id;
    char tenant_id[64];
    long long source_client_id;
    char source_client_name[256];
    long long target_client_id;
    char target_client_name[256];
    char path_type[41];
    char status[41];
    char started_at[64];
    char updated_at[64];
    char expires_at[64];
    char closed_at[64];
    long long rtt_millis;
    char local_endpoint[256];
    char remote_endpoint[256];
    long long direct_bytes;
    long long relay_bytes;
    char last_traffic_at[64];
} st_storage_peer_mesh_session;

typedef struct {
    int enabled;
    int mdns_import_enabled;
    char updated_by[128];
    char updated_at[64];
} st_storage_peer_mesh_service_sharing;

typedef struct {
    long long id;
    char tenant_id[64];
    long long client_id;
    char client_name[256];
    char service_id[65];
    char name[81];
    char description[201];
    char transport[8];
    char application[16];
    char target_host[128];
    int target_port;
    int published_port;
    char path[256];
    int enabled;
    char visibility[16];
    char allowed_client_ids[512];
    char created_at[64];
    char updated_at[64];
} st_storage_peer_mesh_service;

typedef struct {
    char at[64];
    char action[64];
    char tenant_id[64];
    long long client_id;
    long long session_id;
    char service_id[65];
    char reason[256];
} st_storage_peer_mesh_service_audit;

/*
 * Stored apart from st_storage_peer_mesh_acl on purpose: mesh ACLs decide whether two devices may
 * reach each other, this decides whether one may be used as a way out to the wider network.
 * Effective permission is the intersection of the two.
 */
typedef struct {
    long long id;
    char tenant_id[64];
    char owner_username[128];
    long long egress_client_id;
    char egress_client_name[256];
    int enabled;
    char scope[16];
    char allowed_consumer_client_ids[512];
    /* Canonical JSON. Empty denies everything; there is no unconfigured-therefore-open state. */
    char destination_rules[4097];
    /* Canonical JSON array of {match, protocols, portRanges}. Empty grants no name. */
    char domain_rules[4097];
    int max_concurrent_flows;
    int max_flows_per_consumer;
    int idle_timeout_seconds;
    char created_at[64];
    char updated_at[64];
} st_storage_peer_mesh_egress_policy;

/*
 * Latest counters an egress device reported about itself. One row per device rather than an
 * append-only log: the management view needs what the node is doing now, and history from a
 * client-driven message would grow without bound. Counters carry no destination or request content.
 */
typedef struct {
    long long id;
    char tenant_id[64];
    long long egress_client_id;
    char egress_client_name[256];
    /* Bound by the server from the authenticated control connection, not read from the body. */
    long long session_id;
    long long revision;
    long long active_flows;
    long long total_flows;
    /* Refusals aggregated by result code, as canonical JSON. */
    char rejected_flows[1025];
    long long bytes_in;
    long long bytes_out;
    char reported_at[64];
    char created_at[64];
    char updated_at[64];
} st_storage_peer_mesh_egress_activity;

/*
 * Tenant-wide egress switch. Separate from the per-device enabled flag on the policy, and both must
 * be on for a device to act as an egress: the per-device flag says whether that device was chosen,
 * this one lets an operator stop the tenant without losing which devices were configured.
 */
typedef struct {
    char tenant_id[64];
    int enabled;
    char updated_by[128];
    char updated_at[64];
} st_storage_peer_mesh_egress_switch;




typedef struct {
    long long id;
    char tenant_id[64];
    long long client_id;
    char client_name[256];
    char route[128];
    long long resource_id;
    char resource_name[512];
    char method[16];
    char relative_path[1024];
    char raw_query[2048];
    int status_code;
    int success;
    char error[2048];
    char remote_address[256];
    long long request_bytes;
    long long response_bytes;
    long long elapsed_ms;
    char request_content_type[256];
    char response_content_type[256];
    char response_body_type[32];
    char request_headers[8192];
    char response_headers[8192];
    char request_preview_hex[4096];
    char request_preview_text[8192];
    char response_preview_hex[4096];
    char response_preview_text[8192];
    int request_truncated;
    int response_truncated;
    char captured_at[64];
} st_storage_http_exchange;

typedef struct {
    const char *tenant_id;
    long long client_id;
    const char *client_name;
    const char *route;
    long long resource_id;
    const char *resource_name;
    const char *method;
    const char *relative_path;
    const char *raw_query;
    int status_code;
    int success;
    const char *error;
    const char *remote_address;
    long long request_bytes;
    long long response_bytes;
    long long elapsed_ms;
    const char *request_content_type;
    const char *response_content_type;
    const char *response_body_type;
    const char *request_headers;
    const char *response_headers;
    const uint8_t *request_body;
    size_t request_body_len;
    const uint8_t *response_body;
    size_t response_body_len;
    const char *captured_at;
} st_storage_http_exchange_record;

typedef struct {
    long long id;
    char tenant_id[64];
    long long client_id;
    char client_name[256];
    int listen_port;
    long long resource_id;
    char resource_name[512];
    char channel_id[128];
    char direction[32];
    char remote_address[256];
    char source_address[256];
    int source_port;
    char destination_address[256];
    int destination_port;
    long long stream_offset;
    long long stream_end_offset;
    long long frame_index;
    long long payload_bytes;
    uint8_t *payload_data;
    size_t payload_data_len;
    char payload_preview_hex[4096];
    char payload_preview_text[4096];
    int truncated;
    char frame_time[64];
} st_storage_tcp_frame;

typedef struct {
    const char *tenant_id;
    long long client_id;
    const char *client_name;
    int listen_port;
    long long resource_id;
    const char *resource_name;
    const char *channel_id;
    const char *direction;
    const char *remote_address;
    const char *source_address;
    int source_port;
    const char *destination_address;
    int destination_port;
    long long stream_offset;
    long long frame_index;
    const uint8_t *payload_data;
    size_t payload_data_len;
    const char *frame_time;
} st_storage_tcp_frame_record;

int st_storage_init(const char *path, int seed_demo_client);
int st_storage_client_enabled(const char *path, const char *client_name);
int st_storage_count_clients_by_tenant(const char *path, const char *tenant_id, long long *count);
int st_storage_list_clients(const char *path,
                            st_storage_client *clients,
                            size_t max_clients,
                            size_t *client_count);
int st_storage_get_client(const char *path, long long id, st_storage_client *client);
int st_storage_get_client_by_name(const char *path, const char *client_name, st_storage_client *client);
int st_storage_client_has_online_receive_capability(const char *path,
                                                    long long client_id,
                                                    int *capable);
/*
 * Usernames are a global key, so a lookup by name alone (login, registration, create conflicts and
 * token resolution) finds a user of any tenant. Listing, reading on behalf of an administrator,
 * updating and deleting are scoped to one tenant instead (NULL or empty means the default tenant):
 * a user of another tenant is simply not found there, as Java's
 * ManagementUserService.requireMutableUserInTenant has it.
 */
int st_storage_list_management_users(const char *path,
                                     const char *tenant_id,
                                     st_storage_management_user *users,
                                     size_t max_users,
                                     size_t *user_count);
int st_storage_get_management_user(const char *path,
                                   const char *username,
                                   st_storage_management_user *user);
int st_storage_get_management_user_in_tenant(const char *path,
                                             const char *tenant_id,
                                             const char *username,
                                             st_storage_management_user *user);
/* Read-only lookup: 0 when found, 1 when there is no such user, -1 when the store cannot be read. */
int st_storage_find_management_user(const char *path,
                                    const char *username,
                                    st_storage_management_user *user);
int st_storage_create_management_user(const char *path,
                                      const char *username,
                                      const char *tenant_id,
                                      const char *password_hash,
                                      const char *role,
                                      int enabled,
                                      st_storage_management_user *out_user);
/* -1 when the user is not in tenant_id, as when there is no such user at all. */
int st_storage_update_management_user(const char *path,
                                      const char *tenant_id,
                                      const char *username,
                                      const char *password_hash,
                                      const char *role,
                                      int enabled,
                                      st_storage_management_user *out_user);
int st_storage_delete_management_user(const char *path, const char *tenant_id, const char *username);
int st_storage_management_email_exists(const char *path, const char *email);
int st_storage_get_registration_challenge(const char *path,
                                          const char *registration_id,
                                          st_storage_registration_challenge *challenge);
int st_storage_find_registration_challenge(const char *path,
                                           const char *username,
                                           const char *email,
                                           st_storage_registration_challenge *challenge);
int st_storage_create_registration_challenge(const char *path,
                                             const st_storage_registration_challenge *challenge);
int st_storage_update_registration_attempts(const char *path,
                                            const char *registration_id,
                                            int attempts_remaining,
                                            const char *updated_at);
int st_storage_delete_registration_challenge(const char *path, const char *registration_id);
int st_storage_delete_expired_registration_challenges(const char *path, const char *expires_before);
int st_storage_complete_registration(const char *path,
                                     const st_storage_registration_challenge *challenge,
                                     const char *tenant_id,
                                     st_storage_management_user *out_user);
int st_storage_get_client_credential_by_api_key(const char *path,
                                                const char *api_key,
                                                st_storage_client_credential *credential);
int st_storage_get_client_credential(const char *path,
                                     long long id,
                                     st_storage_client_credential *credential);
int st_storage_list_client_credentials(const char *path,
                                       const char *tenant_id,
                                       st_storage_client_credential *credentials,
                                       size_t max_credentials,
                                       size_t *credential_count);
int st_storage_upsert_client_credential(const char *path,
                                        long long id,
                                        const char *tenant_id,
                                        const char *owner_username,
                                        const char *api_key,
                                        const char *secret_hash,
                                        int enabled,
                                        int max_online_instances,
                                        st_storage_client_credential *out_credential);
int st_storage_delete_client_credential(const char *path, long long id);
int st_storage_list_client_download_links(const char *path,
                                          int enabled_only,
                                          st_storage_client_download_link *links,
                                          size_t max_links,
                                          size_t *link_count);
int st_storage_get_client_download_link(const char *path,
                                        long long id,
                                        st_storage_client_download_link *link);
int st_storage_upsert_client_download_link(const char *path,
                                           long long id,
                                           const char *implementation,
                                           const char *platform,
                                           const char *arch,
                                           const char *display_name,
                                           const char *download_url,
                                           const char *description,
                                           int display_order,
                                           int enabled,
                                           st_storage_client_download_link *out_link);
int st_storage_upsert_client_download_link_extended(const char *path,
                                                    long long id,
                                                    const char *implementation,
                                                    const char *platform,
                                                    const char *arch,
                                                    const char *display_name,
                                                    const char *download_url,
                                                    const char *description,
                                                    int display_order,
                                                    int enabled,
                                                    const char *version,
                                                    const char *sha256,
                                                    long long file_size,
                                                    int is_latest,
                                                    const char *changelog_url,
                                                    const char *min_supported_version,
                                                    int hosted,
                                                    const char *package_path,
                                                    const char *package_file_name,
                                                    st_storage_client_download_link *out_link);
int st_storage_mark_client_download_latest(const char *path,
                                           long long id,
                                           st_storage_client_download_link *out_link);
int st_storage_list_user_diagrams(const char *path,
                                  const char *tenant_id,
                                  const char *owner_username,
                                  st_storage_user_diagram *items,
                                  size_t capacity,
                                  size_t *out_count);
int st_storage_get_user_diagram(const char *path,
                                long long id,
                                const char *tenant_id,
                                const char *owner_username,
                                st_storage_user_diagram *out);
int st_storage_create_user_diagram(const char *path,
                                   const char *tenant_id,
                                   const char *owner_username,
                                   const char *name,
                                   const uint8_t *snapshot,
                                   size_t snapshot_len,
                                   st_storage_user_diagram *out);
int st_storage_update_user_diagram(const char *path,
                                   long long id,
                                   const char *tenant_id,
                                   const char *owner_username,
                                   long long expected_revision,
                                   const char *name,
                                   const uint8_t *snapshot,
                                   size_t snapshot_len,
                                   st_storage_user_diagram *out);
int st_storage_delete_user_diagram(const char *path,
                                   long long id,
                                   const char *tenant_id,
                                   const char *owner_username);
void st_storage_user_diagram_free(st_storage_user_diagram *diagram);
int st_storage_delete_client_download_link(const char *path, long long id);
int st_storage_find_or_create_client_identity(const char *path,
                                              const st_storage_client_credential *credential,
                                              const char *machine_fingerprint,
                                              const char *os_user,
                                              const char *hostname,
                                              st_storage_client_identity *identity);
int st_storage_close_http_authenticated_sessions(const char *path,
                                                 long long credential_id,
                                                 const char *machine_fingerprint,
                                                 const char *os_user,
                                                 const char *disconnected_at);
int st_storage_create_client_session(const char *path,
                                     const st_storage_client_session *session,
                                     st_storage_client_session *out_session);
int st_storage_get_client_session_for_login(const char *path,
                                            long long id,
                                            const char *token_hash,
                                            st_storage_client_session *session);
int st_storage_count_online_sessions_by_machine(const char *path,
                                                long long credential_id,
                                                const char *machine_fingerprint,
                                                const char *os_user,
                                                long long exclude_session_id,
                                                int *count);
int st_storage_count_online_sessions_by_credential(const char *path,
                                                   long long credential_id,
                                                   long long exclude_session_id,
                                                   int *count);
/*
 * Reports whether a later HTTP login issued another session to the same credential + machine +
 * OS user. Such a session is retired: its token must not open a control channel again.
 */
int st_storage_client_session_superseded(const char *path,
                                         long long credential_id,
                                         const char *machine_fingerprint,
                                         const char *os_user,
                                         long long session_id,
                                         int *superseded);
/* Lists up to max_ids NETTY_ONLINE session ids of a credential, oldest first. */
int st_storage_list_online_session_ids_by_credential(const char *path,
                                                     long long credential_id,
                                                     long long *ids,
                                                     size_t max_ids,
                                                     size_t *id_count);
int st_storage_mark_client_session_online(const char *path,
                                          long long id,
                                          const char *channel_id,
                                          const char *remote_address,
                                          const char *connected_at);
int st_storage_mark_client_session_disconnected(const char *path,
                                                long long id,
                                                const char *disconnected_at);
int st_storage_close_client_sessions_by_status(const char *path,
                                               const char *from_status,
                                               const char *disconnected_at);
int st_storage_upsert_client(const char *path,
                             long long id,
                             const char *tenant_id,
                             const char *client_name,
                             const char *owner_username,
                             int enabled,
                             int connection_rate_limit_per_minute,
                             st_storage_client *out_client);
int st_storage_delete_client(const char *path, long long id);
int st_storage_load_mappings(const char *path,
                             const char *client_name,
                             st_storage_mapping *mappings,
                             size_t max_mappings,
                             size_t *mapping_count);
int st_storage_list_mappings(const char *path,
                             long long client_id,
                             st_storage_mapping *mappings,
                             size_t max_mappings,
                             size_t *mapping_count);
int st_storage_get_mapping(const char *path, long long id, st_storage_mapping *mapping);
int st_storage_get_mapping_by_client_port(const char *path,
                                          const char *client_name,
                                          int listen_port,
                                          st_storage_mapping *mapping);
int st_storage_upsert_mapping(const char *path,
                              const char *client_name,
                              int listen_port,
                              const char *target_address,
                              int target_port,
                              int enabled);
int st_storage_create_mapping_for_client(const char *path,
                                         long long client_id,
                                         int listen_port,
                                         const char *target_address,
                                         int target_port,
                                         int enabled,
                                         int detail_capture_enabled,
                                         st_storage_mapping *out_mapping);
int st_storage_update_mapping_by_id(const char *path,
                                    long long id,
                                    int listen_port,
                                    const char *target_address,
                                    int target_port,
                                    int enabled,
                                    int detail_capture_enabled,
                                    st_storage_mapping *out_mapping);
int st_storage_delete_mapping_by_id(const char *path, long long id);
int st_storage_load_http_routes(const char *path,
                                const char *client_name,
                                st_storage_http_route *routes,
                                size_t max_routes,
                                size_t *route_count);
int st_storage_list_http_routes(const char *path,
                                long long client_id,
                                st_storage_http_route *routes,
                                size_t max_routes,
                                size_t *route_count);
int st_storage_get_http_route(const char *path, long long id, st_storage_http_route *route);
/* -1 when the records could not be read; otherwise 0 with *found telling whether the route exists. */
int st_storage_find_http_route_by_id(const char *path, long long id, st_storage_http_route *route, int *found);
int st_storage_get_http_route_by_client_route(const char *path,
                                              const char *client_name,
                                              const char *route_name,
                                              st_storage_http_route *route);
int st_storage_find_http_route_by_client_route(const char *path,
                                               const char *client_name,
                                               const char *route_name,
                                               st_storage_http_route *route,
                                               int *found);
int st_storage_create_http_route_for_client(const char *path,
                                            long long client_id,
                                            const char *route,
                                            const char *target_base_url,
                                            int enabled,
                                            int detail_capture_enabled,
                                            int media_capture_enabled,
                                            int path_rewrite_enabled,
                                            int insecure_skip_verify,
                                            int auth_enabled,
                                            const char *auth_username,
                                            const char *auth_password_hash,
                                            st_storage_http_route *out_route);
int st_storage_update_http_route_by_id(const char *path,
                                       long long id,
                                       const char *route,
                                       const char *target_base_url,
                                       int enabled,
                                       int detail_capture_enabled,
                                       int media_capture_enabled,
                                       int path_rewrite_enabled,
                                       int insecure_skip_verify,
                                       int auth_enabled,
                                       const char *auth_username,
                                       const char *auth_password_hash,
                                       st_storage_http_route *out_route);
int st_storage_delete_http_route_by_id(const char *path, long long id);
int st_storage_record_connection(const char *path,
                                 const char *client_name,
                                 int success,
                                 const char *reason,
                                 const char *connected_at);
int st_storage_record_connection_detail(const char *path,
                                        long long client_id,
                                        const char *client_name,
                                        const char *channel_id,
                                        const char *remote_address,
                                        int success,
                                        const char *failure_reason,
                                        const char *disconnect_reason,
                                        const char *connected_at,
                                        const char *disconnected_at);
int st_storage_record_connection_detail_with_id(const char *path,
                                                long long client_id,
                                                const char *client_name,
                                                const char *channel_id,
                                                const char *remote_address,
                                                int success,
                                                const char *failure_reason,
                                                const char *disconnect_reason,
                                                const char *connected_at,
                                                const char *disconnected_at,
                                                long long *record_id);
int st_storage_record_connection_detail_with_tenant_and_id(const char *path,
                                                           const char *tenant_id,
                                                           long long client_id,
                                                           const char *client_name,
                                                           const char *channel_id,
                                                           const char *remote_address,
                                                           int success,
                                                           const char *failure_reason,
                                                           const char *disconnect_reason,
                                                           const char *connected_at,
                                                           const char *disconnected_at,
                                                           long long *record_id);
int st_storage_mark_connection_disconnected(const char *path,
                                            long long id,
                                            const char *disconnect_reason,
                                            const char *disconnected_at);
/*
 * Ends every connection record that is still open, keeping a reason already stamped on it. Used at
 * startup (SERVER_RESTARTED) for rows a killed process left behind and after the graceful shutdown
 * drain (SERVER_SHUTDOWN) for channels that did not finish in time. closed_count may be NULL.
 */
int st_storage_close_open_connections(const char *path,
                                      const char *disconnect_reason,
                                      const char *disconnected_at,
                                      int *closed_count);
int st_storage_list_connections(const char *path,
                                long long client_id,
                                int success_filter,
                                const char *from,
                                const char *to,
                                int page,
                                int size,
                                st_storage_connection *connections,
                                size_t max_connections,
                                size_t *connection_count,
                                long long *total_count);
int st_storage_list_connections_visible(const char *path,
                                        long long client_id,
                                        int success_filter,
                                        const char *from,
                                        const char *to,
                                        const char *tenant_id,
                                        const char *owner_username,
                                        int include_all_clients,
                                        int page,
                                        int size,
                                        st_storage_connection *connections,
                                        size_t max_connections,
                                        size_t *connection_count,
                                        long long *total_count);
int st_storage_archive_connections(const char *path, const char *before_timestamp);
int st_storage_load_connection_stat(const char *path,
                                    const char *client_name,
                                    const char *stat_date,
                                    int *success_count,
                                    int *failure_count);
int st_storage_list_connection_stats(const char *path,
                                     const char *client_name,
                                     int limit,
                                     st_storage_connection_stat *stats,
                                     size_t max_stats,
                                     size_t *stat_count);
int st_storage_list_connection_stats_visible(const char *path,
                                             const char *client_name,
                                             const char *tenant_id,
                                             const char *owner_username,
                                             int include_all_clients,
                                             int limit,
                                             st_storage_connection_stat *stats,
                                             size_t max_stats,
                                             size_t *stat_count);
int st_storage_record_traffic_usage(const char *path,
                                    long long client_id,
                                    const char *client_name,
                                    const char *usage_date,
                                    long long upload_bytes,
                                    long long download_bytes);
int st_storage_list_traffic_usage(const char *path,
                                  long long client_id,
                                  int limit,
                                  st_storage_traffic_usage *items,
                                  size_t max_items,
                                  size_t *item_count);
int st_storage_list_traffic_usage_visible(const char *path,
                                          long long client_id,
                                          const char *tenant_id,
                                          const char *owner_username,
                                          int include_all_clients,
                                          int limit,
                                          st_storage_traffic_usage *items,
                                          size_t max_items,
                                          size_t *item_count);
int st_storage_record_resource_traffic_usage(const char *path,
                                             long long client_id,
                                             const char *client_name,
                                             const char *resource_type,
                                             const char *resource_key,
                                             long long resource_id,
                                             const char *resource_name,
                                             const char *usage_date,
                                             long long upload_bytes,
                                             long long download_bytes);
int st_storage_list_resource_traffic_usage(const char *path,
                                           const char *resource_type,
                                           long long client_id,
                                           int limit,
                                           st_storage_resource_traffic_usage *items,
                                           size_t max_items,
                                           size_t *item_count);
int st_storage_list_resource_traffic_usage_visible(const char *path,
                                                   const char *resource_type,
                                                   long long client_id,
                                                   const char *tenant_id,
                                                   const char *owner_username,
                                                   int include_all_clients,
                                                   int limit,
                                                   st_storage_resource_traffic_usage *items,
                                                   size_t max_items,
                                                   size_t *item_count);
int st_storage_list_peer_mesh_acls_visible(const char *path,
                                           const char *tenant_id,
                                           const char *owner_username,
                                           int include_all_clients,
                                           st_storage_peer_mesh_acl *acls,
                                           size_t max_acls,
                                           size_t *acl_count);
int st_storage_ensure_peer_mesh_device(const char *path,
                                       const st_storage_client *client,
                                       st_storage_peer_mesh_device *out_device);
int st_storage_update_peer_mesh_device_enabled(const char *path,
                                               const st_storage_client *client,
                                               int enabled,
                                               st_storage_peer_mesh_device *out_device);
int st_storage_get_peer_mesh_device_by_client(const char *path,
                                              const char *tenant_id,
                                              long long client_id,
                                              st_storage_peer_mesh_device *out_device);
int st_storage_update_peer_mesh_device_report(const char *path,
                                              const st_storage_client *client,
                                              const char *public_key,
                                              const char *nat_type,
                                              const char *nat_mapping_behavior,
                                              const char *nat_filtering_behavior,
                                              const char *nat_behavior_discovery,
                                              const char *last_endpoint,
                                              const char *virtual_device_mode,
                                              const char *virtual_device_name,
                                              const char *virtual_device_status,
                                              const char *virtual_device_error,
                                              st_storage_peer_mesh_device *out_device);
int st_storage_get_peer_mesh_acl(const char *path, long long id, st_storage_peer_mesh_acl *acl);
int st_storage_can_peer(const char *path,
                        const st_storage_client *source,
                        const st_storage_client *target,
                        int *allowed);
int st_storage_upsert_peer_mesh_acl(const char *path,
                                    const char *tenant_id,
                                    const char *owner_username,
                                    const st_storage_client *source,
                                    const st_storage_client *target,
                                    int allowed,
                                    const char *direction,
                                    st_storage_peer_mesh_acl *out_acl);
int st_storage_delete_peer_mesh_acl_visible(const char *path,
                                            long long id,
                                            const char *tenant_id,
                                            const char *owner_username,
                                            int include_all_clients);
int st_storage_list_peer_mesh_sessions_visible(const char *path,
                                               const char *tenant_id,
                                               const char *owner_username,
                                               int include_all_clients,
                                               int include_closed,
                                               int limit,
                                               st_storage_peer_mesh_session *sessions,
                                               size_t max_sessions,
                                               size_t *session_count);
int st_storage_close_peer_mesh_session_visible(const char *path,
                                               long long id,
                                               const char *tenant_id,
                                               const char *owner_username,
                                               int include_all_clients,
                                               st_storage_peer_mesh_session *out_session);
int st_storage_close_open_peer_mesh_sessions_visible(const char *path,
                                                     const char *tenant_id,
                                                     const char *owner_username,
                                                     int include_all_clients,
                                                     st_storage_peer_mesh_session *sessions,
                                                     size_t max_sessions,
                                                     size_t *session_count);
int st_storage_create_peer_mesh_session(const char *path,
                                        const st_storage_client *source,
                                        const st_storage_client *target,
                                        const char *path_type,
                                        const char *token_hash,
                                        long long ttl_seconds,
                                        st_storage_peer_mesh_session *out_session);
int st_storage_get_peer_mesh_session(const char *path,
                                     const char *tenant_id,
                                     long long id,
                                     st_storage_peer_mesh_session *out_session);
int st_storage_report_peer_mesh_session(const char *path,
                                        const st_storage_client *reporter,
                                        long long id,
                                        const char *path_type,
                                        const char *status,
                                        long long rtt_millis,
                                        const char *local_endpoint,
                                        const char *remote_endpoint,
                                        long long direct_bytes,
                                        long long relay_bytes,
                                        int close_session,
                                        st_storage_peer_mesh_session *out_session);
int st_storage_authorize_peer_mesh_relay(const char *path,
                                         long long session_id,
                                         long long from_client_id,
                                         long long to_client_id,
                                         long long relay_bytes,
                                         int account_traffic);
int st_storage_verify_peer_mesh_probe(const char *path,
                                      long long session_id,
                                      long long from_client_id,
                                      long long to_client_id,
                                      const char *token);
int st_storage_get_peer_mesh_service_sharing(const char *path,
                                             const char *tenant_id,
                                             st_storage_peer_mesh_service_sharing *out_sharing);
int st_storage_upsert_peer_mesh_service_sharing(const char *path,
                                                const char *tenant_id,
                                                int enabled,
                                                int mdns_import_enabled,
                                                const char *updated_by,
                                                st_storage_peer_mesh_service_sharing *out_sharing);
int st_storage_list_peer_mesh_services_visible(const char *path,
                                               const char *tenant_id,
                                               const char *owner_username,
                                               int include_all_clients,
                                               st_storage_peer_mesh_service *services,
                                               size_t max_services,
                                               size_t *service_count);
int st_storage_get_peer_mesh_service_visible(const char *path,
                                             long long id,
                                             const char *tenant_id,
                                             const char *owner_username,
                                             int include_all_clients,
                                             st_storage_peer_mesh_service *out_service);
int st_storage_upsert_peer_mesh_service(const char *path,
                                        const st_storage_peer_mesh_service *service,
                                        st_storage_peer_mesh_service *out_service);
int st_storage_delete_peer_mesh_service(const char *path,
                                        long long id,
                                        const char *tenant_id);
int st_storage_list_peer_mesh_egress_policies(const char *path,
                                              const char *tenant_id,
                                              int enabled_only,
                                              st_storage_peer_mesh_egress_policy *policies,
                                              size_t max_policies,
                                              size_t *policy_count);
int st_storage_get_peer_mesh_egress_policy(const char *path,
                                           long long id,
                                           const char *tenant_id,
                                           st_storage_peer_mesh_egress_policy *out_policy);
int st_storage_find_peer_mesh_egress_policy_by_client(const char *path,
                                                      const char *tenant_id,
                                                      long long egress_client_id,
                                                      st_storage_peer_mesh_egress_policy *out_policy);
int st_storage_upsert_peer_mesh_egress_policy(const char *path,
                                              const st_storage_peer_mesh_egress_policy *policy,
                                              st_storage_peer_mesh_egress_policy *out_policy);
int st_storage_delete_peer_mesh_egress_policy(const char *path,
                                              long long id,
                                              const char *tenant_id);
int st_storage_list_peer_mesh_egress_activity(const char *path,
                                              const char *tenant_id,
                                              st_storage_peer_mesh_egress_activity *rows,
                                              size_t max_rows,
                                              size_t *row_count);
int st_storage_find_peer_mesh_egress_activity(const char *path,
                                              const char *tenant_id,
                                              long long egress_client_id,
                                              st_storage_peer_mesh_egress_activity *out_row);
int st_storage_upsert_peer_mesh_egress_activity(const char *path,
                                                const st_storage_peer_mesh_egress_activity *row);
/* Returns 0 on a hit, 1 when the tenant has never set it, -1 on a storage failure. */
int st_storage_get_peer_mesh_egress_switch(const char *path,
                                           const char *tenant_id,
                                           st_storage_peer_mesh_egress_switch *out_row);
int st_storage_upsert_peer_mesh_egress_switch(const char *path,
                                              const st_storage_peer_mesh_egress_switch *row);
int st_storage_record_peer_mesh_service_audit(const char *path,
                                              const char *action,
                                              const char *tenant_id,
                                              long long client_id,
                                              long long session_id,
                                              const char *service_id,
                                              const char *reason);
int st_storage_list_peer_mesh_service_audits(const char *path,
                                             const char *tenant_id,
                                             st_storage_peer_mesh_service_audit *events,
                                             size_t max_events,
                                             size_t *event_count);
int st_storage_record_http_exchange(const char *path, const st_storage_http_exchange_record *record);
int st_storage_list_http_exchanges_visible(const char *path,
                                           long long client_id,
                                           const char *route,
                                           const char *response_body_type,
                                           const char *field,
                                           const char *query,
                                           const char *tenant_id,
                                           const char *owner_username,
                                           int include_all_clients,
                                           int page,
                                           int size,
                                           st_storage_http_exchange *items,
                                           size_t max_items,
                                           size_t *item_count,
                                           long long *total_count);
int st_storage_record_tcp_frame(const char *path, const st_storage_tcp_frame_record *record);
int st_storage_list_tcp_frames_visible(const char *path,
                                       long long client_id,
                                       int listen_port,
                                       const char *tenant_id,
                                       const char *owner_username,
                                       int include_all_clients,
                                       int page,
                                       int size,
                                       st_storage_tcp_frame *items,
                                       size_t max_items,
                                       size_t *item_count,
                                       long long *total_count);
int st_storage_get_tcp_frame_visible(const char *path,
                                     long long id,
                                     const char *tenant_id,
                                     const char *owner_username,
                                     int include_all_clients,
                                     st_storage_tcp_frame *frame);
int st_storage_list_tcp_stream_visible(const char *path,
                                       const char *channel_id,
                                       const char *tenant_id,
                                       const char *owner_username,
                                       int include_all_clients,
                                       int limit,
                                       st_storage_tcp_frame *items,
                                       size_t max_items,
                                       size_t *item_count);
void st_storage_tcp_frame_free(st_storage_tcp_frame *frame);

/*
 * Service workbench (protocol/spec/service-workbench.md): favourites and recently opened services
 * of one management identity (tenant_id + username), kept in management_workbench_item as bare
 * references (kind, object_id) with an epoch-millisecond time. The bounds are fixed by the contract.
 */
#define ST_STORAGE_WORKBENCH_MAX_FAVORITES 50
#define ST_STORAGE_WORKBENCH_MAX_RECENTS 20
#define ST_STORAGE_WORKBENCH_RECENT_RETENTION_DAYS 30
#define ST_STORAGE_WORKBENCH_RECENT_RETENTION_MS 2592000000LL
/* Results of st_storage_workbench_write besides 0 (done) and -1 (the store failed). */
#define ST_STORAGE_WORKBENCH_TARGET_NOT_FOUND 1
#define ST_STORAGE_WORKBENCH_FAVORITES_FULL 2

typedef enum {
    ST_STORAGE_WORKBENCH_ADD_FAVORITE = 1,
    ST_STORAGE_WORKBENCH_REMOVE_FAVORITE,
    ST_STORAGE_WORKBENCH_CLEAR_FAVORITES,
    ST_STORAGE_WORKBENCH_RECORD_VISIT,
    ST_STORAGE_WORKBENCH_REMOVE_RECENT,
    ST_STORAGE_WORKBENCH_CLEAR_RECENTS
} st_storage_workbench_write_op;

typedef struct {
    char kind[16];
    long long object_id;
    long long at_ms;
} st_storage_workbench_entry;

/* Favourites are all stored rows (more than 50 only when rows were written around the bound). */
typedef struct {
    st_storage_workbench_entry *favorites;
    size_t favorites_len;
    st_storage_workbench_entry recents[ST_STORAGE_WORKBENCH_MAX_RECENTS];
    size_t recents_len;
} st_storage_workbench_document;

/*
 * Visibility of the object a growth write names, decided by the caller from the client that
 * carries it: only tenant_id, owner_username and id are filled (owner_username is empty when a
 * Peer service's client is gone). Nonzero means visible.
 */
typedef int (*st_storage_workbench_visible_fn)(const void *ctx, const st_storage_client *client);

typedef struct {
    st_storage_workbench_write_op op;
    const char *tenant_id;
    const char *username;
    const char *kind;      /* NULL for the clear operations */
    long long object_id;
    long long now_ms;
    st_storage_workbench_visible_fn visible;
    const void *visible_ctx;
} st_storage_workbench_write_request;

/*
 * Reads the identity's document as of now_ms: every favourite (addedAt ascending, then kind order,
 * then id) and the first 20 recents younger than 30 days (visitedAt descending, kind order, id).
 * Never writes. 0 on success, -1 when the store cannot be read; doc is empty on failure.
 */
int st_storage_workbench_read(const char *path,
                              const char *tenant_id,
                              const char *username,
                              long long now_ms,
                              st_storage_workbench_document *doc);
/*
 * Applies one write in a single IMMEDIATE transaction: the identity's rows are read before the
 * visibility of a growth target is checked, a successful write normalises the identity's recents
 * (expired rows, then rows ranked after the 20th, are deleted) and doc receives the document as
 * committed. Returns 0, ST_STORAGE_WORKBENCH_TARGET_NOT_FOUND, ST_STORAGE_WORKBENCH_FAVORITES_FULL
 * (nothing written for either) or -1 when the store failed.
 */
int st_storage_workbench_write(const char *path,
                               const st_storage_workbench_write_request *request,
                               st_storage_workbench_document *doc);
void st_storage_workbench_document_free(st_storage_workbench_document *doc);
/* Global retention sweep: deletes every identity's recents with at_ms <= now_ms - 30 days. */
int st_storage_workbench_sweep(const char *path, long long now_ms);

/*
 * Temporary HTTP shares (protocol/spec/temporary-http-share.md). Every function takes "now" in
 * epoch milliseconds from the share clock and stores whole seconds; a share has expired once
 * now >= expires_at. Share decisions read the share, route, client and creator afresh each time.
 */
typedef struct {
    char share_id[17];
    char tenant_id[128];
    long long route_id;
    char token_sha256[65];
    char access[9];
    char path_prefix[257];
    char label[256];
    int has_label;
    char created_by[128];
    long long created_at;
    long long expires_at;
    int revoked;
    long long revoked_at;
    char revoked_by[128];
    int has_revoked_by;
    char revoke_reason[41];
    int expiry_recorded;
} st_storage_http_share;

/* The built-in admin, who has no specus_management_user row; accepted says it may sign in now. */
typedef struct {
    const char *username;
    const char *tenant_id;
    int accepted;
} st_storage_share_builtin_admin;

/* Share ids a call revoked, so the caller can cut this instance's streams of them. */
typedef struct {
    char (*ids)[17];
    size_t len;
    size_t cap;
} st_storage_share_ids;

typedef struct {
    int found;
    st_storage_http_share share;
    int route_found;
    int client_found;
    long long client_id;
    char client_name[256];
    char route_name[128];
    int path_rewrite_enabled;
    /* Only for an active share: why its route, client or creator no longer allows it, else NULL. */
    const char *lapse_reason;
} st_storage_http_share_resolution;

typedef struct {
    long long id;
    long long occurred_at;
    char actor[128];
    int has_actor;
    char action[41];
    long long route_id;
    char share_id[17];
    int has_share_id;
    char detail_json[513];
} st_storage_http_access_audit;

#define ST_STORAGE_SHARE_OK 0
#define ST_STORAGE_SHARE_ROUTE_NOT_FOUND 1
#define ST_STORAGE_SHARE_ROUTE_DISABLED 2
#define ST_STORAGE_SHARE_CLIENT_DISABLED 3
#define ST_STORAGE_SHARE_ROUTE_PUBLIC 4
#define ST_STORAGE_SHARE_LIMIT_REACHED 5
#define ST_STORAGE_SHARE_ID_TAKEN 6
#define ST_STORAGE_SHARE_NOT_FOUND 7

int st_storage_share_ids_add(st_storage_share_ids *ids, const char *share_id);
void st_storage_share_ids_free(st_storage_share_ids *ids);
/* Test hook: every share read and write fails as if the store were unreadable. */
void st_storage_http_share_fail_for_testing(int failing);

/* Whether caller (re-read now) may manage the route; 0, or -1 when the store cannot be read. */
int st_storage_http_share_caller_can_manage(const char *path,
                                            const st_storage_share_builtin_admin *builtin,
                                            const char *caller,
                                            const char *caller_tenant,
                                            long long route_id,
                                            int *allowed);
/* Whether caller (re-read now) is an enabled tenant admin; fills its tenant. */
int st_storage_http_share_caller_is_admin(const char *path,
                                          const st_storage_share_builtin_admin *builtin,
                                          const char *caller,
                                          const char *caller_tenant,
                                          int *admin,
                                          char tenant_id[128]);
/*
 * Spec 4.1 steps 3-9 in one transaction. draft carries share_id, token_sha256, access,
 * path_prefix, label, created_at and expires_at; tenant and creator come from the route and the
 * caller. Returns ST_STORAGE_SHARE_* or -1.
 */
int st_storage_http_share_create(const char *path,
                                 const st_storage_share_builtin_admin *builtin,
                                 const char *caller,
                                 const char *caller_tenant,
                                 long long route_id,
                                 const st_storage_http_share *draft,
                                 int max_active,
                                 long long now_ms,
                                 st_storage_http_share *out);
/*
 * The stored shares of a route (or the one share_id of it), newest first, after revoking in place
 * every active one that has lapsed. *shares is malloc'd.
 */
int st_storage_http_share_list(const char *path,
                               const st_storage_share_builtin_admin *builtin,
                               long long route_id,
                               const char *share_id,
                               long long now_ms,
                               st_storage_http_share **shares,
                               size_t *count,
                               st_storage_share_ids *revoked);
/* Spec 4.3: ROUTE_NOT_FOUND, NOT_FOUND or OK with the share as it is now; *changed when revoked. */
int st_storage_http_share_revoke(const char *path,
                                 const st_storage_share_builtin_admin *builtin,
                                 const char *caller,
                                 const char *caller_tenant,
                                 long long route_id,
                                 const char *share_id,
                                 long long now_ms,
                                 st_storage_http_share *out,
                                 int *changed);
/* Reads a share with its route and client as they are now (spec 6.1 step 3). */
int st_storage_http_share_resolve(const char *path,
                                  const st_storage_share_builtin_admin *builtin,
                                  const char *share_id,
                                  long long now_ms,
                                  st_storage_http_share_resolution *out);
/* Read-time revoke (spec 7.4): conditional update plus audit, actor NULL; *changed when it won. */
int st_storage_http_share_revoke_lapsed(const char *path,
                                        const char *share_id,
                                        const char *reason,
                                        long long now_ms,
                                        int *changed);
/* Spec 7.5: record expiries, revoke lapsed shares, delete rows past retention. */
int st_storage_http_share_sweep(const char *path,
                                const st_storage_share_builtin_admin *builtin,
                                long long now_ms,
                                st_storage_share_ids *revoked);
/* Audit entries of a tenant (route_id 0: every route), id descending, id < before when before > 0. */
int st_storage_http_access_audit_list(const char *path,
                                      const char *tenant_id,
                                      long long route_id,
                                      long long before,
                                      int limit,
                                      st_storage_http_access_audit **entries,
                                      size_t *count,
                                      int *more);

/*
 * Route, client and user changes with their share hooks and audit in the same transaction
 * (spec 7.3 and 8). actor is the acting user; revoked collects the shares that ended.
 */
int st_storage_create_http_route_audited(const char *path,
                                         long long client_id,
                                         const char *route,
                                         const char *target_base_url,
                                         int enabled,
                                         int detail_capture_enabled,
                                         int media_capture_enabled,
                                         int path_rewrite_enabled,
                                         int insecure_skip_verify,
                                         int auth_enabled,
                                         const char *auth_username,
                                         const char *auth_password_hash,
                                         int password_set,
                                         const char *actor,
                                         long long now_ms,
                                         st_storage_http_route *out_route,
                                         st_storage_share_ids *revoked);
int st_storage_update_http_route_audited(const char *path,
                                         long long id,
                                         const char *route,
                                         const char *target_base_url,
                                         int enabled,
                                         int detail_capture_enabled,
                                         int media_capture_enabled,
                                         int path_rewrite_enabled,
                                         int insecure_skip_verify,
                                         int auth_enabled,
                                         const char *auth_username,
                                         const char *auth_password_hash,
                                         int password_set,
                                         const char *actor,
                                         long long now_ms,
                                         st_storage_http_route *out_route,
                                         st_storage_share_ids *revoked);
int st_storage_delete_http_route_audited(const char *path,
                                         long long id,
                                         const char *actor,
                                         long long now_ms,
                                         st_storage_share_ids *revoked);
int st_storage_update_client_audited(const char *path,
                                     long long id,
                                     const char *client_name,
                                     int enabled,
                                     int connection_rate_limit_per_minute,
                                     const char *actor,
                                     long long now_ms,
                                     st_storage_client *out_client,
                                     st_storage_share_ids *revoked);
int st_storage_delete_client_audited(const char *path,
                                     long long id,
                                     const char *actor,
                                     long long now_ms,
                                     st_storage_share_ids *revoked);
int st_storage_update_management_user_audited(const char *path,
                                              const st_storage_share_builtin_admin *builtin,
                                              const char *tenant_id,
                                              const char *username,
                                              const char *password_hash,
                                              const char *role,
                                              int enabled,
                                              const char *actor,
                                              long long now_ms,
                                              st_storage_management_user *out_user,
                                              st_storage_share_ids *revoked);
int st_storage_delete_management_user_audited(const char *path,
                                              const st_storage_share_builtin_admin *builtin,
                                              const char *tenant_id,
                                              const char *username,
                                              const char *actor,
                                              long long now_ms,
                                              st_storage_share_ids *revoked);

#endif
