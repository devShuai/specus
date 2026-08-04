#ifndef SPECUS_STORAGE_H
#define SPECUS_STORAGE_H

#include <stddef.h>
#include <stdint.h>

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
    char created_at[64];
    char updated_at[64];
} st_storage_client;

typedef struct {
    char username[81];
    char tenant_id[64];
    char password_hash[65];
    char role[20];
    int enabled;
    char created_at[64];
    char updated_at[64];
} st_storage_management_user;

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
    char created_at[64];
    char updated_at[64];
} st_storage_client_download_link;

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
    char http_login_at[64];
    char netty_connected_at[64];
    char disconnected_at[64];
    char expires_at[64];
    char channel_id[161];
    char remote_address[256];
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
    int path_rewrite_enabled;
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
    char public_key[257];
    char nat_type[64];
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
int st_storage_list_management_users(const char *path,
                                     const char *tenant_id,
                                     st_storage_management_user *users,
                                     size_t max_users,
                                     size_t *user_count);
int st_storage_get_management_user(const char *path,
                                   const char *username,
                                   st_storage_management_user *user);
int st_storage_create_management_user(const char *path,
                                      const char *username,
                                      const char *tenant_id,
                                      const char *password_hash,
                                      const char *role,
                                      int enabled,
                                      st_storage_management_user *out_user);
int st_storage_update_management_user(const char *path,
                                      const char *username,
                                      const char *password_hash,
                                      const char *role,
                                      int enabled,
                                      st_storage_management_user *out_user);
int st_storage_delete_management_user(const char *path, const char *username);
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
                                            int path_rewrite_enabled,
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
                                       int path_rewrite_enabled,
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
int st_storage_get_peer_mesh_acl(const char *path, long long id, st_storage_peer_mesh_acl *acl);
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

#endif
