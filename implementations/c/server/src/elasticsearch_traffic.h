#ifndef SPECUS_ELASTICSEARCH_TRAFFIC_H
#define SPECUS_ELASTICSEARCH_TRAFFIC_H

#include "storage.h"

int st_elasticsearch_traffic_enabled_current(void);
int st_elasticsearch_traffic_initialize_current(void);
void st_elasticsearch_traffic_reset_for_tests(void);

int st_elasticsearch_record_http(const st_storage_http_exchange_record *record);
int st_elasticsearch_list_http(const char *database_path,
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
int st_elasticsearch_record_tcp(const st_storage_tcp_frame_record *record);
int st_elasticsearch_list_tcp(const char *database_path,
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
int st_elasticsearch_get_tcp(const char *database_path,
                             long long id,
                             const char *tenant_id,
                             const char *owner_username,
                             int include_all_clients,
                             st_storage_tcp_frame *frame);
int st_elasticsearch_list_tcp_stream(const char *database_path,
                                     const char *channel_id,
                                     const char *tenant_id,
                                     const char *owner_username,
                                     int include_all_clients,
                                     int limit,
                                     st_storage_tcp_frame *items,
                                     size_t max_items,
                                     size_t *item_count);

#endif
