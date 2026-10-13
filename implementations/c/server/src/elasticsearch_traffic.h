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
/* One visible exchange with its headers and previews (the list leaves them out). */
int st_elasticsearch_get_http(const char *database_path,
                              long long exchange_id,
                              const char *tenant_id,
                              const char *owner_username,
                              int include_all_clients,
                              st_storage_http_exchange *item,
                              int *found);
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
/* One page of a channel's frames in capture order (Java findStream sorts by id, ascending). */
int st_elasticsearch_list_tcp_stream(const char *database_path,
                                     const char *channel_id,
                                     const char *tenant_id,
                                     const char *owner_username,
                                     int include_all_clients,
                                     int page,
                                     int size,
                                     st_storage_tcp_frame *items,
                                     size_t max_items,
                                     size_t *item_count,
                                     long long *total_count);

/*
 * The write queue (Java TrafficInspectionService): recorded documents wait in memory and a
 * background writer sends them in _bulk batches. flush sends one batch of each kind now (Java
 * flush(), the flush=true query parameter); shutdown stops the writer and sends what is left.
 */
typedef struct {
    int pending_http;
    int pending_tcp;
    long long dropped_http;
    long long dropped_tcp;
    /* ISO-8601 UTC of the last flush, "" before the first. */
    char last_flushed_at[40];
} st_elasticsearch_traffic_snapshot;

void st_elasticsearch_traffic_flush(void);
void st_elasticsearch_traffic_shutdown(void);
void st_elasticsearch_traffic_snapshot_current(st_elasticsearch_traffic_snapshot *snapshot);

#endif
