#define _POSIX_C_SOURCE 200809L

#include "elasticsearch_traffic.h"
#include "storage.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc != 2 || st_storage_init(argv[1], 1) != 0) return 1;
    st_storage_client client;
    if (st_storage_get_client_by_name(argv[1], "Demo client", &client) != 0) return 1;
    if (st_elasticsearch_traffic_initialize_current() != 0) return 1;

    static const uint8_t request_body[] = "request-items";
    static const uint8_t response_body[] = "{\"items\":[1]}";
    st_storage_http_exchange_record http = {
        .tenant_id = "default",
        .client_id = client.id,
        .client_name = client.client_name,
        .route = "api",
        .resource_id = 77,
        .resource_name = "API route",
        .method = "POST",
        .relative_path = "/v1/items",
        .raw_query = "page=1",
        .status_code = 201,
        .success = 1,
        .remote_address = "127.0.0.1",
        .request_bytes = (long long)sizeof(request_body) - 1,
        .response_bytes = (long long)sizeof(response_body) - 1,
        .elapsed_ms = 12,
        .request_content_type = "text/plain",
        .response_content_type = "application/json",
        .request_headers = "Content-Type: text/plain",
        .response_headers = "Content-Type: application/json",
        .request_body = request_body,
        .request_body_len = sizeof(request_body) - 1,
        .response_body = response_body,
        .response_body_len = sizeof(response_body) - 1,
        .captured_at = "2026-08-28T01:02:03Z"
    };
    if (st_storage_record_http_exchange(argv[1], &http) != 0) return 1;

    st_storage_http_exchange exchanges[4];
    size_t exchange_count = 0;
    long long total = 0;
    if (st_storage_list_http_exchanges_visible(argv[1], client.id, "api", "json", "path", "items",
                                               "default", "admin", 1, 0, 10,
                                               exchanges, 4, &exchange_count, &total) != 0
        || total != 1 || exchange_count != 1 || exchanges[0].status_code != 201
        || strcmp(exchanges[0].relative_path, "/v1/items") != 0) {
        fprintf(stderr, "Elasticsearch HTTP traffic round trip mismatch\n");
        return 1;
    }

    static const uint8_t payload[] = {0x00, 0x01, 0xfe, 0xff, 'x'};
    st_storage_tcp_frame_record tcp = {
        .tenant_id = "default",
        .client_id = client.id,
        .client_name = client.client_name,
        .listen_port = 8443,
        .resource_id = 88,
        .resource_name = "TLS mapping",
        .channel_id = "channel-es-1",
        .direction = "PUBLIC_TO_CLIENT",
        .remote_address = "127.0.0.1:50000",
        .source_address = "127.0.0.1",
        .source_port = 50000,
        .destination_address = "127.0.0.1",
        .destination_port = 8443,
        .stream_offset = 10,
        .frame_index = 2,
        .payload_data = payload,
        .payload_data_len = sizeof(payload),
        .frame_time = "2026-08-28T01:02:04Z"
    };
    if (st_storage_record_tcp_frame(argv[1], &tcp) != 0) return 1;
    st_storage_tcp_frame frames[4];
    size_t frame_count = 0;
    total = 0;
    if (st_storage_list_tcp_frames_visible(argv[1], client.id, 8443, "default", "admin", 1,
                                           0, 10, frames, 4, &frame_count, &total) != 0
        || total != 1 || frame_count != 1 || frames[0].payload_bytes != (long long)sizeof(payload)) {
        fprintf(stderr, "Elasticsearch TCP traffic list mismatch\n");
        return 1;
    }
    long long frame_id = frames[0].id;
    st_storage_tcp_frame detail;
    if (st_storage_get_tcp_frame_visible(argv[1], frame_id, "default", "admin", 1, &detail) != 0
        || detail.payload_data_len != sizeof(payload)
        || memcmp(detail.payload_data, payload, sizeof(payload)) != 0) {
        fprintf(stderr, "Elasticsearch TCP detail payload mismatch\n");
        st_storage_tcp_frame_free(&detail);
        return 1;
    }
    st_storage_tcp_frame_free(&detail);
    frame_count = 0;
    if (st_storage_list_tcp_stream_visible(argv[1], "channel-es-1", "default", "admin", 1,
                                           10, frames, 4, &frame_count) != 0
        || frame_count != 1 || frames[0].frame_index != 2) {
        fprintf(stderr, "Elasticsearch TCP stream mismatch\n");
        return 1;
    }
    for (size_t i = 0; i < frame_count; ++i) st_storage_tcp_frame_free(&frames[i]);

    if (setenv("SPECUS_ELASTICSEARCH_HTTP_MAX_STORE_SIZE", "1", 1) != 0) return 1;
    st_elasticsearch_traffic_reset_for_tests();
    if (st_storage_record_http_exchange(argv[1], &http) != 0) return 1;
    exchange_count = 0;
    total = -1;
    if (st_storage_list_http_exchanges_visible(argv[1], client.id, NULL, NULL, NULL, NULL,
                                               "default", "admin", 1, 0, 10,
                                               exchanges, 4, &exchange_count, &total) != 0
        || total != 0 || exchange_count != 0) {
        fprintf(stderr, "Elasticsearch size retention did not delete oldest documents\n");
        return 1;
    }
    puts("elasticsearch traffic tests passed");
    return 0;
}
