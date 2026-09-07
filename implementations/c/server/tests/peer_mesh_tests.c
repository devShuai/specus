#define _POSIX_C_SOURCE 200809L

#include "peer_mesh.h"
#include "storage.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    char target[128];
    char source[128];
    char message[8192];
} captured_signal;

typedef struct {
    captured_signal signals[32];
    size_t count;
    int target_online;
} peer_test_context;

static int capture_signal(void *raw,
                          const char *target,
                          const char *source,
                          const char *message)
{
    peer_test_context *ctx = (peer_test_context *)raw;
    if (ctx->count >= sizeof(ctx->signals) / sizeof(ctx->signals[0])
        || strlen(target) >= sizeof(ctx->signals[0].target)
        || strlen(source) >= sizeof(ctx->signals[0].source)
        || strlen(message) >= sizeof(ctx->signals[0].message)) return -1;
    captured_signal *signal = &ctx->signals[ctx->count++];
    strcpy(signal->target, target);
    strcpy(signal->source, source);
    strcpy(signal->message, message);
    return 0;
}

static int is_online(void *raw, long long client_id, const char *client_name)
{
    (void)client_id;
    peer_test_context *ctx = (peer_test_context *)raw;
    return strcmp(client_name, "peer-source") == 0
        || (ctx->target_online && strcmp(client_name, "peer-target") == 0);
}

static int contains(const char *value, const char *needle)
{
    return value != NULL && strstr(value, needle) != NULL;
}

int main(void)
{
    char path[] = "/tmp/specus_c_peer_mesh_tests.XXXXXX";
    int temp_fd = mkstemp(path);
    if (temp_fd < 0) return 1;
    close(temp_fd);
    unlink(path);
    setenv("SPECUS_PEER_MESH_ENABLED", "true", 1);
    setenv("SPECUS_PEER_MESH_CIDR", "100.96.0.0/11", 1);
    setenv("SPECUS_PEER_MESH_SESSION_TTL_SECONDS", "3600", 1);
    if (st_storage_init(path, 0) != 0) return 1;

    st_storage_client source;
    st_storage_client target;
    st_storage_client denied;
    st_storage_peer_mesh_device source_device;
    st_storage_peer_mesh_device target_device;
    if (st_storage_upsert_client(path, 0, "tenant-peer", "peer-source", "owner", 1, 60, &source) != 0
        || st_storage_upsert_client(path, 0, "tenant-peer", "peer-target", "owner", 1, 60, &target) != 0
        || st_storage_upsert_client(path, 0, "tenant-peer", "peer-denied", "other", 1, 60, &denied) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &source, 1, &source_device) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &target, 1, &target_device) != 0) {
        fprintf(stderr, "peer mesh fixture setup failed\n");
        return 1;
    }
    if (source_device.virtual_ip[0] == '\0' || target_device.virtual_ip[0] == '\0'
        || strcmp(source_device.virtual_ip, target_device.virtual_ip) == 0
        || strcmp(source_device.cidr, "100.96.0.0/11") != 0) {
        fprintf(stderr, "peer mesh virtual IP allocation mismatch\n");
        return 1;
    }
    st_storage_peer_mesh_service service;
    memset(&service, 0, sizeof(service));
    snprintf(service.tenant_id, sizeof(service.tenant_id), "%s", source.tenant_id);
    service.client_id = source.id;
    snprintf(service.client_name, sizeof(service.client_name), "%s", source.client_name);
    snprintf(service.service_id, sizeof(service.service_id), "service-http-1");
    snprintf(service.name, sizeof(service.name), "Local HTTP");
    snprintf(service.description, sizeof(service.description), "Peer-only test service");
    snprintf(service.transport, sizeof(service.transport), "tcp");
    snprintf(service.application, sizeof(service.application), "http");
    snprintf(service.target_host, sizeof(service.target_host), "127.0.0.1");
    service.target_port = 8080;
    service.published_port = 18080;
    snprintf(service.path, sizeof(service.path), "/");
    service.enabled = 1;
    snprintf(service.visibility, sizeof(service.visibility), "OWNER");
    if (st_storage_upsert_peer_mesh_service_sharing(path, source.tenant_id, 1, 1, "admin", NULL) != 0
        || st_storage_upsert_peer_mesh_service(path, &service, NULL) != 0) {
        fprintf(stderr, "peer service fixture setup failed\n");
        return 1;
    }

    peer_test_context context = {0};
    context.target_online = 1;
    st_peer_mesh_runtime runtime = {path, capture_signal, is_online, &context, 7001, 2};
    if (st_peer_mesh_push_on_login(&runtime, source.client_name) != 0
        || context.count < 2
        || !contains(context.signals[0].message, "\"type\":\"peer-config\"")
        || !contains(context.signals[0].message, "\"peerServiceDiscoveryVersion\":2")
        || !contains(context.signals[0].message, "\"configuredEnabled\":true")
        || !contains(context.signals[0].message, "\"serviceId\":\"service-http-1\"")
        || !contains(context.signals[0].message, target_device.virtual_ip)) {
        fprintf(stderr, "peer mesh login config/roster push mismatch\n");
        return 1;
    }

    context.count = 0;
    const char *service_report =
        "{\"type\":\"service-report\",\"enabled\":true,\"revision\":1,"
        "\"instanceId\":\"instance-a\",\"services\":[{\"serviceId\":\"service-http-1\","
        "\"name\":\"Local HTTP\",\"description\":\"Peer-only test service\","
        "\"transport\":\"tcp\",\"application\":\"http\",\"publishedPort\":18080,\"path\":\"/\"}],"
        "\"stats\":[{\"serviceId\":\"service-http-1\",\"bytesIn\":12,\"bytesOut\":34,"
        "\"activeConnections\":2,\"totalConnections\":5}],"
        "\"mdnsCandidates\":[{\"name\":\"Local Web\",\"application\":\"http\","
        "\"targetHost\":\"localhost\",\"targetPort\":8080},"
        "{\"name\":\"Public Web\",\"transport\":\"tcp\",\"application\":\"http\","
        "\"targetHost\":\"198.51.100.9\",\"targetPort\":8081}]}";
    if (st_peer_mesh_handle_control(&runtime, source.client_name, NULL, service_report) != 0
        || context.count != 1 || strcmp(context.signals[0].target, target.client_name) != 0
        || !contains(context.signals[0].message, "\"type\":\"service-catalog\"")
        || !contains(context.signals[0].message, "\"publisherSessionId\":7001")
        || !contains(context.signals[0].message, "\"serviceId\":\"service-http-1\"")
        || contains(context.signals[0].message, "targetHost")) {
        fprintf(stderr, "peer service catalog fanout mismatch\n");
        return 1;
    }
    st_peer_mesh_mdns_candidate mdns[8];
    size_t mdns_count = 0U;
    st_peer_mesh_service_instance instances[8];
    size_t instance_count = 0U;
    if (st_peer_mesh_list_mdns_candidates(source.tenant_id, source.id, mdns, 8U, &mdns_count) != 0
        || mdns_count != 1 || strcmp(mdns[0].target_host, "127.0.0.1") != 0
        || strcmp(mdns[0].transport, "tcp") != 0
        || st_peer_mesh_list_service_instances(source.tenant_id, source.id, service.service_id,
                                               instances, 8U, &instance_count) != 0
        || instance_count != 1 || !instances[0].advertised || !instances[0].online
        || instances[0].bytes_in != 12 || instances[0].bytes_out != 34
        || instances[0].active_connections != 2 || instances[0].total_connections != 5) {
        fprintf(stderr, "peer service mDNS/stat catalog mismatch\n");
        return 1;
    }
    context.count = 0;
    if (st_peer_mesh_handle_control(&runtime, source.client_name, NULL, service_report) != 0
        || context.count != 0
        || st_peer_mesh_handle_control(&runtime, source.client_name, NULL,
            "{\"type\":\"service-report\",\"sourceClientId\":999,\"revision\":2,\"services\":[]}") == 0) {
        fprintf(stderr, "peer service report revision/envelope validation mismatch\n");
        return 1;
    }
    if (st_peer_mesh_handle_control(&runtime, source.client_name, NULL,
            "{\"type\":\"service-report\",\"enabled\":false,\"revision\":2,\"services\":[]}") != 0
        || context.count != 1 || !contains(context.signals[0].message, "\"services\":[]")) {
        fprintf(stderr, "peer service catalog withdrawal mismatch\n");
        return 1;
    }
    context.count = 0;
    if (st_peer_mesh_handle_control(&runtime, source.client_name, NULL,
            "{\"type\":\"service-report\",\"enabled\":true,\"revision\":3,"
            "\"instanceId\":\"instance-a\",\"services\":[{\"serviceId\":\"service-http-1\","
            "\"name\":\"Local HTTP\",\"description\":\"Peer-only test service\","
            "\"transport\":\"tcp\",\"application\":\"http\",\"publishedPort\":18080,\"path\":\"/\"}]}") != 0
        || context.count != 1) {
        fprintf(stderr, "peer service refresh fixture mismatch\n");
        return 1;
    }
    context.count = 0;
    if (st_storage_update_peer_mesh_device_enabled(path, &target, 0, &target_device) != 0
        || st_peer_mesh_refresh_tenant(&runtime, source.tenant_id) != 0) {
        fprintf(stderr, "peer service tenant refresh failed\n");
        return 1;
    }
    int saw_revoked_catalog = 0;
    for (size_t i = 0; i < context.count; ++i) {
        if (strcmp(context.signals[i].target, target.client_name) == 0
            && contains(context.signals[i].message, "\"type\":\"service-catalog\"")
            && contains(context.signals[i].message, "\"services\":[]")) {
            saw_revoked_catalog = 1;
        }
    }
    if (!saw_revoked_catalog
        || st_storage_update_peer_mesh_device_enabled(path, &target, 1, &target_device) != 0
        || st_peer_mesh_refresh_tenant(&runtime, source.tenant_id) != 0) {
        fprintf(stderr, "peer service permission revocation refresh mismatch\n");
        return 1;
    }
    context.count = 0;
    if (st_peer_mesh_handle_disconnect(&runtime, source.client_name) != 0
        || context.count != 1
        || !contains(context.signals[0].message, "\"publisherSessionId\":7001")
        || !contains(context.signals[0].message, "\"services\":[]")) {
        fprintf(stderr, "peer service disconnect withdrawal mismatch\n");
        return 1;
    }
    setenv("SPECUS_PEER_MESH_CATALOG_TTL_SECONDS", "1", 1);
    context.count = 0;
    if (st_peer_mesh_handle_control(&runtime, source.client_name, NULL,
            "{\"type\":\"service-report\",\"enabled\":true,\"revision\":4,"
            "\"instanceId\":\"instance-a\",\"services\":[{\"serviceId\":\"service-http-1\","
            "\"name\":\"Local HTTP\",\"description\":\"Peer-only test service\","
            "\"transport\":\"tcp\",\"application\":\"http\",\"publishedPort\":18080,\"path\":\"/\"}]}") != 0
        || context.count != 1) {
        fprintf(stderr, "peer service expiry fixture mismatch\n");
        return 1;
    }
    context.count = 0;
    sleep(1);
    if (st_peer_mesh_expire_catalogs(&runtime) != 0
        || context.count != 1
        || !contains(context.signals[0].message, "\"services\":[]")) {
        fprintf(stderr, "peer service catalog expiry mismatch\n");
        return 1;
    }
    unsetenv("SPECUS_PEER_MESH_CATALOG_TTL_SECONDS");

    context.count = 0;
    const char *candidates =
        "{\"type\":\"candidates\",\"sourceClientId\":999,\"sourceClientName\":\"spoof\","
        "\"sourceKeyEpoch\":\"epoch-a\",\"candidates\":[{\"type\":\"host\","
        "\"address\":\"192.0.2.10\",\"port\":40000}],\"dataFrameVersion\":2}";
    if (st_peer_mesh_handle_control(&runtime, source.client_name, target.client_name, candidates) != 0
        || context.count != 2
        || strcmp(context.signals[0].target, source.client_name) != 0
        || !contains(context.signals[0].message, "\"type\":\"session-grant\"")
        || !contains(context.signals[0].message, "\"token\":")
        || strcmp(context.signals[1].target, target.client_name) != 0
        || !contains(context.signals[1].message, "\"sourceClientName\":\"peer-source\"")
        || contains(context.signals[1].message, "spoof")
        || !contains(context.signals[1].message, "\"candidates\":[")
        || !contains(context.signals[1].message, "\"sourceKeyEpoch\":\"epoch-a\"")) {
        fprintf(stderr, "peer mesh candidate/session forwarding mismatch\n");
        return 1;
    }

    st_storage_peer_mesh_session sessions[8];
    size_t session_count = 0;
    if (st_storage_list_peer_mesh_sessions_visible(path, "tenant-peer", "owner", 1, 1, 8,
                                                   sessions, 8, &session_count) != 0
        || session_count != 1 || strcmp(sessions[0].status, "NEGOTIATING") != 0) {
        fprintf(stderr, "peer mesh session creation mismatch\n");
        return 1;
    }
    char report[512];
    snprintf(report, sizeof(report),
             "{\"type\":\"path-report\",\"sessionId\":%lld,\"pathType\":\"DIRECT\","
             "\"rttMillis\":12,\"localEndpoint\":\"10.0.0.1:1\",\"remoteEndpoint\":\"10.0.0.2:2\"}",
             sessions[0].id);
    if (st_peer_mesh_handle_control(&runtime, source.client_name, NULL, report) != 0
        || st_storage_get_peer_mesh_session(path, "tenant-peer", sessions[0].id, &sessions[0]) != 0
        || strcmp(sessions[0].status, "ACTIVE") != 0 || sessions[0].rtt_millis != 12) {
        fprintf(stderr, "peer mesh path report mismatch\n");
        return 1;
    }
    snprintf(report, sizeof(report),
             "{\"type\":\"traffic-report\",\"sessionId\":%lld,\"directBytes\":123}",
             sessions[0].id);
    if (st_peer_mesh_handle_control(&runtime, target.client_name, NULL, report) != 0
        || st_storage_get_peer_mesh_session(path, "tenant-peer", sessions[0].id, &sessions[0]) != 0
        || sessions[0].direct_bytes != 123 || strcmp(sessions[0].path_type, "DIRECT") != 0) {
        fprintf(stderr, "peer mesh traffic report mismatch\n");
        return 1;
    }
    if (st_peer_mesh_handle_control(&runtime, source.client_name, NULL,
            "{\"type\":\"device-report\",\"natType\":\"PORT_RESTRICTED\","
            "\"natMappingBehavior\":\"ENDPOINT_INDEPENDENT\","
            "\"natFilteringBehavior\":\"ADDRESS_AND_PORT_DEPENDENT\","
            "\"natBehaviorDiscovery\":\"RFC5780\","
            "\"lastEndpoint\":\"198.51.100.1:50000\",\"virtualDeviceStatus\":\"UP\"}") != 0
        || st_storage_get_peer_mesh_device_by_client(path, "tenant-peer", source.id, &source_device) != 0
        || strcmp(source_device.nat_type, "PORT_RESTRICTED") != 0
        || strcmp(source_device.nat_mapping_behavior, "ENDPOINT_INDEPENDENT") != 0
        || strcmp(source_device.nat_filtering_behavior, "ADDRESS_AND_PORT_DEPENDENT") != 0
        || strcmp(source_device.nat_behavior_discovery, "RFC5780") != 0
        || strcmp(source_device.virtual_device_status, "UP") != 0) {
        fprintf(stderr, "peer mesh device report mismatch\n");
        return 1;
    }
    if (st_peer_mesh_handle_control(&runtime, source.client_name, denied.client_name,
                                    "{\"type\":\"offer\"}") == 0) {
        fprintf(stderr, "peer mesh denied target was accepted\n");
        return 1;
    }
    context.target_online = 0;
    if (st_peer_mesh_handle_control(&runtime, source.client_name, target.client_name,
                                    "{\"type\":\"offer\"}") == 0) {
        fprintf(stderr, "peer mesh offline target was accepted\n");
        return 1;
    }

    snprintf(report, sizeof(report), "{\"type\":\"close\",\"sessionId\":%lld}", sessions[0].id);
    if (st_peer_mesh_handle_control(&runtime, source.client_name, NULL, report) != 0
        || st_storage_get_peer_mesh_session(path, "tenant-peer", sessions[0].id, &sessions[0]) != 0
        || strcmp(sessions[0].status, "CLOSED") != 0) {
        fprintf(stderr, "peer mesh close mismatch\n");
        return 1;
    }

    unlink(path);
    printf("peer mesh tests passed\n");
    return 0;
}
