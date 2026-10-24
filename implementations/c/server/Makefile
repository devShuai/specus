CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -O2
CPPFLAGS ?= -Isrc
LDFLAGS ?= -lpthread -lz -lsqlite3 -lssl -lcrypto -lcurl -lhiredis -lutf8proc

# hiredis_ssl is optional, as in CMakeLists.txt: with its pkg-config file (hiredis 1.0 or later),
# rediss:// and rediss-sentinel:// work and their tests run; without it those URIs fail startup.
HIREDIS_SSL_LIBS := $(shell pkg-config --libs hiredis_ssl 2>/dev/null)
ifneq ($(HIREDIS_SSL_LIBS),)
CPPFLAGS += -DST_HAVE_HIREDIS_SSL
LDFLAGS += $(HIREDIS_SSL_LIBS)
REDIS_TLS_TEST_COMMANDS = bash scripts/public_coordination_tls_test.sh $(PUBLIC_COORDINATION_TESTS) && \
	bash scripts/public_coordination_sentinel_test.sh $(PUBLIC_COORDINATION_SENTINEL_TESTS) tls
else
REDIS_TLS_TEST_COMMANDS = echo "hiredis_ssl not found: Redis TLS tests skipped"
endif

# libbrotlidec is optional, as in CMakeLists.txt: with its pkg-config file, Content-Encoding br is
# decoded (ST_HAVE_BROTLI); libbrotlienc, when present too, lets the tests compress br fixtures.
BROTLIDEC_LIBS := $(shell pkg-config --libs libbrotlidec 2>/dev/null)
BROTLIENC_LIBS := $(shell pkg-config --libs libbrotlienc 2>/dev/null)
ifneq ($(BROTLIDEC_LIBS),)
CPPFLAGS += -DST_HAVE_BROTLI $(shell pkg-config --cflags libbrotlidec 2>/dev/null)
LDFLAGS += $(BROTLIDEC_LIBS)
ifneq ($(BROTLIENC_LIBS),)
BROTLI_TEST_FLAGS := -DST_HAVE_BROTLI_ENCODER $(shell pkg-config --cflags libbrotlienc 2>/dev/null)
BROTLI_TEST_LIBS := $(BROTLIENC_LIBS)
endif
endif

BUILD_DIR := build
CORE_OBJS := $(BUILD_DIR)/admin_http.o $(BUILD_DIR)/client_address.o $(BUILD_DIR)/client_auth_nonce.o $(BUILD_DIR)/client_package.o $(BUILD_DIR)/connectivity_check.o $(BUILD_DIR)/crypto.o $(BUILD_DIR)/decompression_limits.o $(BUILD_DIR)/elasticsearch_traffic.o $(BUILD_DIR)/github_release.o $(BUILD_DIR)/http_client.o $(BUILD_DIR)/json.o $(BUILD_DIR)/login_rate_limiter.o $(BUILD_DIR)/media_capture.o $(BUILD_DIR)/object_storage.o $(BUILD_DIR)/oidc.o $(BUILD_DIR)/password_hash.o $(BUILD_DIR)/peer_egress.o $(BUILD_DIR)/peer_mesh.o $(BUILD_DIR)/protocol.o $(BUILD_DIR)/public_coordination.o $(BUILD_DIR)/public_discovery.o $(BUILD_DIR)/public_room.o $(BUILD_DIR)/registration.o $(BUILD_DIR)/security.o $(BUILD_DIR)/security_baseline.o $(BUILD_DIR)/storage.o $(BUILD_DIR)/stun_turn.o $(BUILD_DIR)/tls_transport.o $(BUILD_DIR)/traffic_capture.o $(BUILD_DIR)/turn_auth.o $(BUILD_DIR)/stream_tombstones.o $(BUILD_DIR)/workbench.o $(BUILD_DIR)/http_share.o $(BUILD_DIR)/product_metrics.o $(BUILD_DIR)/upstream_browser_headers.o
SERVER := $(BUILD_DIR)/specus-server-c
CORE_OBJS += $(BUILD_DIR)/url_decode.o
URL_DECODE_TESTS := $(BUILD_DIR)/specus_c_url_decode_tests
CONNECTIVITY_LIFETIME_TESTS := $(BUILD_DIR)/specus_c_connectivity_lifetime_tests
CONNECTIVITY_SETTER_TESTS := $(BUILD_DIR)/specus_c_connectivity_setter_tests
CORE_OBJS += $(BUILD_DIR)/instant.o $(BUILD_DIR)/instant_storage.o $(BUILD_DIR)/java_uri.o
CORE_OBJS += $(BUILD_DIR)/redis_uri.o
CORE_OBJS += $(BUILD_DIR)/websocket_ticket.o
CORE_OBJS += $(BUILD_DIR)/traffic_usage.o
CORE_OBJS += $(BUILD_DIR)/metrics.o
INSTANT_TESTS := $(BUILD_DIR)/specus_c_instant_tests
INSTANT_MIGRATION_TESTS := $(BUILD_DIR)/specus_c_instant_migration_tests
CONNECTION_TIME_REFERENCE_TESTS := $(BUILD_DIR)/specus_c_connection_time_reference_tests
AUTH_EXPIRY_REFERENCE_TESTS := $(BUILD_DIR)/specus_c_auth_expiry_reference_tests
WEBSOCKET_TICKET_STORAGE_REFERENCE_TESTS := $(BUILD_DIR)/specus_c_websocket_ticket_storage_reference_tests
ADMIN_TESTS := $(BUILD_DIR)/specus_c_admin_http_tests
DIRECT_WEBSOCKET_TESTS := $(BUILD_DIR)/specus_c_direct_websocket_tests
CLIENT_ADDRESS_TESTS := $(BUILD_DIR)/specus_c_client_address_tests
CLIENT_AUTH_NONCE_TESTS := $(BUILD_DIR)/specus_c_client_auth_nonce_tests
CLIENT_PACKAGE_TESTS := $(BUILD_DIR)/specus_c_client_package_tests
CLIENT_PACKAGE_CLOCK_TESTS := $(BUILD_DIR)/specus_c_client_package_clock_tests
CONNECTIVITY_CHECK_TESTS := $(BUILD_DIR)/specus_c_connectivity_check_tests
CONNECTIVITY_HTTP_VECTOR_TESTS := $(BUILD_DIR)/specus_c_connectivity_http_vector_tests
CONNECTIVITY_RESOURCE_WIRE_TESTS := $(BUILD_DIR)/specus_c_connectivity_resource_wire_tests
CONNECTIVITY_RATE_HTTP_TESTS := $(BUILD_DIR)/specus_c_connectivity_rate_http_tests
CRYPTO_TESTS := $(BUILD_DIR)/specus_c_crypto_tests
DECOMPRESSION_LIMITS_TESTS := $(BUILD_DIR)/specus_c_decompression_limits_tests
ELASTICSEARCH_TRAFFIC_TESTS := $(BUILD_DIR)/specus_c_elasticsearch_traffic_tests
GITHUB_RELEASE_TESTS := $(BUILD_DIR)/specus_c_github_release_tests
JSON_TESTS := $(BUILD_DIR)/specus_c_json_tests
HTTP_CLIENT_TESTS := $(BUILD_DIR)/specus_c_http_client_tests
HTTP_SHARE_TESTS := $(BUILD_DIR)/specus_c_http_share_tests
LOGIN_RATE_LIMITER_TESTS := $(BUILD_DIR)/specus_c_login_rate_limiter_tests
MEDIA_CAPTURE_TESTS := $(BUILD_DIR)/specus_c_media_capture_tests
OBJECT_STORAGE_TESTS := $(BUILD_DIR)/specus_c_object_storage_tests
OIDC_TESTS := $(BUILD_DIR)/specus_c_oidc_tests
PASSWORD_HASH_TESTS := $(BUILD_DIR)/specus_c_password_hash_tests
PEER_EGRESS_TESTS := $(BUILD_DIR)/specus_c_peer_egress_tests
PEER_MESH_TESTS := $(BUILD_DIR)/specus_c_peer_mesh_tests
PEER_MESH_E2E_TESTS := $(BUILD_DIR)/specus_c_peer_mesh_e2e_tests
PRODUCT_METRICS_TESTS := $(BUILD_DIR)/specus_c_product_metrics_tests
PUBLIC_COORDINATION_TESTS := $(BUILD_DIR)/specus_c_public_coordination_tests
PUBLIC_COORDINATION_SENTINEL_TESTS := $(BUILD_DIR)/specus_c_public_coordination_sentinel_tests
PUBLIC_CLUSTER_CODEC_TESTS := $(BUILD_DIR)/specus_c_public_cluster_codec_tests
PUBLIC_TRANSFER_TESTS := $(BUILD_DIR)/specus_c_public_transfer_tests
PROTOCOL_TESTS := $(BUILD_DIR)/specus_c_protocol_fixture_tests
SECURITY_TESTS := $(BUILD_DIR)/specus_c_security_tests
SECURITY_BASELINE_TESTS := $(BUILD_DIR)/specus_c_security_baseline_tests
SESSION_LIFECYCLE_TESTS := $(BUILD_DIR)/specus_c_session_lifecycle_tests
SECURITY_RULES_TESTS := $(BUILD_DIR)/specus_c_security_rules_tests
HTTP_ROUTE_LIFECYCLE_TESTS := $(BUILD_DIR)/specus_c_http_route_lifecycle_tests
CLIENT_ROUTE_SCALE_TESTS := $(BUILD_DIR)/specus_c_client_route_scale_tests
NAT_SIZING_REFERENCE_TESTS := $(BUILD_DIR)/specus_c_nat_sizing_reference_tests
SQLITE_REFERENCE_TESTS := $(BUILD_DIR)/specus_c_sqlite_reference_tests
NAT_STREAM_TESTS := $(BUILD_DIR)/specus_c_nat_stream_tests
CONNECTION_ARCHIVE_TESTS := $(BUILD_DIR)/specus_c_connection_archive_tests
TRAFFIC_DETAIL_API_TESTS := $(BUILD_DIR)/specus_c_traffic_detail_api_tests
CLIENT_MESSAGES_TESTS := $(BUILD_DIR)/specus_c_client_messages_tests
MANAGEMENT_WS_BACKPRESSURE_TESTS := $(BUILD_DIR)/specus_c_management_ws_backpressure_tests
DIRECT_WEBSOCKET_BACKPRESSURE_TESTS := $(BUILD_DIR)/specus_c_direct_websocket_backpressure_tests
MANAGEMENT_LISTS_TESTS := $(BUILD_DIR)/specus_c_management_lists_tests
MANAGEMENT_CRUD_TESTS := $(BUILD_DIR)/specus_c_management_crud_tests
MAILBOX_VECTOR_FILE := ../../../protocol/test-vectors/registration-mailbox-forms-v1.json
EMAIL_MASK_VECTOR_FILE := ../../../protocol/test-vectors/registration-email-mask-v1.json
EMAIL_NUL_VECTOR_FILE := ../../../protocol/test-vectors/registration-email-nul-v1.json
PEER_MESH_API_TESTS := $(BUILD_DIR)/specus_c_peer_mesh_api_tests
MANAGEMENT_OVERVIEW_TESTS := $(BUILD_DIR)/specus_c_management_overview_tests
HTTP_WEBSOCKET_ROUTING_TESTS := $(BUILD_DIR)/specus_c_http_websocket_routing_tests
SERVER_HARNESS_TESTS := $(BUILD_DIR)/specus_c_server_harness_tests
WEBSOCKET_TICKET_API_TESTS := $(BUILD_DIR)/specus_c_websocket_ticket_request_tests $(BUILD_DIR)/specus_c_websocket_ticket_quota_tests $(BUILD_DIR)/specus_c_websocket_ticket_account_tests
STORAGE_TESTS := $(BUILD_DIR)/specus_c_storage_tests
SESSION_ORDER_TESTS := $(BUILD_DIR)/specus_c_session_order_tests
SESSION_SCOPE_TESTS := $(BUILD_DIR)/specus_c_session_scope_tests
STUN_TURN_TESTS := $(BUILD_DIR)/specus_c_stun_turn_tests
STUN_TURN_SCALE_TESTS := $(BUILD_DIR)/specus_c_stun_turn_scale_tests
TLS_TRANSPORT_TESTS := $(BUILD_DIR)/specus_c_tls_transport_tests
SEMANTIC_VERSION_TESTS := $(BUILD_DIR)/specus_c_semantic_version_tests
TRAFFIC_CAPTURE_TESTS := $(BUILD_DIR)/specus_c_traffic_capture_tests
TURNSTILE_VERIFIER_TESTS := $(BUILD_DIR)/specus_c_turnstile_verifier_tests
UPSTREAM_BROWSER_HEADERS_TESTS := $(BUILD_DIR)/specus_c_upstream_browser_headers_tests
WORKBENCH_TESTS := $(BUILD_DIR)/specus_c_workbench_tests
MANAGEMENT_ACCOUNTS_TESTS := $(BUILD_DIR)/specus_c_management_accounts_tests
TESTS := $(ADMIN_TESTS) $(DIRECT_WEBSOCKET_TESTS) $(CLIENT_ADDRESS_TESTS) $(CLIENT_AUTH_NONCE_TESTS) $(CONNECTIVITY_CHECK_TESTS) $(CRYPTO_TESTS) $(DECOMPRESSION_LIMITS_TESTS) $(GITHUB_RELEASE_TESTS) $(HTTP_CLIENT_TESTS) $(JSON_TESTS) $(LOGIN_RATE_LIMITER_TESTS) $(OBJECT_STORAGE_TESTS) $(OIDC_TESTS) $(PASSWORD_HASH_TESTS) $(PEER_EGRESS_TESTS) $(PEER_MESH_TESTS) $(PROTOCOL_TESTS) $(SECURITY_TESTS) $(SECURITY_BASELINE_TESTS) $(STORAGE_TESTS) $(STUN_TURN_TESTS) $(TLS_TRANSPORT_TESTS) $(WORKBENCH_TESTS) $(MANAGEMENT_ACCOUNTS_TESTS) $(HTTP_SHARE_TESTS) $(SEMANTIC_VERSION_TESTS) $(TRAFFIC_CAPTURE_TESTS) $(TURNSTILE_VERIFIER_TESTS) $(UPSTREAM_BROWSER_HEADERS_TESTS) $(CLIENT_PACKAGE_TESTS) $(PUBLIC_CLUSTER_CODEC_TESTS) $(PUBLIC_TRANSFER_TESTS)
ALL_TESTS := $(TESTS) $(PUBLIC_COORDINATION_TESTS) $(PUBLIC_COORDINATION_SENTINEL_TESTS) $(ELASTICSEARCH_TRAFFIC_TESTS) $(MEDIA_CAPTURE_TESTS) $(SESSION_LIFECYCLE_TESTS) $(SECURITY_RULES_TESTS) $(HTTP_ROUTE_LIFECYCLE_TESTS) $(NAT_STREAM_TESTS) $(PRODUCT_METRICS_TESTS) $(CONNECTION_ARCHIVE_TESTS) $(HTTP_WEBSOCKET_ROUTING_TESTS) $(TRAFFIC_DETAIL_API_TESTS) $(CLIENT_MESSAGES_TESTS) $(MANAGEMENT_WS_BACKPRESSURE_TESTS) $(DIRECT_WEBSOCKET_BACKPRESSURE_TESTS) $(MANAGEMENT_LISTS_TESTS) $(MANAGEMENT_CRUD_TESTS) $(PEER_MESH_API_TESTS) $(MANAGEMENT_OVERVIEW_TESTS)
ALL_TESTS += $(PEER_MESH_E2E_TESTS) $(CLIENT_ROUTE_SCALE_TESTS)
ALL_TESTS += $(NAT_SIZING_REFERENCE_TESTS)
ALL_TESTS += $(SQLITE_REFERENCE_TESTS)
ALL_TESTS += $(INSTANT_TESTS) $(INSTANT_MIGRATION_TESTS) $(CONNECTION_TIME_REFERENCE_TESTS)
ALL_TESTS += $(AUTH_EXPIRY_REFERENCE_TESTS)
ALL_TESTS += $(WEBSOCKET_TICKET_STORAGE_REFERENCE_TESTS)
TESTS += $(CONNECTIVITY_LIFETIME_TESTS) $(CONNECTIVITY_SETTER_TESTS)
ALL_TESTS += $(CONNECTIVITY_LIFETIME_TESTS) $(CONNECTIVITY_SETTER_TESTS)
UNICODE_JAVA21_TESTS := $(BUILD_DIR)/specus_c_unicode_java21_tests
UNICODE_JAVA21_VECTORS := ../../../protocol/test-vectors/java21-root-case-v1.json
CORE_OBJS += $(BUILD_DIR)/unicode_java21.o
ALL_TESTS += $(UNICODE_JAVA21_TESTS)
JAVA_URI_TESTS := $(BUILD_DIR)/specus_c_java_uri_tests
DOWNLOAD_LINK_VECTOR_FILE := ../../../protocol/test-vectors/client-download-link-validation-v1.json
ALL_TESTS += $(JAVA_URI_TESTS)
TESTS += $(CONNECTIVITY_HTTP_VECTOR_TESTS)
ALL_TESTS += $(CONNECTIVITY_HTTP_VECTOR_TESTS)
ALL_TESTS += $(CONNECTIVITY_RESOURCE_WIRE_TESTS)
ALL_TESTS += $(CONNECTIVITY_RATE_HTTP_TESTS)
TESTS += $(CLIENT_PACKAGE_CLOCK_TESTS)
ALL_TESTS += $(CLIENT_PACKAGE_CLOCK_TESTS)
TESTS += $(STUN_TURN_SCALE_TESTS)
ALL_TESTS += $(STUN_TURN_SCALE_TESTS)
CONTROL_WRITE_REFERENCE_TESTS := $(BUILD_DIR)/specus_c_control_write_reference_tests
SESSION_REFERENCE_SERVER := $(BUILD_DIR)/specus_c_session_reference_server
SESSION_REFERENCE_TESTS := $(BUILD_DIR)/specus_c_session_reference_tests
TESTS += $(CONTROL_WRITE_REFERENCE_TESTS)
ALL_TESTS += $(CONTROL_WRITE_REFERENCE_TESTS) $(SESSION_REFERENCE_SERVER) $(SESSION_REFERENCE_TESTS)
STREAM_FD_LIFETIME_TESTS := $(BUILD_DIR)/specus_c_stream_fd_lifetime_tests
TESTS += $(STREAM_FD_LIFETIME_TESTS)
ALL_TESTS += $(STREAM_FD_LIFETIME_TESTS)
HTTP_LOG_REASON_REFERENCE_TESTS := $(BUILD_DIR)/specus_c_http_log_reason_reference_tests
HTTP_RESET_REASON_REFERENCE_TESTS := $(BUILD_DIR)/specus_c_http_reset_reason_reference_tests
TESTS += $(HTTP_LOG_REASON_REFERENCE_TESTS)
ALL_TESTS += $(HTTP_LOG_REASON_REFERENCE_TESTS) $(HTTP_RESET_REASON_REFERENCE_TESTS)
TRAFFIC_USAGE_TESTS := $(BUILD_DIR)/specus_c_traffic_usage_tests
ALL_TESTS += $(TRAFFIC_USAGE_TESTS)
METRICS_TESTS := $(BUILD_DIR)/specus_c_metrics_tests
METRICS_ENDPOINT_TESTS := $(BUILD_DIR)/specus_c_metrics_endpoint_tests
TESTS += $(METRICS_TESTS)
ALL_TESTS += $(METRICS_TESTS) $(METRICS_ENDPOINT_TESTS)
HTTP_CONNECTOR_TESTS := $(BUILD_DIR)/specus_c_http_connector_tests
ALL_TESTS += $(HTTP_CONNECTOR_TESTS)

# This adverse clock view uses Linux's process-local preload, never the host clock.
ifeq ($(shell uname -s),Linux)
CONNECTIVITY_CLOCK_OFFSET := $(BUILD_DIR)/libspecus_connectivity_clock_offset.so
ALL_TESTS += $(CONNECTIVITY_CLOCK_OFFSET)
CONNECTIVITY_CLOCK_TEST_COMMAND = env LD_PRELOAD="$(abspath $(CONNECTIVITY_CLOCK_OFFSET))" SPECUS_NAT_STREAM_ONLY="connectivity NAT complete" $(NAT_STREAM_TESTS) $(SERVER)
HTTP_TIMEOUT_CLOCK_TEST_COMMAND = env LD_PRELOAD="$(abspath $(CONNECTIVITY_CLOCK_OFFSET))" SPECUS_NAT_STREAM_ONLY="SPECUS_HTTP_" $(NAT_STREAM_TESTS) $(SERVER)
NAT_PUSH_REFERENCE_SERVER := $(BUILD_DIR)/specus_c_nat_push_reference_server
NAT_PUSH_REFERENCE_TESTS := $(BUILD_DIR)/specus_c_nat_push_reference_tests
NAT_CONTROL_SIZE_VECTOR := ../../../protocol/test-vectors/nat-control-size-v1.json
ALL_TESTS += $(NAT_PUSH_REFERENCE_SERVER) $(NAT_PUSH_REFERENCE_TESTS)
NAT_PUSH_REFERENCE_TEST_COMMAND = $(NAT_PUSH_REFERENCE_TESTS) $(NAT_PUSH_REFERENCE_SERVER)
endif
TESTS += $(SESSION_ORDER_TESTS) $(SESSION_SCOPE_TESTS)
ALL_TESTS += $(SESSION_ORDER_TESTS) $(SESSION_SCOPE_TESTS)
TESTS += $(URL_DECODE_TESTS)
ALL_TESTS += $(URL_DECODE_TESTS)
REDIS_URI_TESTS := $(BUILD_DIR)/specus_c_redis_uri_tests
TESTS += $(REDIS_URI_TESTS)
ALL_TESTS += $(REDIS_URI_TESTS)

.PHONY: all test release clean
ALL_TESTS += $(SERVER_HARNESS_TESTS) $(WEBSOCKET_TICKET_API_TESTS)
TESTS += $(WEBSOCKET_TICKET_API_TESTS)
REGISTRATION_EXPIRY_TESTS := $(BUILD_DIR)/specus_c_registration_expiry_tests
ALL_TESTS += $(REGISTRATION_EXPIRY_TESTS)
TESTS += $(REGISTRATION_EXPIRY_TESTS)
PEER_SESSION_EXPIRY_TESTS := $(BUILD_DIR)/specus_c_peer_session_expiry_tests
ALL_TESTS += $(PEER_SESSION_EXPIRY_TESTS)
TESTS += $(PEER_SESSION_EXPIRY_TESTS)
PAIRING_EXPIRY_TESTS := $(BUILD_DIR)/specus_c_pairing_expiry_tests
ALL_TESTS += $(PAIRING_EXPIRY_TESTS)
TESTS += $(PAIRING_EXPIRY_TESTS)
TRANSFER_EXPIRY_TESTS := $(BUILD_DIR)/specus_c_transfer_expiry_tests
ALL_TESTS += $(TRANSFER_EXPIRY_TESTS)
TESTS += $(TRANSFER_EXPIRY_TESTS)
MEDIA_EXPIRY_TESTS := $(BUILD_DIR)/specus_c_media_expiry_tests
ALL_TESTS += $(MEDIA_EXPIRY_TESTS)

all: $(SERVER) $(ALL_TESTS)

$(BUILD_DIR)/libspecus_connectivity_clock_offset.so: tests/connectivity_clock_offset.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -shared $< -o $@

$(CLIENT_PACKAGE_CLOCK_TESTS): $(CORE_OBJS) tests/client_package_clock_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/client_package_clock_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: src/%.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/unicode_java21.o: src/unicode_java21.h src/unicode_java21_data.h
$(BUILD_DIR)/instant.o: src/instant.h
$(BUILD_DIR)/instant_storage.o $(BUILD_DIR)/storage.o $(BUILD_DIR)/object_storage.o $(BUILD_DIR)/public_room.o $(BUILD_DIR)/media_capture.o: src/instant.h src/instant_storage.h

$(BUILD_DIR)/connectivity_check.o: src/connectivity_check.h

$(UNICODE_JAVA21_TESTS): $(CORE_OBJS) tests/unicode_java21_tests.c $(UNICODE_JAVA21_VECTORS) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/unicode_java21_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(BUILD_DIR)/java_uri.o: src/java_uri.h
$(BUILD_DIR)/redis_uri.o: src/redis_uri.h src/java_uri.h
$(BUILD_DIR)/public_coordination.o: src/public_coordination.h src/redis_uri.h

$(JAVA_URI_TESTS): $(CORE_OBJS) tests/java_uri_tests.c $(DOWNLOAD_LINK_VECTOR_FILE) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/java_uri_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(SERVER): $(CORE_OBJS) src/main.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) src/main.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(CONTROL_WRITE_REFERENCE_TESTS): $(CORE_OBJS) src/main.c tests/control_write_reference_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/control_write_reference_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(STREAM_FD_LIFETIME_TESTS): $(CORE_OBJS) src/main.c tests/stream_fd_lifetime_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/stream_fd_lifetime_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(BUILD_DIR)/session_reference_main.o: src/main.c tests/session_reference_recv.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -include tests/session_reference_recv.h -Dst_peer_mesh_push_on_logout=st_fixture_peer_logout -Dst_product_metrics_milestone=st_fixture_milestone -c $< -o $@

$(SESSION_REFERENCE_SERVER): $(CORE_OBJS) $(BUILD_DIR)/session_reference_main.o tests/session_reference_observer.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/session_reference_observer.c $(BUILD_DIR)/session_reference_main.o $(CORE_OBJS) $(LDFLAGS) -o $@

$(SESSION_REFERENCE_TESTS): $(CORE_OBJS) tests/session_reference_tests.c tests/server_harness.c tests/server_harness.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/session_reference_tests.c tests/server_harness.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(HTTP_LOG_REASON_REFERENCE_TESTS): $(CORE_OBJS) tests/http_log_reason_reference_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/http_log_reason_reference_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(HTTP_RESET_REASON_REFERENCE_TESTS): $(CORE_OBJS) tests/http_reset_reason_reference_tests.c tests/nat_stream_tests.c tests/connectivity_nat_test_cases.h tests/connectivity_nat_complete_cases.h tests/server_harness.c tests/server_harness.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DST_CONNECTIVITY_VECTOR_DIR='"../../../protocol/test-vectors/"' tests/http_reset_reason_reference_tests.c tests/server_harness.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(TRAFFIC_USAGE_TESTS): $(CORE_OBJS) tests/traffic_usage_tests.c tests/nat_stream_tests.c tests/connectivity_nat_test_cases.h tests/connectivity_nat_complete_cases.h tests/server_harness.c tests/server_harness.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DST_CONNECTIVITY_VECTOR_DIR='"../../../protocol/test-vectors/"' tests/traffic_usage_tests.c tests/server_harness.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(HTTP_CONNECTOR_TESTS): $(CORE_OBJS) tests/http_connector_tests.c tests/nat_stream_tests.c tests/connectivity_nat_test_cases.h tests/connectivity_nat_complete_cases.h tests/server_harness.c tests/server_harness.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DST_CONNECTIVITY_VECTOR_DIR='"../../../protocol/test-vectors/"' tests/http_connector_tests.c tests/server_harness.c $(CORE_OBJS) $(LDFLAGS) -o $@

ifeq ($(shell uname -s),Linux)
$(NAT_PUSH_REFERENCE_SERVER): $(CORE_OBJS) src/main.c tests/nat_push_reference_server.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/nat_push_reference_server.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(NAT_PUSH_REFERENCE_TESTS): $(CORE_OBJS) tests/nat_push_reference_tests.c tests/session_lifecycle_tests.c tests/server_harness.c tests/server_harness.h $(NAT_CONTROL_SIZE_VECTOR) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DST_NAT_CONTROL_SIZE_VECTOR_FILE='"$(abspath $(NAT_CONTROL_SIZE_VECTOR))"' tests/nat_push_reference_tests.c tests/server_harness.c $(CORE_OBJS) $(LDFLAGS) -o $@
endif

$(ADMIN_TESTS): $(CORE_OBJS) tests/admin_http_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/admin_http_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(URL_DECODE_TESTS): $(CORE_OBJS) tests/url_decode_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/url_decode_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(REDIS_URI_TESTS): $(CORE_OBJS) tests/redis_uri_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/redis_uri_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@
$(CONNECTIVITY_LIFETIME_TESTS): $(CORE_OBJS) tests/connectivity_lifetime_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/connectivity_lifetime_tests.c $(CORE_OBJS) -Wl,--wrap=free -Wl,--wrap=st_connectivity_checker_new -Wl,--wrap=st_connectivity_handle $(LDFLAGS) -o $@

$(CONNECTIVITY_SETTER_TESTS): $(CORE_OBJS) tests/connectivity_setter_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/connectivity_setter_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(DIRECT_WEBSOCKET_TESTS): $(CORE_OBJS) tests/direct_websocket_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/direct_websocket_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(CLIENT_ADDRESS_TESTS): $(CORE_OBJS) tests/client_address_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/client_address_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(CLIENT_AUTH_NONCE_TESTS): $(CORE_OBJS) tests/client_auth_nonce_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/client_auth_nonce_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(CLIENT_PACKAGE_TESTS): $(CORE_OBJS) tests/client_package_tests.c $(DOWNLOAD_LINK_VECTOR_FILE) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DST_DOWNLOAD_LINK_VECTOR_FILE='"$(abspath $(DOWNLOAD_LINK_VECTOR_FILE))"' tests/client_package_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(CRYPTO_TESTS): $(CORE_OBJS) tests/crypto_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/crypto_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(DECOMPRESSION_LIMITS_TESTS): $(CORE_OBJS) tests/decompression_limits_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(BROTLI_TEST_FLAGS) $(CFLAGS) tests/decompression_limits_tests.c $(CORE_OBJS) $(LDFLAGS) $(BROTLI_TEST_LIBS) -o $@

$(ELASTICSEARCH_TRAFFIC_TESTS): $(CORE_OBJS) tests/elasticsearch_traffic_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/elasticsearch_traffic_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(GITHUB_RELEASE_TESTS): $(CORE_OBJS) tests/github_release_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/github_release_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(JSON_TESTS): $(CORE_OBJS) tests/json_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/json_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(HTTP_CLIENT_TESTS): $(CORE_OBJS) tests/http_client_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/http_client_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(HTTP_SHARE_TESTS): $(CORE_OBJS) tests/http_share_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/http_share_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(LOGIN_RATE_LIMITER_TESTS): $(CORE_OBJS) tests/login_rate_limiter_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/login_rate_limiter_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(MEDIA_CAPTURE_TESTS): $(CORE_OBJS) tests/media_capture_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/media_capture_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(OBJECT_STORAGE_TESTS): $(CORE_OBJS) tests/object_storage_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/object_storage_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(OIDC_TESTS): $(CORE_OBJS) tests/oidc_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/oidc_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(PASSWORD_HASH_TESTS): $(CORE_OBJS) tests/password_hash_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/password_hash_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(CONNECTIVITY_CHECK_TESTS): $(CORE_OBJS) tests/connectivity_check_tests.c tests/connectivity_check_test_support.h tests/connectivity_test_clock.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/connectivity_check_tests.c tests/connectivity_test_clock.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(CONNECTIVITY_HTTP_VECTOR_TESTS): $(CORE_OBJS) tests/connectivity_http_vector_tests.c tests/connectivity_http_resource_tests.c tests/connectivity_http_test_support.h tests/connectivity_check_test_support.h tests/connectivity_test_clock.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/connectivity_http_vector_tests.c tests/connectivity_http_resource_tests.c tests/connectivity_test_clock.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(CONNECTIVITY_RESOURCE_WIRE_TESTS): $(CORE_OBJS) tests/connectivity_resource_wire_tests.c tests/server_harness.c tests/server_harness.h tests/connectivity_http_test_support.h tests/connectivity_check_test_support.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/connectivity_resource_wire_tests.c tests/server_harness.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(CONNECTIVITY_RATE_HTTP_TESTS): $(CORE_OBJS) tests/connectivity_rate_http_tests.c tests/connectivity_http_test_support.h tests/connectivity_check_test_support.h tests/connectivity_test_clock.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/connectivity_rate_http_tests.c tests/connectivity_test_clock.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(PEER_EGRESS_TESTS): $(CORE_OBJS) tests/peer_egress_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/peer_egress_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(PEER_MESH_TESTS): $(CORE_OBJS) tests/peer_mesh_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/peer_mesh_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(PEER_MESH_E2E_TESTS): $(CORE_OBJS) tests/peer_mesh_e2e_tests.c tests/server_harness.c tests/server_harness.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/peer_mesh_e2e_tests.c tests/server_harness.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(PUBLIC_COORDINATION_TESTS): $(CORE_OBJS) tests/public_coordination_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/public_coordination_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(PUBLIC_COORDINATION_SENTINEL_TESTS): $(CORE_OBJS) tests/public_coordination_sentinel_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/public_coordination_sentinel_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(PUBLIC_CLUSTER_CODEC_TESTS): $(CORE_OBJS) tests/public_cluster_codec_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/public_cluster_codec_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(PUBLIC_TRANSFER_TESTS): $(CORE_OBJS) tests/public_transfer_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/public_transfer_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(PROTOCOL_TESTS): $(CORE_OBJS) tests/protocol_fixture_tests.c tests/test_util.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/protocol_fixture_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(SECURITY_TESTS): $(CORE_OBJS) tests/security_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/security_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(SECURITY_BASELINE_TESTS): $(CORE_OBJS) tests/security_baseline_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/security_baseline_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(SESSION_LIFECYCLE_TESTS): $(CORE_OBJS) tests/session_lifecycle_tests.c tests/server_harness.c tests/server_harness.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/session_lifecycle_tests.c tests/server_harness.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(SECURITY_RULES_TESTS): $(CORE_OBJS) tests/security_rules_tests.c tests/server_harness.c tests/server_harness.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/security_rules_tests.c tests/server_harness.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(HTTP_ROUTE_LIFECYCLE_TESTS): $(CORE_OBJS) tests/http_route_lifecycle_tests.c tests/server_harness.c tests/server_harness.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/http_route_lifecycle_tests.c tests/server_harness.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(CLIENT_ROUTE_SCALE_TESTS): $(CORE_OBJS) tests/client_route_scale_tests.c tests/server_harness.c tests/server_harness.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/client_route_scale_tests.c tests/server_harness.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(NAT_SIZING_REFERENCE_TESTS): $(CORE_OBJS) tests/nat_sizing_reference_tests.c src/main.c tests/server_harness.c tests/server_harness.h ../../../protocol/test-vectors/nat-control-size-v1.json | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/nat_sizing_reference_tests.c tests/server_harness.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(SQLITE_REFERENCE_TESTS): $(CORE_OBJS) tests/sqlite_reference_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/sqlite_reference_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(NAT_STREAM_TESTS): $(CORE_OBJS) tests/nat_stream_tests.c tests/connectivity_nat_test_cases.h tests/connectivity_nat_complete_cases.h tests/server_harness.c tests/server_harness.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DST_CONNECTIVITY_VECTOR_DIR='"../../../protocol/test-vectors/"' tests/nat_stream_tests.c tests/server_harness.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(PRODUCT_METRICS_TESTS): $(CORE_OBJS) tests/product_metrics_tests.c tests/server_harness.c tests/server_harness.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/product_metrics_tests.c tests/server_harness.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(CONNECTION_ARCHIVE_TESTS): $(CORE_OBJS) tests/connection_archive_tests.c tests/server_harness.c tests/server_harness.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/connection_archive_tests.c tests/server_harness.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(TRAFFIC_DETAIL_API_TESTS): $(CORE_OBJS) tests/traffic_detail_api_tests.c tests/server_harness.c tests/server_harness.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/traffic_detail_api_tests.c tests/server_harness.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(CLIENT_MESSAGES_TESTS): $(CORE_OBJS) tests/client_messages_tests.c tests/client_messages_revocation_tests.h tests/server_harness.c tests/server_harness.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/client_messages_tests.c tests/server_harness.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(MANAGEMENT_WS_BACKPRESSURE_TESTS): $(CORE_OBJS) tests/management_ws_backpressure_tests.c tests/server_harness.c tests/server_harness.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/management_ws_backpressure_tests.c tests/server_harness.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(DIRECT_WEBSOCKET_BACKPRESSURE_TESTS): $(CORE_OBJS) tests/direct_websocket_backpressure_tests.c tests/server_harness.c tests/server_harness.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/direct_websocket_backpressure_tests.c tests/server_harness.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(MANAGEMENT_LISTS_TESTS): $(CORE_OBJS) tests/management_lists_tests.c tests/server_harness.c tests/server_harness.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/management_lists_tests.c tests/server_harness.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(MANAGEMENT_CRUD_TESTS): $(CORE_OBJS) tests/management_crud_tests.c tests/server_harness.c tests/server_harness.h $(MAILBOX_VECTOR_FILE) $(EMAIL_MASK_VECTOR_FILE) $(EMAIL_NUL_VECTOR_FILE) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DST_MAILBOX_VECTOR_FILE='"$(abspath $(MAILBOX_VECTOR_FILE))"' -DST_EMAIL_MASK_VECTOR_FILE='"$(abspath $(EMAIL_MASK_VECTOR_FILE))"' -DST_EMAIL_NUL_VECTOR_FILE='"$(abspath $(EMAIL_NUL_VECTOR_FILE))"' tests/management_crud_tests.c tests/server_harness.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(PEER_MESH_API_TESTS): $(CORE_OBJS) tests/peer_mesh_api_tests.c tests/server_harness.c tests/server_harness.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/peer_mesh_api_tests.c tests/server_harness.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(MANAGEMENT_OVERVIEW_TESTS): $(CORE_OBJS) tests/management_overview_tests.c tests/server_harness.c tests/server_harness.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/management_overview_tests.c tests/server_harness.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(REGISTRATION_EXPIRY_TESTS): $(CORE_OBJS) tests/registration_expiry_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/registration_expiry_tests.c $(CORE_OBJS) -Wl,--wrap=time -Wl,--wrap=clock_gettime $(LDFLAGS) -o $@

$(PEER_SESSION_EXPIRY_TESTS): $(CORE_OBJS) tests/peer_session_expiry_tests.c tests/instant_reference_cases.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/peer_session_expiry_tests.c $(CORE_OBJS) -Wl,--wrap=clock_gettime $(LDFLAGS) -o $@

$(PAIRING_EXPIRY_TESTS): $(CORE_OBJS) tests/pairing_expiry_tests.c tests/instant_reference_cases.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/pairing_expiry_tests.c $(CORE_OBJS) -Wl,--wrap=time -Wl,--wrap=clock_gettime $(LDFLAGS) -o $@

$(TRANSFER_EXPIRY_TESTS): $(CORE_OBJS) tests/transfer_expiry_tests.c tests/instant_reference_cases.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/transfer_expiry_tests.c $(CORE_OBJS) -Wl,--wrap=time -Wl,--wrap=clock_gettime $(LDFLAGS) -o $@

$(MEDIA_EXPIRY_TESTS): $(CORE_OBJS) tests/media_expiry_tests.c tests/instant_reference_cases.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/media_expiry_tests.c $(CORE_OBJS) -Wl,--wrap=time -Wl,--wrap=clock_gettime $(LDFLAGS) -o $@

$(SERVER_HARNESS_TESTS): $(CORE_OBJS) tests/server_harness_tests.c tests/server_harness.c tests/server_harness.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/server_harness_tests.c tests/server_harness.c $(CORE_OBJS) -Wl,--wrap=bind $(LDFLAGS) -o $@

$(WEBSOCKET_TICKET_API_TESTS): $(BUILD_DIR)/specus_c_%_tests: tests/%_tests.c tests/websocket_ticket_request_tests.c $(CORE_OBJS) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(CORE_OBJS) -Wl,--wrap=clock_gettime $(LDFLAGS) -o $@

$(HTTP_WEBSOCKET_ROUTING_TESTS): $(CORE_OBJS) tests/http_websocket_routing_tests.c tests/server_harness.c tests/server_harness.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/http_websocket_routing_tests.c tests/server_harness.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(STORAGE_TESTS): $(CORE_OBJS) tests/storage_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/storage_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(SESSION_ORDER_TESTS): $(CORE_OBJS) tests/session_order_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/session_order_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(SESSION_SCOPE_TESTS): $(CORE_OBJS) tests/session_order_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DST_SESSION_ORDER_VECTOR_FILE='"../../../protocol/test-vectors/peer-egress-session-scope-v1.json"' -DST_SESSION_ORDER_EXPECTED_CASES=8U -DST_SESSION_SCOPE_NOCASE=1 tests/session_order_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(METRICS_TESTS): $(CORE_OBJS) tests/metrics_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/metrics_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(METRICS_ENDPOINT_TESTS): $(CORE_OBJS) tests/metrics_endpoint_tests.c tests/server_harness.c tests/server_harness.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/metrics_endpoint_tests.c tests/server_harness.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(STUN_TURN_TESTS): $(CORE_OBJS) tests/stun_turn_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/stun_turn_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(STUN_TURN_SCALE_TESTS): $(CORE_OBJS) tests/stun_turn_scale_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/stun_turn_scale_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(TLS_TRANSPORT_TESTS): $(CORE_OBJS) tests/tls_transport_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/tls_transport_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(SEMANTIC_VERSION_TESTS): $(CORE_OBJS) tests/semantic_version_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/semantic_version_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(TRAFFIC_CAPTURE_TESTS): $(CORE_OBJS) tests/traffic_capture_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/traffic_capture_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(TURNSTILE_VERIFIER_TESTS): $(CORE_OBJS) tests/turnstile_verifier_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/turnstile_verifier_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(UPSTREAM_BROWSER_HEADERS_TESTS): $(CORE_OBJS) tests/upstream_browser_headers_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/upstream_browser_headers_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(WORKBENCH_TESTS): $(CORE_OBJS) tests/workbench_tests.c tests/server_harness.c tests/server_harness.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/workbench_tests.c tests/server_harness.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(MANAGEMENT_ACCOUNTS_TESTS): $(CORE_OBJS) tests/management_accounts_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/management_accounts_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(INSTANT_TESTS): $(CORE_OBJS) tests/instant_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/instant_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(INSTANT_MIGRATION_TESTS): $(CORE_OBJS) tests/instant_migration_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/instant_migration_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(CONNECTION_TIME_REFERENCE_TESTS): $(CORE_OBJS) tests/connection_time_reference_tests.c tests/instant_reference_cases.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/connection_time_reference_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(AUTH_EXPIRY_REFERENCE_TESTS): $(CORE_OBJS) tests/auth_expiry_reference_tests.c tests/instant_reference_cases.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/auth_expiry_reference_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(WEBSOCKET_TICKET_STORAGE_REFERENCE_TESTS): $(CORE_OBJS) tests/websocket_ticket_storage_reference_tests.c tests/instant_reference_cases.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/websocket_ticket_storage_reference_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

test: all
	PYTHONDONTWRITEBYTECODE=1 python3 tests/websocket_ticket_restart_tests.py $(abspath $(SERVER))
	$(SQLITE_REFERENCE_TESTS)
	$(NAT_SIZING_REFERENCE_TESTS) $(SERVER)
	$(NAT_PUSH_REFERENCE_TEST_COMMAND)
	$(SESSION_REFERENCE_TESTS) $(SESSION_REFERENCE_SERVER)
	$(HTTP_RESET_REASON_REFERENCE_TESTS) $(SERVER)
	$(TRAFFIC_USAGE_TESTS) $(SERVER)
	$(METRICS_ENDPOINT_TESTS) $(SERVER)
	$(HTTP_CONNECTOR_TESTS) $(SERVER)
	$(CONNECTIVITY_RATE_HTTP_TESTS)
	$(CONNECTIVITY_RESOURCE_WIRE_TESTS) $(SERVER)
	$(UNICODE_JAVA21_TESTS) "$(abspath $(UNICODE_JAVA21_VECTORS))"
	$(JAVA_URI_TESTS) "$(abspath $(DOWNLOAD_LINK_VECTOR_FILE))"
	@for test in $(TESTS); do $$test || exit 1; done
	bash scripts/public_coordination_test.sh $(PUBLIC_COORDINATION_TESTS)
	bash scripts/public_coordination_sentinel_test.sh $(PUBLIC_COORDINATION_SENTINEL_TESTS) plain
	$(REDIS_TLS_TEST_COMMANDS)
	bash scripts/public_discovery_cluster_e2e.sh $(SERVER)
	python3 scripts/management_cluster_e2e.py $(SERVER)
	SPECUS_TEST_OSS_START_DELAY_SECONDS=0.5 bash scripts/object_storage_e2e.sh $(SERVER)
	bash scripts/tls_deployment_e2e.sh $(SERVER)
	bash scripts/elasticsearch_traffic_test.sh $(ELASTICSEARCH_TRAFFIC_TESTS)
	bash scripts/elasticsearch_traffic_test.sh $(TRAFFIC_DETAIL_API_TESTS) $(SERVER)
	bash scripts/media_capture_test.sh $(MEDIA_CAPTURE_TESTS)
	bash scripts/media_capture_test.sh $(MEDIA_EXPIRY_TESTS) expiry
	$(SESSION_LIFECYCLE_TESTS) $(SERVER)
	$(SECURITY_RULES_TESTS) $(SERVER)
	$(HTTP_ROUTE_LIFECYCLE_TESTS) $(SERVER)
	$(CLIENT_ROUTE_SCALE_TESTS) $(SERVER)
	$(NAT_STREAM_TESTS) $(SERVER)
	$(CONNECTIVITY_CLOCK_TEST_COMMAND)
	$(HTTP_TIMEOUT_CLOCK_TEST_COMMAND)
	$(PRODUCT_METRICS_TESTS) $(SERVER)
	$(CONNECTION_ARCHIVE_TESTS) $(SERVER)
	$(CLIENT_MESSAGES_TESTS) $(SERVER)
	$(MANAGEMENT_WS_BACKPRESSURE_TESTS) $(SERVER)
	$(DIRECT_WEBSOCKET_BACKPRESSURE_TESTS) $(SERVER)
	$(MANAGEMENT_LISTS_TESTS)
	$(MANAGEMENT_CRUD_TESTS)
	$(PEER_MESH_API_TESTS)
	$(MANAGEMENT_OVERVIEW_TESTS) $(SERVER)
	$(HTTP_WEBSOCKET_ROUTING_TESTS) $(SERVER)
	$(SERVER_HARNESS_TESTS) $(SERVER)
	$(PEER_MESH_E2E_TESTS) $(SERVER)
	$(INSTANT_TESTS)
	$(INSTANT_MIGRATION_TESTS)
	$(CONNECTION_TIME_REFERENCE_TESTS)
	$(AUTH_EXPIRY_REFERENCE_TESTS)
	$(WEBSOCKET_TICKET_STORAGE_REFERENCE_TESTS)

release: CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -O3 -DNDEBUG
release: clean $(SERVER)
	strip $(SERVER) 2>/dev/null || true

clean:
	rm -rf $(BUILD_DIR)
