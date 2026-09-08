CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -O2
CPPFLAGS ?= -Isrc
LDFLAGS ?= -lpthread -lz -lsqlite3 -lssl -lcrypto -lcurl -lhiredis -lutf8proc

BUILD_DIR := build
CORE_OBJS := $(BUILD_DIR)/admin_http.o $(BUILD_DIR)/client_address.o $(BUILD_DIR)/client_package.o $(BUILD_DIR)/crypto.o $(BUILD_DIR)/decompression_limits.o $(BUILD_DIR)/elasticsearch_traffic.o $(BUILD_DIR)/github_release.o $(BUILD_DIR)/http_client.o $(BUILD_DIR)/json.o $(BUILD_DIR)/login_rate_limiter.o $(BUILD_DIR)/media_capture.o $(BUILD_DIR)/object_storage.o $(BUILD_DIR)/password_hash.o $(BUILD_DIR)/peer_egress.o $(BUILD_DIR)/peer_mesh.o $(BUILD_DIR)/protocol.o $(BUILD_DIR)/public_coordination.o $(BUILD_DIR)/public_discovery.o $(BUILD_DIR)/public_room.o $(BUILD_DIR)/registration.o $(BUILD_DIR)/security.o $(BUILD_DIR)/security_baseline.o $(BUILD_DIR)/storage.o $(BUILD_DIR)/stun_turn.o $(BUILD_DIR)/tls_transport.o $(BUILD_DIR)/turn_auth.o
SERVER := $(BUILD_DIR)/specus-server-c
ADMIN_TESTS := $(BUILD_DIR)/specus_c_admin_http_tests
CLIENT_ADDRESS_TESTS := $(BUILD_DIR)/specus_c_client_address_tests
CRYPTO_TESTS := $(BUILD_DIR)/specus_c_crypto_tests
DECOMPRESSION_LIMITS_TESTS := $(BUILD_DIR)/specus_c_decompression_limits_tests
ELASTICSEARCH_TRAFFIC_TESTS := $(BUILD_DIR)/specus_c_elasticsearch_traffic_tests
GITHUB_RELEASE_TESTS := $(BUILD_DIR)/specus_c_github_release_tests
JSON_TESTS := $(BUILD_DIR)/specus_c_json_tests
HTTP_CLIENT_TESTS := $(BUILD_DIR)/specus_c_http_client_tests
LOGIN_RATE_LIMITER_TESTS := $(BUILD_DIR)/specus_c_login_rate_limiter_tests
MEDIA_CAPTURE_TESTS := $(BUILD_DIR)/specus_c_media_capture_tests
OBJECT_STORAGE_TESTS := $(BUILD_DIR)/specus_c_object_storage_tests
PASSWORD_HASH_TESTS := $(BUILD_DIR)/specus_c_password_hash_tests
PEER_EGRESS_TESTS := $(BUILD_DIR)/specus_c_peer_egress_tests
PEER_MESH_TESTS := $(BUILD_DIR)/specus_c_peer_mesh_tests
PUBLIC_COORDINATION_TESTS := $(BUILD_DIR)/specus_c_public_coordination_tests
PROTOCOL_TESTS := $(BUILD_DIR)/specus_c_protocol_fixture_tests
SECURITY_TESTS := $(BUILD_DIR)/specus_c_security_tests
SECURITY_BASELINE_TESTS := $(BUILD_DIR)/specus_c_security_baseline_tests
STORAGE_TESTS := $(BUILD_DIR)/specus_c_storage_tests
STUN_TURN_TESTS := $(BUILD_DIR)/specus_c_stun_turn_tests
TLS_TRANSPORT_TESTS := $(BUILD_DIR)/specus_c_tls_transport_tests
TESTS := $(ADMIN_TESTS) $(CLIENT_ADDRESS_TESTS) $(CRYPTO_TESTS) $(DECOMPRESSION_LIMITS_TESTS) $(GITHUB_RELEASE_TESTS) $(HTTP_CLIENT_TESTS) $(JSON_TESTS) $(LOGIN_RATE_LIMITER_TESTS) $(OBJECT_STORAGE_TESTS) $(PASSWORD_HASH_TESTS) $(PEER_EGRESS_TESTS) $(PEER_MESH_TESTS) $(PROTOCOL_TESTS) $(SECURITY_TESTS) $(SECURITY_BASELINE_TESTS) $(STORAGE_TESTS) $(STUN_TURN_TESTS) $(TLS_TRANSPORT_TESTS)
ALL_TESTS := $(TESTS) $(PUBLIC_COORDINATION_TESTS) $(ELASTICSEARCH_TRAFFIC_TESTS) $(MEDIA_CAPTURE_TESTS)

.PHONY: all test release clean

all: $(SERVER) $(ALL_TESTS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: src/%.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(SERVER): $(CORE_OBJS) src/main.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) src/main.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(ADMIN_TESTS): $(CORE_OBJS) tests/admin_http_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/admin_http_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(CLIENT_ADDRESS_TESTS): $(CORE_OBJS) tests/client_address_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/client_address_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(CRYPTO_TESTS): $(CORE_OBJS) tests/crypto_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/crypto_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(DECOMPRESSION_LIMITS_TESTS): $(CORE_OBJS) tests/decompression_limits_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/decompression_limits_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(ELASTICSEARCH_TRAFFIC_TESTS): $(CORE_OBJS) tests/elasticsearch_traffic_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/elasticsearch_traffic_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(GITHUB_RELEASE_TESTS): $(CORE_OBJS) tests/github_release_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/github_release_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(JSON_TESTS): $(CORE_OBJS) tests/json_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/json_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(HTTP_CLIENT_TESTS): $(CORE_OBJS) tests/http_client_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/http_client_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(LOGIN_RATE_LIMITER_TESTS): $(CORE_OBJS) tests/login_rate_limiter_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/login_rate_limiter_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(MEDIA_CAPTURE_TESTS): $(CORE_OBJS) tests/media_capture_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/media_capture_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(OBJECT_STORAGE_TESTS): $(CORE_OBJS) tests/object_storage_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/object_storage_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(PASSWORD_HASH_TESTS): $(CORE_OBJS) tests/password_hash_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/password_hash_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(PEER_EGRESS_TESTS): $(CORE_OBJS) tests/peer_egress_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/peer_egress_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(PEER_MESH_TESTS): $(CORE_OBJS) tests/peer_mesh_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/peer_mesh_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(PUBLIC_COORDINATION_TESTS): $(CORE_OBJS) tests/public_coordination_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/public_coordination_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(PROTOCOL_TESTS): $(CORE_OBJS) tests/protocol_fixture_tests.c tests/test_util.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/protocol_fixture_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(SECURITY_TESTS): $(CORE_OBJS) tests/security_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/security_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(SECURITY_BASELINE_TESTS): $(CORE_OBJS) tests/security_baseline_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/security_baseline_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(STORAGE_TESTS): $(CORE_OBJS) tests/storage_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/storage_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(STUN_TURN_TESTS): $(CORE_OBJS) tests/stun_turn_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/stun_turn_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(TLS_TRANSPORT_TESTS): $(CORE_OBJS) tests/tls_transport_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/tls_transport_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

test: all
	@for test in $(TESTS); do $$test || exit 1; done
	bash scripts/public_coordination_test.sh $(PUBLIC_COORDINATION_TESTS)
	bash scripts/public_discovery_cluster_e2e.sh $(SERVER)
	bash scripts/object_storage_e2e.sh $(SERVER)
	bash scripts/elasticsearch_traffic_test.sh $(ELASTICSEARCH_TRAFFIC_TESTS)
	bash scripts/media_capture_test.sh $(MEDIA_CAPTURE_TESTS)

release: CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -O3 -DNDEBUG
release: clean $(SERVER)
	strip $(SERVER) 2>/dev/null || true

clean:
	rm -rf $(BUILD_DIR)
