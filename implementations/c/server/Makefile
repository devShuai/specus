CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -O2
CPPFLAGS ?= -Isrc
LDFLAGS ?= -lpthread -lz -lsqlite3

BUILD_DIR := build
CORE_OBJS := $(BUILD_DIR)/admin_http.o $(BUILD_DIR)/crypto.o $(BUILD_DIR)/json.o $(BUILD_DIR)/protocol.o $(BUILD_DIR)/security.o $(BUILD_DIR)/storage.o
SERVER := $(BUILD_DIR)/specus-server-c
ADMIN_TESTS := $(BUILD_DIR)/specus_c_admin_http_tests
CRYPTO_TESTS := $(BUILD_DIR)/specus_c_crypto_tests
JSON_TESTS := $(BUILD_DIR)/specus_c_json_tests
PROTOCOL_TESTS := $(BUILD_DIR)/specus_c_protocol_fixture_tests
SECURITY_TESTS := $(BUILD_DIR)/specus_c_security_tests
STORAGE_TESTS := $(BUILD_DIR)/specus_c_storage_tests
TESTS := $(ADMIN_TESTS) $(CRYPTO_TESTS) $(JSON_TESTS) $(PROTOCOL_TESTS) $(SECURITY_TESTS) $(STORAGE_TESTS)

.PHONY: all test release clean

all: $(SERVER) $(TESTS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: src/%.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(SERVER): $(CORE_OBJS) src/main.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) src/main.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(ADMIN_TESTS): $(CORE_OBJS) tests/admin_http_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/admin_http_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(CRYPTO_TESTS): $(CORE_OBJS) tests/crypto_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/crypto_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(JSON_TESTS): $(CORE_OBJS) tests/json_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/json_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(PROTOCOL_TESTS): $(CORE_OBJS) tests/protocol_fixture_tests.c tests/test_util.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/protocol_fixture_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(SECURITY_TESTS): $(CORE_OBJS) tests/security_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/security_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(STORAGE_TESTS): $(CORE_OBJS) tests/storage_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/storage_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

test: all
	@for test in $(TESTS); do $$test || exit 1; done

release: CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -O3 -DNDEBUG
release: clean $(SERVER)
	strip $(SERVER) 2>/dev/null || true

clean:
	rm -rf $(BUILD_DIR)
