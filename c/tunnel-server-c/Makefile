CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -O2
CPPFLAGS ?= -Isrc
LDFLAGS ?= -lz

BUILD_DIR := build
CORE_OBJS := $(BUILD_DIR)/crypto.o $(BUILD_DIR)/json.o $(BUILD_DIR)/protocol.o
SERVER := $(BUILD_DIR)/shuai-tunnel-server-c
CRYPTO_TESTS := $(BUILD_DIR)/shuai_tunnel_c_crypto_tests
JSON_TESTS := $(BUILD_DIR)/shuai_tunnel_c_json_tests
PROTOCOL_TESTS := $(BUILD_DIR)/shuai_tunnel_c_protocol_fixture_tests
TESTS := $(CRYPTO_TESTS) $(JSON_TESTS) $(PROTOCOL_TESTS)

.PHONY: all test clean

all: $(SERVER) $(TESTS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: src/%.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(SERVER): $(CORE_OBJS) src/main.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) src/main.c $(CORE_OBJS) -lpthread $(LDFLAGS) -o $@

$(CRYPTO_TESTS): $(CORE_OBJS) tests/crypto_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/crypto_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(JSON_TESTS): $(CORE_OBJS) tests/json_tests.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/json_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

$(PROTOCOL_TESTS): $(CORE_OBJS) tests/protocol_fixture_tests.c tests/test_util.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/protocol_fixture_tests.c $(CORE_OBJS) $(LDFLAGS) -o $@

test: all
	@for test in $(TESTS); do $$test || exit 1; done

clean:
	rm -rf $(BUILD_DIR)
