#define _POSIX_C_SOURCE 200809L
/* Reuse the actual server's configuration builder, including escaping and entry serialization.
 * No I/O calls are substituted. The ordinary server remains a separate executable. */
#define main specus_server_entry_for_sizing_reference
#define read_frame specus_server_read_frame_for_sizing_reference
#include "../src/main.c"
#undef read_frame
#undef main
#include "server_harness.h"
#include <openssl/evp.h>
#include <sqlite3.h>

#ifndef ST_NAT_CONTROL_SIZE_VECTOR_FILE
#define ST_NAT_CONTROL_SIZE_VECTOR_FILE "../../../protocol/test-vectors/nat-control-size-v1.json"
#endif

static const char sizing_target_prefix[] = "http://127.0.0.1:8080/";
static char *sizing_vector;

static int sizing_json(server_config *config, const char *name)
{
    free(config->nat_control_json);
    config->nat_control_json = NULL;
    return build_nat_control_json_named(config, name);
}

static void sizing_init(server_config *config, int port)
{
    memset(config, 0, sizeof(*config));
    config->owns_routes = 1;
    config->port = port;
    strcpy(config->public_address, "127.0.0.1");
}

/* Construct an exact J using the production JSON builder and bounded native route fields.
 * Measure a real minimal entry, choose enough entries for their combined padding capacity,
 * then distribute the remaining ASCII bytes. No copy of the reservation formula is used. */
static int sizing_exact_config(server_config *config, size_t target)
{
    config_release_routes(config);
    CHECK(sizing_json(config, "") == 0, "empty sizing JSON");
    size_t empty = strlen(config->nat_control_json);
    http_route_mapping *probe = config_add_http_route(config);
    CHECK(probe != NULL, "sizing probe allocation");
    strcpy(probe->route, "s000000");
    strcpy(probe->target_base_url, sizing_target_prefix);
    CHECK(sizing_json(config, "") == 0, "single sizing JSON");
    size_t unit = strlen(config->nat_control_json) - empty + 1U;
    size_t capacity = sizeof(probe->target_base_url) - 1U - strlen(sizing_target_prefix);
    CHECK(target > empty && unit > 1U, "sizing J too small");
    size_t count = (target - empty + 1U + unit + capacity - 1U) / (unit + capacity);
    CHECK(count > 0U && count < 100000U, "sizing route count");
    config_release_routes(config);
    for (size_t i = 0; i < count; ++i) {
        http_route_mapping *route = config_add_http_route(config);
        CHECK(route != NULL, "sizing route allocation");
        snprintf(route->route, sizeof(route->route), "s%06u", (unsigned)i);
        strcpy(route->target_base_url, sizing_target_prefix);
    }
    CHECK(sizing_json(config, "") == 0 && strlen(config->nat_control_json) <= target,
          "minimal sizing routes exceed target");
    size_t remaining = target - strlen(config->nat_control_json);
    for (size_t i = 0; i < count && remaining != 0U; ++i) {
        size_t pad = remaining < capacity ? remaining : capacity;
        size_t start = strlen(sizing_target_prefix);
        memset(config->http_routes[i].target_base_url + start, 'f', pad);
        config->http_routes[i].target_base_url[start + pad] = '\0';
        remaining -= pad;
    }
    CHECK(remaining == 0U && sizing_json(config, "") == 0
              && strlen(config->nat_control_json) == target, "actual production JSON is not exact J=%zu", target);
    return 0;
}

static int sizing_vector_cases(void)
{
    long long limit = 0, reserve = 0, field = 0, escaped = 0;
    char *name = st_json_get_top_level_raw(sizing_vector, "clientNameReserve");
    CHECK(name != NULL && st_json_get_i64(sizing_vector, "messageBodyLimitBytes", &limit) == 0
              && st_json_get_i64(name, "maxCharacters", &reserve) == 0
              && st_json_get_i64(name, "fieldBytes", &field) == 0
              && st_json_get_i64(name, "jsonBytes", &escaped) == 0
              && limit == ST_MAX_MESSAGE_BODY_SIZE && reserve == ST_NAT_CONTROL_CLIENT_NAME_RESERVE_CHARACTERS
              && field == reserve * 4 && escaped == reserve * 6, "shared sizing constants");
    free(name);
    char **cases = NULL;
    size_t count = 0U;
    CHECK(st_json_get_raw_array(sizing_vector, "sizing", &cases, &count) == 0 && count == 5U,
          "all five shared sizing cases required");
    server_config config;
    sizing_init(&config, 7010);
    for (size_t i = 0; i < count; ++i) {
        long long j = 0, expected = 0;
        int fits = 0;
        CHECK(st_json_get_i64(cases[i], "jsonBytesWithEmptyClientName", &j) == 0 && j > 0
                  && st_json_get_i64(cases[i], "bodyBytes", &expected) == 0
                  && st_json_get_bool(cases[i], "fits", &fits) == 0, "sizing vector case %zu shape", i);
        CHECK(sizing_exact_config(&config, (size_t)j) == 0, "construct sizing J=%lld", j);
        size_t bytes = 0U;
        CHECK(st_protocol_nat_control_reserved_body_size(strlen(config.nat_control_json), &bytes) == 0
                  && bytes == (size_t)expected && (bytes <= ST_MAX_MESSAGE_BODY_SIZE) == fits,
              "shared sizing case %zu: J=%lld actual body=%zu expected=%lld", i, j, bytes, expected);
        printf("NAT sizing vector %zu: actual production J=%lld body=%zu fits=%d passed\n", i, j, bytes, fits);
    }
    config_release_routes(&config);
    st_json_free_string_array(cases, count);
    size_t sentinel = 7U;
    CHECK(st_protocol_nat_control_reserved_body_size(SIZE_MAX, &sentinel) == -1 && sentinel == 0U
              && st_protocol_nat_control_reserved_body_size(UINT32_MAX, &sentinel) == -1 && sentinel == 0U
              && st_protocol_nat_control_reserved_body_size(1000U, NULL) == -1,
          "unencodable lengths and NULL output must fail safely");
    return 0;
}

static int sizing_name_families(void)
{
    server_config config;
    sizing_init(&config, 7010);
    tcp_mapping *mapping = config_add_mapping(&config);
    http_route_mapping *route = config_add_http_route(&config);
    CHECK(mapping != NULL && route != NULL, "name fixture allocation");
    mapping->port = 42001;
    mapping->specus_port = 22;
    strcpy(mapping->specus_address, "127.0.0.1");
    strcpy(route->route, "web");
    snprintf(route->target_base_url, sizeof(route->target_base_url), "%s?a=1&b=<2>", sizing_target_prefix);
    CHECK(sizing_json(&config, "") == 0, "empty-name actual builder");
    size_t reserved = 0U;
    CHECK(st_protocol_nat_control_reserved_body_size(strlen(config.nat_control_json), &reserved) == 0,
          "name fixture reserved bytes");
    const char *const units[] = {"\x01", "\"", "\xe4\xb8\xad", "\xf0\x9f\x98\x80", "\xe2\x80\xa8", "a"};
    const size_t repeats[] = {120U, 120U, 120U, 60U, 120U, 120U};
    for (size_t i = 0; i < sizeof(units) / sizeof(units[0]); ++i) {
        char name[481];
        size_t unit = strlen(units[i]);
        for (size_t k = 0; k < repeats[i]; ++k) memcpy(name + k * unit, units[i], unit);
        name[repeats[i] * unit] = '\0';
        CHECK(sizing_json(&config, name) == 0, "actual builder name family %zu", i);
        st_buffer wire = st_protocol_encode_nat_control(name, config.nat_control_json);
        st_frame_header header;
        st_message_response decoded = {0};
        CHECK(wire.data != NULL && wire.len >= ST_HEADER_SIZE
                  && st_protocol_read_header(wire.data, &header) == 0
                  && header.length == wire.len - ST_HEADER_SIZE && header.length <= reserved
                  && st_protocol_decode_message_response(wire.data + ST_HEADER_SIZE, header.length, &decoded) == 0,
              "encoded name family %zu exceeds reserve=%zu", i, reserved);
        char *json_name = st_json_get_top_level_string(decoded.message, "clientName");
        CHECK(decoded.message_type == ST_MESSAGE_TYPE_NAT_CONTROL && decoded.to_client_name == NULL
                  && strcmp(decoded.client_name, name) == 0 && json_name != NULL && strcmp(json_name, name) == 0,
              "encoded name family %zu did not round trip", i);
        printf("NAT name reserve family %zu: actual encoded body=%u reserved=%zu passed\n", i, header.length, reserved);
        free(json_name);
        st_message_response_free(&decoded);
        st_buffer_free(&wire);
    }
    config_release_routes(&config);
    return 0;
}

typedef struct {
    char name[32];
    char target[512];
    long long id;
    int enabled, detail, deleted, listen_port;
} sizing_item;

typedef struct {
    test_server *server;
    char token[1024];
    long long client_id;
    sizing_item routes[16], mappings[16];
    size_t route_count, mapping_count;
} sizing_management;

static const char sizing_client_name[] = "nat-control-size";

/* Hash the typed values of EVERY column of EVERY row for this client, ordered by id.
 * This includes timestamps and disabled rows, not just the enabled wire snapshot. */
static int sizing_store_fingerprint(const test_server *server, uint8_t digest[32])
{
    sqlite3 *db = NULL;
    EVP_MD_CTX *hash = EVP_MD_CTX_new();
    CHECK(hash != NULL && EVP_DigestInit_ex(hash, EVP_sha256(), NULL) == 1
              && sqlite3_open(server->db_path, &db) == SQLITE_OK, "open typed persistence snapshot");
    sqlite3_busy_timeout(db, 5000);
    CHECK(sqlite3_exec(db, "BEGIN", NULL, NULL, NULL) == SQLITE_OK, "begin persistence snapshot");
    const char *const tables[] = {"specus_mapping", "http_route_mapping"};
    for (size_t t = 0; t < 2U; ++t) {
        sqlite3_stmt *stmt = NULL;
        char sql[160];
        snprintf(sql, sizeof(sql), "SELECT * FROM %s WHERE client_name=? ORDER BY id", tables[t]);
        CHECK(sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK
                  && sqlite3_bind_text(stmt, 1, sizing_client_name, -1, SQLITE_STATIC) == SQLITE_OK,
              "prepare full persistence snapshot");
        CHECK(EVP_DigestUpdate(hash, tables[t], strlen(tables[t])) == 1, "hash table");
        int columns = sqlite3_column_count(stmt);
        CHECK(EVP_DigestUpdate(hash, &columns, sizeof(columns)) == 1, "hash schema width");
        for (int c = 0; c < columns; ++c) {
            const char *name = sqlite3_column_name(stmt, c);
            size_t size = strlen(name);
            CHECK(EVP_DigestUpdate(hash, &size, sizeof(size)) == 1
                      && EVP_DigestUpdate(hash, name, size) == 1, "hash column name");
        }
        int rc;
        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
            const uint8_t row = 0xff;
            CHECK(EVP_DigestUpdate(hash, &row, 1U) == 1, "hash row boundary");
            for (int c = 0; c < columns; ++c) {
                int type = sqlite3_column_type(stmt, c);
                const void *value = sqlite3_column_blob(stmt, c);
                int size = sqlite3_column_bytes(stmt, c);
                CHECK(EVP_DigestUpdate(hash, &type, sizeof(type)) == 1
                          && EVP_DigestUpdate(hash, &size, sizeof(size)) == 1
                          && (size == 0 || (value != NULL && EVP_DigestUpdate(hash, value, (size_t)size) == 1)),
                      "hash full typed row");
            }
        }
        CHECK(rc == SQLITE_DONE, "snapshot read error is not absence");
        sqlite3_finalize(stmt);
    }
    unsigned int length = 0U;
    CHECK(EVP_DigestFinal_ex(hash, digest, &length) == 1 && length == 32U
              && sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK, "finish persistence snapshot");
    EVP_MD_CTX_free(hash);
    sqlite3_close(db);
    return 0;
}

static int sizing_load_snapshot(const test_server *server, server_config *config)
{
    sizing_init(config, server->control_port);
    strcpy(config->client_name, sizing_client_name);
    CHECK(load_database_config(config, server->db_path) == 0 && sizing_json(config, "") == 0,
          "actual production enabled-entry snapshot");
    return 0;
}

static int sizing_fill_store(const test_server *server, size_t target)
{
    server_config config;
    sizing_init(&config, server->control_port);
    CHECK(sizing_exact_config(&config, target) == 0, "exact shared management fill");
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    CHECK(sqlite3_open(server->db_path, &db) == SQLITE_OK, "open direct-store fill");
    sqlite3_busy_timeout(db, 5000);
    CHECK(sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK
              && sqlite3_prepare_v2(db, "INSERT INTO http_route_mapping(client_name,route,target_base_url,enabled)"
                  " VALUES(?,?,?,1)", -1, &stmt, NULL) == SQLITE_OK, "prepare direct-store fill");
    for (size_t i = 0; i < config.http_route_count; ++i) {
        CHECK(sqlite3_bind_text(stmt, 1, sizing_client_name, -1, SQLITE_STATIC) == SQLITE_OK
                  && sqlite3_bind_text(stmt, 2, config.http_routes[i].route, -1, SQLITE_TRANSIENT) == SQLITE_OK
                  && sqlite3_bind_text(stmt, 3, config.http_routes[i].target_base_url, -1, SQLITE_TRANSIENT) == SQLITE_OK
                  && sqlite3_step(stmt) == SQLITE_DONE && sqlite3_reset(stmt) == SQLITE_OK
                  && sqlite3_clear_bindings(stmt) == SQLITE_OK, "insert bounded filler route %zu", i);
    }
    sqlite3_finalize(stmt);
    CHECK(sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK, "commit direct-store fill");
    sqlite3_close(db);
    config_release_routes(&config);
    CHECK(sizing_load_snapshot(server, &config) == 0 && strlen(config.nat_control_json) == target,
          "stored fill not exact J=%zu", target);
    config_release_routes(&config);
    return 0;
}

static sizing_item *sizing_find_item(sizing_item *items, size_t count, const char *name)
{
    for (size_t i = 0; i < count; ++i) if (strcmp(items[i].name, name) == 0) return &items[i];
    return NULL;
}

static int sizing_assert_items(const sizing_management *f)
{
    for (size_t i = 0; i < f->route_count; ++i) {
        const sizing_item *item = &f->routes[i];
        st_storage_http_route route;
        int found = 0;
        CHECK(st_storage_find_http_route_by_id(f->server->db_path, item->id, &route, &found) == 0
                  && found == !item->deleted, "accepted route %s presence/readability", item->name);
        if (found) {
            CHECK(route.id == item->id && route.client_id == f->client_id
                      && strcmp(route.client_name, sizing_client_name) == 0 && strcmp(route.route, item->name) == 0
                      && strcmp(route.target_base_url, item->target) == 0 && route.enabled == item->enabled
                      && route.detail_capture_enabled == item->detail && !route.media_capture_enabled
                      && !route.path_rewrite_enabled && !route.insecure_skip_verify && !route.auth_enabled
                      && route.auth_username[0] == '\0' && route.auth_password_hash[0] == '\0',
                  "accepted route %s fields were not persisted intact", item->name);
        }
    }
    for (size_t i = 0; i < f->mapping_count; ++i) {
        const sizing_item *item = &f->mappings[i];
        st_storage_mapping mapping;
        CHECK(st_storage_get_mapping(f->server->db_path, item->id, &mapping) == 0
                  && mapping.id == item->id && mapping.client_id == f->client_id
                  && strcmp(mapping.client_name, sizing_client_name) == 0
                  && mapping.listen_port == item->listen_port && mapping.target_port == 8080
                  && strcmp(mapping.target_address, "127.0.0.1") == 0
                  && mapping.enabled == item->enabled && !mapping.detail_capture_enabled,
              "accepted mapping %s fields were not persisted intact", item->name);
    }
    return 0;
}

static int sizing_management_steps(test_server *server)
{
    sizing_management f = {.server = server};
    char auth[256];
    snprintf(auth, sizeof(auth), "{\"username\":\"%s\",\"password\":\"%s\"}", ADMIN_USERNAME, ADMIN_PASSWORD);
    int status = 0;
    char *response = NULL;
    CHECK(http_request(server->admin_port, "POST", "/auth/login", auth, NULL, &status, &response) == 0 && status == 200,
          "management sizing admin login");
    char *token = st_json_get_top_level_string(response, "accessToken");
    CHECK(token != NULL && strlen(token) < sizeof(f.token), "management sizing token");
    strcpy(f.token, token);
    free(token); free(response); response = NULL;
    CHECK(http_request(server->admin_port, "POST", "/api/admin/clients",
              "{\"clientName\":\"nat-control-size\",\"enabled\":true}", f.token, &status, &response) == 0
              && status == 201 && st_json_get_i64(response, "id", &f.client_id) == 0 && f.client_id > 0,
          "create fresh management sizing client");
    free(response); response = NULL;
    long long max_json = 0, gap = 0;
    char *management = st_json_get_top_level_raw(sizing_vector, "management");
    char *error_contains = st_json_get_top_level_string(sizing_vector, "errorContains");
    char **steps = NULL;
    size_t count = 0U;
    CHECK(management != NULL && error_contains != NULL
              && st_json_get_i64(sizing_vector, "maxJsonBytesWithEmptyClientName", &max_json) == 0
              && st_json_get_i64(management, "fillRemainingJsonBytes", &gap) == 0 && gap > 0 && max_json > gap
              && st_json_get_raw_array(management, "steps", &steps, &count) == 0 && count == 14U
              && sizing_fill_store(server, (size_t)(max_json - gap)) == 0, "shared management14 setup");
    int next_port = 42000;
    for (size_t i = 0; i < count; ++i) {
        char *op = st_json_get_top_level_string(steps[i], "op");
        char *route_name = st_json_get_top_level_string(steps[i], "route");
        char *mapping_name = st_json_get_top_level_string(steps[i], "mapping");
        const char *name = route_name != NULL ? route_name : mapping_name;
        CHECK(op != NULL && name != NULL && strlen(name) < 32U, "management step %zu shape", i);
        int is_route = route_name != NULL, create = strcmp(op, "createRoute") == 0 || strcmp(op, "createMapping") == 0;
        int update = strcmp(op, "updateRoute") == 0 || strcmp(op, "updateMapping") == 0;
        int delete_route = strcmp(op, "deleteRoute") == 0;
        CHECK(create || update || (delete_route && is_route), "unknown management operation %s", op);
        sizing_item *item = sizing_find_item(is_route ? f.routes : f.mappings,
                                             is_route ? f.route_count : f.mapping_count, name);
        sizing_item proposed = {0};
        if (!create) { CHECK(item != NULL && !item->deleted, "step %zu missing stored %s", i, name); proposed = *item; }
        else { strcpy(proposed.name, name); proposed.enabled = 1; }
        (void)st_json_get_bool(steps[i], "enabled", &proposed.enabled);
        (void)st_json_get_bool(steps[i], "detailCaptureEnabled", &proposed.detail);
        char *target = create && is_route ? st_json_get_top_level_string(steps[i], "targetBaseUrl") : NULL;
        int exact = target != NULL && strcmp(target, "exact") == 0;
        if (create && is_route) {
            CHECK(target != NULL, "route creation target");
            if (exact) {
                server_config config;
                CHECK(sizing_load_snapshot(server, &config) == 0, "exact target current snapshot");
                http_route_mapping *probe = config_add_http_route(&config);
                CHECK(probe != NULL, "exact target probe");
                strcpy(probe->route, name); strcpy(probe->target_base_url, sizing_target_prefix);
                CHECK(sizing_json(&config, "") == 0 && strlen(config.nat_control_json) <= (size_t)max_json,
                      "exact target minimum too large");
                size_t pad = (size_t)max_json - strlen(config.nat_control_json), prefix = strlen(sizing_target_prefix);
                CHECK(prefix + pad < sizeof(proposed.target), "exact target exceeds native field");
                memcpy(proposed.target, sizing_target_prefix, prefix);
                memset(proposed.target + prefix, 'e', pad); proposed.target[prefix + pad] = '\0';
                config_release_routes(&config);
            } else { CHECK(strlen(target) < sizeof(proposed.target), "target field length"); strcpy(proposed.target, target); }
        }
        long long grow = 0, expected = 0;
        (void)st_json_get_i64(steps[i], "growTargetBaseUrlBy", &grow);
        size_t target_len = strlen(proposed.target);
        CHECK(grow >= 0 && (size_t)grow < sizeof(proposed.target) - target_len, "route grow overflow");
        memset(proposed.target + target_len, 'g', (size_t)grow); proposed.target[target_len + (size_t)grow] = '\0';
        char path[160], body[2048];
        const char *method = create ? "POST" : delete_route ? "DELETE" : "PUT";
        if (create) snprintf(path, sizeof(path), "/api/admin/clients/%lld/%s", f.client_id,
                              is_route ? "http-routes" : "specus-mappings");
        else snprintf(path, sizeof(path), "/api/admin/%s/%lld", is_route ? "http-routes" : "specus-mappings", item->id);
        if (is_route) {
            char *escaped = st_json_escape(proposed.target);
            CHECK(escaped != NULL, "escape management route target");
            snprintf(body, sizeof(body), "{\"route\":\"%s\",\"targetBaseUrl\":\"%s\",\"enabled\":%s,\"detailCaptureEnabled\":%s}",
                     name, escaped, proposed.enabled ? "true" : "false", proposed.detail ? "true" : "false");
            free(escaped);
        } else {
            if (create) proposed.listen_port = ++next_port;
            snprintf(body, sizeof(body), "{\"listenPort\":%d,\"targetAddress\":\"127.0.0.1\",\"targetPort\":8080,\"enabled\":%s}",
                     proposed.listen_port, proposed.enabled ? "true" : "false");
        }
        uint8_t before[32], after[32];
        CHECK(st_json_get_i64(steps[i], "expect", &expected) == 0
                  && sizing_store_fingerprint(server, before) == 0
                  && http_request(server->admin_port, method, path, delete_route ? NULL : body, f.token, &status, &response) == 0,
              "management step %zu %s actual HTTP failed", i, op);
        CHECK(status == expected, "management step %zu %s HTTP%d expected%lld: %.400s", i, op, status, expected,
              response == NULL ? "" : response);
        if (status == 400) {
            char *error = st_json_get_top_level_string(response, "error");
            CHECK(error != NULL && strstr(error, error_contains) != NULL, "step %zu parsed error field", i);
            free(error);
            CHECK(sizing_store_fingerprint(server, after) == 0 && memcmp(before, after, 32U) == 0,
                  "step %zu %s refused mutation changed a row/field/type/timestamp", i, op);
        } else {
            if (create) {
                CHECK(st_json_get_i64(response, "id", &proposed.id) == 0 && proposed.id > 0, "created item id");
                size_t *items_count = is_route ? &f.route_count : &f.mapping_count;
                CHECK(*items_count < 16U, "tracked management item capacity");
                item = (is_route ? f.routes : f.mappings) + (*items_count)++;
            }
            proposed.deleted = delete_route;
            *item = proposed;
        }
        CHECK(sizing_assert_items(&f) == 0, "step %zu accepted persistent fields", i);
        server_config config;
        size_t reserved = 0U;
        CHECK(sizing_load_snapshot(server, &config) == 0
                  && st_protocol_nat_control_reserved_body_size(strlen(config.nat_control_json), &reserved) == 0
                  && reserved <= ST_MAX_MESSAGE_BODY_SIZE, "step %zu accepted configuration does not fit", i);
        CHECK(!exact || (strlen(config.nat_control_json) == (size_t)max_json && reserved == ST_MAX_MESSAGE_BODY_SIZE),
              "step %zu exact J/body boundary not reached", i);
        printf("NAT management vector step%zu %s: HTTP%d J=%zu reserved=%zu all stored fields%s passed\n",
               i, op, status, strlen(config.nat_control_json), reserved, status == 400 ? " unchanged on refusal" : " verified");
        config_release_routes(&config);
        free(response); response = NULL;
        free(op); free(route_name); free(mapping_name); free(target);
    }
    st_json_free_string_array(steps, count);
    free(management); free(error_contains);
    printf("NAT management vector: all14 actual HTTP steps, exact1MiB edge, parsed errors and complete typed persistence passed\n");
    return 0;
}

static char *sizing_read_vector(void)
{
    FILE *file = fopen(ST_NAT_CONTROL_SIZE_VECTOR_FILE, "rb");
    if (file == NULL || fseek(file, 0L, SEEK_END) != 0) { if (file != NULL) fclose(file); return NULL; }
    long size = ftell(file);
    if (size < 0 || size > 1000000L || fseek(file, 0L, SEEK_SET) != 0) { fclose(file); return NULL; }
    char *json = malloc((size_t)size + 1U);
    if (json == NULL) { fclose(file); return NULL; }
    size_t read = fread(json, 1U, (size_t)size, file);
    fclose(file);
    if (read != (size_t)size) { free(json); return NULL; }
    json[read] = '\0';
    return json;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    sizing_vector = sizing_read_vector();
    CHECK(sizing_vector != NULL && st_json_is_valid_object(sizing_vector), "read shared sizing vector");
    int failures = sizing_vector_cases() + sizing_name_families();
    if (argc > 1) {
        server_binary = argv[1];
        signal(SIGPIPE, SIG_IGN);
        failures += run_on_fresh_server("nat-control-exact-management14", sizing_management_steps, NULL);
    }
    free(sizing_vector);
    return failures == 0 ? 0 : 1;
}
