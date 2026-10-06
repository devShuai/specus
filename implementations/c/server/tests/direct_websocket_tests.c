#define _POSIX_C_SOURCE 200809L

/*
 * Direct HTTP-route WebSocket (SWS2) tests: the central application-protocol vectors, the
 * envelope codec rules, and the full browser <-> NAT state machine driven through a real admin
 * listener. The test plays the browser over a TCP socket and plays the NAT session the way
 * main.c does (a stream reference per mapped stream, RST after a refused frame).
 */

#include "admin_http.h"
#include "json.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifndef ST_APPLICATION_FIXTURE_FILE
#define ST_APPLICATION_FIXTURE_FILE "../../../protocol/test-vectors/application-protocol-v2.json"
#endif

#define CHECK(condition, ...)                                         \
    do {                                                              \
        if (!(condition)) {                                           \
            fprintf(stderr, "%s:%d: ", __FILE__, __LINE__);           \
            fprintf(stderr, __VA_ARGS__);                             \
            fputc('\n', stderr);                                      \
            return 1;                                                 \
        }                                                             \
    } while (0)

#define MAX_CHUNK ST_ADMIN_SWS2_MAX_PAYLOAD
#define WAIT_MS 10000

/* ---------------------------------------------------------------- shared helpers */

static long long now_ms(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (long long)now.tv_sec * 1000LL + (long long)(now.tv_nsec / 1000000L);
}

static void sleep_ms(long ms)
{
    struct timespec delay = {.tv_sec = ms / 1000L, .tv_nsec = (ms % 1000L) * 1000000L};
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
    }
}

static void deadline_after(long long ms, struct timespec *out)
{
    clock_gettime(CLOCK_REALTIME, out);
    out->tv_sec += (time_t)(ms / 1000LL);
    out->tv_nsec += (long)((ms % 1000LL) * 1000000LL);
    if (out->tv_nsec >= 1000000000L) {
        out->tv_sec += 1;
        out->tv_nsec -= 1000000000L;
    }
}

static void put_u16(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)(value >> 8U);
    out[1] = (uint8_t)value;
}

static uint16_t get_u16(const uint8_t *in)
{
    return (uint16_t)(((uint16_t)in[0] << 8U) | in[1]);
}

static void put_u32(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value >> 24U);
    out[1] = (uint8_t)(value >> 16U);
    out[2] = (uint8_t)(value >> 8U);
    out[3] = (uint8_t)value;
}

/* Builds an SWS2 envelope without validation, so tests can also craft malformed ones. */
static uint8_t *raw_sws2(uint8_t opcode,
                         int fin,
                         uint8_t rsv,
                         uint16_t close_code,
                         const void *payload,
                         size_t payload_len,
                         size_t *encoded_len)
{
    uint8_t *encoded = (uint8_t *)malloc(ST_ADMIN_SWS2_HEADER_BYTES + payload_len + 1U);
    if (encoded == NULL) {
        return NULL;
    }
    memcpy(encoded, "SWS2", 4U);
    encoded[4] = opcode;
    encoded[5] = (uint8_t)((fin ? 1U : 0U) | ((unsigned)rsv << 1U));
    put_u16(encoded + 6U, close_code);
    put_u32(encoded + 8U, (uint32_t)payload_len);
    if (payload_len > 0U) {
        memcpy(encoded + ST_ADMIN_SWS2_HEADER_BYTES, payload, payload_len);
    }
    *encoded_len = ST_ADMIN_SWS2_HEADER_BYTES + payload_len;
    return encoded;
}

static char *read_text_file(const char *path)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL || fseek(file, 0, SEEK_END) != 0) {
        if (file != NULL) fclose(file);
        return NULL;
    }
    long size = ftell(file);
    if (size < 0 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return NULL;
    }
    char *text = (char *)malloc((size_t)size + 1U);
    if (text == NULL || fread(text, 1U, (size_t)size, file) != (size_t)size) {
        free(text);
        fclose(file);
        return NULL;
    }
    fclose(file);
    text[size] = '\0';
    return text;
}

static int hex_nibble(char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static uint8_t *decode_hex(const char *hex, size_t *decoded_len)
{
    size_t len = hex == NULL ? 0U : strlen(hex);
    if (len == 0U || len % 2U != 0U) return NULL;
    uint8_t *decoded = (uint8_t *)malloc(len / 2U);
    if (decoded == NULL) return NULL;
    for (size_t i = 0U; i < len; i += 2U) {
        int high = hex_nibble(hex[i]);
        int low = hex_nibble(hex[i + 1U]);
        if (high < 0 || low < 0) {
            free(decoded);
            return NULL;
        }
        decoded[i / 2U] = (uint8_t)((high << 4) | low);
    }
    *decoded_len = len / 2U;
    return decoded;
}

/* ---------------------------------------------------------------- central vectors */

typedef struct {
    char *names[16];
    char *hex[16];
    size_t count;
} hex_fields;

/* Every "*Hex" field of the webSocket vector, so a newly added malformed sample is replayed too. */
static int collect_hex_fields(const char *object, hex_fields *fields)
{
    memset(fields, 0, sizeof(*fields));
    const char *cursor = object;
    while ((cursor = strstr(cursor, "Hex\"")) != NULL) {
        const char *start = cursor;
        while (start > object && start[-1] != '"') {
            --start;
        }
        size_t name_len = (size_t)(cursor + 3 - start);
        cursor += 4;
        const char *after = cursor;
        while (*after == ' ' || *after == '\n' || *after == '\r' || *after == '\t') ++after;
        if (*after != ':' || fields->count == sizeof(fields->names) / sizeof(fields->names[0])) {
            continue;
        }
        char *name = (char *)malloc(name_len + 1U);
        if (name == NULL) return -1;
        memcpy(name, start, name_len);
        name[name_len] = '\0';
        fields->names[fields->count] = name;
        fields->hex[fields->count] = st_json_get_string(object, name);
        if (fields->hex[fields->count] == NULL) return -1;
        ++fields->count;
    }
    return 0;
}

static void free_hex_fields(hex_fields *fields)
{
    for (size_t i = 0U; i < fields->count; ++i) {
        free(fields->names[i]);
        free(fields->hex[i]);
    }
    fields->count = 0U;
}

static int has_field(const hex_fields *fields, const char *name)
{
    for (size_t i = 0U; i < fields->count; ++i) {
        if (strcmp(fields->names[i], name) == 0) return 1;
    }
    return 0;
}

static char *load_websocket_vector(void)
{
    char *json = read_text_file(ST_APPLICATION_FIXTURE_FILE);
    if (json == NULL) return NULL;
    char *object = st_json_get_top_level_raw(json, "webSocket");
    free(json);
    return object;
}

static int test_central_vectors(void)
{
    char *object = load_websocket_vector();
    CHECK(object != NULL, "application-protocol-v2.json webSocket vector could not be read");
    int opcode = -1;
    int fin = -1;
    int rsv = -1;
    int close_code = -1;
    char *payload = st_json_get_string(object, "payloadUtf8");
    CHECK(st_json_get_int(object, "opcode", &opcode) == 0
              && st_json_get_bool(object, "finalFragment", &fin) == 0
              && st_json_get_int(object, "rsv", &rsv) == 0
              && st_json_get_int(object, "closeCode", &close_code) == 0
              && payload != NULL,
          "webSocket vector fields are missing");

    hex_fields fields;
    CHECK(collect_hex_fields(object, &fields) == 0, "webSocket vector hex fields could not be read");
    CHECK(has_field(&fields, "frameHex") && has_field(&fields, "invalidMagicHex")
              && has_field(&fields, "truncatedHex") && has_field(&fields, "trailingHex"),
          "webSocket vector lost one of its canonical/malformed samples");

    for (size_t i = 0U; i < fields.count; ++i) {
        size_t bytes_len = 0U;
        uint8_t *bytes = decode_hex(fields.hex[i], &bytes_len);
        CHECK(bytes != NULL, "%s is not hex", fields.names[i]);
        st_admin_sws2_frame frame;
        int decoded = st_admin_sws2_decode(bytes, bytes_len, &frame) == 0;
        if (strcmp(fields.names[i], "frameHex") == 0) {
            CHECK(decoded, "canonical SWS2 vector was rejected");
            CHECK(frame.opcode == opcode && frame.fin == fin && frame.rsv == rsv
                      && frame.close_code == close_code && frame.payload_len == strlen(payload)
                      && memcmp(frame.payload, payload, frame.payload_len) == 0,
                  "canonical SWS2 vector decoded to different fields");
            st_admin_sws2_frame expected = {
                .opcode = (uint8_t)opcode,
                .fin = fin,
                .rsv = (uint8_t)rsv,
                .close_code = (uint16_t)close_code,
                .payload = (const uint8_t *)payload,
                .payload_len = strlen(payload)
            };
            size_t encoded_len = 0U;
            uint8_t *encoded = st_admin_sws2_encode(&expected, &encoded_len);
            CHECK(encoded != NULL && encoded_len == bytes_len && memcmp(encoded, bytes, bytes_len) == 0,
                  "encoding the vector fields does not reproduce frameHex");
            free(encoded);
        } else {
            CHECK(!decoded, "malformed SWS2 vector %s was accepted", fields.names[i]);
        }
        free(bytes);
    }

    char **codes = NULL;
    size_t codes_len = 0U;
    CHECK(st_json_get_raw_array(object, "wireForbiddenCloseCodes", &codes, &codes_len) == 0
              && codes_len > 0U,
          "webSocket vector has no wire-forbidden close codes");
    for (size_t i = 0U; i < codes_len; ++i) {
        uint16_t code = (uint16_t)strtoul(codes[i], NULL, 10);
        st_admin_sws2_frame close_frame = {.opcode = 0x8U, .fin = 1, .close_code = code};
        size_t encoded_len = 0U;
        uint8_t *encoded = st_admin_sws2_encode(&close_frame, &encoded_len);
        CHECK(encoded == NULL, "wire-forbidden close code %u was encoded", (unsigned)code);
        uint8_t *raw = raw_sws2(0x8U, 1, 0U, code, NULL, 0U, &encoded_len);
        CHECK(raw != NULL && st_admin_sws2_decode(raw, encoded_len, NULL) != 0,
              "wire-forbidden close code %u was decoded", (unsigned)code);
        free(raw);
    }
    st_json_free_string_array(codes, codes_len);
    free_hex_fields(&fields);
    free(payload);
    free(object);
    return 0;
}

/* The same accept/reject table the Go and Java codecs assert. */
static int test_codec_rules(void)
{
    static uint8_t big[MAX_CHUNK + 1U];
    struct {
        const char *name;
        uint8_t opcode;
        int fin;
        uint8_t rsv;
        uint16_t close_code;
        size_t payload_len;
        int valid;
    } cases[] = {
        {"final text", 0x1U, 1, 0U, 0U, 5U, 1},
        {"empty text", 0x1U, 1, 0U, 0U, 0U, 1},
        {"fragment start", 0x2U, 0, 0U, 0U, 3U, 1},
        {"continuation", 0x0U, 1, 0U, 0U, 3U, 1},
        {"data rsv kept for extensions", 0x1U, 1, 4U, 0U, 1U, 1},
        {"max payload", 0x2U, 1, 0U, 0U, MAX_CHUNK, 1},
        {"payload over the NAT chunk limit", 0x2U, 1, 0U, 0U, MAX_CHUNK + 1U, 0},
        {"ping 125", 0x9U, 1, 0U, 0U, 125U, 1},
        {"pong over 125", 0xAU, 1, 0U, 0U, 126U, 0},
        {"fragmented ping", 0x9U, 0, 0U, 0U, 0U, 0},
        {"control with rsv", 0x8U, 1, 1U, 1000U, 0U, 0},
        {"close without code", 0x8U, 1, 0U, 0U, 0U, 1},
        {"close 1000 + 123-byte reason", 0x8U, 1, 0U, 1000U, 123U, 1},
        {"close reason over 123", 0x8U, 1, 0U, 1000U, 124U, 0},
        {"close reason without code", 0x8U, 1, 0U, 0U, 1U, 0},
        {"close 4999", 0x8U, 1, 0U, 4999U, 0U, 1},
        {"close 999", 0x8U, 1, 0U, 999U, 0U, 0},
        {"close 5000", 0x8U, 1, 0U, 5000U, 0U, 0},
        {"close 1004", 0x8U, 1, 0U, 1004U, 0U, 0},
        {"close code on data", 0x1U, 1, 0U, 1000U, 0U, 0},
        {"close code on ping", 0x9U, 1, 0U, 1000U, 0U, 0},
        {"unknown opcode 3", 0x3U, 1, 0U, 0U, 0U, 0},
        {"unknown opcode 11", 0xBU, 1, 0U, 0U, 0U, 0},
    };
    for (size_t i = 0U; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        st_admin_sws2_frame frame = {
            .opcode = cases[i].opcode,
            .fin = cases[i].fin,
            .rsv = cases[i].rsv,
            .close_code = cases[i].close_code,
            .payload = big,
            .payload_len = cases[i].payload_len
        };
        size_t encoded_len = 0U;
        uint8_t *encoded = st_admin_sws2_encode(&frame, &encoded_len);
        CHECK((encoded != NULL) == cases[i].valid, "encode %s: expected %s", cases[i].name,
              cases[i].valid ? "success" : "rejection");
        free(encoded);
        uint8_t *raw = raw_sws2(cases[i].opcode, cases[i].fin, cases[i].rsv, cases[i].close_code,
                                big, cases[i].payload_len, &encoded_len);
        CHECK(raw != NULL, "allocation failed");
        CHECK((st_admin_sws2_decode(raw, encoded_len, NULL) == 0) == cases[i].valid,
              "decode %s: expected %s", cases[i].name, cases[i].valid ? "success" : "rejection");
        free(raw);
    }

    size_t valid_len = 0U;
    uint8_t *valid = raw_sws2(0x1U, 1, 0U, 0U, "ok", 2U, &valid_len);
    CHECK(valid != NULL && st_admin_sws2_decode(valid, valid_len, NULL) == 0, "valid frame rejected");
    CHECK(st_admin_sws2_decode(valid, ST_ADMIN_SWS2_HEADER_BYTES - 1U, NULL) != 0,
          "truncated header accepted");
    CHECK(st_admin_sws2_decode(valid, valid_len - 1U, NULL) != 0, "truncated payload accepted");
    valid[5] |= 0x80U;
    CHECK(st_admin_sws2_decode(valid, valid_len, NULL) != 0, "unknown flag bits accepted");
    valid[5] = 1U;
    put_u32(valid + 8U, MAX_CHUNK + 1U);
    CHECK(st_admin_sws2_decode(valid, valid_len, NULL) != 0, "declared length over the limit accepted");
    put_u32(valid + 8U, 2U);
    valid[0] = 'X';
    CHECK(st_admin_sws2_decode(valid, valid_len, NULL) != 0, "bad magic accepted");
    free(valid);
    return 0;
}

/* ---------------------------------------------------------------- fake NAT session */

typedef struct {
    uint8_t *data;
    size_t len;
} captured_envelope;

typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    st_admin_direct_ws_stream *stream; /* the mapped reference, NULL once unmapped */
    int opened;
    captured_envelope *envelopes;
    size_t envelope_count;
    size_t envelope_cap;
    int auto_credit;
    int hold_close;
    int close_held;
    int release_close;
    int ended;
    int end_mapped;
    uint32_t end_reset_code;
    char end_reason[128];
    uint32_t nat_reset_code;
    int early_frame;
    int early_started;
    pthread_t early_thread;
    int early_result;
} fake_nat;

static fake_nat nat = {.lock = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};

static void nat_clear_envelopes(void)
{
    pthread_mutex_lock(&nat.lock);
    for (size_t i = 0U; i < nat.envelope_count; ++i) free(nat.envelopes[i].data);
    nat.envelope_count = 0U;
    pthread_mutex_unlock(&nat.lock);
}

static void nat_reset_state(void)
{
    nat_clear_envelopes();
    pthread_mutex_lock(&nat.lock);
    nat.stream = NULL;
    nat.opened = 0;
    nat.auto_credit = 1;
    nat.hold_close = 0;
    nat.close_held = 0;
    nat.release_close = 0;
    nat.ended = 0;
    nat.end_mapped = 0;
    nat.end_reset_code = 0U;
    nat.end_reason[0] = '\0';
    nat.nat_reset_code = 0U;
    nat.early_frame = 0;
    nat.early_started = 0;
    nat.early_result = 99;
    pthread_mutex_unlock(&nat.lock);
}

static st_admin_direct_ws_stream *nat_acquire(void)
{
    pthread_mutex_lock(&nat.lock);
    st_admin_direct_ws_stream *stream = nat.stream;
    st_admin_direct_ws_retain(stream);
    pthread_mutex_unlock(&nat.lock);
    return stream;
}

/* main.c's reset_ws_stream: unmap and "send" RST, unless the browser side ended it first. */
static void nat_unmap_reset(int result)
{
    pthread_mutex_lock(&nat.lock);
    st_admin_direct_ws_stream *stream = nat.stream;
    nat.stream = NULL;
    if (stream != NULL) nat.nat_reset_code = st_admin_direct_ws_reset_code(result, NULL);
    pthread_cond_broadcast(&nat.cond);
    pthread_mutex_unlock(&nat.lock);
    st_admin_direct_ws_release(stream);
}

/* Delivers one client DATA payload; returns the stream's verdict, or 1 if no longer mapped. */
static int client_deliver(const uint8_t *payload, size_t payload_len)
{
    st_admin_direct_ws_stream *stream = nat_acquire();
    if (stream == NULL) return 1;
    int result = st_admin_direct_ws_send_framed_payload(stream, payload, payload_len);
    st_admin_direct_ws_release(stream);
    if (result != ST_ADMIN_DIRECT_WS_ACCEPTED) nat_unmap_reset(result);
    return result;
}

static int client_send(uint8_t opcode, int fin, uint8_t rsv, uint16_t close_code,
                       const void *payload, size_t payload_len)
{
    size_t encoded_len = 0U;
    uint8_t *encoded = raw_sws2(opcode, fin, rsv, close_code, payload, payload_len, &encoded_len);
    if (encoded == NULL) return 2;
    int result = client_deliver(encoded, encoded_len);
    free(encoded);
    return result;
}

static int client_fin(void)
{
    st_admin_direct_ws_stream *stream = nat_acquire();
    if (stream == NULL) return 1;
    int result = st_admin_direct_ws_peer_finished(stream);
    st_admin_direct_ws_release(stream);
    if (result != ST_ADMIN_DIRECT_WS_ACCEPTED) nat_unmap_reset(result);
    return result;
}

static void client_rst(void)
{
    pthread_mutex_lock(&nat.lock);
    st_admin_direct_ws_stream *stream = nat.stream;
    nat.stream = NULL;
    pthread_mutex_unlock(&nat.lock);
    if (stream != NULL) {
        st_admin_direct_ws_peer_reset(stream);
        st_admin_direct_ws_release(stream);
    }
}

/* main.c's session_shutdown for one stream: the control connection is gone. */
static void control_connection_lost(void)
{
    pthread_mutex_lock(&nat.lock);
    st_admin_direct_ws_stream *stream = nat.stream;
    nat.stream = NULL;
    pthread_mutex_unlock(&nat.lock);
    if (stream != NULL) {
        st_admin_direct_ws_close(stream);
        st_admin_direct_ws_release(stream);
    }
}

static void *early_deliver(void *arg)
{
    (void)arg;
    int result = client_send(0x1U, 1, 0U, 0U, "early", 5U);
    pthread_mutex_lock(&nat.lock);
    nat.early_result = result;
    pthread_cond_broadcast(&nat.cond);
    pthread_mutex_unlock(&nat.lock);
    return NULL;
}

static int fake_ws_open(void *ctx, const st_admin_direct_ws_request *request)
{
    (void)ctx;
    pthread_mutex_lock(&nat.lock);
    nat.stream = request->stream;
    st_admin_direct_ws_retain(request->stream);
    nat.opened = 1;
    int early = nat.early_frame;
    pthread_cond_broadcast(&nat.cond);
    pthread_mutex_unlock(&nat.lock);
    if (early && pthread_create(&nat.early_thread, NULL, early_deliver, NULL) == 0) {
        nat.early_started = 1;
        /* Let the early frame reach the stream before the 101 response is written. */
        sleep_ms(150);
    }
    return 0;
}

static int fake_ws_data(void *ctx, const char *channel_id, const uint8_t *payload, size_t payload_len)
{
    (void)ctx;
    (void)channel_id;
    pthread_mutex_lock(&nat.lock);
    if (nat.stream == NULL) {
        pthread_mutex_unlock(&nat.lock);
        return -1;
    }
    if (nat.envelope_count == nat.envelope_cap) {
        size_t next = nat.envelope_cap == 0U ? 64U : nat.envelope_cap * 2U;
        captured_envelope *grown = (captured_envelope *)realloc(nat.envelopes, next * sizeof(*grown));
        if (grown == NULL) {
            pthread_mutex_unlock(&nat.lock);
            return -1;
        }
        nat.envelopes = grown;
        nat.envelope_cap = next;
    }
    uint8_t *copy = (uint8_t *)malloc(payload_len);
    if (copy == NULL) {
        pthread_mutex_unlock(&nat.lock);
        return -1;
    }
    memcpy(copy, payload, payload_len);
    nat.envelopes[nat.envelope_count].data = copy;
    nat.envelopes[nat.envelope_count].len = payload_len;
    ++nat.envelope_count;
    st_admin_direct_ws_stream *credit_stream = nat.auto_credit ? nat.stream : NULL;
    st_admin_direct_ws_retain(credit_stream);
    pthread_cond_broadcast(&nat.cond);
    if (payload_len > 4U && payload[4] == 0x8U && nat.hold_close) {
        nat.close_held = 1;
        pthread_cond_broadcast(&nat.cond);
        while (!nat.release_close) pthread_cond_wait(&nat.cond, &nat.lock);
    }
    pthread_mutex_unlock(&nat.lock);
    if (credit_stream != NULL) {
        (void)st_admin_direct_ws_add_send_credit(credit_stream, (uint32_t)payload_len);
        st_admin_direct_ws_release(credit_stream);
    }
    return 0;
}

static void fake_ws_close(void *ctx, const char *channel_id, uint32_t reset_code, const char *reason)
{
    (void)ctx;
    (void)channel_id;
    pthread_mutex_lock(&nat.lock);
    st_admin_direct_ws_stream *stream = nat.stream;
    nat.stream = NULL;
    nat.ended = 1;
    nat.end_mapped = stream != NULL;
    nat.end_reset_code = reset_code;
    snprintf(nat.end_reason, sizeof(nat.end_reason), "%s", reason == NULL ? "" : reason);
    pthread_cond_broadcast(&nat.cond);
    pthread_mutex_unlock(&nat.lock);
    st_admin_direct_ws_release(stream);
}

static int nat_wait_envelopes(size_t count, long long timeout_ms)
{
    struct timespec until;
    deadline_after(timeout_ms, &until);
    pthread_mutex_lock(&nat.lock);
    while (nat.envelope_count < count) {
        if (pthread_cond_timedwait(&nat.cond, &nat.lock, &until) == ETIMEDOUT) break;
    }
    int ok = nat.envelope_count >= count;
    pthread_mutex_unlock(&nat.lock);
    return ok ? 0 : -1;
}

static int nat_wait_ended(long long timeout_ms)
{
    struct timespec until;
    deadline_after(timeout_ms, &until);
    pthread_mutex_lock(&nat.lock);
    while (!nat.ended) {
        if (pthread_cond_timedwait(&nat.cond, &nat.lock, &until) == ETIMEDOUT) break;
    }
    int ok = nat.ended;
    pthread_mutex_unlock(&nat.lock);
    return ok ? 0 : -1;
}

static int nat_wait_close_held(long long timeout_ms)
{
    struct timespec until;
    deadline_after(timeout_ms, &until);
    pthread_mutex_lock(&nat.lock);
    while (!nat.close_held) {
        if (pthread_cond_timedwait(&nat.cond, &nat.lock, &until) == ETIMEDOUT) break;
    }
    int ok = nat.close_held;
    pthread_mutex_unlock(&nat.lock);
    return ok ? 0 : -1;
}

static void nat_release_close(void)
{
    pthread_mutex_lock(&nat.lock);
    nat.release_close = 1;
    pthread_cond_broadcast(&nat.cond);
    pthread_mutex_unlock(&nat.lock);
}

static size_t nat_envelope_count(void)
{
    pthread_mutex_lock(&nat.lock);
    size_t count = nat.envelope_count;
    pthread_mutex_unlock(&nat.lock);
    return count;
}

/* Decodes captured envelope index; every envelope the server sends must itself be valid SWS2. */
static int nat_envelope(size_t index, st_admin_sws2_frame *frame)
{
    pthread_mutex_lock(&nat.lock);
    int rc = index < nat.envelope_count
        ? st_admin_sws2_decode(nat.envelopes[index].data, nat.envelopes[index].len, frame)
        : -1;
    pthread_mutex_unlock(&nat.lock);
    return rc;
}

static int expect_envelope(size_t index, uint8_t opcode, int fin, uint16_t close_code,
                           const void *payload, size_t payload_len)
{
    st_admin_sws2_frame frame;
    CHECK(nat_wait_envelopes(index + 1U, WAIT_MS) == 0, "envelope %zu never arrived", index);
    CHECK(nat_envelope(index, &frame) == 0, "envelope %zu is not valid SWS2", index);
    CHECK(frame.opcode == opcode && frame.fin == fin && frame.rsv == 0U
              && frame.close_code == close_code && frame.payload_len == payload_len
              && (payload_len == 0U || memcmp(frame.payload, payload, payload_len) == 0),
          "envelope %zu: got opcode %u fin %d code %u len %zu, want opcode %u fin %d code %u len %zu",
          index, frame.opcode, frame.fin, frame.close_code, frame.payload_len, opcode, fin,
          close_code, payload_len);
    return 0;
}

/* ---------------------------------------------------------------- browser side */

static int admin_port;

static int browser_connect(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct timeval timeout = {.tv_sec = WAIT_MS / 1000, .tv_usec = 0};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons((uint16_t)admin_port);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(fd);
        return -1;
    }
    static const char request[] =
        "GET /http/Demo%20client/ws/echo?room=1 HTTP/1.1\r\nHost: localhost\r\n"
        "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
    if (send(fd, request, sizeof(request) - 1U, 0) != (ssize_t)(sizeof(request) - 1U)) {
        close(fd);
        return -1;
    }
    /* Read the response byte by byte so any frame that follows it stays in the socket. */
    char response[1024];
    size_t received = 0U;
    while (received + 1U < sizeof(response)) {
        if (recv(fd, response + received, 1U, 0) != 1) break;
        ++received;
        response[received] = '\0';
        if (received >= 4U && memcmp(response + received - 4U, "\r\n\r\n", 4U) == 0) break;
    }
    response[received] = '\0';
    if (strncmp(response, "HTTP/1.1 101 Switching Protocols\r\n", 34) != 0
        || strstr(response, "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n") == NULL) {
        fprintf(stderr, "unexpected upgrade response: %s\n", response);
        close(fd);
        return -1;
    }
    return fd;
}

static int send_all_bytes(int fd, const uint8_t *data, size_t len)
{
    size_t offset = 0U;
    while (offset < len) {
        ssize_t sent = send(fd, data + offset, len - offset, 0);
        if (sent < 0 && errno == EINTR) continue;
        if (sent <= 0) return -1;
        offset += (size_t)sent;
    }
    return 0;
}

/* Sends one masked browser frame using the shortest length encoding. */
static int browser_send(int fd, int fin, uint8_t rsv, uint8_t opcode, const void *payload, size_t len)
{
    static const uint8_t mask[4] = {0x37U, 0xfaU, 0x21U, 0x3dU};
    uint8_t header[14];
    size_t header_len = 0U;
    header[header_len++] = (uint8_t)((fin ? 0x80U : 0U) | ((unsigned)(rsv & 7U) << 4U) | (opcode & 0x0fU));
    if (len <= 125U) {
        header[header_len++] = (uint8_t)(0x80U | len);
    } else if (len <= 0xffffU) {
        header[header_len++] = 0x80U | 126U;
        header[header_len++] = (uint8_t)(len >> 8U);
        header[header_len++] = (uint8_t)len;
    } else {
        header[header_len++] = 0x80U | 127U;
        for (int i = 7; i >= 0; --i) {
            header[header_len++] = (uint8_t)(((uint64_t)len >> ((unsigned)i * 8U)) & 0xffU);
        }
    }
    memcpy(header + header_len, mask, sizeof(mask));
    header_len += sizeof(mask);
    uint8_t *masked = (uint8_t *)malloc(len == 0U ? 1U : len);
    if (masked == NULL) return -1;
    for (size_t i = 0U; i < len; ++i) masked[i] = ((const uint8_t *)payload)[i] ^ mask[i & 3U];
    int rc = send_all_bytes(fd, header, header_len) == 0 && send_all_bytes(fd, masked, len) == 0 ? 0 : -1;
    free(masked);
    return rc;
}

static int browser_send_close(int fd, uint16_t code, const char *reason)
{
    uint8_t payload[125];
    size_t reason_len = strlen(reason);
    put_u16(payload, code);
    memcpy(payload + 2U, reason, reason_len);
    return browser_send(fd, 1, 0U, 0x8U, payload, 2U + reason_len);
}

static int recv_exact(int fd, uint8_t *buffer, size_t len)
{
    size_t offset = 0U;
    while (offset < len) {
        ssize_t got = recv(fd, buffer + offset, len - offset, 0);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) return -1;
        offset += (size_t)got;
    }
    return 0;
}

typedef struct {
    int fin;
    uint8_t rsv;
    uint8_t opcode;
    uint8_t *payload;
    size_t len;
} ws_frame;

/* Reads one server frame (which must be unmasked); -1 on EOF, error or timeout. */
static int browser_read(int fd, ws_frame *frame)
{
    memset(frame, 0, sizeof(*frame));
    uint8_t header[2];
    if (recv_exact(fd, header, sizeof(header)) != 0 || (header[1] & 0x80U) != 0U) return -1;
    uint64_t len = header[1] & 0x7fU;
    if (len >= 126U) {
        uint8_t extended[8];
        size_t extended_len = len == 126U ? 2U : 8U;
        if (recv_exact(fd, extended, extended_len) != 0) return -1;
        len = 0U;
        for (size_t i = 0U; i < extended_len; ++i) len = (len << 8U) | extended[i];
    }
    frame->fin = (header[0] & 0x80U) != 0U;
    frame->rsv = (uint8_t)((header[0] >> 4U) & 7U);
    frame->opcode = header[0] & 0x0fU;
    frame->len = (size_t)len;
    frame->payload = (uint8_t *)malloc(frame->len == 0U ? 1U : frame->len);
    if (frame->payload == NULL || (frame->len > 0U && recv_exact(fd, frame->payload, frame->len) != 0)) {
        free(frame->payload);
        frame->payload = NULL;
        return -1;
    }
    return 0;
}

static int browser_expect(int fd, int fin, uint8_t opcode, const void *payload, size_t len)
{
    ws_frame frame;
    CHECK(browser_read(fd, &frame) == 0, "browser expected opcode %u but the socket ended", opcode);
    int ok = frame.fin == fin && frame.rsv == 0U && frame.opcode == opcode && frame.len == len
        && (len == 0U || memcmp(frame.payload, payload, len) == 0);
    uint8_t got_opcode = frame.opcode;
    size_t got_len = frame.len;
    int got_fin = frame.fin;
    free(frame.payload);
    CHECK(ok, "browser got opcode %u fin %d len %zu, want opcode %u fin %d len %zu",
          got_opcode, got_fin, got_len, opcode, fin, len);
    return 0;
}

static int browser_expect_close(int fd, uint16_t code, const char *reason)
{
    ws_frame frame;
    CHECK(browser_read(fd, &frame) == 0, "browser expected CLOSE %u but the socket ended", code);
    int ok = frame.opcode == 0x8U && frame.fin && frame.len >= 2U && get_u16(frame.payload) == code
        && (reason == NULL
            || (frame.len - 2U == strlen(reason) && memcmp(frame.payload + 2U, reason, frame.len - 2U) == 0));
    uint8_t got_opcode = frame.opcode;
    uint16_t got_code = frame.len >= 2U ? get_u16(frame.payload) : 0U;
    free(frame.payload);
    CHECK(ok, "browser got opcode %u code %u, want CLOSE %u", got_opcode, got_code, code);
    return 0;
}

/* Nothing but the end of the stream may follow: no frame after a CLOSE. */
static int browser_expect_eof(int fd)
{
    uint8_t byte;
    ssize_t got;
    do {
        got = recv(fd, &byte, 1U, 0);
    } while (got < 0 && errno == EINTR);
    CHECK(got == 0 || (got < 0 && errno == ECONNRESET),
          "browser expected end of stream, got %zd (errno %d)", got, got < 0 ? errno : 0);
    return 0;
}

/* Opens a session and waits until the fake NAT side mapped the stream. */
static int session_open(int *fd_out)
{
    int fd = browser_connect();
    CHECK(fd >= 0, "WebSocket upgrade failed");
    struct timespec until;
    deadline_after(WAIT_MS, &until);
    pthread_mutex_lock(&nat.lock);
    while (!nat.opened) {
        if (pthread_cond_timedwait(&nat.cond, &nat.lock, &until) == ETIMEDOUT) break;
    }
    int opened = nat.opened;
    pthread_mutex_unlock(&nat.lock);
    if (!opened) close(fd);
    CHECK(opened, "NAT side never saw the open");
    *fd_out = fd;
    return 0;
}

/* Closes the browser socket and waits for the server side to finish with the stream. */
static int session_finish(int fd)
{
    close(fd);
    CHECK(nat_wait_ended(WAIT_MS) == 0, "server never ended the NAT stream");
    pthread_mutex_lock(&nat.lock);
    int early = nat.early_started;
    nat.early_started = 0;
    pthread_mutex_unlock(&nat.lock);
    if (early) pthread_join(nat.early_thread, NULL);
    nat_reset_state();
    return 0;
}

static int expect_nat_end(int mapped, uint32_t reset_code)
{
    CHECK(nat_wait_ended(WAIT_MS) == 0, "server never ended the NAT stream");
    pthread_mutex_lock(&nat.lock);
    int got_mapped = nat.end_mapped;
    uint32_t got_code = nat.end_reset_code;
    char reason[128];
    snprintf(reason, sizeof(reason), "%s", nat.end_reason);
    pthread_mutex_unlock(&nat.lock);
    CHECK(got_mapped == mapped && (!mapped || got_code == reset_code),
          "NAT end: mapped %d reset %u (%s), want mapped %d reset %u", got_mapped,
          (unsigned)got_code, reason, mapped, (unsigned)reset_code);
    return 0;
}

/*
 * A refused client frame must end the stream with this RST. The NAT side and the browser thread
 * race to unmap it, so it may come from either: the fake's own reset, or the close callback.
 */
static int expect_nat_reset(uint32_t code)
{
    CHECK(nat_wait_ended(WAIT_MS) == 0, "server never ended the NAT stream");
    pthread_mutex_lock(&nat.lock);
    uint32_t direct = nat.nat_reset_code;
    int mapped = nat.end_mapped;
    uint32_t end_code = nat.end_reset_code;
    pthread_mutex_unlock(&nat.lock);
    CHECK(direct != 0U ? direct == code && !mapped : mapped && end_code == code,
          "stream ended with RST %u/%u (mapped %d), want RST %u", (unsigned)direct,
          (unsigned)end_code, mapped, (unsigned)code);
    return 0;
}

/* ---------------------------------------------------------------- state machine tests */

static int test_round_trip_and_browser_close(void)
{
    int fd;
    if (session_open(&fd) != 0) return 1;
    /* WINDOW_UPDATE must be positive and may never push the window past 16 MiB, even by wrapping. */
    st_admin_direct_ws_stream *stream = nat_acquire();
    CHECK(stream != NULL, "stream not mapped");
    int zero = st_admin_direct_ws_add_send_credit(stream, 0U);
    int wrap = st_admin_direct_ws_add_send_credit(stream, UINT32_MAX);
    int over = st_admin_direct_ws_add_send_credit(stream, 16U * 1024U * 1024U);
    st_admin_direct_ws_release(stream);
    CHECK(zero != 0 && wrap != 0 && over != 0, "invalid credit accepted (%d %d %d)", zero, wrap, over);
    CHECK(browser_send(fd, 1, 0U, 0x1U, "hello", 5U) == 0, "browser send failed");
    if (expect_envelope(0U, 0x1U, 1, 0U, "hello", 5U) != 0) return 1;
    CHECK(client_send(0x1U, 1, 0U, 0U, "hi", 2U) == ST_ADMIN_DIRECT_WS_ACCEPTED, "client text refused");
    if (browser_expect(fd, 1, 0x1U, "hi", 2U) != 0) return 1;
    CHECK(client_send(0x2U, 1, 0U, 0U, "\x00\xff\x10", 3U) == ST_ADMIN_DIRECT_WS_ACCEPTED,
          "client binary refused");
    if (browser_expect(fd, 1, 0x2U, "\x00\xff\x10", 3U) != 0) return 1;

    /* Browser-initiated close: echoed, forwarded as the terminal SWS2 CLOSE, then FIN. A frame the
     * browser sends after its CLOSE is never read. */
    CHECK(browser_send_close(fd, 1000U, "bye") == 0 && browser_send(fd, 1, 0U, 0x1U, "late", 4U) == 0,
          "browser close send failed");
    if (browser_expect_close(fd, 1000U, "bye") != 0) return 1;
    if (browser_expect_eof(fd) != 0) return 1;
    if (expect_envelope(1U, 0x8U, 1, 1000U, "bye", 3U) != 0) return 1;
    if (expect_nat_end(1, 0U) != 0) return 1;
    CHECK(nat_envelope_count() == 2U, "frames reached the client after the browser's CLOSE");
    /* The client's CLOSE reply arrives once the stream is already unmapped and is dropped. */
    CHECK(client_send(0x8U, 1, 0U, 1000U, "bye", 3U) == 1, "late client CLOSE was not dropped");
    return session_finish(fd);
}

static int test_browser_normalization(void)
{
    int fd;
    if (session_open(&fd) != 0) return 1;

    /* One large raw frame becomes MAX_CHUNK envelopes: first keeps the opcode, only the last FIN. */
    size_t big_len = 3U * MAX_CHUNK + 100U;
    uint8_t *big = (uint8_t *)malloc(big_len);
    CHECK(big != NULL, "allocation failed");
    for (size_t i = 0U; i < big_len; ++i) big[i] = (uint8_t)(i * 7U);
    CHECK(browser_send(fd, 1, 0U, 0x2U, big, big_len) == 0, "browser send failed");
    if (expect_envelope(0U, 0x2U, 0, 0U, big, MAX_CHUNK) != 0
        || expect_envelope(1U, 0x0U, 0, 0U, big + MAX_CHUNK, MAX_CHUNK) != 0
        || expect_envelope(2U, 0x0U, 0, 0U, big + 2U * MAX_CHUNK, MAX_CHUNK) != 0
        || expect_envelope(3U, 0x0U, 1, 0U, big + 3U * MAX_CHUNK, 100U) != 0) {
        free(big);
        return 1;
    }
    nat_clear_envelopes();

    /* A fragmented text message with control frames between the fragments: PING is answered
     * locally and not forwarded, PONG is forwarded, and the continuation keeps the message open. */
    memset(big, 'a', MAX_CHUNK + 10U);
    CHECK(browser_send(fd, 0, 0U, 0x1U, big, MAX_CHUNK + 10U) == 0
              && browser_send(fd, 1, 0U, 0x9U, "p1", 2U) == 0
              && browser_send(fd, 1, 0U, 0xAU, "q1", 2U) == 0
              && browser_send(fd, 1, 0U, 0x0U, "tail", 4U) == 0,
          "browser send failed");
    if (browser_expect(fd, 1, 0xAU, "p1", 2U) != 0
        || expect_envelope(0U, 0x1U, 0, 0U, big, MAX_CHUNK) != 0
        || expect_envelope(1U, 0x0U, 0, 0U, big, 10U) != 0
        || expect_envelope(2U, 0xAU, 1, 0U, "q1", 2U) != 0
        || expect_envelope(3U, 0x0U, 1, 0U, "tail", 4U) != 0) {
        free(big);
        return 1;
    }
    free(big);
    nat_clear_envelopes();

    /* A code point split across fragments is valid; an empty final text frame is one envelope. */
    CHECK(browser_send(fd, 0, 0U, 0x1U, "\xe4\xbd", 2U) == 0
              && browser_send(fd, 1, 0U, 0x0U, "\xa0", 1U) == 0
              && browser_send(fd, 1, 0U, 0x1U, "", 0U) == 0,
          "browser send failed");
    if (expect_envelope(0U, 0x1U, 0, 0U, "\xe4\xbd", 2U) != 0
        || expect_envelope(1U, 0x0U, 1, 0U, "\xa0", 1U) != 0
        || expect_envelope(2U, 0x1U, 1, 0U, "", 0U) != 0) {
        return 1;
    }
    nat_clear_envelopes();

    /* Exactly 16 MiB in one raw frame is the largest message accepted. */
    size_t limit = ST_ADMIN_WS_MAX_MESSAGE_BYTES;
    uint8_t *huge = (uint8_t *)malloc(limit);
    CHECK(huge != NULL, "allocation failed");
    for (size_t i = 0U; i < limit; ++i) huge[i] = (uint8_t)(i >> 9U);
    CHECK(browser_send(fd, 1, 0U, 0x2U, huge, limit) == 0, "browser send failed");
    size_t expected = (limit + MAX_CHUNK - 1U) / MAX_CHUNK;
    CHECK(nat_wait_envelopes(expected, WAIT_MS) == 0, "16 MiB frame was not forwarded in full");
    size_t offset = 0U;
    for (size_t i = 0U; i < expected; ++i) {
        st_admin_sws2_frame frame;
        CHECK(nat_envelope(i, &frame) == 0, "envelope %zu invalid", i);
        int last = i + 1U == expected;
        CHECK(frame.opcode == (i == 0U ? 0x2U : 0x0U) && frame.fin == last
                  && frame.payload_len == (last ? limit - offset : MAX_CHUNK)
                  && memcmp(frame.payload, huge + offset, frame.payload_len) == 0,
              "16 MiB envelope %zu is wrong", i);
        offset += frame.payload_len;
    }
    free(huge);
    nat_clear_envelopes();

    CHECK(browser_send_close(fd, 1000U, "") == 0, "browser close failed");
    if (browser_expect_close(fd, 1000U, "") != 0 || browser_expect_eof(fd) != 0) return 1;
    if (expect_nat_end(1, 0U) != 0) return 1;
    return session_finish(fd);
}

typedef struct {
    const char *name;
    uint8_t bytes[32];
    size_t len;
    uint16_t close_code;
    size_t forwarded_before;
} browser_violation;

/* Builds a masked frame into a violation case (mask zero keeps payload bytes readable). */
static size_t masked_frame(uint8_t *out, uint8_t first, const void *payload, size_t len)
{
    out[0] = first;
    out[1] = (uint8_t)(0x80U | len);
    memset(out + 2U, 0, 4U);
    memcpy(out + 6U, payload, len);
    return 6U + len;
}

static int run_browser_violation(const browser_violation *violation)
{
    int fd;
    if (session_open(&fd) != 0) return 1;
    CHECK(send_all_bytes(fd, violation->bytes, violation->len) == 0, "%s: send failed", violation->name);
    if (browser_expect_close(fd, violation->close_code, NULL) != 0 || browser_expect_eof(fd) != 0) {
        fprintf(stderr, "browser violation case: %s\n", violation->name);
        return 1;
    }
    /* The client hears the same close code, as the terminal envelope after what was forwarded. */
    st_admin_sws2_frame frame;
    CHECK(nat_wait_envelopes(violation->forwarded_before + 1U, WAIT_MS) == 0
              && nat_envelope(violation->forwarded_before, &frame) == 0 && frame.opcode == 0x8U
              && frame.close_code == violation->close_code
              && nat_envelope_count() == violation->forwarded_before + 1U,
          "%s: client did not get CLOSE %u last", violation->name, violation->close_code);
    if (expect_nat_end(1, 0U) != 0) {
        fprintf(stderr, "browser violation case: %s\n", violation->name);
        return 1;
    }
    return session_finish(fd);
}

static int test_browser_violations(void)
{
    browser_violation cases[32];
    size_t count = 0U;
    browser_violation *c;

#define ADD_CASE(case_name, code, before)                \
    c = &cases[count++];                                  \
    memset(c, 0, sizeof(*c));                             \
    c->name = (case_name);                                \
    c->close_code = (code);                               \
    c->forwarded_before = (before)

    ADD_CASE("unmasked frame", 1002U, 0U);
    c->bytes[0] = 0x81U; c->bytes[1] = 0x01U; c->bytes[2] = 'x'; c->len = 3U;
    ADD_CASE("RSV1 without an extension", 1002U, 0U);
    c->len = masked_frame(c->bytes, 0xc1U, "x", 1U);
    ADD_CASE("unknown data opcode", 1002U, 0U);
    c->len = masked_frame(c->bytes, 0x83U, "x", 1U);
    ADD_CASE("unknown control opcode", 1002U, 0U);
    c->len = masked_frame(c->bytes, 0x8bU, "", 0U);
    ADD_CASE("fragmented ping", 1002U, 0U);
    c->len = masked_frame(c->bytes, 0x09U, "p", 1U);
    ADD_CASE("ping longer than 125", 1002U, 0U);
    c->bytes[0] = 0x89U; c->bytes[1] = 0x80U | 126U; c->bytes[2] = 0U; c->bytes[3] = 126U; c->len = 4U;
    ADD_CASE("orphan continuation", 1002U, 0U);
    c->len = masked_frame(c->bytes, 0x80U, "x", 1U);
    ADD_CASE("new message inside a fragmented one", 1002U, 1U);
    c->len = masked_frame(c->bytes, 0x01U, "a", 1U);
    c->len += masked_frame(c->bytes + c->len, 0x82U, "b", 1U);
    ADD_CASE("non-minimal 16-bit length", 1002U, 0U);
    c->bytes[0] = 0x81U; c->bytes[1] = 0x80U | 126U; c->bytes[2] = 0U; c->bytes[3] = 5U; c->len = 8U + 5U;
    ADD_CASE("64-bit length with the top bit set", 1002U, 0U);
    c->bytes[0] = 0x82U; c->bytes[1] = 0x80U | 127U; c->bytes[2] = 0x80U; c->len = 10U;
    ADD_CASE("non-minimal 64-bit length", 1002U, 0U);
    c->bytes[0] = 0x82U; c->bytes[1] = 0x80U | 127U; c->bytes[9] = 100U; c->len = 10U;
    ADD_CASE("close payload of one byte", 1002U, 0U);
    c->len = masked_frame(c->bytes, 0x88U, "\x03", 1U);
    ADD_CASE("close code 1005", 1002U, 0U);
    c->len = masked_frame(c->bytes, 0x88U, "\x03\xed", 2U);
    ADD_CASE("close code 999", 1002U, 0U);
    c->len = masked_frame(c->bytes, 0x88U, "\x03\xe7", 2U);
    ADD_CASE("close code 1015", 1002U, 0U);
    c->len = masked_frame(c->bytes, 0x88U, "\x03\xf7", 2U);
    ADD_CASE("close code 5000", 1002U, 0U);
    c->len = masked_frame(c->bytes, 0x88U, "\x13\x88", 2U);
    ADD_CASE("close reason with invalid UTF-8", 1007U, 0U);
    c->len = masked_frame(c->bytes, 0x88U, "\x03\xe8\xff", 3U);
    ADD_CASE("text with an invalid byte", 1007U, 0U);
    c->len = masked_frame(c->bytes, 0x81U, "a\xff", 2U);
    ADD_CASE("text with an overlong encoding", 1007U, 0U);
    c->len = masked_frame(c->bytes, 0x81U, "\xc0\xaf", 2U);
    ADD_CASE("text with a UTF-16 surrogate", 1007U, 0U);
    c->len = masked_frame(c->bytes, 0x81U, "\xed\xa0\x80", 3U);
    ADD_CASE("text above U+10FFFF", 1007U, 0U);
    c->len = masked_frame(c->bytes, 0x81U, "\xf4\x90\x80\x80", 4U);
    ADD_CASE("final text ending inside a code point", 1007U, 0U);
    c->len = masked_frame(c->bytes, 0x81U, "\xe4\xbd", 2U);
    ADD_CASE("message ending inside a code point", 1007U, 1U);
    c->len = masked_frame(c->bytes, 0x01U, "\xe4", 1U);
    c->len += masked_frame(c->bytes + c->len, 0x80U, "", 0U);
    ADD_CASE("frame over 16 MiB", 1009U, 0U);
    c->bytes[0] = 0x82U; c->bytes[1] = 0x80U | 127U;
    put_u32(c->bytes + 6U, ST_ADMIN_WS_MAX_MESSAGE_BYTES + 1U);
    c->len = 10U;
#undef ADD_CASE

    for (size_t i = 0U; i < count; ++i) {
        if (run_browser_violation(&cases[i]) != 0) return 1;
    }

    /* A fragmented message that crosses 16 MiB is refused at the frame that crosses it. */
    int fd;
    if (session_open(&fd) != 0) return 1;
    size_t limit = ST_ADMIN_WS_MAX_MESSAGE_BYTES;
    uint8_t *half = (uint8_t *)calloc(1U, limit / 2U);
    CHECK(half != NULL, "allocation failed");
    CHECK(browser_send(fd, 0, 0U, 0x2U, half, limit / 2U) == 0
              && browser_send(fd, 0, 0U, 0x0U, half, limit / 2U) == 0,
          "browser send failed");
    free(half);
    size_t forwarded = 2U * ((limit / 2U + MAX_CHUNK - 1U) / MAX_CHUNK);
    CHECK(nat_wait_envelopes(forwarded, WAIT_MS) == 0, "the first 16 MiB were not forwarded");
    uint8_t one_more[7] = {0x80U, 0x81U, 0, 0, 0, 0, 'x'};
    CHECK(send_all_bytes(fd, one_more, sizeof(one_more)) == 0, "browser send failed");
    if (browser_expect_close(fd, 1009U, NULL) != 0 || browser_expect_eof(fd) != 0) return 1;
    st_admin_sws2_frame frame;
    CHECK(nat_wait_envelopes(forwarded + 1U, WAIT_MS) == 0 && nat_envelope(forwarded, &frame) == 0
              && frame.opcode == 0x8U && frame.close_code == 1009U,
          "client did not get CLOSE 1009 for the oversized message");
    if (expect_nat_end(1, 0U) != 0) return 1;
    return session_finish(fd);
}

static int test_close_browser_initiated_races_client_reply(void)
{
    /* The client's CLOSE reply arrives while the server is still forwarding the browser's CLOSE:
     * it completes the handshake silently; anything after it is a violation. */
    int fd;
    if (session_open(&fd) != 0) return 1;
    pthread_mutex_lock(&nat.lock);
    nat.hold_close = 1;
    pthread_mutex_unlock(&nat.lock);
    CHECK(browser_send_close(fd, 1000U, "bye") == 0, "browser close failed");
    if (browser_expect_close(fd, 1000U, "bye") != 0) return 1;
    CHECK(nat_wait_close_held(WAIT_MS) == 0, "browser CLOSE never reached the client");
    CHECK(client_send(0x1U, 1, 0U, 0U, "in-flight", 9U) == ST_ADMIN_DIRECT_WS_ACCEPTED,
          "in-flight client data after the browser's CLOSE was refused instead of dropped");
    CHECK(client_send(0x8U, 1, 0U, 1000U, "bye", 3U) == ST_ADMIN_DIRECT_WS_ACCEPTED,
          "client CLOSE reply was refused");
    CHECK(client_send(0x9U, 1, 0U, 0U, "", 0U) == ST_ADMIN_DIRECT_WS_INVALID,
          "a frame after the client's CLOSE was accepted");
    nat_release_close();
    if (browser_expect_eof(fd) != 0) return 1;
    if (expect_nat_reset(ST_ADMIN_DIRECT_WS_RST_INVALID_SWS2) != 0) return 1;
    if (session_finish(fd) != 0) return 1;

    /* Same race, ending cleanly with the client's FIN. */
    if (session_open(&fd) != 0) return 1;
    pthread_mutex_lock(&nat.lock);
    nat.hold_close = 1;
    pthread_mutex_unlock(&nat.lock);
    CHECK(browser_send_close(fd, 4000U, "app") == 0, "browser close failed");
    if (browser_expect_close(fd, 4000U, "app") != 0) return 1;
    CHECK(nat_wait_close_held(WAIT_MS) == 0, "browser CLOSE never reached the client");
    CHECK(client_send(0x8U, 1, 0U, 4000U, "app", 3U) == ST_ADMIN_DIRECT_WS_ACCEPTED
              && client_fin() == ST_ADMIN_DIRECT_WS_ACCEPTED,
          "client CLOSE + FIN refused");
    nat_release_close();
    if (browser_expect_eof(fd) != 0) return 1;
    if (expect_envelope(0U, 0x8U, 1, 4000U, "app", 3U) != 0) return 1;
    if (expect_nat_end(1, 0U) != 0) return 1;
    return session_finish(fd);
}

static int test_close_client_initiated(void)
{
    int fd;
    if (session_open(&fd) != 0) return 1;
    CHECK(client_send(0x8U, 1, 0U, 1001U, "gone", 4U) == ST_ADMIN_DIRECT_WS_ACCEPTED, "client CLOSE refused");
    if (browser_expect_close(fd, 1001U, "gone") != 0) return 1;
    CHECK(client_fin() == ST_ADMIN_DIRECT_WS_ACCEPTED, "client FIN after CLOSE refused");
    /* Until its CLOSE reply the browser may still send data; the server sends nothing more. */
    CHECK(browser_send(fd, 1, 0U, 0x1U, "late", 4U) == 0 && browser_send(fd, 1, 0U, 0x9U, "p", 1U) == 0,
          "browser send failed");
    if (expect_envelope(0U, 0x1U, 1, 0U, "late", 4U) != 0) return 1;
    CHECK(browser_send_close(fd, 1001U, "gone") == 0, "browser close reply failed");
    if (expect_envelope(1U, 0x8U, 1, 1001U, "gone", 4U) != 0) return 1;
    if (expect_nat_end(1, 0U) != 0) return 1;
    if (browser_expect_eof(fd) != 0) return 1;
    if (session_finish(fd) != 0) return 1;

    /* The client's CLOSE is terminal: a frame after it resets the stream. */
    if (session_open(&fd) != 0) return 1;
    CHECK(client_send(0x8U, 1, 0U, 0U, "", 0U) == ST_ADMIN_DIRECT_WS_ACCEPTED, "client CLOSE refused");
    ws_frame frame;
    CHECK(browser_read(fd, &frame) == 0 && frame.opcode == 0x8U && frame.len == 0U,
          "browser did not get the empty CLOSE");
    free(frame.payload);
    CHECK(client_send(0x1U, 1, 0U, 0U, "after", 5U) == ST_ADMIN_DIRECT_WS_INVALID,
          "data after the client's CLOSE was accepted");
    if (browser_expect_eof(fd) != 0) return 1;
    if (expect_nat_reset(ST_ADMIN_DIRECT_WS_RST_INVALID_SWS2) != 0) return 1;
    return session_finish(fd);
}

static int test_close_reply_timeout(void)
{
    int fd;
    if (session_open(&fd) != 0) return 1;
    long long started = now_ms();
    CHECK(client_send(0x8U, 1, 0U, 1000U, "", 0U) == ST_ADMIN_DIRECT_WS_ACCEPTED, "client CLOSE refused");
    if (browser_expect_close(fd, 1000U, "") != 0) return 1;
    /* The browser never answers: the server gives up after the close timeout and ends with FIN. */
    if (expect_nat_end(1, 0U) != 0) return 1;
    long long waited = now_ms() - started;
    CHECK(waited >= 4500 && waited < 9000, "close reply wait took %lld ms", waited);
    CHECK(nat_envelope_count() == 0U, "an SWS2 CLOSE was invented without the browser's reply");
    if (browser_expect_eof(fd) != 0) return 1;
    return session_finish(fd);
}

static int test_client_fin_and_reset(void)
{
    /* FIN without CLOSE: the browser hears 1001 and its reply returns as SWS2 CLOSE + FIN. */
    int fd;
    if (session_open(&fd) != 0) return 1;
    CHECK(client_fin() == ST_ADMIN_DIRECT_WS_ACCEPTED, "client FIN refused");
    if (browser_expect_close(fd, 1001U, "") != 0) return 1;
    CHECK(browser_send_close(fd, 1001U, "") == 0, "browser close reply failed");
    if (expect_envelope(0U, 0x8U, 1, 1001U, "", 0U) != 0) return 1;
    if (expect_nat_end(1, 0U) != 0) return 1;
    if (browser_expect_eof(fd) != 0) return 1;
    if (session_finish(fd) != 0) return 1;

    /* DATA after FIN and a second FIN are stream-state violations (RST 7). */
    if (session_open(&fd) != 0) return 1;
    CHECK(client_fin() == ST_ADMIN_DIRECT_WS_ACCEPTED, "client FIN refused");
    if (browser_expect_close(fd, 1001U, "") != 0) return 1;
    CHECK(client_send(0x1U, 1, 0U, 0U, "x", 1U) == ST_ADMIN_DIRECT_WS_AFTER_FIN, "DATA after FIN accepted");
    if (browser_expect_eof(fd) != 0) return 1;
    if (expect_nat_reset(ST_ADMIN_DIRECT_WS_RST_STREAM_STATE) != 0) return 1;
    if (session_finish(fd) != 0) return 1;

    if (session_open(&fd) != 0) return 1;
    CHECK(client_fin() == ST_ADMIN_DIRECT_WS_ACCEPTED && client_fin() == ST_ADMIN_DIRECT_WS_AFTER_FIN,
          "a second FIN was accepted");
    if (browser_expect_close(fd, 1001U, "") != 0 || browser_expect_eof(fd) != 0) return 1;
    if (expect_nat_reset(ST_ADMIN_DIRECT_WS_RST_STREAM_STATE) != 0) return 1;
    if (session_finish(fd) != 0) return 1;

    /* RST: the browser hears 1011 and nothing goes back to the client. */
    if (session_open(&fd) != 0) return 1;
    client_rst();
    if (browser_expect_close(fd, 1011U, "WebSocket tunnel reset") != 0 || browser_expect_eof(fd) != 0) return 1;
    if (expect_nat_end(0, 0U) != 0) return 1;
    CHECK(nat_envelope_count() == 0U, "frames reached the client after its RST");
    if (session_finish(fd) != 0) return 1;

    /* Losing the control connection closes the browser with 1001. */
    if (session_open(&fd) != 0) return 1;
    control_connection_lost();
    if (browser_expect_close(fd, 1001U, "") != 0 || browser_expect_eof(fd) != 0) return 1;
    if (expect_nat_end(0, 0U) != 0) return 1;
    return session_finish(fd);
}

/* Every client-side violation: RST 30 to the client and 1002 to the browser. */
static int run_client_violation(const char *name,
                                const uint8_t *const *frames,
                                const size_t *lens,
                                size_t count,
                                size_t accepted_before)
{
    int fd;
    if (session_open(&fd) != 0) return 1;
    for (size_t i = 0U; i < count; ++i) {
        int result = client_deliver(frames[i], lens[i]);
        int want = i < accepted_before ? ST_ADMIN_DIRECT_WS_ACCEPTED : ST_ADMIN_DIRECT_WS_INVALID;
        CHECK(result == want, "%s: frame %zu result %d, want %d", name, i, result, want);
        if (result == ST_ADMIN_DIRECT_WS_ACCEPTED) {
            ws_frame frame;
            CHECK(browser_read(fd, &frame) == 0, "%s: accepted frame %zu never reached the browser", name, i);
            free(frame.payload);
        }
    }
    if (browser_expect_close(fd, 1002U, "invalid WebSocket frame") != 0 || browser_expect_eof(fd) != 0
        || expect_nat_reset(ST_ADMIN_DIRECT_WS_RST_INVALID_SWS2) != 0) {
        fprintf(stderr, "client violation case: %s\n", name);
        return 1;
    }
    return session_finish(fd);
}

static int test_client_violations(void)
{
    /* The central malformed vectors, delivered as client DATA. */
    char *object = load_websocket_vector();
    CHECK(object != NULL, "webSocket vector could not be read");
    hex_fields fields;
    CHECK(collect_hex_fields(object, &fields) == 0, "webSocket vector hex fields could not be read");
    for (size_t i = 0U; i < fields.count; ++i) {
        size_t len = 0U;
        uint8_t *bytes = decode_hex(fields.hex[i], &len);
        CHECK(bytes != NULL, "%s is not hex", fields.names[i]);
        const uint8_t *frames[1] = {bytes};
        int rc;
        if (strcmp(fields.names[i], "frameHex") == 0) {
            int fd;
            if (session_open(&fd) != 0) return 1;
            CHECK(client_deliver(bytes, len) == ST_ADMIN_DIRECT_WS_ACCEPTED, "canonical vector refused");
            rc = browser_expect(fd, 1, 0x1U, "hello", 5U) != 0 || session_finish(fd) != 0;
        } else {
            rc = run_client_violation(fields.names[i], frames, &len, 1U, 0U);
        }
        free(bytes);
        if (rc != 0) return 1;
    }
    free_hex_fields(&fields);
    free(object);

    struct {
        const char *name;
        uint8_t opcode[3];
        int fin[3];
        uint8_t rsv[3];
        uint16_t code[3];
        const char *payload[3];
        size_t payload_len[3];
        size_t count;
        size_t accepted_before;
    } cases[] = {
        {"RSV on data", {0x1U}, {1}, {4U}, {0U}, {"x"}, {1U}, 1U, 0U},
        {"orphan continuation", {0x0U}, {1}, {0U}, {0U}, {"x"}, {1U}, 1U, 0U},
        {"new message inside a fragmented one", {0x2U, 0x1U}, {0, 1}, {0U, 0U}, {0U, 0U}, {"a", "b"},
         {1U, 1U}, 2U, 1U},
        {"invalid UTF-8 text", {0x1U}, {1}, {0U}, {0U}, {"\xff"}, {1U}, 1U, 0U},
        {"final text ending inside a code point", {0x1U}, {1}, {0U}, {0U}, {"\xe4\xbd"}, {2U}, 1U, 0U},
        {"message ending inside a code point", {0x1U, 0x0U}, {0, 1}, {0U, 0U}, {0U, 0U}, {"\xe4", ""},
         {1U, 0U}, 2U, 1U},
        {"close reason with invalid UTF-8", {0x8U}, {1}, {0U}, {1000U}, {"\xc3"}, {1U}, 1U, 0U},
        {"wire-forbidden close code", {0x8U}, {1}, {0U}, {1006U}, {""}, {0U}, 1U, 0U},
        {"fragmented control frame", {0x9U}, {0}, {0U}, {0U}, {""}, {0U}, 1U, 0U},
    };
    for (size_t i = 0U; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint8_t *frames[3] = {NULL, NULL, NULL};
        size_t lens[3] = {0U, 0U, 0U};
        for (size_t j = 0U; j < cases[i].count; ++j) {
            frames[j] = raw_sws2(cases[i].opcode[j], cases[i].fin[j], cases[i].rsv[j], cases[i].code[j],
                                 cases[i].payload[j], cases[i].payload_len[j], &lens[j]);
            CHECK(frames[j] != NULL, "allocation failed");
        }
        int rc = run_client_violation(cases[i].name, (const uint8_t *const *)frames, lens,
                                      cases[i].count, cases[i].accepted_before);
        for (size_t j = 0U; j < cases[i].count; ++j) free(frames[j]);
        if (rc != 0) return 1;
    }
    return 0;
}

typedef struct {
    int fd;
    size_t frames;
    size_t bytes;
    uint8_t last_opcode;
    uint16_t last_close_code;
} browser_drain;

static void *drain_browser(void *arg)
{
    browser_drain *drain = (browser_drain *)arg;
    ws_frame frame;
    while (browser_read(drain->fd, &frame) == 0) {
        ++drain->frames;
        drain->bytes += frame.len;
        drain->last_opcode = frame.opcode;
        drain->last_close_code = frame.opcode == 0x8U && frame.len >= 2U ? get_u16(frame.payload) : 0U;
        free(frame.payload);
    }
    return NULL;
}

static int test_client_message_limit(void)
{
    /* The client's message is capped at 16 MiB across its continuations, like the Go/Java
     * reassembly limit; the browser keeps reading meanwhile. */
    int fd;
    if (session_open(&fd) != 0) return 1;
    browser_drain drain = {.fd = fd};
    pthread_t reader;
    CHECK(pthread_create(&reader, NULL, drain_browser, &drain) == 0, "reader thread failed");
    static uint8_t chunk[MAX_CHUNK];
    size_t sent = 0U;
    int result = ST_ADMIN_DIRECT_WS_ACCEPTED;
    size_t index = 0U;
    while (result == ST_ADMIN_DIRECT_WS_ACCEPTED) {
        result = client_send(index == 0U ? 0x2U : 0x0U, 0, 0U, 0U, chunk, MAX_CHUNK);
        if (result == ST_ADMIN_DIRECT_WS_ACCEPTED) sent += MAX_CHUNK;
        ++index;
    }
    pthread_join(reader, NULL);
    CHECK(result == ST_ADMIN_DIRECT_WS_INVALID, "oversized message ended with %d", result);
    CHECK(sent <= ST_ADMIN_WS_MAX_MESSAGE_BYTES && sent + MAX_CHUNK > ST_ADMIN_WS_MAX_MESSAGE_BYTES,
          "refused after %zu bytes", sent);
    CHECK(drain.bytes == sent + 2U + strlen("invalid WebSocket frame") && drain.last_opcode == 0x8U
              && drain.last_close_code == 1002U,
          "browser got %zu bytes, last opcode %u code %u", drain.bytes, drain.last_opcode,
          drain.last_close_code);
    if (expect_nat_reset(ST_ADMIN_DIRECT_WS_RST_INVALID_SWS2) != 0) return 1;
    return session_finish(fd);
}

static int test_client_fragments_and_control(void)
{
    int fd;
    if (session_open(&fd) != 0) return 1;
    /* Fragments keep their physical boundaries; control frames may sit between them; a code point
     * may be split across fragments. */
    CHECK(client_send(0x1U, 0, 0U, 0U, "ab", 2U) == ST_ADMIN_DIRECT_WS_ACCEPTED
              && client_send(0x9U, 1, 0U, 0U, "p", 1U) == ST_ADMIN_DIRECT_WS_ACCEPTED
              && client_send(0x0U, 0, 0U, 0U, "\xe4\xbd", 2U) == ST_ADMIN_DIRECT_WS_ACCEPTED
              && client_send(0xAU, 1, 0U, 0U, "q", 1U) == ST_ADMIN_DIRECT_WS_ACCEPTED
              && client_send(0x0U, 1, 0U, 0U, "\xa0", 1U) == ST_ADMIN_DIRECT_WS_ACCEPTED,
          "client fragments refused");
    if (browser_expect(fd, 0, 0x1U, "ab", 2U) != 0 || browser_expect(fd, 1, 0x9U, "p", 1U) != 0
        || browser_expect(fd, 0, 0x0U, "\xe4\xbd", 2U) != 0 || browser_expect(fd, 1, 0xAU, "q", 1U) != 0
        || browser_expect(fd, 1, 0x0U, "\xa0", 1U) != 0) {
        return 1;
    }
    /* The browser's PONG to the client's PING goes back as SWS2 PONG. */
    CHECK(browser_send(fd, 1, 0U, 0xAU, "p", 1U) == 0, "browser pong failed");
    if (expect_envelope(0U, 0xAU, 1, 0U, "p", 1U) != 0) return 1;
    CHECK(browser_send_close(fd, 1000U, "") == 0, "browser close failed");
    if (browser_expect_close(fd, 1000U, "") != 0 || browser_expect_eof(fd) != 0) return 1;
    if (expect_nat_end(1, 0U) != 0) return 1;
    return session_finish(fd);
}

static int test_handshake_gate(void)
{
    /* A client frame that races the 101 response must reach the browser after it. */
    pthread_mutex_lock(&nat.lock);
    nat.early_frame = 1;
    pthread_mutex_unlock(&nat.lock);
    int fd;
    if (session_open(&fd) != 0) return 1;
    if (browser_expect(fd, 1, 0x1U, "early", 5U) != 0) return 1;
    struct timespec until;
    deadline_after(WAIT_MS, &until);
    pthread_mutex_lock(&nat.lock);
    while (nat.early_result == 99) {
        if (pthread_cond_timedwait(&nat.cond, &nat.lock, &until) == ETIMEDOUT) break;
    }
    int early = nat.early_result;
    pthread_mutex_unlock(&nat.lock);
    CHECK(early == ST_ADMIN_DIRECT_WS_ACCEPTED, "early frame result %d", early);
    CHECK(browser_send_close(fd, 1000U, "") == 0, "browser close failed");
    if (browser_expect_close(fd, 1000U, "") != 0 || browser_expect_eof(fd) != 0) return 1;
    if (expect_nat_end(1, 0U) != 0) return 1;
    return session_finish(fd);
}

static int test_close_credit_timeout(void)
{
    /* With the client withholding credit, the browser's CLOSE cannot be forwarded; after the close
     * timeout the stream is reset instead of hanging (Java's close credit timeout). */
    int fd;
    if (session_open(&fd) != 0) return 1;
    pthread_mutex_lock(&nat.lock);
    nat.auto_credit = 0;
    pthread_mutex_unlock(&nat.lock);
    size_t window = 1024U * 1024U;
    size_t envelopes = window / (MAX_CHUNK + ST_ADMIN_SWS2_HEADER_BYTES);
    size_t len = envelopes * MAX_CHUNK;
    uint8_t *data = (uint8_t *)calloc(1U, len);
    CHECK(data != NULL, "allocation failed");
    CHECK(browser_send(fd, 1, 0U, 0x2U, data, len) == 0, "browser send failed");
    free(data);
    CHECK(nat_wait_envelopes(envelopes, WAIT_MS) == 0, "the initial window was not used");
    long long started = now_ms();
    CHECK(browser_send_close(fd, 1000U, "") == 0, "browser close failed");
    if (browser_expect_close(fd, 1000U, "") != 0) return 1;
    if (expect_nat_end(1, ST_ADMIN_DIRECT_WS_RST_BROWSER_GONE) != 0) return 1;
    long long waited = now_ms() - started;
    CHECK(waited >= 4500 && waited < 9000, "close credit wait took %lld ms", waited);
    CHECK(nat_envelope_count() == envelopes, "an envelope was sent without credit");
    if (browser_expect_eof(fd) != 0) return 1;
    return session_finish(fd);
}

static int start_admin(st_admin_server *server)
{
    if (st_admin_server_start_with_handlers(server, 0, "", NULL, NULL, fake_ws_open, fake_ws_data,
                                            fake_ws_close, NULL) != 0) {
        return -1;
    }
    struct sockaddr_in address;
    socklen_t address_len = sizeof(address);
    memset(&address, 0, sizeof(address));
    if (getsockname(server->fd, (struct sockaddr *)&address, &address_len) != 0) return -1;
    admin_port = ntohs(address.sin_port);
    return 0;
}

int main(void)
{
    /* The server writes to sockets the test closes on purpose. */
    (void)signal(SIGPIPE, SIG_IGN);
    unsetenv("SPECUS_DATABASE_PATH");
    setenv("SPECUS_ENV", "test", 1);
    /* Without a database only SPECUS_HTTP_ROUTES routes are admitted at the public entry. */
    setenv("SPECUS_HTTP_ROUTES", "ws=http://127.0.0.1:8080", 1);

    if (test_central_vectors() != 0 || test_codec_rules() != 0) return 1;

    st_admin_server server;
    memset(&server, 0, sizeof(server));
    if (start_admin(&server) != 0) {
        fprintf(stderr, "admin server start failed\n");
        return 1;
    }
    nat_reset_state();

    struct {
        const char *name;
        int (*run)(void);
    } tests[] = {
        {"round trip and browser close", test_round_trip_and_browser_close},
        {"browser normalization", test_browser_normalization},
        {"browser violations", test_browser_violations},
        {"browser close racing the client's reply", test_close_browser_initiated_races_client_reply},
        {"client-initiated close", test_close_client_initiated},
        {"close reply timeout", test_close_reply_timeout},
        {"client FIN and RST", test_client_fin_and_reset},
        {"client violations", test_client_violations},
        {"client message limit", test_client_message_limit},
        {"client fragments and control frames", test_client_fragments_and_control},
        {"handshake gate", test_handshake_gate},
        {"close credit timeout", test_close_credit_timeout},
    };
    for (size_t i = 0U; i < sizeof(tests) / sizeof(tests[0]); ++i) {
        long long started = now_ms();
        if (tests[i].run() != 0) {
            fprintf(stderr, "FAILED: %s\n", tests[i].name);
            return 1;
        }
        printf("ok - %s (%lld ms)\n", tests[i].name, now_ms() - started);
    }
    shutdown(server.fd, SHUT_RDWR);
    close(server.fd);
    printf("direct websocket tests passed\n");
    return 0;
}
