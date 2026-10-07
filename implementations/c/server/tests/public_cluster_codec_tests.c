/*
 * The STCE v2 Pub/Sub envelope and the cluster identifiers against the Java reference
 * (PublicTransferClusterFrameTests, PublicTransferCoordinationServiceTests) and the shared vector
 * protocol/test-vectors/public-transfer-cluster-v2.json. The Redis round trip of the same envelope
 * is covered by public_coordination_tests and public_discovery_cluster_e2e.
 */
#define _POSIX_C_SOURCE 200809L

#include "crypto.h"
#include "json.h"
#include "public_coordination.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef ST_CLUSTER_VECTOR_FILE
#define ST_CLUSTER_VECTOR_FILE "../../../protocol/test-vectors/public-transfer-cluster-v2.json"
#endif

#define CHECK(condition, ...)                                   \
    do {                                                        \
        if (!(condition)) {                                     \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
            fprintf(stderr, __VA_ARGS__);                       \
            fprintf(stderr, "\n");                              \
            return 1;                                           \
        }                                                       \
    } while (0)

static char *read_text(const char *path)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        perror(path);
        return NULL;
    }
    char *text = NULL;
    long len = fseek(file, 0, SEEK_END) == 0 ? ftell(file) : -1;
    if (len >= 0 && fseek(file, 0, SEEK_SET) == 0 && (text = (char *)malloc((size_t)len + 1U)) != NULL) {
        if (fread(text, 1U, (size_t)len, file) != (size_t)len) {
            free(text);
            text = NULL;
        } else {
            text[len] = '\0';
        }
    }
    fclose(file);
    return text;
}

static int hex_value(char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

/* Decodes the vector's frameHex; the caller frees the bytes. */
static uint8_t *hex_bytes(const char *hex, size_t *len)
{
    size_t hex_len = strlen(hex);
    uint8_t *bytes = hex_len % 2U == 0U ? (uint8_t *)malloc(hex_len / 2U + 1U) : NULL;
    for (size_t i = 0U; bytes != NULL && i < hex_len / 2U; ++i) {
        int high = hex_value(hex[2U * i]);
        int low = hex_value(hex[2U * i + 1U]);
        if (high < 0 || low < 0) {
            free(bytes);
            return NULL;
        }
        bytes[i] = (uint8_t)((high << 4) | low);
    }
    *len = hex_len / 2U;
    return bytes;
}

/* Copies a vector member into an event field; an absent or oversized string is an error. */
static int copy_member(const char *object, const char *key, char *out, size_t out_len)
{
    char *value = st_json_get_top_level_string(object, key);
    int ok = value != NULL && strlen(value) < out_len;
    if (ok) memcpy(out, value, strlen(value) + 1U);
    free(value);
    return ok ? 0 : -1;
}

/* Builds the event a vector case describes; event->payload is malloc'ed. */
static int vector_event(const char *vector, st_public_cluster_event *event)
{
    memset(event, 0, sizeof(*event));
    long long kind = 0;
    long long revision = 0;
    char *exclude = st_json_get_top_level_raw(vector, "excludeSource");
    char *payload = st_json_get_top_level_string(vector, "payloadUtf8");
    int ok = st_json_get_i64(vector, "kind", &kind) == 0
        && st_json_get_i64(vector, "revision", &revision) == 0
        && exclude != NULL && payload != NULL
        && copy_member(vector, "groupId", event->group_id, sizeof(event->group_id)) == 0
        && copy_member(vector, "targetPeerId", event->target_peer_id, sizeof(event->target_peer_id)) == 0
        && copy_member(vector, "sourceLeaseId", event->source_lease_id, sizeof(event->source_lease_id)) == 0;
    if (ok) {
        event->kind = (uint8_t)kind;
        event->revision = (uint64_t)revision;
        event->exclude_source = strcmp(exclude, "true") == 0;
        event->payload = (uint8_t *)payload;
        event->payload_len = strlen(payload);
        payload = NULL;
    }
    free(exclude);
    free(payload);
    return ok ? 0 : -1;
}

/* Encodes the vector case, compares it with frameHex and decodes the bytes back. */
static int check_canonical(const char *root, const char *name, st_public_cluster_event *decoded)
{
    char *vector = st_json_get_top_level_raw(root, name);
    char *frame_hex = vector == NULL ? NULL : st_json_get_top_level_string(vector, "frameHex");
    st_public_cluster_event event;
    size_t expected_len = 0U;
    uint8_t *expected = frame_hex == NULL ? NULL : hex_bytes(frame_hex, &expected_len);
    uint8_t *encoded = NULL;
    size_t encoded_len = 0U;
    int ok = expected != NULL && vector_event(vector, &event) == 0;
    if (ok) {
        ok = st_public_cluster_event_encode(&event, &encoded, &encoded_len) == 0
            && encoded_len == expected_len && memcmp(encoded, expected, expected_len) == 0
            && st_public_cluster_event_decode(encoded, encoded_len, decoded) == 0
            && decoded->kind == event.kind && decoded->exclude_source == event.exclude_source
            && decoded->revision == event.revision
            && strcmp(decoded->group_id, event.group_id) == 0
            && strcmp(decoded->target_peer_id, event.target_peer_id) == 0
            && strcmp(decoded->source_lease_id, event.source_lease_id) == 0
            && decoded->payload_len == event.payload_len
            && memcmp(decoded->payload, event.payload, event.payload_len) == 0;
        free(event.payload);
    }
    if (!ok) fprintf(stderr, "%s does not match the STCE vector\n", name);
    free(encoded);
    free(expected);
    free(frame_hex);
    free(vector);
    return ok ? 0 : 1;
}

static int encode_event(uint8_t kind, int exclude, uint64_t revision, const char *group, const char *target,
                        const char *source, const char *payload, uint8_t **encoded, size_t *encoded_len)
{
    st_public_cluster_event event;
    memset(&event, 0, sizeof(event));
    event.kind = kind;
    event.exclude_source = exclude;
    event.revision = revision;
    snprintf(event.group_id, sizeof(event.group_id), "%s", group);
    snprintf(event.target_peer_id, sizeof(event.target_peer_id), "%s", target);
    snprintf(event.source_lease_id, sizeof(event.source_lease_id), "%s", source);
    event.payload = (uint8_t *)payload;
    event.payload_len = payload == NULL ? 0U : strlen(payload);
    return st_public_cluster_event_encode(&event, encoded, encoded_len);
}

static int decodes(const uint8_t *encoded, size_t encoded_len)
{
    st_public_cluster_event event;
    int rc = st_public_cluster_event_decode(encoded, encoded_len, &event);
    if (rc == 0) free(event.payload);
    return rc == 0;
}

/* textEventMatchesCanonicalVectorAndRoundTrips, managementEventMatchesCanonicalVectorAndTenantBinding. */
static int test_canonical_frames(const char *root)
{
    st_public_cluster_event decoded;
    CHECK(check_canonical(root, "canonicalText", &decoded) == 0, "canonical text frame");
    CHECK(decoded.kind == ST_PUBLIC_CLUSTER_EVENT_TEXT && decoded.exclude_source && decoded.revision == 17U
              && strcmp(decoded.group_id, "0123456789abcdef") == 0
              && strcmp(decoded.target_peer_id, "peer-b") == 0
              && strcmp(decoded.source_lease_id, "lease-a") == 0,
          "decoded text event fields");
    free(decoded.payload);
    CHECK(check_canonical(root, "canonicalManagement", &decoded) == 0, "canonical management frame");
    CHECK(decoded.kind == ST_PUBLIC_CLUSTER_EVENT_MANAGEMENT, "decoded management kind");
    free(decoded.payload);

    /* The management shape: group and payload only, on encode and on decode. */
    uint8_t *encoded = NULL;
    size_t encoded_len = 0U;
    CHECK(encode_event(4, 0, 0, "tenant-group", "unexpected-target", "", "{}", &encoded, &encoded_len) != 0,
          "a management event with a target was encoded");
    CHECK(encode_event(4, 0, 0, "tenant-group", "", "lease", "{}", &encoded, &encoded_len) != 0,
          "a management event with a source lease was encoded");
    CHECK(encode_event(4, 0, 3, "tenant-group", "", "", "{}", &encoded, &encoded_len) != 0,
          "a management event with a revision was encoded");
    CHECK(encode_event(4, 1, 0, "tenant-group", "", "", "{}", &encoded, &encoded_len) != 0,
          "a management event with excludeSource was encoded");
    CHECK(encode_event(4, 0, 0, "tenant-group", "", "", "", &encoded, &encoded_len) != 0,
          "a management event without payload was encoded");
    CHECK(encode_event(4, 0, 0, "tenant-group", "", "", "{}", &encoded, &encoded_len) == 0
              && decodes(encoded, encoded_len), "a valid management event did not round-trip");
    encoded[15] = 1U; /* revision 1 */
    CHECK(!decodes(encoded, encoded_len), "a management frame with a revision was decoded");
    encoded[15] = 0U;
    encoded[6] = 1U; /* excludeSource */
    CHECK(!decodes(encoded, encoded_len), "a management frame with excludeSource was decoded");
    free(encoded);
    return 0;
}

/* decoderRejectsTrailingBytesAndBinaryWithoutTarget, plus the vector's other malformed cases. */
static int test_malformed_frames(void)
{
    uint8_t *encoded = NULL;
    size_t encoded_len = 0U;
    CHECK(encode_event(1, 0, 1, "group", "", "", NULL, &encoded, &encoded_len) == 0
              && decodes(encoded, encoded_len), "roster event round trip");
    uint8_t *longer = (uint8_t *)calloc(encoded_len + 1U, 1U);
    CHECK(longer != NULL, "allocation");
    memcpy(longer, encoded, encoded_len);
    CHECK(!decodes(longer, encoded_len + 1U), "a frame with a trailing byte was decoded");
    CHECK(!decodes(encoded, encoded_len - 1U), "a truncated frame was decoded");
    free(longer);
    encoded[4] = 1U;
    CHECK(!decodes(encoded, encoded_len), "a version 1 frame was decoded");
    encoded[4] = 2U;
    encoded[7] = 1U;
    CHECK(!decodes(encoded, encoded_len), "a frame with a non-zero reserved byte was decoded");
    encoded[7] = 0U;
    encoded[6] = 2U;
    CHECK(!decodes(encoded, encoded_len), "a frame with an unknown flag bit was decoded");
    encoded[6] = 0U;
    encoded[5] = 5U;
    CHECK(!decodes(encoded, encoded_len), "a frame of an unknown kind was decoded");
    free(encoded);

    CHECK(encode_event(3, 0, 0, "group", "", "", "\x01", &encoded, &encoded_len) != 0,
          "a binary event without a target was encoded");
    CHECK(encode_event(1, 0, 0, "group", "", "", "x", &encoded, &encoded_len) != 0,
          "a roster event with a payload was encoded");
    CHECK(encode_event(1, 0, 0, "", "", "", NULL, &encoded, &encoded_len) != 0,
          "an event without a group was encoded");

    /* A binary frame whose target is blank, and a text frame whose group is blank (both U+0020). */
    CHECK(encode_event(2, 0, 0, "group", "   ", "", "{}", &encoded, &encoded_len) == 0, "text event");
    encoded[5] = 3U;
    CHECK(!decodes(encoded, encoded_len), "a binary frame with a blank target was decoded");
    free(encoded);
    CHECK(encode_event(2, 0, 0, "   ", "peer", "", "{}", &encoded, &encoded_len) == 0
              && !decodes(encoded, encoded_len), "a frame with a blank group was decoded");
    free(encoded);

    /* Identities must be strict UTF-8: an invalid byte, a surrogate and an overlong form. */
    static const uint8_t invalid[][3] = {{0xffU, 'b', 'c'}, {0xedU, 0xa0U, 0x80U}, {0xc0U, 0xafU, 'c'}};
    for (size_t i = 0U; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        CHECK(encode_event(2, 0, 0, "abc", "xyz", "lmn", "{}", &encoded, &encoded_len) == 0, "text event");
        uint8_t *field = encoded + 26U + (i % 3U) * 3U;
        memcpy(field, invalid[i], 3U);
        CHECK(!decodes(encoded, encoded_len), "an identity with invalid UTF-8 (case %zu) was decoded", i);
        free(encoded);
    }
    /* Identities up to the 512-byte STCE limit decode; the payload limit is 256 KiB. */
    char target[ST_PUBLIC_CLUSTER_EVENT_ID_BYTES + 1U];
    memset(target, 't', ST_PUBLIC_CLUSTER_EVENT_ID_BYTES);
    target[ST_PUBLIC_CLUSTER_EVENT_ID_BYTES] = '\0';
    CHECK(encode_event(3, 0, 0, "group", target, target, "x", &encoded, &encoded_len) == 0
              && decodes(encoded, encoded_len), "a frame with 512-byte identities was refused");
    free(encoded);
    char group[ST_PUBLIC_CLUSTER_EVENT_GROUP_BYTES + 1U];
    memset(group, 'g', ST_PUBLIC_CLUSTER_EVENT_GROUP_BYTES);
    group[ST_PUBLIC_CLUSTER_EVENT_GROUP_BYTES] = '\0';
    CHECK(encode_event(2, 0, 0, group, "", "", "{}", &encoded, &encoded_len) == 0
              && decodes(encoded, encoded_len), "a frame with a 128-byte group was refused");
    free(encoded);
    return 0;
}

static int participant_ids(const char *room_id, const char *room_key, const char *address,
                           st_public_cluster_participant *participant)
{
    memset(participant, 0, sizeof(*participant));
    snprintf(participant->peer_id, sizeof(participant->peer_id), "peer");
    snprintf(participant->room_id, sizeof(participant->room_id), "%s", room_id);
    snprintf(participant->room_key, sizeof(participant->room_key), "%s", room_key);
    snprintf(participant->public_address, sizeof(participant->public_address), "%s", address);
    return st_public_coordination_prepare_participant(participant);
}

/*
 * groupIdIsStableAndSeparatesRoomComponents (vector groupIdDerivation) and the
 * PublicTransferCoordinationServiceTests vectors: groupId = sha256(roomId NUL roomKey) and
 * netId = sha256(publicAddress) as lower-case hex.
 */
static int test_identifiers(const char *root)
{
    char *derivation = st_json_get_top_level_raw(root, "groupIdDerivation");
    char room_id[64], room_key[64], group_id[80];
    st_public_cluster_participant participant;
    CHECK(derivation != NULL && copy_member(derivation, "roomId", room_id, sizeof(room_id)) == 0
              && copy_member(derivation, "roomKey", room_key, sizeof(room_key)) == 0
              && copy_member(derivation, "groupId", group_id, sizeof(group_id)) == 0,
          "groupIdDerivation vector");
    free(derivation);
    CHECK(participant_ids(room_id, room_key, "203.0.113.8", &participant) == 0
              && strcmp(participant.group_id, group_id) == 0,
          "groupId of the vector derivation: %s", participant.group_id);

    st_public_cluster_participant first, second;
    CHECK(participant_ids("a\nb", "c", "", &first) == 0 && participant_ids("a", "b\nc", "", &second) == 0
              && strcmp(first.group_id, second.group_id) != 0,
          "groupId does not separate the room components");

    CHECK(participant_ids("room", "key", "203.0.113.10", &participant) == 0
              && strcmp(participant.group_id,
                        "3a18ade7ffb1a1940f2cf4b2891ad8d0fa575625c8da9706202dc2bd52f5d3c8") == 0
              && strcmp(participant.net_id,
                        "631f08140b24b7274d12df3c37a1a80ce5876dafd7007d772e0114fddf88b682") == 0,
          "groupId/netId vectors: %s %s", participant.group_id, participant.net_id);
    CHECK(participant_ids("room", "key", "198.51.100.7", &second) == 0
              && strcmp(second.net_id, participant.net_id) != 0
              && strcmp(second.group_id, participant.group_id) == 0,
          "netId does not vary by public address only");
    /* Java netId(null) == netId(""): sha256 of the empty string. */
    CHECK(participant_ids("room", "key", "", &second) == 0
              && strcmp(second.net_id,
                        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0,
          "netId of an empty address: %s", second.net_id);
    return 0;
}

int main(void)
{
    char *root = read_text(ST_CLUSTER_VECTOR_FILE);
    if (root == NULL || !st_json_is_valid_object(root)) {
        fprintf(stderr, "cannot read %s\n", ST_CLUSTER_VECTOR_FILE);
        free(root);
        return 1;
    }
    int failed = test_canonical_frames(root) || test_malformed_frames() || test_identifiers(root);
    free(root);
    if (failed) return 1;
    puts("public cluster codec tests passed");
    return 0;
}
