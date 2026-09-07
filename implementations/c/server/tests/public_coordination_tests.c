#define _POSIX_C_SOURCE 200809L

#include "public_coordination.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int received;
    uint8_t kind;
    char target[ST_PUBLIC_CLUSTER_PEER_BYTES + 1U];
    char payload[256];
} event_capture;

static event_capture capture = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .cond = PTHREAD_COND_INITIALIZER
};

static void capture_event(const st_public_cluster_event *event, void *context)
{
    (void)context;
    if (event == NULL || event->kind == ST_PUBLIC_CLUSTER_EVENT_UNAVAILABLE) return;
    pthread_mutex_lock(&capture.lock);
    capture.kind = event->kind;
    snprintf(capture.target, sizeof(capture.target), "%s", event->target_peer_id);
    size_t length = event->payload_len < sizeof(capture.payload) - 1U
        ? event->payload_len : sizeof(capture.payload) - 1U;
    if (length > 0U) memcpy(capture.payload, event->payload, length);
    capture.payload[length] = '\0';
    capture.received = 1;
    pthread_cond_broadcast(&capture.cond);
    pthread_mutex_unlock(&capture.lock);
}

static int wait_for_event(void)
{
    struct timespec deadline;
    (void)clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 3;
    pthread_mutex_lock(&capture.lock);
    while (!capture.received) {
        if (pthread_cond_timedwait(&capture.cond, &capture.lock, &deadline) != 0) break;
    }
    int received = capture.received;
    pthread_mutex_unlock(&capture.lock);
    return received ? 0 : -1;
}

static int participant(st_public_cluster_participant *value,
                       const char *peer_id,
                       const char *display_name,
                       const char *room_id,
                       const char *room_key,
                       const char *address)
{
    memset(value, 0, sizeof(*value));
    snprintf(value->peer_id, sizeof(value->peer_id), "%s", peer_id);
    snprintf(value->display_name, sizeof(value->display_name), "%s", display_name);
    snprintf(value->room_id, sizeof(value->room_id), "%s", room_id);
    snprintf(value->room_key, sizeof(value->room_key), "%s", room_key);
    snprintf(value->public_address, sizeof(value->public_address), "%s", address);
    snprintf(value->room_role, sizeof(value->room_role), "EDITOR");
    snprintf(value->connected_at, sizeof(value->connected_at), "2026-08-28T00:00:00Z");
    value->shared_room = 1;
    return st_public_coordination_prepare_participant(value);
}

static int roster_has(const st_public_cluster_roster *roster, const char *peer_id)
{
    for (size_t i = 0U; i < roster->count; ++i)
        if (strcmp(roster->participants[i].peer_id, peer_id) == 0) return 1;
    return 0;
}

int main(void)
{
    if (!st_public_coordination_enabled()
        || st_public_coordination_initialize(capture_event, NULL) != 0) {
        fprintf(stderr, "Redis coordination did not initialize\n");
        return 1;
    }
    struct timespec idle = {.tv_sec = 0, .tv_nsec = 250000000L};
    (void)nanosleep(&idle, NULL);
    if (!st_public_coordination_available()) {
        fprintf(stderr, "idle Pub/Sub connection incorrectly used the command timeout\n");
        return 1;
    }
    st_public_cluster_participant p1, p2, p3, duplicate, duplicate_name, full, unicode_name;
    if (participant(&p1, "peer-a", "Alice", "room-a", "room:1", "198.51.100.1") != 0
        || participant(&p2, "peer-b", "Bob", "room-a", "room:1", "198.51.100.2") != 0
        || participant(&p3, "peer-c", "Carol", "room-b", "room:2", "198.51.100.1") != 0
        || participant(&duplicate, "peer-a", "Other", "room-a", "room:1", "198.51.100.9") != 0
        || participant(&duplicate_name, "peer-name", "Alice", "room-c", "room:3", "198.51.100.3") != 0
        || participant(&full, "peer-full", "Full", "room-a", "room:1", "198.51.100.4") != 0
        || participant(&unicode_name,
                       "peer-unicode",
                       "\xC3\x89lodie",
                       "room-unicode",
                       "room:unicode",
                       "203.0.113.8") != 0) {
        fprintf(stderr, "participant preparation failed\n");
        return 1;
    }
    uint64_t revision = 0U;
    if (st_public_coordination_register(&p1, 2, &revision) != 0 || revision == 0U
        || st_public_coordination_register(&duplicate, 2, &revision) != 1
        || st_public_coordination_register(&duplicate_name, 2, &revision) != 2
        || st_public_coordination_register(&p2, 2, &revision) != 0
        || st_public_coordination_register(&full, 2, &revision) != 3
        || st_public_coordination_register(&p3, 2, &revision) != 0
        || st_public_coordination_register(&unicode_name, 2, &revision) != 0) {
        fprintf(stderr, "registration policy mismatch\n");
        return 1;
    }
    st_public_cluster_roster roster = {0};
    if (st_public_coordination_roster(&p1, &roster) != 0
        || roster.count != 3U
        || !roster_has(&roster, "peer-a")
        || !roster_has(&roster, "peer-b")
        || !roster_has(&roster, "peer-c")) {
        fprintf(stderr, "merged same-room/same-net roster mismatch count=%zu\n", roster.count);
        return 1;
    }
    st_public_coordination_roster_free(&roster);
    st_public_cluster_participant found_peer;
    int found = 0;
    if (st_public_coordination_find_peer(&p1, "peer-b", &found_peer, &found) != 0
        || !found || strcmp(found_peer.group_id, p2.group_id) != 0
        || st_public_coordination_find_peer(&p1, "peer-c", &found_peer, &found) != 0
        || !found || strcmp(found_peer.group_id, p3.group_id) != 0) {
        fprintf(stderr, "merged-scope peer lookup mismatch\n");
        return 1;
    }
    int available = 0;
    if (st_public_coordination_name_available("Alice", "", &available) != 0 || available
        || st_public_coordination_name_available("Alice", "peer-a", &available) != 0 || !available
        || st_public_coordination_name_available("E\xCC\x81LODIE", "", &available) != 0
        || available) {
        fprintf(stderr, "global name availability mismatch\n");
        return 1;
    }
    int allowed = 0;
    if (st_public_coordination_allow_rate("test", "identity", 2, 30, &allowed) != 0 || !allowed
        || st_public_coordination_allow_rate("test", "identity", 2, 30, &allowed) != 0 || !allowed
        || st_public_coordination_allow_rate("test", "identity", 2, 30, &allowed) != 0 || allowed) {
        fprintf(stderr, "distributed rate limit mismatch\n");
        return 1;
    }
    static const char text_payload[] = "{\"type\":\"signal\",\"payload\":{\"ok\":true}}";
    if (st_public_coordination_publish_text(p1.group_id,
                                           p2.peer_id,
                                           p1.lease_id,
                                           0,
                                           (const uint8_t *)text_payload,
                                           strlen(text_payload)) != 0
        || wait_for_event() != 0
        || capture.kind != ST_PUBLIC_CLUSTER_EVENT_TEXT
        || strcmp(capture.target, p2.peer_id) != 0
        || strcmp(capture.payload, text_payload) != 0) {
        fprintf(stderr, "STCE Pub/Sub event mismatch\n");
        return 1;
    }
    if (st_public_coordination_refresh(&p1) != 0
        || st_public_coordination_unregister(&p2, &revision) != 0
        || revision == 0U
        || st_public_coordination_roster(&p1, &roster) != 0
        || roster.count != 2U
        || roster_has(&roster, "peer-b")) {
        fprintf(stderr, "refresh/unregister mismatch\n");
        return 1;
    }
    st_public_coordination_roster_free(&roster);
    (void)st_public_coordination_unregister(&p1, &revision);
    (void)st_public_coordination_unregister(&p3, &revision);
    (void)st_public_coordination_unregister(&unicode_name, &revision);
    st_public_coordination_shutdown();
    puts("public coordination tests passed");
    return 0;
}
