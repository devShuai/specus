#define _POSIX_C_SOURCE 200809L

#include "public_coordination.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int received;
    uint8_t kind;
    char target[ST_PUBLIC_CLUSTER_EVENT_ID_BYTES + 1U];
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

/* The roster's peer IDs in order, e.g. "peer-a,peer-b". */
static int roster_order_is(const st_public_cluster_roster *roster, const char *expected)
{
    char actual[1024] = "";
    size_t used = 0U;
    for (size_t i = 0U; i < roster->count; ++i) {
        int written = snprintf(actual + used, sizeof(actual) - used, "%s%s", i == 0U ? "" : ",",
                               roster->participants[i].peer_id);
        if (written < 0 || (size_t)written >= sizeof(actual) - used) return 0;
        used += (size_t)written;
    }
    if (strcmp(actual, expected) != 0) fprintf(stderr, "roster %s, expected %s\n", actual, expected);
    return strcmp(actual, expected) == 0;
}

/*
 * PublicTransferCoordinationRedisIT.rosterMergesSameNetAcrossGroupsAndKeepsRevisionMonotonic: the
 * merged roster spans the group and the net, a peer ID is unique across the net, a directed lookup
 * resolves same-net targets in other groups but not the other net, and an unregistration makes the
 * roster revision strictly larger.
 */
static int test_merged_roster_and_revision(void)
{
    st_public_cluster_participant alpha, beta, gamma, delta, zeta, echo;
    if (participant(&alpha, "merge-a", "Merge Alpha", "merge-room", "room:m1", "203.0.113.61") != 0
        || participant(&beta, "merge-b", "Merge Beta", "merge-room", "room:m2", "203.0.113.61") != 0
        || participant(&gamma, "merge-c", "Merge Gamma", "merge-room", "room:m1", "198.51.100.62") != 0
        || participant(&delta, "merge-d", "Merge Delta", "merge-other", "room:m1", "203.0.113.61") != 0
        || participant(&zeta, "merge-z", "Merge Zeta", "merge-other", "room:m1", "192.0.2.63") != 0
        || participant(&echo, "merge-b", "Merge Echo", "merge-room", "room:m9", "203.0.113.61") != 0) {
        fprintf(stderr, "merged roster participants\n");
        return 1;
    }
    st_public_cluster_participant *const all[] = {&alpha, &beta, &gamma, &delta, &zeta};
    uint64_t revision = 0U;
    for (size_t i = 0U; i < sizeof(all) / sizeof(all[0]); ++i) {
        snprintf(all[i]->connected_at, sizeof(all[i]->connected_at), "2026-07-22T00:00:0%zuZ", i);
        if (st_public_coordination_register(all[i], 10, &revision) != 0) {
            fprintf(stderr, "merged roster registration %s failed\n", all[i]->peer_id);
            return 1;
        }
    }
    st_public_cluster_roster roster = {0};
    if (st_public_coordination_roster(&alpha, &roster) != 0
        || !roster_order_is(&roster, "merge-a,merge-b,merge-c,merge-d")) {
        fprintf(stderr, "merged same-net/same-group roster mismatch\n");
        return 1;
    }
    uint64_t before = roster.revision;
    st_public_coordination_roster_free(&roster);
    if (st_public_coordination_register(&echo, 10, &revision) != 1) {
        fprintf(stderr, "a peer ID taken on the net was registered in another group\n");
        return 1;
    }
    st_public_cluster_participant found_peer;
    int found = 0;
    if (st_public_coordination_find_peer(&alpha, "merge-b", &found_peer, &found) != 0 || !found
        || strcmp(found_peer.group_id, beta.group_id) != 0
        || st_public_coordination_find_peer(&alpha, "merge-d", &found_peer, &found) != 0 || !found
        || strcmp(found_peer.group_id, delta.group_id) != 0
        || st_public_coordination_find_peer(&alpha, "merge-z", &found_peer, &found) != 0 || found) {
        fprintf(stderr, "directed lookup across groups and nets mismatch\n");
        return 1;
    }
    if (st_public_coordination_unregister(&beta, &revision) != 0 || revision == 0U
        || st_public_coordination_roster(&alpha, &roster) != 0
        || roster.revision <= before
        || !roster_order_is(&roster, "merge-a,merge-c,merge-d")) {
        fprintf(stderr, "revision after unregister was not strictly larger (%llu -> %llu)\n",
                (unsigned long long)before, (unsigned long long)roster.revision);
        return 1;
    }
    st_public_coordination_roster_free(&roster);
    for (size_t i = 0U; i < sizeof(all) / sizeof(all[0]); ++i) {
        if (all[i] != &beta) (void)st_public_coordination_unregister(all[i], &revision);
    }
    return 0;
}

/*
 * PublicTransferCoordinationServiceTests.unknownOrBlankAddressIsNeverSameNet through the shared
 * roster: participants whose equal address is "unknown", blank or empty share no net, while a
 * shared group still makes them visible.
 */
static int test_unidentifiable_addresses(void)
{
    static const char *const addresses[] = {"unknown", "   ", ""};
    for (size_t i = 0U; i < sizeof(addresses) / sizeof(addresses[0]); ++i) {
        char peer[3][32], name[3][32], room[2][32];
        for (size_t p = 0U; p < 3U; ++p) {
            snprintf(peer[p], sizeof(peer[p]), "unk-%zu-%zu", i, p);
            snprintf(name[p], sizeof(name[p]), "Unknown %zu %zu", i, p);
        }
        snprintf(room[0], sizeof(room[0]), "unk-room-a-%zu", i);
        snprintf(room[1], sizeof(room[1]), "unk-room-b-%zu", i);
        st_public_cluster_participant first, second, mate;
        uint64_t revision = 0U;
        if (participant(&first, peer[0], name[0], room[0], "room:u1", addresses[i]) != 0
            || participant(&second, peer[1], name[1], room[1], "room:u2", addresses[i]) != 0
            || participant(&mate, peer[2], name[2], room[0], "room:u1", addresses[i]) != 0
            || st_public_coordination_register(&first, 10, &revision) != 0
            || st_public_coordination_register(&second, 10, &revision) != 0
            || st_public_coordination_register(&mate, 10, &revision) != 0) {
            fprintf(stderr, "participants at address '%s'\n", addresses[i]);
            return 1;
        }
        st_public_cluster_roster roster = {0};
        st_public_cluster_participant found_peer;
        int found = 0;
        if (st_public_coordination_roster(&first, &roster) != 0 || roster.count != 2U
            || !roster_has(&roster, peer[0]) || !roster_has(&roster, peer[2])) {
            fprintf(stderr, "address '%s' made a net: %zu peers\n", addresses[i], roster.count);
            return 1;
        }
        st_public_coordination_roster_free(&roster);
        if (st_public_coordination_roster(&second, &roster) != 0 || roster.count != 1U
            || st_public_coordination_find_peer(&first, peer[1], &found_peer, &found) != 0 || found) {
            fprintf(stderr, "address '%s' reached another group\n", addresses[i]);
            return 1;
        }
        st_public_coordination_roster_free(&roster);
        (void)st_public_coordination_unregister(&first, &revision);
        (void)st_public_coordination_unregister(&second, &revision);
        (void)st_public_coordination_unregister(&mate, &revision);
    }
    return 0;
}

/*
 * The second instance of PublicTransferCoordinationRedisIT.twoInstancesSharePresenceEventsNamesAndRateLimits,
 * run as a separate process over the same Redis while the first still holds Alice and Bob in
 * room-a (limit 2) and one call of the integration window.
 */
static int second_instance(void)
{
    if (!st_public_coordination_enabled() || st_public_coordination_initialize(NULL, NULL) != 0) return 10;
    st_public_cluster_participant full, name;
    uint64_t revision = 0U;
    int allowed = 1;
    int result = 0;
    if (participant(&full, "peer-second-full", "Second Full", "room-a", "room:1", "198.51.100.40") != 0
        || participant(&name, "peer-second-name", "alice", "room-z", "room:z", "198.51.100.41") != 0) {
        result = 11;
    } else if (st_public_coordination_register(&full, 2, &revision) != 3) {
        result = 12;
    } else if (st_public_coordination_register(&name, 2, &revision) != 2) {
        result = 13;
    } else if (st_public_coordination_allow_rate("integration", "same-source", 1, 60, &allowed) != 0 || allowed) {
        result = 14;
    } else {
        static const char text[] = "cross-instance";
        st_public_cluster_participant bob;
        if (participant(&bob, "peer-b", "Bob", "room-a", "room:1", "198.51.100.2") != 0
            || st_public_coordination_publish_text(bob.group_id, "peer-b", full.lease_id, 0,
                                                   (const uint8_t *)text, strlen(text)) != 0) {
            result = 15;
        }
    }
    st_public_coordination_shutdown();
    return result;
}

static int run_second_instance(void)
{
    pid_t child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        char *const argv[] = {"public_coordination_tests", "--second-instance", NULL};
        execv("/proc/self/exe", argv);
        _exit(127);
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "--second-instance") == 0) return second_instance();
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
    /*
     * A second instance (another process on the same Redis) shares the room capacity, the global
     * names and the rate windows, and its events reach this one.
     */
    pthread_mutex_lock(&capture.lock);
    capture.received = 0;
    pthread_mutex_unlock(&capture.lock);
    if (st_public_coordination_allow_rate("integration", "same-source", 1, 60, &allowed) != 0 || !allowed) {
        fprintf(stderr, "first instance rate window mismatch\n");
        return 1;
    }
    int second = run_second_instance();
    if (second != 0 || wait_for_event() != 0
        || capture.kind != ST_PUBLIC_CLUSTER_EVENT_TEXT
        || strcmp(capture.target, "peer-b") != 0
        || strcmp(capture.payload, "cross-instance") != 0) {
        fprintf(stderr, "second instance mismatch (exit %d)\n", second);
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
    if (test_merged_roster_and_revision() != 0 || test_unidentifiable_addresses() != 0) return 1;
    st_public_coordination_shutdown();
    puts("public coordination tests passed");
    return 0;
}
