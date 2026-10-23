#define _POSIX_C_SOURCE 200809L

#include "public_coordination.h"

#include "crypto.h"

#include <errno.h>
#include <fcntl.h>
#include <hiredis/hiredis.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
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
    unsigned long handled;
    int block;
    uint8_t kind;
    char target[ST_PUBLIC_CLUSTER_EVENT_ID_BYTES + 1U];
    char payload[256];
} event_capture;

extern char **environ;

static event_capture capture = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .cond = PTHREAD_COND_INITIALIZER
};

/* Records the event; while capture.block is set the handler stays inside, as a slow consumer. */
static void capture_event(const st_public_cluster_event *event, void *context)
{
    (void)context;
    if (event == NULL) return;
    pthread_mutex_lock(&capture.lock);
    capture.kind = event->kind;
    snprintf(capture.target, sizeof(capture.target), "%s", event->target_peer_id);
    size_t length = event->payload_len < sizeof(capture.payload) - 1U
        ? event->payload_len : sizeof(capture.payload) - 1U;
    if (length > 0U) memcpy(capture.payload, event->payload, length);
    capture.payload[length] = '\0';
    capture.received = 1;
    ++capture.handled;
    pthread_cond_broadcast(&capture.cond);
    while (capture.block) pthread_cond_wait(&capture.cond, &capture.lock);
    pthread_mutex_unlock(&capture.lock);
}

static long long now_ms(void)
{
    struct timespec now;
    (void)clock_gettime(CLOCK_MONOTONIC, &now);
    return (long long)now.tv_sec * 1000LL + now.tv_nsec / 1000000L;
}

static void sleep_ms(long milliseconds)
{
    struct timespec pause = {.tv_sec = milliseconds / 1000L, .tv_nsec = (milliseconds % 1000L) * 1000000L};
    while (nanosleep(&pause, &pause) != 0 && errno == EINTR) {
    }
}

static int fixture_port(void)
{
    const char *port = getenv("SPECUS_TEST_REDIS_PORT");
    return port == NULL ? 16389 : atoi(port);
}

/* One command of the fixture itself, on its own short-lived connection. */
static redisReply *fixture_command(const char *format, ...)
{
    struct timeval timeout = {.tv_sec = 2, .tv_usec = 0};
    redisContext *redis = redisConnectWithTimeout("127.0.0.1", fixture_port(), timeout);
    if (redis == NULL || redis->err) {
        if (redis != NULL) redisFree(redis);
        return NULL;
    }
    (void)redisSetTimeout(redis, timeout);
    va_list arguments;
    va_start(arguments, format);
    redisReply *reply = (redisReply *)redisvCommand(redis, format, arguments);
    va_end(arguments);
    redisFree(redis);
    return reply;
}

/* How often Redis has run one command so far (INFO commandstats). */
static long long command_calls(const char *command)
{
    redisReply *reply = fixture_command("INFO commandstats");
    if (reply == NULL || (reply->type != REDIS_REPLY_STRING && reply->type != REDIS_REPLY_VERB)) {
        freeReplyObject(reply);
        return -1;
    }
    char needle[64];
    snprintf(needle, sizeof(needle), "cmdstat_%s:calls=", command);
    const char *found = strstr(reply->str, needle);
    long long calls = found == NULL ? 0 : strtoll(found + strlen(needle), NULL, 10);
    freeReplyObject(reply);
    return calls;
}

static st_public_coordination_status status_now(void)
{
    st_public_coordination_status status;
    st_public_coordination_status_get(&status);
    return status;
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
 * Java findPeer walks the merged scope with one SMEMBERS and one MGET per group, without cleanup or
 * revision reads; roster() reads the presences with one MGET per group instead of a GET per member.
 */
static int test_lookup_costs(void)
{
    static const char *const ids[] = {"cost-a", "cost-b", "cost-c", "cost-d"};
    static const char *const names[] = {"Cost A", "Cost B", "Cost C", "Cost D"};
    st_public_cluster_participant peers[4];
    uint64_t revision = 0U;
    for (size_t i = 0U; i < 4U; ++i) {
        if (participant(&peers[i], ids[i], names[i], "cost-room", "room:cost", "203.0.113.90") != 0
            || st_public_coordination_register(&peers[i], 10, &revision) != 0) {
            fprintf(stderr, "lookup cost participant %s\n", ids[i]);
            return 1;
        }
    }
    long long get_before = command_calls("get");
    long long eval_before = command_calls("eval");
    long long mget_before = command_calls("mget");
    st_public_cluster_participant found_peer;
    int found = 0;
    if (st_public_coordination_find_peer(&peers[0], "cost-d", &found_peer, &found) != 0 || !found) {
        fprintf(stderr, "lookup cost target not found\n");
        return 1;
    }
    long long get_lookup = command_calls("get");
    long long eval_lookup = command_calls("eval");
    long long mget_lookup = command_calls("mget");
    if (get_lookup != get_before || eval_lookup != eval_before || mget_lookup != mget_before + 1) {
        fprintf(stderr, "findPeer cost: %lld GET, %lld EVAL, %lld MGET (expected 0, 0, 1)\n",
                get_lookup - get_before, eval_lookup - eval_before, mget_lookup - mget_before);
        return 1;
    }
    st_public_cluster_roster roster = {0};
    if (st_public_coordination_roster(&peers[0], &roster) != 0 || roster.count != 4U) {
        fprintf(stderr, "lookup cost roster\n");
        return 1;
    }
    st_public_coordination_roster_free(&roster);
    long long get_roster = command_calls("get") - get_lookup;
    long long eval_roster = command_calls("eval") - eval_lookup;
    long long mget_roster = command_calls("mget") - mget_lookup;
    /*
     * One cleanup script (its two revision GETs count too), four revision reads around one stable
     * pass and one MGET for the one group; no GET per member.
     */
    if (get_roster != 6 || eval_roster != 1 || mget_roster != 1) {
        fprintf(stderr, "roster cost: %lld GET, %lld EVAL, %lld MGET (expected 6, 1, 1)\n",
                get_roster, eval_roster, mget_roster);
        return 1;
    }
    for (size_t i = 0U; i < 4U; ++i) (void)st_public_coordination_unregister(&peers[i], &revision);
    return 0;
}

/* Java command(): an error reply fails that call only; the connection stays and the next call works. */
static int test_error_reply_fails_only_the_call(void)
{
    static const char bucket_and_identity[] = "wrongtype\0probe";
    uint8_t digest[ST_SHA256_LEN];
    char hex[ST_SHA256_LEN * 2U + 1U];
    st_sha256((const uint8_t *)bucket_and_identity, sizeof(bucket_and_identity) - 1U, digest);
    st_hex_encode(digest, sizeof(digest), hex);
    char key[256];
    snprintf(key, sizeof(key), "%s:rate:%s", getenv("SPECUS_PUBLIC_TRANSFER_REDIS_KEY_PREFIX"), hex);
    /* A set where the rate script expects a counter: INCR answers WRONGTYPE. */
    redisReply *seeded = fixture_command("SADD %s member", key);
    int seeded_ok = seeded != NULL && seeded->type == REDIS_REPLY_INTEGER;
    freeReplyObject(seeded);
    st_public_coordination_status before = status_now();
    int allowed = 1;
    if (!seeded_ok || st_public_coordination_allow_rate("wrongtype", "probe", 5, 30, &allowed) != -1) {
        fprintf(stderr, "a WRONGTYPE reply did not fail the rate call\n");
        return 1;
    }
    st_public_coordination_status after = status_now();
    if (!after.command_connected || after.command_reconnects != before.command_reconnects
        || !st_public_coordination_available()
        || st_public_coordination_allow_rate("after-error", "probe", 5, 30, &allowed) != 0 || !allowed) {
        fprintf(stderr, "an error reply affected more than its own call\n");
        return 1;
    }
    freeReplyObject(fixture_command("DEL %s", key));
    return 0;
}

/* A timed-out command fails alone; the next command reconnects instead of the instance giving up. */
static int test_timeout_fails_only_the_call(void)
{
    st_public_coordination_status before = status_now();
    redisReply *paused = fixture_command("CLIENT PAUSE %d", 700);
    int paused_ok = paused != NULL && paused->type == REDIS_REPLY_STATUS;
    freeReplyObject(paused);
    long long started = now_ms();
    int available = 0;
    int timed_out = st_public_coordination_name_available("Pause Probe", "", &available) == -1;
    long long elapsed = now_ms() - started;
    if (!paused_ok || !timed_out || elapsed > 600) {
        fprintf(stderr, "a paused Redis did not time the command out (%lld ms)\n", elapsed);
        return 1;
    }
    sleep_ms(900 - (long)elapsed);
    st_public_coordination_status after = status_now();
    if (st_public_coordination_name_available("Pause Probe", "", &available) != 0 || !available
        || status_now().command_reconnects <= before.command_reconnects
        || !after.subscriber_connected || after.subscriber_reconnects != before.subscriber_reconnects) {
        fprintf(stderr, "the command after a timeout did not reconnect, or the timeout reached Pub/Sub\n");
        return 1;
    }
    return 0;
}

/*
 * Java's event executor: a blocked handler leaves at most 4096 events queued and drops the rest,
 * while the subscription keeps reading.
 */
static int test_event_queue_is_bounded(void)
{
    static const char text[] = "{\"type\":\"queue\"}";
    st_public_cluster_participant source;
    if (participant(&source, "queue-source", "Queue Source", "queue-room", "room:queue", "203.0.113.91") != 0) {
        return 1;
    }
    st_public_coordination_status before = status_now();
    pthread_mutex_lock(&capture.lock);
    capture.handled = 0U;
    capture.block = 1;
    pthread_mutex_unlock(&capture.lock);
    if (st_public_coordination_publish_text(source.group_id, "", source.lease_id, 0,
                                            (const uint8_t *)text, strlen(text)) != 0) return 1;
    long long deadline = now_ms() + 3000;
    for (;;) {
        pthread_mutex_lock(&capture.lock);
        unsigned long handled = capture.handled;
        pthread_mutex_unlock(&capture.lock);
        if (handled == 1U) break;
        if (now_ms() > deadline) {
            fprintf(stderr, "the first queued event never reached the handler\n");
            return 1;
        }
        sleep_ms(5);
    }
    const unsigned long extra = 64U;
    for (unsigned long i = 0U; i < ST_PUBLIC_CLUSTER_EVENT_QUEUE_LIMIT + extra; ++i) {
        if (st_public_coordination_publish_text(source.group_id, "", source.lease_id, 0,
                                                (const uint8_t *)text, strlen(text)) != 0) {
            fprintf(stderr, "publish %lu failed\n", i);
            return 1;
        }
    }
    st_public_coordination_status full;
    deadline = now_ms() + 5000;
    do {
        full = status_now();
        if (full.events_dropped - before.events_dropped >= extra) break;
        sleep_ms(10);
    } while (now_ms() < deadline);
    if (full.events_queued != ST_PUBLIC_CLUSTER_EVENT_QUEUE_LIMIT
        || full.events_dropped - before.events_dropped != extra || !full.subscriber_connected) {
        fprintf(stderr, "queue: %zu queued, %lu dropped, subscriber %d\n", full.events_queued,
                full.events_dropped - before.events_dropped, full.subscriber_connected);
        return 1;
    }
    pthread_mutex_lock(&capture.lock);
    capture.block = 0;
    pthread_cond_broadcast(&capture.cond);
    pthread_mutex_unlock(&capture.lock);
    deadline = now_ms() + 5000;
    unsigned long handled = 0U;
    while (now_ms() < deadline) {
        pthread_mutex_lock(&capture.lock);
        handled = capture.handled;
        pthread_mutex_unlock(&capture.lock);
        if (handled >= 1U + ST_PUBLIC_CLUSTER_EVENT_QUEUE_LIMIT) break;
        sleep_ms(10);
    }
    sleep_ms(200);
    pthread_mutex_lock(&capture.lock);
    handled = capture.handled;
    pthread_mutex_unlock(&capture.lock);
    if (handled != 1U + ST_PUBLIC_CLUSTER_EVENT_QUEUE_LIMIT) {
        fprintf(stderr, "handled %lu events, expected %u\n", handled, 1U + ST_PUBLIC_CLUSTER_EVENT_QUEUE_LIMIT);
        return 1;
    }
    return 0;
}

/* The fixture's own redis-server, started again on the same port after SHUTDOWN. */
static pid_t restarted_redis = -1;

/*
 * posix_spawn rather than fork: this process already runs the coordination threads. In the
 * rediss:// run (public_coordination_tls_test.sh) the TLS port comes back with the plain one.
 */
static pid_t start_redis(void)
{
    char port[16];
    snprintf(port, sizeof(port), "%d", fixture_port());
    const char *dir = getenv("SPECUS_TEST_REDIS_DIR");
    const char *tls_port = getenv("SPECUS_TEST_REDIS_TLS_PORT");
    char *argv[32] = {"redis-server", "--bind", "127.0.0.1", "--port", port,
                      "--protected-mode", "yes", "--save", "", "--appendonly", "no",
                      "--dir", (char *)(dir == NULL ? "/tmp" : dir)};
    size_t argc = 13U;
    if (tls_port != NULL) {
        const char *const tls[] = {"--tls-port", tls_port,
                                   "--tls-cert-file", getenv("SPECUS_TEST_REDIS_TLS_CERT"),
                                   "--tls-key-file", getenv("SPECUS_TEST_REDIS_TLS_KEY"),
                                   "--tls-ca-cert-file", getenv("SPECUS_TEST_REDIS_TLS_CA"),
                                   "--tls-auth-clients", "no"};
        for (size_t i = 0U; i < sizeof(tls) / sizeof(tls[0]); ++i) {
            if (tls[i] == NULL) return -1;
            argv[argc++] = (char *)tls[i];
        }
    }
    argv[argc] = NULL;
    posix_spawn_file_actions_t actions;
    if (posix_spawn_file_actions_init(&actions) != 0) return -1;
    (void)posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
    (void)posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
    pid_t child = -1;
    int rc = posix_spawnp(&child, "redis-server", &actions, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&actions);
    return rc == 0 ? child : -1;
}

/*
 * Lettuce reconnects on its own: while Redis is down the operations fail, and once it is back the
 * commands work again and the Pub/Sub subscription is re-established, without a process restart.
 */
static int test_reconnect_after_restart(void)
{
    st_public_coordination_status before = status_now();
    freeReplyObject(fixture_command("SHUTDOWN NOSAVE"));
    long long deadline = now_ms() + 3000;
    while (status_now().subscriber_connected && now_ms() < deadline) sleep_ms(10);
    int allowed = 0;
    static const char text[] = "{\"type\":\"restart\"}";
    st_public_cluster_participant source;
    if (participant(&source, "restart-source", "Restart Source", "restart-room", "room:restart", "203.0.113.92") != 0
        || status_now().subscriber_connected
        || st_public_coordination_allow_rate("restart", "probe", 5, 30, &allowed) != -1
        || st_public_coordination_publish_text(source.group_id, "", source.lease_id, 0,
                                               (const uint8_t *)text, strlen(text)) != -1) {
        fprintf(stderr, "operations did not fail while Redis was down\n");
        return 1;
    }
    restarted_redis = start_redis();
    deadline = now_ms() + 5000;
    int up = 0;
    while (!up && now_ms() < deadline) {
        redisReply *pong = fixture_command("PING");
        up = pong != NULL && pong->type == REDIS_REPLY_STATUS;
        freeReplyObject(pong);
        if (!up) sleep_ms(20);
    }
    if (restarted_redis < 0 || !up) {
        fprintf(stderr, "the fixture could not restart redis-server\n");
        return 1;
    }
    deadline = now_ms() + 10000;
    int recovered = 0;
    while (!recovered && now_ms() < deadline) {
        recovered = st_public_coordination_allow_rate("restart", "probe", 5, 30, &allowed) == 0 && allowed;
        if (!recovered) sleep_ms(50);
    }
    while (recovered && !status_now().subscriber_connected && now_ms() < deadline) sleep_ms(20);
    if (!recovered || !status_now().subscriber_connected) {
        fprintf(stderr, "coordination did not recover after Redis came back\n");
        return 1;
    }
    pthread_mutex_lock(&capture.lock);
    capture.received = 0;
    pthread_mutex_unlock(&capture.lock);
    if (st_public_coordination_publish_text(source.group_id, "restart-target", source.lease_id, 0,
                                            (const uint8_t *)text, strlen(text)) != 0
        || wait_for_event() != 0 || strcmp(capture.target, "restart-target") != 0
        || strcmp(capture.payload, text) != 0) {
        fprintf(stderr, "the Pub/Sub subscription was not re-established\n");
        return 1;
    }
    st_public_coordination_status after = status_now();
    if (after.subscriber_reconnects <= before.subscriber_reconnects
        || after.command_reconnects <= before.command_reconnects
        || after.publisher_reconnects <= before.publisher_reconnects || !st_public_coordination_available()) {
        fprintf(stderr, "reconnect counters did not move\n");
        return 1;
    }
    return 0;
}

/* ---- Spring binding of the cluster settings, each in a fresh process ------------------------- */

static int probe_presence(void)
{
    if (st_public_coordination_initialize(NULL, NULL) != 0) return 20;
    char peer_id[64];
    snprintf(peer_id, sizeof(peer_id), "probe-%ld", (long)getpid());
    st_public_cluster_participant probe;
    uint64_t revision = 0U;
    if (participant(&probe, peer_id, peer_id, "probe-room", "room:probe", "192.0.2.77") != 0
        || st_public_coordination_register(&probe, 10, &revision) != 0) return 21;
    uint8_t digest[ST_SHA256_LEN];
    char member[ST_SHA256_LEN * 2U + 1U];
    st_sha256((const uint8_t *)peer_id, strlen(peer_id), digest);
    st_hex_encode(digest, sizeof(digest), member);
    const char *prefix = getenv("SPECUS_TEST_EXPECT_PREFIX");
    long long lease = atoll(getenv("SPECUS_TEST_EXPECT_LEASE_MS"));
    redisReply *ttl = fixture_command("PTTL %s:presence:%s:%s", prefix, probe.group_id, member);
    int result = ttl != NULL && ttl->type == REDIS_REPLY_INTEGER && ttl->integer > lease - 1000
        && ttl->integer <= lease ? 0 : 22;
    if (result != 0) fprintf(stderr, "presence PTTL under prefix '%s': %lld, expected %lld\n", prefix,
                             ttl == NULL ? -9LL : ttl->integer, lease);
    freeReplyObject(ttl);
    (void)st_public_coordination_unregister(&probe, &revision);
    st_public_coordination_shutdown();
    return result;
}

static int probe_timeout(void)
{
    if (st_public_coordination_initialize(NULL, NULL) != 0) return 30;
    redisReply *paused = fixture_command("CLIENT PAUSE %d", 400);
    freeReplyObject(paused);
    long long started = now_ms();
    int available = 0;
    int failed = st_public_coordination_name_available("Timeout Probe", "", &available) == -1;
    long long elapsed = now_ms() - started;
    sleep_ms(500);
    st_public_coordination_shutdown();
    if (!failed || elapsed > 350) {
        fprintf(stderr, "command timeout 0 did not mean 100 ms (%lld ms)\n", elapsed);
        return 31;
    }
    return 0;
}

/* Starts with the URI in the environment and runs one command over it. */
static int probe_connects(void)
{
    if (st_public_coordination_initialize(NULL, NULL) != 0) return 40;
    int allowed = 0;
    int ran = st_public_coordination_allow_rate("tls-probe", "probe", 1000, 30, &allowed) == 0 && allowed;
    st_public_coordination_shutdown();
    return ran ? 0 : 41;
}

static int run_probe(const char *probe)
{
    if (strcmp(probe, "connects") == 0) return probe_connects();
    if (strcmp(probe, "disabled") == 0)
        return !st_public_coordination_enabled() && st_public_coordination_validate_config() == 0 ? 0 : 10;
    if (strcmp(probe, "enabled") == 0)
        return st_public_coordination_enabled() && st_public_coordination_validate_config() == 0 ? 0 : 11;
    if (strcmp(probe, "invalid") == 0)
        return !st_public_coordination_enabled() && st_public_coordination_validate_config() == -1 ? 0 : 12;
    if (strcmp(probe, "invalid-number") == 0) return st_public_coordination_validate_config() == -1 ? 0 : 13;
    if (strcmp(probe, "refused") == 0) {
        int refused = st_public_coordination_validate_config() == 0
            && st_public_coordination_initialize(NULL, NULL) == -1;
        st_public_coordination_shutdown();
        return refused ? 0 : 14;
    }
    if (strcmp(probe, "presence") == 0) return probe_presence();
    if (strcmp(probe, "timeout") == 0) return probe_timeout();
    return 99;
}

/* Runs one probe in a fresh process whose environment differs by the NAME, VALUE pairs. */
static int probe_with(const char *probe, const char *const *settings, size_t count)
{
    size_t inherited = 0U;
    while (environ[inherited] != NULL) ++inherited;
    char **environment = (char **)calloc(inherited + count / 2U + 1U, sizeof(*environment));
    if (environment == NULL) return -1;
    size_t used = 0U;
    for (size_t i = 0U; i < inherited; ++i) {
        int replaced = 0;
        for (size_t s = 0U; s + 1U < count && !replaced; s += 2U) {
            size_t len = strlen(settings[s]);
            replaced = strncmp(environ[i], settings[s], len) == 0 && environ[i][len] == '=';
        }
        if (!replaced) environment[used++] = strdup(environ[i]);
    }
    for (size_t s = 0U; s + 1U < count; s += 2U) {
        size_t len = strlen(settings[s]) + strlen(settings[s + 1U]) + 2U;
        environment[used] = (char *)malloc(len);
        if (environment[used] != NULL) snprintf(environment[used], len, "%s=%s", settings[s], settings[s + 1U]);
        ++used;
    }
    char *const argv[] = {"public_coordination_tests", "--probe", (char *)probe, NULL};
    pid_t child = -1;
    int rc = posix_spawn(&child, "/proc/self/exe", NULL, NULL, argv, environment);
    for (size_t i = 0U; i < used; ++i) free(environment[i]);
    free(environment);
    int status = 0;
    if (rc != 0 || waitpid(child, &status, 0) != child || !WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

#define PROBE(name, ...) \
    probe_with((name), (const char *const[]){__VA_ARGS__}, \
               sizeof((const char *const[]){__VA_ARGS__}) / sizeof(const char *))

/*
 * PublicTransferProperties as Spring binds them: the switch takes true/false, on/off, yes/no or 1/0
 * in any case and with blanks around, the numbers fail startup unless they parse (with or without
 * clustering), the lease and timeout have floors of 5 s and 100 ms, the refresh period must also
 * suit @Scheduled (positive decimal, with or without clustering) and be under half the lease, and
 * the key prefix is trimmed of blanks and trailing colons, a blank one meaning the default. One
 * deliberate exception: an empty value keeps the default in C, where Spring fails startup.
 */
static int test_spring_binding(void)
{
    char uri[128];
    snprintf(uri, sizeof(uri), "  redis://127.0.0.1:%d/0 ", fixture_port());
    struct {
        const char *label;
        int result;
    } checks[] = {
        {"' OFF ' is false", PROBE("disabled", "SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED", " OFF ")},
        {"'No' is false", PROBE("disabled", "SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED", "No")},
        /* C keeps the default for an empty value; Spring fails to bind "" to the primitive. */
        {"an empty switch keeps the default (C only)", PROBE("disabled", "SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED", "")},
        {"a blank switch fails", PROBE("invalid", "SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED", "   ")},
        {"' On ' is true", PROBE("enabled", "SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED", " On ")},
        {"'YES' is true", PROBE("enabled", "SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED", "YES")},
        {"'maybe' fails", PROBE("invalid", "SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED", "maybe")},
        {"'enabled' fails", PROBE("invalid", "SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED", "enabled")},
        {"'y' fails", PROBE("invalid", "SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED", "y")},
        {"a word lease fails even standalone",
         PROBE("invalid-number", "SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED", "false",
               "SPECUS_PUBLIC_TRANSFER_PRESENCE_LEASE_SECONDS", "abc")},
        {"a fractional refresh fails", PROBE("invalid-number", "SPECUS_PUBLIC_TRANSFER_PRESENCE_REFRESH_INTERVAL_MS", "1.5")},
        {"a unit on the timeout fails", PROBE("invalid-number", "SPECUS_PUBLIC_TRANSFER_REDIS_COMMAND_TIMEOUT_MS", "2s")},
        {"a blank number fails", PROBE("invalid-number", "SPECUS_PUBLIC_TRANSFER_PRESENCE_LEASE_SECONDS", " ")},
        {"empty numbers keep their defaults (C only)",
         PROBE("presence", "SPECUS_PUBLIC_TRANSFER_PRESENCE_LEASE_SECONDS", "",
               "SPECUS_PUBLIC_TRANSFER_PRESENCE_REFRESH_INTERVAL_MS", "",
               "SPECUS_PUBLIC_TRANSFER_REDIS_COMMAND_TIMEOUT_MS", "",
               "SPECUS_TEST_EXPECT_PREFIX", "specus:test:coordination", "SPECUS_TEST_EXPECT_LEASE_MS", "30000")},
        /* The refresh period is also @Scheduled(fixedDelayString), so it fails even standalone. */
        {"refresh 0 fails even standalone",
         PROBE("invalid-number", "SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED", "false",
               "SPECUS_PUBLIC_TRANSFER_PRESENCE_REFRESH_INTERVAL_MS", "0")},
        {"a negative refresh fails even standalone",
         PROBE("invalid-number", "SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED", "false",
               "SPECUS_PUBLIC_TRANSFER_PRESENCE_REFRESH_INTERVAL_MS", "-5")},
        {"a hexadecimal refresh fails even standalone",
         PROBE("invalid-number", "SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED", "false",
               "SPECUS_PUBLIC_TRANSFER_PRESENCE_REFRESH_INTERVAL_MS", "0x2710")},
        {"blanks in the refresh fail even standalone",
         PROBE("invalid-number", "SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED", "false",
               "SPECUS_PUBLIC_TRANSFER_PRESENCE_REFRESH_INTERVAL_MS", " 1 0 ")},
        {"a refresh with a plus sign", PROBE("presence", "SPECUS_PUBLIC_TRANSFER_PRESENCE_REFRESH_INTERVAL_MS", "+1000",
                                             "SPECUS_TEST_EXPECT_PREFIX", "specus:test:coordination",
                                             "SPECUS_TEST_EXPECT_LEASE_MS", "30000")},
        {"lease 0 is 5 s, too short for the default refresh",
         PROBE("refused", "SPECUS_PUBLIC_TRANSFER_PRESENCE_LEASE_SECONDS", "0")},
        {"lease 0 is 5 s", PROBE("presence", "SPECUS_PUBLIC_TRANSFER_PRESENCE_LEASE_SECONDS", "0",
                                 "SPECUS_PUBLIC_TRANSFER_PRESENCE_REFRESH_INTERVAL_MS", "1000",
                                 "SPECUS_TEST_EXPECT_PREFIX", "specus:test:coordination",
                                 "SPECUS_TEST_EXPECT_LEASE_MS", "5000")},
        {"whitespace inside a number is removed",
         PROBE("presence", "SPECUS_PUBLIC_TRANSFER_PRESENCE_LEASE_SECONDS", " 1 0 ",
               "SPECUS_PUBLIC_TRANSFER_PRESENCE_REFRESH_INTERVAL_MS", "1000",
               "SPECUS_TEST_EXPECT_PREFIX", "specus:test:coordination", "SPECUS_TEST_EXPECT_LEASE_MS", "10000")},
        {"a hexadecimal lease", PROBE("presence", "SPECUS_PUBLIC_TRANSFER_PRESENCE_LEASE_SECONDS", "0x1E",
                                      "SPECUS_PUBLIC_TRANSFER_PRESENCE_REFRESH_INTERVAL_MS", "1000",
                                      "SPECUS_TEST_EXPECT_PREFIX", "specus:test:coordination",
                                      "SPECUS_TEST_EXPECT_LEASE_MS", "30000")},
        {"a blank prefix is the default",
         PROBE("presence", "SPECUS_PUBLIC_TRANSFER_REDIS_KEY_PREFIX", "   ",
               "SPECUS_TEST_EXPECT_PREFIX", "specus:v2:public-transfer", "SPECUS_TEST_EXPECT_LEASE_MS", "30000")},
        {"a prefix of colons is empty",
         PROBE("presence", "SPECUS_PUBLIC_TRANSFER_REDIS_KEY_PREFIX", "::",
               "SPECUS_TEST_EXPECT_PREFIX", "", "SPECUS_TEST_EXPECT_LEASE_MS", "30000")},
        {"trim, then the trailing colons",
         PROBE("presence", "SPECUS_PUBLIC_TRANSFER_REDIS_KEY_PREFIX", " probe tail ::\t",
               "SPECUS_TEST_EXPECT_PREFIX", "probe tail ", "SPECUS_TEST_EXPECT_LEASE_MS", "30000")},
        {"the URI is trimmed",
         PROBE("presence", "SPECUS_PUBLIC_TRANSFER_REDIS_URI", uri,
               "SPECUS_TEST_EXPECT_PREFIX", "specus:test:coordination", "SPECUS_TEST_EXPECT_LEASE_MS", "30000")},
        {"timeout 0 is 100 ms", PROBE("timeout", "SPECUS_PUBLIC_TRANSFER_REDIS_COMMAND_TIMEOUT_MS", "0")}
    };
    int failed = 0;
    for (size_t i = 0U; i < sizeof(checks) / sizeof(checks[0]); ++i) {
        if (checks[i].result != 0) {
            fprintf(stderr, "Spring binding: %s (probe exit %d)\n", checks[i].label, checks[i].result);
            failed = 1;
        }
    }
    return failed;
}

/*
 * redis-socket:// and redis+socket://, which Lettuce connects through Netty's native transport:
 * the path is the socket and the database comes from the query. Plain run only.
 */
static int test_unix_socket(void)
{
    const char *socket_path = getenv("SPECUS_TEST_REDIS_SOCKET");
    if (socket_path == NULL) return 0;
    char by_socket[256], by_alias[256], missing[256];
    snprintf(by_socket, sizeof(by_socket), "redis-socket://%s?database=1", socket_path);
    snprintf(by_alias, sizeof(by_alias), "redis+socket://%s", socket_path);
    snprintf(missing, sizeof(missing), "redis-socket://%s.missing", socket_path);
    static const char uri_env[] = "SPECUS_PUBLIC_TRANSFER_REDIS_URI";
    int failed = 0;
    if (PROBE("connects", uri_env, by_socket) != 0 || PROBE("connects", uri_env, by_alias) != 0) {
        fprintf(stderr, "Unix socket: the coordination layer did not connect through %s\n", socket_path);
        failed = 1;
    }
    if (PROBE("refused", uri_env, missing) != 0) {
        fprintf(stderr, "Unix socket: a missing socket did not fail startup\n");
        failed = 1;
    }
    return failed;
}

/*
 * rediss:// verified as Lettuce's SslVerifyMode does, in the TLS run only: FULL (the default)
 * needs a trusted chain and the connected host in the certificate (DNS:localhost and
 * IP:127.0.0.1 here, so 127.0.0.2 is not in it), CA only the chain, NONE nothing. The trust store
 * is OpenSSL's default; the script points SSL_CERT_FILE at the test CA, as a Java deployment points
 * javax.net.ssl.trustStore at its CA. Neither side offers a client certificate.
 */
static int test_tls_verification(void)
{
    const char *tls_port = getenv("SPECUS_TEST_REDIS_TLS_PORT");
    const char *other_ca = getenv("SPECUS_TEST_REDIS_OTHER_CA");
    if (tls_port == NULL) return 0;
    if (other_ca == NULL) {
        fprintf(stderr, "the TLS run needs SPECUS_TEST_REDIS_OTHER_CA\n");
        return 1;
    }
    char by_name[96], unnamed[96], unnamed_ca[128], ssl_alias[96], by_ip[96], by_ip_ca[128], by_ip_none[128];
    char tls_to_plain[96], plain_to_tls[96];
    snprintf(by_name, sizeof(by_name), "rediss://localhost:%s/0", tls_port);
    snprintf(unnamed, sizeof(unnamed), "rediss://127.0.0.2:%s/0", tls_port);
    snprintf(unnamed_ca, sizeof(unnamed_ca), "rediss://127.0.0.2:%s/0?verifyPeer=CA", tls_port);
    snprintf(ssl_alias, sizeof(ssl_alias), "redis+ssl://127.0.0.1:%s/0", tls_port);
    snprintf(by_ip, sizeof(by_ip), "rediss://127.0.0.1:%s/0", tls_port);
    snprintf(by_ip_ca, sizeof(by_ip_ca), "rediss://127.0.0.1:%s/0?verifyPeer=ca", tls_port);
    snprintf(by_ip_none, sizeof(by_ip_none), "rediss://127.0.0.1:%s/0?verifyPeer=NONE", tls_port);
    snprintf(tls_to_plain, sizeof(tls_to_plain), "rediss://127.0.0.1:%d/0", fixture_port());
    snprintf(plain_to_tls, sizeof(plain_to_tls), "redis://127.0.0.1:%s/0", tls_port);
    static const char uri_env[] = "SPECUS_PUBLIC_TRANSFER_REDIS_URI";
    struct {
        const char *label;
        int result;
    } checks[] = {
        {"FULL accepts the host name in the certificate", PROBE("connects", uri_env, by_name)},
        {"FULL refuses an address the certificate does not name", PROBE("refused", uri_env, unnamed)},
        {"CA accepts that address", PROBE("connects", uri_env, unnamed_ca)},
        {"redis+ssl:// is rediss://", PROBE("connects", uri_env, ssl_alias)},
        {"FULL refuses an untrusted CA", PROBE("refused", uri_env, by_ip, "SSL_CERT_FILE", other_ca)},
        {"CA refuses an untrusted CA", PROBE("refused", uri_env, by_ip_ca, "SSL_CERT_FILE", other_ca)},
        {"NONE accepts an untrusted CA", PROBE("connects", uri_env, by_ip_none, "SSL_CERT_FILE", other_ca)},
        {"rediss:// to a plain port fails", PROBE("refused", uri_env, tls_to_plain)},
        {"redis:// to the TLS port fails", PROBE("refused", uri_env, plain_to_tls)}
    };
    int failed = 0;
    for (size_t i = 0U; i < sizeof(checks) / sizeof(checks[0]); ++i) {
        if (checks[i].result != 0) {
            fprintf(stderr, "TLS verification: %s (probe exit %d)\n", checks[i].label, checks[i].result);
            failed = 1;
        }
    }
    return failed;
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
    /* hiredis writes without MSG_NOSIGNAL; a dropped Redis connection must fail a call, not the run. */
    (void)signal(SIGPIPE, SIG_IGN);
    if (argc > 1 && strcmp(argv[1], "--second-instance") == 0) return second_instance();
    if (argc > 2 && strcmp(argv[1], "--probe") == 0) return run_probe(argv[2]);
    if (!st_public_coordination_enabled()
        || st_public_coordination_initialize(capture_event, NULL) != 0) {
        fprintf(stderr, "Redis coordination did not initialize\n");
        return 1;
    }
    struct timespec idle = {.tv_sec = 0, .tv_nsec = 250000000L};
    (void)nanosleep(&idle, NULL);
    if (!st_public_coordination_available() || status_now().subscriber_reconnects != 0U) {
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
    int failed = test_lookup_costs() != 0
        || test_error_reply_fails_only_the_call() != 0
        || test_timeout_fails_only_the_call() != 0
        || test_event_queue_is_bounded() != 0
        || test_spring_binding() != 0
        || test_unix_socket() != 0
        || test_tls_verification() != 0
        || test_reconnect_after_restart() != 0;
    st_public_coordination_shutdown();
    if (restarted_redis > 0) {
        (void)kill(restarted_redis, SIGTERM);
        (void)waitpid(restarted_redis, NULL, 0);
    }
    if (failed) return 1;
    puts("public coordination tests passed");
    return 0;
}
