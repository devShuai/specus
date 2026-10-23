#define _POSIX_C_SOURCE 200809L

#include "public_coordination.h"

#include <errno.h>
#include <hiredis/hiredis.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/*
 * redis-sentinel:// (or rediss-sentinel://) as Lettuce follows it, against the master, replica and
 * Sentinel that public_coordination_sentinel_test.sh starts: the master is found through the
 * Sentinel list (an unreachable Sentinel first), the URI's password reaches the data nodes and
 * never a Sentinel, every connection carries the client name, and after SENTINEL FAILOVER the
 * connections that the old master drops come back on the promoted one, because each reconnect asks
 * the Sentinels again. The fixture talks to every node over its plain port.
 */

#define CLIENT_NAME "specus-c-sentinel"

static pthread_mutex_t capture_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t capture_cond = PTHREAD_COND_INITIALIZER;
static int capture_received;
static char capture_target[ST_PUBLIC_CLUSTER_EVENT_ID_BYTES + 1U];

static void capture_event(const st_public_cluster_event *event, void *context)
{
    (void)context;
    if (event == NULL) return;
    pthread_mutex_lock(&capture_lock);
    snprintf(capture_target, sizeof(capture_target), "%s", event->target_peer_id);
    capture_received = 1;
    pthread_cond_broadcast(&capture_cond);
    pthread_mutex_unlock(&capture_lock);
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

static int env_port(const char *name)
{
    const char *value = getenv(name);
    return value == NULL ? -1 : atoi(value);
}

/* One fixture command on its own plain connection; data nodes need the password, Sentinels none. */
static redisReply *fixture_command(int port, int data_node, const char *format, ...)
{
    struct timeval timeout = {.tv_sec = 2, .tv_usec = 0};
    redisContext *redis = redisConnectWithTimeout("127.0.0.1", port, timeout);
    if (redis == NULL || redis->err) {
        if (redis != NULL) redisFree(redis);
        return NULL;
    }
    (void)redisSetTimeout(redis, timeout);
    const char *password = getenv("SPECUS_TEST_DATA_PASSWORD");
    if (data_node && password != NULL) {
        redisReply *auth = (redisReply *)redisCommand(redis, "AUTH %s", password);
        int ok = auth != NULL && auth->type == REDIS_REPLY_STATUS;
        freeReplyObject(auth);
        if (!ok) {
            redisFree(redis);
            return NULL;
        }
    }
    va_list arguments;
    va_start(arguments, format);
    redisReply *reply = (redisReply *)redisvCommand(redis, format, arguments);
    va_end(arguments);
    redisFree(redis);
    return reply;
}

/* How many connections on a data node carry the URI's client name (-1 when it cannot be asked). */
static int named_clients(int port)
{
    redisReply *list = fixture_command(port, 1, "CLIENT LIST");
    if (list == NULL || (list->type != REDIS_REPLY_STRING && list->type != REDIS_REPLY_VERB)) {
        freeReplyObject(list);
        return -1;
    }
    int count = 0;
    for (const char *found = strstr(list->str, "name=" CLIENT_NAME " "); found != NULL;
         found = strstr(found + 1, "name=" CLIENT_NAME " "))
        ++count;
    freeReplyObject(list);
    return count;
}

/* The master port the Sentinel reports now, -1 when it reports none. */
static int sentinel_master_port(void)
{
    redisReply *reply = fixture_command(env_port("SPECUS_TEST_SENTINEL_PORT"), 0,
                                        "SENTINEL GET-MASTER-ADDR-BY-NAME mymaster");
    int port = reply != NULL && reply->type == REDIS_REPLY_ARRAY && reply->elements == 2U
        && reply->element[1]->type == REDIS_REPLY_STRING ? atoi(reply->element[1]->str) : -1;
    freeReplyObject(reply);
    return port;
}

static int role_is_master(int port)
{
    redisReply *info = fixture_command(port, 1, "INFO replication");
    int master = info != NULL && (info->type == REDIS_REPLY_STRING || info->type == REDIS_REPLY_VERB)
        && strstr(info->str, "role:master") != NULL;
    freeReplyObject(info);
    return master;
}

static int participant(st_public_cluster_participant *value, const char *peer_id, const char *name)
{
    memset(value, 0, sizeof(*value));
    snprintf(value->peer_id, sizeof(value->peer_id), "%s", peer_id);
    snprintf(value->display_name, sizeof(value->display_name), "%s", name);
    snprintf(value->room_id, sizeof(value->room_id), "sentinel-room");
    snprintf(value->room_key, sizeof(value->room_key), "room:sentinel");
    snprintf(value->public_address, sizeof(value->public_address), "198.51.100.70");
    snprintf(value->room_role, sizeof(value->room_role), "EDITOR");
    snprintf(value->connected_at, sizeof(value->connected_at), "2026-10-23T00:00:00Z");
    value->shared_room = 1;
    return st_public_coordination_prepare_participant(value);
}

/* Publishes a directed event and waits until this instance's own subscription delivers it. */
static int round_trip(const st_public_cluster_participant *source, const char *target)
{
    static const char text[] = "{\"type\":\"sentinel\"}";
    pthread_mutex_lock(&capture_lock);
    capture_received = 0;
    pthread_mutex_unlock(&capture_lock);
    if (st_public_coordination_publish_text(source->group_id, target, source->lease_id, 0,
                                            (const uint8_t *)text, strlen(text)) != 0) return -1;
    struct timespec deadline;
    (void)clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 3;
    pthread_mutex_lock(&capture_lock);
    while (!capture_received) {
        if (pthread_cond_timedwait(&capture_cond, &capture_lock, &deadline) != 0) break;
    }
    int received = capture_received && strcmp(capture_target, target) == 0;
    pthread_mutex_unlock(&capture_lock);
    return received ? 0 : -1;
}

/* Starts this binary with another URI; it exits 0 when that URI fails startup. */
static int refused_with(const char *uri)
{
    pid_t child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        if (setenv("SPECUS_PUBLIC_TRANSFER_REDIS_URI", uri, 1) != 0) _exit(98);
        char *const argv[] = {"public_coordination_sentinel_tests", "--refused", NULL};
        execv("/proc/self/exe", argv);
        _exit(127);
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

static int fail(const char *message)
{
    fprintf(stderr, "sentinel test: %s\n", message);
    st_public_coordination_shutdown();
    return 1;
}

int main(int argc, char **argv)
{
    (void)signal(SIGPIPE, SIG_IGN);
    if (argc > 1 && strcmp(argv[1], "--refused") == 0) {
        int refused = st_public_coordination_initialize(NULL, NULL) == -1;
        st_public_coordination_shutdown();
        return refused ? 0 : 1;
    }
    int master = env_port("SPECUS_TEST_MASTER_PORT");
    int replica = env_port("SPECUS_TEST_REPLICA_PORT");
    int replica_address = env_port("SPECUS_TEST_REPLICA_ADDRESS_PORT");
    if (master < 0 || replica < 0 || replica_address < 0 || env_port("SPECUS_TEST_SENTINEL_PORT") < 0) {
        fprintf(stderr, "sentinel test: the fixture ports are missing\n");
        return 1;
    }
    /* Lettuce fails the lookup on an unknown master id, and without a reachable Sentinel. */
    static const char *const refusals[][2] = {
        {"SPECUS_TEST_UNKNOWN_MASTER_URI", "an unknown master id"},
        {"SPECUS_TEST_NO_SENTINEL_URI", "no reachable Sentinel"},
        {"SPECUS_TEST_WRONG_PASSWORD_URI", "a wrong data-node password"}
    };
    for (size_t i = 0U; i < sizeof(refusals) / sizeof(refusals[0]); ++i) {
        const char *uri = getenv(refusals[i][0]);
        if (uri == NULL || refused_with(uri) != 0) {
            fprintf(stderr, "sentinel test: startup with %s did not fail\n", refusals[i][1]);
            return 1;
        }
    }

    if (!st_public_coordination_enabled() || st_public_coordination_initialize(capture_event, NULL) != 0)
        return fail("coordination did not start through the Sentinel");
    /* The command, publish and subscribe connections, all on the master the Sentinel named. */
    if (named_clients(master) != 3 || named_clients(replica) != 0) {
        fprintf(stderr, "named connections: master %d, replica %d\n", named_clients(master), named_clients(replica));
        return fail("the connections are not on the master");
    }
    st_public_cluster_participant first, second;
    uint64_t revision = 0U;
    if (participant(&first, "sentinel-a", "Sentinel A") != 0 || participant(&second, "sentinel-b", "Sentinel B") != 0
        || st_public_coordination_register(&first, 10, &revision) != 0 || round_trip(&first, "before-failover") != 0)
        return fail("registration or Pub/Sub on the first master");

    /* A forced failover; NOGOODSLAVE until the Sentinel has seen the replica. */
    long long deadline = now_ms() + 20000;
    int started = 0;
    while (!started && now_ms() < deadline) {
        redisReply *reply = fixture_command(env_port("SPECUS_TEST_SENTINEL_PORT"), 0, "SENTINEL FAILOVER mymaster");
        started = reply != NULL && reply->type == REDIS_REPLY_STATUS;
        freeReplyObject(reply);
        if (!started) sleep_ms(200);
    }
    if (!started) return fail("the Sentinel did not start a failover");
    deadline = now_ms() + 30000;
    while ((sentinel_master_port() != replica_address || !role_is_master(replica)) && now_ms() < deadline)
        sleep_ms(100);
    if (sentinel_master_port() != replica_address || !role_is_master(replica))
        return fail("the Sentinel did not promote the replica");

    /*
     * The old master is still up and still a master, so nothing has dropped the connections yet.
     * The Sentinel converts it some ten seconds later with REPLICAOF and CLIENT KILL TYPE normal /
     * pubsub (sentinelSendSlaveOf); the fixture sends the same commands now instead of waiting.
     */
    redisReply *demoted = fixture_command(master, 1, "REPLICAOF 127.0.0.1 %d", replica_address);
    int demote_ok = demoted != NULL && demoted->type == REDIS_REPLY_STATUS;
    freeReplyObject(demoted);
    freeReplyObject(fixture_command(master, 1, "CLIENT KILL TYPE normal"));
    freeReplyObject(fixture_command(master, 1, "CLIENT KILL TYPE pubsub"));
    if (!demote_ok) return fail("the old master could not be reconfigured");
    long long dropped_at = now_ms();

    /* Each connection reconnects on its own, asks the Sentinel again and lands on the new master. */
    deadline = now_ms() + 15000;
    int registered = -1;
    while (registered != 0 && now_ms() < deadline) {
        registered = st_public_coordination_register(&second, 10, &revision);
        if (registered != 0) sleep_ms(100);
    }
    if (registered != 0) return fail("writes did not reach the promoted master");
    st_public_coordination_status status;
    do {
        st_public_coordination_status_get(&status);
        if (status.subscriber_connected && status.subscriber_reconnects > 0U) break;
        sleep_ms(50);
    } while (now_ms() < deadline);
    if (!status.subscriber_connected || status.subscriber_reconnects == 0U)
        return fail("the subscription did not come back");
    if (round_trip(&second, "after-failover") != 0) return fail("Pub/Sub on the promoted master");
    if (named_clients(replica) != 3 || named_clients(master) != 0) {
        fprintf(stderr, "named connections after failover: promoted %d, old master %d\n",
                named_clients(replica), named_clients(master));
        return fail("the connections did not follow the promoted master");
    }
    st_public_coordination_status_get(&status);
    if (status.command_reconnects == 0U || status.publisher_reconnects == 0U || !st_public_coordination_available())
        return fail("reconnect counters did not move");
    printf("on the promoted master %lld ms after the old one dropped the connections\n", now_ms() - dropped_at);
    (void)st_public_coordination_unregister(&first, &revision);
    (void)st_public_coordination_unregister(&second, &revision);
    st_public_coordination_shutdown();
    puts("public coordination sentinel tests passed");
    return 0;
}
