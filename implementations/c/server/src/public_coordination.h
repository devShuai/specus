#ifndef SPECUS_PUBLIC_COORDINATION_H
#define SPECUS_PUBLIC_COORDINATION_H

#include <stddef.h>
#include <stdint.h>

#define ST_PUBLIC_CLUSTER_ID_BYTES 64U
#define ST_PUBLIC_CLUSTER_LEASE_BYTES 64U
#define ST_PUBLIC_CLUSTER_PEER_BYTES 480U
#define ST_PUBLIC_CLUSTER_NAME_BYTES 480U
#define ST_PUBLIC_CLUSTER_ROOM_BYTES 480U
#define ST_PUBLIC_CLUSTER_ADDRESS_BYTES 128U
#define ST_PUBLIC_CLUSTER_ROOM_KEY_BYTES 80U
/* STCE v2 frame limits (protocol/spec/public-transfer-cluster.md): group and identity UTF-8 bytes. */
#define ST_PUBLIC_CLUSTER_EVENT_GROUP_BYTES 128U
#define ST_PUBLIC_CLUSTER_EVENT_ID_BYTES 512U

typedef struct {
    char lease_id[ST_PUBLIC_CLUSTER_LEASE_BYTES + 1U];
    char peer_id[ST_PUBLIC_CLUSTER_PEER_BYTES + 1U];
    char display_name[ST_PUBLIC_CLUSTER_NAME_BYTES + 1U];
    char room_id[ST_PUBLIC_CLUSTER_ROOM_BYTES + 1U];
    char public_address[ST_PUBLIC_CLUSTER_ADDRESS_BYTES + 1U];
    char room_key[ST_PUBLIC_CLUSTER_ROOM_KEY_BYTES + 1U];
    char room_role[16];
    char connected_at[40];
    char group_id[ST_PUBLIC_CLUSTER_ID_BYTES + 1U];
    char net_id[ST_PUBLIC_CLUSTER_ID_BYTES + 1U];
    int shared_room;
} st_public_cluster_participant;

typedef struct {
    uint64_t revision;
    st_public_cluster_participant *participants;
    size_t count;
} st_public_cluster_roster;

enum {
    ST_PUBLIC_CLUSTER_EVENT_ROSTER = 1,
    ST_PUBLIC_CLUSTER_EVENT_TEXT = 2,
    ST_PUBLIC_CLUSTER_EVENT_BINARY = 3,
    ST_PUBLIC_CLUSTER_EVENT_MANAGEMENT = 4,
    ST_PUBLIC_CLUSTER_EVENT_MANAGEMENT_REVOCATION = 5
};

/*
 * Java's single "public-transfer-cluster-events" executor: decoded events wait in a bounded queue
 * and one dispatcher thread hands them to the handler, so a slow handler never stalls the Redis
 * subscription. A full queue drops the event (Java logs and discards). C also bounds the queued
 * payload bytes, which Java does not.
 */
#define ST_PUBLIC_CLUSTER_EVENT_QUEUE_LIMIT 4096U
#define ST_PUBLIC_CLUSTER_EVENT_QUEUE_MAX_BYTES (64U * 1024U * 1024U)

/* Lettuce's default reconnect delay: 2^(attempt-1) ms after each failed attempt, at most 30 s. */
#define ST_PUBLIC_CLUSTER_RECONNECT_MAX_DELAY_MS 30000L

typedef struct {
    int initialized;
    int command_connected;
    int publisher_connected;
    int subscriber_connected;
    unsigned long command_reconnects;
    unsigned long publisher_reconnects;
    unsigned long subscriber_reconnects;
    unsigned long events_dropped;
    size_t events_queued;
} st_public_coordination_status;

typedef struct {
    uint8_t kind;
    int exclude_source;
    uint64_t revision;
    char group_id[ST_PUBLIC_CLUSTER_EVENT_GROUP_BYTES + 1U];
    char target_peer_id[ST_PUBLIC_CLUSTER_EVENT_ID_BYTES + 1U];
    char source_lease_id[ST_PUBLIC_CLUSTER_EVENT_ID_BYTES + 1U];
    uint8_t *payload;
    size_t payload_len;
} st_public_cluster_event;

typedef void (*st_public_cluster_event_handler)(const st_public_cluster_event *event,
                                                void *context);

/*
 * SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED as Spring binds it: trimmed, case-insensitive
 * true/on/yes/1 or false/off/no/0. Unset is false, and so is an empty value (Spring fails startup
 * on ""; C keeps the default). Any other value, a blank one included, is a configuration error
 * that st_public_coordination_validate_config() reports, and reads as disabled here.
 */
int st_public_coordination_enabled(void);
/*
 * Startup check of the settings Java binds or schedules whether or not clustering is on: the
 * switch must be a boolean, the lease, refresh and timeout values numbers, and the refresh period
 * a positive decimal (@Scheduled). An empty value counts as unset. 0 or -1 (logged).
 */
int st_public_coordination_validate_config(void);
/*
 * Startup connects the command, publish and subscribe connections (PING and SUBSCRIBE must
 * succeed, as Java requires). Afterwards a lost connection is re-established in the background
 * (Pub/Sub, with SUBSCRIBE replayed) or by the next command, with Lettuce's exponential delay;
 * while a connection is down its operations fail without affecting the others.
 */
int st_public_coordination_initialize(st_public_cluster_event_handler handler, void *context);
void st_public_coordination_shutdown(void);
/* 1 after a successful initialize while the command and subscribe connections are both up. */
int st_public_coordination_available(void);
void st_public_coordination_status_get(st_public_coordination_status *status);
long st_public_coordination_refresh_interval_ms(void);

int st_public_coordination_prepare_participant(st_public_cluster_participant *participant);

/* 0 accepted, 1 duplicate peer, 2 duplicate name, 3 room full, -1 unavailable/error. */
int st_public_coordination_register(const st_public_cluster_participant *participant,
                                    int room_limit,
                                    uint64_t *revision);
/* 0 refreshed, 1 lease lost (the presence or name is no longer this lease's), -1 Redis failure. */
int st_public_coordination_refresh(const st_public_cluster_participant *participant);
int st_public_coordination_unregister(const st_public_cluster_participant *participant,
                                      uint64_t *revision);
/* Java sweep(groupId, netId): prunes expired members and publishes both rosters when any left. */
int st_public_coordination_sweep(const char *group_id, const char *net_id);

int st_public_coordination_roster(const st_public_cluster_participant *recipient,
                                  st_public_cluster_roster *roster);
void st_public_coordination_roster_free(st_public_cluster_roster *roster);
int st_public_coordination_find_peer(const st_public_cluster_participant *recipient,
                                    const char *peer_id,
                                    st_public_cluster_participant *target,
                                    int *found);
int st_public_coordination_name_available(const char *display_name,
                                          const char *exclude_peer_id,
                                          int *available);
int st_public_coordination_allow_rate(const char *bucket,
                                      const char *identity,
                                      long limit,
                                      long window_seconds,
                                      int *allowed);

/*
 * The STCE v2 Pub/Sub envelope (protocol/spec/public-transfer-cluster.md). Both return 0 on success
 * and -1 for an event Java's PublicTransferClusterFrame refuses; the encoded buffer and a decoded
 * payload are malloc'ed and owned by the caller.
 */
int st_public_cluster_event_encode(const st_public_cluster_event *event,
                                   uint8_t **encoded,
                                   size_t *encoded_len);
int st_public_cluster_event_decode(const uint8_t *encoded,
                                   size_t encoded_len,
                                   st_public_cluster_event *event);

int st_public_coordination_publish_roster(const char *group_id, uint64_t revision);
/* Java's SHA-256(trim(tenantId)); NULL has the same digest as an empty string. */
void st_public_coordination_management_group(const char *tenant_id, char out[65]);
int st_public_coordination_publish_management(uint8_t kind, const char *tenant_id,
                                              const uint8_t *payload, size_t payload_len);
int st_public_coordination_publish_text(const char *group_id,
                                        const char *target_peer_id,
                                        const char *source_lease_id,
                                        int exclude_source,
                                        const uint8_t *payload,
                                        size_t payload_len);
int st_public_coordination_publish_binary(const char *group_id,
                                          const char *target_peer_id,
                                          const uint8_t *payload,
                                          size_t payload_len);

#endif
