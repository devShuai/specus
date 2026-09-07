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
    ST_PUBLIC_CLUSTER_EVENT_UNAVAILABLE = 255
};

typedef struct {
    uint8_t kind;
    int exclude_source;
    uint64_t revision;
    char group_id[ST_PUBLIC_CLUSTER_ID_BYTES + 1U];
    char target_peer_id[ST_PUBLIC_CLUSTER_PEER_BYTES + 1U];
    char source_lease_id[ST_PUBLIC_CLUSTER_LEASE_BYTES + 1U];
    uint8_t *payload;
    size_t payload_len;
} st_public_cluster_event;

typedef void (*st_public_cluster_event_handler)(const st_public_cluster_event *event,
                                                void *context);

int st_public_coordination_enabled(void);
int st_public_coordination_initialize(st_public_cluster_event_handler handler, void *context);
void st_public_coordination_shutdown(void);
int st_public_coordination_available(void);
long st_public_coordination_refresh_interval_ms(void);

int st_public_coordination_prepare_participant(st_public_cluster_participant *participant);

/* 0 accepted, 1 duplicate peer, 2 duplicate name, 3 room full, -1 unavailable/error. */
int st_public_coordination_register(const st_public_cluster_participant *participant,
                                    int room_limit,
                                    uint64_t *revision);
int st_public_coordination_refresh(const st_public_cluster_participant *participant);
int st_public_coordination_unregister(const st_public_cluster_participant *participant,
                                      uint64_t *revision);
int st_public_coordination_sweep(const st_public_cluster_participant *participant);

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

int st_public_coordination_publish_roster(const char *group_id, uint64_t revision);
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
