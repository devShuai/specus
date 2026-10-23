#ifndef SPECUS_STUN_TURN_H
#define SPECUS_STUN_TURN_H

typedef struct st_stun_turn_server st_stun_turn_server;

int st_stun_turn_server_start(st_stun_turn_server **out_server);
int st_stun_turn_server_port(const st_stun_turn_server *server);
/*
 * Writes the Peer Mesh relay bytes counted since the last batch, as the periodic flush (every
 * SPECUS_PEER_MESH_RELAY_TRAFFIC_FLUSH_INTERVAL_MS) and the stop do.
 */
void st_stun_turn_server_flush_relay_traffic(st_stun_turn_server *server);
void st_stun_turn_server_stop(st_stun_turn_server *server);

#endif
