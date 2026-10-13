#ifndef SPECUS_TURN_AUTH_H
#define SPECUS_TURN_AUTH_H

#include <stddef.h>
#include <stdint.h>

int st_turn_auth_issue(const char *subject,
                       char *username,
                       size_t username_len,
                       char *credential,
                       size_t credential_len);
const char *st_turn_auth_realm(void);
const char *st_turn_auth_nonce(void);
int st_turn_auth_username_valid(const char *username);
int st_turn_auth_credential_for(const char *username, char *out, size_t out_len);
int st_turn_auth_long_term_key(const char *username, uint8_t out[16]);

/*
 * The subject an issued username carries, read as Java TurnCredentialService does: the field
 * between the first and second colon of "<expiry>:<subject>:<random>".
 *
 * A Peer Mesh subject "pm-<clientId>" names the client its allocation relays for; any other
 * subject gives 0. A "public-transfer" subject is the general relay (browser WebRTC); a subject
 * that is neither is no relay identity at all, and its allocation relays nothing.
 */
long long st_turn_auth_peer_mesh_client_id(const char *username);
int st_turn_auth_is_general_relay_subject(const char *username);

#endif
