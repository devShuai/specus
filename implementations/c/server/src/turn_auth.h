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

#endif
