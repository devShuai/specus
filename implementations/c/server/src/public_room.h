#ifndef SPECUS_PUBLIC_ROOM_H
#define SPECUS_PUBLIC_ROOM_H

#include <stddef.h>

typedef struct {
    char room_key[80];
    char role[16];
} st_public_room_access;

/* Returns 0 on success, 1 when persistence is not configured, 2 for an invalid credential. */
int st_public_room_resolve(const char *room_name,
                           const char *room_token,
                           const char *peer_id,
                           st_public_room_access *out);

/* Returns 0 when the route does not belong to this module; otherwise an HTTP response length. */
int st_public_room_build_response(const char *method,
                                  const char *path,
                                  const char *body,
                                  const char *remote_address,
                                  char *out,
                                  size_t out_len);

void st_public_room_reset_for_tests(void);

#endif
