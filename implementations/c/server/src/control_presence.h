#ifndef SPECUS_C_CONTROL_PRESENCE_H
#define SPECUS_C_CONTROL_PRESENCE_H

typedef struct st_control_presence st_control_presence;
enum { ST_CONTROL_PRESENCE_UNKNOWN = -1, ST_CONTROL_PRESENCE_DEAD = 0, ST_CONTROL_PRESENCE_LIVE = 1 };

/* Physical c-<32 lowercase hex> channels are server-generated, never taken from a login body.
 * An advisory sidecar is acquired BEFORE native ONLINE, held through socket/audit teardown, and
 * inherited by no exec'ed helper. Only cooperating instances sharing the same SQLite filesystem
 * are covered; failure/unknown ownership must not be interpreted as death. */
int st_control_presence_acquire(const char *database_path, const char *channel,
                                st_control_presence **out);
void st_control_presence_release(st_control_presence *presence, int forget);
int st_control_presence_probe(const char *database_path, const char *channel);
/* Call only after native ONLINE and open-audit references to this terminal channel are absent. */
void st_control_presence_forget_dead(const char *database_path, const char *channel);

#endif
