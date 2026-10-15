#define _XOPEN_SOURCE 700
#include "control_presence.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

struct st_control_presence { int fd; char path[PATH_MAX + 80]; };
static int physical_channel(const char *channel)
{
    return channel && strlen(channel) == 34U && !memcmp(channel, "c-", 2U)
        && strspn(channel + 2, "0123456789abcdef") == 32U;
}
static int filename(const char *database_path, const char *channel, char *out, size_t length)
{
    if (!database_path || !physical_channel(channel)) return -1;
    char *canonical = realpath(database_path, NULL); if (!canonical) return -1;
    struct stat database;
    if (stat(canonical, &database) != 0 || !S_ISREG(database.st_mode)) { free(canonical); return -1; }
    int written = snprintf(out, length, "%s.control-%s.lock", canonical, channel);
    free(canonical); return written > 0 && (size_t)written < length ? 0 : -1;
}
static void unlink_owned(int fd, const char *path)
{
    struct stat owned, named;
    if (fstat(fd, &owned) == 0 && lstat(path, &named) == 0 && S_ISREG(named.st_mode)
        && owned.st_dev == named.st_dev && owned.st_ino == named.st_ino) (void)unlink(path);
}
int st_control_presence_acquire(const char *database_path, const char *channel, st_control_presence **out)
{
    if (!out) return -1;
    *out = NULL;
    st_control_presence *presence = calloc(1, sizeof(*presence)); if (!presence) return -1;
    presence->fd = -1;
    if (filename(database_path, channel, presence->path, sizeof(presence->path)) != 0) { free(presence); return -1; }
    presence->fd = open(presence->path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (presence->fd < 0) { free(presence); return -1; }
    if (flock(presence->fd, LOCK_EX | LOCK_NB) != 0) {
        unlink_owned(presence->fd, presence->path); close(presence->fd); free(presence); return -1;
    }
    *out = presence; return 0;
}
void st_control_presence_release(st_control_presence *presence, int forget)
{
    if (!presence) return;
    if (forget) unlink_owned(presence->fd, presence->path);
    close(presence->fd); free(presence);
}
int st_control_presence_probe(const char *database_path, const char *channel)
{
    /* Historical unattributed rows cannot belong to a current randomized CONTROL. Keep their
     * existing recovery behavior. Missing sidecars for modern channels are UNKNOWN instead:
     * an older C instance may still own that physical channel during a rolling upgrade. */
    if (!physical_channel(channel)) return ST_CONTROL_PRESENCE_DEAD;
    char path[PATH_MAX + 80];
    if (filename(database_path, channel, path, sizeof(path)) != 0) return ST_CONTROL_PRESENCE_UNKNOWN;
    int fd = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return ST_CONTROL_PRESENCE_UNKNOWN;
    struct stat attributes;
    if (fstat(fd, &attributes) != 0 || !S_ISREG(attributes.st_mode)) { close(fd); return ST_CONTROL_PRESENCE_UNKNOWN; }
    int locked = flock(fd, LOCK_EX | LOCK_NB), error = errno;
    close(fd);
    return locked == 0 ? ST_CONTROL_PRESENCE_DEAD
        : (error == EWOULDBLOCK || error == EAGAIN) ? ST_CONTROL_PRESENCE_LIVE : ST_CONTROL_PRESENCE_UNKNOWN;
}
void st_control_presence_forget_dead(const char *database_path, const char *channel)
{
    char path[PATH_MAX + 80];
    if (filename(database_path, channel, path, sizeof(path)) != 0) return;
    int fd = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW); if (fd < 0) return;
    if (flock(fd, LOCK_EX | LOCK_NB) == 0) unlink_owned(fd, path);
    close(fd);
}
