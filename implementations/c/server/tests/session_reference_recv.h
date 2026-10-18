#ifndef ST_SESSION_REFERENCE_RECV_H
#define ST_SESSION_REFERENCE_RECV_H
#define _POSIX_C_SOURCE 200809L
#include <sys/socket.h>
/* Declare libc first: renaming its declaration before fortify headers would inline a call to
 * __recv_alias instead of reaching the fixture. This header is forced only on the test server. */
ssize_t st_fixture_recv(int fd, void *buffer, size_t length, int flags);
#define recv st_fixture_recv
#endif
