#define _GNU_SOURCE
#include <time.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

/* Linux regression fixture, loaded only by the clock-adjustment NAT tests.
 * REALTIME reads are 3s behind the kernel's timed-wait clock; MONOTONIC is unchanged.
 * This models an inconsistent wall-clock deadline without changing the host clock. */
int clock_gettime(clockid_t clock, struct timespec *out)
{
    int result = (int)syscall(SYS_clock_gettime, clock, out);
    if (result == 0 && clock == CLOCK_REALTIME) out->tv_sec -= 3;
    return result;
}

/* The same wall clock through gettimeofday, which glibc answers without clock_gettime. */
int gettimeofday(struct timeval *restrict out, void *restrict zone)
{
    (void)zone;
    struct timespec now;
    int result = (int)syscall(SYS_clock_gettime, CLOCK_REALTIME, &now);
    if (result == 0) {
        out->tv_sec = now.tv_sec - 3;
        out->tv_usec = now.tv_nsec / 1000L;
    }
    return result;
}
