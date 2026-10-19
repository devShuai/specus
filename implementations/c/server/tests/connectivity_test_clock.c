#include <time.h>

/* Test-executable-only libc symbol interposition, matching the Java fixture's fixed wall clock.
 * No production clock seam, date conversion or random-byte source is replaced. */
time_t time(time_t *out)
{
    time_t fixed = (time_t)1791273600;
    if (out != NULL) *out = fixed;
    return fixed;
}
