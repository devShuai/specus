#include "admin_http.h"
#include <stdio.h>
#include <string.h>

int main(void)
{
    char safe[2048];
    static const char reason[] = "a\r\nb\tc\0" "d\xe2\x80\xa8" "e\\f";
    static const char expected[] = "a\\r\\nb\\tc\\u0000d\\u2028e\\\\f";
    if (st_admin_log_safe_reason_n(reason, sizeof(reason)-1U, safe, sizeof(safe)) != strlen(expected)
        || strcmp(safe, expected) != 0) return 1;
    if (st_admin_log_safe_reason_n(NULL, 19U, safe, sizeof(safe)) != 0U || safe[0] != '\0') return 1;
    char long_reason[300];
    memset(long_reason, 'x', sizeof(long_reason));
    if (st_admin_log_safe_reason_n(long_reason, sizeof(long_reason), safe, sizeof(safe))
        != 256U+strlen("...(truncated)")) return 1;
    for (size_t i=0U; i<256U; ++i) if (safe[i] != 'x') return 1;
    if (strcmp(safe+256U, "...(truncated)") != 0) return 1;
    char unicode[257U*4U];
    for (size_t i=0U; i<257U; ++i) memcpy(unicode+i*4U, "\xf0\x9f\x98\x80", 4U);
    if (st_admin_log_safe_reason_n(unicode, sizeof(unicode), safe, sizeof(safe)) != 1024U+strlen("...(truncated)")
        || memcmp(safe, unicode, 1024U) != 0 || strcmp(safe+1024U, "...(truncated)") != 0) return 1;
    const char incomplete[] = {(char)0xf0, (char)0x9f};
    if (st_admin_log_safe_reason_n(incomplete, sizeof(incomplete), safe, sizeof(safe)) != 8U
        || strcmp(safe, "\\xf0\\x9f") != 0) return 1;
    char tiny[8];
    if (st_admin_log_safe_reason("abc\r\ndefgh", tiny, sizeof(tiny)) != 7U
        || strcmp(tiny, "abc\\r\\n") != 0) return 1;
    if (st_admin_log_safe_reason_n(reason, sizeof(reason)-1U, NULL, sizeof(safe)) != 0U
        || st_admin_log_safe_reason_n(reason, sizeof(reason)-1U, safe, 0U) != 0U) return 1;
    puts("HTTP log reason reference: exact Java NUL/controls, null, 256 code points, Unicode, bounded UTF8 and legacy C string passed");
    return 0;
}
