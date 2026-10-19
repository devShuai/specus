#ifndef ST_UNICODE_JAVA21_H
#define ST_UNICODE_JAVA21_H

#include <stddef.h>
#include <stdint.h>

/* Registration's pinned Java 21 reference semantics, not case folding or NFC.
 * Byte lengths include embedded NUL; the registration boundary rejects NUL first.
 * lower_root returns an allocated NUL-terminated buffer; out_len excludes only its
 * final terminator. Invalid UTF-8 => NULL/EINVAL, allocation/size failure => NULL/ENOMEM. */
char *st_unicode_java21_lower_root(const char *text, size_t length, size_t *out_len);
/* 1 non-whitespace, 0 empty/blank, -1 invalid UTF-8. No C-string truncation. */
int st_unicode_java21_has_text(const char *text, size_t length);
/* InternetAddress uses Character.isLetterOrDigit(char), so supplementary scalars
 * are not DNS-domain characters; bracketed literals have their own grammar. */
int st_unicode_java21_domain_char(int32_t point);

#endif
