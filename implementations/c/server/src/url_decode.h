#ifndef SPECUS_URL_DECODE_H
#define SPECUS_URL_DECODE_H

#include <stddef.h>

/* Form-style decoding; malformed escapes remain literal. Caller owns the result.
 * decoded_len counts all bytes, including any decoded zero bytes. */
char *st_url_decode(const char *value, size_t len, size_t *decoded_len);
/* As above, but refuses output that cannot be represented by a complete C string. */
char *st_url_decode_string(const char *value, size_t len);

#endif
