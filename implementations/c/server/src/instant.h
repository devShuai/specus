#ifndef SPECUS_INSTANT_H
#define SPECUS_INSTANT_H

#include <stddef.h>

#define ST_INSTANT_CAPACITY 40U
/* UTC, seven fractional digits (100ns), matching the sortable stored form. */
int st_instant_format(long long epoch_seconds, long nanoseconds, char out[ST_INSTANT_CAPACITY]);
int st_instant_format_millis(long long epoch_millis, char out[ST_INSTANT_CAPACITY]);
int st_instant_now(char out[ST_INSTANT_CAPACITY]);
/* ISO UTC/offset input, or SQLite's legacy UTC yyyy-MM-dd HH:mm:ss. Invalid input is rejected.
 * Bounded to years0000..9999, the existing four-digit C storage date range. */
int st_instant_normalize(const char *input, char out[ST_INSTANT_CAPACITY]);
/* Add whole seconds without losing the stored100ns fraction; reject bounded-date overflow. */
int st_instant_add_seconds(const char *input, long long seconds, char out[ST_INSTANT_CAPACITY]);
/* Stored fixed precision is private: views use Instant.toString's 0/3/6/9 fraction groups.
 * Invalid legacy text is copied unchanged if it fits. */
int st_instant_public(const char *input, char *out, size_t capacity);

#endif
