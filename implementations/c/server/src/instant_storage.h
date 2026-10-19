#ifndef SPECUS_INSTANT_STORAGE_H
#define SPECUS_INSTANT_STORAGE_H

#include <sqlite3.h>

#define ST_INSTANT_MIGRATION_BATCH 500U
/* Internal schema identifiers only. Missing tables are skipped. Numeric/text keys keep their
 * SQLite types; invalid legacy text is preserved, and optimistic updates do not overwrite a
 * concurrent replacement. Caller owns any surrounding transaction and handles a failed migration. */
int st_instant_migrate_column(sqlite3 *db, const char *table, const char *key, const char *column,
                              long long *rewritten);

#endif
