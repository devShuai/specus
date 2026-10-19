#ifndef SPECUS_WEBSOCKET_TICKET_H
#define SPECUS_WEBSOCKET_TICKET_H

#include <stddef.h>
#include "instant.h"

/*45 seconds, inclusive expiry;1024 management tickets combined and1024 public tickets.
 * The server initializes its configured database schema at startup; errors fail closed.
 * No database configuration uses volatile memory.
 * Issue:0 success,-2 quota,-1 error. Consume:0 success,1 refused,-1 error; caller frees JSON. */
int st_websocket_ticket_issue(const char *scope, const char *attributes_json, const char *remote_address,
    char token[64], char expires_at[ST_INSTANT_CAPACITY]);
int st_websocket_ticket_consume(const char *scope, const char *token, const char *remote_address, char **attributes_json);
/* Length-aware JSON string copy: required means present, not nonempty. Embedded NUL refused. */
int st_websocket_ticket_json_string(const char *json, const char *key, char *out, size_t capacity, int required);
int st_websocket_ticket_identity_matches(const char *json, const char *tenant_id, const char *username);
void st_websocket_ticket_revoke_memory_identity(const char *tenant_id, const char *username);
/* Used by existing test-fixture reset APIs; never removes persistent tickets. NULL clears all. */
void st_websocket_ticket_reset_memory_scope(const char *scope);

#endif
