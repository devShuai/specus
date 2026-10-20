#define _POSIX_C_SOURCE 200809L
#include "websocket_ticket.h"
#include "crypto.h"
#include "json.h"
#include "storage.h"
#include <openssl/rand.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Unconsumed management tickets of both scopes together. */
#define ST_WS_TICKET_LIMIT 1024U
/*
 * Java caps no ticket category. Public tickets are anonymous, so C bounds them per source address
 * (one source cannot lock everybody else out) and, for memory, in total.
 */
static unsigned int public_source_limit = 1024U;
static unsigned int public_total_limit = 16384U;
typedef struct memory_ticket {
    char hash[65], remote_hash[65], scope[32], expires[ST_INSTANT_CAPACITY];
    char *json;
    struct memory_ticket *next;
} memory_ticket;
static pthread_mutex_t ticket_lock = PTHREAD_MUTEX_INITIALIZER;
static memory_ticket *memory_tickets;

static int scope_valid(const char *scope)
{
    return scope != NULL && (strcmp(scope, "connections") == 0 || strcmp(scope, "client-messages") == 0 || strcmp(scope, "public-transfer") == 0);
}
static const char *database_path(void)
{
    const char *path = getenv("SPECUS_DATABASE_PATH");
    return path != NULL && *path != '\0' ? path : NULL;
}
static void hash_text(const char *text, size_t bytes, char out[65])
{
    uint8_t digest[ST_SHA256_LEN];
    st_sha256((const uint8_t *)text, bytes, digest); st_hex_encode(digest, sizeof(digest), out);
}
static void remote_hash(const char *remote, char out[65])
{
    memset(out, 0, 65U);
    if (remote == NULL) return;
    size_t len = strlen(remote);
    while (len > 0U && (unsigned char)*remote <= 32U) { ++remote; --len; }
    while (len > 0U && (unsigned char)remote[len - 1U] <= 32U) --len;
    if (len > 0U) hash_text(remote, len, out);
}
static int random_token(char out[64])
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    uint8_t random[32];
    if (RAND_bytes(random, sizeof(random)) != 1) return -1;
    size_t at = 0U;
    for (size_t i = 0U; i < sizeof(random); i += 3U) {
        size_t left = sizeof(random) - i;
        uint32_t bits = (uint32_t)random[i] << 16U;
        if (left > 1U) bits |= (uint32_t)random[i + 1U] << 8U;
        if (left > 2U) bits |= random[i + 2U];
        out[at++] = alphabet[(bits >> 18U) & 63U]; out[at++] = alphabet[(bits >> 12U) & 63U];
        if (left > 1U) out[at++] = alphabet[(bits >> 6U) & 63U];
        if (left > 2U) out[at++] = alphabet[bits & 63U];
    }
    out[at] = '\0'; return 0;
}
static void free_ticket(memory_ticket *ticket)
{
    free(ticket->json); free(ticket);
}
static void prune_locked(const char *now)
{
    memory_ticket **cursor = &memory_tickets;
    while (*cursor != NULL) {
        memory_ticket *ticket = *cursor;
        if (strcmp(ticket->expires, now) < 0) { *cursor = ticket->next; free_ticket(ticket); }
        else cursor = &ticket->next;
    }
}
int st_websocket_ticket_json_string(const char *json, const char *key, char *out, size_t capacity, int required)
{
    if (json == NULL || key == NULL || out == NULL || capacity == 0U) return -1;
    out[0] = '\0'; char *raw = st_json_get_top_level_raw(json, key);
    if (raw == NULL) return required ? -1 : 0;
    size_t len = 0U; char *value = st_json_decode_string(raw, &len); free(raw);
    int result = -1;
    if (value != NULL && len < capacity && strlen(value) == len) { memcpy(out, value, len + 1U); result = 0; }
    free(value); return result;
}
static int json_string_equals(const char *json, const char *key, const char *expected)
{
    char *raw = st_json_get_top_level_raw(json, key);
    size_t len = 0U; char *value = raw == NULL ? NULL : st_json_decode_string(raw, &len);
    int equal = value != NULL && expected != NULL && len == strlen(expected) && memcmp(value, expected, len) == 0;
    free(raw); free(value); return equal;
}
int st_websocket_ticket_identity_matches(const char *json, const char *tenant_id, const char *username)
{
    return st_json_object_keys_unique(json) && json_string_equals(json, "tenantId", tenant_id) && json_string_equals(json, "wsUser", username);
}
int st_websocket_ticket_issue(const char *scope, const char *attributes_json, const char *remote_address,
    char token[64], char expires_at[ST_INSTANT_CAPACITY])
{
    if (token == NULL || expires_at == NULL || !scope_valid(scope) || !st_json_object_keys_unique(attributes_json)) return -1;
    char now[ST_INSTANT_CAPACITY], expires[ST_INSTANT_CAPACITY], hash[65], address[65];
    if (st_instant_now(now) != 0 || st_instant_add_seconds(now, 45, expires) != 0
        || st_instant_public(expires, expires_at, ST_INSTANT_CAPACITY) != 0 || random_token(token) != 0) return -1;
    hash_text(token, strlen(token), hash); remote_hash(remote_address, address);
    const char *path = database_path();
    int is_public = strcmp(scope, "public-transfer") == 0;
    pthread_mutex_lock(&ticket_lock);
    unsigned int total_limit = is_public ? public_total_limit : ST_WS_TICKET_LIMIT;
    unsigned int source_limit = is_public ? public_source_limit : 0U;
    pthread_mutex_unlock(&ticket_lock);
    if (path != NULL) {
        return st_storage_issue_websocket_ticket_limited(path, hash, scope, attributes_json,
            *address == '\0' ? NULL : address, now, expires, total_limit, source_limit);
    }
    memory_ticket *ticket = calloc(1U, sizeof(*ticket));
    if (ticket == NULL) return -1;
    ticket->json = strdup(attributes_json);
    if (ticket->json == NULL) { free(ticket); return -1; }
    memcpy(ticket->hash, hash, sizeof(hash)); memcpy(ticket->remote_hash, address, sizeof(address));
    strcpy(ticket->scope, scope); strcpy(ticket->expires, expires);
    pthread_mutex_lock(&ticket_lock); prune_locked(now);
    unsigned int count = 0U, same_source = 0U;
    int collision = 0;
    for (memory_ticket *existing = memory_tickets; existing != NULL; existing = existing->next) {
        int same_category = (strcmp(existing->scope, "public-transfer") == 0) == is_public;
        count += same_category;
        same_source += same_category && strcmp(existing->remote_hash, address) == 0;
        collision |= st_constant_time_eq((const uint8_t *)hash, (const uint8_t *)existing->hash, 64U);
    }
    int result = collision ? -1
        : count >= total_limit || (source_limit > 0U && same_source >= source_limit) ? -2 : 0;
    if (result == 0) { ticket->next = memory_tickets; memory_tickets = ticket; }
    pthread_mutex_unlock(&ticket_lock);
    if (result != 0) free_ticket(ticket);
    return result;
}
int st_websocket_ticket_consume(const char *scope, const char *token, const char *remote_address, char **attributes_json)
{
    if (attributes_json == NULL) return -1;
    *attributes_json = NULL;
    if (!scope_valid(scope)) return -1;
    if (token == NULL || strlen(token) > 256U) return 1;
    size_t len = strlen(token);
    while (len > 0U && (unsigned char)*token <= 32U) { ++token; --len; }
    while (len > 0U && (unsigned char)token[len - 1U] <= 32U) --len;
    if (len == 0U) return 1;
    char now[ST_INSTANT_CAPACITY], hash[65], address[65];
    if (st_instant_now(now) != 0) return -1;
    hash_text(token, len, hash); remote_hash(remote_address, address);
    const char *path = database_path();
    if (path != NULL) {
        return st_storage_consume_websocket_ticket(path, hash, scope, *address == '\0' ? NULL : address, now, attributes_json);
    }
    pthread_mutex_lock(&ticket_lock); prune_locked(now);
    memory_ticket **cursor = &memory_tickets;
    int result = 1;
    while (*cursor != NULL) {
        memory_ticket *ticket = *cursor;
        if (!st_constant_time_eq((const uint8_t *)hash, (const uint8_t *)ticket->hash, 64U)) { cursor = &ticket->next; continue; }
        if (strcmp(scope, ticket->scope) == 0 && (*ticket->remote_hash == '\0'
            || st_constant_time_eq((const uint8_t *)address, (const uint8_t *)ticket->remote_hash, 64U))) {
            *cursor = ticket->next; *attributes_json = ticket->json; ticket->json = NULL;
            free_ticket(ticket); result = 0;
        }
        break;
    }
    pthread_mutex_unlock(&ticket_lock); return result;
}
void st_websocket_ticket_revoke_memory_identity(const char *tenant_id, const char *username)
{
    pthread_mutex_lock(&ticket_lock);
    memory_ticket **cursor = &memory_tickets;
    while (*cursor != NULL) {
        memory_ticket *ticket = *cursor;
        if (strcmp(ticket->scope, "public-transfer") != 0 && st_websocket_ticket_identity_matches(ticket->json, tenant_id, username)) {
            *cursor = ticket->next; free_ticket(ticket);
        } else cursor = &ticket->next;
    }
    pthread_mutex_unlock(&ticket_lock);
}
void st_websocket_ticket_set_public_limits_for_tests(unsigned int per_source, unsigned int total)
{
    pthread_mutex_lock(&ticket_lock);
    public_source_limit = per_source;
    public_total_limit = total;
    pthread_mutex_unlock(&ticket_lock);
}
void st_websocket_ticket_reset_memory_scope(const char *scope)
{
    pthread_mutex_lock(&ticket_lock);
    memory_ticket **cursor = &memory_tickets;
    while (*cursor != NULL) {
        memory_ticket *ticket = *cursor;
        if (scope == NULL || strcmp(ticket->scope, scope) == 0) { *cursor = ticket->next; free_ticket(ticket); }
        else cursor = &ticket->next;
    }
    pthread_mutex_unlock(&ticket_lock);
}
