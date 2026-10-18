/* Real private registry/reference lifecycle, without production test hooks. */
#define main specus_source_watch_server_main
#include "../src/main.c"
#undef main
#include <sqlite3.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL source watch line %d: %s\n", __LINE__, #c); return 1; } } while (0)
static void initialize(specus_session *session)
{
    memset(session, 0, sizeof(*session)); session->control_fd = -1;
    session->references = 1; session->active = 1;
    atomic_init(&session->control_cancelled, 0); atomic_init(&session->nat_retired, 0);
    pthread_mutex_init(&session->map_lock, NULL); pthread_mutex_init(&session->direct_lock, NULL);
    pthread_cond_init(&session->reference_cond, NULL);
}
static void destroy(specus_session *session)
{
    pthread_mutex_destroy(&session->map_lock); pthread_mutex_destroy(&session->direct_lock);
    pthread_cond_destroy(&session->reference_cond);
}
static int retry_cadence(void)
{
    unsigned int retry_ms = 50U;
    static const unsigned int expected[] = {50U, 100U, 200U, 400U, 800U, 1000U, 1000U};
    CHECK(control_source_watch_wait_ms(0, &retry_ms) == 1000U && retry_ms == 50U);
    for (size_t i = 0; i < sizeof(expected) / sizeof(expected[0]); ++i)
        CHECK(control_source_watch_wait_ms(-1, &retry_ms) == expected[i]);
    CHECK(control_source_watch_wait_ms(0, &retry_ms) == 1000U && retry_ms == 50U);
    CHECK(control_source_watch_wait_ms(-1, &retry_ms) == 50U);
    puts("PASS transient read retry is prompt, exponentially bounded at 1s, and reset by a successful native round");
    return 0;
}
static int fair_queue(void)
{
    enum { count = ST_STORAGE_CONTROL_SOURCE_BATCH + 3U };
    specus_session *sessions = calloc(count + 2U, sizeof(*sessions)); CHECK(sessions);
    for (size_t i = 0; i < count + 2U; ++i) {
        initialize(&sessions[i]);
        sessions[i].config.client_session_db_backed = i != count;
        sessions[i].is_data_connection = i == count + 1U;
        active_session_add_locked(&sessions[i]);
    }
    CHECK(source_watch_count == count && source_watch_head == &sessions[0] && source_watch_tail == &sessions[count - 1]);
    specus_session *selected[ST_STORAGE_CONTROL_SOURCE_BATCH];
    CHECK(control_source_watch_take(selected) == ST_STORAGE_CONTROL_SOURCE_BATCH);
    for (size_t i = 0; i < ST_STORAGE_CONTROL_SOURCE_BATCH; ++i) {
        CHECK(selected[i] == &sessions[i] && selected[i]->references == 2);
        session_reference_release(selected[i]);
    }
    CHECK(source_watch_head == &sessions[ST_STORAGE_CONTROL_SOURCE_BATCH]);
    /* Removing a scanned element and the next waiter must not break the intrusive queue. */
    active_session_remove_locked(&sessions[0]);
    active_session_remove_locked(&sessions[ST_STORAGE_CONTROL_SOURCE_BATCH]);
    CHECK(source_watch_count == count - 2U);
    CHECK(control_source_watch_take(selected) == ST_STORAGE_CONTROL_SOURCE_BATCH);
    CHECK(selected[0] == &sessions[ST_STORAGE_CONTROL_SOURCE_BATCH + 1U]
        && selected[1] == &sessions[ST_STORAGE_CONTROL_SOURCE_BATCH + 2U]
        && selected[2] == &sessions[1]);
    /* Removal does not free a selected object: the scan's reference survives until release. */
    active_session_remove_locked(selected[0]);
    CHECK(selected[0]->references == 2 && !selected[0]->source_watch_queued);
    for (size_t i = 0; i < ST_STORAGE_CONTROL_SOURCE_BATCH; ++i) {
        for (size_t j = 0; j < i; ++j) CHECK(selected[i] != selected[j]);
        session_reference_release(selected[i]);
    }
    /* Re-admission appends, rather than letting new arrivals overtake unscanned old sources. */
    active_session_add_locked(&sessions[0]);
    CHECK(source_watch_head == &sessions[ST_STORAGE_CONTROL_SOURCE_BATCH - 1U] && source_watch_tail == &sessions[0]);
    for (size_t i = 0; i < count + 2U; ++i) {
        active_session_remove_locked(&sessions[i]); active_session_remove_locked(&sessions[i]);
        CHECK(sessions[i].references == 1 && !sessions[i].source_watch_queued); destroy(&sessions[i]);
    }
    free(sessions);
    CHECK(!source_watch_count && !source_watch_head && !source_watch_tail && !active_sessions);
    CHECK(control_source_watch_take(selected) == 0);
    puts("PASS bounded fair source queue, >64 entries, exact ownership, DATA/trusted exclusions, concurrent removal references, re-admission and reclamation");
    return 0;
}
static int execute(const char *path, const char *sql)
{
    sqlite3 *db = NULL; int rc = sqlite3_open(path, &db);
    if (rc == SQLITE_OK) rc = sqlite3_exec(db, sql, NULL, NULL, NULL);
    sqlite3_close(db); return rc == SQLITE_OK ? 0 : -1;
}
static int native_tick(void)
{
    char dir[] = "/tmp/specus-watch-unit-XXXXXX", path[320]; CHECK(mkdtemp(dir));
    snprintf(path, sizeof(path), "%s/specus.db", dir); CHECK(st_storage_init(path, 0) == 0);
    st_storage_client client; st_storage_client_credential credential; st_storage_client_session native = {0};
    CHECK(st_storage_upsert_client(path, 0, "watch", "watch-source", "alice", 1, 60, &client) == 0);
    CHECK(st_storage_insert_client_credential(path, "watch", "alice", "watch-key", "watch-secret", 1, 10, &credential) == 0);
    native.client_id = client.id; native.identity_id = client.id; native.credential_id = credential.id;
    snprintf(native.tenant_id, sizeof(native.tenant_id), "watch");
    snprintf(native.client_name, sizeof(native.client_name), "watch-source");
    memset(native.token_hash, 'a', 64); native.token_hash[64] = '\0';
    snprintf(native.status, sizeof(native.status), "HTTP_AUTHENTICATED");
    snprintf(native.machine_fingerprint, sizeof(native.machine_fingerprint), "watch-machine");
    snprintf(native.expires_at, sizeof(native.expires_at), "2999-01-01T00:00:00Z");
    CHECK(st_storage_create_client_session(path, &native, &native) == 0);
    CHECK(st_storage_mark_client_session_online(path, native.id, "physical-watch", "127.0.0.1:9", "2026-10-16T00:00:00Z") == 0);
    specus_session *session = calloc(1, sizeof(*session)); CHECK(session); initialize(session);
    session->config.client_session_db_backed = 1;
    st_storage_control_source *guard = &session->control_source_guard;
    guard->client_id = client.id; guard->session_id = native.id;
    snprintf(guard->tenant_id, sizeof(guard->tenant_id), "watch");
    snprintf(guard->client_name, sizeof(guard->client_name), "watch-source");
    snprintf(guard->channel_id, sizeof(guard->channel_id), "physical-watch");
    snprintf(guard->token_hash, sizeof(guard->token_hash), "%s", native.token_hash);
    int sockets[2]; CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0); session->control_fd = sockets[0];
    active_session_add_locked(session);
    st_storage_control_source guards[ST_STORAGE_CONTROL_SOURCE_BATCH]; int results[ST_STORAGE_CONTROL_SOURCE_BATCH];
    for (size_t i = 0; i < ST_STORAGE_CONTROL_SOURCE_BATCH; ++i) guards[i] = *guard;
    guards[1].channel_id[0] = 'X'; guards[2].token_hash[0] = 'X';
    CHECK(st_storage_control_sources_validate(path, guards, ST_STORAGE_CONTROL_SOURCE_BATCH, results) == 0);
    for (size_t i = 0; i < ST_STORAGE_CONTROL_SOURCE_BATCH; ++i) CHECK(results[i] == (i == 1 || i == 2 ? ST_STORAGE_CONTROL_SOURCE_RETIRED : 0));
    CHECK(st_storage_control_sources_validate(NULL, NULL, 0, NULL) == 0);
    CHECK(st_storage_control_sources_validate(path, guards, ST_STORAGE_CONTROL_SOURCE_BATCH + 1, results) == -1);
    CHECK(control_source_watch_tick(path) == 0); CHECK(control_source_active(session) && session->references == 1);
    CHECK(execute(path, "UPDATE client_account SET enabled=0") == 0);
    CHECK(control_source_watch_tick(path) == 0); CHECK(control_source_active(session) && session->references == 1);
    CHECK(execute(path, "UPDATE client_account SET enabled=1; UPDATE specus_client_credential SET enabled=0") == 0);
    CHECK(control_source_watch_tick(path) == 0); CHECK(control_source_active(session) && session->references == 1);
    CHECK(execute(path, "UPDATE specus_client_credential SET enabled=1") == 0);
    sqlite3 *writer = NULL; CHECK(sqlite3_open(path, &writer) == SQLITE_OK);
    CHECK(sqlite3_exec(writer, "BEGIN EXCLUSIVE", NULL, NULL, NULL) == SQLITE_OK);
    long long started = control_monotonic_ms();
    CHECK(st_storage_control_sources_validate(path, guards, ST_STORAGE_CONTROL_SOURCE_BATCH, results) == -1);
    CHECK(control_monotonic_ms() - started < 1000);
    for (size_t i = 0; i < ST_STORAGE_CONTROL_SOURCE_BATCH; ++i) CHECK(results[i] == -1);
    CHECK(control_source_watch_tick(path) == -1); CHECK(control_source_active(session) && session->references == 1);
    CHECK(sqlite3_exec(writer, "ROLLBACK", NULL, NULL, NULL) == SQLITE_OK); sqlite3_close(writer);
    CHECK(st_storage_mark_client_session_online(path, native.id, "replacement-watch", "127.0.0.1:10", "2026-10-16T00:00:01Z") == 0);
    control_source_watch_tick(path);
    CHECK(atomic_load(&session->control_cancelled) && !session->bound && !source_watch_count
        && session->references == 1 && !strcmp(session->displaced_reason, "AUTH_SOURCE_RETIRED"));
    char byte; CHECK(recv(sockets[1], &byte, 1, MSG_DONTWAIT) == 0);
    CHECK(st_storage_mark_client_session_online(path, native.id, "physical-watch", "127.0.0.1:9", "2026-10-16T00:00:02Z") == 0);
    control_source_watch_tick(path); CHECK(!session->bound && atomic_load(&session->control_cancelled));
    for (int i = 0; i < 20; ++i) {
        CHECK(control_source_watch_start(path) == 0 && control_source_watch_start(path) == 0);
        control_source_watch_stop(); control_source_watch_stop(); CHECK(!control_source_watch.started);
    }
    close(sockets[0]); close(sockets[1]); destroy(session); free(session);
    unlink(path); rmdir(dir);
    puts("PASS native bounded batch, disabled policy and SQL busy never retire, original physical source retirement/ABA/ref release, monotonic watcher start/stop");
    return 0;
}
int main(void) { return retry_cadence() || fair_queue() || native_tick(); }
