#define main catalog_reconnect_reference_main
#include "catalog_reconnect_e2e_tests.c"
#undef main
#include <poll.h>
#include <sys/socket.h>

typedef struct {
    test_server a, b;
    int prepared_a, started_a, prepared_b, started_b;
    int control, recipient, replacement, other_recipient, data, public_fd, new_data, new_public;
    runtime_session publisher, peer, other;
    char *token, *other_token;
    char preload[512], barrier[512], database[512], mode[80], old_channel[161], new_channel[161], tenant[64];
    long long first_revision;
    int port;
} source_fixture;

static const char *caps = ",\"sendMessages\":true,\"receiveMessages\":true,"
    "\"clientPeerServiceCapabilities\":{\"version\":2,\"applications\":[\"http\"]}";
static int source_enable(source_fixture *f, const runtime_session *runtime)
{
    st_storage_client account;
    return st_storage_get_client(f->a.db_path, runtime->client_id, &account) == 0
        && st_storage_update_peer_mesh_device_enabled(f->a.db_path, &account, 1, NULL) == 0 ? 0 : -1;
}
static int source_setup(source_fixture *f, const char *library, const char *mode)
{
    memset(f, 0, sizeof(*f));
    f->control = f->recipient = f->replacement = f->other_recipient = f->data = f->public_fd = f->new_data = f->new_public = -1;
    if (server_prepare(&f->a)) return -1;
    f->prepared_a = 1;
    void *asan = dlsym(RTLD_DEFAULT, "__asan_init"); Dl_info sanitizer = {0};
    if (asan && dladdr(asan, &sanitizer) && sanitizer.dli_fname)
        snprintf(f->preload, sizeof(f->preload), "LD_PRELOAD=%s:%s", sanitizer.dli_fname, library);
    else snprintf(f->preload, sizeof(f->preload), "LD_PRELOAD=%s", library);
    snprintf(f->barrier, sizeof(f->barrier), "SPECUS_TEST_CONTROL_BARRIER_DIR=%s", f->a.dir);
    snprintf(f->mode, sizeof(f->mode), "SPECUS_TEST_CATALOG_SOURCE_MODE=%s", mode);
    f->a.extra_env[0] = f->preload; f->a.extra_env[1] = f->barrier;
    f->a.extra_env[2] = "SPECUS_PEER_MESH_ENABLED=true"; f->a.extra_env[3] = "SPECUS_PEER_MESH_STUN_TURN_PORT=0";
    f->a.extra_env[4] = f->mode;
    if (server_start(&f->a)) return -1;
    f->started_a = 1;
    if (create_credential(f->a.db_path, "ck_catalog_source", "catalog-source-secret", 4)) return -1;
    harness_login_environment_extra = caps;
    int rc = http_client_login(&f->a, "ck_catalog_source", "catalog-source-secret", "catalog-source-p", "user", &f->publisher)
        || http_client_login(&f->a, "ck_catalog_source", "catalog-source-secret", "catalog-source-r", "user", &f->peer);
    harness_login_environment_extra = "";
    if (rc || source_enable(f, &f->publisher) || source_enable(f, &f->peer)) return -1;
    st_storage_client account;
    if (st_storage_get_client(f->a.db_path, f->publisher.client_id, &account)) return -1;
    snprintf(f->tenant, sizeof(f->tenant), "%s", account.tenant_id);
    if (st_storage_upsert_peer_mesh_service_sharing(f->a.db_path, account.tenant_id, 1, 1, ADMIN_USERNAME, NULL)) return -1;
    st_storage_peer_mesh_service definition = {0};
    snprintf(definition.tenant_id, sizeof(definition.tenant_id), "%s", account.tenant_id);
    definition.client_id = account.id; snprintf(definition.client_name, sizeof(definition.client_name), "%s", account.client_name);
    snprintf(definition.service_id, sizeof(definition.service_id), "svc-reconnect");
    snprintf(definition.name, sizeof(definition.name), "Catalog Service");
    snprintf(definition.transport, sizeof(definition.transport), "tcp"); snprintf(definition.application, sizeof(definition.application), "http");
    snprintf(definition.target_host, sizeof(definition.target_host), "127.0.0.1"); definition.target_port = 8080;
    snprintf(definition.path, sizeof(definition.path), "/"); definition.published_port = 18080;
    definition.enabled = 1; snprintf(definition.visibility, sizeof(definition.visibility), "OWNER");
    if (st_storage_upsert_peer_mesh_service(f->a.db_path, &definition, NULL)) return -1;
    char reason[512];
    if (channel_login(f->a.control_port, &f->peer, ST_CONNECTION_ROLE_CONTROL, &f->recipient, reason, sizeof(reason)) != 1
        || wait_peer(f->recipient, "peer-config", NULL, 0, NULL)
        || channel_login(f->a.control_port, &f->publisher, ST_CONNECTION_ROLE_CONTROL, &f->control, reason, sizeof(reason)) != 1
        || wait_peer(f->control, "peer-config", NULL, 0, NULL)
        || send_report(f->control, &f->publisher, 1, "old-physical", 1)
        || wait_peer(f->recipient, "service-catalog", &f->publisher, 0, &f->first_revision)) return -1;
    f->token = admin_token(&f->a);
    return f->token && instances(&f->a, f->token, 1, "old-physical") == 0 ? 0 : -1;
}
static int source_cleanup(source_fixture *f, int failed)
{
    harness_login_environment_extra = "";
    if (f->prepared_a) marker(&f->a, "resume");
    close_fd(&f->control); close_fd(&f->recipient); close_fd(&f->replacement); close_fd(&f->other_recipient);
    close_fd(&f->data); close_fd(&f->public_fd); close_fd(&f->new_data); close_fd(&f->new_public);
    if (f->started_a && server_stop(&f->a, 20000)) failed = 1;
    if (f->started_b && server_stop(&f->b, 20000)) failed = 1;
    free(f->token); free(f->other_token);
    if (f->prepared_b) server_cleanup(&f->b, failed);
    if (f->prepared_a) {
        const char *names[] = {"arm", "ready", "resume", "native-write-attempt", "slow-entered", "slow-returned"};
        for (size_t i = 0; i < sizeof(names)/sizeof(names[0]); ++i) { char path[512]; snprintf(path, sizeof(path), "%s/%s", f->a.dir, names[i]); unlink(path); }
        server_cleanup(&f->a, failed);
    }
    return failed;
}
static int source_catalog(const st_message_response *message, const runtime_session *publisher)
{
    long long cid = 0, sid = 0;
    return message->message_type == ST_MESSAGE_TYPE_PEER_CONTROL && message->message
        && strstr(message->message, "\"type\":\"service-catalog\"")
        && st_json_get_i64(message->message, "publisherClientId", &cid) == 0 && cid == publisher->client_id
        && st_json_get_i64(message->message, "publisherSessionId", &sid) == 0 && sid == publisher->session_id
        && strstr(message->message, "\"services\":[]") == NULL;
}
/* The real later business frame is a completion fence for the original worker, not a sleep. */
static int source_fence_named(source_fixture *f, int *nonempty, const char *old_name, const char *new_name, int *old_count)
{
    st_buffer packet = st_protocol_encode_message_response(f->publisher.client_name, f->peer.client_name,
        ST_MESSAGE_TYPE_CLIENT_TO_CLIENT, "catalog-after-native-failure");
    if (!packet.data) return -1;
    packet.data[6] = ST_CMD_MESSAGE_REQUEST;
    if (send_buffer(f->control, &packet)) return -1;
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS; *nonempty = 0;
    int completed = 0, fresh_seen = new_name == NULL;
    if (old_count) *old_count = 0;
    while (monotonic_ms() < deadline) {
        st_frame_header header; uint8_t *body = NULL; st_message_response message = {0};
        int rc = read_frame(f->recipient, (int)(deadline-monotonic_ms()), &header, &body);
        if (rc != 1) { fprintf(stderr, "OBSERVATION catalog fence read rc=%d\n", rc); return -1; }
        int decoded = header.command == ST_CMD_MESSAGE_RESPONSE && st_protocol_decode_message_response(body, header.length, &message) == 0;
        free(body);
        if (decoded && source_catalog(&message, &f->publisher)) {
            ++*nonempty;
            if (old_name && old_count && strstr(message.message,old_name)) ++*old_count;
            if (new_name && strstr(message.message,new_name)) fresh_seen = 1;
        }
        int done = decoded && message.message_type == ST_MESSAGE_TYPE_CLIENT_TO_CLIENT && message.message
            && !strcmp(message.message, "catalog-after-native-failure");
        completed |= done;
        st_message_response_free(&message); if (completed && fresh_seen) return 0;
    }
    return -1;
}
static int source_fence(source_fixture *f, int *nonempty) { return source_fence_named(f,nonempty,NULL,NULL,NULL); }
static int audit_failure(const char *library, const char *mode)
{
    source_fixture f; int failed = 1, nonempty = -1; char count[64];
#define REQUIRE(c, text) do { if (!(c)) { fprintf(stderr, "FAIL real catalog %s: %s\n", mode, text); goto done; } } while (0)
    REQUIRE(source_setup(&f, library, "pre") == 0, "signed HTTP/v2 CONTROL, authoritative service and accepted old catalog");
    REQUIRE(db_scalar(f.a.db_path, "SELECT COUNT(*) FROM peer_mesh_service_audit WHERE tenant_id=?", f.tenant, 0, count, sizeof(count)) == 0
        && !strcmp(count, "1"), "exact initial native audit fixture before injecting failure");
    int expected = 1;
    if (!strcmp(mode, "audit-insert"))
        REQUIRE(sql(&f.a, "CREATE TRIGGER fail_catalog_audit BEFORE INSERT ON peer_mesh_service_audit WHEN NEW.action='service-report' BEGIN SELECT RAISE(ABORT,'audit fault'); END") == 0, "actual native audit INSERT fault");
    else if (!strcmp(mode, "audit-prune")) {
        for (int i = 1; i < 80; ++i) REQUIRE(st_storage_record_peer_mesh_service_audit(f.a.db_path, "fixture", f.tenant,
            f.publisher.client_id, f.publisher.session_id, NULL, "fill") == 0, "fill bounded native audit");
        expected = 80;
        REQUIRE(sql(&f.a, "CREATE TRIGGER fail_catalog_audit BEFORE DELETE ON peer_mesh_service_audit BEGIN SELECT RAISE(ABORT,'retention fault'); END") == 0, "actual native retention DELETE fault");
    } else REQUIRE(sql(&f.a, "CREATE TRIGGER fail_catalog_audit AFTER INSERT ON peer_mesh_service_audit WHEN NEW.action='service-report' BEGIN UPDATE specus_client_session SET token_hash='changed'; END") == 0,
        "actual within-transaction source change");
    REQUIRE(send_report(f.control, &f.publisher, 100, "failed-physical", 0) == 0 && source_fence(&f, &nonempty) == 0,
        "later real client message completes on original CONTROL after rejected report");
    REQUIRE(db_scalar(f.a.db_path, "SELECT COUNT(*) FROM peer_mesh_service_audit WHERE tenant_id=?", f.tenant, 0, count, sizeof(count)) == 0,
        "read actual audit after completed business");
    fprintf(stderr, "OBSERVATION real catalog %s postFailureNonempty=%d nativeAudits=%s\n", mode, nonempty, count);
    REQUIRE(nonempty == 0 && atoi(count) == expected && instances(&f.a, f.token, 1, "old-physical") == 0,
        "failed native commit has no changed REST instance/stats or catalog publication and no partial audit");
    REQUIRE(expect_channel_alive(f.control) == 0 && expect_channel_alive(f.recipient) == 0
        && sql(&f.a, "DROP TRIGGER fail_catalog_audit") == 0, "rolled-back failure retains both physical controls");
    long long revision = 0;
    REQUIRE(send_report(f.control, &f.publisher, 2, "new-physical", 0) == 0
        && wait_peer(f.recipient, "service-catalog", &f.publisher, 0, &revision) == 0
        && revision == f.first_revision + 1 && instances(&f.a, f.token, 1, "new-physical") == 0,
        "retry commits once with the original next wire revision and no failed raw100 high-water");
    failed = 0;
done:
    failed = source_cleanup(&f, failed); printf("%s real catalog %s audit/cache rollback, original CONTROL and retry\n", failed ? "FAIL" : "PASS", mode); return failed;
#undef REQUIRE
}
static int wait_native_closed(source_fixture *f)
{
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS; char value[32];
    do {
        if (db_scalar(f->a.db_path, "SELECT COUNT(*) FROM connection_record WHERE channel_id=? AND disconnected_at IS NOT NULL AND disconnected_at<>''",
            f->old_channel, 0, value, sizeof(value)) == 0 && !strcmp(value, "1")) return 0;
        sleep_ms(1);
    } while (monotonic_ms() < deadline);
    return -1;
}
static int drain_closed_source(source_fixture *f, int *nonempty)
{
    st_buffer heartbeat = st_protocol_encode_empty_packet(ST_CMD_HEARTBEAT_REQUEST);
    if (send_buffer(f->recipient, &heartbeat)) return -1;
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS; *nonempty = 0;
    while (monotonic_ms() < deadline) {
        st_frame_header header; uint8_t *body = NULL; st_message_response message = {0};
        if (read_frame(f->recipient, (int)(deadline-monotonic_ms()), &header, &body) != 1) return -1;
        int done = header.command == ST_CMD_HEARTBEAT_RESPONSE;
        if (header.command == ST_CMD_MESSAGE_RESPONSE && st_protocol_decode_message_response(body, header.length, &message) == 0
            && source_catalog(&message, &f->publisher)) ++*nonempty;
        st_message_response_free(&message); free(body); if (done) return 0;
    }
    return -1;
}
static int takeover(const char *library, int writer_first)
{
    source_fixture f; int failed = 1, nonempty = -1; char reason[512], count[64];
#define REQUIRE(c, text) do { if (!(c)) { fprintf(stderr, "FAIL real catalog %s: %s\n", writer_first ? "writer-first" : "replace-first", text); goto done; } } while (0)
    REQUIRE(source_setup(&f, library, writer_first ? "writer" : "pre") == 0, "original physical publisher and recipient with real accepted report");
    f.port = pick_free_port();
    REQUIRE(f.port > 0 && create_mapping(f.a.db_path, f.publisher.client_id, f.port) == 0
        && channel_login(f.a.control_port, &f.publisher, ST_CONNECTION_ROLE_DATA, &f.data, reason, sizeof(reason)) == 1
        && nat_register(f.data, f.publisher.client_name, f.port, 9) == 0 && open_public_stream(f.data, f.port, &f.public_fd) == 0,
        "original real DATA and public TCP namespace");
    REQUIRE(server_prepare(&f.b) == 0, "prepare independent server"); f.prepared_b = 1;
    snprintf(f.database, sizeof(f.database), "SPECUS_DATABASE_PATH=%s", f.a.db_path);
    f.b.extra_env[0] = f.database; f.b.extra_env[1] = f.preload; f.b.extra_env[2] = f.barrier;
    f.b.extra_env[3] = "SPECUS_PEER_MESH_ENABLED=true"; f.b.extra_env[4] = "SPECUS_PEER_MESH_STUN_TURN_PORT=0";
    f.b.extra_env[5] = "SPECUS_TEST_CATALOG_SOURCE_MODE=observer";
    REQUIRE(server_start(&f.b) == 0, "second process shares live SQLite"); f.started_b = 1;
    harness_login_environment_extra = caps;
    REQUIRE(http_client_login(&f.b, "ck_catalog_source", "catalog-source-secret", "catalog-source-other", "user", &f.other) == 0,
        "signed independent recipient session"); harness_login_environment_extra = "";
    REQUIRE(source_enable(&f, &f.other) == 0 && channel_login(f.b.control_port, &f.other, ST_CONNECTION_ROLE_CONTROL,
        &f.other_recipient, reason, sizeof(reason)) == 1 && wait_peer(f.other_recipient, "peer-config", NULL, 0, NULL) == 0,
        "new server's unrelated physical recipient");
    REQUIRE(db_scalar(f.a.db_path, "SELECT channel_id FROM specus_client_session WHERE id=?", NULL, f.publisher.session_id,
        f.old_channel, sizeof(f.old_channel)) == 0 && marker(&f.a, "arm") == 0
        && send_report(f.control, &f.publisher, 100, "must-not-resurrect", 1) == 0 && wait_marker(&f.a) == 0,
        "actual source report paused at selected real SQLite boundary");
    REQUIRE(expect_channel_alive(f.control) == 0 && expect_channel_alive(f.recipient) == 0,
        "held report/transaction never blocks independent heartbeat readers");
    f.replacement = connect_local(f.b.control_port);
    REQUIRE(f.replacement >= 0 && send_login_request(f.replacement, &f.publisher, ST_CONNECTION_ROLE_CONTROL) == 0,
        "same SID new physical source submitted in independent process");
    if (writer_first) {
        char path[512]; snprintf(path, sizeof(path), "%s/native-write-attempt", f.a.dir);
        long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
        while (access(path, F_OK) && monotonic_ms() < deadline) sleep_ms(1);
        struct pollfd pending = {.fd=f.replacement, .events=POLLIN};
        REQUIRE(access(path, F_OK) == 0 && poll(&pending, 1, 100) == 0,
            "replacement actually enters native writer but cannot ACK before held report commits");
        REQUIRE(marker(&f.a, "resume") == 0, "release original authorized native writer");
    }
    int command, success;
    REQUIRE(read_login_response(f.replacement, IO_TIMEOUT_MS, &command, &success, reason, sizeof(reason)) == 1 && success
        && db_scalar(f.a.db_path, "SELECT channel_id FROM specus_client_session WHERE id=?", NULL, f.publisher.session_id,
            f.new_channel, sizeof(f.new_channel)) == 0 && strcmp(f.old_channel, f.new_channel), "replacement epoch actually commits");
    f.other_token = admin_token(&f.b); REQUIRE(f.other_token != NULL, "second real management identity");
    long long revision = 0;
    REQUIRE(wait_peer(f.replacement, "peer-config", NULL, 0, NULL) == 0
        && send_report(f.replacement, &f.publisher, 1, "new-physical", 0) == 0
        && wait_peer(f.other_recipient, "service-catalog", &f.publisher, 0, &revision) == 0
        && instances(&f.b, f.other_token, 1, "new-physical") == 0, "new authenticated source accepts raw1 and publishes its own clean instance");
    if (!writer_first) REQUIRE(marker(&f.a, "resume") == 0, "resume old source only after winner report committed");
    REQUIRE(wait_native_closed(&f) == 0 && drain_closed_source(&f, &nonempty) == 0,
        "actual old audit closes only after worker/withdrawal completes, then heartbeat orders receiver observation");
    REQUIRE(db_scalar(f.a.db_path, "SELECT COUNT(*) FROM peer_mesh_service_audit WHERE action='service-report' AND client_id=?",
        NULL, f.publisher.client_id, count, sizeof(count)) == 0, "read actual committed source report count");
    fprintf(stderr, "OBSERVATION real catalog %s postCutoverNonempty=%d acceptedNativeReports=%s\n", writer_first ? "writer-first" : "replace-first", nonempty, count);
    REQUIRE((writer_first ? nonempty <= 1 && !strcmp(count, "3") : nonempty == 0 && !strcmp(count, "2")),
        "old source cannot mutate/publish after native takeover; writer-first acceptance is ordered before takeover");
    REQUIRE(expect_channel_closed(f.control, IO_TIMEOUT_MS) == 0 && expect_channel_closed(f.data, IO_TIMEOUT_MS) == 0
        && expect_socket_eof(f.public_fd, IO_TIMEOUT_MS) == 0 && expect_channel_alive(f.replacement) == 0
        && expect_channel_alive(f.other_recipient) == 0 && instances(&f.b, f.other_token, 1, "new-physical") == 0,
        "only original physical family retires, winner/recipient and winner directory survive old cleanup");
    uint32_t stream_id;
    REQUIRE(channel_login(f.b.control_port, &f.publisher, ST_CONNECTION_ROLE_DATA, &f.new_data, reason, sizeof(reason)) == 1
        && nat_register(f.new_data, f.publisher.client_name, f.port, 9) == 0
        && open_public_stream_id(f.new_data, f.port, &f.new_public, &stream_id) == 0, "winner's real DATA binds released namespace");
    const uint8_t payload[] = "catalog winner DATA"; uint8_t received[sizeof(payload)];
    st_buffer packet = st_protocol_encode_nat_message(ST_NAT_DATA, 0, stream_id, 0, NULL, payload, sizeof(payload));
    REQUIRE(send_buffer(f.new_data, &packet) == 0
        && recv_exact(f.new_public, received, sizeof(received), monotonic_ms()+IO_TIMEOUT_MS) == 1
        && !memcmp(payload, received, sizeof(payload)), "winner transfers actual DATA-to-public TCP bytes after old cache/source cleanup");
    failed = 0;
done:
    failed = source_cleanup(&f, failed); printf("%s real catalog cross-process %s source/native writer, heartbeat, original family and winner\n",
        failed ? "FAIL" : "PASS", writer_first ? "writer-first" : "replace-first"); return failed;
#undef REQUIRE
}
static int consistent_read(const char *library)
{
    source_fixture f; int failed=1; long long revision=0;
#define REQUIRE(c, text) do { if (!(c)) { fprintf(stderr,"FAIL real catalog single-read: %s\n",text); goto done; } } while(0)
    REQUIRE(source_setup(&f,library,"publication") == 0,"signed v2 publisher/recipient and accepted native fixture");
    REQUIRE(sql(&f.a,"PRAGMA journal_mode=WAL") == 0 && marker(&f.a,"arm") == 0
        && send_report(f.control,&f.publisher,2,"read-snapshot",0) == 0 && wait_marker(&f.a) == 0,
        "actual definition projection paused inside native publication writer");
    REQUIRE(expect_channel_alive(f.control) == 0 && expect_channel_alive(f.recipient) == 0,
        "independent heartbeats while catalog publication writer is paused");
    sqlite3 *observer=NULL;
    REQUIRE(sqlite3_open(f.a.db_path,&observer)==SQLITE_OK && sqlite3_busy_timeout(observer,0)==SQLITE_OK,
        "independent native writer observer");
    int busy=sqlite3_exec(observer,"BEGIN IMMEDIATE",NULL,NULL,NULL);
    if(busy==SQLITE_OK) (void)sqlite3_exec(observer,"ROLLBACK",NULL,NULL,NULL);
    sqlite3_close(observer);
    REQUIRE(busy==SQLITE_BUSY,"native publication, not another read-before-send, excludes a policy writer");
    char mutation[1024]; snprintf(mutation,sizeof(mutation),
        "BEGIN IMMEDIATE; UPDATE client_account SET owner_username='changed-owner' WHERE rowid=%lld; "
        "UPDATE peer_mesh_device SET owner_username='changed-owner' WHERE client_id=%lld; "
        "UPDATE peer_mesh_shared_service SET name='After Snapshot' WHERE client_id=%lld; COMMIT;",
        f.publisher.client_id,f.publisher.client_id,f.publisher.client_id);
    REQUIRE(marker(&f.a,"resume") == 0,"resume the same reader, not a rebuilt/fake view");
    REQUIRE(sql(&f.a,mutation) == 0,"independent WAL writer commits only after native publication acceptance");
    int observed=0; long long deadline=monotonic_ms()+IO_TIMEOUT_MS;
    while(!observed && monotonic_ms()<deadline) {
        st_frame_header header; uint8_t *body=NULL; st_message_response message={0};
        REQUIRE(read_frame(f.recipient,(int)(deadline-monotonic_ms()),&header,&body) == 1,"physical catalog response");
        int decoded=header.command==ST_CMD_MESSAGE_RESPONSE && st_protocol_decode_message_response(body,header.length,&message)==0;
        free(body);
        if(decoded && source_catalog(&message,&f.publisher)) {
            observed=strstr(message.message,"\"name\":\"Catalog Service\"") != NULL
                && strstr(message.message,"After Snapshot") == NULL
                && st_json_get_i64(message.message,"revision",&revision) == 0 && revision==f.first_revision+1;
            st_message_response_free(&message); REQUIRE(observed,"one coherent pre-mutation parent/policy/definition snapshot, never mixed rows");
        } else st_message_response_free(&message);
    }
    REQUIRE(observed && send_report(f.control,&f.publisher,3,"after-snapshot",0)==0
        && wait_peer(f.recipient,"service-catalog",&f.publisher,1,&revision)==0
        && revision==f.first_revision+2,"next native snapshot sees transferred owner and withdraws lost access");
    REQUIRE(expect_channel_alive(f.control)==0 && expect_channel_alive(f.recipient)==0,"management-only transfer preserves both physical connections");
    failed=0;
done:
    failed=source_cleanup(&f,failed); printf("%s real catalog native publication excludes WAL writer, independent heartbeat and next-view revocation\n",failed?"FAIL":"PASS"); return failed;
#undef REQUIRE
}
static int recipient_replaced(const char *library)
{
    source_fixture f; int failed=1, nonempty=0, old_count=0; char reason[512];
#define REQUIRE(c, text) do { if (!(c)) { fprintf(stderr,"FAIL real catalog recipient binding: %s\n",text); goto done; } } while(0)
    REQUIRE(source_setup(&f,library,"delivery")==0 && marker(&f.a,"arm")==0
        && send_report(f.control,&f.publisher,2,"pending-recipient",0)==0 && wait_marker(&f.a)==0,
        "actual payload READ has committed and closed before original delivery");
    REQUIRE(channel_login(f.a.control_port,&f.peer,ST_CONNECTION_ROLE_CONTROL,&f.replacement,reason,sizeof(reason))==1,
        "same HTTP SID establishes a new physical recipient while publisher waits");
    int old=f.recipient; f.recipient=f.replacement; f.replacement=old;
    REQUIRE(sql(&f.a,"UPDATE peer_mesh_shared_service SET name='Fresh Recipient View'")==0 && marker(&f.a,"resume")==0,
        "definition changes after old payload snapshot but before new login replay");
    REQUIRE(source_fence_named(&f,&nonempty,"\"name\":\"Catalog Service\"","\"name\":\"Fresh Recipient View\"",&old_count)==0,
        "later original publisher business AND fresh recipient replay are physically received");
    fprintf(stderr,"OBSERVATION recipient replacement oldSnapshotOnNew=%d totalNonempty=%d\n",old_count,nonempty);
    REQUIRE(old_count==0,"pending old-recipient payload is never redirected by name onto successor CONTROL");
    REQUIRE(expect_channel_closed(f.replacement,IO_TIMEOUT_MS)==0 && expect_channel_alive(f.recipient)==0
        && expect_channel_alive(f.control)==0,"only old physical recipient retires; source and successor remain usable");
    failed=0;
done:
    failed=source_cleanup(&f,failed);printf("%s real catalog original recipient binding and independent fresh replay\n",failed?"FAIL":"PASS");return failed;
#undef REQUIRE
}
static int publisher_detached(const char *library)
{
    source_fixture f; int failed=1, nonempty=0; char reason[512];
#define REQUIRE(c, text) do { if (!(c)) { fprintf(stderr,"FAIL real catalog publisher binding: %s\n",text); goto done; } } while(0)
    REQUIRE(source_setup(&f,library,"delivery")==0,"original physical publisher/recipient");
    f.port=pick_free_port();
    REQUIRE(f.port>0 && create_mapping(f.a.db_path,f.publisher.client_id,f.port)==0
        && channel_login(f.a.control_port,&f.publisher,ST_CONNECTION_ROLE_DATA,&f.data,reason,sizeof(reason))==1
        && nat_register(f.data,f.publisher.client_name,f.port,9)==0 && open_public_stream(f.data,f.port,&f.public_fd)==0,
        "original publisher DATA/public TCP family established");
    REQUIRE(db_scalar(f.a.db_path,"SELECT channel_id FROM specus_client_session WHERE id=?",NULL,f.publisher.session_id,
        f.old_channel,sizeof(f.old_channel))==0 && marker(&f.a,"arm")==0
        && send_report(f.control,&f.publisher,2,"detached-source",0)==0 && wait_marker(&f.a)==0,
        "accepted report's final native READ is closed before send");
    close_fd(&f.control);
    REQUIRE(expect_channel_closed(f.data,IO_TIMEOUT_MS)==0 && expect_socket_eof(f.public_fd,IO_TIMEOUT_MS)==0
        && expect_channel_alive(f.recipient)==0,"reader has actually detached original source/family while its worker waits");
    REQUIRE(marker(&f.a,"resume")==0 && wait_native_closed(&f)==0 && drain_closed_source(&f,&nonempty)==0,
        "original worker and native audit finish before recipient heartbeat completion fence");
    fprintf(stderr,"OBSERVATION publisher detached lateNonempty=%d\n",nonempty);
    REQUIRE(nonempty==0,"a locally detached original publisher cannot emit its pending nonempty snapshot");
    failed=0;
done:
    failed=source_cleanup(&f,failed);printf("%s real catalog original publisher binding, actual family detach and recipient heartbeat\n",failed?"FAIL":"PASS");return failed;
#undef REQUIRE
}
static int endpoint_capability(const char *library, int publisher)
{
    source_fixture f; int failed=1, nonempty=0; char change[512]; long long revision=0;
#define REQUIRE(c, text) do { if (!(c)) { fprintf(stderr,"FAIL real catalog %s capability: %s\n",publisher?"publisher":"recipient",text); goto done; } } while(0)
    REQUIRE(source_setup(&f,library,"pre")==0,"real original receiver with v2 capability");
    harness_login_environment_extra=caps;
    const runtime_session *subject=publisher?&f.publisher:&f.peer;
    int login=http_client_login(&f.a,"ck_catalog_source","catalog-source-secret",publisher?"catalog-source-p":"catalog-source-r","user",&f.other);
    harness_login_environment_extra="";
    REQUIRE(login==0 && f.other.client_id==subject->client_id && f.other.session_id!=subject->session_id
        && st_storage_mark_client_session_online(f.a.db_path,f.other.session_id,"other-capability-row","127.0.0.1","2026-10-16T00:00:00Z")==0,
        "another signed same-client session advertises v2 but is not the physical receiver");
    snprintf(change,sizeof(change),"UPDATE specus_client_session SET peer_service_discovery_version=0 WHERE id=%lld",subject->session_id);
    REQUIRE(sql(&f.a,change)==0 && send_report(f.control,&f.publisher,publisher?100:2,"revoked-endpoint",0)==0 && source_fence(&f,&nonempty)==0,
        "original receiver capability changes, then actual publisher business completes");
    fprintf(stderr,"OBSERVATION %s original capability unauthorizedNonempty=%d\n",publisher?"publisher":"recipient",nonempty);
    REQUIRE(nonempty==0 && expect_channel_alive(f.control)==0 && expect_channel_alive(f.recipient)==0,
        "another session's v2 capability must not authorize this original receiver or cause physical retirement");
    if(publisher) {
        char count[32];REQUIRE(db_scalar(f.a.db_path,"SELECT COUNT(*) FROM peer_mesh_service_audit WHERE action='service-report' AND tenant_id=?",f.tenant,0,count,sizeof(count))==0
            && !strcmp(count,"1"),"revoked publisher report never commits audit/private cache state despite another session's v2");
    }
    snprintf(change,sizeof(change),"UPDATE specus_client_session SET peer_service_discovery_version=2 WHERE id=%lld; UPDATE specus_client_session SET status='EXPIRED' WHERE id=%lld",subject->session_id,f.other.session_id);
    REQUIRE(sql(&f.a,change)==0 && send_report(f.control,&f.publisher,publisher?2:3,"new-physical",0)==0
        && wait_peer(f.recipient,"service-catalog",&f.publisher,0,&revision)==0 && revision==f.first_revision+(publisher?1:2),
        "same original receiver recovers after its own capability is restored");
    failed=0;
done:
    harness_login_environment_extra="";failed=source_cleanup(&f,failed);
    printf("%s real catalog exact %s session capability, no sibling inheritance and recovery\n",failed?"FAIL":"PASS",publisher?"publisher":"recipient");return failed;
#undef REQUIRE
}
static int acceptance_rollback(const char *library)
{
    source_fixture f;int failed=1,nonempty=0;long long revision=0;char reason[512],count[32];
#define REQUIRE(c,text) do {if(!(c)){fprintf(stderr,"FAIL real publication rollback: %s\n",text);goto done;}}while(0)
    REQUIRE(source_setup(&f,library,"accept-commit-fail")==0 && marker(&f.a,"arm")==0
        && send_report(f.control,&f.publisher,2,"pending-publication",0)==0 && wait_marker(&f.a)==0,
        "actual delivery writer COMMIT fails after private payload staging");
    REQUIRE(source_fence(&f,&nonempty)==0 && nonempty==0,"later ordered business frame fences aborted catalog, not a timer");
    REQUIRE(expect_channel_alive(f.control)==0 && expect_channel_alive(f.recipient)==0,
        "publication SQL failure does not retire either physical endpoint");
    REQUIRE(db_scalar(f.a.db_path,"SELECT COUNT(*) FROM peer_mesh_service_audit WHERE action='service-report' AND tenant_id=?",
            f.tenant,0,count,sizeof(count))==0 && !strcmp(count,"2")
        && instances(&f.a,f.token,1,"pending-publication")==0,"already committed report/cache survives failed delivery only");
    REQUIRE(channel_login(f.a.control_port,&f.peer,ST_CONNECTION_ROLE_CONTROL,&f.other_recipient,reason,sizeof(reason))==1
        && wait_peer(f.other_recipient,"peer-config",NULL,0,NULL)==0
        && wait_peer(f.other_recipient,"service-catalog",&f.publisher,0,&revision)==0 && revision==f.first_revision+1,
        "same accepted report replays after original recipient reconnect, with retained revision");
    REQUIRE(db_scalar(f.a.db_path,"SELECT COUNT(*) FROM peer_mesh_service_audit WHERE action='service-report' AND tenant_id=?",
        f.tenant,0,count,sizeof(count))==0 && !strcmp(count,"2"),"retry never invents another report audit");
    failed=0;
done:
    failed=source_cleanup(&f,failed);printf("%s real catalog publication COMMIT rollback / ordered abort / retained replay\n",failed?"FAIL":"PASS");return failed;
#undef REQUIRE
}
static int send_counter(test_server *server,const char *name)
{
    char path[512];snprintf(path,sizeof(path),"%s/%s",server->dir,name);FILE *file=fopen(path,"r");int value=0;
    if(file) {if(fscanf(file,"%d",&value)!=1)value=0;fclose(file);}return value;
}
static int slow_receiver(const char *library)
{
    source_fixture f;int failed=1;long long revision=0;char reason[512];char *payload=NULL;
#define REQUIRE(c,text) do {if(!(c)){fprintf(stderr,"FAIL real slow receiver: %s\n",text);goto done;}}while(0)
    REQUIRE(source_setup(&f,library,"slow-output")==0,"signed publisher/recipient accepted original report");
    harness_login_environment_extra=caps;
    int login=http_client_login(&f.a,"ck_catalog_source","catalog-source-secret","slow-witness","user",&f.other);
    harness_login_environment_extra="";
    REQUIRE(login==0 && source_enable(&f,&f.other)==0
        && channel_login(f.a.control_port,&f.other,ST_CONNECTION_ROLE_CONTROL,&f.other_recipient,reason,sizeof(reason))==1
        && wait_peer(f.other_recipient,"peer-config",NULL,0,NULL)==0
        && wait_peer(f.other_recipient,"service-catalog",&f.publisher,0,&revision)==0,"independent actual witness CONTROL");
    REQUIRE(db_scalar(f.a.db_path,"SELECT channel_id FROM specus_client_session WHERE id=?",NULL,f.publisher.session_id,
        f.old_channel,sizeof(f.old_channel))==0,"exact original source channel");
    int window=4096;
    REQUIRE(setsockopt(f.recipient,SOL_SOCKET,SO_RCVBUF,&window,sizeof(window))==0 && marker(&f.a,"arm")==0,
        "actual non-reading receiver with small kernel receive window");
    size_t size=512U*1024U;payload=malloc(size+1U);REQUIRE(payload!=NULL,"bounded flood buffer");memset(payload,'x',size);payload[size]='\0';
    for(int i=0;i<16;++i) {
        st_buffer packet=st_protocol_encode_message_response(f.publisher.client_name,f.peer.client_name,ST_MESSAGE_TYPE_CLIENT_TO_CLIENT,payload);
        REQUIRE(packet.data!=NULL,"bounded actual 512KiB business frame");packet.data[6]=ST_CMD_MESSAGE_REQUEST;
        REQUIRE(send_buffer(f.control,&packet)==0,"actual publisher sends 8MiB behind non-reading peer");
    }
    REQUIRE(send_report(f.control,&f.publisher,2,"behind-slow-peer",0)==0
        && wait_peer(f.other_recipient,"service-catalog",&f.publisher,0,&revision)==0 && revision==f.first_revision+1,
        "same publisher business/CID completes report while peer socket is actually backpressured");
    int entered=send_counter(&f.a,"slow-entered"),returned=send_counter(&f.a,"slow-returned");
    fprintf(stderr,"OBSERVATION actual slow socket entered=%d returned=%d\n",entered,returned);
    REQUIRE(entered>returned && expect_channel_alive(f.control)==0 && expect_channel_alive(f.other_recipient)==0,
        "observed real send still blocked; unrelated and publisher heartbeats independent");
    close_fd(&f.control);
    REQUIRE(wait_native_closed(&f)==0,"original source cleanup is not pinned by target output or queued catalog refs");
    REQUIRE(channel_login(f.a.control_port,&f.publisher,ST_CONNECTION_ROLE_CONTROL,&f.replacement,reason,sizeof(reason))==1
        && expect_channel_alive(f.replacement)==0 && expect_channel_alive(f.other_recipient)==0,
        "original SID can reconnect before slow receiver drains");
    REQUIRE(send_counter(&f.a,"slow-entered")>send_counter(&f.a,"slow-returned"),"actual old socket remains blocked across source cleanup/reconnect");
    failed=0;
done:
    free(payload);failed=source_cleanup(&f,failed);printf("%s real kernel-backpressured receiver / source business+heartbeat+cleanup+sameSID reconnect\n",failed?"FAIL":"PASS");return failed;
#undef REQUIRE
}
int main(int argc, char **argv)
{
    if (argc != 3 && argc != 4) return 2;
    signal(SIGPIPE, SIG_IGN); server_binary = argv[1];
    if (argc == 4) {
        if (!strcmp(argv[3], "acceptance-rollback")) return acceptance_rollback(argv[2]);
        if (!strcmp(argv[3], "slow-receiver")) return slow_receiver(argv[2]);
        if (!strcmp(argv[3], "recipient-replaced")) return recipient_replaced(argv[2]);
        if (!strcmp(argv[3], "publisher-detached")) return publisher_detached(argv[2]);
        if (!strcmp(argv[3], "recipient-capability")) return endpoint_capability(argv[2],0);
        if (!strcmp(argv[3], "publisher-capability")) return endpoint_capability(argv[2],1);
        if (!strcmp(argv[3], "read-snapshot")) return consistent_read(argv[2]);
        if (!strcmp(argv[3], "replace-first")) return takeover(argv[2], 0);
        if (!strcmp(argv[3], "writer-first")) return takeover(argv[2], 1);
        if (strcmp(argv[3], "audit-insert") && strcmp(argv[3], "audit-prune") && strcmp(argv[3], "trigger")) return 2;
        return audit_failure(argv[2], argv[3]);
    }
    return audit_failure(argv[2], "audit-insert") + audit_failure(argv[2], "audit-prune") + audit_failure(argv[2], "trigger")
        + takeover(argv[2], 0) + takeover(argv[2], 1) + consistent_read(argv[2])
        + recipient_replaced(argv[2]) + publisher_detached(argv[2]) + endpoint_capability(argv[2],0) + endpoint_capability(argv[2],1)
        + acceptance_rollback(argv[2]) + slow_receiver(argv[2]) ? 1 : 0;
}
