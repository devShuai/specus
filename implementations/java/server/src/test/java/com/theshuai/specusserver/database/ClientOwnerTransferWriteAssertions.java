package com.theshuai.specusserver.database;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.theshuai.common.clientauth.ClientAuthLoginRequest;
import com.theshuai.common.clientauth.ClientAuthSigner;
import com.theshuai.common.clientauth.ClientEnvironmentInfo;
import com.theshuai.common.protocol.request.LoginRequestPacket;
import com.theshuai.common.session.Session;
import com.theshuai.specusserver.attribute.ServerAttributes;
import com.theshuai.specusserver.management.service.ClientAuthService;
import com.theshuai.specusserver.management.service.PeerMeshService;
import com.theshuai.specusserver.session.SessionUtil;
import io.netty.channel.embedded.EmbeddedChannel;
import com.theshuai.specusserver.config.AuthProperties;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.tenant.TenantContext;
import com.theshuai.specusserver.management.service.ClientOwnerTransferException;
import com.theshuai.specusserver.management.service.ClientOwnerTransferService;
import com.theshuai.specusserver.management.service.ClientOwnerTransferWriter;
import com.theshuai.specusserver.security.PasswordService;
import org.junit.jupiter.api.function.Executable;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.server.ResponseStatusException;
import org.aopalliance.intercept.MethodInterceptor;
import org.springframework.aop.framework.Advised;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import javax.sql.DataSource;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.sql.SQLException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import static org.junit.jupiter.api.Assertions.*;

/** Actual database-only core, deliberately not API/runtime acceptance. Same cases on each provider. */
public final class ClientOwnerTransferWriteAssertions {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final ManagementContext ADMIN = new ManagementContext(TenantContext.defaultTenant(), "owner-writer-admin", true, "owner-writer-admin-key");
    enum Case { LEGACY, EXCLUSIVE, SHARED_GROUP, EMPTY_GROUP, NOOP, SELF_TARGET, BUILTIN, BUILTIN_DISABLED, BUILTIN_OTHER_TENANT,
        SHARED_MISSING_FIELDS, BAD_SCOPE_SHARED, BAD_TYPE_SHARED, BAD_REVISION, DELETED_PATH,
        BROKEN_MEMBER, REMOVED_MEMBER, RENAMED, DISABLED_RESOURCE, FOREIGN_EDGE, MULTIPLE_CREDENTIALS,
        TARGET_DISABLED, TARGET_MISSING, TARGET_FOREIGN, FOREIGN_RESOURCE, CASE_FOREIGN_RESOURCE, ACTOR_DISABLED,
        ACTOR_DEMOTED, MALFORMED_MISSING_PATH, STALE_REVISION_BEFORE_BAD_TARGET }

    public static void verify(ConfigurableApplicationContext context, DataSource independent) throws Exception {
        JdbcTemplate jdbc = context.getBean(JdbcTemplate.class);
        var service = context.getBean(ClientOwnerTransferWriter.class);
        var previews = context.getBean(ClientOwnerTransferService.class);
        var auth = context.getBean(AuthProperties.class);
        String originalUsername = auth.getUsername(), originalPassword = auth.getPassword(), originalTenant = auth.getTenantId();
        boolean originalEnabled = auth.isPasswordLoginEnabled();
        String now = Instant.now().toString();
        user(jdbc, ADMIN.accountKey(), ADMIN.username(), "ADMIN", now);
        ArrayList<Executable> cases = new ArrayList<>();
        for (Case selected : Case.values()) cases.add(() -> {
            auth.setUsername("owner-writer-built-in"); auth.setPassword("proof-only-config-password");
            auth.setTenantId("default"); auth.setPasswordLoginEnabled(true);
            jdbc.update("update specus_management_user set enabled=true,role='ADMIN' where username=?", ADMIN.accountKey());
            long base = 2_600_000L + selected.ordinal() * 10, credential = base, client = base + 1, device = base + 3;
            String target = "WriterTarget" + selected.ordinal();
            user(jdbc, "owner-writer-target-" + selected.ordinal(), target, "USER", now);
            credential(jdbc, credential, now);
            client(jdbc, client, "old-client-owner", now);
            identity(jdbc, base + 4, credential, client, now);
            jdbc.update("insert into peer_mesh_device(id,tenant_id,owner_username,client_id,client_name,virtual_ip,cidr,enabled,public_key,created_at,updated_at) values (?,'default','old-device-owner',?,?,?,'100.101.0.0/16',false,'retained-public-key',?,?)",
                    device, client, "writer-client-" + client, "100.101." + (80 + selected.ordinal()) + ".21", now, now);
            boolean group = selected == Case.SHARED_GROUP || selected == Case.EMPTY_GROUP || selected == Case.REMOVED_MEMBER;
            boolean shared = group && selected != Case.EMPTY_GROUP || selected == Case.SHARED_MISSING_FIELDS
                    || selected == Case.BAD_SCOPE_SHARED || selected == Case.BAD_TYPE_SHARED;
            if (shared) { client(jdbc, base + 2, "different-old-owner", now); identity(jdbc, base + 5, credential, base + 2, now); }
            if (selected == Case.LEGACY) {
                jdbc.update("delete from specus_client_identity where id=?", base + 4);
                jdbc.update("delete from specus_client_credential where id=?", credential);
            }
            if (selected == Case.EMPTY_GROUP) {
                jdbc.update("delete from specus_client_identity where id=?", base + 4);
                jdbc.update("delete from peer_mesh_device where id=?", device);
                jdbc.update("delete from specus_client_account where id=?", client);
            }
            if (selected == Case.NOOP) {
                jdbc.update("update specus_client_account set owner_username=? where id=?", target, client);
                jdbc.update("update specus_client_credential set owner_username=? where id=?", target, credential);
                jdbc.update("update peer_mesh_device set owner_username=? where id=?", target, device);
            }
            String path = Long.toString(group ? credential : client);
            var preview = group ? previews.previewCredential(ADMIN, path) : previews.previewClient(ADMIN, path);
            ObjectNode request = JSON.createObjectNode().put("scope", group ? "credential-group" : "single")
                    .put("targetUsername", "  " + target.toUpperCase(Locale.ROOT) + "  ")
                    .put("expectedRevision", preview.revision() == null ? "unused" : preview.revision());
            int expected = 200; String code = null;
            switch (selected) {
                case SELF_TARGET -> { target = ADMIN.username(); request.put("targetUsername", target); }
                case BUILTIN -> { target = auth.getUsername(); request.put("targetUsername", target.toUpperCase(Locale.ROOT)); }
                case BUILTIN_DISABLED -> { request.put("targetUsername", auth.getUsername()); auth.setPasswordLoginEnabled(false); expected = 400; code = "INVALID_TARGET_OWNER"; }
                case BUILTIN_OTHER_TENANT -> { request.put("targetUsername", auth.getUsername()); auth.setTenantId("foreign"); expected = 400; code = "INVALID_TARGET_OWNER"; }
                case SHARED_MISSING_FIELDS -> { request.remove(List.of("targetUsername", "expectedRevision")); expected = 409; code = "CREDENTIAL_SHARED"; }
                case BAD_SCOPE_SHARED -> { request.put("scope", "credential-group"); expected = 400; code = "INVALID_TRANSFER_REQUEST"; }
                case BAD_TYPE_SHARED -> { request.put("targetUsername", false); expected = 400; code = "INVALID_TRANSFER_REQUEST"; }
                case BAD_REVISION -> { request.put("expectedRevision", "stale"); expected = 409; code = "TRANSFER_PREVIEW_CHANGED"; }
                case DELETED_PATH -> { jdbc.update("delete from specus_client_account where id=?", client); expected = 404; code = "RESOURCE_NOT_FOUND"; }
                case BROKEN_MEMBER -> { jdbc.update("delete from specus_client_credential where id=?", credential); expected = 409; code = "INCONSISTENT_CREDENTIAL_GROUP"; }
                case REMOVED_MEMBER -> { jdbc.update("delete from specus_client_identity where id=?", base + 5); jdbc.update("delete from specus_client_account where id=?", base + 2); expected = 409; code = "TRANSFER_PREVIEW_CHANGED"; }
                case RENAMED -> { jdbc.update("update specus_client_account set client_name='renamed-after-preview' where id=?", client); expected = 409; code = "TRANSFER_PREVIEW_CHANGED"; }
                case DISABLED_RESOURCE -> { jdbc.update("update specus_client_account set enabled=true where id=?", client); expected = 409; code = "TRANSFER_PREVIEW_CHANGED"; }
                case FOREIGN_EDGE -> { jdbc.update("update specus_client_identity set tenant_id='foreign' where id=?", base + 4); expected = 409; code = "INCONSISTENT_CREDENTIAL_GROUP"; }
                case MULTIPLE_CREDENTIALS -> { credential(jdbc, base + 8, now); identity(jdbc, base + 9, base + 8, client, now); expected = 409; code = "INCONSISTENT_CREDENTIAL_GROUP"; }
                case TARGET_DISABLED -> { jdbc.update("update specus_management_user set enabled=false where username=?", "owner-writer-target-" + selected.ordinal()); expected = 400; code = "INVALID_TARGET_OWNER"; }
                case TARGET_MISSING -> { request.put("targetUsername", "absent-target"); expected = 400; code = "INVALID_TARGET_OWNER"; }
                case TARGET_FOREIGN -> { jdbc.update("update specus_management_user set tenant_id='foreign' where username=?", "owner-writer-target-" + selected.ordinal()); expected = 400; code = "INVALID_TARGET_OWNER"; }
                case FOREIGN_RESOURCE, CASE_FOREIGN_RESOURCE -> { jdbc.update("update specus_client_account set tenant_id=? where id=?", selected == Case.FOREIGN_RESOURCE ? "foreign" : "DEFAULT", client); expected = 404; code = "RESOURCE_NOT_FOUND"; }
                case ACTOR_DISABLED -> { jdbc.update("update specus_management_user set enabled=false where username=?", ADMIN.accountKey()); expected = 403; }
                case ACTOR_DEMOTED -> { jdbc.update("update specus_management_user set role='USER' where username=?", ADMIN.accountKey()); expected = 403; code = "FORBIDDEN"; }
                case MALFORMED_MISSING_PATH -> { path = "800000000"; expected = 400; code = "INVALID_TRANSFER_REQUEST"; }
                case STALE_REVISION_BEFORE_BAD_TARGET -> { request.put("expectedRevision", "stale").put("targetUsername", "absent-target"); expected = 409; code = "TRANSFER_PREVIEW_CHANGED"; }
                default -> {}
            }
            JsonNode body = selected == Case.MALFORMED_MISSING_PATH ? JSON.createArrayNode() : request;
            final String currentPath = path;
            String before = ownership(jdbc, base);
            if (expected != 200) {
                RuntimeException failure = assertThrows(RuntimeException.class, () -> {
                    if (group) service.transferCredential(ADMIN, currentPath, body); else service.transferClient(ADMIN, currentPath, body);
                }, selected.toString());
                if (failure instanceof ClientOwnerTransferException transfer) { assertEquals(expected, transfer.status(), selected.toString()); assertEquals(code, transfer.code()); }
                else { var denied = assertInstanceOf(ResponseStatusException.class, failure); assertEquals(expected, denied.getStatusCode().value()); }
                assertEquals(before, ownership(jdbc, base), "failure must not write any ownership/timestamp: " + selected);
            } else {
                var outcome = group ? service.transferCredential(ADMIN, path, body) : service.transferClient(ADMIN, path, body);
                assertEquals(target, outcome.response().targetUsername()); assertTrue(outcome.response().accessRetained());
                assertEquals(selected != Case.NOOP, outcome.response().changed());
                assertEquals(selected == Case.EMPTY_GROUP ? List.of() : shared ? List.of(client, base + 2) : List.of(client), outcome.response().affectedClientIds());
                for (long affected : outcome.response().affectedClientIds()) {
                    assertEquals(target, jdbc.queryForObject("select owner_username from specus_client_account where id=?", String.class, affected));
                    assertFalse(jdbc.queryForObject("select enabled from specus_client_account where id=?", Boolean.class, affected));
                    assertEquals(17, jdbc.queryForObject("select connection_rate_limit_per_minute from specus_client_account where id=?", Integer.class, affected));
                }
                if (selected != Case.EMPTY_GROUP) {
                    assertEquals(target, jdbc.queryForObject("select owner_username from peer_mesh_device where id=?", String.class, device));
                    assertFalse(jdbc.queryForObject("select enabled from peer_mesh_device where id=?", Boolean.class, device));
                    assertEquals("retained-public-key", jdbc.queryForObject("select public_key from peer_mesh_device where id=?", String.class, device));
                }
                if (selected != Case.LEGACY) {
                    assertEquals(target, jdbc.queryForObject("select owner_username from specus_client_credential where id=?", String.class, credential));
                    assertFalse(jdbc.queryForObject("select enabled from specus_client_credential where id=?", Boolean.class, credential));
                    assertEquals(PasswordService.hashToken("retained-secret"), jdbc.queryForObject("select secret_hash from specus_client_credential where id=?", String.class, credential));
                }
                if (selected == Case.NOOP) { assertNull(outcome.auditId()); assertEquals(before, ownership(jdbc, base)); }
                else {
                    String audit = jdbc.queryForObject("select detail_json from client_owner_transfer_audit where id=?", String.class, outcome.auditId());
                    JsonNode parsed = JSON.readTree(audit);
                    assertEquals(outcome.response().affectedClientIds().size(), parsed.path("affectedClientIds").size());
                    assertFalse(audit.contains("secret_hash")); assertFalse(audit.contains("retained-secret"));
                    assertFalse(audit.contains("retained-public-key"));
                }
                if (selected == Case.NOOP) assertFalse(service.transferClient(ADMIN, path, body).response().changed());
                else {
                    ClientOwnerTransferException stale = assertThrows(ClientOwnerTransferException.class, () -> {
                        if (group) service.transferCredential(ADMIN, currentPath, body); else service.transferClient(ADMIN, currentPath, body);
                    });
                    assertEquals("TRANSFER_PREVIEW_CHANGED", stale.code());
                }
            }
            assertEquals(expected == 200 && selected != Case.NOOP ? 1 : 0,
                    jdbc.queryForObject("select count(*) from client_owner_transfer_audit where tenant_id='default' and path_id=?", Integer.class, Long.parseLong(path)));
        });
        try {
            assertAll("actual atomic ownership writer cases (not POST acceptance)", cases);
            verifyRollback(context, independent);
            verifyLargeAudit(context);
            verifyCurrentSnapshotsAndLocks(context, independent);
            verifyRetainedAccess(context);
        }
        finally { auth.setUsername(originalUsername); auth.setPassword(originalPassword); auth.setTenantId(originalTenant); auth.setPasswordLoginEnabled(originalEnabled); }
    }

    private static void verifyRollback(ConfigurableApplicationContext context, DataSource independent) throws Exception {
        JdbcTemplate jdbc = context.getBean(JdbcTemplate.class);
        var service = context.getBean(ClientOwnerTransferWriter.class);
        var previews = context.getBean(ClientOwnerTransferService.class);
        String product;
        try (var connection = independent.getConnection()) { product = connection.getMetaData().getDatabaseProductName(); }
        boolean sqlite = product.toLowerCase(Locale.ROOT).contains("sqlite"), postgres = product.contains("PostgreSQL");
        String now = Instant.now().toString(), target = "owner-writer-fault-target";
        user(jdbc, "owner-writer-fault-target-key", target, "USER", now);
        ArrayList<Executable> cases = new ArrayList<>();
        for (int stage = 0; stage < 3; stage++) {
            int selected = stage;
            cases.add(() -> {
                long base = 2_700_000L + selected * 10;
                credential(jdbc, base, now); client(jdbc, base + 1, "old-client-owner", now);
                identity(jdbc, base + 4, base, base + 1, now);
                jdbc.update("insert into peer_mesh_device(id,tenant_id,owner_username,client_id,client_name,virtual_ip,cidr,enabled,created_at,updated_at) values (?,'default','old-device-owner',?,?,?,'100.101.0.0/16',false,?,?)",
                        base + 3, base + 1, "writer-client-" + (base + 1), "100.101.150." + (21 + selected), now, now);
                String path = Long.toString(base + 1);
                ObjectNode request = JSON.createObjectNode().put("scope", "single").put("targetUsername", target)
                        .put("expectedRevision", previews.previewClient(ADMIN, path).revision());
                String before = ownership(jdbc, base);
                String table = selected == 0 ? "client_owner_transfer_audit" : "peer_mesh_device";
                String operation = selected == 0 ? "insert" : "update";
                String marker = selected == 0 ? "forced-owner-audit" : selected == 1 ? "forced-owner-device" : "ownership write postcondition failed";
                String trigger = "owner_transfer_fault_" + selected;
                if (sqlite) jdbc.execute("create trigger " + trigger + " before " + operation + " on " + table
                        + " begin select raise(" + (selected == 2 ? "ignore" : "abort,'" + marker + "'") + "); end");
                else if (postgres) {
                    jdbc.execute("create function " + trigger + "_fn() returns trigger language plpgsql as $$ begin "
                            + (selected == 2 ? "return null;" : "raise exception '" + marker + "';") + " end $$");
                    jdbc.execute("create trigger " + trigger + " before " + operation + " on " + table
                            + " for each row execute function " + trigger + "_fn()");
                } else jdbc.execute("create trigger " + trigger + " before " + operation + " on " + table + " for each row "
                        + (selected == 2 ? "set new.owner_username=old.owner_username" : "signal sqlstate '45000' set message_text='" + marker + "'"));
                try {
                    RuntimeException failure = assertThrows(RuntimeException.class, () -> service.transferClient(ADMIN, path, request));
                    StringBuilder messages = new StringBuilder();
                    for (Throwable cause = failure; cause != null; cause = cause.getCause()) messages.append(cause.getMessage());
                    assertTrue(messages.toString().contains(marker), "must hit the actual injected final write, not an earlier denial: " + messages);
                    assertEquals(before, ownership(jdbc, base), "all prior ownership/timestamp writes must roll back");
                    assertEquals(0, jdbc.queryForObject("select count(*) from client_owner_transfer_audit where path_id=?", Integer.class, base + 1));
                } finally {
                    jdbc.execute("drop trigger " + trigger + (postgres ? " on " + table : ""));
                    if (postgres) jdbc.execute("drop function " + trigger + "_fn()");
                }
                var success = service.transferClient(ADMIN, path, request);
                assertTrue(success.response().changed(), "same request succeeds after removing only the fault");
                assertEquals(target, jdbc.queryForObject("select owner_username from specus_client_account where id=?", String.class, base + 1));
                assertEquals(1, jdbc.queryForObject("select count(*) from client_owner_transfer_audit where path_id=?", Integer.class, base + 1));
            });
        }
        assertAll("actual last write/audit failure rollback and silent skipped-write protection", cases);
    }

    private static void verifyLargeAudit(ConfigurableApplicationContext context) throws Exception {
        JdbcTemplate jdbc = context.getBean(JdbcTemplate.class);
        var service = context.getBean(ClientOwnerTransferWriter.class);
        var previews = context.getBean(ClientOwnerTransferService.class);
        String now = Instant.now().toString(), target = "owner-writer-large-target";
        user(jdbc, "owner-writer-large-target-key", target, "USER", now);
        long credential = 2_800_000;
        credential(jdbc, credential, now);
        for (int i = 0; i < 400; i++) {
            client(jdbc, 2_810_000 + i, "old-client-owner-" + "x".repeat(60), now);
            identity(jdbc, 2_820_000 + i, credential, 2_810_000 + i, now);
        }
        String path = Long.toString(credential);
        var preview = previews.previewCredential(ADMIN, path);
        assertEquals(400, preview.affectedClientCount());
        ObjectNode request = JSON.createObjectNode().put("scope", "credential-group").put("targetUsername", target)
                .put("expectedRevision", preview.revision());
        var outcome = service.transferCredential(ADMIN, path, request);
        String audit = jdbc.queryForObject("select detail_json from client_owner_transfer_audit where id=?", String.class, outcome.auditId());
        assertTrue(audit.length() > 65_535, "exercise actual MySQL LONGTEXT, not an accidental 64 KiB TEXT limit");
        var detail = JSON.readTree(audit);
        assertEquals(400, detail.path("clients").size()); assertEquals(400, detail.path("affectedClientIds").size());
        assertEquals(2_810_399L, detail.path("affectedClientIds").get(399).asLong());
        assertEquals(400, jdbc.queryForObject("select count(*) from specus_client_account where id>=2810000 and id<2810400 and owner_username=?", Integer.class, target));
        assertEquals(400, jdbc.queryForObject("select count(*) from specus_client_identity where credential_id=?", Integer.class, credential));
    }

    private static void verifyCurrentSnapshotsAndLocks(ConfigurableApplicationContext context, DataSource independent) throws Exception {
        String product;
        try (var connection = independent.getConnection()) { product = connection.getMetaData().getDatabaseProductName(); }
        // SQLite has one database writer; cross-connection committed changes cannot occur after
        // an earlier read inside that writer. Its actual pool1 atomic/rollback matrix ran above.
        if (product.toLowerCase(Locale.ROOT).contains("sqlite")) return;
        boolean mysql = !product.contains("PostgreSQL");
        JdbcTemplate jdbc = context.getBean(JdbcTemplate.class), other = new JdbcTemplate(independent);
        var service = context.getBean(ClientOwnerTransferWriter.class);
        var previews = context.getBean(ClientOwnerTransferService.class);
        String now = Instant.now().toString(), target = "owner-writer-lock-target";
        String targetKey = "owner-writer-lock-target-key";
        user(jdbc, targetKey, target, "USER", now);
        long credential = 2_900_000, client = credential + 1;
        credential(jdbc, credential, now); client(jdbc, client, "old-client-owner", now);
        identity(jdbc, credential + 4, credential, client, now);
        jdbc.update("insert into peer_mesh_device(id,tenant_id,owner_username,client_id,client_name,virtual_ip,cidr,enabled,created_at,updated_at) values (?,'default','old-device-owner',?,?, '100.101.151.21','100.101.0.0/16',false,?,?)",
                credential + 3, client, "writer-client-" + client, now, now);
        String path = Long.toString(client);
        ObjectNode request = JSON.createObjectNode().put("scope", "single").put("targetUsername", target)
                .put("expectedRevision", previews.previewClient(ADMIN, path).revision());
        CountDownLatch locked = new CountDownLatch(1), resume = new CountDownLatch(1);
        AtomicBoolean observed = new AtomicBoolean();
        Advised proxy = assertInstanceOf(Advised.class, context.getBean("clientOwnerTransferRows"));
        MethodInterceptor afterLocks = invocation -> {
            Object result = invocation.proceed();
            if (invocation.getMethod().getName().equals("lock") && ((Number) invocation.getArguments()[2]).longValue() == client
                    && observed.compareAndSet(false, true)) {
                locked.countDown(); assertTrue(resume.await(15, TimeUnit.SECONDS));
            }
            return result;
        };
        proxy.addAdvice(0, afterLocks);
        credential(jdbc, credential + 10, now); client(jdbc, credential + 11, "unrelated", now);
        try (var executor = Executors.newSingleThreadExecutor()) {
            var transfer = executor.submit(() -> service.transferClient(ADMIN, path, request));
            try {
                assertTrue(locked.await(15, TimeUnit.SECONDS), "observe actual complete current row locks, not a stub");
                try (var connection = independent.getConnection(); var sql = connection.createStatement()) {
                    sql.execute(mysql ? "set innodb_lock_wait_timeout=1" : "set lock_timeout='200ms'");
                    for (String mutation : List.of(
                            "update specus_management_user set enabled=false where username='" + ADMIN.accountKey() + "'",
                            "update specus_management_user set enabled=false where username='" + targetKey + "'",
                            "update specus_client_credential set enabled=true where id=" + credential,
                            "update specus_client_account set enabled=true where id=" + client,
                            "update peer_mesh_device set enabled=true where id=" + (credential + 3))) {
                        SQLException blocked = assertThrows(SQLException.class, () -> sql.executeUpdate(mutation));
                        if (mysql) assertEquals(1205, blocked.getErrorCode()); else assertEquals("55P03", blocked.getSQLState());
                    }
                    assertEquals(1, sql.executeUpdate("update specus_client_credential set max_online_instances=4 where id=" + (credential + 10)));
                    assertEquals(1, sql.executeUpdate("update specus_client_account set connection_rate_limit_per_minute=18 where id=" + (credential + 11)));
                }
            } finally { resume.countDown(); }
            assertTrue(transfer.get(15, TimeUnit.SECONDS).response().changed());
            assertTrue(observed.get());
        } finally { resume.countDown(); proxy.removeAdvice(afterLocks); }
        assertEquals(1, other.update("update specus_management_user set enabled=false where username=?", targetKey));

        // Prime a real earlier MySQL RR snapshot, then independently commit a rename. The
        // writer must compare CURRENT rows with the earlier revision, not transfer stale data.
        user(jdbc, "owner-writer-snapshot-target-key", "owner-writer-snapshot-target", "USER", now);
        long snapshotCredential = 2_900_100, snapshotClient = snapshotCredential + 1;
        credential(jdbc, snapshotCredential, now); client(jdbc, snapshotClient, "old-client-owner", now);
        identity(jdbc, snapshotCredential + 4, snapshotCredential, snapshotClient, now);
        ObjectNode stale = JSON.createObjectNode().put("scope", "single").put("targetUsername", "owner-writer-snapshot-target")
                .put("expectedRevision", previews.previewClient(ADMIN, Long.toString(snapshotClient)).revision());
        TransactionTemplate transaction = new TransactionTemplate(context.getBean(PlatformTransactionManager.class));
        ClientOwnerTransferException failure = assertThrows(ClientOwnerTransferException.class, () -> transaction.execute(status -> {
            assertEquals("writer-client-" + snapshotClient, jdbc.queryForObject("select client_name from specus_client_account where id=?", String.class, snapshotClient));
            assertEquals(1, other.update("update specus_client_account set client_name='independently-renamed' where id=?", snapshotClient));
            return service.transferClient(ADMIN, Long.toString(snapshotClient), stale);
        }));
        assertEquals("TRANSFER_PREVIEW_CHANGED", failure.code());
        assertEquals("independently-renamed", jdbc.queryForObject("select client_name from specus_client_account where id=?", String.class, snapshotClient));
        assertEquals("old-client-owner", jdbc.queryForObject("select owner_username from specus_client_account where id=?", String.class, snapshotClient));
        assertEquals(0, jdbc.queryForObject("select count(*) from client_owner_transfer_audit where path_id=?", Integer.class, snapshotClient));
    }

    private static void verifyRetainedAccess(ConfigurableApplicationContext context) {
        JdbcTemplate jdbc = context.getBean(JdbcTemplate.class);
        var service = context.getBean(ClientOwnerTransferWriter.class);
        var previews = context.getBean(ClientOwnerTransferService.class);
        var auth = context.getBean(ClientAuthService.class);
        String now = Instant.now().toString(), target = "owner-writer-access-target";
        user(jdbc, "owner-writer-access-target-key", target, "USER", now);
        long credential = 2_950_000;
        credential(jdbc, credential, now);
        jdbc.update("update specus_client_credential set enabled=true where id=?", credential);
        ClientEnvironmentInfo environment = new ClientEnvironmentInfo();
        environment.setMachineFingerprint("owner-writer-retained-machine"); environment.setHostname("retained-owner-writer");
        environment.setOsUser("retained-user"); environment.setPeerPublicKey("retained-device-public-key");
        var login = signedLogin(auth, credential, environment);
        var device = context.getBean(PeerMeshService.class).ensureDevice(
                context.getBean(com.theshuai.specusserver.management.repository.ClientAccountRepository.class)
                        .findById(login.getClientId()).orElseThrow(), environment);
        EmbeddedChannel channel = new EmbeddedChannel();
        LoginRequestPacket control = new LoginRequestPacket(); control.setAccessToken(login.getAccessToken());
        var accepted = auth.authenticateNetty(control, channel.id().asLongText(), "loopback", false);
        assertTrue(accepted.success());
        channel.attr(ServerAttributes.CLIENT_SESSION_ID).set(accepted.clientSessionId());
        SessionUtil.bindControlSession(new Session(control.getClientName()), channel);
        String path = Long.toString(credential);
        ObjectNode request = JSON.createObjectNode().put("scope", "credential-group").put("targetUsername", target)
                .put("expectedRevision", previews.previewCredential(ADMIN, path).revision());
        try {
            assertTrue(service.transferCredential(ADMIN, path, request).response().changed());
            assertTrue(channel.isActive()); assertSame(channel, SessionUtil.getChannel(control.getClientName()));
            LoginRequestPacket data = new LoginRequestPacket(); data.setAccessToken(login.getAccessToken());
            var admitted = auth.authenticateNetty(data, "retained-data-channel", "loopback", true);
            assertTrue(admitted.success()); assertEquals(target, admitted.account().getOwnerUsername());
            assertTrue(SessionUtil.hasMatchingControl(data.getClientName(), admitted.clientSessionId()));
            var current = previews.previewCredential(ADMIN, path);
            var repeated = signedLogin(auth, credential, environment);
            assertEquals(login.getClientId(), repeated.getClientId()); assertEquals(login.getClientName(), repeated.getClientName());
            assertEquals(device.getVirtualIp(), jdbc.queryForObject("select virtual_ip from peer_mesh_device where id=?", String.class, device.getId()));
            assertEquals("retained-device-public-key", jdbc.queryForObject("select public_key from peer_mesh_device where id=?", String.class, device.getId()));
            request.put("expectedRevision", current.revision());
            assertFalse(service.transferCredential(ADMIN, path, request).response().changed(), "identity/session heartbeat must not invalidate preview");
            assertEquals(1, jdbc.queryForObject("select count(*) from client_owner_transfer_audit where path_id=?", Integer.class, credential));
        } finally {
            auth.markNettyDisconnected(accepted.clientSessionId(), channel.id().asLongText());
            SessionUtil.unBindSession(channel); channel.finishAndReleaseAll();
        }
        LoginRequestPacket reconnect = new LoginRequestPacket(); reconnect.setAccessToken(login.getAccessToken());
        var reconnected = auth.authenticateNetty(reconnect, "retained-reconnect", "loopback", false);
        assertTrue(reconnected.success()); assertEquals(target, reconnected.account().getOwnerUsername());
        jdbc.update("update specus_client_session set expires_at=? where id=?", Instant.now().minusSeconds(60).toString(), accepted.clientSessionId());
        assertFalse(auth.authenticateNetty(reconnect, "expired-reconnect", "loopback", false).success(), "retained access does not bypass expiry");
    }

    private static com.theshuai.common.clientauth.ClientAuthLoginResponse signedLogin(ClientAuthService auth, long credential, ClientEnvironmentInfo environment) {
        String apiKey = "owner-writer-key-" + credential;
        ClientAuthLoginRequest request = new ClientAuthLoginRequest();
        request.setApiKey(apiKey); request.setTimestamp(Long.toString(System.currentTimeMillis()));
        request.setNonce(UUID.randomUUID().toString()); request.setEnvironment(environment);
        request.setSignature(ClientAuthSigner.signApiKey(apiKey, request.getTimestamp(), request.getNonce(), environment, "retained-secret"));
        return auth.login(request, "localhost");
    }

    private static String ownership(JdbcTemplate jdbc, long base) {
        return jdbc.queryForList("select id,owner_username,updated_at from specus_client_account where id>=? and id<? order by id", base, base + 10).toString()
                + jdbc.queryForList("select id,owner_username,updated_at from specus_client_credential where id>=? and id<? order by id", base, base + 10)
                + jdbc.queryForList("select id,owner_username,updated_at from peer_mesh_device where id>=? and id<? order by id", base, base + 10);
    }
    private static void user(JdbcTemplate jdbc, String key, String login, String role, String now) {
        jdbc.update("insert into specus_management_user(username,tenant_id,login_name,login_name_normalized,password_hash,role,enabled,created_at,updated_at) values (?,'default',?,?,?,?,true,?,?)",
                key, login, login.toLowerCase(Locale.ROOT), PasswordService.hashToken("fixture-only-password"), role, now, now);
    }
    private static void credential(JdbcTemplate jdbc, long id, String now) {
        jdbc.update("insert into specus_client_credential(id,tenant_id,owner_username,api_key,secret_hash,enabled,max_online_instances,created_at,updated_at) values (?,'default','old-credential-owner',?,?,false,3,?,?)",
                id, "owner-writer-key-" + id, PasswordService.hashToken("retained-secret"), now, now);
    }
    private static void client(JdbcTemplate jdbc, long id, String owner, String now) {
        jdbc.update("insert into specus_client_account(id,tenant_id,owner_username,client_name,password_hash,enabled,connection_rate_limit_per_minute,created_at,updated_at) values (?,'default',?,?,?,false,17,?,?)",
                id, owner, "writer-client-" + id, PasswordService.hashToken("retained-client-secret"), now, now);
    }
    private static void identity(JdbcTemplate jdbc, long id, long credential, long client, String now) {
        jdbc.update("insert into specus_client_identity(id,tenant_id,credential_id,client_id,client_name,machine_fingerprint,os_user,first_seen_at,last_seen_at) values (?,'default',?,?,?,?,'fixture-user',?,?)",
                id, credential, client, "writer-client-" + client, "writer-machine-" + id, now, now);
    }
}
