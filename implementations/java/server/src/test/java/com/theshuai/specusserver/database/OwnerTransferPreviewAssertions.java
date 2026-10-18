package com.theshuai.specusserver.database;

import com.theshuai.specusserver.management.model.ClientOwnerTransferPreview.AffectedClient;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.service.ClientOwnerTransferException;
import com.theshuai.specusserver.management.service.ClientOwnerTransferService;
import com.theshuai.specusserver.management.tenant.TenantContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Preview SQL against the actual ORM-created schema on each real database provider. */
final class OwnerTransferPreviewAssertions {
    private static final String STAMP = "2026-10-14T00:00:00Z";
    private static final ManagementContext ADMIN = new ManagementContext(new TenantContext("tenant-a"), "admin", true);

    static void verify(ConfigurableApplicationContext context) {
        JdbcTemplate jdbc = context.getBean(JdbcTemplate.class);
        ClientOwnerTransferService transfers = context.getBean(ClientOwnerTransferService.class);
        for (long id : new long[]{81001, 81002, 81003}) {
            jdbc.update("INSERT INTO specus_client_account(id,tenant_id,owner_username,client_name,password_hash,enabled,connection_rate_limit_per_minute,created_at,updated_at) VALUES (?,?,?,?,?,?,30,?,?)",
                    id, "tenant-a", id == 81002 ? "carol" : "alice", "preview-" + id, "untouched-password", id != 81002, STAMP, STAMP);
        }
        for (long id : new long[]{81050, 81051}) {
            jdbc.update("INSERT INTO specus_client_credential(id,tenant_id,owner_username,api_key,secret_hash,enabled,max_online_instances,created_at,updated_at) VALUES (?,?,?,?,?,?,10,?,?)",
                    id, "tenant-a", "alice", "preview-key-" + id, "untouched-secret", false, STAMP, STAMP);
        }
        for (long id : new long[]{81701, 81702}) {
            jdbc.update("INSERT INTO specus_client_identity(id,tenant_id,credential_id,client_id,client_name,machine_fingerprint,os_user,first_seen_at,last_seen_at) VALUES (?,?,?,?,?,?,?,?,?)",
                    id, "tenant-a", 81050, id == 81701 ? 81001 : 81002, "fixture",
                    "fingerprint-" + id, "os-user", STAMP, STAMP);
        }
        jdbc.update("INSERT INTO peer_mesh_device(id,tenant_id,client_id,client_name,owner_username,virtual_ip,cidr,enabled,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                81801, "tenant-a", 81001, "preview-81001", "alice", "100.96.0.1", "100.96.0.0/16", true, STAMP, STAMP);
        var credentialBefore = jdbc.queryForMap("SELECT * FROM specus_client_credential WHERE id=81050");
        var clientsBefore = jdbc.queryForList("SELECT * FROM specus_client_account WHERE tenant_id='tenant-a' ORDER BY id");
        var group = transfers.previewCredential(ADMIN, "81050");
        assertThat(group.affectedClients()).extracting(AffectedClient::id).containsExactly(81001L, 81002L);
        assertThat(group.affectedClients().getLast().enabled()).isFalse();
        assertThat(group.affectedClients().getLast().ownerUsername()).isEqualTo("carol");
        assertThat(group.credentialEnabled()).isFalse();
        assertThat(group.accessRetained()).isTrue();
        assertThat(group.canTransfer()).isTrue();
        assertThat(group.revision()).isNotBlank();
        var single = transfers.previewClient(ADMIN, "81001");
        assertThat(single.canTransfer()).isFalse();
        assertThat(single.conflictCode()).isEqualTo("CREDENTIAL_SHARED");
        assertThat(single.revision()).isNull();
        assertThat(transfers.previewCredential(ADMIN, "81051").affectedClients()).isEmpty();
        assertThat(transfers.previewClient(ADMIN, "81003").credentialId()).isNull();
        assertThat(jdbc.queryForMap("SELECT * FROM specus_client_credential WHERE id=81050")).isEqualTo(credentialBefore);
        assertThat(jdbc.queryForList("SELECT * FROM specus_client_account WHERE tenant_id='tenant-a' ORDER BY id")).isEqualTo(clientsBefore);
        jdbc.update("UPDATE specus_client_identity SET last_seen_at=? WHERE id=81701", "2026-10-15T00:00:00Z");
        assertThat(transfers.previewCredential(ADMIN, "81050").revision()).isEqualTo(group.revision());
        jdbc.update("INSERT INTO specus_client_identity(id,tenant_id,credential_id,client_id,client_name,machine_fingerprint,os_user,first_seen_at,last_seen_at) VALUES (?,?,?,?,?,?,?,?,?)",
                81703, "tenant-a", 81050, 81001, "fixture", "fingerprint-81703", "os-user", STAMP, STAMP);
        assertThat(transfers.previewCredential(ADMIN, "81050").affectedClients()).hasSize(2);
        assertThat(transfers.previewCredential(ADMIN, "81050").revision()).isNotEqualTo(group.revision());
        jdbc.update("UPDATE specus_client_identity SET tenant_id='tenant-b' WHERE id=81702");
        assertThatThrownBy(() -> transfers.previewCredential(ADMIN, "81050"))
                .isInstanceOfSatisfying(ClientOwnerTransferException.class, error -> {
                    assertThat(error.status()).isEqualTo(409);
                    assertThat(error.code()).isEqualTo("INCONSISTENT_CREDENTIAL_GROUP");
                });
    }
}
