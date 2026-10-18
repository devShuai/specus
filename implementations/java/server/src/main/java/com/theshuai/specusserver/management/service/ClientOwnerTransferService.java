package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.management.model.ClientOwnerTransferPreview;
import com.theshuai.specusserver.management.security.ManagementContext;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.sql.DataSource;
import java.util.ArrayList;
import java.util.Map;

import static com.theshuai.specusserver.management.service.ClientOwnerTransferPlan.*;

/** Read-only previews. No transfer writer is exposed until all mutation paths are coordinated. */
@Service
public class ClientOwnerTransferService {
    private final NamedParameterJdbcTemplate jdbc;

    public ClientOwnerTransferService(DataSource dataSource) {
        this.jdbc = new NamedParameterJdbcTemplate(dataSource);
    }

    @Transactional(readOnly = true)
    public ClientOwnerTransferPreview previewClient(ManagementContext context, String id) {
        return preview(context, PathScope.SINGLE, parseId(context, id));
    }

    @Transactional(readOnly = true)
    public ClientOwnerTransferPreview previewCredential(ManagementContext context, String id) {
        return preview(context, PathScope.CREDENTIAL_GROUP, parseId(context, id));
    }

    private ClientOwnerTransferPreview preview(ManagementContext context, PathScope scope, long id) {
        return ClientOwnerTransferPlan.preview(context, scope, id, load(context, scope, id));
    }

    static long parseId(ManagementContext context, String text) {
        // Role is checked before parsing, so an invalid path cannot change non-admin error priority.
        authorizeAndValidateId(context, 1);
        if (text == null || text.length() > 19 || !text.matches("[0-9]+")) {
            throw new ClientOwnerTransferException(400, "INVALID_TRANSFER_REQUEST");
        }
        long id;
        try { id = Long.parseLong(text); }
        catch (NumberFormatException invalid) {
            throw new ClientOwnerTransferException(400, "INVALID_TRANSFER_REQUEST");
        }
        authorizeAndValidateId(context, id);
        return id;
    }

    /**
     * One statement gives one database snapshot even with PostgreSQL READ COMMITTED.
     * Only the path resource is tenant-filtered initially: filtering identity edges before
     * validation could silently drop a corrupt/foreign member and approve an incomplete group.
     * The semi-joins have no per-device SQL parameters or paging limit.
     */
    Snapshot load(ManagementContext context, PathScope scope, long id) {
        ArrayList<ClientRow> clients = new ArrayList<>();
        ArrayList<CredentialRow> credentials = new ArrayList<>();
        ArrayList<IdentityRow> identities = new ArrayList<>();
        ArrayList<PeerRow> peers = new ArrayList<>();
        jdbc.query(SNAPSHOT_SQL, Map.of("tenant", context.tenant().tenantId(), "id", id, "scope", scope.wireName),
                (org.springframework.jdbc.core.RowCallbackHandler) row -> {
                    long rowId = row.getLong("row_id");
                    String tenant = row.getString("tenant_id");
                    switch (row.getString("kind")) {
                        case "client" -> clients.add(new ClientRow(rowId, tenant, row.getString("client_name"),
                                row.getString("owner_username"), row.getBoolean("enabled")));
                        case "credential" -> credentials.add(new CredentialRow(rowId, tenant,
                                row.getString("owner_username"), row.getBoolean("enabled")));
                        case "identity" -> identities.add(new IdentityRow(rowId, tenant,
                                row.getLong("credential_id"), row.getLong("client_id")));
                        case "peer" -> peers.add(new PeerRow(rowId, tenant, row.getLong("client_id"),
                                row.getString("client_name"), row.getString("owner_username"), row.getBoolean("enabled")));
                        default -> throw new IllegalStateException("unknown ownership snapshot row type");
                    }
                });
        return new Snapshot(clients, credentials, identities, peers);
    }

    static final String SNAPSHOT_SQL = """
            WITH path_client AS (
                SELECT id FROM specus_client_account
                WHERE id = :id AND tenant_id = :tenant AND :scope = 'single'
            ), selected_credentials AS (
                SELECT id FROM specus_client_credential
                WHERE id = :id AND tenant_id = :tenant AND :scope = 'credential-group'
                UNION
                SELECT i.credential_id FROM specus_client_identity i
                WHERE i.client_id IN (SELECT id FROM path_client)
            ), affected_clients AS (
                SELECT id FROM path_client
                UNION
                SELECT i.client_id FROM specus_client_identity i
                WHERE i.credential_id IN (SELECT id FROM selected_credentials)
            )
            SELECT 'client' AS kind, c.id AS row_id, c.tenant_id, c.client_name,
                   c.owner_username, c.enabled,
                   CAST(NULL AS DECIMAL(19,0)) AS credential_id, CAST(NULL AS DECIMAL(19,0)) AS client_id
            FROM specus_client_account c WHERE c.id IN (SELECT id FROM affected_clients)
            UNION ALL
            SELECT 'credential', c.id, c.tenant_id, NULL, c.owner_username, c.enabled, NULL, NULL
            FROM specus_client_credential c WHERE c.id IN (SELECT id FROM selected_credentials)
            UNION ALL
            SELECT 'identity', i.id, i.tenant_id, NULL, NULL, NULL, i.credential_id, i.client_id
            FROM specus_client_identity i
            WHERE i.credential_id IN (SELECT id FROM selected_credentials)
               OR i.client_id IN (SELECT id FROM affected_clients)
            UNION ALL
            SELECT 'peer', p.id, p.tenant_id, p.client_name, p.owner_username, p.enabled, NULL, p.client_id
            FROM peer_mesh_device p
            WHERE p.tenant_id = :tenant AND p.client_id IN (SELECT id FROM affected_clients)
            """;
}
