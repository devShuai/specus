package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.ClientCredentialRepository;
import com.theshuai.specusserver.management.repository.PeerMeshDeviceRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.hibernate.Session;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.TreeSet;
import static com.theshuai.specusserver.management.service.ClientOwnerTransferPlan.*;

/** Internal database boundary, not a transfer API. Existing writers take credential before client.
 * Group discovery uses current locking reads, never the preview's repeatable-read snapshot.
 * Identity creation allocates a new client ID under its credential; it cannot add a credential
 * to an existing client. Any future reassociation writer must obey this same boundary. */
@Component
@Transactional(propagation = Propagation.MANDATORY)
class ClientOwnerTransferRows {
    @PersistenceContext private EntityManager entities;
    private final ClientAccountRepository accounts;
    private final ClientCredentialRepository credentials;
    private final PeerMeshDeviceRepository devices;

    ClientOwnerTransferRows(ClientAccountRepository accounts, ClientCredentialRepository credentials,
                            PeerMeshDeviceRepository devices) {
        this.accounts = accounts; this.credentials = credentials; this.devices = devices;
    }

    Snapshot lock(String tenant, PathScope scope, long id) {
        ArrayList<ClientRow> clients = new ArrayList<>();
        ArrayList<CredentialRow> credentialRows = new ArrayList<>();
        LinkedHashMap<Long, IdentityRow> identities = new LinkedHashMap<>();
        ArrayList<PeerRow> peers = new ArrayList<>();
        Long credentialId = scope == PathScope.CREDENTIAL_GROUP ? id : null;
        if (scope == PathScope.SINGLE) {
            ClientAccount account = accounts.lockCurrent(id, tenant).orElse(null);
            if (account == null) return new Snapshot(clients, credentialRows, List.of(), peers);
            clients.add(new ClientRow(id, tenant, account.getClientName(), account.getOwnerUsername(), account.isEnabled()));
            List<IdentityRow> direct = identityRows("client_id", id);
            direct.forEach(row -> identities.put(row.id(), row));
            TreeSet<Long> linked = new TreeSet<>();
            direct.forEach(row -> linked.add(row.credentialId()));
            if (linked.size() > 1) return new Snapshot(clients, credentialRows, new ArrayList<>(identities.values()), peers);
            if (!linked.isEmpty()) credentialId = linked.first();
        }
        if (credentialId != null) {
            var credential = credentials.lockCurrent(credentialId, tenant).orElse(null);
            if (credential == null) return new Snapshot(clients, credentialRows, new ArrayList<>(identities.values()), peers);
            credentialRows.add(new CredentialRow(credentialId, credential.getTenantId(), credential.getOwnerUsername(), credential.isEnabled()));
            identityRows("credential_id", credentialId).forEach(row -> identities.put(row.id(), row));
        }
        TreeSet<Long> ids = new TreeSet<>();
        if (scope == PathScope.SINGLE) ids.add(id);
        identities.values().forEach(row -> ids.add(row.clientId()));
        // Reverse edges must not disappear through tenant filtering or an old subquery snapshot.
        for (long client : ids) identityRows("client_id", client).forEach(row -> identities.put(row.id(), row));
        final Long selected = credentialId;
        if (identities.values().stream().anyMatch(row -> !tenant.equals(row.tenantId())
                || selected == null || selected.longValue() != row.credentialId())) {
            return new Snapshot(clients, credentialRows, new ArrayList<>(identities.values()), peers);
        }
        for (long client : ids) {
            if (scope != PathScope.SINGLE || client != id) {
                // The selected credential is already locked. Do not discover/lock another
                // credential after a child lock: corrupt reverse edges were rejected above.
                entities.createNativeQuery("update specus_client_account set enabled=enabled where id=?1 and tenant_id=?2")
                        .setParameter(1, client).setParameter(2, tenant).executeUpdate();
                List<?> rows = entities.createNativeQuery("select id,tenant_id,client_name,owner_username,enabled from specus_client_account where id=?1 and tenant_id=?2" + rowLock())
                        .setParameter(1, client).setParameter(2, tenant).getResultList();
                if (!rows.isEmpty()) {
                    Object[] row = (Object[]) rows.getFirst();
                    if (tenant.equals(row[1])) clients.add(new ClientRow(((Number) row[0]).longValue(), (String) row[1],
                            (String) row[2], (String) row[3], bool(row[4])));
                }
            }
            devices.lockCurrent(tenant, client).ifPresent(device -> peers.add(new PeerRow(device.getId(),
                    device.getTenantId(), device.getClientId(), device.getClientName(), device.getOwnerUsername(), device.isEnabled())));
        }
        return new Snapshot(clients, credentialRows, new ArrayList<>(identities.values()), peers);
    }

    private List<IdentityRow> identityRows(String column, long id) {
        // column is selected only by this class, never supplied by a request.
        List<?> rows = entities.createNativeQuery("select id,tenant_id,credential_id,client_id from specus_client_identity where " + column + "=?1 order by id" + rowLock())
                .setParameter(1, id).getResultList();
        return rows.stream().map(value -> { Object[] row = (Object[]) value;
            return new IdentityRow(((Number) row[0]).longValue(), (String) row[1],
                    ((Number) row[2]).longValue(), ((Number) row[3]).longValue()); }).toList();
    }

    private String rowLock() {
        return entities.unwrap(Session.class).doReturningWork(connection ->
                connection.getMetaData().supportsSelectForUpdate() ? " for update" : "");
    }
    private static boolean bool(Object value) { return value instanceof Boolean b ? b : ((Number) value).intValue() != 0; }
}
