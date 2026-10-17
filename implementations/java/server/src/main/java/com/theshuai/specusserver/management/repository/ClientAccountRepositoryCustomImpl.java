package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.ClientAccount;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.hibernate.Session;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import java.util.Optional;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeSet;

public class ClientAccountRepositoryCustomImpl implements ClientAccountRepositoryCustom {
    @PersistenceContext private EntityManager entities;
    private final ClientCredentialRepository credentials;

    public ClientAccountRepositoryCustomImpl(ClientCredentialRepository credentials) { this.credentials = credentials; }

    @Override
    @Transactional(propagation = Propagation.MANDATORY)
    public Optional<ClientAccount> lockCurrent(Long id, String tenantId) {
        if (id == null) return Optional.empty();
        return Optional.ofNullable(lockCurrentAll(Collections.singleton(id), tenantId).get(id));
    }

    @Override
    @Transactional(propagation = Propagation.MANDATORY)
    public Map<Long, ClientAccount> lockCurrentAll(Collection<Long> ids, String tenantId) {
        entities.createNativeQuery("update specus_client_account set enabled=enabled where 1=0").executeUpdate();
        // Runtime credential/client links are immutable: authentication allocates a NEW client ID
        // for every new identity. Read the stable links without taking identity locks first, then
        // lock credentials in order before the client, matching authentication's credential first
        // order and avoiding a rename(identity update) versus login deadlock. Deleted credentials
        // do not prevent management of the remaining client. No ownership/integrity validation for
        // a transfer is implied by this ordinary resource writer; the transfer planner does that.
        TreeSet<Long> clients = new TreeSet<>(ids), linked = new TreeSet<>();
        for (long id : clients) for (Object credential : entities.createNativeQuery("""
                select distinct credential_id from specus_client_identity
                 where client_id=?1 order by credential_id
                """).setParameter(1, id).getResultList()) {
            if (credential != null) linked.add(((Number) credential).longValue());
        }
        for (long credential : linked) credentials.lockCurrent(credential, tenantId);
        Map<Long, ClientAccount> result = new LinkedHashMap<>();
        for (long id : clients) lockClientRow(id, tenantId).ifPresent(account -> result.put(id, account));
        return Collections.unmodifiableMap(result);
    }

    private Optional<ClientAccount> lockClientRow(Long id, String tenantId) {
        entities.createNativeQuery("update specus_client_account set enabled=enabled where id=?1 and tenant_id=?2")
                .setParameter(1, id).setParameter(2, tenantId).executeUpdate();
        String lock = entities.unwrap(Session.class).doReturningWork(connection ->
                connection.getMetaData().supportsSelectForUpdate() ? " for update" : "");
        var rows = entities.createNativeQuery("""
                select id, tenant_id, owner_username, client_name, password_hash, enabled,
                       connection_rate_limit_per_minute, created_at, updated_at
                  from specus_client_account where id=?1 and tenant_id=?2
                """ + lock).setParameter(1, id).setParameter(2, tenantId).getResultList();
        if (rows.isEmpty()) return Optional.empty();
        Object[] row = (Object[]) rows.getFirst();
        ClientAccount account = new ClientAccount();
        account.setId(((Number) row[0]).longValue()); account.setTenantId((String) row[1]);
        account.setOwnerUsername((String) row[2]); account.setClientName((String) row[3]);
        account.setPasswordHash((String) row[4]);
        account.setEnabled(row[5] instanceof Boolean value ? value : ((Number) row[5]).intValue() != 0);
        account.setConnectionRateLimitPerMinute(((Number) row[6]).intValue());
        account.setCreatedAt((String) row[7]); account.setUpdatedAt((String) row[8]);
        return tenantId.equals(account.getTenantId()) ? Optional.of(account) : Optional.empty();
    }
}
