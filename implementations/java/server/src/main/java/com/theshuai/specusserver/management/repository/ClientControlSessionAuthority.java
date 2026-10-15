package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.service.ClientAuthService;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.hibernate.Session;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;
import java.util.Objects;

/** Used only AFTER globally ordered credential/client locks. Immutable hints reject a foreign
 * session/identity before locking it; hints never authorize status, ownership or availability. */
@Repository
@Transactional(propagation = Propagation.MANDATORY)
public class ClientControlSessionAuthority {
    @PersistenceContext private EntityManager entities;
    private final ClientCredentialRepository credentials;
    private final ClientSessionRepository sessions;

    public ClientControlSessionAuthority(ClientCredentialRepository credentials, ClientSessionRepository sessions) {
        this.credentials = credentials;
        this.sessions = sessions;
    }

    public void reserveWriter() {
        entities.createNativeQuery("update specus_client_account set enabled=enabled where 1=0").executeUpdate();
    }

    public void verify(ClientAccount account, Long sessionId, String channelId) {
        String tenant = account.getTenantId();
        List<?> bindings = entities.createNativeQuery("select id,credential_id,tenant_id from specus_client_identity where client_id=?1")
                .setParameter(1, account.getId()).getResultList();
        if (sessionId == null) {
            if (!bindings.isEmpty()) throw denied(); // A derived/token identity cannot downgrade to legacy.
            return;
        }
        var hints = entities.createNativeQuery("select client_id,credential_id,identity_id,tenant_id from specus_client_session where id=?1")
                .setParameter(1, sessionId).getResultList();
        if (hints.size() != 1) throw denied();
        Object[] hint = (Object[]) hints.getFirst();
        if (!Objects.equals(number(hint[0]), account.getId()) || !tenant.equals(hint[3])) throw denied();
        Long credential = number(hint[1]), identity = number(hint[2]);
        if (bindings.isEmpty() || bindings.stream().anyMatch(item -> {
            Object[] row = (Object[]) item;
            return !Objects.equals(credential, number(row[1])) || !tenant.equals(row[2]);
        }) || bindings.stream().noneMatch(item -> Objects.equals(identity, number(((Object[]) item)[0])))) throw denied();

        // Every binding credential was acquired by lockCurrentAll before either client row.
        var key = credentials.lockCurrent(credential, tenant).filter(value -> value.isEnabled()
                && Objects.equals(value.getOwnerUsername(), account.getOwnerUsername())).orElseThrow(ClientControlSessionAuthority::denied);
        var current = sessions.lockCurrent(sessionId, tenant).orElseThrow(ClientControlSessionAuthority::denied);
        if (!Objects.equals(current.clientId(), account.getId()) || !Objects.equals(current.credentialId(), key.getId())
                || !Objects.equals(current.identityId(), identity) || !account.getClientName().equals(current.clientName())
                || !ClientAuthService.STATUS_NETTY_ONLINE.equals(current.status()) || !channelId.equals(current.channelId())) throw denied();
        var rows = entities.createNativeQuery("select client_id,credential_id,tenant_id from specus_client_identity where id=?1" + rowLock())
                .setParameter(1, identity).getResultList();
        if (rows.size() != 1) throw denied();
        Object[] row = (Object[]) rows.getFirst();
        if (!Objects.equals(number(row[0]), account.getId()) || !Objects.equals(number(row[1]), credential) || !tenant.equals(row[2])) throw denied();
    }

    /** The capability belongs to this exact authenticated control session, never another login. */
    public boolean verifyReceiver(ClientAccount account, Long sessionId, String channelId) {
        verify(account, sessionId, channelId);
        if (sessionId == null) return false;
        var rows = entities.createNativeQuery("select message_receive_capable,tenant_id,client_id from specus_client_session where id=?1" + rowLock())
                .setParameter(1, sessionId).getResultList();
        if (rows.size() != 1) return false;
        Object[] row = (Object[]) rows.getFirst();
        return account.getTenantId().equals(row[1]) && Objects.equals(account.getId(), number(row[2]))
                && (row[0] instanceof Boolean flag ? flag : row[0] instanceof Number number && number.intValue() != 0);
    }

    private String rowLock() {
        return entities.unwrap(Session.class).doReturningWork(connection -> connection.getMetaData().supportsSelectForUpdate() ? " for update" : "");
    }

    private static Long number(Object value) { return value == null ? null : ((Number) value).longValue(); }
    private static IllegalArgumentException denied() { return new IllegalArgumentException("client control authentication is no longer current"); }
}
