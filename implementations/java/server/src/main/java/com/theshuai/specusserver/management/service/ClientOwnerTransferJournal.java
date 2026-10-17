package com.theshuai.specusserver.management.service;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/** The atomic ownership audit is also the durable invalidation journal. There is deliberately no
 * ID/time high-water mark: IDs may be allocated before another transaction commits a higher ID.
 * Exact per-node receipts prevent that late commit from being skipped. No secret payload is read. */
@Service
public class ClientOwnerTransferJournal {
    @PersistenceContext private EntityManager entities;
    public record Event(long id, String tenant, String detail) {}

    @Transactional(readOnly = true)
    public List<Event> pending(String node) {
        return query(node, null, 0);
    }

    @Transactional(readOnly = true)
    public List<Event> pendingAfter(String node, long after) { return query(node, null, after); }

    @Transactional(readOnly = true)
    public Optional<Event> pending(String node, long eventId) {
        return query(node, eventId, 0).stream().findFirst();
    }

    private List<Event> query(String node, Long eventId, long after) {
        var query = entities.createNativeQuery("""
                select a.id,a.tenant_id,a.detail_json from client_owner_transfer_audit a
                 where not exists (select 1 from client_owner_transfer_receipt r
                                   where r.node_id=?1 and r.event_id=a.id)
                """ + (eventId != null ? " and a.id=?2" : after > 0 ? " and a.id>?2" : "") + " order by a.id").setParameter(1, node).setMaxResults(32);
        if (eventId != null) query.setParameter(2, eventId);
        else if (after > 0) query.setParameter(2, after);
        return query.getResultList().stream().map(value -> {
            Object[] row = (Object[]) value;
            return new Event(((Number) row[0]).longValue(), (String) row[1], (String) row[2]);
        }).toList();
    }

    @Transactional
    public void acknowledge(String node, Event event) {
        String key = node + ":" + event.id();
        if (entities.find(com.theshuai.specusserver.management.model.ClientOwnerTransferReceipt.class, key) != null) return;
        entities.createNativeQuery("""
                insert into client_owner_transfer_receipt(id,node_id,event_id,processed_at) values (?1,?2,?3,?4)
                """).setParameter(1, key).setParameter(2, node).setParameter(3, event.id())
                .setParameter(4, Instant.now().toString()).executeUpdate();
    }
}
