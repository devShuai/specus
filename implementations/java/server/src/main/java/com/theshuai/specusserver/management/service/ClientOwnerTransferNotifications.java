package com.theshuai.specusserver.management.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.util.UUID;
import java.util.List;
import java.util.TreeSet;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.concurrent.atomic.AtomicBoolean;

/** Every process consumes the shared committed journal independently and recomputes CURRENT policy,
 * never replays historical owners. Network work runs after the journal read transaction releases
 * its connection (including SQLite pool1). A failed refresh/receipt remains pending for retry.
 * New processes have a new identity and replay; receipts are not remote ACKs or key revocation. */
@Service
@Slf4j
public class ClientOwnerTransferNotifications {
    private final String node = UUID.randomUUID().toString();
    private static final ObjectMapper JSON = new ObjectMapper();
    private final AtomicBoolean draining = new AtomicBoolean();
    private final ClientOwnerTransferJournal journal;
    private final ClientAccountService accounts;
    private final PeerSignalService signals;
    private final boolean polling;
    private long scanAfter; // Fairness only, never a durable high-water mark; wrap and retry lower IDs.

    public ClientOwnerTransferNotifications(ClientOwnerTransferJournal journal, ClientAccountService accounts,
            PeerSignalService signals, @Value("${specus.owner-transfer.notifications.poll:true}") boolean polling) {
        this.journal = journal; this.accounts = accounts; this.signals = signals; this.polling = polling;
    }

    @Scheduled(fixedDelayString = "${specus.owner-transfer.notifications.interval-ms:250}")
    public void poll() { if (polling) drain(); }

    public void committed(Long auditId) {
        if (auditId == null) return;
        requireOutsideTransaction();
        accounts.invalidateOwnershipCache();
        if (!draining.compareAndSet(false, true)) return; // The durable journal is the retry, not this hint.
        try { journal.pending(node, auditId).ifPresent(this::process); }
        catch (RuntimeException failure) { log.warn("[owner-transfer] committed refresh pending event={}", auditId, failure); }
        finally { draining.set(false); }
    }

    public void drain() {
        requireOutsideTransaction();
        if (!draining.compareAndSet(false, true)) return;
        try {
            var events = journal.pendingAfter(node, scanAfter);
            if (events.isEmpty() && scanAfter != 0) { scanAfter = 0; events = journal.pending(node); }
            for (var event : events) { scanAfter = event.id(); process(event); }
        }
        catch (RuntimeException failure) { log.warn("[owner-transfer] journal scan pending", failure); }
        finally { draining.set(false); }
    }

    private void process(ClientOwnerTransferJournal.Event event) {
        try {
            accounts.invalidateOwnershipCache();
            signals.reconcileOwnership(event.tenant(), affectedClients(event));
            journal.acknowledge(node, event);
        } catch (RuntimeException failure) {
            log.warn("[owner-transfer] retrying committed refresh event={} tenant={}", event.id(), event.tenant(), failure);
        }
    }

    private static List<Long> affectedClients(ClientOwnerTransferJournal.Event event) {
        try {
            var ids = JSON.readTree(event.detail()).path("affectedClientIds");
            if (!ids.isArray()) throw new IllegalStateException("ownership journal lacks complete client IDs");
            var result = new TreeSet<Long>();
            for (var id : ids) {
                if (!id.isIntegralNumber() || !id.canConvertToLong() || id.longValue() <= 0 || id.longValue() > 9_007_199_254_740_991L)
                    throw new IllegalStateException("ownership journal contains invalid client ID");
                result.add(id.longValue());
            }
            return List.copyOf(result);
        } catch (java.io.IOException invalid) { throw new IllegalStateException("invalid ownership journal", invalid); }
    }

    private static void requireOutsideTransaction() {
        if (TransactionSynchronizationManager.isActualTransactionActive())
            throw new IllegalStateException("ownership notification must run after transaction completion");
    }
}
