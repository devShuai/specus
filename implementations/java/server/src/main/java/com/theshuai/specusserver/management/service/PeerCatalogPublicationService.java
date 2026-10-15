package com.theshuai.specusserver.management.service;

import com.theshuai.common.peermesh.PeerControlMessage;
import com.theshuai.common.protocol.MessageType;
import com.theshuai.common.protocol.response.MessageResponsePacket;
import com.theshuai.common.session.Session;
import com.theshuai.common.util.JsonUtil;
import com.theshuai.specusserver.attribute.ServerAttributes;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.session.SessionUtil;
import io.netty.channel.Channel;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.LongSupplier;

/** Bounded ephemeral catalog delivery, not the durable ownership event outbox. A worker runs
 * after the producer releases its connection (including SQLite pool1), then reauthorizes. */
@Service
@Slf4j
public class PeerCatalogPublicationService {
    private static final int MAX_BYTES = 64 * 1024;
    private static final long TTL = TimeUnit.SECONDS.toNanos(10);
    private final PeerServiceDiscoveryService catalogs;
    private final PeerCatalogAuthority authority;
    private final ConcurrentLinkedQueue<Pending> pending = new ConcurrentLinkedQueue<>();
    private final Semaphore slots, bytes = new Semaphore(16 * 1024 * 1024);
    private final LongSupplier clock;
    @Autowired
    public PeerCatalogPublicationService(PeerServiceDiscoveryService catalogs, PeerCatalogAuthority authority,
                                        @Value("${specus.peer-mesh.catalog-queue-capacity:1024}") int capacity) {
        this(catalogs, authority, capacity, System::nanoTime);
    }
    public PeerCatalogPublicationService(PeerServiceDiscoveryService catalogs, PeerCatalogAuthority authority, int capacity, LongSupplier clock) {
        if (capacity < 1 || capacity > 65536) throw new IllegalArgumentException("invalid catalog queue capacity");
        this.catalogs = catalogs; this.authority = authority; this.slots = new Semaphore(capacity); this.clock = Objects.requireNonNull(clock);
    }
    record Binding(Channel channel, Session session, Long authentication, String tenant) {
        Binding(Channel channel) { this(channel, SessionUtil.getSession(channel), channel.attr(ServerAttributes.CLIENT_SESSION_ID).get(), channel.attr(ServerAttributes.TENANT_ID).get()); }
        boolean matches(ClientAccount account) {
            return account != null && channel.isActive() && session != null && account.getClientName().equals(session.getClientName())
                    && account.getTenantId().equals(tenant) && SessionUtil.getChannel(account.getClientName()) == channel
                    && SessionUtil.getSession(channel) == session && Objects.equals(authentication, channel.attr(ServerAttributes.CLIENT_SESSION_ID).get())
                    && tenant.equals(channel.attr(ServerAttributes.TENANT_ID).get());
        }
    }
    private final class Pending {
        final String tenant, body, recipientName;
        final long publisher, recipient, session, revision, created = clock.getAsLong();
        final Binding from, to;
        final boolean snapshot;
        final int charge;
        final AtomicBoolean released = new AtomicBoolean();
        final AtomicBoolean enqueued = new AtomicBoolean();
        int attempts;
        Pending(String tenant, long publisher, long recipient, long session, long revision, String recipientName,
                String body, Binding from, Binding to, boolean snapshot, int charge) {
            this.tenant=tenant; this.publisher=publisher; this.recipient=recipient; this.session=session; this.revision=revision;
            this.recipientName=recipientName; this.body=body; this.from=from; this.to=to; this.snapshot=snapshot; this.charge=charge;
        }
        void release() { if (released.compareAndSet(false,true)) { slots.release(); bytes.release(charge); } }
        void enqueue() { if (enqueued.compareAndSet(false,true)) pending.add(this); }
    }
    public void submit(PeerServiceDiscoveryService.CatalogDelivery delivery) {
        var recipient=delivery.recipient(); var offered=delivery.catalog();
        Channel channel=SessionUtil.getChannel(recipient.getClientName());
        if (channel == null || !SessionUtil.hasLogin(channel)) return;
        var catalog=JsonUtil.stringToObject(JsonUtil.objectToString(offered),PeerControlMessage.class);
        if (catalog == null || catalog.getPublisherClientId() == null || catalog.getPublisherSessionId() == null || catalog.getRevision() == null) throw new IllegalArgumentException("invalid catalog delivery");
        var snapshot=catalogs.currentCatalog(recipient.getTenantId(),catalog.getPublisherClientId(),catalog.getPublisherSessionId());
        boolean data=snapshot != null && snapshot.revision() == catalog.getRevision();
        // Keep the committed publisher's complete offer internally. A stale informational OWNER
        // filter may omit a newly authorized consumer; only the current worker guard filters wire data.
        if (data) catalog.setServices(snapshot.services());
        else if (catalog.getServices() != null && !catalog.getServices().isEmpty()) return;
        String encoded=JsonUtil.objectToString(catalog); int charge=encoded.getBytes(StandardCharsets.UTF_8).length+4096;
        if (charge > MAX_BYTES+4096) throw new IllegalArgumentException("service catalog too large");
        if (!slots.tryAcquire()) throw new IllegalStateException("catalog publication queue busy");
        if (!bytes.tryAcquire(charge)) { slots.release(); throw new IllegalStateException("catalog publication byte budget exceeded"); }
        Channel publisher=SessionUtil.getChannel(catalog.getPublisherClientName());
        var work=new Pending(recipient.getTenantId(),catalog.getPublisherClientId(),recipient.getId(),catalog.getPublisherSessionId(),catalog.getRevision(),
                recipient.getClientName(),encoded,publisher == null ? null : new Binding(publisher),new Binding(channel),data,charge);
        boolean submitted=false;
        try {
            if (TransactionSynchronizationManager.isActualTransactionActive() && TransactionSynchronizationManager.isSynchronizationActive() && !PeerCatalogCache.inCommittedEffect()) {
                TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                    @Override public void afterCommit() { work.enqueue(); }
                    @Override public void afterCompletion(int status) { if (status != STATUS_COMMITTED) work.release(); else work.enqueue(); }
                });
            } else work.enqueue();
            submitted=true;
        } finally { if (!submitted) work.release(); }
    }

    @Scheduled(fixedDelayString="${specus.peer-mesh.catalog-publish-interval-ms:25}")
    public void publishPending() {
        if (TransactionSynchronizationManager.isActualTransactionActive()) throw new IllegalStateException("catalog worker requires a completed producer transaction");
        for (int i=0;i<64;i++) {
            var work=pending.poll(); if (work == null) return;
            boolean retry=false; AtomicBoolean attempted=new AtomicBoolean();
            try {
                if (clock.getAsLong()-work.created > TTL) continue;
                var current=catalogs.currentCatalog(work.tenant,work.publisher,work.session);
                if (work.snapshot ? current == null || current.revision() != work.revision : current != null) continue;
                var catalog=JsonUtil.stringToObject(work.body,PeerControlMessage.class);
                // Never redirect an old publication onto a successor publisher control binding.
                if (work.snapshot && (work.from == null || !bindingMatches(work.from,work.tenant,catalog.getPublisherClientName()))) continue;
                authority.publish(work.tenant,work.publisher,work.recipient,catalog,work.from,work.to,authorized->{
                    if (!catalogs.currentForPublication(work.tenant,work.publisher,work.session,work.revision,work.snapshot)) return;
                    if (!bindingMatches(work.to,work.tenant,work.recipientName)) return;
                    if (work.snapshot && !bindingMatches(work.from,work.tenant,catalog.getPublisherClientName())) return;
                    var packet=new MessageResponsePacket();packet.setMessageType(MessageType.PEER_CONTROL);packet.setClientName("server");
                    String encoded=JsonUtil.objectToString(authorized);
                    if (encoded.getBytes(StandardCharsets.UTF_8).length > MAX_BYTES) throw new IllegalArgumentException("current service catalog too large");
                    packet.setToClientName(work.recipientName);packet.setMessage(encoded);
                    attempted.set(true); // Never retry after uncertain network acceptance, including commit failure.
                    work.to.channel().writeAndFlush(packet).addListener(future->{if(!future.isSuccess())log.warn("catalog write failed publisher={} recipient={}",work.publisher,work.recipient);});
                });
            } catch (IllegalArgumentException denied) {
                log.debug("catalog recipient no longer authenticated publisher={} recipient={}",work.publisher,work.recipient);
            } catch (RuntimeException failure) {
                retry=!attempted.get() && ++work.attempts < 3 && clock.getAsLong()-work.created <= TTL;
                if (retry) pending.add(work);
                log.warn("catalog publication failed publisher={} recipient={} retry={} type={}",work.publisher,work.recipient,retry,failure.getClass().getSimpleName());
            } finally { if (!retry) work.release(); }
            if (retry) return;
        }
    }
    private static boolean bindingMatches(Binding binding,String tenant,String name) {
        var account=new ClientAccount();account.setTenantId(tenant);account.setClientName(name);return binding.matches(account);
    }
}
