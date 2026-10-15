package com.theshuai.specusserver.management.service;

import com.theshuai.common.protocol.MessageType;
import com.theshuai.common.protocol.request.MessageRequestPacket;
import com.theshuai.common.protocol.response.MessageResponsePacket;
import com.theshuai.common.session.Session;
import com.theshuai.specusserver.attribute.ServerAttributes;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.repository.ClientControlSessionAuthority;
import com.theshuai.specusserver.session.SessionUtil;
import io.netty.channel.Channel;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.util.StringUtils;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** Ephemeral message fallback, not a durable inbox. Producer rollback never publishes; a
 * separate worker avoids opening another transaction in an afterCommit callback (pool size 1). */
@Service
@Slf4j
public class ClientMessageRelayService {
    private static final int MAX_BYTES = 64 * 1024;
    private static final long TTL = TimeUnit.SECONDS.toNanos(10);
    private final ClientAccountService accounts;
    private final PeerMeshService peers;
    private final ClientControlSessionAuthority controls;
    private final ConcurrentLinkedQueue<Pending> pending = new ConcurrentLinkedQueue<>();
    private final Semaphore slots;
    private final Semaphore bytes = new Semaphore(16 * 1024 * 1024);
    private final java.util.function.LongSupplier clock;

    @Autowired
    public ClientMessageRelayService(ClientAccountService accounts, PeerMeshService peers, ClientControlSessionAuthority controls,
                                    @Value("${specus.peer-mesh.message-queue-capacity:1024}") int capacity) {
        this(accounts, peers, controls, capacity, System::nanoTime);
    }

    public ClientMessageRelayService(ClientAccountService accounts, PeerMeshService peers, ClientControlSessionAuthority controls,
                                    int capacity, java.util.function.LongSupplier clock) {
        if (capacity < 1 || capacity > 65536) throw new IllegalArgumentException("invalid client message queue capacity");
        this.accounts = accounts; this.peers = peers; this.controls = controls; this.slots = new Semaphore(capacity);
        this.clock = Objects.requireNonNull(clock);
    }

    private record Binding(Channel channel, Session session, Long authentication, String tenant) {
        private Binding(Channel channel) { this(channel, SessionUtil.getSession(channel), channel.attr(ServerAttributes.CLIENT_SESSION_ID).get(), channel.attr(ServerAttributes.TENANT_ID).get()); }
        private boolean matches(ClientAccount account) {
            return channel.isActive() && session != null && account.getClientName().equals(session.getClientName())
                    && account.getTenantId().equals(tenant) && SessionUtil.getChannel(account.getClientName()) == channel
                    && SessionUtil.getSession(channel) == session && Objects.equals(authentication, channel.attr(ServerAttributes.CLIENT_SESSION_ID).get())
                    && tenant.equals(channel.attr(ServerAttributes.TENANT_ID).get());
        }
    }
    private final class Pending {
        final ClientAccount source, target;
        final Binding from, to;
        final String body;
        final int charge;
        final long created = clock.getAsLong();
        final AtomicBoolean released = new AtomicBoolean();
        int attempts;
        Pending(ClientAccount source, ClientAccount target, Binding from, Binding to, String body, int charge) {
            this.source = reference(source); this.target = reference(target); this.from = from; this.to = to; this.body = body; this.charge = charge;
        }
        void release() { if (released.compareAndSet(false, true)) { slots.release(); bytes.release(charge); } }
    }

    @Transactional
    public void submit(MessageRequestPacket request, Session session, Channel incoming) {
        if (request == null || request.getMessageType() != MessageType.CLIENT_TO_CLIENT || session == null || incoming == null
                || SessionUtil.getSession(incoming) != session || SessionUtil.getChannel(session.getClientName()) != incoming)
            throw new IllegalArgumentException("client message requires current control connection");
        String body = request.getMessage(), name = request.getToClientName();
        if (!StringUtils.hasText(body) || body.length() > MAX_BYTES || !StringUtils.hasText(name) || name.length() > 120)
            throw new IllegalArgumentException("invalid client message");
        int charge = body.getBytes(StandardCharsets.UTF_8).length + 4096;
        if (charge > MAX_BYTES + 4096) throw new IllegalArgumentException("client message is too large");
        controls.reserveWriter(); // First SQL: no SQLite read-to-writer upgrade.
        var source = accounts.findClientByName(session.getClientName()).orElseThrow(() -> new IllegalArgumentException("source client unavailable"));
        var target = accounts.findClientByName(name.trim()).orElseThrow(() -> new IllegalArgumentException("target client unavailable"));
        Channel targetChannel = SessionUtil.getChannel(target.getClientName());
        if (targetChannel == null) throw new IllegalArgumentException("target client offline");
        var from = new Binding(incoming); var to = new Binding(targetChannel);
        if (!from.matches(source) || !to.matches(target)) throw new IllegalArgumentException("client message connection changed");
        if (!slots.tryAcquire()) throw new IllegalStateException("client message queue busy");
        if (!bytes.tryAcquire(charge)) { slots.release(); throw new IllegalStateException("client message byte budget exceeded"); }
        var work = new Pending(source, target, from, to, body, charge);
        boolean submitted = false;
        try {
            peers.publishAuthorizedSignal(source, target, null, null, current -> validate(work, current));
            if (!TransactionSynchronizationManager.isActualTransactionActive() || !TransactionSynchronizationManager.isSynchronizationActive())
                throw new IllegalStateException("client message transaction required");
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override public void afterCommit() { pending.add(work); }
                @Override public void afterCompletion(int status) { if (status != STATUS_COMMITTED) work.release(); }
            });
            submitted = true;
        } finally { if (!submitted) work.release(); }
    }

    private void validate(Pending work, PeerMeshService.AuthorizedSignal current) {
        var source = current.source().account(); var target = current.target().account();
        if (!source.getClientName().equals(work.source.getClientName()) || !target.getClientName().equals(work.target.getClientName())
                || !work.from.matches(source) || !work.to.matches(target)) throw new IllegalArgumentException("client message connection changed");
        controls.verify(source, work.from.authentication(), work.from.channel().id().asLongText());
        controls.verify(target, work.to.authentication(), work.to.channel().id().asLongText());
    }

    @Scheduled(fixedDelayString = "${specus.peer-mesh.message-publish-interval-ms:25}")
    public void publishPending() {
        for (int i = 0; i < 64; i++) {
            var work = pending.poll(); if (work == null) return;
            boolean retry = false; AtomicBoolean attempted = new AtomicBoolean();
            try {
                if (clock.getAsLong() - work.created > TTL || !work.from.matches(work.source) || !work.to.matches(work.target)) continue;
                peers.publishAuthorizedSignal(work.source, work.target, null, null, current -> {
                    validate(work, current);
                    if (!work.from.matches(current.source().account()) || !work.to.matches(current.target().account())) return;
                    var packet = new MessageResponsePacket(); packet.setMessageType(MessageType.CLIENT_TO_CLIENT);
                    packet.setClientName(current.source().account().getClientName()); packet.setToClientName(current.target().account().getClientName()); packet.setMessage(work.body);
                    attempted.set(true); // Never retry after an uncertain/failed network acceptance.
                    work.to.channel().writeAndFlush(packet).addListener(future -> {
                        if (!future.isSuccess()) log.warn("client message write failed source={} target={}", work.source.getId(), work.target.getId());
                    });
                });
            } catch (IllegalArgumentException denied) {
                log.debug("client message no longer authorized source={} target={}", work.source.getId(), work.target.getId());
            } catch (RuntimeException failure) {
                retry = !attempted.get() && ++work.attempts < 3 && clock.getAsLong() - work.created <= TTL;
                if (retry) pending.add(work);
                log.warn("client message publication failed source={} target={} retry={}", work.source.getId(), work.target.getId(), retry);
            } finally { if (!retry) work.release(); }
            if (retry) return;
        }
    }

    private static ClientAccount reference(ClientAccount account) {
        var result = new ClientAccount(); result.setId(account.getId()); result.setTenantId(account.getTenantId()); result.setClientName(account.getClientName()); return result;
    }
}
