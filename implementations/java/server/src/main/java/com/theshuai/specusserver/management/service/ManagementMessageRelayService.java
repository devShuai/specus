package com.theshuai.specusserver.management.service;

import com.theshuai.common.protocol.MessageType;
import com.theshuai.common.protocol.response.MessageResponsePacket;
import com.theshuai.common.session.Session;
import com.theshuai.common.util.JsonUtil;
import com.theshuai.specusserver.attribute.ServerAttributes;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.repository.ClientControlSessionAuthority;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.tenant.TenantContext;
import com.theshuai.specusserver.session.SessionUtil;
import com.theshuai.specusserver.websocket.ManagementWebSocketIdentity;
import com.theshuai.specusserver.websocket.WebSocketTicketHandshakeInterceptor;
import io.netty.channel.Channel;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.LongSupplier;

/** Best-effort management chat, not a durable inbox. Queue only after producer commit; every
 * recipient is authorized independently in its own worker transaction, so stale tabs do not
 * poison valid deliveries or invert management-account lock ordering. */
@Service
@Slf4j
public class ManagementMessageRelayService {
    private static final int MAX_BYTES = 64 * 1024;
    private static final long TTL = TimeUnit.SECONDS.toNanos(10);
    private final ManagementMessageAuthority authority;
    private final ClientControlSessionAuthority controls;
    private final Semaphore slots;
    private final Semaphore bytes = new Semaphore(16 * 1024 * 1024);
    private final ConcurrentLinkedQueue<Pending> queue = new ConcurrentLinkedQueue<>();
    private final LongSupplier clock;

    @Autowired
    public ManagementMessageRelayService(ManagementMessageAuthority authority, ClientControlSessionAuthority controls,
                                        @Value("${specus.management.message-queue-capacity:1024}") int capacity) {
        this(authority, controls, capacity, System::nanoTime);
    }
    public ManagementMessageRelayService(ManagementMessageAuthority authority, ClientControlSessionAuthority controls, int capacity, LongSupplier clock) {
        if (capacity < 1 || capacity > 65536) throw new IllegalArgumentException("invalid management message queue capacity");
        this.authority = authority; this.controls = controls; this.slots = new Semaphore(capacity); this.clock = Objects.requireNonNull(clock);
    }

    private record Browser(WebSocketSession session, ManagementContext identity) {
        static Browser capture(WebSocketSession session) {
            var attrs = session.getAttributes();
            if (!(attrs.get(WebSocketTicketHandshakeInterceptor.ATTR_USER) instanceof String user)
                    || !(attrs.get(WebSocketTicketHandshakeInterceptor.ATTR_TENANT_ID) instanceof String tenant)
                    || !(attrs.get(WebSocketTicketHandshakeInterceptor.ATTR_ADMIN) instanceof Boolean admin))
                throw new ManagementMessageAuthority.Denied("identity-revoked");
            Object key = attrs.get(WebSocketTicketHandshakeInterceptor.ATTR_ACCOUNT_KEY);
            if (key != null && !(key instanceof String)) throw new ManagementMessageAuthority.Denied("identity-revoked");
            if (!tenant.equals(TenantContext.normalize(tenant))) throw new ManagementMessageAuthority.Denied("identity-revoked");
            return new Browser(session, new ManagementContext(new TenantContext(tenant), user, admin, (String) key));
        }
        boolean current() {
            if (!session.isOpen()) return false;
            try { return identity.equals(capture(session).identity); }
            catch (ManagementMessageAuthority.Denied invalid) { return false; }
        }
    }
    private record Control(Channel channel, Session session, Long authentication, String tenant) {
        static Control capture(Channel channel) {
            return channel == null ? null : new Control(channel, SessionUtil.getSession(channel), channel.attr(ServerAttributes.CLIENT_SESSION_ID).get(), channel.attr(ServerAttributes.TENANT_ID).get());
        }
        boolean current(ClientAccount client) {
            return channel.isActive() && session != null && client.getClientName().equals(session.getClientName())
                    && client.getTenantId().equals(tenant) && SessionUtil.getChannel(client.getClientName()) == channel
                    && SessionUtil.getSession(channel) == session && Objects.equals(authentication, channel.attr(ServerAttributes.CLIENT_SESSION_ID).get())
                    && tenant.equals(channel.attr(ServerAttributes.TENANT_ID).get());
        }
    }
    private final class Pending {
        final Browser browser; final ClientAccount client; final Control control;
        final String body, messageId; final boolean toClient; final int charge; final long created = clock.getAsLong();
        final AtomicBoolean released = new AtomicBoolean(); int attempts;
        final AtomicBoolean completed = new AtomicBoolean();
        Pending(Browser browser, ClientAccount client, Control control, String body, String messageId, boolean toClient, int charge) {
            this.browser = browser; this.client = reference(client); this.control = control; this.body = body; this.messageId = messageId; this.toClient = toClient; this.charge = charge;
        }
        void release() { if (released.compareAndSet(false, true)) { slots.release(); bytes.release(charge); } }
    }
    @Transactional
    public void toClient(WebSocketSession browser, ClientAccount target, String body, String messageId) {
        stage(browser, target, Control.capture(SessionUtil.getChannel(target.getClientName())), body, messageId == null ? "" : messageId, true);
    }
    @Transactional
    public void fromClient(WebSocketSession browser, ClientAccount source, Channel incoming, String body) {
        Control control = Control.capture(incoming);
        if (control == null || !control.current(source)) throw new IllegalArgumentException("source control connection changed");
        stage(browser, source, control, body, "", false);
    }
    private void stage(WebSocketSession session, ClientAccount client, Control control, String body, String messageId, boolean toClient) {
        if (body == null || body.isBlank() || body.length() > MAX_BYTES || messageId.length() > MAX_BYTES) throw new IllegalArgumentException("message-too-large");
        int encoded = body.getBytes(StandardCharsets.UTF_8).length + messageId.getBytes(StandardCharsets.UTF_8).length;
        if (encoded > MAX_BYTES) throw new IllegalArgumentException("message-too-large");
        Browser browser = Browser.capture(session);
        if (!browser.current()) throw new ManagementMessageAuthority.Denied("identity-revoked");
        if (!TransactionSynchronizationManager.isActualTransactionActive() || !TransactionSynchronizationManager.isSynchronizationActive())
            throw new IllegalStateException("management message transaction required");
        int charge = encoded + 8192;
        if (!slots.tryAcquire()) throw new IllegalStateException("server-busy");
        if (!bytes.tryAcquire(charge)) { slots.release(); throw new IllegalStateException("server-busy"); }
        boolean staged = false;
        try {
            var pending = new Pending(browser, client, control, body, messageId, toClient, charge);
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override public void afterCommit() { queue.add(pending); }
                @Override public void afterCompletion(int status) { if (status != STATUS_COMMITTED) pending.release(); }
            });
            staged = true;
        } finally { if (!staged) { slots.release(); bytes.release(charge); } }
    }

    @Scheduled(fixedDelayString = "${specus.management.message-publish-interval-ms:25}")
    public void publishPending() {
        // A scheduled publication must not accidentally join a caller's old/rollbackable TX.
        if (TransactionSynchronizationManager.isActualTransactionActive()) return;
        for (int i = 0; i < 64; i++) {
            Pending pending = queue.poll(); if (pending == null) return;
            boolean retry = false; var attempted = new AtomicBoolean();
            try {
                if (clock.getAsLong() - pending.created > TTL) { error(pending, "message-expired"); continue; }
                if (!pending.browser.current()) continue;
                authority.publish(pending.browser.identity, pending.client, current -> {
                    if (!pending.browser.current()) return;
                    Control control = pending.control;
                    if (control == null || !control.current(current)) throw new ManagementMessageAuthority.Denied("target-offline");
                    try {
                        if (pending.toClient) {
                            if (!controls.verifyReceiver(current, control.authentication, control.channel.id().asLongText()))
                                throw new ManagementMessageAuthority.Denied("target-cannot-receive-message");
                        } else controls.verify(current, control.authentication, control.channel.id().asLongText());
                    } catch (IllegalArgumentException revoked) { throw new ManagementMessageAuthority.Denied("target-offline"); }
                    if (!pending.browser.current() || !control.current(current)) return;
                    attempted.set(true);
                    if (pending.toClient) {
                        var packet = new MessageResponsePacket(); packet.setClientName("admin:" + pending.browser.identity.username());
                        packet.setToClientName(current.getClientName()); packet.setMessageType(MessageType.CLIENT_TO_CLIENT); packet.setMessage(pending.body);
                        control.channel.writeAndFlush(packet).addListener(future -> status(pending, future.isSuccess()));
                    } else send(pending.browser, Map.of("type", "message", "direction", "in", "fromClientName", current.getClientName(),
                            "toClientName", "admin:" + pending.browser.identity.username(), "message", pending.body, "createdAt", Instant.now().toString()));
                });
            } catch (ManagementMessageAuthority.Denied denied) {
                if ("identity-revoked".equals(denied.reason())) closeRevoked(pending.browser); else error(pending, denied.reason());
            } catch (RuntimeException failure) {
                retry = !attempted.get() && ++pending.attempts < 3 && clock.getAsLong() - pending.created <= TTL;
                if (retry) queue.add(pending); else error(pending, attempted.get() ? "delivery-uncertain" : "target-write-failed");
                log.warn("management message publication failed client={} retry={}", pending.client.getId(), retry);
            } finally { if (!retry) pending.release(); }
            if (retry) return;
        }
    }
    private static void error(Pending pending, String reason) {
        if (pending.toClient && pending.completed.compareAndSet(false, true)) send(pending.browser, Map.of("type", "error", "error", reason, "messageId", pending.messageId));
    }
    private static void status(Pending pending, boolean success) {
        if (!pending.completed.compareAndSet(false, true)) return;
        if (success) send(pending.browser, Map.of("type", "written", "messageId", pending.messageId, "toClientName", pending.client.getClientName(), "message", pending.body));
        else send(pending.browser, Map.of("type", "failed", "error", "target-write-failed", "messageId", pending.messageId));
    }
    private static void send(Browser browser, Object payload) {
        try { synchronized (browser.session) { if (browser.current()) browser.session.sendMessage(new TextMessage(JsonUtil.objectToString(payload))); } }
        catch (Exception failed) { throw new IllegalStateException("management websocket write failed", failed); }
    }
    private static void closeRevoked(Browser browser) {
        try { browser.session.close(CloseStatus.POLICY_VIOLATION.withReason(ManagementWebSocketIdentity.REVOKED)); }
        catch (Exception failed) { log.debug("management message close failed"); }
    }
    private static ClientAccount reference(ClientAccount account) {
        var value = new ClientAccount(); value.setId(account.getId()); value.setTenantId(account.getTenantId()); value.setClientName(account.getClientName()); return value;
    }
}
