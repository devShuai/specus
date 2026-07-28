package com.theshuai.specusserver.management.service;

import com.theshuai.common.protocol.request.LoginRequestPacket;
import com.theshuai.specusserver.management.model.ConnectionRecord;
import com.theshuai.specusserver.management.model.ConnectionRecordView;
import com.theshuai.specusserver.management.model.DisconnectReason;
import com.theshuai.specusserver.management.repository.ConnectionRecordRepository;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.tenant.TenantContext;
import com.theshuai.specusserver.websocket.ConnectionEvent;
import jakarta.persistence.criteria.Predicate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.event.ContextClosedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * 控制连接的登录 / 退出事件持久化与查询。从原 {@code ClientManagementService} 中拆出，
 * 让"账号管理"和"连接审计"两个领域各自有自己的事务边界。
 */
@Service
public class ConnectionRecordService {
    private static final Logger log = LoggerFactory.getLogger(ConnectionRecordService.class);

    private final ConnectionRecordRepository connectionRecordRepository;
    private final ClientAccountService clientAccountService;
    private final ApplicationEventPublisher events;

    public ConnectionRecordService(ConnectionRecordRepository connectionRecordRepository,
                                   ClientAccountService clientAccountService,
                                   ApplicationEventPublisher events) {
        this.connectionRecordRepository = connectionRecordRepository;
        this.clientAccountService = clientAccountService;
        this.events = events;
    }

    /** 写一条连接记录，登录失败时 {@code disconnectedAt} 与 {@code connectedAt} 同时间戳。 */
    @Transactional
    public long recordConnection(AuthenticationResult result, LoginRequestPacket packet,
                                 String channelId, String remoteAddress) {
        String now = Instant.now().toString();
        ConnectionRecord record = new ConnectionRecord();
        String tenantId = result.account() == null
                ? TenantContext.DEFAULT_TENANT_ID
                : TenantContext.normalize(result.account().getTenantId());
        record.setTenantId(tenantId);
        record.setClientId(result.account() == null ? null : result.account().getId());
        String clientName = result.account() == null ? packet.getClientName() : result.account().getClientName();
        record.setClientName(StringUtils.hasText(clientName) ? clientName : "unknown-client");
        record.setChannelId(channelId);
        record.setRemoteAddress(remoteAddress);
        record.setConnectedAt(now);
        record.setDisconnectedAt(result.success() ? null : now);
        record.setSuccess(result.success());
        record.setFailureReason(result.reason());
        // 登录失败直接落 LOGIN_FAILURE；成功的行等 channelInactive 再写。
        if (!result.success()) {
            record.setDisconnectReason(DisconnectReason.LOGIN_FAILURE.name());
        }
        ConnectionRecord saved = connectionRecordRepository.save(record);
        // AFTER_COMMIT 才真正推 WebSocket（见 ConnectionEventBroadcaster），这里只是发布事务事件。
        events.publishEvent(ConnectionEvent.created(tenantId, toView(saved)));
        return saved.getId();
    }

    @Transactional
    public void recordDisconnect(long connectionRecordId, DisconnectReason reason) {
        if (connectionRecordId <= 0) {
            return;
        }
        DisconnectReason effective = reason == null ? DisconnectReason.UNKNOWN : reason;
        connectionRecordRepository.findById(connectionRecordId).ifPresent(record -> {
            boolean dirty = false;
            if (record.getDisconnectedAt() == null) {
                record.setDisconnectedAt(Instant.now().toString());
                dirty = true;
            }
            if (record.getDisconnectReason() == null) {
                record.setDisconnectReason(effective.name());
                dirty = true;
            }
            if (dirty) {
                ConnectionRecord saved = connectionRecordRepository.save(record);
                events.publishEvent(ConnectionEvent.updated(
                        TenantContext.normalize(saved.getTenantId()), toView(saved)));
            }
        });
    }

    /**
     * 服务端进程被 kill / 重启时，Netty 的 {@code channelInactive} 不会执行，那些登录成功的
     * 连接记录会停在 {@code disconnectedAt = null}，前端按"未断开"持续累计在线时长。
     * <p>启动后立即把启动前还没收尾的记录全部关掉，cutoff 用 {@link Instant#now()}，
     * 避免误伤启动过程中刚进来的新连接（它们的 connectedAt &gt;= cutoff）。
     */
    @EventListener(ApplicationReadyEvent.class)
    @Transactional
    public void closeStaleOpenRecordsOnStartup() {
        String cutoff = Instant.now().toString();
        int closed = connectionRecordRepository.closeOpenRecordsBefore(
                cutoff, DisconnectReason.SERVER_RESTARTED.name());
        if (closed > 0) {
            log.info("closed {} stale open connection record(s) at startup (cutoff={}, reason={})",
                    closed, cutoff, DisconnectReason.SERVER_RESTARTED);
        }
    }

    /**
     * Spring 容器关闭时（systemctl stop / kill -TERM 经过 graceful shutdown）触发。
     * 此刻 {@code loginExecutor} 已经在 shutdown，channelInactive 派发的 recordDisconnect 任务
     * 大概率会被拒掉。这里直接在调用线程里做一次 bulk update，把所有仍在线的记录收尾。
     */
    @EventListener(ContextClosedEvent.class)
    @Transactional
    public void markAllOpenAsShutdownOnContextClose() {
        String now = Instant.now().toString();
        int closed = connectionRecordRepository.markAllOpenAsClosed(
                now, DisconnectReason.SERVER_SHUTDOWN.name());
        if (closed > 0) {
            log.info("marked {} open connection record(s) as {} during graceful shutdown",
                    closed, DisconnectReason.SERVER_SHUTDOWN);
        }
    }

    @Transactional(readOnly = true)
    public Page<ConnectionRecordView> listConnections(ConnectionFilter filter, Pageable pageable) {
        return listConnections(TenantContext.defaultTenant(), filter, pageable);
    }

    @Transactional(readOnly = true)
    public Page<ConnectionRecordView> listConnections(TenantContext tenant, ConnectionFilter filter, Pageable pageable) {
        return listConnections(tenant, filter, null, pageable);
    }

    @Transactional(readOnly = true)
    public Page<ConnectionRecordView> listConnections(ManagementContext context, ConnectionFilter filter, Pageable pageable) {
        List<Long> visibleClientIds = context.isAdmin() ? null : clientAccountService.visibleClientIds(context);
        if (isDenied(visibleClientIds, filter.clientId())) {
            return Page.empty(pageable);
        }
        return listConnections(context.tenant(), filter, visibleClientIds, pageable);
    }

    private Page<ConnectionRecordView> listConnections(TenantContext tenant,
                                                       ConnectionFilter filter,
                                                       List<Long> visibleClientIds,
                                                       Pageable pageable) {
        Specification<ConnectionRecord> spec = (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();
            predicates.add(cb.equal(root.get("tenantId"), tenant.tenantId()));
            if (filter.clientId() != null) {
                predicates.add(cb.equal(root.get("clientId"), filter.clientId()));
            } else if (visibleClientIds != null) {
                predicates.add(root.get("clientId").in(visibleClientIds));
            }
            if (filter.success() != null) {
                predicates.add(cb.equal(root.get("success"), filter.success()));
            }
            if (StringUtils.hasText(filter.from())) {
                predicates.add(cb.greaterThanOrEqualTo(root.get("connectedAt"), filter.from()));
            }
            if (StringUtils.hasText(filter.to())) {
                predicates.add(cb.lessThanOrEqualTo(root.get("connectedAt"), filter.to()));
            }
            return predicates.isEmpty() ? cb.conjunction() : cb.and(predicates.toArray(new Predicate[0]));
        };
        return connectionRecordRepository.findAll(spec, pageable).map(this::toView);
    }

    private boolean isDenied(List<Long> visibleClientIds, Long clientId) {
        if (visibleClientIds == null) {
            return false;
        }
        return visibleClientIds.isEmpty() || (clientId != null && !visibleClientIds.contains(clientId));
    }

    private ConnectionRecordView toView(ConnectionRecord record) {
        DisconnectReason reason = DisconnectReason.parse(record.getDisconnectReason());
        return new ConnectionRecordView(
                record.getId(),
                record.getClientId(),
                record.getClientName(),
                record.getChannelId(),
                record.getRemoteAddress(),
                record.getConnectedAt(),
                record.getDisconnectedAt(),
                record.isSuccess(),
                record.getFailureReason(),
                reason == null ? null : reason.name(),
                reason == null ? null : reason.label()
        );
    }

    public record ConnectionFilter(Long clientId, Boolean success, String from, String to) {
    }
}
