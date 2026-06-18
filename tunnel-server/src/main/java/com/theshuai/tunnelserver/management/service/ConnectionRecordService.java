package com.theshuai.tunnelserver.management.service;

import com.theshuai.common.protocol.request.LoginRequestPacket;
import com.theshuai.tunnelserver.management.model.ConnectionRecord;
import com.theshuai.tunnelserver.management.model.ConnectionRecordView;
import com.theshuai.tunnelserver.management.repository.ConnectionRecordRepository;
import jakarta.persistence.criteria.Predicate;
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
    private final ConnectionRecordRepository connectionRecordRepository;

    public ConnectionRecordService(ConnectionRecordRepository connectionRecordRepository) {
        this.connectionRecordRepository = connectionRecordRepository;
    }

    /** 写一条连接记录，登录失败时 {@code disconnectedAt} 与 {@code connectedAt} 同时间戳。 */
    @Transactional
    public long recordConnection(AuthenticationResult result, LoginRequestPacket packet,
                                 String channelId, String remoteAddress) {
        String now = Instant.now().toString();
        ConnectionRecord record = new ConnectionRecord();
        record.setClientId(result.account() == null ? null : result.account().getId());
        record.setClientName(packet.getClientName());
        record.setChannelId(channelId);
        record.setRemoteAddress(remoteAddress);
        record.setConnectedAt(now);
        record.setDisconnectedAt(result.success() ? null : now);
        record.setSuccess(result.success());
        record.setFailureReason(result.reason());
        return connectionRecordRepository.save(record).getId();
    }

    @Transactional
    public void recordDisconnect(long connectionRecordId) {
        if (connectionRecordId <= 0) {
            return;
        }
        connectionRecordRepository.findById(connectionRecordId).ifPresent(record -> {
            if (record.getDisconnectedAt() == null) {
                record.setDisconnectedAt(Instant.now().toString());
                connectionRecordRepository.save(record);
            }
        });
    }

    @Transactional(readOnly = true)
    public Page<ConnectionRecordView> listConnections(ConnectionFilter filter, Pageable pageable) {
        Specification<ConnectionRecord> spec = (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();
            if (filter.clientId() != null) {
                predicates.add(cb.equal(root.get("clientId"), filter.clientId()));
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

    private ConnectionRecordView toView(ConnectionRecord record) {
        return new ConnectionRecordView(
                record.getId(),
                record.getClientId(),
                record.getClientName(),
                record.getChannelId(),
                record.getRemoteAddress(),
                record.getConnectedAt(),
                record.getDisconnectedAt(),
                record.isSuccess(),
                record.getFailureReason()
        );
    }

    public record ConnectionFilter(Long clientId, Boolean success, String from, String to) {
    }
}
