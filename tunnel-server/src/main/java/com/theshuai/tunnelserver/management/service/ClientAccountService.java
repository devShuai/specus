package com.theshuai.tunnelserver.management.service;

import com.theshuai.common.protocol.request.LoginRequestPacket;
import com.theshuai.common.security.HmacSigner;
import com.theshuai.tunnelserver.attribute.ServerAttributes;
import com.theshuai.tunnelserver.management.model.ClientAccount;
import com.theshuai.tunnelserver.management.model.ClientAccountView;
import com.theshuai.tunnelserver.management.model.DisconnectReason;
import com.theshuai.tunnelserver.management.repository.ClientAccountRepository;
import com.theshuai.tunnelserver.management.repository.ConnectionRecordRepository;
import com.theshuai.tunnelserver.management.repository.TrafficTotal;
import com.theshuai.tunnelserver.management.repository.TrafficUsageRepository;
import com.theshuai.tunnelserver.management.tenant.TenantContext;
import com.theshuai.tunnelserver.security.PasswordService;
import com.theshuai.tunnelserver.session.SessionUtil;
import io.netty.channel.Channel;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * 客户端账号生命周期管理 + 登录鉴权。
 *
 * <p>这个类原本叫 {@code ClientManagementService}，承担了 5 个领域；按职责拆分后留下的就是
 * "客户端账号"这一个领域：
 * <ul>
 *   <li>账号 CRUD（{@link #createClient}, {@link #updateClient}, {@link #deleteClient}, {@link #listClients}）</li>
 *   <li>登录鉴权（{@link #authenticate}）——产出 {@link AuthenticationResult}，
 *       由调用方决定是否绑定会话/记录连接，本类自身不写连接表</li>
 * </ul>
 *
 * <p>已搬走的功能：
 * <ul>
 *   <li>连接记录（recordConnection / listConnections）→ {@link ConnectionRecordService}</li>
 *   <li>流量列表 → {@link TrafficViewService}</li>
 *   <li>Overview 卡片 → {@link OverviewService}</li>
 * </ul>
 */
@Service
public class ClientAccountService {
    private final ClientAccountRepository clientAccountRepository;
    private final ConnectionRecordRepository connectionRecordRepository;
    private final TrafficUsageRepository trafficUsageRepository;

    public ClientAccountService(ClientAccountRepository clientAccountRepository,
                                ConnectionRecordRepository connectionRecordRepository,
                                TrafficUsageRepository trafficUsageRepository) {
        this.clientAccountRepository = clientAccountRepository;
        this.connectionRecordRepository = connectionRecordRepository;
        this.trafficUsageRepository = trafficUsageRepository;
    }

    @Transactional(readOnly = true)
    public List<ClientAccountView> listClients() {
        return listClients(TenantContext.defaultTenant());
    }

    @Transactional(readOnly = true)
    public List<ClientAccountView> listClients(TenantContext tenant) {
        // 一次性聚合所有客户端的上下行总量，避免 N+1（每客户端一条 findByClientId 查询）。
        Map<Long, TrafficTotal> totals = trafficUsageRepository.sumBytesByTenantId(tenant.tenantId()).stream()
                .collect(Collectors.toMap(TrafficTotal::getClientId, t -> t));
        return clientAccountRepository.findByTenantIdOrderByIdDesc(tenant.tenantId()).stream()
                .map(account -> toView(account, totals.get(account.getId())))
                .toList();
    }

    @Transactional
    public CredentialResult createClient(ClientMutation request) {
        return createClient(TenantContext.defaultTenant(), request);
    }

    @Transactional
    public CredentialResult createClient(TenantContext tenant, ClientMutation request) {
        String clientName = requireClientName(request.clientName());
        clientAccountRepository.findByClientName(clientName).ifPresent(existing -> {
            throw new IllegalArgumentException("clientName " + clientName + " 已存在");
        });
        String password = StringUtils.hasText(request.password())
                ? request.password() : PasswordService.generatePassword();
        String now = Instant.now().toString();

        ClientAccount account = new ClientAccount();
        account.setId(ClientIdGenerator.newId());
        account.setTenantId(tenant.tenantId());
        account.setClientName(clientName);
        account.setPasswordHash(PasswordService.hash(password));
        account.setEnabled(request.enabled() == null || request.enabled());
        account.setConnectionRateLimitPerMinute(normalizeRateLimit(request.connectionRateLimitPerMinute(), 30));
        account.setCreatedAt(now);
        account.setUpdatedAt(now);
        return new CredentialResult(toView(clientAccountRepository.save(account), null), password);
    }

    @Transactional
    public CredentialResult updateClient(long id, ClientMutation request) {
        return updateClient(TenantContext.defaultTenant(), id, request);
    }

    @Transactional
    public CredentialResult updateClient(TenantContext tenant, long id, ClientMutation request) {
        ClientAccount account = findClientById(tenant, id);
        String originalClientName = account.getClientName();
        String newClientName = StringUtils.hasText(request.clientName())
                ? requireClientName(request.clientName())
                : originalClientName;
        if (!newClientName.equals(originalClientName)) {
            clientAccountRepository.findByClientName(newClientName).ifPresent(existing -> {
                throw new IllegalArgumentException("clientName " + newClientName + " 已存在");
            });
        }
        account.setClientName(newClientName);
        if (StringUtils.hasText(request.password())) {
            account.setPasswordHash(PasswordService.hash(request.password()));
        }
        if (request.enabled() != null) {
            account.setEnabled(request.enabled());
        }
        account.setConnectionRateLimitPerMinute(normalizeRateLimit(
                request.connectionRateLimitPerMinute(),
                account.getConnectionRateLimitPerMinute()
        ));
        account.setUpdatedAt(Instant.now().toString());
        clientAccountRepository.save(account);
        if (!account.isEnabled() || !account.getClientName().equals(originalClientName)) {
            // 优先用"停用"作为原因（更直接），若只是改名则用 ADMIN_RENAMED。
            DisconnectReason reason = !account.isEnabled()
                    ? DisconnectReason.ADMIN_DISABLED
                    : DisconnectReason.ADMIN_RENAMED;
            closeOnlineChannel(originalClientName, reason);
        }
        TrafficTotal total = trafficUsageRepository
                .sumBytesByTenantIdAndClientId(tenant.tenantId(), account.getId())
                .orElse(null);
        return new CredentialResult(toView(account, total), request.password());
    }

    @Transactional
    public void deleteClient(long id) {
        deleteClient(TenantContext.defaultTenant(), id);
    }

    @Transactional
    public void deleteClient(TenantContext tenant, long id) {
        ClientAccount account = findClientById(tenant, id);
        closeOnlineChannel(account.getClientName(), DisconnectReason.ADMIN_DELETED);
        clientAccountRepository.delete(account);
    }

    @Transactional(readOnly = true)
    public AuthenticationResult authenticate(LoginRequestPacket packet) {
        Optional<ClientAccount> optionalAccount = findClientByName(packet.getClientName());
        if (optionalAccount.isEmpty()) {
            return AuthenticationResult.failure(null, "客户端不存在");
        }
        ClientAccount account = optionalAccount.get();
        if (!account.isEnabled()) {
            return AuthenticationResult.failure(account, "客户端已停用");
        }
        if (hasExceededRateLimit(account)) {
            return AuthenticationResult.failure(account, "连接频率超过限制");
        }
        if (!hasValidSignature(packet, account)) {
            return AuthenticationResult.failure(account, "签名无效或已过期");
        }
        return AuthenticationResult.success(account);
    }

    @Transactional(readOnly = true)
    public Optional<ClientAccount> findClientByName(String clientName) {
        return clientAccountRepository.findByClientName(clientName);
    }

    private ClientAccount findClientById(long id) {
        return clientAccountRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("client not found: " + id));
    }

    public ClientAccount findClientById(TenantContext tenant, long id) {
        return clientAccountRepository.findByIdAndTenantId(id, tenant.tenantId())
                .orElseThrow(() -> new IllegalArgumentException("client not found: " + id));
    }

    private ClientAccountView toView(ClientAccount account, TrafficTotal total) {
        Channel channel = SessionUtil.getChannel(account.getClientName());
        boolean online = channel != null;
        Long connectedSinceMs = online ? channel.attr(ServerAttributes.LOGIN_TIME_MS).get() : null;
        long uploadBytes = total == null ? 0L : total.getUploadBytes();
        long downloadBytes = total == null ? 0L : total.getDownloadBytes();
        return new ClientAccountView(
                account.getId(),
                account.getClientName(),
                account.isEnabled(),
                account.getConnectionRateLimitPerMinute(),
                online,
                connectedSinceMs,
                uploadBytes,
                downloadBytes,
                account.getCreatedAt(),
                account.getUpdatedAt()
        );
    }

    private boolean hasExceededRateLimit(ClientAccount account) {
        return account.getConnectionRateLimitPerMinute() > 0
                && connectionRecordRepository.countByTenantIdAndClientIdAndConnectedAtGreaterThanEqual(
                account.getTenantId(),
                account.getId(),
                Instant.now().minus(1, ChronoUnit.MINUTES).toString()
        ) >= account.getConnectionRateLimitPerMinute();
    }

    private boolean hasValidSignature(LoginRequestPacket packet, ClientAccount account) {
        if (packet.getClientName() == null || packet.getTimestamp() == null
                || packet.getNonce() == null || packet.getCheckSign() == null) {
            return false;
        }
        if (packet.getCheckSign().length != HmacSigner.signatureLength()) {
            return false;
        }
        long ts;
        try {
            ts = Long.parseLong(packet.getTimestamp());
        } catch (NumberFormatException e) {
            return false;
        }
        if (Math.abs(ts - System.currentTimeMillis()) > 30_000L) {
            return false;
        }
        byte[] key;
        try {
            key = HmacSigner.decodeHex(account.getPasswordHash());
        } catch (IllegalArgumentException e) {
            // Stored hash is corrupt — fail closed.
            return false;
        }
        String message = packet.getClientName() + "\n" + packet.getTimestamp() + "\n" + packet.getNonce();
        byte[] expected = HmacSigner.hmacSha256(key, message);
        return java.security.MessageDigest.isEqual(expected, packet.getCheckSign());
    }

    private void closeOnlineChannel(String clientName, DisconnectReason reason) {
        Channel channel = SessionUtil.getChannel(clientName);
        if (channel != null) {
            DisconnectReason.markIfAbsent(channel, reason);
            channel.close();
        }
    }

    private String requireClientName(String clientName) {
        if (!StringUtils.hasText(clientName)) {
            throw new IllegalArgumentException("clientName cannot be blank");
        }
        String normalized = clientName.trim();
        if (normalized.length() > 120) {
            throw new IllegalArgumentException("clientName is too long");
        }
        return normalized;
    }

    private int normalizeRateLimit(Integer rateLimit, int defaultValue) {
        int normalized = rateLimit == null ? defaultValue : rateLimit;
        if (normalized < 0 || normalized > 10000) {
            throw new IllegalArgumentException("connectionRateLimitPerMinute must be between 0 and 10000");
        }
        return normalized;
    }

    public record ClientMutation(
            String clientName,
            String password,
            Boolean enabled,
            Integer connectionRateLimitPerMinute
    ) {
    }

    public record CredentialResult(ClientAccountView client, String password) {
    }
}
