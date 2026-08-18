package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.attribute.ServerAttributes;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.model.ClientAccountView;
import com.theshuai.specusserver.management.model.ClientSession;
import com.theshuai.specusserver.management.model.DisconnectReason;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.ClientNameReferenceRepository;
import com.theshuai.specusserver.management.repository.ClientSessionRepository;
import com.theshuai.specusserver.management.repository.TrafficTotal;
import com.theshuai.specusserver.management.repository.TrafficUsageRepository;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.tenant.TenantContext;
import com.theshuai.specusserver.security.PasswordService;
import com.theshuai.specusserver.session.SessionUtil;
import io.netty.channel.Channel;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * 客户端账号生命周期管理。
 *
 * <p>这个类原本叫 {@code ClientManagementService}，承担了 5 个领域；按职责拆分后留下的就是
 * "客户端账号"这一个领域：
 * <ul>
 *   <li>账号 CRUD（{@link #createClient}, {@link #updateClient}, {@link #deleteClient}, {@link #listClients}）</li>
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
    private final TrafficUsageRepository trafficUsageRepository;
    private final ClientSessionRepository clientSessionRepository;
    private final ClientNameReferenceRepository clientNameReferenceRepository;

    public ClientAccountService(ClientAccountRepository clientAccountRepository,
                                TrafficUsageRepository trafficUsageRepository,
                                ClientSessionRepository clientSessionRepository,
                                ClientNameReferenceRepository clientNameReferenceRepository) {
        this.clientAccountRepository = clientAccountRepository;
        this.trafficUsageRepository = trafficUsageRepository;
        this.clientSessionRepository = clientSessionRepository;
        this.clientNameReferenceRepository = clientNameReferenceRepository;
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
        List<ClientAccount> accounts = clientAccountRepository.findByTenantIdOrderByIdDesc(tenant.tenantId());
        Map<Long, ClientSession> activeSessions = activeSessionMap(tenant.tenantId(), accounts);
        return accounts.stream()
                .map(account -> toView(account, totals.get(account.getId()), activeSessions.get(account.getId())))
                .toList();
    }

    @Transactional(readOnly = true)
    public List<ClientAccountView> listClients(ManagementContext context) {
        Map<Long, TrafficTotal> totals = trafficUsageRepository.sumBytesByTenantId(context.tenant().tenantId()).stream()
                .collect(Collectors.toMap(TrafficTotal::getClientId, t -> t));
        List<ClientAccount> accounts = visibleAccounts(context);
        Map<Long, ClientSession> activeSessions = activeSessionMap(context.tenant().tenantId(), accounts);
        return accounts.stream()
                .map(account -> toView(account, totals.get(account.getId()), activeSessions.get(account.getId())))
                .toList();
    }

    @Transactional
    public ClientResult createClient(ClientMutation request) {
        return createClient(TenantContext.defaultTenant(), request);
    }

    @Transactional
    public ClientResult createClient(TenantContext tenant, ClientMutation request) {
        String clientName = requireClientName(request.clientName());
        clientAccountRepository.findByClientName(clientName).ifPresent(existing -> {
            throw new IllegalArgumentException("clientName " + clientName + " 已存在");
        });
        String now = Instant.now().toString();

        ClientAccount account = new ClientAccount();
        account.setId(ClientIdGenerator.newId());
        account.setTenantId(tenant.tenantId());
        account.setClientName(clientName);
        account.setPasswordHash(PasswordService.hashToken(PasswordService.generatePassword()));
        account.setEnabled(request.enabled() == null || request.enabled());
        account.setConnectionRateLimitPerMinute(normalizeRateLimit(request.connectionRateLimitPerMinute(), 30));
        account.setCreatedAt(now);
        account.setUpdatedAt(now);
        invalidateNameCache(account.getClientName());
        return new ClientResult(toView(clientAccountRepository.save(account), null, null));
    }

    @Transactional
    public ClientResult createClient(ManagementContext context, ClientMutation request) {
        String clientName = requireClientName(request.clientName());
        clientAccountRepository.findByClientName(clientName).ifPresent(existing -> {
            throw new IllegalArgumentException("clientName " + clientName + " 已存在");
        });
        String now = Instant.now().toString();

        ClientAccount account = new ClientAccount();
        account.setId(ClientIdGenerator.newId());
        account.setTenantId(context.tenant().tenantId());
        account.setOwnerUsername(context.username());
        account.setClientName(clientName);
        account.setPasswordHash(PasswordService.hashToken(PasswordService.generatePassword()));
        account.setEnabled(request.enabled() == null || request.enabled());
        account.setConnectionRateLimitPerMinute(normalizeRateLimit(request.connectionRateLimitPerMinute(), 30));
        account.setCreatedAt(now);
        account.setUpdatedAt(now);
        invalidateNameCache(account.getClientName());
        return new ClientResult(toView(clientAccountRepository.save(account), null, null));
    }

    @Transactional
    public ClientResult updateClient(long id, ClientMutation request) {
        return updateClient(TenantContext.defaultTenant(), id, request);
    }

    @Transactional
    public ClientResult updateClient(TenantContext tenant, long id, ClientMutation request) {
        ClientAccount account = findClientById(tenant, id);
        return updateClient(tenant, account, request);
    }

    @Transactional
    public ClientResult updateClient(ManagementContext context, long id, ClientMutation request) {
        ClientAccount account = findClientById(context, id);
        return updateClient(context.tenant(), account, request);
    }

    @Transactional(readOnly = true)
    public ClientNameAvailability checkClientNameAvailability(ManagementContext context,
                                                              String requestedClientName,
                                                              Long excludeClientId) {
        String clientName = requireClientName(requestedClientName);
        ClientAccount excluded = excludeClientId == null ? null : findClientById(context, excludeClientId);
        boolean available = clientAccountRepository.findByClientName(clientName)
                .map(existing -> excluded != null && existing.getId().equals(excluded.getId()))
                .orElse(true);
        return new ClientNameAvailability(clientName, available);
    }

    private ClientResult updateClient(TenantContext tenant, ClientAccount account, ClientMutation request) {
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
        if (request.enabled() != null) {
            account.setEnabled(request.enabled());
        }
        account.setConnectionRateLimitPerMinute(normalizeRateLimit(
                request.connectionRateLimitPerMinute(),
                account.getConnectionRateLimitPerMinute()
        ));
        String updatedAt = Instant.now().toString();
        account.setUpdatedAt(updatedAt);
        invalidateNameCache(originalClientName);
        if (!newClientName.equals(originalClientName)) {
            invalidateNameCache(newClientName);
        }
        clientAccountRepository.saveAndFlush(account);
        if (!newClientName.equals(originalClientName)) {
            clientNameReferenceRepository.rename(account.getId(), newClientName, updatedAt);
        }
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
        return new ClientResult(toView(account, total, null));
    }

    @Transactional
    public void deleteClient(long id) {
        deleteClient(TenantContext.defaultTenant(), id);
    }

    @Transactional
    public void deleteClient(TenantContext tenant, long id) {
        ClientAccount account = findClientById(tenant, id);
        closeOnlineChannel(account.getClientName(), DisconnectReason.ADMIN_DELETED);
        invalidateNameCache(account.getClientName());
        clientAccountRepository.delete(account);
    }

    @Transactional
    public void deleteClient(ManagementContext context, long id) {
        ClientAccount account = findClientById(context, id);
        closeOnlineChannel(account.getClientName(), DisconnectReason.ADMIN_DELETED);
        invalidateNameCache(account.getClientName());
        clientAccountRepository.delete(account);
    }

    @Transactional(readOnly = true)
    public Optional<ClientAccount> findClientByName(String clientName) {
        if (clientName == null) {
            return Optional.empty();
        }
        // S1.3 60 秒 TTL 名称缓存。trafficUsageService.flushCounter() 每 5 秒为每个活跃
        // 客户端调一次本方法，加缓存后稳定状态下 DB 查询量降到 ~1/12。
        CachedClient cached = nameCache.get(clientName);
        long now = System.currentTimeMillis();
        if (cached != null && cached.expiresAtMillis > now) {
            return Optional.ofNullable(cached.account);
        }
        Optional<ClientAccount> fresh = clientAccountRepository.findByClientName(clientName);
        nameCache.put(clientName, new CachedClient(fresh.orElse(null), now + NAME_CACHE_TTL_MILLIS));
        return fresh;
    }

    /** 缓存任何客户端账号被增/改/删后调用，确保下次 findClientByName 拿到最新。 */
    private void invalidateNameCache(String clientName) {
        if (clientName != null) {
            nameCache.remove(clientName);
        }
    }

    /** 60s TTL 缓存条目；过期则从 DB 重读。 */
    private record CachedClient(ClientAccount account, long expiresAtMillis) {}

    private static final long NAME_CACHE_TTL_MILLIS = 60_000;
    private final Map<String, CachedClient> nameCache = new ConcurrentHashMap<>();

    private ClientAccount findClientById(long id) {
        return clientAccountRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("client not found: " + id));
    }

    public ClientAccount findClientById(TenantContext tenant, long id) {
        return clientAccountRepository.findByIdAndTenantId(id, tenant.tenantId())
                .orElseThrow(() -> new IllegalArgumentException("client not found: " + id));
    }

    public ClientAccount findClientById(ManagementContext context, long id) {
        Optional<ClientAccount> account = context.isAdmin()
                ? clientAccountRepository.findByIdAndTenantId(id, context.tenant().tenantId())
                : clientAccountRepository.findByIdAndTenantIdAndOwnerUsername(
                        id, context.tenant().tenantId(), context.username());
        return account.orElseThrow(() -> new IllegalArgumentException("client not found: " + id));
    }

    @Transactional(readOnly = true)
    public List<Long> visibleClientIds(ManagementContext context) {
        return visibleAccounts(context).stream().map(ClientAccount::getId).toList();
    }

    @Transactional(readOnly = true)
    public boolean canAccessClient(ManagementContext context, Long clientId) {
        if (clientId == null) {
            return true;
        }
        if (context.isAdmin()) {
            return clientAccountRepository.findByIdAndTenantId(clientId, context.tenant().tenantId()).isPresent();
        }
        return clientAccountRepository.findByIdAndTenantIdAndOwnerUsername(
                clientId, context.tenant().tenantId(), context.username()).isPresent();
    }

    private List<ClientAccount> visibleAccounts(ManagementContext context) {
        return context.isAdmin()
                ? clientAccountRepository.findByTenantIdOrderByIdDesc(context.tenant().tenantId())
                : clientAccountRepository.findByTenantIdAndOwnerUsernameOrderByIdDesc(
                        context.tenant().tenantId(), context.username());
    }

    private Map<Long, ClientSession> activeSessionMap(String tenantId, List<ClientAccount> accounts) {
        if (accounts == null || accounts.isEmpty()) {
            return Map.of();
        }
        List<Long> clientIds = accounts.stream().map(ClientAccount::getId).toList();
        return clientSessionRepository
                .findByTenantIdAndClientIdInAndStatus(tenantId, clientIds, ClientAuthService.STATUS_NETTY_ONLINE)
                .stream()
                .collect(Collectors.toMap(
                        ClientSession::getClientId,
                        session -> session,
                        this::newerSession
                ));
    }

    private ClientSession newerSession(ClientSession left, ClientSession right) {
        String leftAt = left.getNettyConnectedAt();
        String rightAt = right.getNettyConnectedAt();
        if (leftAt == null) {
            return right;
        }
        if (rightAt == null) {
            return left;
        }
        return leftAt.compareTo(rightAt) >= 0 ? left : right;
    }

    private ClientAccountView toView(ClientAccount account, TrafficTotal total, ClientSession activeSession) {
        Channel channel = SessionUtil.getChannel(account.getClientName());
        boolean online = channel != null;
        Long connectedSinceMs = online ? channel.attr(ServerAttributes.LOGIN_TIME_MS).get() : null;
        ClientSession messageSession = online ? activeSession : null;
        long uploadBytes = total == null ? 0L : total.getUploadBytes();
        long downloadBytes = total == null ? 0L : total.getDownloadBytes();
        return new ClientAccountView(
                account.getId(),
                account.getClientName(),
                account.getOwnerUsername(),
                account.isEnabled(),
                account.getConnectionRateLimitPerMinute(),
                online,
                connectedSinceMs,
                messageSession == null ? null : messageSession.getClientVersion(),
                messageSession != null && messageSession.isMessageSendCapable(),
                messageSession != null && messageSession.isMessageReceiveCapable(),
                messageSession != null && messageSession.isMessageAttachmentsCapable(),
                messageSession != null && messageSession.isMessageMediaPreviewCapable(),
                messageSession == null ? 0L : messageSession.getMessageMaxAttachmentBytes(),
                uploadBytes,
                downloadBytes,
                account.getCreatedAt(),
                account.getUpdatedAt()
        );
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
            Boolean enabled,
            Integer connectionRateLimitPerMinute
    ) {
    }

    public record ClientResult(ClientAccountView client) {
    }

    public record ClientNameAvailability(String clientName, boolean available) {
    }
}
