package com.theshuai.tunnelserver.management.service;

import com.theshuai.common.handler.LoginRequestHandler;
import com.theshuai.common.protocol.request.LoginRequestPacket;
import com.theshuai.common.util.SessionUtil;
import com.theshuai.tunnelserver.management.model.ClientAccount;
import com.theshuai.tunnelserver.management.model.ClientAccountView;
import com.theshuai.tunnelserver.management.model.ConnectionRecord;
import com.theshuai.tunnelserver.management.model.ConnectionRecordView;
import com.theshuai.tunnelserver.management.model.TrafficUsage;
import com.theshuai.tunnelserver.management.model.TrafficUsageView;
import com.theshuai.tunnelserver.management.repository.ClientAccountRepository;
import com.theshuai.tunnelserver.management.repository.ConnectionRecordRepository;
import com.theshuai.tunnelserver.management.repository.TrafficUsageRepository;
import com.theshuai.tunnelserver.security.PasswordService;
import io.netty.channel.Channel;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.DigestUtils;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class ClientManagementService {
    private final ClientAccountRepository clientAccountRepository;
    private final ConnectionRecordRepository connectionRecordRepository;
    private final TrafficUsageRepository trafficUsageRepository;

    public ClientManagementService(ClientAccountRepository clientAccountRepository,
                                   ConnectionRecordRepository connectionRecordRepository,
                                   TrafficUsageRepository trafficUsageRepository) {
        this.clientAccountRepository = clientAccountRepository;
        this.connectionRecordRepository = connectionRecordRepository;
        this.trafficUsageRepository = trafficUsageRepository;
    }

    @Transactional(readOnly = true)
    public List<ClientAccountView> listClients() {
        return clientAccountRepository.findAll().stream()
                .sorted((left, right) -> Long.compare(right.getId(), left.getId()))
                .map(this::toView)
                .toList();
    }

    @Transactional
    public CredentialResult createClient(ClientMutation request) {
        String clientName = requireClientName(request.clientName());
        String password = StringUtils.hasText(request.password()) ? request.password() : PasswordService.generatePassword();
        String now = Instant.now().toString();

        ClientAccount account = new ClientAccount();
        account.setId(ClientIdGenerator.newId());
        account.setClientName(clientName);
        account.setPasswordHash(PasswordService.hash(password));
        account.setEnabled(request.enabled() == null || request.enabled());
        account.setConnectionRateLimitPerMinute(normalizeRateLimit(request.connectionRateLimitPerMinute(), 30));
        account.setCreatedAt(now);
        account.setUpdatedAt(now);
        return new CredentialResult(toView(clientAccountRepository.save(account)), password);
    }

    @Transactional
    public CredentialResult updateClient(long id, ClientMutation request) {
        ClientAccount account = findClientById(id);
        String originalClientName = account.getClientName();
        account.setClientName(StringUtils.hasText(request.clientName())
                ? requireClientName(request.clientName())
                : originalClientName);
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
            closeOnlineChannel(originalClientName);
        }
        return new CredentialResult(toView(account), request.password());
    }

    @Transactional
    public void deleteClient(long id) {
        ClientAccount account = findClientById(id);
        closeOnlineChannel(account.getClientName());
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
        if (!PasswordService.matches(packet.getPassword(), account.getPasswordHash())) {
            return AuthenticationResult.failure(account, "客户端名称或密码错误");
        }
        if (!hasValidSignature(packet)) {
            return AuthenticationResult.failure(account, "签名无效或已过期");
        }
        return AuthenticationResult.success(account);
    }

    @Transactional
    public long recordConnection(AuthenticationResult result, LoginRequestPacket packet, String channelId, String remoteAddress) {
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
    public List<ConnectionRecordView> listConnections(Long clientId, int limit) {
        PageRequest pageRequest = PageRequest.of(0, normalizeListLimit(limit));
        List<ConnectionRecord> records = clientId == null
                ? connectionRecordRepository.findAllByOrderByIdDesc(pageRequest)
                : connectionRecordRepository.findByClientIdOrderByIdDesc(clientId, pageRequest);
        return records.stream().map(this::toView).toList();
    }

    @Transactional(readOnly = true)
    public List<TrafficUsageView> listTraffic(Long clientId, int limit) {
        PageRequest pageRequest = PageRequest.of(0, normalizeListLimit(limit));
        List<TrafficUsage> usages = clientId == null
                ? trafficUsageRepository.findAllByOrderByUsageDateDescIdDesc(pageRequest)
                : trafficUsageRepository.findByClientIdOrderByUsageDateDescIdDesc(clientId, pageRequest);
        return usages.stream().map(this::toView).toList();
    }

    @Transactional(readOnly = true)
    public Map<String, Object> overview() {
        List<ClientAccountView> clients = listClients();
        Map<String, Object> overview = new LinkedHashMap<>();
        overview.put("clients", clients.size());
        overview.put("onlineClients", clients.stream().filter(ClientAccountView::online).count());
        overview.put("successfulConnections", connectionRecordRepository.countBySuccess(true));
        overview.put("failedConnections", connectionRecordRepository.countBySuccess(false));
        overview.put("uploadBytes", clients.stream().mapToLong(ClientAccountView::uploadBytes).sum());
        overview.put("downloadBytes", clients.stream().mapToLong(ClientAccountView::downloadBytes).sum());
        return overview;
    }

    @Transactional(readOnly = true)
    public Optional<ClientAccount> findClientByName(String clientName) {
        return clientAccountRepository.findByClientName(clientName);
    }

    private ClientAccount findClientById(long id) {
        return clientAccountRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("client not found: " + id));
    }

    private ClientAccountView toView(ClientAccount account) {
        List<TrafficUsage> usages = trafficUsageRepository.findByClientId(account.getId());
        return new ClientAccountView(
                account.getId(),
                account.getClientName(),
                account.isEnabled(),
                account.getConnectionRateLimitPerMinute(),
                SessionUtil.getChannel(account.getClientName()) != null,
                usages.stream().mapToLong(TrafficUsage::getUploadBytes).sum(),
                usages.stream().mapToLong(TrafficUsage::getDownloadBytes).sum(),
                account.getCreatedAt(),
                account.getUpdatedAt()
        );
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

    private TrafficUsageView toView(TrafficUsage usage) {
        return new TrafficUsageView(
                usage.getId(),
                usage.getClientId(),
                usage.getClientName(),
                usage.getUsageDate(),
                usage.getUploadBytes(),
                usage.getDownloadBytes(),
                usage.getUpdatedAt()
        );
    }

    private boolean hasExceededRateLimit(ClientAccount account) {
        return account.getConnectionRateLimitPerMinute() > 0
                && connectionRecordRepository.countByClientIdAndConnectedAtGreaterThanEqual(
                account.getId(),
                Instant.now().minus(1, ChronoUnit.MINUTES).toString()
        ) >= account.getConnectionRateLimitPerMinute();
    }

    private boolean hasValidSignature(LoginRequestPacket packet) {
        try {
            if (Math.abs(Long.parseLong(packet.getTimestamp()) - System.currentTimeMillis()) > 30 * 1000) {
                return false;
            }
            String signString = LoginRequestHandler.md5Salt + packet.getClientName()
                    + packet.getPassword() + packet.getTimestamp();
            return DigestUtils.md5DigestAsHex(signString.getBytes(StandardCharsets.UTF_8))
                    .equals(packet.getCheckSign());
        } catch (RuntimeException e) {
            return false;
        }
    }

    private void closeOnlineChannel(String clientName) {
        Channel channel = SessionUtil.getChannel(clientName);
        if (channel != null) {
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

    private int normalizeListLimit(int limit) {
        return Math.max(1, Math.min(limit, 500));
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

    public record AuthenticationResult(boolean success, ClientAccount account, String reason) {
        public static AuthenticationResult success(ClientAccount account) {
            return new AuthenticationResult(true, account, null);
        }

        public static AuthenticationResult failure(ClientAccount account, String reason) {
            return new AuthenticationResult(false, account, reason);
        }
    }
}
