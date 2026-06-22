package com.theshuai.tunnelserver.management.service;

import com.theshuai.common.clientauth.ClientAuthLoginRequest;
import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import com.theshuai.common.clientauth.ClientAuthSigner;
import com.theshuai.common.clientauth.ClientEnvironmentInfo;
import com.theshuai.common.protocol.request.LoginRequestPacket;
import com.theshuai.common.security.HmacSigner;
import com.theshuai.tunnelserver.config.ClientAuthProperties;
import com.theshuai.tunnelserver.config.NettyServerProperties;
import com.theshuai.tunnelserver.management.model.ClientAccount;
import com.theshuai.tunnelserver.management.model.ClientCredential;
import com.theshuai.tunnelserver.management.model.ClientIdentity;
import com.theshuai.tunnelserver.management.model.ClientSession;
import com.theshuai.tunnelserver.management.model.HttpRouteMapping;
import com.theshuai.tunnelserver.management.model.TunnelMapping;
import com.theshuai.tunnelserver.management.repository.ClientAccountRepository;
import com.theshuai.tunnelserver.management.repository.ClientCredentialRepository;
import com.theshuai.tunnelserver.management.repository.ClientIdentityRepository;
import com.theshuai.tunnelserver.management.repository.ClientSessionRepository;
import com.theshuai.tunnelserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.tunnelserver.management.repository.TunnelMappingRepository;
import com.theshuai.tunnelserver.security.PasswordService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.boot.context.event.ApplicationReadyEvent;

import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.UUID;

@Service
@Slf4j
public class ClientAuthService {
    public static final String STATUS_HTTP_AUTHENTICATED = "HTTP_AUTHENTICATED";
    public static final String STATUS_NETTY_ONLINE = "NETTY_ONLINE";
    public static final String STATUS_DISCONNECTED = "DISCONNECTED";

    private final ClientCredentialRepository credentialRepository;
    private final ClientIdentityRepository identityRepository;
    private final ClientSessionRepository sessionRepository;
    private final ClientAccountRepository clientAccountRepository;
    private final TunnelMappingRepository tunnelMappingRepository;
    private final HttpRouteMappingRepository httpRouteMappingRepository;
    private final ClientAuthProperties properties;
    private final NettyServerProperties nettyProperties;
    private final String publicAddress;

    public ClientAuthService(ClientCredentialRepository credentialRepository,
                             ClientIdentityRepository identityRepository,
                             ClientSessionRepository sessionRepository,
                             ClientAccountRepository clientAccountRepository,
                             TunnelMappingRepository tunnelMappingRepository,
                             HttpRouteMappingRepository httpRouteMappingRepository,
                             ClientAuthProperties properties,
                             NettyServerProperties nettyProperties,
                             @Value("${tunnel.public-address:}") String publicAddress) {
        this.credentialRepository = credentialRepository;
        this.identityRepository = identityRepository;
        this.sessionRepository = sessionRepository;
        this.clientAccountRepository = clientAccountRepository;
        this.tunnelMappingRepository = tunnelMappingRepository;
        this.httpRouteMappingRepository = httpRouteMappingRepository;
        this.properties = properties;
        this.nettyProperties = nettyProperties;
        this.publicAddress = StringUtils.hasText(publicAddress) ? publicAddress.trim() : "";
    }

    @EventListener(ApplicationReadyEvent.class)
    @Transactional
    public void closeStaleOnlineSessionsOnStartup() {
        int closed = sessionRepository.closeSessionsByStatus(
                STATUS_NETTY_ONLINE,
                STATUS_DISCONNECTED,
                Instant.now().toString()
        );
        if (closed > 0) {
            log.info("closed {} stale client session(s) at startup", closed);
        }
    }

    @Transactional
    public ClientAuthLoginResponse login(ClientAuthLoginRequest request, String requestServerName) {
        ClientEnvironmentInfo environment = requireEnvironment(request == null ? null : request.getEnvironment());
        ClientCredential credential = authenticateCredential(request);
        if (!credential.isEnabled()) {
            throw new IllegalArgumentException("客户端凭证已停用");
        }

        ClientIdentity identity = findOrCreateIdentity(credential, environment);
        ClientAccount account = clientAccountRepository.findByIdAndTenantId(identity.getClientId(), credential.getTenantId())
                .orElseThrow(() -> new IllegalStateException("client account missing: " + identity.getClientId()));
        if (!account.isEnabled()) {
            throw new IllegalArgumentException("客户端已停用");
        }

        String accessToken = "cs_" + UUID.randomUUID().toString().replace("-", "")
                + UUID.randomUUID().toString().replace("-", "");
        Instant now = Instant.now();
        ClientSession session = new ClientSession();
        session.setId(ClientIdGenerator.newId());
        session.setTenantId(credential.getTenantId());
        session.setCredentialId(credential.getId());
        session.setIdentityId(identity.getId());
        session.setClientId(account.getId());
        session.setClientName(account.getClientName());
        session.setTokenHash(tokenHash(accessToken));
        session.setStatus(STATUS_HTTP_AUTHENTICATED);
        applyEnvironment(session, environment);
        session.setHttpLoginAt(now.toString());
        session.setExpiresAt(now.plusSeconds(properties.getTokenTtlSeconds()).toString());
        sessionRepository.save(session);

        ClientAuthLoginResponse response = new ClientAuthLoginResponse();
        response.setTenantId(credential.getTenantId());
        response.setClientId(account.getId());
        response.setClientName(account.getClientName());
        response.setClientSessionId(session.getId());
        response.setAccessToken(accessToken);
        response.setTokenTtlSeconds(properties.getTokenTtlSeconds());
        response.setNettyHost(resolveNettyHost(requestServerName));
        response.setNettyPort(nettyProperties.getPort());
        response.setMaxOnlineInstances(credential.getMaxOnlineInstances());
        response.setTunnelConfigList(loadTcpMappings(account));
        response.setHttpTunnelConfigList(loadHttpRoutes(account));
        response.getPolicy().setEnabled(true);
        return response;
    }

    @Transactional
    public AuthenticationResult authenticateNetty(LoginRequestPacket packet, String channelId, String remoteAddress) {
        if (packet == null || !StringUtils.hasText(packet.getAccessToken())) {
            return AuthenticationResult.failure(null, "缺少客户端访问令牌");
        }
        ClientSession session = sessionRepository.findByTokenHash(tokenHash(packet.getAccessToken())).orElse(null);
        if (session == null) {
            return AuthenticationResult.failure(null, "客户端访问令牌无效");
        }
        if (Instant.parse(session.getExpiresAt()).isBefore(Instant.now())) {
            session.setStatus(STATUS_DISCONNECTED);
            session.setDisconnectedAt(Instant.now().toString());
            sessionRepository.save(session);
            return AuthenticationResult.failure(null, "客户端访问令牌已过期");
        }

        ClientCredential credential = credentialRepository.findByIdAndTenantId(session.getCredentialId(), session.getTenantId())
                .orElse(null);
        ClientAccount account = clientAccountRepository.findByIdAndTenantId(session.getClientId(), session.getTenantId())
                .orElse(null);
        if (credential == null || account == null) {
            return AuthenticationResult.failure(null, "客户端身份不存在");
        }
        if (!credential.isEnabled() || !account.isEnabled()) {
            return AuthenticationResult.failure(account, "客户端已停用");
        }
        if (isAnotherOnlineSessionForMachine(session)) {
            return AuthenticationResult.failure(account, "同一台机器和用户已经有在线实例");
        }
        if (isOnlineLimitExceeded(session, credential)) {
            return AuthenticationResult.failure(account, "在线实例数已达上限");
        }

        String now = Instant.now().toString();
        session.setStatus(STATUS_NETTY_ONLINE);
        session.setNettyConnectedAt(now);
        session.setDisconnectedAt(null);
        session.setChannelId(channelId);
        session.setRemoteAddress(remoteAddress);
        sessionRepository.save(session);
        packet.setClientName(account.getClientName());
        packet.setClientSessionId(session.getId());
        return AuthenticationResult.success(account, session.getId());
    }

    @Transactional
    public void markNettyDisconnected(Long sessionId) {
        if (sessionId == null || sessionId <= 0) {
            return;
        }
        sessionRepository.findById(sessionId).ifPresent(session -> {
            if (STATUS_NETTY_ONLINE.equals(session.getStatus())) {
                session.setStatus(STATUS_DISCONNECTED);
                session.setDisconnectedAt(Instant.now().toString());
                sessionRepository.save(session);
            }
        });
    }

    private ClientCredential authenticateCredential(ClientAuthLoginRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("登录请求不能为空");
        }
        String authType = StringUtils.hasText(request.getAuthType()) ? request.getAuthType().trim() : "";
        if ("password".equalsIgnoreCase(authType)) {
            String username = requireText(request.getUsername(), "username");
            String password = requireText(request.getPassword(), "password");
            ClientCredential credential = credentialRepository.findByApiKey(username)
                    .orElseThrow(() -> new IllegalArgumentException("客户端凭证不存在"));
            if (!PasswordService.matches(password, credential.getSecretHash())) {
                throw new IllegalArgumentException("客户端凭证无效");
            }
            return credential;
        }

        String apiKey = requireText(request.getApiKey(), "apiKey");
        ClientCredential credential = credentialRepository.findByApiKey(apiKey)
                .orElseThrow(() -> new IllegalArgumentException("客户端凭证不存在"));
        if (!hasValidApiKeySignature(request, credential)) {
            throw new IllegalArgumentException("客户端签名无效或已过期");
        }
        return credential;
    }

    private boolean hasValidApiKeySignature(ClientAuthLoginRequest request, ClientCredential credential) {
        if (!StringUtils.hasText(request.getTimestamp()) || !StringUtils.hasText(request.getNonce())
                || !StringUtils.hasText(request.getSignature())) {
            return false;
        }
        long timestamp;
        try {
            timestamp = Long.parseLong(request.getTimestamp());
        } catch (NumberFormatException e) {
            return false;
        }
        if (Math.abs(timestamp - System.currentTimeMillis()) > 60_000L) {
            return false;
        }
        byte[] key;
        try {
            key = HmacSigner.decodeHex(credential.getSecretHash());
        } catch (IllegalArgumentException e) {
            return false;
        }
        String expected = HexFormat.of().formatHex(HmacSigner.hmacSha256(
                key,
                ClientAuthSigner.canonicalApiKeyMessage(
                        request.getApiKey(),
                        request.getTimestamp(),
                        request.getNonce(),
                        request.getEnvironment()
                )
        ));
        return MessageDigest.isEqual(expected.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                request.getSignature().getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private ClientIdentity findOrCreateIdentity(ClientCredential credential, ClientEnvironmentInfo environment) {
        return identityRepository.findByCredentialIdAndMachineFingerprintAndOsUser(
                credential.getId(),
                environment.getMachineFingerprint(),
                environment.getOsUser()
        ).map(identity -> updateIdentityLastSeen(identity, environment)).orElseGet(() -> createIdentity(credential, environment));
    }

    private ClientIdentity updateIdentityLastSeen(ClientIdentity identity, ClientEnvironmentInfo environment) {
        identity.setHostname(limit(environment.getHostname(), 160));
        identity.setLastSeenAt(Instant.now().toString());
        return identityRepository.save(identity);
    }

    private ClientIdentity createIdentity(ClientCredential credential, ClientEnvironmentInfo environment) {
        String now = Instant.now().toString();
        ClientAccount account = new ClientAccount();
        account.setId(ClientIdGenerator.newId());
        account.setTenantId(credential.getTenantId());
        account.setClientName(generateClientName(credential, environment));
        account.setPasswordHash(PasswordService.hash(UUID.randomUUID().toString()));
        account.setEnabled(true);
        account.setConnectionRateLimitPerMinute(30);
        account.setCreatedAt(now);
        account.setUpdatedAt(now);
        clientAccountRepository.save(account);

        ClientIdentity identity = new ClientIdentity();
        identity.setId(ClientIdGenerator.newId());
        identity.setTenantId(credential.getTenantId());
        identity.setCredentialId(credential.getId());
        identity.setClientId(account.getId());
        identity.setClientName(account.getClientName());
        identity.setMachineFingerprint(environment.getMachineFingerprint());
        identity.setOsUser(environment.getOsUser());
        identity.setHostname(limit(environment.getHostname(), 160));
        identity.setFirstSeenAt(now);
        identity.setLastSeenAt(now);
        return identityRepository.save(identity);
    }

    private String generateClientName(ClientCredential credential, ClientEnvironmentInfo environment) {
        String host = slug(environment.getHostname(), "client");
        String user = slug(environment.getOsUser(), "user");
        String suffix = HexFormat.of().formatHex(HmacSigner.sha256(
                credential.getId() + "\n" + environment.getMachineFingerprint() + "\n" + environment.getOsUser()
        )).substring(0, 8);
        String base = limit(host + "-" + user + "-" + suffix, 120);
        String candidate = base;
        int i = 2;
        while (clientAccountRepository.findByClientName(candidate).isPresent()) {
            String extra = "-" + i++;
            candidate = limit(base, 120 - extra.length()) + extra;
        }
        return candidate;
    }

    private boolean isAnotherOnlineSessionForMachine(ClientSession session) {
        long online = sessionRepository.countByCredentialIdAndMachineFingerprintAndOsUserAndStatus(
                session.getCredentialId(),
                session.getMachineFingerprint(),
                session.getOsUser(),
                STATUS_NETTY_ONLINE
        );
        return online >= properties.getPerMachineUserMaxInstances();
    }

    private boolean isOnlineLimitExceeded(ClientSession session, ClientCredential credential) {
        long online = sessionRepository.countByCredentialIdAndStatus(
                credential.getId(),
                STATUS_NETTY_ONLINE
        );
        return online >= credential.getMaxOnlineInstances();
    }

    private ClientEnvironmentInfo requireEnvironment(ClientEnvironmentInfo environment) {
        if (environment == null) {
            throw new IllegalArgumentException("environment 不能为空");
        }
        environment.setMachineFingerprint(limit(requireText(environment.getMachineFingerprint(), "machineFingerprint"), 160));
        environment.setOsUser(limit(requireText(environment.getOsUser(), "osUser"), 120));
        environment.setHostname(limit(firstText(environment.getHostname(), "unknown-host"), 160));
        return environment;
    }

    private void applyEnvironment(ClientSession session, ClientEnvironmentInfo environment) {
        session.setMachineFingerprint(environment.getMachineFingerprint());
        session.setOsUser(environment.getOsUser());
        session.setHostname(limit(environment.getHostname(), 160));
        session.setOsName(limit(environment.getOsName(), 120));
        session.setOsVersion(limit(environment.getOsVersion(), 80));
        session.setOsArch(limit(environment.getOsArch(), 60));
        session.setClientVersion(limit(environment.getClientVersion(), 80));
        session.setJavaVersion(limit(environment.getJavaVersion(), 80));
        List<String> addresses = environment.getLocalAddresses() == null ? List.of() : environment.getLocalAddresses();
        session.setLocalAddresses(limit(String.join(",", addresses.stream().filter(Objects::nonNull).toList()), 2000));
    }

    private List<ClientAuthLoginResponse.TunnelEndpoint> loadTcpMappings(ClientAccount account) {
        return tunnelMappingRepository
                .findByTenantIdAndClientIdAndEnabledTrueOrderByIdAsc(account.getTenantId(), account.getId())
                .stream()
                .map(this::toTunnelEndpoint)
                .toList();
    }

    private List<ClientAuthLoginResponse.HttpRouteEndpoint> loadHttpRoutes(ClientAccount account) {
        return httpRouteMappingRepository
                .findByTenantIdAndClientIdAndEnabledTrueOrderByIdAsc(account.getTenantId(), account.getId())
                .stream()
                .map(this::toHttpEndpoint)
                .toList();
    }

    private ClientAuthLoginResponse.TunnelEndpoint toTunnelEndpoint(TunnelMapping mapping) {
        ClientAuthLoginResponse.TunnelEndpoint endpoint = new ClientAuthLoginResponse.TunnelEndpoint();
        endpoint.setPort(mapping.getListenPort());
        endpoint.setTunnelAddress(mapping.getTargetAddress());
        endpoint.setTunnelPort(mapping.getTargetPort());
        return endpoint;
    }

    private ClientAuthLoginResponse.HttpRouteEndpoint toHttpEndpoint(HttpRouteMapping route) {
        ClientAuthLoginResponse.HttpRouteEndpoint endpoint = new ClientAuthLoginResponse.HttpRouteEndpoint();
        endpoint.setRoute(route.getRoute());
        endpoint.setTargetBaseUrl(route.getTargetBaseUrl());
        return endpoint;
    }

    private String resolveNettyHost(String requestServerName) {
        return firstText(publicAddress, requestServerName);
    }

    private String tokenHash(String token) {
        return HexFormat.of().formatHex(HmacSigner.sha256(token));
    }

    private String requireText(String value, String field) {
        if (!StringUtils.hasText(value)) {
            throw new IllegalArgumentException(field + " cannot be blank");
        }
        return value.trim();
    }

    private String firstText(String... values) {
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return "";
    }

    private String slug(String value, String fallback) {
        String normalized = StringUtils.hasText(value) ? value.trim().toLowerCase(Locale.ROOT) : fallback;
        normalized = normalized.replaceAll("[^a-z0-9._-]+", "-").replaceAll("^-+|-+$", "");
        return StringUtils.hasText(normalized) ? limit(normalized, 50) : fallback;
    }

    private String limit(String value, int maxLength) {
        if (value == null || value.length() <= maxLength) {
            return value;
        }
        return value.substring(0, maxLength);
    }
}
