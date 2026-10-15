package com.theshuai.specusserver.management.service;

import com.theshuai.common.clientauth.ClientAuthLoginRequest;
import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import com.theshuai.common.clientauth.ClientAuthSigner;
import com.theshuai.common.clientauth.ClientEnvironmentInfo;
import com.theshuai.common.peermesh.PeerServiceDiscovery;
import com.theshuai.common.peeregress.PeerEgressProtocol;
import com.theshuai.common.protocol.request.LoginRequestPacket;
import com.theshuai.common.security.HmacSigner;
import com.theshuai.specusserver.config.ClientAuthProperties;
import com.theshuai.specusserver.config.NettyServerProperties;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.model.ClientCredential;
import com.theshuai.specusserver.management.model.ClientIdentity;
import com.theshuai.specusserver.management.model.ClientSession;
import com.theshuai.specusserver.management.model.HttpRouteMapping;
import com.theshuai.specusserver.management.model.SortableInstant;
import com.theshuai.specusserver.management.model.SpecusMapping;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.ClientCredentialRepository;
import com.theshuai.specusserver.management.repository.ClientIdentityRepository;
import com.theshuai.specusserver.management.repository.ClientSessionRepository;
import com.theshuai.specusserver.management.repository.ClientSessionRepositoryCustom.SessionSnapshot;
import com.theshuai.specusserver.management.repository.ConnectionRecordRepository;
import com.theshuai.specusserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.specusserver.management.repository.SpecusMappingRepository;
import com.theshuai.specusserver.security.PasswordService;
import com.theshuai.specusserver.security.TlsContextFactory;
import com.theshuai.specusserver.security.TlsProperties;
import com.theshuai.specusserver.session.ClientHttpRouteCapabilities;
import com.theshuai.specusserver.session.SessionUtil;
import io.netty.channel.Channel;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.StringUtils;
import org.springframework.boot.context.event.ApplicationReadyEvent;

import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
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
    private final ConnectionRecordRepository connectionRecordRepository;
    private final SpecusMappingRepository specusMappingRepository;
    private final HttpRouteMappingRepository httpRouteMappingRepository;
    private final PeerMeshService peerMeshService;
    private final ClientAuthNonceService nonceService;
    private final ClientAuthProperties properties;
    private final NettyServerProperties nettyProperties;
    private final TlsProperties tlsProperties;
    private final ClientHttpRouteCapabilities httpRouteCapabilities;
    private final String publicAddress;
    private final TransactionTemplate transactionTemplate;

    public ClientAuthService(ClientCredentialRepository credentialRepository,
                             ClientIdentityRepository identityRepository,
                             ClientSessionRepository sessionRepository,
                             ClientAccountRepository clientAccountRepository,
                             ConnectionRecordRepository connectionRecordRepository,
                             SpecusMappingRepository specusMappingRepository,
                             HttpRouteMappingRepository httpRouteMappingRepository,
                             PeerMeshService peerMeshService,
                             ClientAuthNonceService nonceService,
                             ClientAuthProperties properties,
                             NettyServerProperties nettyProperties,
                             TlsProperties tlsProperties,
                             ClientHttpRouteCapabilities httpRouteCapabilities,
                             PlatformTransactionManager transactionManager,
                             @Value("${specus.public-address:}") String publicAddress) {
        this.credentialRepository = credentialRepository;
        this.identityRepository = identityRepository;
        this.sessionRepository = sessionRepository;
        this.clientAccountRepository = clientAccountRepository;
        this.connectionRecordRepository = connectionRecordRepository;
        this.specusMappingRepository = specusMappingRepository;
        this.httpRouteMappingRepository = httpRouteMappingRepository;
        this.peerMeshService = peerMeshService;
        this.nonceService = nonceService;
        this.properties = properties;
        this.nettyProperties = nettyProperties;
        this.tlsProperties = tlsProperties;
        this.httpRouteCapabilities = httpRouteCapabilities;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
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

    public ClientAuthLoginResponse login(ClientAuthLoginRequest request, String requestServerName) {
        ClientEnvironmentInfo environment = requireEnvironment(request == null ? null : request.getEnvironment());
        ClientCredential credential = authenticateCredential(request);
        if (!credential.isEnabled()) {
            throw new IllegalArgumentException("客户端凭证已停用");
        }
        // Capture authenticated material before a refresh can mutate any managed entity.
        Long credentialId = credential.getId();
        String tenantId = credential.getTenantId(), apiKey = credential.getApiKey(), secretHash = credential.getSecretHash();
        return transactionTemplate.execute(status -> {
            ClientCredential current = credentialRepository.lockCurrent(credentialId, tenantId)
                    .orElseThrow(() -> new IllegalArgumentException("客户端凭证不存在或已变更"));
            if (!Objects.equals(apiKey, current.getApiKey()) || !Objects.equals(secretHash, current.getSecretHash())) {
                throw new IllegalArgumentException("客户端签名无效或已过期");
            }
            if (!current.isEnabled()) throw new IllegalArgumentException("客户端凭证已停用");
            // The nonce was consumed exactly once above. Current owner and policy, identity/account
            // creation and session insertion now share the credential's database write lock.
            return completeLogin(current, environment, requestServerName);
        });
    }

    private ClientAuthLoginResponse completeLogin(ClientCredential credential,
                                                  ClientEnvironmentInfo environment,
                                                  String requestServerName) {
        ClientIdentity identity = findOrCreateIdentity(credential, environment);
        ClientAccount account = clientAccountRepository.findByIdAndTenantId(identity.getClientId(), credential.getTenantId())
                .orElseThrow(() -> new IllegalStateException("client account missing: " + identity.getClientId()));
        if (!account.isEnabled()) {
            throw new IllegalArgumentException("客户端已停用");
        }
        closeStaleHttpAuthenticatedSessions(credential, environment);

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
        Instant expiresAt = now.plusSeconds(properties.getTokenTtlSeconds());
        session.setExpiresAt(expiresAt.toString());
        sessionRepository.save(session);
        // Kept in memory with the session, not in its row: the connectivity check reads it through
        // the session id its data connection carries.
        httpRouteCapabilities.remember(session.getId(),
                environment.getClientHttpRouteCapabilities().getVersion(), expiresAt);

        ClientAuthLoginResponse response = new ClientAuthLoginResponse();
        response.setTenantId(credential.getTenantId());
        response.setClientId(account.getId());
        response.setClientName(account.getClientName());
        response.setClientSessionId(session.getId());
        response.setAccessToken(accessToken);
        response.setTokenTtlSeconds(properties.getTokenTtlSeconds());
        response.setNettyHost(resolveNettyHost(requestServerName));
        response.setNettyPort(nettyProperties.getPort());
        response.setNettyTls(tlsProperties.resolveMode() != TlsContextFactory.Mode.DISABLED
                || tlsProperties.isTerminatedUpstream());
        response.setMaxOnlineInstances(credential.getMaxOnlineInstances());
        response.setSpecusConfigList(loadTcpMappings(account));
        response.setHttpSpecusConfigList(loadHttpRoutes(account));
        response.setPeerMesh(peerMeshService.buildLoginConfig(account, environment, requestServerName));
        response.getPolicy().setEnabled(true);
        return response;
    }

    public AuthenticationResult authenticateNetty(LoginRequestPacket packet, String channelId, String remoteAddress) {
        return authenticateNetty(packet, channelId, remoteAddress, false);
    }

    public AuthenticationResult authenticateNetty(LoginRequestPacket packet, String channelId,
                                                   String remoteAddress, boolean dataConnection) {
        return authenticateNetty(packet, channelId, remoteAddress, dataConnection, null);
    }

    /** Resolve before acquiring the process lifecycle: the lookup must release its JDBC connection
     * before a caller waits for another CONTROL generation. The writer revalidates this identity. */
    public Long controlClientId(String accessToken) {
        if (!StringUtils.hasText(accessToken)) return null;
        return sessionRepository.findByTokenHash(tokenHash(accessToken)).map(ClientSession::getClientId).orElse(null);
    }

    public AuthenticationResult authenticateNetty(LoginRequestPacket packet, String channelId,
                                                   String remoteAddress, boolean dataConnection, Long expectedClientId) {
        if (packet == null || !StringUtils.hasText(packet.getAccessToken())) {
            return AuthenticationResult.failure(null, "缺少客户端访问令牌");
        }
        String expectedToken = tokenHash(packet.getAccessToken());
        ClientSession session = sessionRepository.findByTokenHash(expectedToken).orElse(null);
        if (session == null) {
            return AuthenticationResult.failure(null, "客户端访问令牌无效");
        }
        if (expectedClientId != null && !Objects.equals(expectedClientId, session.getClientId())) {
            return AuthenticationResult.failure(null, "客户端访问令牌或身份已变更");
        }
        // Like signed HTTP login, the initial lookup is not the admission decision. Start a
        // short writer only for a known token; its FIRST statement locks the credential and
        // reserves SQLite's writer before any snapshot read. Invalid tokens take no write lock.
        return transactionTemplate.execute(status -> authenticateCurrentNetty(
                packet, channelId, remoteAddress, dataConnection, session, expectedToken));
    }

    private AuthenticationResult authenticateCurrentNetty(LoginRequestPacket packet, String channelId,
                                                          String remoteAddress, boolean dataConnection,
                                                          ClientSession session, String expectedToken) {
        Long selectedId = session.getId(), selectedCredential = session.getCredentialId();
        Long selectedClient = session.getClientId(), selectedIdentity = session.getIdentityId();
        String selectedTenant = session.getTenantId();
        ClientCredential credential = credentialRepository.lockCurrent(selectedCredential, selectedTenant)
                .orElse(null);
        if (credential == null) return AuthenticationResult.failure(null, "客户端身份不存在");
        if (!hasUnambiguousCredential(selectedClient, credential))
            return AuthenticationResult.failure(null, "客户端身份关联不一致");
        ClientAccount account = clientAccountRepository.lockCurrent(selectedClient, selectedTenant)
                .orElse(null);
        if (credential == null || account == null) {
            return AuthenticationResult.failure(null, "客户端身份不存在");
        }
        SessionSnapshot current = sessionRepository.lockCurrent(selectedId, selectedTenant).orElse(null);
        if (current == null || !Objects.equals(expectedToken, current.tokenHash())
                || !Objects.equals(selectedCredential, current.credentialId()) || !Objects.equals(selectedClient, current.clientId())
                || !Objects.equals(selectedIdentity, current.identityId()))
            return AuthenticationResult.failure(null, "客户端访问令牌或身份已变更");
        if (Instant.parse(current.expiresAt()).isBefore(Instant.now())) {
            sessionRepository.markDisconnected(current, Instant.now().toString());
            return AuthenticationResult.failure(null, "客户端访问令牌已过期");
        }
        if (!credential.isEnabled() || !account.isEnabled()) {
            return AuthenticationResult.failure(account, "客户端已停用");
        }
        if (dataConnection && !STATUS_NETTY_ONLINE.equals(current.status())) {
            return AuthenticationResult.failure(account, "数据连接要求控制连接先登录");
        }
        if (dataConnection) {
            packet.setClientName(account.getClientName());
            packet.setClientSessionId(current.id());
            return AuthenticationResult.success(account, current.id());
        }
        if (hasExceededRateLimit(account)) {
            return AuthenticationResult.failure(account, "连接频率超过限制");
        }
        List<SessionSnapshot> online = closeStaleOnlineSessions(sessionRepository.lockOnline(credential.getId(), selectedTenant));
        if (online.stream().filter(row -> !Objects.equals(row.id(), current.id()))
                .filter(row -> Objects.equals(row.machineFingerprint(), current.machineFingerprint())
                && Objects.equals(row.osUser(), current.osUser())).count() >= properties.getPerMachineUserMaxInstances()) {
            return AuthenticationResult.failure(account, "同一台机器和用户已经有在线实例");
        }
        if (online.stream().filter(row -> !Objects.equals(row.id(), current.id())).count() >= credential.getMaxOnlineInstances()) {
            return AuthenticationResult.failure(account, "在线实例数已达上限");
        }

        String now = Instant.now().toString();
        sessionRepository.markOnline(current, account.getClientName(), channelId, remoteAddress, now);
        packet.setClientName(account.getClientName());
        packet.setClientSessionId(current.id());
        return AuthenticationResult.success(account, current.id());
    }

    @Transactional
    public boolean markNettyDisconnected(Long sessionId, String channelId) {
        if (sessionId == null || sessionId <= 0 || !StringUtils.hasText(channelId)) {
            return false;
        }
        return sessionRepository.disconnectChannel(sessionId, channelId, Instant.now().toString()) == 1;
    }

    public boolean isSessionDisconnected(Long sessionId, Long clientId) {
        return sessionId != null && clientId != null && sessionRepository.findById(sessionId)
                .filter(row -> Objects.equals(row.getClientId(), clientId))
                .filter(row -> STATUS_DISCONNECTED.equals(row.getStatus())).isPresent();
    }

    private ClientCredential authenticateCredential(ClientAuthLoginRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("登录请求不能为空");
        }
        String apiKey = requireText(request.getApiKey(), "apiKey");
        ClientCredential credential = credentialRepository.findByApiKey(apiKey)
                .orElseThrow(() -> new IllegalArgumentException("客户端凭证不存在"));
        if (!hasValidApiKeySignature(request, credential)) {
            throw new IllegalArgumentException("客户端签名无效或已过期");
        }
        if (!nonceService.consume(apiKey, request.getNonce())) {
            throw new IllegalArgumentException("客户端签名 nonce 已使用");
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
        ).map(identity -> {
            if (!hasUnambiguousCredential(identity.getClientId(), credential))
                throw new IllegalArgumentException("客户端身份关联不一致");
            return updateIdentityLastSeen(identity, environment);
        }).orElseGet(() -> createIdentity(credential, environment));
    }

    private boolean hasUnambiguousCredential(Long clientId, ClientCredential credential) {
        // Check immutable membership BEFORE saving an identity or acquiring a different
        // credential through the parent-client lock. Otherwise malformed legacy links can
        // invert the global credential order (high credential -> identity -> low credential).
        return identityRepository.findCredentialBindings(clientId).stream().allMatch(row ->
                Objects.equals(credential.getId(), ((Number) row[0]).longValue())
                        && Objects.equals(credential.getTenantId(), row[1]));
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
        account.setOwnerUsername(credential.getOwnerUsername());
        account.setClientName(generateClientName(credential, environment));
        account.setPasswordHash(PasswordService.hashToken(UUID.randomUUID().toString()));
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

    private List<SessionSnapshot> closeStaleOnlineSessions(List<SessionSnapshot> sessions) {
        if (sessions.isEmpty()) return sessions;
        java.util.ArrayList<SessionSnapshot> live = new java.util.ArrayList<>();
        String now = Instant.now().toString();
        int closed = 0;
        for (SessionSnapshot onlineSession : sessions) {
            Channel channel = SessionUtil.getChannel(onlineSession.clientName());
            boolean current = channel != null && channel.isActive() && SessionUtil.hasLogin(channel)
                    && Objects.equals(channel.id().asLongText(), onlineSession.channelId())
                    && Objects.equals(channel.attr(com.theshuai.specusserver.attribute.ServerAttributes.CLIENT_SESSION_ID).get(), onlineSession.id());
            if (current || com.theshuai.specusserver.session.ControlLifecycle.isPublishing(onlineSession.clientId(), onlineSession.channelId())) {
                live.add(onlineSession);
                continue;
            }
            sessionRepository.markDisconnected(onlineSession, now);
            closed++;
        }
        if (closed > 0) {
            log.info("closed {} stale online client session(s) before netty authentication", closed);
        }
        return live;
    }

    private void closeStaleHttpAuthenticatedSessions(ClientCredential credential, ClientEnvironmentInfo environment) {
        int closed = sessionRepository.closeHttpAuthenticatedSessions(
                credential.getId(),
                environment.getMachineFingerprint(),
                environment.getOsUser(),
                STATUS_HTTP_AUTHENTICATED,
                STATUS_DISCONNECTED,
                Instant.now().toString()
        );
        if (closed > 0) {
            log.debug("closed {} stale HTTP-authenticated client session(s) before issuing refreshed token", closed);
        }
    }

    private boolean hasExceededRateLimit(ClientAccount account) {
        return account.getConnectionRateLimitPerMinute() > 0
                && connectionRecordRepository.countCurrentConnections(
                account.getTenantId(),
                account.getId(),
                SortableInstant.format(Instant.now().minus(1, ChronoUnit.MINUTES))
        ) >= account.getConnectionRateLimitPerMinute();
    }

    private ClientEnvironmentInfo requireEnvironment(ClientEnvironmentInfo environment) {
        if (environment == null) {
            throw new IllegalArgumentException("environment 不能为空");
        }
        environment.setMachineFingerprint(limit(requireText(environment.getMachineFingerprint(), "machineFingerprint"), 160));
        environment.setOsUser(limit(requireText(environment.getOsUser(), "osUser"), 120));
        environment.setHostname(limit(firstText(environment.getHostname(), "unknown-host"), 160));
        environment.setPeerPublicKey(limit(environment.getPeerPublicKey(), 256));
        if (environment.getClientMessageCapabilities() == null) {
            environment.setClientMessageCapabilities(new ClientEnvironmentInfo.ClientMessageCapabilities());
        }
        if (environment.getClientPeerServiceCapabilities() == null) {
            environment.setClientPeerServiceCapabilities(new ClientEnvironmentInfo.ClientPeerServiceCapabilities());
        }
        if (environment.getClientEgressCapabilities() == null) {
            // An explicit null reads as "no egress", like an absent object, instead of failing login.
            environment.setClientEgressCapabilities(new ClientEnvironmentInfo.ClientEgressCapabilities());
        }
        if (environment.getClientHttpRouteCapabilities() == null) {
            // Likewise an explicit null is an older client, whose resets are never classified.
            environment.setClientHttpRouteCapabilities(new ClientEnvironmentInfo.ClientHttpRouteCapabilities());
        }
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
        ClientEnvironmentInfo.ClientMessageCapabilities messages = environment.getClientMessageCapabilities();
        session.setMessageSendCapable(messages.isSendMessages());
        session.setMessageReceiveCapable(messages.isReceiveMessages());
        session.setMessageAttachmentsCapable(messages.isAttachments());
        session.setMessageMediaPreviewCapable(messages.isMediaPreview());
        session.setMessageMaxAttachmentBytes(Math.max(0L, messages.getMaxAttachmentBytes()));
        ClientEnvironmentInfo.ClientPeerServiceCapabilities discovery = environment.getClientPeerServiceCapabilities();
        int version = PeerServiceDiscovery.normalizeVersion(discovery.getVersion());
        session.setPeerServiceDiscoveryVersion(version);
        session.setPeerServiceApplications(PeerServiceDiscovery.encodeApplications(
                version < 1 ? List.of() : discovery.getApplications()));
        ClientEnvironmentInfo.ClientEgressCapabilities egress = environment.getClientEgressCapabilities();
        int egressVersion = PeerEgressProtocol.normalizeVersion(egress.getVersion());
        session.setClientEgressVersion(egressVersion);
        // A domain-target claim means nothing from a client that does not take part in egress at
        // all, so it is only kept alongside a version the server will push egress messages for.
        session.setClientEgressDomainTargets(egressVersion >= 1 && egress.isDomainTargetCapable());
    }

    private List<ClientAuthLoginResponse.SpecusEndpoint> loadTcpMappings(ClientAccount account) {
        return specusMappingRepository
                .findByTenantIdAndClientIdAndEnabledTrueOrderByIdAsc(account.getTenantId(), account.getId())
                .stream()
                .map(this::toSpecusEndpoint)
                .toList();
    }

    private List<ClientAuthLoginResponse.HttpRouteEndpoint> loadHttpRoutes(ClientAccount account) {
        return httpRouteMappingRepository
                .findByTenantIdAndClientIdAndEnabledTrueOrderByIdAsc(account.getTenantId(), account.getId())
                .stream()
                .map(this::toHttpEndpoint)
                .toList();
    }

    private ClientAuthLoginResponse.SpecusEndpoint toSpecusEndpoint(SpecusMapping mapping) {
        ClientAuthLoginResponse.SpecusEndpoint endpoint = new ClientAuthLoginResponse.SpecusEndpoint();
        endpoint.setPort(mapping.getListenPort());
        endpoint.setSpecusAddress(mapping.getTargetAddress());
        endpoint.setSpecusPort(mapping.getTargetPort());
        return endpoint;
    }

    private ClientAuthLoginResponse.HttpRouteEndpoint toHttpEndpoint(HttpRouteMapping route) {
        ClientAuthLoginResponse.HttpRouteEndpoint endpoint = new ClientAuthLoginResponse.HttpRouteEndpoint();
        endpoint.setRoute(route.getRoute());
        endpoint.setTargetBaseUrl(route.getTargetBaseUrl());
        endpoint.setInsecureSkipVerify(Boolean.TRUE.equals(route.getInsecureSkipVerify()));
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
