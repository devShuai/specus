package com.theshuai.specusserver.management.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.theshuai.common.clientauth.ClientEnvironmentInfo;
import com.theshuai.common.peeregress.PeerEgressCatalogEntry;
import com.theshuai.common.peeregress.PeerEgressCodes;
import com.theshuai.common.peeregress.PeerEgressPolicy;
import com.theshuai.common.peeregress.PeerEgressProtocol;
import com.theshuai.common.peermesh.PeerControlMessage;
import com.theshuai.common.peermesh.PeerServiceDiscovery;
import com.theshuai.common.util.JsonUtil;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.model.PeerMeshDevice;
import com.theshuai.specusserver.management.model.PeerMeshEgressActivity;
import com.theshuai.specusserver.management.model.PeerMeshEgressActivityView;
import com.theshuai.specusserver.management.model.PeerMeshEgressSwitch;
import com.theshuai.specusserver.management.model.PeerMeshEgressPolicy;
import com.theshuai.specusserver.management.model.PeerMeshEgressSwitchView;
import com.theshuai.specusserver.management.model.PeerMeshEgressPolicyView;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.PeerMeshDeviceRepository;
import com.theshuai.specusserver.management.repository.PeerMeshEgressActivityRepository;
import com.theshuai.specusserver.management.repository.PeerMeshEgressSwitchRepository;
import com.theshuai.specusserver.management.repository.PeerMeshEgressPolicyRepository;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.function.Predicate;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Egress authorization: storage, management mutations and the payloads pushed to clients.
 *
 * <p>Kept apart from {@code PeerMeshService} because the two answer different questions. Mesh ACLs
 * decide whether two devices may see each other; this decides whether one may be used as a way out.
 * Effective permission is the intersection, computed in {@link #allowedConsumerIds}.
 */
@Slf4j
@Service
public class PeerEgressService {
    /** Bumped on every push so a client can ignore a snapshot it has already applied. */
    private final AtomicLong revisions = new AtomicLong();

    private final PeerMeshEgressPolicyRepository policyRepository;
    private final PeerMeshEgressActivityRepository activityRepository;
    private final PeerMeshEgressSwitchRepository switchRepository;
    private final ConcurrentHashMap<Long, ConcurrentLinkedDeque<Long>> reportTimestamps = new ConcurrentHashMap<>();
    private final PeerMeshDeviceRepository deviceRepository;
    private final ClientAccountRepository clientAccountRepository;
    private final PeerMeshService peerMeshService;

    public PeerEgressService(PeerMeshEgressPolicyRepository policyRepository,
                             PeerMeshEgressActivityRepository activityRepository,
                             PeerMeshEgressSwitchRepository switchRepository,
                             PeerMeshDeviceRepository deviceRepository,
                             ClientAccountRepository clientAccountRepository,
                             PeerMeshService peerMeshService) {
        this.policyRepository = policyRepository;
        this.activityRepository = activityRepository;
        this.switchRepository = switchRepository;
        this.deviceRepository = deviceRepository;
        this.clientAccountRepository = clientAccountRepository;
        this.peerMeshService = peerMeshService;
    }

    /** Mutation accepted by the management API; absent fields keep their stored value. */
    public record PolicyMutation(Long egressClientId,
                                 Boolean enabled,
                                 String scope,
                                 List<Long> allowedConsumerClientIds,
                                 List<PeerEgressPolicy.PeerEgressDestinationRule> destinationRules,
                                 Integer maxConcurrentFlows,
                                 Integer maxFlowsPerConsumer,
                                 Integer idleTimeoutSeconds) {
    }

    /** Whether the tenant switch is on. Off by default: egress is opt-in for the tenant too. */
    @Transactional(readOnly = true)
    public boolean egressEnabledFor(String tenantId) {
        return switchRepository.findById(tenantId).map(PeerMeshEgressSwitch::isEnabled).orElse(false);
    }

    @Transactional(readOnly = true)
    public PeerMeshEgressSwitchView switchStatus(ManagementContext context) {
        String tenantId = context.tenant().tenantId();
        PeerMeshEgressSwitch stored = switchRepository.findById(tenantId).orElse(null);
        boolean configured = stored != null && stored.isEnabled();
        int enabledPolicies = policyRepository
                .findByTenantIdAndEnabledTrueOrderByEgressClientNameAsc(tenantId).size();
        return new PeerMeshEgressSwitchView(
                peerMeshService.isEnabled(),
                configured,
                peerMeshService.isEnabled() && configured,
                PeerEgressProtocol.PROTOCOL_VERSION,
                enabledPolicies,
                stored == null ? null : stored.getUpdatedAt(),
                stored == null ? null : stored.getUpdatedBy());
    }

    /**
     * Turns egress on or off for the whole tenant.
     *
     * <p>Switching off leaves every per-device policy intact, so turning it back on restores what
     * was configured rather than making the operator rebuild it.
     */
    @Transactional
    public PeerMeshEgressSwitchView setSwitch(ManagementContext context, boolean enabled) {
        if (!context.isAdmin()) {
            throw new IllegalArgumentException("只有租户 ADMIN 可以管理出口授权");
        }
        if (enabled && !peerMeshService.isEnabled()) {
            throw new IllegalArgumentException("部署端未启用 Peer Mesh，不能开启出口分流");
        }
        String tenantId = context.tenant().tenantId();
        PeerMeshEgressSwitch stored = switchRepository.findById(tenantId)
                .orElseGet(() -> {
                    PeerMeshEgressSwitch created = new PeerMeshEgressSwitch();
                    created.setTenantId(tenantId);
                    return created;
                });
        stored.setEnabled(enabled);
        stored.setUpdatedBy(context.username());
        stored.setUpdatedAt(Instant.now().toString());
        switchRepository.save(stored);
        return switchStatus(context);
    }

    @Transactional(readOnly = true)
    public List<PeerMeshEgressPolicy> listPolicies(ManagementContext context) {
        return policyRepository.findByTenantIdOrderByEgressClientNameAsc(context.tenant().tenantId());
    }

    @Transactional
    public PeerMeshEgressPolicy upsertPolicy(ManagementContext context, PolicyMutation mutation) {
        if (!context.isAdmin()) {
            throw new IllegalArgumentException("只有租户 ADMIN 可以管理出口授权");
        }
        Long egressClientId = mutation.egressClientId();
        if (egressClientId == null) {
            throw new IllegalArgumentException("egressClientId is required");
        }
        ClientAccount egress = clientAccountRepository
                .findByIdAndTenantId(egressClientId, context.tenant().tenantId())
                .orElseThrow(() -> new IllegalArgumentException("client not found: " + egressClientId));

        PeerMeshEgressPolicy policy = policyRepository
                .findByTenantIdAndEgressClientId(context.tenant().tenantId(), egressClientId)
                .orElseGet(PeerMeshEgressPolicy::new);
        if (policy.getId() == null) {
            policy.setId(ClientIdGenerator.newId());
            policy.setTenantId(context.tenant().tenantId());
            policy.setCreatedAt(Instant.now().toString());
        }
        policy.setOwnerUsername(context.username());
        policy.setEgressClientId(egress.getId());
        policy.setEgressClientName(egress.getClientName());

        if (mutation.enabled() != null) {
            policy.setEnabled(mutation.enabled());
        }
        if (mutation.scope() != null) {
            String scope = mutation.scope().trim().toUpperCase();
            if (!PeerEgressPolicy.SCOPE_PUBLIC.equals(scope) && !PeerEgressPolicy.SCOPE_LAN.equals(scope)) {
                throw new IllegalArgumentException("invalid scope: " + mutation.scope());
            }
            policy.setScope(scope);
        }
        if (mutation.allowedConsumerClientIds() != null) {
            policy.setAllowedConsumerClientIds(
                    PeerServiceDiscovery.encodeClientIds(mutation.allowedConsumerClientIds()));
        }
        if (mutation.destinationRules() != null) {
            policy.setDestinationRules(encodeDestinationRules(mutation.destinationRules()));
        }
        if (mutation.maxConcurrentFlows() != null) {
            policy.setMaxConcurrentFlows(requirePositive(mutation.maxConcurrentFlows(), "maxConcurrentFlows"));
        }
        if (mutation.maxFlowsPerConsumer() != null) {
            policy.setMaxFlowsPerConsumer(requirePositive(mutation.maxFlowsPerConsumer(), "maxFlowsPerConsumer"));
        }
        if (mutation.idleTimeoutSeconds() != null) {
            policy.setIdleTimeoutSeconds(requirePositive(mutation.idleTimeoutSeconds(), "idleTimeoutSeconds"));
        }
        policy.setUpdatedAt(Instant.now().toString());
        return policyRepository.save(policy);
    }

    @Transactional(readOnly = true)
    public List<PeerMeshEgressPolicyView> listPolicyViews(ManagementContext context) {
        return listPolicies(context).stream().map(this::toView).toList();
    }

    @Transactional
    public PeerMeshEgressPolicyView upsertPolicyView(ManagementContext context, PolicyMutation mutation) {
        return toView(upsertPolicy(context, mutation));
    }

    private PeerMeshEgressPolicyView toView(PeerMeshEgressPolicy policy) {
        List<Long> configured = PeerServiceDiscovery.decodeClientIds(policy.getAllowedConsumerClientIds());
        List<Long> effective = clientAccountRepository
                .findByIdAndTenantId(policy.getEgressClientId(), policy.getTenantId())
                .map(egress -> allowedConsumerIds(egress, policy))
                .orElseGet(List::of);
        return new PeerMeshEgressPolicyView(
                policy.getId(),
                policy.getEgressClientId(),
                policy.getEgressClientName(),
                policy.isEnabled(),
                policy.getScope(),
                configured,
                effective,
                decodeDestinationRules(policy.getDestinationRules()),
                policy.getMaxConcurrentFlows(),
                policy.getMaxFlowsPerConsumer(),
                policy.getIdleTimeoutSeconds(),
                policy.getCreatedAt(),
                policy.getUpdatedAt());
    }

    @Transactional
    public void deletePolicy(ManagementContext context, long id) {
        if (!context.isAdmin()) {
            throw new IllegalArgumentException("只有租户 ADMIN 可以管理出口授权");
        }
        PeerMeshEgressPolicy policy = policyRepository
                .findByIdAndTenantId(id, context.tenant().tenantId())
                .orElseThrow(() -> new IllegalArgumentException("egress policy not found: " + id));
        policyRepository.delete(policy);
    }

    /**
     * Records one {@code egress-report}.
     *
     * <p>The reporter identity and session come from the authenticated control connection the
     * caller resolved, never from the message body. Counters are clamped to non-negative and
     * refusal keys are filtered to codes this build defines, so a client cannot grow the stored map
     * with keys of its own invention.
     */
    @Transactional
    public void handleReport(ClientAccount source, PeerControlMessage report, long sessionId) {
        enforceReportRateLimit(sessionId);
        long revision = report.getRevision() == null ? 0L : report.getRevision();

        PeerMeshEgressActivity activity = activityRepository
                .findByTenantIdAndEgressClientId(source.getTenantId(), source.getId())
                .orElse(null);
        String now = Instant.now().toString();
        if (activity == null) {
            activity = new PeerMeshEgressActivity();
            activity.setId(ClientIdGenerator.newId());
            activity.setTenantId(source.getTenantId());
            activity.setEgressClientId(source.getId());
            activity.setCreatedAt(now);
        } else if (revision > 0 && revision < activity.getRevision()) {
            // Reports can overtake each other on reconnect; an older snapshot must not overwrite a
            // newer one.
            return;
        }
        activity.setEgressClientName(source.getClientName());
        activity.setSessionId(sessionId);
        activity.setRevision(revision);
        activity.setActiveFlows(nonNegative(report.getActiveFlows()));
        activity.setTotalFlows(nonNegative(report.getTotalFlows()));
        activity.setBytesIn(nonNegative(report.getBytesIn()));
        activity.setBytesOut(nonNegative(report.getBytesOut()));
        activity.setRejectedFlows(encodeRejectedFlows(report.getRejectedFlows()));
        activity.setReportedAt(now);
        activity.setUpdatedAt(now);
        activityRepository.save(activity);
    }

    /** Latest self-reported counters for every egress device in the tenant. */
    @Transactional(readOnly = true)
    public List<PeerMeshEgressActivityView> listActivity(ManagementContext context,
                                                         Predicate<String> onlineCheck) {
        List<PeerMeshEgressActivityView> views = new ArrayList<>();
        for (PeerMeshEgressActivity row : activityRepository
                .findByTenantIdOrderByEgressClientNameAsc(context.tenant().tenantId())) {
            views.add(new PeerMeshEgressActivityView(
                    row.getEgressClientId(),
                    row.getEgressClientName(),
                    onlineCheck != null && onlineCheck.test(row.getEgressClientName()),
                    row.getRevision(),
                    row.getActiveFlows(),
                    row.getTotalFlows(),
                    decodeRejectedFlows(row.getRejectedFlows()),
                    row.getBytesIn(),
                    row.getBytesOut(),
                    row.getReportedAt()));
        }
        return views;
    }

    private static long nonNegative(Long value) {
        return value == null || value < 0L ? 0L : value;
    }

    static String encodeRejectedFlows(Map<String, Long> reported) {
        if (reported == null || reported.isEmpty()) {
            return "{}";
        }
        Map<String, Long> filtered = new LinkedHashMap<>();
        for (Map.Entry<String, Long> entry : reported.entrySet()) {
            if (!PeerEgressCodes.isKnown(entry.getKey()) || entry.getValue() == null || entry.getValue() < 0L) {
                continue;
            }
            filtered.put(entry.getKey(), entry.getValue());
        }
        if (filtered.isEmpty()) {
            return "{}";
        }
        String encoded = JsonUtil.objectToString(filtered);
        if (encoded == null || encoded.getBytes(StandardCharsets.UTF_8).length
                > PeerMeshEgressActivity.MAX_REJECTED_FLOWS_BYTES) {
            // Cannot happen with known codes only; refusing beats storing a truncated map.
            return "{}";
        }
        return encoded;
    }

    static Map<String, Long> decodeRejectedFlows(String raw) {
        if (!StringUtils.hasText(raw)) {
            return Map.of();
        }
        try {
            Map<String, Long> decoded = JsonUtil.stringToObject(raw, new TypeReference<>() {
            });
            return decoded == null ? Map.of() : decoded;
        } catch (RuntimeException ex) {
            log.warn("[peer-egress] stored refusal counters are unreadable; reporting none");
            return Map.of();
        }
    }

    /**
     * Bounds how often one control session may report.
     *
     * <p>The tracked table has a hard ceiling: it is keyed by client-driven session ids, so without
     * one an abusive peer could grow it without bound.
     */
    void enforceReportRateLimit(long sessionId) {
        long now = System.currentTimeMillis();
        long windowStart = now - PeerEgressProtocol.REPORT_RATE_WINDOW.toMillis();
        ConcurrentLinkedDeque<Long> stamps = reportTimestamps.get(sessionId);
        if (stamps == null) {
            synchronized (reportTimestamps) {
                stamps = reportTimestamps.get(sessionId);
                if (stamps == null) {
                    if (reportTimestamps.size() >= PeerEgressProtocol.MAX_RATE_TABLE_ENTRIES) {
                        throw new IllegalArgumentException("egress-report rate limited");
                    }
                    stamps = new ConcurrentLinkedDeque<>();
                    reportTimestamps.put(sessionId, stamps);
                }
            }
        }
        synchronized (stamps) {
            while (true) {
                Long first = stamps.peekFirst();
                if (first == null || first >= windowStart) {
                    break;
                }
                stamps.pollFirst();
            }
            if (stamps.size() >= PeerEgressProtocol.REPORT_RATE_LIMIT) {
                throw new IllegalArgumentException("egress-report rate limited");
            }
            stamps.addLast(now);
        }
    }

    /**
     * Rejects an {@code egress-report} envelope that carries routing or identity the server binds
     * itself. An explicit {@code null} is a violation too: the field must be absent.
     */
    public static void validateReportEnvelope(String message, String toClientName) {
        if (message == null
                || message.getBytes(StandardCharsets.UTF_8).length > PeerEgressProtocol.MAX_REPORT_BYTES) {
            throw new IllegalArgumentException(
                    "egress-report exceeds " + PeerEgressProtocol.MAX_REPORT_BYTES + " bytes");
        }
        if (StringUtils.hasText(toClientName)) {
            throw new IllegalArgumentException("egress-report toClientName must be empty");
        }
        JsonNode root = JsonUtil.readString(message);
        if (root == null || !root.isObject()) {
            throw new IllegalArgumentException("invalid egress-report");
        }
        for (String field : List.of(
                "sourceClientId", "sourceClientName", "sourceVirtualIp", "sourcePublicKey", "sourceKeyEpoch",
                "targetClientId", "targetClientName", "targetVirtualIp", "targetPublicKey",
                "sessionId", "token")) {
            if (root.has(field)) {
                throw new IllegalArgumentException("egress-report " + field + " is server-bound");
            }
        }
    }

    /**
     * Builds the {@code egress-config} pushed to an egress device.
     *
     * <p>Returns null when the client cannot take part, so callers never push a half-formed policy
     * to a runtime that would not understand it.
     */
    @Transactional(readOnly = true)
    public PeerControlMessage buildEgressConfig(ClientAccount account, ClientEnvironmentInfo environment) {
        return buildEgressConfig(account, environmentVersion(environment));
    }

    /**
     * Builds the {@code egress-config} for a client whose announced version is already known, which
     * is what the signal push path has: it starts from a stored session rather than a login payload.
     */
    @Transactional(readOnly = true)
    public PeerControlMessage buildEgressConfig(ClientAccount account, int clientEgressVersion) {
        if (account == null || clientEgressVersion < 1) {
            return null;
        }
        PeerControlMessage message = new PeerControlMessage();
        message.setType(PeerControlMessage.TYPE_EGRESS_CONFIG);
        message.setRevision(revisions.incrementAndGet());

        Optional<PeerMeshEgressPolicy> stored = policyRepository
                .findByTenantIdAndEgressClientId(account.getTenantId(), account.getId());
        if (stored.isEmpty() || !stored.get().isEnabled() || !peerMeshService.isEnabled()
                || !egressEnabledFor(account.getTenantId())) {
            message.setEnabled(false);
            message.setAllowedConsumerClientIds(List.of());
            message.setDestinationRules(List.of());
            return message;
        }
        PeerMeshEgressPolicy policy = stored.get();
        message.setEnabled(true);
        message.setScope(policy.getScope());
        message.setAllowedConsumerClientIds(allowedConsumerIds(account, policy));
        message.setDestinationRules(decodeDestinationRules(policy.getDestinationRules()));

        PeerEgressPolicy.PeerEgressLimits limits = new PeerEgressPolicy.PeerEgressLimits();
        limits.setMaxConcurrentFlows(policy.getMaxConcurrentFlows());
        limits.setMaxFlowsPerConsumer(policy.getMaxFlowsPerConsumer());
        limits.setIdleTimeoutSeconds(policy.getIdleTimeoutSeconds());
        message.setLimits(limits);
        return message;
    }

    /** Builds the {@code egress-catalog} pushed to a consumer device. */
    @Transactional(readOnly = true)
    public PeerControlMessage buildEgressCatalog(ClientAccount account, ClientEnvironmentInfo environment) {
        return buildEgressCatalog(account, environmentVersion(environment));
    }

    /** Builds the {@code egress-catalog} for a client whose announced version is already known. */
    @Transactional(readOnly = true)
    public PeerControlMessage buildEgressCatalog(ClientAccount account, int clientEgressVersion) {
        if (account == null || clientEgressVersion < 1) {
            return null;
        }
        PeerControlMessage message = new PeerControlMessage();
        message.setType(PeerControlMessage.TYPE_EGRESS_CATALOG);
        message.setRevision(revisions.incrementAndGet());
        if (!peerMeshService.isEnabled() || !egressEnabledFor(account.getTenantId())) {
            message.setEgresses(List.of());
            return message;
        }

        List<PeerEgressCatalogEntry> entries = new ArrayList<>();
        for (PeerMeshEgressPolicy policy : policyRepository
                .findByTenantIdAndEnabledTrueOrderByEgressClientNameAsc(account.getTenantId())) {
            if (Objects.equals(policy.getEgressClientId(), account.getId())) {
                continue;
            }
            Optional<ClientAccount> egress = clientAccountRepository
                    .findByIdAndTenantId(policy.getEgressClientId(), account.getTenantId());
            if (egress.isEmpty() || !peerMeshService.canPeer(account, egress.get())) {
                continue;
            }
            if (!allowedConsumerIds(egress.get(), policy).contains(account.getId())) {
                continue;
            }
            PeerEgressCatalogEntry entry = new PeerEgressCatalogEntry();
            entry.setClientId(policy.getEgressClientId());
            entry.setClientName(policy.getEgressClientName());
            entry.setOnline(isDeviceEnabled(egress.get()));
            entry.setScope(policy.getScope());
            entry.setProtocols(protocolsOf(decodeDestinationRules(policy.getDestinationRules())));
            entry.setDomainTargetCapable(false);
            entry.setIpv6TargetCapable(false);
            entries.add(entry);
        }
        message.setEgresses(entries);
        return message;
    }

    /**
     * Effective consumers for an egress: the policy allowlist intersected with the base Peer ACL.
     *
     * <p>Taking the intersection here, rather than only on the egress node, keeps the two failure
     * modes aligned: a device that cannot see the egress in its catalogue also cannot reach it on
     * the data plane.
     */
    List<Long> allowedConsumerIds(ClientAccount egress, PeerMeshEgressPolicy policy) {
        if (egress == null || policy == null || !policy.isEnabled()) {
            return List.of();
        }
        List<Long> explicit = PeerServiceDiscovery.decodeClientIds(policy.getAllowedConsumerClientIds());
        if (explicit.isEmpty()) {
            // An empty consumer allowlist grants nothing. Egress is opt-in per device on both sides.
            return List.of();
        }
        Set<Long> allowed = new LinkedHashSet<>();
        for (ClientAccount candidate : clientAccountRepository
                .findByTenantIdOrderByIdDesc(egress.getTenantId())) {
            if (Objects.equals(candidate.getId(), egress.getId())) {
                continue;
            }
            if (!explicit.contains(candidate.getId())) {
                continue;
            }
            if (!peerMeshService.canPeer(candidate, egress)) {
                continue;
            }
            allowed.add(candidate.getId());
        }
        return List.copyOf(allowed);
    }

    static boolean supportsEgress(ClientEnvironmentInfo environment) {
        return environmentVersion(environment) >= 1;
    }

    private static int environmentVersion(ClientEnvironmentInfo environment) {
        if (environment == null || environment.getClientEgressCapabilities() == null) {
            return 0;
        }
        return PeerEgressProtocol.normalizeVersion(environment.getClientEgressCapabilities().getVersion());
    }

    private boolean isDeviceEnabled(ClientAccount account) {
        return deviceRepository.findByTenantIdAndClientId(account.getTenantId(), account.getId())
                .map(PeerMeshDevice::isEnabled)
                .orElse(false);
    }

    private static List<String> protocolsOf(List<PeerEgressPolicy.PeerEgressDestinationRule> rules) {
        Set<String> protocols = new LinkedHashSet<>();
        for (PeerEgressPolicy.PeerEgressDestinationRule rule : rules) {
            if (rule.getProtocols() != null) {
                protocols.addAll(rule.getProtocols());
            }
        }
        return List.copyOf(protocols);
    }

    static String encodeDestinationRules(List<PeerEgressPolicy.PeerEgressDestinationRule> rules) {
        if (rules == null || rules.isEmpty()) {
            return "[]";
        }
        if (rules.size() > PeerMeshEgressPolicy.MAX_DESTINATION_RULES) {
            throw new IllegalArgumentException("too many destination rules: " + rules.size());
        }
        String json = JsonUtil.objectToString(rules);
        if (json == null) {
            throw new IllegalArgumentException("destination rules cannot be serialised");
        }
        if (json.getBytes(StandardCharsets.UTF_8).length > PeerMeshEgressPolicy.MAX_DESTINATION_RULES_BYTES) {
            throw new IllegalArgumentException("destination rules exceed the storage limit");
        }
        return json;
    }

    static List<PeerEgressPolicy.PeerEgressDestinationRule> decodeDestinationRules(String raw) {
        if (!StringUtils.hasText(raw)) {
            return List.of();
        }
        try {
            List<PeerEgressPolicy.PeerEgressDestinationRule> rules = JsonUtil.stringToObject(
                    raw, new TypeReference<List<PeerEgressPolicy.PeerEgressDestinationRule>>() {
                    });
            return rules == null ? List.of() : rules;
        } catch (RuntimeException e) {
            // A row we cannot read must not widen access; treat it as deny-all and say so.
            log.warn("Peer egress destination rules are unreadable; treating the policy as deny-all");
            return List.of();
        }
    }

    private static int requirePositive(int value, String field) {
        if (value <= 0) {
            throw new IllegalArgumentException(field + " must be positive");
        }
        return value;
    }
}
