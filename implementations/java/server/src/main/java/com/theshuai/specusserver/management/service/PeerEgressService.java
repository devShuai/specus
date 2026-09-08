package com.theshuai.specusserver.management.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.theshuai.common.clientauth.ClientEnvironmentInfo;
import com.theshuai.common.peeregress.PeerEgressCatalogEntry;
import com.theshuai.common.peeregress.PeerEgressPolicy;
import com.theshuai.common.peeregress.PeerEgressProtocol;
import com.theshuai.common.peermesh.PeerControlMessage;
import com.theshuai.common.peermesh.PeerServiceDiscovery;
import com.theshuai.common.util.JsonUtil;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.model.PeerMeshDevice;
import com.theshuai.specusserver.management.model.PeerMeshEgressPolicy;
import com.theshuai.specusserver.management.model.PeerMeshEgressPolicyView;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.PeerMeshDeviceRepository;
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
    private final PeerMeshDeviceRepository deviceRepository;
    private final ClientAccountRepository clientAccountRepository;
    private final PeerMeshService peerMeshService;

    public PeerEgressService(PeerMeshEgressPolicyRepository policyRepository,
                             PeerMeshDeviceRepository deviceRepository,
                             ClientAccountRepository clientAccountRepository,
                             PeerMeshService peerMeshService) {
        this.policyRepository = policyRepository;
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
        if (stored.isEmpty() || !stored.get().isEnabled() || !peerMeshService.isEnabled()) {
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
        if (!peerMeshService.isEnabled()) {
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
