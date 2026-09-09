package com.theshuai.specusserver.management.service;

import com.theshuai.common.clientauth.ClientEnvironmentInfo;
import com.theshuai.common.peeregress.PeerEgressCodes;
import com.theshuai.common.peeregress.PeerEgressPolicy;
import com.theshuai.common.peeregress.PeerEgressProtocol;
import com.theshuai.common.peermesh.PeerControlMessage;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.model.PeerMeshDevice;
import com.theshuai.specusserver.management.model.PeerMeshEgressActivity;
import com.theshuai.specusserver.management.model.PeerMeshEgressSwitch;
import com.theshuai.specusserver.management.model.PeerMeshEgressPolicy;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.PeerMeshDeviceRepository;
import com.theshuai.specusserver.management.repository.PeerMeshEgressActivityRepository;
import com.theshuai.specusserver.management.repository.PeerMeshEgressSwitchRepository;
import com.theshuai.specusserver.management.repository.PeerMeshEgressPolicyRepository;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class PeerEgressServiceTests {
    private static final String TENANT = "t1";

    private final PeerMeshEgressPolicyRepository policyRepository = mock(PeerMeshEgressPolicyRepository.class);
    private final PeerMeshDeviceRepository deviceRepository = mock(PeerMeshDeviceRepository.class);
    private final ClientAccountRepository clientAccountRepository = mock(ClientAccountRepository.class);
    private final PeerMeshService peerMeshService = mock(PeerMeshService.class);
    private final PeerMeshEgressActivityRepository activityRepository = mock(PeerMeshEgressActivityRepository.class);
    private final PeerMeshEgressSwitchRepository switchRepository = mock(PeerMeshEgressSwitchRepository.class);

    private final PeerEgressService service = new PeerEgressService(
            policyRepository, activityRepository, switchRepository, deviceRepository,
            clientAccountRepository, peerMeshService);

    private final ClientAccount egress = account(2, "office-gateway");
    private final ClientAccount consumer = account(1, "laptop");

    /**
     * The tenant switch is off by default, so any test expecting a policy to take effect has to turn
     * it on. That default is the point: egress is opt-in for the tenant as well as per device.
     */
    private void tenantEgressOn() {
        PeerMeshEgressSwitch on = new PeerMeshEgressSwitch();
        on.setTenantId(TENANT);
        on.setEnabled(true);
        when(switchRepository.findById(TENANT)).thenReturn(Optional.of(on));
    }

    /**
     * The point of keeping egress policy separate from the mesh ACL: naming a device in the egress
     * allowlist must not grant it anything if the base ACL does not already allow the pair.
     */
    @Test
    void baseMeshAccessIsRequiredOnTopOfTheEgressAllowlist() {
        PeerMeshEgressPolicy policy = policy(List.of(1L));
        when(clientAccountRepository.findByTenantIdOrderByIdDesc(TENANT)).thenReturn(List.of(consumer, egress));

        when(peerMeshService.canPeer(any(), any())).thenReturn(true);
        assertThat(service.allowedConsumerIds(egress, policy)).containsExactly(1L);

        when(peerMeshService.canPeer(any(), any())).thenReturn(false);
        assertThat(service.allowedConsumerIds(egress, policy)).isEmpty();
    }

    @Test
    void anEmptyConsumerAllowlistGrantsNothing() {
        PeerMeshEgressPolicy policy = policy(List.of());
        when(clientAccountRepository.findByTenantIdOrderByIdDesc(TENANT)).thenReturn(List.of(consumer, egress));
        when(peerMeshService.canPeer(any(), any())).thenReturn(true);

        assertThat(service.allowedConsumerIds(egress, policy)).isEmpty();
    }

    @Test
    void aDisabledPolicyGrantsNothingAndPushesAnEmptyConfig() {
        PeerMeshEgressPolicy policy = policy(List.of(1L));
        policy.setEnabled(false);
        when(clientAccountRepository.findByTenantIdOrderByIdDesc(TENANT)).thenReturn(List.of(consumer, egress));
        when(peerMeshService.canPeer(any(), any())).thenReturn(true);
        when(peerMeshService.isEnabled()).thenReturn(true);
        when(policyRepository.findByTenantIdAndEgressClientId(TENANT, 2L)).thenReturn(Optional.of(policy));

        assertThat(service.allowedConsumerIds(egress, policy)).isEmpty();

        PeerControlMessage config = service.buildEgressConfig(egress, environment(1));
        assertThat(config).isNotNull();
        assertThat(config.getEnabled()).isFalse();
        assertThat(config.getDestinationRules()).isEmpty();
        assertThat(config.getAllowedConsumerClientIds()).isEmpty();
    }

    @Test
    void clientsThatCannotDoEgressAreNeverPushedAPolicy() {
        assertThat(service.buildEgressConfig(egress, environment(0))).isNull();
        assertThat(service.buildEgressConfig(egress, null)).isNull();
        assertThat(service.buildEgressCatalog(consumer, environment(0))).isNull();
    }

    @Test
    void anEnabledPolicyPushesRulesAndLimits() {
        tenantEgressOn();
        PeerMeshEgressPolicy policy = policy(List.of(1L));
        when(clientAccountRepository.findByTenantIdOrderByIdDesc(TENANT)).thenReturn(List.of(consumer, egress));
        when(peerMeshService.canPeer(any(), any())).thenReturn(true);
        when(peerMeshService.isEnabled()).thenReturn(true);
        when(policyRepository.findByTenantIdAndEgressClientId(TENANT, 2L)).thenReturn(Optional.of(policy));

        PeerControlMessage config = service.buildEgressConfig(egress, environment(1));
        assertThat(config.getEnabled()).isTrue();
        assertThat(config.getScope()).isEqualTo(PeerEgressPolicy.SCOPE_PUBLIC);
        assertThat(config.getAllowedConsumerClientIds()).containsExactly(1L);
        assertThat(config.getDestinationRules()).hasSize(1);
        assertThat(config.getDestinationRules().get(0).getCidr()).isEqualTo("203.0.113.0/24");
        assertThat(config.getLimits().getMaxFlowsPerConsumer()).isEqualTo(64);
        assertThat(config.getRevision()).isPositive();
    }

    /**
     * A consumer learns which egress nodes exist, never what they are permitted to reach. Shipping
     * the destination allowlist would hand every peer a map of that node's network.
     */
    @Test
    void theCatalogueCarriesNoDestinationAllowlist() {
        tenantEgressOn();
        PeerMeshEgressPolicy policy = policy(List.of(1L));
        when(peerMeshService.isEnabled()).thenReturn(true);
        when(peerMeshService.canPeer(any(), any())).thenReturn(true);
        when(clientAccountRepository.findByTenantIdOrderByIdDesc(TENANT)).thenReturn(List.of(consumer, egress));
        when(clientAccountRepository.findByIdAndTenantId(2L, TENANT)).thenReturn(Optional.of(egress));
        when(policyRepository.findByTenantIdAndEnabledTrueOrderByEgressClientNameAsc(TENANT))
                .thenReturn(List.of(policy));
        PeerMeshDevice device = new PeerMeshDevice();
        device.setEnabled(true);
        when(deviceRepository.findByTenantIdAndClientId(TENANT, 2L)).thenReturn(Optional.of(device));

        PeerControlMessage catalog = service.buildEgressCatalog(consumer, environment(1));
        assertThat(catalog.getEgresses()).hasSize(1);
        assertThat(catalog.getEgresses().get(0).getClientId()).isEqualTo(2L);
        assertThat(catalog.getEgresses().get(0).getProtocols()).containsExactly("tcp");
        assertThat(catalog.getEgresses().get(0).isDomainTargetCapable()).isFalse();
        assertThat(catalog.getDestinationRules()).isNull();
    }

    @Test
    void aConsumerOutsideTheAllowlistDoesNotSeeTheEgress() {
        PeerMeshEgressPolicy policy = policy(List.of(99L));
        when(peerMeshService.isEnabled()).thenReturn(true);
        when(peerMeshService.canPeer(any(), any())).thenReturn(true);
        when(clientAccountRepository.findByTenantIdOrderByIdDesc(TENANT)).thenReturn(List.of(consumer, egress));
        when(clientAccountRepository.findByIdAndTenantId(2L, TENANT)).thenReturn(Optional.of(egress));
        when(policyRepository.findByTenantIdAndEnabledTrueOrderByEgressClientNameAsc(TENANT))
                .thenReturn(List.of(policy));

        assertThat(service.buildEgressCatalog(consumer, environment(1)).getEgresses()).isEmpty();
    }

    @Test
    void destinationRulesRoundTripAndRejectOversizedInput() {
        PeerEgressPolicy.PeerEgressDestinationRule rule = destinationRule();
        String encoded = PeerEgressService.encodeDestinationRules(List.of(rule));
        assertThat(PeerEgressService.decodeDestinationRules(encoded)).hasSize(1);
        assertThat(PeerEgressService.decodeDestinationRules(null)).isEmpty();

        List<PeerEgressPolicy.PeerEgressDestinationRule> tooMany =
                java.util.Collections.nCopies(PeerMeshEgressPolicy.MAX_DESTINATION_RULES + 1, rule);
        assertThatThrownBy(() -> PeerEgressService.encodeDestinationRules(tooMany))
                .isInstanceOf(IllegalArgumentException.class);
    }

    /** An unreadable row must deny everything rather than fall back to something permissive. */
    @Test
    void unreadableStoredRulesDenyEverything() {
        assertThat(PeerEgressService.decodeDestinationRules("{not json")).isEmpty();
        assertThat(PeerEgressService.decodeDestinationRules("")).isEmpty();
    }

    private static PeerEgressPolicy.PeerEgressDestinationRule destinationRule() {
        PeerEgressPolicy.PeerEgressDestinationRule rule = new PeerEgressPolicy.PeerEgressDestinationRule();
        rule.setCidr("203.0.113.0/24");
        rule.setProtocols(List.of("tcp"));
        rule.setPortRanges(List.of(List.of(443, 443)));
        return rule;
    }

    private PeerMeshEgressPolicy policy(List<Long> consumers) {
        PeerMeshEgressPolicy policy = new PeerMeshEgressPolicy();
        policy.setId(10L);
        policy.setTenantId(TENANT);
        policy.setOwnerUsername("admin");
        policy.setEgressClientId(2L);
        policy.setEgressClientName("office-gateway");
        policy.setEnabled(true);
        policy.setScope(PeerEgressPolicy.SCOPE_PUBLIC);
        policy.setAllowedConsumerClientIds(
                com.theshuai.common.peermesh.PeerServiceDiscovery.encodeClientIds(consumers));
        policy.setDestinationRules(PeerEgressService.encodeDestinationRules(List.of(destinationRule())));
        return policy;
    }

    private static ClientAccount account(long id, String name) {
        ClientAccount account = new ClientAccount();
        account.setId(id);
        account.setTenantId(TENANT);
        account.setClientName(name);
        account.setOwnerUsername("admin");
        return account;
    }

    private static ClientEnvironmentInfo environment(int egressVersion) {
        ClientEnvironmentInfo environment = new ClientEnvironmentInfo();
        environment.getClientEgressCapabilities().setVersion(egressVersion);
        environment.getClientEgressCapabilities().setEgressCapable(egressVersion >= 1);
        environment.getClientEgressCapabilities().setConsumerCapable(egressVersion >= 1);
        return environment;
    }

    /**
     * The report carries counters only. A client that invents refusal keys must not be able to grow
     * what the server stores.
     */
    @Test
    void refusalCountersKeepOnlyCodesThisBuildDefines() {
        assertThat(PeerEgressService.encodeRejectedFlows(new LinkedHashMap<>(Map.of(
                PeerEgressCodes.DEST_DENIED, 4L,
                "EGRESS_MADE_UP", 9L,
                PeerEgressCodes.PORT_DENIED, 1L))))
                .contains(PeerEgressCodes.DEST_DENIED)
                .contains(PeerEgressCodes.PORT_DENIED)
                .doesNotContain("EGRESS_MADE_UP");
        assertThat(PeerEgressService.encodeRejectedFlows(Map.of("EGRESS_MADE_UP", 9L))).isEqualTo("{}");
        assertThat(PeerEgressService.encodeRejectedFlows(null)).isEqualTo("{}");
        // A negative counter is a client bug or an attempt to skew the view; drop the entry.
        assertThat(PeerEgressService.encodeRejectedFlows(Map.of(PeerEgressCodes.PORT_DENIED, -3L)))
                .isEqualTo("{}");
    }

    /** An unreadable stored map must read as no refusals rather than break the management view. */
    @Test
    void unreadableStoredCountersReadAsEmpty() {
        assertThat(PeerEgressService.decodeRejectedFlows("not json")).isEmpty();
        assertThat(PeerEgressService.decodeRejectedFlows("")).isEmpty();
        assertThat(PeerEgressService.decodeRejectedFlows(null)).isEmpty();
        assertThat(PeerEgressService.decodeRejectedFlows("{\"EGRESS_PORT_DENIED\":2}"))
                .containsEntry(PeerEgressCodes.PORT_DENIED, 2L);
    }

    /**
     * The server binds the reporter from the authenticated control connection, so a report that
     * carries routing or identity of its own is a protocol violation rather than something to
     * sanitise and accept.
     */
    @Test
    void reportEnvelopeRejectsClientControlledRoutingAndIdentity() {
        PeerEgressService.validateReportEnvelope("{\"type\":\"egress-report\",\"activeFlows\":3}", "");
        assertThatThrownBy(() -> PeerEgressService.validateReportEnvelope(
                "{\"type\":\"egress-report\"}", "peer-b"))
                .isInstanceOf(IllegalArgumentException.class);
        for (String field : List.of("sourceClientId", "sourceClientName", "targetClientId",
                "targetClientName", "sessionId", "token")) {
            // An explicit null is a violation too: the field has to be absent.
            assertThatThrownBy(() -> PeerEgressService.validateReportEnvelope(
                    "{\"type\":\"egress-report\",\"" + field + "\":null}", ""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining(field);
        }
        assertThatThrownBy(() -> PeerEgressService.validateReportEnvelope(
                "{\"type\":\"egress-report\",\"padding\":\"" + "x".repeat(9000) + "\"}", ""))
                .isInstanceOf(IllegalArgumentException.class);
    }

    /** The rate table is keyed by client-driven session ids, so it needs a ceiling of its own. */
    @Test
    void reportRateLimitBoundsBothTheWindowAndTheTable() {
        for (int i = 0; i < PeerEgressProtocol.REPORT_RATE_LIMIT; i++) {
            service.enforceReportRateLimit(7001L);
        }
        assertThatThrownBy(() -> service.enforceReportRateLimit(7001L))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("rate limited");

        // Session 7001 above already holds one slot, so fill the remainder.
        for (long session = 2; session <= PeerEgressProtocol.MAX_RATE_TABLE_ENTRIES; session++) {
            service.enforceReportRateLimit(100_000L + session);
        }
        assertThatThrownBy(() -> service.enforceReportRateLimit(999_999L))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("rate limited");
    }

    /** A snapshot that arrives after a newer one must not roll the counters backwards. */
    @Test
    void anOlderSnapshotDoesNotOverwriteANewerOne() {
        PeerMeshEgressActivity stored = new PeerMeshEgressActivity();
        stored.setId(9L);
        stored.setTenantId(TENANT);
        stored.setEgressClientId(egress.getId());
        stored.setRevision(12L);
        stored.setActiveFlows(18L);
        when(activityRepository.findByTenantIdAndEgressClientId(TENANT, egress.getId()))
                .thenReturn(Optional.of(stored));

        PeerControlMessage stale = new PeerControlMessage();
        stale.setRevision(5L);
        stale.setActiveFlows(1L);
        service.handleReport(egress, stale, 4242L);
        verify(activityRepository, never()).save(any());

        PeerControlMessage fresh = new PeerControlMessage();
        fresh.setRevision(13L);
        fresh.setActiveFlows(21L);
        fresh.setRejectedFlows(Map.of(PeerEgressCodes.PORT_DENIED, 2L));
        service.handleReport(egress, fresh, 4242L);
        assertThat(stored.getActiveFlows()).isEqualTo(21L);
        assertThat(stored.getSessionId()).isEqualTo(4242L);
        assertThat(stored.getRejectedFlows()).contains(PeerEgressCodes.PORT_DENIED);
        verify(activityRepository).save(stored);
    }


    /** The tenant switch and the per-device flag are two gates; both must be on. */
    @Test
    void theTenantSwitchGatesEveryPolicy() {
        PeerMeshEgressPolicy policy = policy(List.of(1L));
        when(policyRepository.findByTenantIdAndEgressClientId(TENANT, egress.getId()))
                .thenReturn(Optional.of(policy));
        when(clientAccountRepository.findByTenantIdOrderByIdDesc(TENANT))
                .thenReturn(List.of(consumer, egress));
        when(peerMeshService.isEnabled()).thenReturn(true);
        when(peerMeshService.canPeer(any(), any())).thenReturn(true);

        // Off by default: an unset tenant switch grants nothing even with an enabled policy.
        when(switchRepository.findById(TENANT)).thenReturn(Optional.empty());
        PeerControlMessage config = service.buildEgressConfig(egress, 1);
        assertThat(config.getEnabled()).isFalse();
        assertThat(config.getAllowedConsumerClientIds()).isEmpty();

        PeerMeshEgressSwitch on = new PeerMeshEgressSwitch();
        on.setTenantId(TENANT);
        on.setEnabled(true);
        when(switchRepository.findById(TENANT)).thenReturn(Optional.of(on));
        config = service.buildEgressConfig(egress, 1);
        assertThat(config.getEnabled()).isTrue();
        assertThat(config.getAllowedConsumerClientIds()).containsExactly(1L);
    }

}
