package com.theshuai.specusserver.management.service;

import com.theshuai.common.clientauth.ClientEnvironmentInfo;
import com.theshuai.common.peeregress.PeerEgressPolicy;
import com.theshuai.common.peermesh.PeerControlMessage;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.model.PeerMeshDevice;
import com.theshuai.specusserver.management.model.PeerMeshEgressPolicy;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.PeerMeshDeviceRepository;
import com.theshuai.specusserver.management.repository.PeerMeshEgressPolicyRepository;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PeerEgressServiceTests {
    private static final String TENANT = "t1";

    private final PeerMeshEgressPolicyRepository policyRepository = mock(PeerMeshEgressPolicyRepository.class);
    private final PeerMeshDeviceRepository deviceRepository = mock(PeerMeshDeviceRepository.class);
    private final ClientAccountRepository clientAccountRepository = mock(ClientAccountRepository.class);
    private final PeerMeshService peerMeshService = mock(PeerMeshService.class);

    private final PeerEgressService service = new PeerEgressService(
            policyRepository, deviceRepository, clientAccountRepository, peerMeshService);

    private final ClientAccount egress = account(2, "office-gateway");
    private final ClientAccount consumer = account(1, "laptop");

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
}
