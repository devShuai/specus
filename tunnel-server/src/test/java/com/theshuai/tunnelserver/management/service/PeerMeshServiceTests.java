package com.theshuai.tunnelserver.management.service;

import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import com.theshuai.common.clientauth.ClientEnvironmentInfo;
import com.theshuai.tunnelserver.config.PeerMeshProperties;
import com.theshuai.tunnelserver.management.model.ClientAccount;
import com.theshuai.tunnelserver.management.model.PeerMeshAcl;
import com.theshuai.tunnelserver.management.model.PeerMeshDevice;
import com.theshuai.tunnelserver.management.repository.ClientAccountRepository;
import com.theshuai.tunnelserver.management.repository.PeerMeshAclRepository;
import com.theshuai.tunnelserver.management.repository.PeerMeshDeviceRepository;
import com.theshuai.tunnelserver.management.repository.PeerMeshSessionRepository;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PeerMeshServiceTests {

    private final PeerMeshDeviceRepository deviceRepository = mock(PeerMeshDeviceRepository.class);
    private final PeerMeshAclRepository aclRepository = mock(PeerMeshAclRepository.class);
    private final PeerMeshSessionRepository sessionRepository = mock(PeerMeshSessionRepository.class);
    private final ClientAccountRepository clientAccountRepository = mock(ClientAccountRepository.class);
    private final PeerMeshProperties properties = new PeerMeshProperties();
    private final PeerMeshService service = new PeerMeshService(
            properties,
            deviceRepository,
            aclRepository,
            sessionRepository,
            clientAccountRepository
    );

    @Test
    void sameOwnerCanPeerByDefault() {
        assertThat(service.canPeer(client(1, "alice", "a"), client(2, "alice", "b"))).isTrue();
    }

    @Test
    void crossOwnerDeniedWithoutAcl() {
        when(aclRepository.findByTenantIdAndSourceClientIdAndTargetClientId("tenant-a", 1L, 2L))
                .thenReturn(Optional.empty());

        assertThat(service.canPeer(client(1, "alice", "a"), client(2, "bob", "b"))).isFalse();
    }

    @Test
    void crossOwnerAllowedWithExplicitAcl() {
        PeerMeshAcl acl = new PeerMeshAcl();
        acl.setAllowed(true);
        when(aclRepository.findByTenantIdAndSourceClientIdAndTargetClientId("tenant-a", 1L, 2L))
                .thenReturn(Optional.of(acl));

        assertThat(service.canPeer(client(1, "alice", "a"), client(2, "bob", "b"))).isTrue();
    }

    @Test
    void loginConfigAllocatesVirtualIpButLeavesDeviceDisabledByDefault() {
        properties.setEnabled(true);
        when(deviceRepository.findByTenantIdAndClientId("tenant-a", 1L)).thenReturn(Optional.empty());
        when(deviceRepository.findByTenantIdAndVirtualIp(any(), any())).thenReturn(Optional.empty());
        when(deviceRepository.save(any(PeerMeshDevice.class))).thenAnswer(invocation -> invocation.getArgument(0));

        ClientEnvironmentInfo environment = new ClientEnvironmentInfo();
        environment.setPeerPublicKey("public-key");
        ClientAuthLoginResponse.PeerMeshConfig config = service.buildLoginConfig(client(1, "alice", "a"), environment, "127.0.0.1");

        assertThat(config.isEnabled()).isFalse();
        assertThat(config.getVirtualIp()).startsWith("100.");
        assertThat(config.getCidr()).isEqualTo("100.96.0.0/11");
        assertThat(config.getClientPublicKey()).isEqualTo("public-key");
        assertThat(config.getStunPort()).isEqualTo(3478);
    }

    private ClientAccount client(long id, String owner, String name) {
        ClientAccount account = new ClientAccount();
        account.setId(id);
        account.setTenantId("tenant-a");
        account.setOwnerUsername(owner);
        account.setClientName(name);
        account.setEnabled(true);
        return account;
    }
}
