package com.theshuai.specusserver.management.service;

import com.theshuai.common.protocol.response.MessageResponsePacket;
import com.theshuai.common.session.Session;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.repository.ClientSessionRepository;
import com.theshuai.specusserver.session.SessionUtil;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A device that leaves has to be announced as gone, the way a device that arrives is announced as
 * here. Rosters were pushed on login and never on logout, so a consumer kept an egress that had
 * stopped as online and went on sending it flows that nothing would ever answer.
 */
class PeerSignalServiceLogoutTests {

    private final ClientAccountService accounts = mock(ClientAccountService.class);
    private final PeerMeshService mesh = mock(PeerMeshService.class);
    private final PeerSignalService service = new PeerSignalService(accounts, mesh,
            mock(PeerServiceDiscoveryService.class), mock(ClientSessionRepository.class),
            mock(PeerEgressService.class));
    private final List<EmbeddedChannel> bound = new ArrayList<>();

    @AfterEach
    void unbind() {
        for (EmbeddedChannel channel : bound) {
            SessionUtil.unBindSession(channel);
            channel.finishAndReleaseAll();
        }
    }

    @Test
    void pushOnLogoutSendsTheDepartedDevicesPeersARoster() {
        ClientAccount consumer = account(1201L, "alice-laptop");
        ClientAccount departed = account(1202L, "office-gateway");
        when(mesh.isEnabled()).thenReturn(true);
        when(accounts.findClientByName("office-gateway")).thenReturn(Optional.of(departed));
        when(mesh.rosterRefreshTargets(departed)).thenReturn(List.of(consumer));
        when(mesh.allowedRoster(consumer)).thenReturn(List.of());
        EmbeddedChannel consumerChannel = bind("alice-laptop");

        service.pushOnLogout("office-gateway");

        MessageResponsePacket roster = consumerChannel.readOutbound();
        assertNotNull(roster, "the consumer was not sent a roster when its peer left");
        assertTrue(roster.getMessage().contains("\"type\":\"roster\""), roster.getMessage());
    }

    // A device already back on a newer channel when the old one is torn down was announced by that
    // login; a logout push would announce it as gone while it is not.
    @Test
    void pushOnLogoutIsSilentForADeviceThatIsAlreadyBack() {
        ClientAccount departed = account(1202L, "office-gateway");
        when(mesh.isEnabled()).thenReturn(true);
        when(accounts.findClientByName("office-gateway")).thenReturn(Optional.of(departed));
        EmbeddedChannel consumerChannel = bind("alice-laptop");
        bind("office-gateway");

        service.pushOnLogout("office-gateway");

        assertNull(consumerChannel.readOutbound(), "a device that is still bound was announced");
        verify(mesh, never()).rosterRefreshTargets(any());
    }

    private EmbeddedChannel bind(String clientName) {
        EmbeddedChannel channel = new EmbeddedChannel();
        SessionUtil.bindSession(new Session(clientName), channel);
        bound.add(channel);
        return channel;
    }

    private static ClientAccount account(long id, String name) {
        ClientAccount account = new ClientAccount();
        account.setId(id);
        account.setTenantId("tenant-a");
        account.setClientName(name);
        return account;
    }
}
