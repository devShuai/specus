package com.theshuai.specusserver.handler;

import com.theshuai.common.protocol.ConnectionRole;
import com.theshuai.common.protocol.request.LoginRequestPacket;
import com.theshuai.common.protocol.response.LoginResponsePacket;
import com.theshuai.specusserver.config.NettyServerProperties;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.service.AuthenticationResult;
import com.theshuai.specusserver.management.service.ClientAuthService;
import com.theshuai.specusserver.management.service.ConnectionRecordService;
import com.theshuai.specusserver.management.service.NatControlService;
import com.theshuai.specusserver.management.service.PeerSignalService;
import com.theshuai.specusserver.productmetrics.ProductMetricsService;
import com.theshuai.specusserver.session.SessionUtil;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.AbstractExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A client whose control connection goes away has to be announced to its peers as gone. The
 * close-future listener {@link SessionUtil} registers unbinds the session before
 * {@code channelInactive} runs, so the handler cannot find the departed client in the session there.
 */
class ManagedLoginLogoutPushTests {
    private final String clientName = "logout-push-" + UUID.randomUUID();
    private final PeerSignalService peerSignal = mock(PeerSignalService.class);
    private final List<EmbeddedChannel> channels = new ArrayList<>();
    private final ManagedLoginRequestHandler handler;

    ManagedLoginLogoutPushTests() {
        ClientAccount account = new ClientAccount();
        account.setId(42L);
        account.setTenantId("t1");
        account.setClientName(clientName);
        ClientAuthService auth = mock(ClientAuthService.class);
        when(auth.authenticateNetty(any(), anyString(), anyString(), anyBoolean()))
                .thenReturn(AuthenticationResult.success(account, 7L));
        handler = new ManagedLoginRequestHandler(auth, mock(ConnectionRecordService.class),
                mock(NatControlService.class), peerSignal, new NettyServerProperties(), new CallerRunsExecutor(),
                mock(ProductMetricsService.class));
    }

    @AfterEach
    void closeChannels() {
        channels.forEach(EmbeddedChannel::finishAndReleaseAll);
    }

    @Test
    void closingTheControlConnectionTellsThePeersOnceTheClientIsUnbound() {
        AtomicBoolean boundWhenPushed = new AtomicBoolean();
        doAnswer(invocation -> {
            boundWhenPushed.set(SessionUtil.getChannel(clientName) != null);
            return null;
        }).when(peerSignal).pushOnLogout(clientName);
        EmbeddedChannel control = login(ConnectionRole.CONTROL);

        control.close();

        verify(peerSignal).pushOnLogout(clientName);
        assertThat(boundWhenPushed).as("the roster would still count the client as online").isFalse();
    }

    // The client is still online on the newer connection, whose login already told its peers.
    @Test
    void closingAControlConnectionReplacedByANewerLoginLeavesTheClientOnline() {
        EmbeddedChannel replaced = login(ConnectionRole.CONTROL);
        EmbeddedChannel current = login(ConnectionRole.CONTROL);
        replaced.runPendingTasks();

        assertThat(replaced.isOpen()).isFalse();
        verify(peerSignal, never()).pushOnLogout(anyString());

        current.close();

        verify(peerSignal).pushOnLogout(clientName);
    }

    @Test
    void closingTheDataConnectionLeavesTheClientOnline() {
        EmbeddedChannel control = login(ConnectionRole.CONTROL);
        EmbeddedChannel data = login(ConnectionRole.DATA);

        data.close();

        verify(peerSignal, never()).pushOnLogout(anyString());
        assertThat(SessionUtil.getChannel(clientName)).isSameAs(control);
    }

    private EmbeddedChannel login(String role) {
        EmbeddedChannel channel = new EmbeddedChannel(handler);
        channels.add(channel);
        LoginRequestPacket login = new LoginRequestPacket();
        login.setClientName(clientName);
        login.setAccessToken("cs_token");
        login.setConnectionRole(role);
        channel.writeInbound(login);
        LoginResponsePacket response = channel.readOutbound();
        assertThat(response).isNotNull();
        assertThat(response.isSuccess()).as(response.getReason()).isTrue();
        return channel;
    }

    /** Runs the handler's background work inline, so each step has finished when the test checks it. */
    private static final class CallerRunsExecutor extends AbstractExecutorService {
        private volatile boolean shutdown;

        @Override
        public void execute(Runnable command) {
            command.run();
        }

        @Override
        public void shutdown() {
            shutdown = true;
        }

        @Override
        public List<Runnable> shutdownNow() {
            shutdown = true;
            return List.of();
        }

        @Override
        public boolean isShutdown() {
            return shutdown;
        }

        @Override
        public boolean isTerminated() {
            return shutdown;
        }

        @Override
        public boolean awaitTermination(long timeout, TimeUnit unit) {
            return true;
        }
    }
}
