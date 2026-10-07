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
import org.junit.jupiter.api.Test;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** A successful control login reports client_online for the client's owner; a data login does not. */
class ManagedLoginProductMetricsTests {

    @Test
    void controlLoginReportsClientOnlineForTheOwner() throws Exception {
        ClientAccount account = new ClientAccount();
        account.setId(42L);
        account.setTenantId("t1");
        account.setOwnerUsername("alice");
        account.setClientName("metrics-login-client");
        ClientAuthService auth = mock(ClientAuthService.class);
        when(auth.authenticateNetty(any(), anyString(), anyString(), anyBoolean()))
                .thenReturn(AuthenticationResult.success(account, 7L));
        ProductMetricsService metrics = mock(ProductMetricsService.class);
        ExecutorService executor = Executors.newSingleThreadExecutor();
        ManagedLoginRequestHandler handler = new ManagedLoginRequestHandler(auth, mock(ConnectionRecordService.class),
                mock(NatControlService.class), mock(PeerSignalService.class), new NettyServerProperties(), executor,
                metrics);
        EmbeddedChannel channel = new EmbeddedChannel(handler);
        try {
            LoginRequestPacket login = new LoginRequestPacket();
            login.setClientName(account.getClientName());
            login.setAccessToken("cs_token");
            login.setConnectionRole(ConnectionRole.CONTROL);
            channel.writeInbound(login);
            LoginResponsePacket response = null;
            for (int attempt = 0; attempt < 200 && response == null; attempt++) {
                channel.runPendingTasks();
                response = channel.readOutbound();
                if (response == null) {
                    Thread.sleep(10);
                }
            }
            assertThat(response).isNotNull();
            assertThat(response.isSuccess()).isTrue();
            verify(metrics, timeout(2000)).clientOnline(account);
        } finally {
            SessionUtil.unBindSession(channel);
            channel.finishAndReleaseAll();
            executor.shutdownNow();
            assertThat(executor.awaitTermination(2, TimeUnit.SECONDS)).isTrue();
        }
        verify(metrics, never()).milestone(anyString(), anyString(), anyString());
    }
}
