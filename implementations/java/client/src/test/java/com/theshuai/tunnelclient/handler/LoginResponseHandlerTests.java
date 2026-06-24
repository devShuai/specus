package com.theshuai.tunnelclient.handler;

import com.theshuai.common.protocol.response.LoginResponsePacket;
import com.theshuai.tunnelclient.bean.TunnelBean;
import com.theshuai.tunnelclient.client.NettyClient;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LoginResponseHandlerTests {

    @Test
    void terminalLoginFailureSuppressesReconnect() {
        NettyClient client = nettyClient();
        EmbeddedChannel channel = new EmbeddedChannel(new LoginResponseHandler(client));
        try {
            LoginResponsePacket response = failure("同一台机器和用户已经有在线实例");

            channel.writeInbound(response);

            assertTrue(client.isReconnectSuppressed());
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    @Test
    void serverBusyLoginFailureKeepsReconnectEnabled() {
        NettyClient client = nettyClient();
        EmbeddedChannel channel = new EmbeddedChannel(new LoginResponseHandler(client));
        try {
            LoginResponsePacket response = failure("服务器繁忙，请稍后重试");

            channel.writeInbound(response);

            assertFalse(client.isReconnectSuppressed());
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    @Test
    void expiredTokenLoginFailureRefreshesCredentials() {
        RefreshRecordingNettyClient client = new RefreshRecordingNettyClient();
        EmbeddedChannel channel = new EmbeddedChannel(new LoginResponseHandler(client));
        try {
            LoginResponsePacket response = failure("客户端访问令牌已过期");

            channel.writeInbound(response);

            assertTrue(client.refreshRequested);
            assertFalse(client.isReconnectSuppressed());
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    private static LoginResponsePacket failure(String reason) {
        LoginResponsePacket response = new LoginResponsePacket();
        response.setClientName("unit-client");
        response.setSuccess(false);
        response.setReason(reason);
        return response;
    }

    private static NettyClient nettyClient() {
        TunnelBean bean = new TunnelBean();
        bean.setClientName("unit-client");
        bean.setClientSessionId(1L);
        bean.setAccessToken("cs_unit_token");
        bean.setRemoteAddress("127.0.0.1");
        bean.setRemotePort(7010);
        return new NettyClient(bean);
    }

    private static final class RefreshRecordingNettyClient extends NettyClient {
        private boolean refreshRequested;

        private RefreshRecordingNettyClient() {
            super(bean());
        }

        @Override
        public void refreshCredentialsAndReconnect(String reason) {
            refreshRequested = true;
        }

        private static TunnelBean bean() {
            TunnelBean bean = new TunnelBean();
            bean.setClientName("unit-client");
            bean.setClientSessionId(1L);
            bean.setAccessToken("cs_unit_token");
            bean.setRemoteAddress("127.0.0.1");
            bean.setRemotePort(7010);
            return bean;
        }
    }
}
