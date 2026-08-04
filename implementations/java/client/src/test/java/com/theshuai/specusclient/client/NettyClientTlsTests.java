package com.theshuai.specusclient.client;

import com.theshuai.specusclient.bean.SpecusBean;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslHandler;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class NettyClientTlsTests {

    @Test
    void verifiedTlsEnablesEndpointIdentification() {
        SslContext context = NettyClient.buildClientSslContext();
        NettyClient client = new NettyClient(bean(), context, "control.example", true);
        NioSocketChannel channel = new NioSocketChannel();
        try {
            SslHandler handler = client.newControlSslHandler(channel);
            assertThat(handler.engine().getSSLParameters().getEndpointIdentificationAlgorithm())
                    .isEqualTo("HTTPS");
            assertThat(handler.engine().getPeerHost()).isEqualTo("control.example");
        } finally {
            channel.unsafe().closeForcibly();
        }
    }

    @Test
    void insecureTlsLeavesEndpointIdentificationDisabled() {
        SslContext context = NettyClient.buildInsecureClientSslContext();
        NettyClient client = new NettyClient(bean(), context, null, false);
        NioSocketChannel channel = new NioSocketChannel();
        try {
            SslHandler handler = client.newControlSslHandler(channel);
            assertThat(handler.engine().getSSLParameters().getEndpointIdentificationAlgorithm()).isEmpty();
            assertThat(handler.engine().getPeerHost()).isEqualTo("127.0.0.1");
        } finally {
            channel.unsafe().closeForcibly();
        }
    }

    @Test
    void missingCaCertificateFailsBeforeConnecting() {
        assertThatThrownBy(() -> NettyClient.buildClientSslContextFromCaCertificate("missing-ca.pem"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("CA certificate not found");
    }

    private static SpecusBean bean() {
        SpecusBean bean = new SpecusBean();
        bean.setClientName("tls-test");
        bean.setClientSessionId(1L);
        bean.setAccessToken("token");
        bean.setRemoteAddress("127.0.0.1");
        bean.setRemotePort(7010);
        return bean;
    }
}
