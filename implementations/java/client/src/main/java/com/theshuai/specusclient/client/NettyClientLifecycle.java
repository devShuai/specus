package com.theshuai.specusclient.client;

import com.theshuai.specusclient.bean.ClientStartupConfig;
import com.theshuai.specusclient.bean.ControlTlsConfig;
import com.theshuai.specusclient.bean.SpecusBean;
import com.theshuai.specusclient.cli.ClientExitStatus;
import io.netty.handler.ssl.SslContext;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
@Slf4j
public class NettyClientLifecycle implements ApplicationRunner {
    private final SpecusBean specusBean;
    private final ClientStartupConfig startupConfig;
    private volatile NettyClient nettyClient;
    private final ClientExitStatus exitStatus;
    private final com.theshuai.specusclient.cli.CliState cliState;

    public NettyClientLifecycle(SpecusBean specusBean, ClientStartupConfig startupConfig, ClientExitStatus exitStatus,
            com.theshuai.specusclient.cli.CliState cliState) {
        this.specusBean = specusBean;
        this.startupConfig = startupConfig;
        this.exitStatus = exitStatus;
        this.cliState = cliState;
    }

    @Override
    public void run(ApplicationArguments args) {
        // Published before any forwarding starts, so the handlers that build their SSL context
        // statically see the operator's policy rather than the verifying default.
        UpstreamTlsPolicyHolder.configure(startupConfig.getUpstreamTls());

        ControlTlsConfig tls = startupConfig.getControlTls();
        boolean tlsEnabled = tls.resolveEnabled(specusBean.isNettyTls());
        SslContext sslContext = null;
        if (tlsEnabled) {
            if (tls.isInsecureSkipVerify()) {
                sslContext = NettyClient.buildInsecureClientSslContext();
            } else if (StringUtils.hasText(tls.getCaCertificatePath())) {
                sslContext = NettyClient.buildClientSslContextFromCaCertificate(tls.getCaCertificatePath());
            } else {
                sslContext = NettyClient.buildClientSslContext();
            }
        }
        NettyClient client = new NettyClient(
                specusBean,
                sslContext,
                tls.getServerName(),
                tlsEnabled && !tls.isInsecureSkipVerify());
        nettyClient = client;
        client.setTerminalFailureListener(exitStatus::fail);
        cliState.observe(client::diagnosticSnapshot);
        if (tlsEnabled && tls.isInsecureSkipVerify()) {
            log.warn("Control TLS enabled with certificate and hostname verification disabled (development only)");
        } else {
            log.info("Control TLS {}", tlsEnabled ? "enabled" : "disabled");
        }
        client.start();
    }

    @PreDestroy
    public void stop() {
        NettyClient client = nettyClient;
        nettyClient = null;
        if (client != null) {
            log.info("Spring 上下文关闭, 停止 specus client");
            client.shutdown();
        }
    }
}
