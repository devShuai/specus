package com.theshuai.tunnelclient.client;

import com.theshuai.tunnelclient.bean.TunnelBean;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class NettyClientLifecycle implements ApplicationRunner {
    private final TunnelBean tunnelBean;
    private volatile NettyClient nettyClient;

    public NettyClientLifecycle(TunnelBean tunnelBean) {
        this.tunnelBean = tunnelBean;
    }

    @Override
    public void run(ApplicationArguments args) {
        NettyClient client = new NettyClient(tunnelBean);
        nettyClient = client;
        client.start();
    }

    @PreDestroy
    public void stop() {
        NettyClient client = nettyClient;
        nettyClient = null;
        if (client != null) {
            log.info("Spring 上下文关闭, 停止 tunnel client");
            client.shutdown();
        }
    }
}
