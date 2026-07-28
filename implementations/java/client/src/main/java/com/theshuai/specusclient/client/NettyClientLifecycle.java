package com.theshuai.specusclient.client;

import com.theshuai.specusclient.bean.SpecusBean;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class NettyClientLifecycle implements ApplicationRunner {
    private final SpecusBean specusBean;
    private volatile NettyClient nettyClient;

    public NettyClientLifecycle(SpecusBean specusBean) {
        this.specusBean = specusBean;
    }

    @Override
    public void run(ApplicationArguments args) {
        NettyClient client = new NettyClient(specusBean);
        nettyClient = client;
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
