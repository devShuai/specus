package com.theshuai.tunnelserver;

import com.theshuai.tunnelserver.server.NettyServer;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class TunnelServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(TunnelServerApplication.class, args);
        NettyServer.start();
    }

}
