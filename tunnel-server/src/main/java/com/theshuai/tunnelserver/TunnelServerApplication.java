package com.theshuai.tunnelserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class TunnelServerApplication {

    static void main(String[] args) {
        SpringApplication.run(TunnelServerApplication.class, args);
    }

}
