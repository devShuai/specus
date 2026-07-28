package com.theshuai.specusserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class SpecusServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpecusServerApplication.class, args);
    }

}
