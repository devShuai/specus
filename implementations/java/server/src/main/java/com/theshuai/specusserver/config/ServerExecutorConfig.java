package com.theshuai.specusserver.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

@Configuration
public class ServerExecutorConfig {

    /**
     * Bounded pool that runs the blocking login work (DB auth, connection-record writes,
     * NAT_CONTROL push) off the Netty I/O event loops. A bounded queue with AbortPolicy gives
     * back-pressure under a login storm instead of letting work pile up on the event loop.
     */
    @Bean(name = "loginExecutor", destroyMethod = "shutdown")
    public ExecutorService loginExecutor(
            @Value("${specus.login.executor.core-size:8}") int coreSize,
            @Value("${specus.login.executor.max-size:32}") int maxSize,
            @Value("${specus.login.executor.queue-capacity:20000}") int queueCapacity) {
        ThreadFactory threadFactory = new ThreadFactory() {
            private final AtomicInteger counter = new AtomicInteger();

            @Override
            public Thread newThread(Runnable runnable) {
                Thread thread = new Thread(runnable, "login-worker-" + counter.incrementAndGet());
                thread.setDaemon(true);
                return thread;
            }
        };
        return new ThreadPoolExecutor(coreSize, maxSize, 60L, TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(queueCapacity), threadFactory,
                new ThreadPoolExecutor.AbortPolicy());
    }
}
