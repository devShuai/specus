package com.theshuai.common.service;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ExecuteService {
    private final static ExecutorService executorService = Executors.newCachedThreadPool();

    public static void submit(Runnable runnable) {
        executorService.submit(runnable);
    }
}
