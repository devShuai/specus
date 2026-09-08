package com.theshuai.specusclient.cli;

import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextClosedEvent;
import org.springframework.stereotype.Component;

import java.util.concurrent.CompletableFuture;

/** Wake the CLI main thread on terminal failure; never close Netty on its own event loop. */
@Component
public final class ClientExitStatus implements ApplicationListener<ContextClosedEvent> {
    private final CompletableFuture<Integer> completion = new CompletableFuture<>();

    public void fail() { completion.complete(3); }

    public int await() { return completion.join(); }
    public int awaitInterruptibly() throws InterruptedException {
        try { return completion.get(); }
        catch (java.util.concurrent.ExecutionException error) { return 1; }
    }

    @Override
    public void onApplicationEvent(ContextClosedEvent event) { completion.complete(0); }
}
