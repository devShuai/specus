package com.theshuai.specusserver.handler;

import com.theshuai.specusserver.session.SessionUtil;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import static org.junit.jupiter.api.Assertions.*;

/** Repeats the native invariants with two actual WAL SQLite connections. The inherited pool-one
 * progress tests are proven specifically by the base context; here a second connection prevents
 * accidental DB-pool serialization from concealing the original-source generation race. */
@SpringBootTest(webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT,properties={
        "spring.datasource.url=jdbc:sqlite:file:target/test-native-control-source-generation.db?journal_mode=WAL&busy_timeout=5000",
        "spring.datasource.hikari.maximum-pool-size=2","spring.jpa.hibernate.ddl-auto=create-drop",
        "specus.netty.port=0","specus.netty.bind-address=127.0.0.1","specus.netty.worker-threads=3",
        "specus.database.seed-demo-client=false","specus.tls.mode=disabled"
})
class NativeControlSourceGenerationTests extends NativeControlGenerationTests {
    @Test
    void aReportPastItsInitialIdentityGuardCannotBorrowTheNextPhysicalControl() throws Exception {
        try (var fixture=new Fixture(4,4);var workers=Executors.newSingleThreadExecutor()) {
            assertEquals(2, jdbc.getDataSource().unwrap(com.zaxxer.hikari.HikariDataSource.class).getMaximumPoolSize());
            assertEquals("wal",jdbc.queryForObject("pragma journal_mode",String.class));
            var auth=fixture.authenticate();var original=fixture.control(auth);assertTrue(original.reply.isSuccess());
            original.report(1,"before-inflight-source");fixture.catalog(auth,"before-inflight-source");
            String originalChannel=fixture.nativeChannel(auth);
            var source=new SourceProbe(auth.getClientName(),"stale-inflight-source",new CompletableFuture<>(),
                    new CompletableFuture<>(),new CountDownLatch(1),new AtomicBoolean());SOURCE.set(source);
            try {
                original.report(40,source.instance());
                source.entered().get(5,TimeUnit.SECONDS); // AFTER PeerSignal.handle's initial physical identity guard.
                var resolved=new CompletableFuture<Void>();LOOKUP.set(new LookupProbe(auth.getAccessToken(),resolved));
                var pending=workers.submit(() -> fixture.control(auth));
                resolved.get(5,TimeUnit.SECONDS); // A real second native connection is available; this is not a pool wait.

                assertThrows(TimeoutException.class,() -> pending.get(200,TimeUnit.MILLISECONDS),
                        "new CONTROL must wait until the original report transaction completes");
                assertEquals(originalChannel,fixture.nativeChannel(auth));
                source.resume().countDown();source.finished().get(5,TimeUnit.SECONDS);
                var successor=pending.get(5,TimeUnit.SECONDS);assertTrue(successor.reply.isSuccess());
                successor.report(1,"fresh-after-inflight-source");fixture.catalog(auth,"fresh-after-inflight-source");
                assertEquals(SessionUtil.getChannel(auth.getClientName()).id().asLongText(),fixture.nativeChannel(auth));
            } finally {source.resume().countDown();}
        }
    }
}
