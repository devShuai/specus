package com.theshuai.specusserver.session;

import io.netty.channel.DefaultChannelId;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.Test;
import java.util.ArrayList;
import java.util.concurrent.*;
import static org.junit.jupiter.api.Assertions.*;

class ControlLifecycleTests {
    @Test
    void aClosedWaitingChannelCancelsWithoutTakingTheNextGenerationLease() throws Exception {
        var channel=new EmbeddedChannel(DefaultChannelId.newInstance());
        try (var worker=Executors.newSingleThreadExecutor();var held=ControlLifecycle.acquire(19_000_001,null)) {
            var entered=new CountDownLatch(1);
            var pending=worker.submit(() -> {entered.countDown();try(var acquired=ControlLifecycle.acquire(19_000_001,channel)){return true;}});
            assertTrue(entered.await(1,TimeUnit.SECONDS));channel.close();
            var failure=assertThrows(ExecutionException.class,() -> pending.get(1,TimeUnit.SECONDS));
            assertInstanceOf(CancellationException.class,failure.getCause());
            held.close();
            try(var next=ControlLifecycle.acquire(19_000_001,null)) {assertNotNull(next);}
        } finally {channel.finishAndReleaseAll();}
    }

    @Test
    void pendingPublicationMatchesTheExactPhysicalChannelAndReleasesItsSlot() {
        var first=new EmbeddedChannel(DefaultChannelId.newInstance());var other=new EmbeddedChannel(DefaultChannelId.newInstance());
        try {
            try(var pending=ControlLifecycle.beginPublication(19_000_002,first)) {
                assertTrue(ControlLifecycle.isPublishing(19_000_002L,first.id().asLongText()));
                assertFalse(ControlLifecycle.isPublishing(19_000_002L,other.id().asLongText()));
                assertFalse(ControlLifecycle.isPublishing(19_000_003L,first.id().asLongText()));
                first.close();assertFalse(ControlLifecycle.isPublishing(19_000_002L,first.id().asLongText()));
            }
            assertFalse(ControlLifecycle.isPublishing(19_000_002L,first.id().asLongText()));
            try(var next=ControlLifecycle.beginPublication(19_000_002,other)) {assertTrue(ControlLifecycle.isPublishing(19_000_002L,other.id().asLongText()));}
        } finally {first.finishAndReleaseAll();other.finishAndReleaseAll();}
    }

    @Test
    void publicationCapacityIsBoundedAndReturnedAfterRejection() {
        var channel=new EmbeddedChannel(DefaultChannelId.newInstance());var admitted=new ArrayList<ControlLifecycle.Publication>();
        try {
            for(long i=0;i<4096;i++) admitted.add(ControlLifecycle.beginPublication(19_100_000+i,channel));
            assertThrows(RejectedExecutionException.class,() -> ControlLifecycle.beginPublication(19_200_000,channel));
        } finally {admitted.forEach(ControlLifecycle.Publication::close);}
        try(var next=ControlLifecycle.beginPublication(19_200_000,channel)) {assertTrue(ControlLifecycle.isPublishing(19_200_000L,channel.id().asLongText()));}
        finally {channel.finishAndReleaseAll();}
    }
}
