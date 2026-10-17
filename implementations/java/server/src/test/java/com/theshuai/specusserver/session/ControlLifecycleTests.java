package com.theshuai.specusserver.session;

import io.netty.channel.DefaultChannelId;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.Test;
import java.util.ArrayList;
import java.util.concurrent.*;
import static org.junit.jupiter.api.Assertions.*;

class ControlLifecycleTests {
    @Test
    void distinctClientsWithTheSameFormerStripeDoNotBlockOneAnother() throws Exception {
        // Both IDs hashed to stripe 1 in the former fixed-stripe implementation.
        try (var worker=Executors.newSingleThreadExecutor();var held=ControlLifecycle.acquire(1,null)) {
            assertTrue(worker.submit(() -> {
                try(var independent=ControlLifecycle.acquire(257,null)) {return true;}
            }).get(1,TimeUnit.SECONDS));
        }
    }

    @Test
    void aQueuedWaiterKeepsTheExactGateUntilAllGenerationsLeave() throws Exception {
        try(var workers=Executors.newFixedThreadPool(2);var first=ControlLifecycle.acquire(19_300_001,null)) {
            var requested=new CountDownLatch(1);var acquired=new CountDownLatch(1);var resume=new CountDownLatch(1);
            var second=workers.submit(() -> {
                requested.countDown();
                try(var held=ControlLifecycle.acquire(19_300_001,null)) {
                    acquired.countDown();assertTrue(resume.await(3,TimeUnit.SECONDS));return true;
                }
            });
            assertTrue(requested.await(1,TimeUnit.SECONDS));
            try {
                assertFalse(acquired.await(100,TimeUnit.MILLISECONDS));
                first.close();assertTrue(acquired.await(1,TimeUnit.SECONDS));
                var third=workers.submit(() -> {try(var held=ControlLifecycle.acquire(19_300_001,null)){return true;}});
                assertThrows(TimeoutException.class,() -> third.get(100,TimeUnit.MILLISECONDS));
                resume.countDown();assertTrue(second.get(1,TimeUnit.SECONDS));assertTrue(third.get(1,TimeUnit.SECONDS));
            } finally {resume.countDown();}
        }
    }

    @Test
    void lifecycleCapacityIsBoundedAndReentrantReferencesReturnExactlyOnce() throws Exception {
        var held=new ArrayList<ControlLifecycle.Lease>();
        try {
            for(long i=0;i<4096;i++) held.add(ControlLifecycle.acquire(19_400_000+i,null));
            assertThrows(RejectedExecutionException.class,() -> ControlLifecycle.acquire(19_500_000,null));
            try(var nested=ControlLifecycle.acquire(19_400_000,null)) {assertNotNull(nested);}
            held.getFirst().close();held.getFirst().close();
            try(var replacement=ControlLifecycle.acquire(19_500_000,null)) {assertNotNull(replacement);}
        } finally {held.forEach(ControlLifecycle.Lease::close);}
        try(var next=ControlLifecycle.acquire(19_500_000,null)) {assertNotNull(next);}
    }

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
