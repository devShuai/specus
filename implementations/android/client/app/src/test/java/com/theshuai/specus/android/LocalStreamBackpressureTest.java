package com.theshuai.specus.android;

import org.junit.After;
import org.junit.Test;

import java.io.IOException;
import java.io.Closeable;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;
import java.util.Map;
import java.util.ArrayDeque;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;

/**
 * Exercises a local TCP stream against a real socket and a consumer that stops reading.
 *
 * The multiplexed data channel has one reader thread for every stream, so a local service that
 * stalls must never be able to hold it. These tests use real sockets rather than a fake stream
 * because the failure only appears once the kernel send buffer actually fills.
 */
public class LocalStreamBackpressureTest {
    private final List<Throwable> asynchronousFailures = new CopyOnWriteArrayList<>();
    private final ExecutorService ioPool = new ThreadPoolExecutor(
            0, Integer.MAX_VALUE, 60L, TimeUnit.SECONDS, new SynchronousQueue<>()) {
        @Override protected void afterExecute(Runnable task, Throwable failure) {
            super.afterExecute(task, failure);
            recordAsynchronousFailure(task, failure);
        }
    };
    private final ScheduledExecutorService watchdogs = new ScheduledThreadPoolExecutor(1) {
        @Override protected void afterExecute(Runnable task, Throwable failure) {
            super.afterExecute(task, failure);
            recordAsynchronousFailure(task, failure);
        }
    };
    private final List<Closeables> opened = new CopyOnWriteArrayList<>();

    @After
    public void tearDown() throws Exception {
        for (Closeables closeable : opened) {
            closeable.closeQuietly();
        }
        // Writers must finish while their watchdog scheduler still exists. Observe exceptions
        // from execute AND submit/scheduled Future tasks, not only JUnit's assertion thread.
        ioPool.shutdown();
        boolean writersFinished;
        try {
            writersFinished = ioPool.awaitTermination(5, TimeUnit.SECONDS);
        } finally {
            ioPool.shutdownNow();
            watchdogs.shutdownNow();
        }
        assertTrue("owned watchdog tasks leaked", watchdogs.awaitTermination(5, TimeUnit.SECONDS));
        assertTrue("owned socket/writer tasks leaked", writersFinished);
        assertTrue("background failures: " + asynchronousFailures, asynchronousFailures.isEmpty());
    }

    private void recordAsynchronousFailure(Runnable task, Throwable failure) {
        if (failure == null && task instanceof Future<?> && ((Future<?>) task).isDone()) {
            try {
                ((Future<?>) task).get();
            } catch (CancellationException expectedDuringClose) {
                return;
            } catch (ExecutionException error) {
                failure = error.getCause();
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
                failure = error;
            }
        }
        if (failure != null) asynchronousFailures.add(failure);
    }

    private SpecusCore.LocalSpecus own(SpecusCore.LocalSpecus stream) {
        opened.add(stream::close);
        return stream;
    }

    /** A local server that accepts a connection and then never reads a byte from it. */
    private final class SilentConsumer implements Closeables {
        private final ServerSocket server;
        private final AtomicReference<Socket> accepted = new AtomicReference<>();
        private final CountDownLatch connected = new CountDownLatch(1);
        private boolean closed;

        private SilentConsumer() throws IOException {
            server = new ServerSocket(0, 8, InetAddress.getLoopbackAddress());
            server.setReceiveBufferSize(4096);
            ioPool.submit(() -> {
                try {
                    Socket socket = server.accept();
                    synchronized (this) {
                        if (closed) socket.close();
                        else accepted.set(socket);
                    }
                    connected.countDown();
                } catch (IOException ignored) {
                    connected.countDown();
                }
            });
            opened.add(this);
        }

        int port() {
            return server.getLocalPort();
        }

        @Override
        public synchronized void closeQuietly() {
            closed = true;
            Socket socket = accepted.get();
            if (socket != null) {
                try {
                    socket.close();
                } catch (IOException ignored) {
                    // best effort
                }
            }
            try {
                server.close();
            } catch (IOException ignored) {
                // best effort
            }
        }
    }

    private interface Closeables {
        void closeQuietly();
    }

    /** Records what the stream sent back to the control channel. */
    private final class RecordingChannel implements SpecusCore.LocalStreamChannel {
        private final AtomicInteger windowUpdates = new AtomicInteger();
        private final AtomicInteger creditedBytes = new AtomicInteger();
        private final CountDownLatch opened = new CountDownLatch(1);
        private final CountDownLatch reset = new CountDownLatch(1);
        private final AtomicReference<String> resetReason = new AtomicReference<>();
        private final AtomicInteger resets = new AtomicInteger();
        private CountDownLatch schedulingEntered;
        private CountDownLatch schedulingRelease;
        private boolean returnNoWatchdog;
        private SpecusCore.LocalStreamChannel productionChannel;

        @Override
        public void protect(Socket socket) throws IOException {
            socket.setSendBufferSize(16 * 1024);
        }

        @Override
        public void markStreamOpened(int streamId) {
            if (productionChannel != null) productionChannel.markStreamOpened(streamId);
            opened.countDown();
        }

        @Override
        public void sendNatData(int streamId, byte[] data) {
        }

        @Override
        public void sendWindowUpdate(int streamId, int credit) {
            windowUpdates.incrementAndGet();
            creditedBytes.addAndGet(credit);
        }

        @Override
        public void sendFin(int streamId) {
        }

        @Override
        public void completeTcpStream(int streamId, SpecusCore.LocalSpecus specus) {
        }

        @Override
        public void resetTcpStream(int streamId, SpecusCore.LocalSpecus specus,
                                   long errorCode, String reason) {
            if (productionChannel != null) productionChannel.resetTcpStream(streamId, specus, errorCode, reason);
            resetReason.compareAndSet(null, reason);
            resets.incrementAndGet();
            reset.countDown();
        }

        @Override
        public ScheduledFuture<?> scheduleWatchdog(Runnable task, long delayMillis) {
            if (schedulingEntered != null) {
                schedulingEntered.countDown();
                try {
                    assertTrue("writer schedule barrier was not released",
                            schedulingRelease.await(5, TimeUnit.SECONDS));
                } catch (InterruptedException error) {
                    Thread.currentThread().interrupt();
                    throw new RejectedExecutionException("writer schedule interrupted", error);
                }
            }
            if (returnNoWatchdog) return null;
            if (productionChannel != null) return productionChannel.scheduleWatchdog(task, delayMillis);
            return watchdogs.schedule(task, delayMillis, TimeUnit.MILLISECONDS);
        }
    }

    /**
     * The shared reader hands bytes to the stream and must come straight back, even when the local
     * service has stopped reading and the socket buffers are full.
     */
    @Test
    public void writeReturnsImmediatelyWhileTheLocalConsumerIsStalled() throws Exception {
        SilentConsumer consumer = new SilentConsumer();
        RecordingChannel channel = new RecordingChannel();
        SpecusCore.LocalSpecus stream = own(new SpecusCore.LocalSpecus(
                1, endpoint(consumer.port()), channel, ioPool));
        stream.start();
        assertTrue("local connect never completed", channel.opened.await(5, TimeUnit.SECONDS));

        // Enough to overflow both socket buffers so a synchronous write would certainly park.
        byte[] chunk = new byte[64 * 1024];
        long start = System.nanoTime();
        int accepted = 0;
        for (int i = 0; i < 16; i++) {
            try {
                stream.write(chunk);
                accepted++;
            } catch (IOException overflow) {
                // The receive window is bounded; refusing beyond it is the intended behaviour.
                break;
            }
        }
        long elapsedMillis = (System.nanoTime() - start) / 1_000_000L;

        assertTrue("nothing was accepted", accepted > 0);
        assertTrue("write blocked on the local socket for " + elapsedMillis + "ms",
                elapsedMillis < 2_000L);
        stream.close();
    }

    /** The queue is bounded: past the advertised window the stream refuses rather than buffers. */
    @Test
    public void inboundQueueIsBoundedByTheAdvertisedWindow() throws Exception {
        SilentConsumer consumer = new SilentConsumer();
        RecordingChannel channel = new RecordingChannel();
        SpecusCore.LocalSpecus stream = own(new SpecusCore.LocalSpecus(
                2, endpoint(consumer.port()), channel, ioPool));
        stream.start();
        assertTrue(channel.opened.await(5, TimeUnit.SECONDS));

        byte[] chunk = new byte[64 * 1024];
        IOException refusal = null;
        for (int i = 0; i < 512 && refusal == null; i++) {
            try {
                stream.write(chunk);
            } catch (IOException error) {
                refusal = error;
            }
        }
        assertNotNull("an unbounded queue would have swallowed every chunk", refusal);
        assertTrue(refusal.getMessage(), refusal.getMessage().contains("receive window"));
        stream.close();
    }

    /** A consumer that does read gets the bytes, and only then is the window reopened. */
    @Test
    public void windowUpdateFollowsTheActualLocalWrite() throws Exception {
        ServerSocket server = new ServerSocket(0, 8, InetAddress.getLoopbackAddress());
        opened.add(() -> { try { server.close(); } catch (IOException ignored) { } });
        CountDownLatch received = new CountDownLatch(1);
        AtomicInteger readBytes = new AtomicInteger();
        ioPool.submit(() -> {
            try (Socket socket = server.accept(); InputStream in = socket.getInputStream()) {
                byte[] buffer = new byte[4096];
                int read = in.read(buffer);
                if (read > 0) {
                    readBytes.set(read);
                    received.countDown();
                }
                // Hold the socket open so the stream is not torn down mid-assertion.
                Thread.sleep(500L);
            } catch (Exception ignored) {
                received.countDown();
            }
        });

        RecordingChannel channel = new RecordingChannel();
        SpecusCore.LocalSpecus stream = own(new SpecusCore.LocalSpecus(
                3, endpoint(server.getLocalPort()), channel, ioPool));
        stream.start();
        assertTrue(channel.opened.await(5, TimeUnit.SECONDS));

        stream.write("hello local service".getBytes());
        assertTrue("local service never received the bytes", received.await(5, TimeUnit.SECONDS));

        long deadline = System.currentTimeMillis() + 5_000L;
        while (channel.windowUpdates.get() == 0 && System.currentTimeMillis() < deadline) {
            Thread.sleep(10L);
        }
        assertEquals(1, channel.windowUpdates.get());
        assertEquals("hello local service".length(), channel.creditedBytes.get());
        assertEquals("hello local service".length(), readBytes.get());
        stream.close();
        server.close();
    }

    /**
     * A blocking socket write has no timeout of its own. When the local service stops reading and
     * never closes, the only thing that can free the stream is the watchdog closing the socket.
     */
    @Test
    public void aStalledLocalWriteIsAbandonedByTheWatchdog() throws Exception {
        SilentConsumer consumer = new SilentConsumer();
        RecordingChannel channel = new RecordingChannel();
        // A short deadline: production waits 30s, which no test should sit through.
        SpecusCore.LocalSpecus stream = own(new SpecusCore.LocalSpecus(
                4, endpoint(consumer.port()), channel, ioPool, 300L));
        stream.start();
        assertTrue("local connect never completed", channel.opened.await(5, TimeUnit.SECONDS));

        // Fill the socket buffers so a write genuinely parks rather than completing instantly.
        byte[] chunk = new byte[64 * 1024];
        CountDownLatch writesFinished = new CountDownLatch(1);
        ioPool.submit(() -> {
            try {
                for (int i = 0; i < 128; i++) {
                    stream.write(chunk);
                }
            } catch (IOException ignored) {
            } finally {
                writesFinished.countDown();
            }
        });

        boolean abandoned = channel.reset.await(8, TimeUnit.SECONDS);
        assertTrue("the stalled write was never abandoned", abandoned);
        assertNotNull(channel.resetReason.get());
        assertTrue("unexpected reset reason: " + channel.resetReason.get(),
                channel.resetReason.get().contains("timed out")
                        || channel.resetReason.get().contains("write to local TCP failed"));
        stream.close();
    }

    @Test
    public void rejectedWatchdogResetsPendingWriteAndDiscardsQueueWithoutCredit() throws Exception {
        exerciseUnavailableWatchdog(false, false);
    }

    @Test
    public void missingWatchdogCannotPermitAnUnprotectedSocketWrite() throws Exception {
        exerciseUnavailableWatchdog(true, false);
    }

    @Test
    public void productionRejectionRemovesRegisteredStreamAndClosesItsRealSocket() throws Exception {
        exerciseUnavailableWatchdog(false, true);
    }

    private void exerciseUnavailableWatchdog(boolean returnNull, boolean useProduction) throws Exception {
        SilentConsumer consumer = new SilentConsumer();
        RecordingChannel channel = new RecordingChannel();
        channel.schedulingEntered = new CountDownLatch(1);
        channel.schedulingRelease = new CountDownLatch(1);
        channel.returnNoWatchdog = returnNull;
        SpecusCore.LocalSpecus stream = own(new SpecusCore.LocalSpecus(
                5, endpoint(consumer.port()), channel, ioPool));
        Object connection = useProduction ? newProductionConnection() : null;
        ScheduledExecutorService deadline = connection == null ? watchdogs
                : (ScheduledExecutorService) field(connection, "heartbeat");
        if (connection != null) {
            channel.productionChannel = (SpecusCore.LocalStreamChannel) connection;
            @SuppressWarnings("unchecked")
            Map<Integer, SpecusCore.LocalSpecus> registry =
                    (Map<Integer, SpecusCore.LocalSpecus>) field(connection, "localSpecusMappings");
            SpecusCore.StreamLifecycleRegistry lifecycle =
                    (SpecusCore.StreamLifecycleRegistry) field(connection, "streamLifecycle");
            assertTrue(lifecycle.beginPending(5));
            assertEquals(1, lifecycle.pendingCount());
            registry.put(5, stream);
        }
        try {
            stream.start();
            assertTrue(channel.opened.await(5, TimeUnit.SECONDS));
            assertTrue(consumer.connected.await(5, TimeUnit.SECONDS));
            stream.write("must not reach service".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            assertTrue("no actual pending writer", channel.schedulingEntered.await(5, TimeUnit.SECONDS));
            stream.write(new byte[32]);
            stream.receiveRemoteFin();
            assertEquals(32, field(stream, "inboundBytes"));
            assertTrue((Boolean) field(stream, "draining"));
            assertTrue((Boolean) field(stream, "inboundFin"));
            deadline.shutdownNow();
            assertTrue(deadline.awaitTermination(1, TimeUnit.SECONDS));
            channel.schedulingRelease.countDown();
            assertTrue("unavailable watchdog did not reset the pending stream",
                    channel.reset.await(5, TimeUnit.SECONDS));
            ioPool.shutdown();
            assertTrue("reset left socket reader/writer alive", ioPool.awaitTermination(5, TimeUnit.SECONDS));
            assertEquals(1, channel.resets.get());
            assertEquals(0, channel.windowUpdates.get());
            assertEquals(0, channel.creditedBytes.get());
            assertTrue("local socket leaked", ((Socket) field(stream, "socket")).isClosed());
            assertEquals(0, field(stream, "inboundBytes"));
            assertTrue(((ArrayDeque<?>) field(stream, "inbound")).isEmpty());
            assertFalse((Boolean) field(stream, "draining"));
            assertFalse((Boolean) field(stream, "inboundFin"));
            if (connection != null) {
                assertTrue("production stream registration leaked",
                        ((Map<?, ?>) field(connection, "localSpecusMappings")).isEmpty());
                SpecusCore.StreamLifecycleRegistry lifecycle =
                        (SpecusCore.StreamLifecycleRegistry) field(connection, "streamLifecycle");
                assertEquals(0, lifecycle.pendingCount());
                assertTrue("closed stream lost its tombstone", lifecycle.isRecentlyClosed(5));
                lifecycle.requireRecentlyClosedReset(5);
            }
            Socket service = consumer.accepted.get();
            assertNotNull(service);
            service.setSoTimeout(1000);
            assertEquals("an unprotected write reached the real service", -1, service.getInputStream().read());
            assertTrue("rejection escaped the drain task: " + asynchronousFailures, asynchronousFailures.isEmpty());
        } finally {
            channel.schedulingRelease.countDown();
            if (connection != null) ((Closeable) connection).close();
        }
    }

    @Test
    public void productionChannelDoesNotHideSchedulerRejectionAsNoWatchdog() throws Exception {
        Object connection = newProductionConnection();
        ScheduledExecutorService scheduler = (ScheduledExecutorService) field(connection, "heartbeat");
        ScheduledExecutorService refresh = (ScheduledExecutorService) field(connection, "credentialRefresh");
        try {
            scheduler.shutdownNow();
            assertTrue(scheduler.awaitTermination(1, TimeUnit.SECONDS));
            assertThrows(RejectedExecutionException.class,
                    () -> ((SpecusCore.LocalStreamChannel) connection).scheduleWatchdog(() -> { }, 1000));
        } finally {
            ((Closeable) connection).close();
            scheduler.shutdownNow();
            refresh.shutdownNow();
            assertTrue(scheduler.awaitTermination(1, TimeUnit.SECONDS));
            assertTrue(refresh.awaitTermination(1, TimeUnit.SECONDS));
        }
    }

    @Test
    public void closingProductionChannelRejectsDeadlinesBeforeSchedulerShutdown() throws Exception {
        Object connection = newProductionConnection();
        AtomicBoolean closing = (AtomicBoolean) field(connection, "closed");
        ScheduledExecutorService scheduler = (ScheduledExecutorService) field(connection, "heartbeat");
        try {
            assertFalse(scheduler.isShutdown());
            closing.set(true);
            assertThrows(RejectedExecutionException.class,
                    () -> ((SpecusCore.LocalStreamChannel) connection).scheduleWatchdog(() -> { }, 1000));
            assertFalse("the closing fence must not depend on scheduler shutdown", scheduler.isShutdown());
        } finally {
            closing.set(false);
            ((Closeable) connection).close();
            assertTrue(scheduler.awaitTermination(1, TimeUnit.SECONDS));
            assertTrue(((ScheduledExecutorService) field(connection, "credentialRefresh"))
                    .awaitTermination(1, TimeUnit.SECONDS));
        }
    }

    private Object newProductionConnection() throws Exception {
        Class<?> connectionClass = Class.forName(SpecusCore.class.getName() + "$ControlConnection");
        Class<?> statusClass = Class.forName(SpecusCore.class.getName() + "$StatusSink");
        Class<?> refresherClass = Class.forName(SpecusCore.class.getName() + "$SessionRefresher");
        Constructor<?> constructor = connectionClass.getDeclaredConstructor(
                SpecusCore.SpecusSession.class, ExecutorService.class, statusClass,
                AtomicBoolean.class, SpecusCore.VpnPlatform.class, refresherClass);
        constructor.setAccessible(true);
        Object status = Proxy.newProxyInstance(statusClass.getClassLoader(), new Class<?>[]{statusClass},
                (proxy, method, args) -> null);
        return constructor.newInstance(new SpecusCore.SpecusSession(), ioPool, status,
                new AtomicBoolean(true), null, null);
    }

    private static Object field(Object target, String name) throws Exception {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        return field.get(target);
    }

    private static SpecusCore.SpecusEndpoint endpoint(int port) {
        return new SpecusCore.SpecusEndpoint(
                InetAddress.getLoopbackAddress().getHostAddress(), port);
    }
}
