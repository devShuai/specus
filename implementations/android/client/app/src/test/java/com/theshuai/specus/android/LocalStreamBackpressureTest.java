package com.theshuai.specus.android;

import org.junit.After;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Exercises a local TCP stream against a real socket and a consumer that stops reading.
 *
 * The multiplexed data channel has one reader thread for every stream, so a local service that
 * stalls must never be able to hold it. These tests use real sockets rather than a fake stream
 * because the failure only appears once the kernel send buffer actually fills.
 */
public class LocalStreamBackpressureTest {
    private final ExecutorService ioPool = Executors.newCachedThreadPool();
    private final ScheduledExecutorService watchdogs = Executors.newSingleThreadScheduledExecutor();
    private final List<Closeables> opened = new CopyOnWriteArrayList<>();

    @After
    public void tearDown() {
        for (Closeables closeable : opened) {
            closeable.closeQuietly();
        }
        ioPool.shutdownNow();
        watchdogs.shutdownNow();
    }

    /** A local server that accepts a connection and then never reads a byte from it. */
    private final class SilentConsumer implements Closeables {
        private final ServerSocket server;
        private final AtomicReference<Socket> accepted = new AtomicReference<>();
        private final CountDownLatch connected = new CountDownLatch(1);

        private SilentConsumer() throws IOException {
            server = new ServerSocket(0, 8, InetAddress.getLoopbackAddress());
            ioPool.submit(() -> {
                try {
                    Socket socket = server.accept();
                    accepted.set(socket);
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
        public void closeQuietly() {
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

        @Override
        public void protect(Socket socket) {
        }

        @Override
        public void markStreamOpened(int streamId) {
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
            resetReason.compareAndSet(null, reason);
            reset.countDown();
        }

        @Override
        public ScheduledFuture<?> scheduleWatchdog(Runnable task, long delayMillis) {
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
        SpecusCore.LocalSpecus stream = new SpecusCore.LocalSpecus(
                1, endpoint(consumer.port()), channel, ioPool);
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
        SpecusCore.LocalSpecus stream = new SpecusCore.LocalSpecus(
                2, endpoint(consumer.port()), channel, ioPool);
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
        SpecusCore.LocalSpecus stream = new SpecusCore.LocalSpecus(
                3, endpoint(server.getLocalPort()), channel, ioPool);
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
        SpecusCore.LocalSpecus stream = new SpecusCore.LocalSpecus(
                4, endpoint(consumer.port()), channel, ioPool, 300L);
        stream.start();
        assertTrue("local connect never completed", channel.opened.await(5, TimeUnit.SECONDS));

        // Fill the socket buffers so a write genuinely parks rather than completing instantly.
        byte[] chunk = new byte[64 * 1024];
        for (int i = 0; i < 128; i++) {
            try {
                stream.write(chunk);
            } catch (IOException bounded) {
                break;
            }
        }

        assertTrue("the stalled write was never abandoned",
                channel.reset.await(20, TimeUnit.SECONDS));
        assertNotNull(channel.resetReason.get());
        assertTrue("unexpected reset reason: " + channel.resetReason.get(),
                channel.resetReason.get().contains("timed out")
                        || channel.resetReason.get().contains("write to local TCP failed"));
        stream.close();
    }

    private static SpecusCore.SpecusEndpoint endpoint(int port) {
        return new SpecusCore.SpecusEndpoint(
                InetAddress.getLoopbackAddress().getHostAddress(), port);
    }
}
