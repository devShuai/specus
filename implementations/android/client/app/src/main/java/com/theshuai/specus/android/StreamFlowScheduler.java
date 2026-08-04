package com.theshuai.specus.android;

import java.io.Closeable;
import java.io.IOException;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

/**
 * Shared NAT DATA scheduler with per-stream credit, bounded queues and round-robin fairness.
 */
final class StreamFlowScheduler implements Closeable {
    static final long INITIAL_BYTES = 1024L * 1024L;
    static final long MAXIMUM_BYTES = 16L * 1024L * 1024L;
    static final int MAX_PENDING_BYTES = 4 * 1024 * 1024;
    static final int MAX_CHUNK_BYTES = 64 * 1024;

    @FunctionalInterface
    interface SendAction {
        void send() throws Exception;
    }

    private final Object lock = new Object();
    private final Map<Integer, StreamState> streams = new HashMap<>();
    private final ArrayDeque<Integer> readyStreams = new ArrayDeque<>();
    private final Thread worker;
    private boolean closed;

    StreamFlowScheduler() {
        worker = new Thread(this::run, "specus-stream-flow");
        worker.setDaemon(true);
        worker.start();
    }

    boolean open(int streamId) {
        synchronized (lock) {
            if (closed || streams.containsKey(streamId)) {
                return false;
            }
            streams.put(streamId, new StreamState());
            return true;
        }
    }

    boolean contains(int streamId) {
        synchronized (lock) {
            return streams.containsKey(streamId);
        }
    }

    void send(int streamId, int bytes, SendAction action) throws Exception {
        if (bytes <= 0 || bytes > MAX_CHUNK_BYTES || action == null) {
            throw new IOException("invalid stream DATA chunk");
        }
        Pending pending = new Pending(bytes, action);
        synchronized (lock) {
            StreamState state = streams.get(streamId);
            if (closed || state == null || state.closed) {
                throw new IOException("stream send window closed");
            }
            while (!closed && !state.closed
                    && state.pendingBytes > MAX_PENDING_BYTES - bytes) {
                try {
                    lock.wait();
                } catch (InterruptedException error) {
                    Thread.currentThread().interrupt();
                    throw new IOException("interrupted while waiting for stream queue", error);
                }
            }
            if (closed || state.closed || streams.get(streamId) != state) {
                throw new IOException("stream send window closed");
            }
            state.pending.addLast(pending);
            state.pendingBytes += bytes;
            schedule(streamId, state);
            lock.notifyAll();
        }
        await(pending.completion);
    }

    void finish(int streamId, SendAction action) throws Exception {
        terminate(streamId, action, false);
    }

    void reset(int streamId, SendAction action) throws Exception {
        terminate(streamId, action, true);
    }

    boolean addCredit(int streamId, long bytes) {
        synchronized (lock) {
            StreamState state = streams.get(streamId);
            if (state == null || bytes <= 0 || bytes > MAXIMUM_BYTES
                    || bytes > state.outstanding
                    || state.credit > MAXIMUM_BYTES - bytes) {
                return false;
            }
            state.outstanding -= bytes;
            state.credit += bytes;
            schedule(streamId, state);
            lock.notifyAll();
            return true;
        }
    }

    void closeStream(int streamId) {
        try {
            terminate(streamId, () -> { }, true);
        } catch (Exception ignored) {
            // Closing is best-effort; all queued callers were already released.
        }
    }

    @Override
    public void close() {
        synchronized (lock) {
            if (closed) return;
            closed = true;
            IOException error = new IOException("stream flow scheduler closed");
            for (StreamState state : streams.values()) {
                state.closed = true;
                failPending(state, error);
            }
            streams.clear();
            readyStreams.clear();
            lock.notifyAll();
        }
        worker.interrupt();
    }

    private void run() {
        while (true) {
            Pending pending;
            int streamId;
            StreamState state;
            synchronized (lock) {
                while (!closed && readyStreams.isEmpty()) {
                    try {
                        lock.wait();
                    } catch (InterruptedException ignored) {
                        if (closed) return;
                    }
                }
                if (closed) return;
                streamId = readyStreams.removeFirst();
                state = streams.get(streamId);
                if (state == null) {
                    continue;
                }
                state.scheduled = false;
                pending = state.pending.peekFirst();
                if (pending == null || !pending.terminal && state.credit < pending.bytes) {
                    continue;
                }
                state.pending.removeFirst();
                if (!pending.terminal) {
                    state.pendingBytes -= pending.bytes;
                    state.credit -= pending.bytes;
                    state.outstanding += pending.bytes;
                }
                schedule(streamId, state);
                lock.notifyAll();
            }
            try {
                pending.action.send();
                pending.completion.complete(null);
                if (pending.terminal) {
                    closeCompletedStream(streamId, state, pending);
                }
            } catch (Throwable error) {
                pending.completion.completeExceptionally(error);
                closeFailedStream(streamId, state, error);
            }
        }
    }

    private void schedule(int streamId, StreamState state) {
        Pending first = state.pending.peekFirst();
        if (!state.scheduled && first != null
                && (first.terminal || state.credit >= first.bytes)) {
            state.scheduled = true;
            readyStreams.addLast(streamId);
        }
    }

    private void terminate(int streamId, SendAction action, boolean abortPending) throws Exception {
        if (action == null) {
            throw new IOException("stream terminal action is required");
        }
        Pending terminal = null;
        boolean runDirect = false;
        synchronized (lock) {
            StreamState state = streams.get(streamId);
            if (state == null) {
                if (abortPending && !closed) {
                    runDirect = true;
                } else {
                    throw new IOException("stream send window closed");
                }
            } else if (state.closed) {
                if (!abortPending) {
                    throw new IOException("stream terminal action already queued");
                }
                terminal = state.terminal;
                if (terminal == null) {
                    throw new IOException("stream send window closed");
                }
                if (!state.abortTerminal) {
                    IOException superseded = new IOException(
                            "stream reset superseded graceful close");
                    failPending(state, superseded);
                    // The graceful terminal may already have been dequeued by the worker. Its
                    // physical FIN cannot be unsent, but the RST must still follow it instead of
                    // being silently discarded.
                    terminal.completion.completeExceptionally(superseded);
                    terminal = Pending.terminal(action);
                    state.terminal = terminal;
                    state.abortTerminal = true;
                    state.pending.addLast(terminal);
                    schedule(streamId, state);
                    lock.notifyAll();
                }
            } else {
                state.closed = true;
                if (abortPending) {
                    failPending(state, new IOException("stream send window closed"));
                }
                terminal = Pending.terminal(action);
                state.terminal = terminal;
                state.abortTerminal = abortPending;
                state.pending.addLast(terminal);
                schedule(streamId, state);
                lock.notifyAll();
            }
        }
        if (runDirect) {
            action.send();
            return;
        }
        try {
            await(terminal.completion);
        } finally {
            synchronized (lock) {
                StreamState state = streams.get(streamId);
                if (state != null && state.closed && state.terminal == terminal
                        && terminal.completion.isDone() && state.pending.isEmpty()) {
                    streams.remove(streamId, state);
                    state.scheduled = false;
                }
                lock.notifyAll();
            }
        }
    }

    private void closeCompletedStream(int streamId, StreamState expected, Pending terminal) {
        synchronized (lock) {
            StreamState state = streams.get(streamId);
            if (state == expected && state.closed && state.terminal == terminal
                    && state.pending.isEmpty()) {
                streams.remove(streamId, state);
                state.scheduled = false;
            }
            lock.notifyAll();
        }
    }

    private void closeFailedStream(int streamId, StreamState expected, Throwable cause) {
        synchronized (lock) {
            StreamState state = streams.get(streamId);
            if (state != expected) return;
            streams.remove(streamId);
            state.closed = true;
            state.scheduled = false;
            failPending(state, cause);
            lock.notifyAll();
        }
    }

    private static void failPending(StreamState state, Throwable error) {
        Pending pending;
        while ((pending = state.pending.pollFirst()) != null) {
            pending.completion.completeExceptionally(error);
        }
        state.pendingBytes = 0;
    }

    private static void await(CompletableFuture<Void> completion) throws Exception {
        try {
            completion.get();
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted while waiting for stream send", error);
        } catch (ExecutionException error) {
            Throwable cause = error.getCause() == null ? error : error.getCause();
            if (cause instanceof Exception exception) {
                throw exception;
            }
            throw new IOException("stream send failed", cause);
        }
    }

    private static final class StreamState {
        final ArrayDeque<Pending> pending = new ArrayDeque<>();
        long credit = INITIAL_BYTES;
        long outstanding;
        int pendingBytes;
        boolean scheduled;
        boolean closed;
        boolean abortTerminal;
        Pending terminal;
    }

    private record Pending(int bytes, SendAction action, CompletableFuture<Void> completion,
                           boolean terminal) {
        Pending(int bytes, SendAction action) {
            this(bytes, action, new CompletableFuture<>(), false);
        }

        static Pending terminal(SendAction action) {
            return new Pending(0, action, new CompletableFuture<>(), true);
        }
    }
}
