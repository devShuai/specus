package com.theshuai.common.handler;

import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import io.netty.channel.Channel;
import io.netty.util.AttributeKey;

import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/** Connection-local credit controller for mandatory tunnel stream v2 DATA frames. */
public final class StreamFlowController {
    public static final long INITIAL_WINDOW_BYTES = 1024L * 1024L;
    public static final int MAX_DATA_FRAME_BYTES = 64 * 1024;
    public static final long MAX_PENDING_BYTES_PER_STREAM = 4L * 1024L * 1024L;
    public static final long MAX_WINDOW_BYTES = 16L * 1024L * 1024L;

    private static final AttributeKey<StreamFlowController> KEY =
            AttributeKey.valueOf("tunnel.stream-flow-v2");

    private final Channel controlChannel;
    private final Map<Integer, StreamState> streams = new HashMap<>();
    private final ArrayDeque<Integer> readyStreams = new ArrayDeque<>();
    private boolean draining;

    private StreamFlowController(Channel controlChannel) {
        this.controlChannel = controlChannel;
    }

    public static StreamFlowController get(Channel controlChannel) {
        StreamFlowController existing = controlChannel.attr(KEY).get();
        if (existing != null) {
            return existing;
        }
        StreamFlowController created = new StreamFlowController(controlChannel);
        StreamFlowController raced = controlChannel.attr(KEY).setIfAbsent(created);
        return raced == null ? created : raced;
    }

    public void open(int streamId, Channel sourceChannel) {
        execute(() -> streams.computeIfAbsent(streamId, ignored -> new StreamState(sourceChannel)));
    }

    public void send(int streamId, byte[] data, Channel sourceChannel, Runnable overflowAction) {
        sendAsync(streamId, data, sourceChannel, overflowAction);
    }

    public CompletableFuture<Void> sendAsync(int streamId, byte[] data, Channel sourceChannel,
                                             Runnable overflowAction) {
        if (data == null || data.length == 0) {
            return CompletableFuture.completedFuture(null);
        }
        CompletableFuture<Void> completion = new CompletableFuture<>();
        execute(() -> {
            if (!controlChannel.isActive()) {
                completion.completeExceptionally(new IllegalStateException("control channel is closed"));
                return;
            }
            StreamState state = streams.computeIfAbsent(streamId, ignored -> new StreamState(sourceChannel));
            if (state.finPending) {
                failStream(streamId, state, overflowAction, "DATA after FIN", completion);
                return;
            }
            if (state.pendingBytes + data.length > MAX_PENDING_BYTES_PER_STREAM) {
                failStream(streamId, state, overflowAction, "stream send queue exceeded", completion);
                return;
            }
            state.pending.addLast(new PendingData(data, completion));
            state.pendingBytes += data.length;
            enqueueReady(streamId, state);
            drain();
        });
        return completion;
    }

    public void finish(int streamId) {
        finishAsync(streamId, null);
    }

    public CompletableFuture<Void> finishAsync(int streamId, Map<String, Object> metadata) {
        CompletableFuture<Void> completion = new CompletableFuture<>();
        execute(() -> {
            StreamState state = streams.computeIfAbsent(streamId, ignored -> new StreamState(null));
            if (state.finPending) {
                completion.completeExceptionally(new IllegalStateException("duplicate FIN"));
                return;
            }
            state.finPending = true;
            state.finMetadata = metadata == null || metadata.isEmpty() ? null : Map.copyOf(metadata);
            state.finCompletion = completion;
            enqueueReady(streamId, state);
            drain();
        });
        return completion;
    }

    public void reset(int streamId, long errorCode, String reason) {
        execute(() -> {
            StreamState state = streams.remove(streamId);
            if (state != null) {
                resumeSource(state);
                failPending(state, new IllegalStateException("stream reset"));
            }
            NatMessagePacket reset = new NatMessagePacket();
            reset.setNatMessageType(NatMessageType.RST);
            reset.setStreamId(streamId);
            reset.setValue(errorCode);
            if (reason != null && !reason.isBlank()) {
                reset.setMetaData(Map.of("reason", reason));
            }
            controlChannel.writeAndFlush(reset);
        });
    }

    public void onWindowUpdate(int streamId, long credit) {
        if (credit <= 0 || credit > MAX_WINDOW_BYTES) {
            controlChannel.close();
            return;
        }
        execute(() -> {
            StreamState state = streams.get(streamId);
            if (state == null) {
                return;
            }
            if (state.credit > MAX_WINDOW_BYTES - credit) {
                controlChannel.close();
                return;
            }
            state.credit += credit;
            enqueueReady(streamId, state);
            drain();
        });
    }

    public void onControlWritabilityChanged() {
        execute(this::drain);
    }

    public void remove(int streamId) {
        execute(() -> {
            StreamState state = streams.remove(streamId);
            if (state != null) {
                resumeSource(state);
                failPending(state, new IllegalStateException("stream removed"));
            }
        });
    }

    public void closeAll() {
        execute(() -> {
            for (StreamState state : streams.values()) {
                resumeSource(state);
                failPending(state, new IllegalStateException("control channel closed"));
            }
            streams.clear();
            readyStreams.clear();
        });
    }

    private void drain() {
        if (draining || !controlChannel.isActive()) {
            return;
        }
        draining = true;
        boolean wrote = false;
        try {
            int turnsWithoutProgress = readyStreams.size();
            while (!readyStreams.isEmpty() && controlChannel.isWritable() && turnsWithoutProgress > 0) {
                int streamId = readyStreams.removeFirst();
                StreamState state = streams.get(streamId);
                if (state == null) {
                    turnsWithoutProgress = readyStreams.size();
                    continue;
                }
                state.ready = false;
                boolean progressed = writeOne(streamId, state);
                if (streams.containsKey(streamId) && (!state.pending.isEmpty() || state.finPending)) {
                    enqueueReady(streamId, state);
                }
                if (progressed) {
                    wrote = true;
                    turnsWithoutProgress = readyStreams.size();
                } else {
                    turnsWithoutProgress--;
                }
            }
        } finally {
            draining = false;
            if (wrote) {
                controlChannel.flush();
            }
            if (!controlChannel.isWritable()) {
                for (StreamState state : streams.values()) {
                    if (!state.pending.isEmpty()) {
                        pauseSource(state);
                    }
                }
            }
        }
    }

    private boolean writeOne(int streamId, StreamState state) {
        PendingData current = state.pending.peekFirst();
        if (current != null && state.credit > 0) {
            int length = (int) Math.min(Math.min(state.credit, MAX_DATA_FRAME_BYTES), current.remaining());
            byte[] payload;
            if (current.offset == 0 && length == current.data.length) {
                payload = current.data;
            } else {
                payload = new byte[length];
                System.arraycopy(current.data, current.offset, payload, 0, length);
            }
            current.offset += length;
            state.credit -= length;
            state.pendingBytes -= length;
            boolean completedData = current.remaining() == 0;
            if (completedData) {
                state.pending.removeFirst();
            }
            NatMessagePacket packet = new NatMessagePacket();
            packet.setNatMessageType(NatMessageType.DATA);
            packet.setStreamId(streamId);
            packet.setData(payload);
            var writeFuture = controlChannel.write(packet);
            if (completedData) {
                writeFuture.addListener(result -> {
                    if (result.isSuccess()) {
                        current.completion.complete(null);
                    } else {
                        current.completion.completeExceptionally(result.cause());
                    }
                });
            }
            if (state.pending.isEmpty()) {
                resumeSource(state);
            } else if (state.credit == 0) {
                pauseSource(state);
            }
            return true;
        }
        if (current != null) {
            pauseSource(state);
            return false;
        }
        if (state.finPending) {
            NatMessagePacket fin = new NatMessagePacket();
            fin.setNatMessageType(NatMessageType.FIN);
            fin.setStreamId(streamId);
            fin.setMetaData(state.finMetadata);
            var writeFuture = controlChannel.write(fin);
            if (state.finCompletion != null) {
                writeFuture.addListener(result -> {
                    if (result.isSuccess()) {
                        state.finCompletion.complete(null);
                    } else {
                        state.finCompletion.completeExceptionally(result.cause());
                    }
                });
            }
            streams.remove(streamId);
            resumeSource(state);
            return true;
        }
        return false;
    }

    private void failStream(int streamId, StreamState state, Runnable overflowAction, String reason,
                            CompletableFuture<Void> currentCompletion) {
        streams.remove(streamId);
        resumeSource(state);
        failPending(state, new IllegalStateException(reason));
        currentCompletion.completeExceptionally(new IllegalStateException(reason));
        if (overflowAction != null) {
            overflowAction.run();
        }
        NatMessagePacket reset = new NatMessagePacket();
        reset.setNatMessageType(NatMessageType.RST);
        reset.setStreamId(streamId);
        reset.setValue(6);
        reset.setMetaData(Map.of("reason", reason));
        controlChannel.writeAndFlush(reset);
    }

    private static void failPending(StreamState state, Throwable error) {
        for (PendingData pending : state.pending) {
            pending.completion.completeExceptionally(error);
        }
        state.pending.clear();
        if (state.finCompletion != null) {
            state.finCompletion.completeExceptionally(error);
        }
    }

    private void enqueueReady(int streamId, StreamState state) {
        if (!state.ready) {
            state.ready = true;
            readyStreams.addLast(streamId);
        }
    }

    private void pauseSource(StreamState state) {
        if (!state.sourcePaused && state.sourceChannel != null) {
            state.sourcePaused = true;
            ChannelBackpressure.setAutoRead(state.sourceChannel, false);
        }
    }

    private void resumeSource(StreamState state) {
        if (state.sourcePaused && state.sourceChannel != null) {
            state.sourcePaused = false;
            ChannelBackpressure.setAutoRead(state.sourceChannel, true);
        }
    }

    private void execute(Runnable operation) {
        if (controlChannel.eventLoop().inEventLoop()) {
            operation.run();
        } else {
            controlChannel.eventLoop().execute(operation);
        }
    }

    private static final class StreamState {
        private final Channel sourceChannel;
        private final ArrayDeque<PendingData> pending = new ArrayDeque<>();
        private long credit = INITIAL_WINDOW_BYTES;
        private long pendingBytes;
        private boolean ready;
        private boolean sourcePaused;
        private boolean finPending;
        private Map<String, Object> finMetadata;
        private CompletableFuture<Void> finCompletion;

        private StreamState(Channel sourceChannel) {
            this.sourceChannel = sourceChannel;
        }
    }

    private static final class PendingData {
        private final byte[] data;
        private final CompletableFuture<Void> completion;
        private int offset;

        private PendingData(byte[] data, CompletableFuture<Void> completion) {
            this.data = data;
            this.completion = completion;
        }

        private int remaining() {
            return data.length - offset;
        }
    }
}
