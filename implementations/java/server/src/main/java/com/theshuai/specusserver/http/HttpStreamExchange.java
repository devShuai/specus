package com.theshuai.specusserver.http;

import com.theshuai.common.handler.StreamFlowController;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/** One mandatory HTTP stream v2 exchange keyed by a connection-local stream id. */
public final class HttpStreamExchange {
    private static final int MAX_QUEUED_DATA_EVENTS = 4096;
    private static final long MAX_QUEUED_DATA_BYTES = StreamFlowController.INITIAL_WINDOW_BYTES;

    private final int streamId;
    private final CompletableFuture<ResponseHead> responseHead = new CompletableFuture<>();
    private final LinkedBlockingQueue<Event> events = new LinkedBlockingQueue<>();
    private volatile List<String> trailers = List.of();
    private int queuedDataEvents;
    private long queuedDataBytes;
    private boolean terminalQueued;

    public HttpStreamExchange(int streamId) {
        this.streamId = streamId;
    }

    public int streamId() {
        return streamId;
    }

    public boolean onResponseHead(Map<String, Object> metadata) {
        if (metadata == null || !"http".equals(text(metadata.get("source")))
                || !"response".equals(text(metadata.get("phase")))) {
            return false;
        }
        Object statusValue = metadata.get("statusCode");
        int statusCode = statusValue instanceof Number number ? number.intValue() : 0;
        if (statusCode < 100 || statusCode > 599) {
            return false;
        }
        return responseHead.complete(new ResponseHead(statusCode, stringList(metadata.get("headers"))));
    }

    public synchronized boolean onData(byte[] data) {
        if (data == null || data.length == 0 || terminalQueued
                || queuedDataEvents >= MAX_QUEUED_DATA_EVENTS
                || queuedDataBytes > MAX_QUEUED_DATA_BYTES - data.length) {
            return false;
        }
        queuedDataEvents++;
        queuedDataBytes += data.length;
        events.offer(new Data(data));
        return true;
    }

    public synchronized void onFin(Map<String, Object> metadata) {
        if (terminalQueued) {
            return;
        }
        terminalQueued = true;
        trailers = stringList(metadata == null ? null : metadata.get("trailers"));
        events.offer(new End(trailers));
    }

    public synchronized void onReset(long errorCode, Map<String, Object> metadata) {
        String reason = metadata == null ? null : text(metadata.get("reason"));
        Reset reset = new Reset(errorCode, reason == null || reason.isBlank() ? "HTTP stream reset" : reason);
        responseHead.completeExceptionally(new HttpStreamException(reset.reason(), errorCode));
        if (terminalQueued) {
            return;
        }
        terminalQueued = true;
        events.offer(reset);
    }

    public ResponseHead awaitResponseHead(long timeoutMillis) throws Exception {
        return responseHead.get(timeoutMillis, TimeUnit.MILLISECONDS);
    }

    public Event take() throws InterruptedException {
        Event event = events.take();
        if (event instanceof Data data) {
            synchronized (this) {
                queuedDataEvents--;
                queuedDataBytes -= data.bytes().length;
            }
        }
        return event;
    }

    public List<String> trailers() {
        return trailers;
    }

    public sealed interface Event permits Data, End, Reset {
    }

    public record Data(byte[] bytes) implements Event {
    }

    public record End(List<String> trailers) implements Event {
    }

    public record Reset(long errorCode, String reason) implements Event {
    }

    public record ResponseHead(int statusCode, List<String> headers) {
    }

    public static final class HttpStreamException extends Exception {
        private final long errorCode;

        public HttpStreamException(String message, long errorCode) {
            super(message);
            this.errorCode = errorCode;
        }

        public long errorCode() {
            return errorCode;
        }
    }

    private static String text(Object value) {
        return value == null ? null : value.toString();
    }

    private static List<String> stringList(Object value) {
        if (!(value instanceof Iterable<?> values)) {
            return List.of();
        }
        List<String> result = new ArrayList<>();
        for (Object item : values) {
            if (item != null) {
                result.add(item.toString());
            }
        }
        return List.copyOf(result);
    }
}
