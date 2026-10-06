package com.theshuai.specusserver.http;

import com.theshuai.common.handler.StreamFlowController;
import com.theshuai.common.protocol.HttpRouteFailure;

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
    private volatile List<String> responseTrailerNames = List.of();
    private int queuedDataEvents;
    private long queuedDataBytes;
    private boolean responseOpened;
    private boolean terminalQueued;
    private boolean responseEnded;

    public HttpStreamExchange(int streamId) {
        this.streamId = streamId;
    }

    public int streamId() {
        return streamId;
    }

    public synchronized boolean onResponseHead(Map<String, Object> metadata) {
        if (metadata == null || !"http".equals(text(metadata.get("source")))
                || !"response".equals(text(metadata.get("phase")))) {
            return false;
        }
        Object statusValue = metadata.get("statusCode");
        int statusCode = statusValue instanceof Number number ? number.intValue() : 0;
        if (statusCode < 100 || statusCode > 599) {
            return false;
        }
        if (responseOpened || terminalQueued) {
            return false;
        }
        responseTrailerNames = HttpSpecusController.validTrailerNames(
                stringList(metadata.get("trailerNames")), false);
        responseOpened = true;
        return responseHead.complete(new ResponseHead(
                statusCode,
                stringList(metadata.get("headers")),
                responseTrailerNames));
    }

    public synchronized boolean onData(byte[] data) {
        if (data == null || data.length == 0 || !responseOpened || terminalQueued
                || queuedDataEvents >= MAX_QUEUED_DATA_EVENTS
                || queuedDataBytes > MAX_QUEUED_DATA_BYTES - data.length) {
            return false;
        }
        queuedDataEvents++;
        queuedDataBytes += data.length;
        events.offer(new Data(data));
        return true;
    }

    public synchronized boolean onFin(Map<String, Object> metadata) {
        if (!responseOpened || terminalQueued) {
            return false;
        }
        terminalQueued = true;
        responseEnded = true;
        trailers = HttpSpecusController.validTrailerLines(
                stringList(metadata == null ? null : metadata.get("trailers")), responseTrailerNames);
        events.offer(new End(trailers));
        return true;
    }

    /** An RST the client sent for this stream. */
    public void onReset(long errorCode, Map<String, Object> metadata) {
        onReset(errorCode, metadata, ResetOrigin.PEER);
    }

    /**
     * Ends the exchange with a reset. Only a {@link ResetOrigin#PEER} reset keeps the client's
     * {@code metadata.failure}, the classification the connectivity check reads; the public path
     * keeps its fixed body and never shows the reason or the failure.
     */
    public synchronized void onReset(long errorCode, Map<String, Object> metadata, ResetOrigin origin) {
        String reason = metadata == null ? null : text(metadata.get("reason"));
        String failure = origin == ResetOrigin.PEER && metadata != null
                ? text(metadata.get(HttpRouteFailure.METADATA_KEY)) : null;
        Reset reset = new Reset(errorCode, reason == null || reason.isBlank() ? "HTTP stream reset" : reason);
        responseHead.completeExceptionally(new HttpStreamException(reset.reason(), errorCode, origin, failure));
        if (terminalQueued) {
            return;
        }
        terminalQueued = true;
        events.offer(reset);
    }

    /** Whether the client ended its response with FIN, so the response direction is closed. */
    public synchronized boolean responseEnded() {
        return responseEnded;
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

    public record ResponseHead(int statusCode, List<String> headers, List<String> trailerNames) {
    }

    /** Who ended a stream with a reset. */
    public enum ResetOrigin {
        /** The client sent RST; its metadata may classify why the target could not be used. */
        PEER,
        /** This server cancelled the stream, for example for an invalid response head. */
        LOCAL,
        /** The data connection closed, or the OPEN could not be written to it. */
        CONNECTION
    }

    public static final class HttpStreamException extends Exception {
        private final long errorCode;
        private final ResetOrigin origin;
        private final String failure;

        public HttpStreamException(String message, long errorCode) {
            this(message, errorCode, ResetOrigin.PEER, null);
        }

        public HttpStreamException(String message, long errorCode, ResetOrigin origin, String failure) {
            super(message);
            this.errorCode = errorCode;
            this.origin = origin;
            this.failure = failure;
        }

        public long errorCode() {
            return errorCode;
        }

        public ResetOrigin origin() {
            return origin;
        }

        /**
         * The client's {@code metadata.failure}, verbatim and unvalidated, or null. Only a peer reset
         * carries one; whether to trust it depends on the capability of the session it came from.
         */
        public String failure() {
            return failure;
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
