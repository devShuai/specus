package com.theshuai.specusserver.connectivity;

import com.theshuai.specusserver.attribute.ServerAttributes;
import com.theshuai.specusserver.handler.NatServerHandler;
import com.theshuai.specusserver.handler.SpecusStreamIds;
import com.theshuai.specusserver.http.HttpStreamExchange;
import com.theshuai.specusserver.session.ClientHttpRouteCapabilities;
import com.theshuai.specusserver.session.SessionUtil;
import io.netty.channel.Channel;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

/**
 * The connectivity probe over the client's real NAT connections: the same HTTP stream the public
 * path opens ({@link NatServerHandler#openHttpStream}), but with no Basic auth, no path rewrite, no
 * traffic accounting or detail capture, and no body read. The stream shares the data connection's
 * flow control with public requests and gets no reserved slot.
 *
 * <p>This server has no per-connection stream limit, so an open fails only when the data connection
 * is gone or the OPEN cannot be written; {@link ConnectivityProbe.OpenFailed#streamLimit()} is never
 * true here.
 */
@Component
public class NatConnectivityProbe implements ConnectivityProbe {
    static final String ABANDON_REASON = "connectivity check finished";

    private final ClientHttpRouteCapabilities capabilities;

    public NatConnectivityProbe(ClientHttpRouteCapabilities capabilities) {
        this.capabilities = capabilities;
    }

    @Override
    public DeviceLink link(String clientName) {
        Channel control = clientName == null ? null : SessionUtil.getChannel(clientName);
        if (control == null || !control.isActive() || !SessionUtil.hasLogin(control)) {
            return new Offline();
        }
        Channel data = SessionUtil.getDataChannel(clientName);
        NatServerHandler handler = data == null ? null : data.pipeline().get(NatServerHandler.class);
        if (handler == null || !data.isActive()) {
            return new DataChannelDown();
        }
        // The capability of the session that owns this very data connection.
        int capability = capabilities.versionOf(data.attr(ServerAttributes.CLIENT_SESSION_ID).get());
        return new Online(new DataChannel(handler, capability));
    }

    /** One data connection; each exchange is its own stream. */
    static final class DataChannel implements ConnectivityProbe.ProbeChannel {
        private final NatServerHandler handler;
        private final int capability;

        DataChannel(NatServerHandler handler, int capability) {
            this.handler = handler;
            this.capability = capability;
        }

        @Override
        public int httpRouteCapability() {
            return capability;
        }

        @Override
        public Answer exchange(Map<String, Object> metadata, long timeoutMillis) {
            int streamId = SpecusStreamIds.next();
            HttpStreamExchange exchange = new HttpStreamExchange(streamId);
            if (!handler.openHttpStream(exchange, metadata)) {
                // The data connection went away between the online check and the open.
                return new OpenFailed(false);
            }
            CompletableFuture<Void> requestFin = handler.finishHttpRequest(streamId, List.of());
            try {
                return new Head(exchange.awaitResponseHead(timeoutMillis).statusCode());
            } catch (TimeoutException silent) {
                return new NoAnswer();
            } catch (ExecutionException ended) {
                return classify(ended.getCause());
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new CancellationException("connectivity check interrupted");
            } catch (Exception unexpected) {
                return classify(unexpected);
            } finally {
                // The head is all the check wanted, or it gave up: the stream ends here, its body
                // is never read.
                handler.abandonHttpStream(streamId,
                        requestFin.isDone() && !requestFin.isCompletedExceptionally(), ABANDON_REASON);
            }
        }

        private static Answer classify(Throwable cause) {
            if (!(cause instanceof HttpStreamExchange.HttpStreamException reset)) {
                return new LinkLost();
            }
            return switch (reset.origin()) {
                case PEER -> new Reset(reset.failure());
                // Before a head, this server only cancels a stream for a response OPEN it refused.
                case LOCAL -> new InvalidHead();
                case CONNECTION -> new LinkLost();
            };
        }
    }
}
