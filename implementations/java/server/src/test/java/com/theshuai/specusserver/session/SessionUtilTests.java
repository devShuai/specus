package com.theshuai.specusserver.session;

import com.theshuai.common.session.Session;
import com.theshuai.specusserver.attribute.ServerAttributes;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/** A data connection lives only as long as the control connection it was opened under. */
class SessionUtilTests {
    private final String clientName = "session-" + UUID.randomUUID();
    private final List<EmbeddedChannel> channels = new ArrayList<>();

    @AfterEach
    void closeChannels() {
        channels.forEach(EmbeddedChannel::finishAndReleaseAll);
    }

    @Test
    void closingTheCurrentControlConnectionClosesItsDataConnection() {
        EmbeddedChannel control = bindControl();
        EmbeddedChannel data = bindData();

        // What the server does to a disabled, renamed or deleted client: it closes the control only.
        control.close();

        assertThat(data.isOpen()).isFalse();
        assertThat(SessionUtil.getChannel(clientName)).isNull();
        assertThat(SessionUtil.getDataChannel(clientName)).isNull();
    }

    @Test
    void closingAReplacedControlConnectionLeavesTheNewDataConnection() {
        EmbeddedChannel replaced = bindControl();
        bindData();
        EmbeddedChannel control = bindControl();
        EmbeddedChannel data = bindData();

        // On a real event loop the replaced connection's close bookkeeping can run this late.
        SessionUtil.unBindSession(replaced);

        assertThat(replaced.isOpen()).isFalse();
        assertThat(data.isOpen()).isTrue();
        assertThat(SessionUtil.getChannel(clientName)).isSameAs(control);
        assertThat(SessionUtil.getDataChannel(clientName)).isSameAs(data);
    }

    @Test
    void replacingControlDetachesOnlyTheDataThatPrecededItsPublication() {
        EmbeddedChannel successorData = new EmbeddedChannel();
        channels.add(successorData);
        EmbeddedChannel replaced = new EmbeddedChannel(new ChannelOutboundHandlerAdapter() {
            @Override
            public void close(ChannelHandlerContext ctx, ChannelPromise promise) {
                // Closing the displaced socket can immediately invoke application callbacks. By
                // this point the successor CONTROL is visible and may accept its own DATA.
                SessionUtil.bindDataSession(new Session(clientName), successorData);
                ctx.close(promise);
            }
        });
        channels.add(replaced);
        SessionUtil.bindControlSession(new Session(clientName), replaced);
        EmbeddedChannel previousData = bindData();

        EmbeddedChannel current = bindControl();

        assertThat(replaced.isOpen()).isFalse();
        assertThat(previousData.isOpen()).isFalse();
        assertThat(SessionUtil.getChannel(clientName)).isSameAs(current);
        assertThat(successorData.isActive()).as("old CONTROL cleanup must not remove successor DATA").isTrue();
        assertThat(SessionUtil.getDataChannel(clientName)).isSameAs(successorData);
    }

    @Test
    void rejectedPhysicalPairDoesNotDisplaceTheCurrentData() {
        EmbeddedChannel obsolete = bindControl();
        obsolete.attr(ServerAttributes.CLIENT_SESSION_ID).set(7L);
        EmbeddedChannel control = bindControl();
        control.attr(ServerAttributes.CLIENT_SESSION_ID).set(7L);
        EmbeddedChannel data = bindData();
        EmbeddedChannel candidate = new EmbeddedChannel();channels.add(candidate);

        assertThat(SessionUtil.bindDataSession(new Session(clientName), candidate, obsolete, 7L)).isFalse();
        assertThat(SessionUtil.getDataChannel(clientName)).isSameAs(data);
        assertThat(data.isActive()).isTrue();
        assertThat(SessionUtil.getSession(candidate)).isNull();
    }

    @Test
    void matchingPhysicalControlStillRequiresTheAuthenticatedSession() {
        EmbeddedChannel control = bindControl();
        control.attr(ServerAttributes.CLIENT_SESSION_ID).set(7L);
        EmbeddedChannel candidate = new EmbeddedChannel();channels.add(candidate);

        assertThat(SessionUtil.bindDataSession(new Session(clientName), candidate, control, 8L)).isFalse();
        assertThat(SessionUtil.bindDataSession(new Session(clientName), candidate, control, null)).isFalse();
        assertThat(SessionUtil.getDataChannel(clientName)).isNull();
        assertThat(SessionUtil.bindDataSession(new Session(clientName), candidate, control, 7L)).isTrue();
        assertThat(SessionUtil.getDataChannel(clientName)).isSameAs(candidate);
    }

    @Test
    void closedDataCannotBecomeAPublishedSession() {
        EmbeddedChannel control = bindControl();
        control.attr(ServerAttributes.CLIENT_SESSION_ID).set(7L);
        EmbeddedChannel candidate = new EmbeddedChannel();channels.add(candidate);candidate.close();

        assertThat(SessionUtil.bindDataSession(new Session(clientName), candidate, control, 7L)).isFalse();
        assertThat(SessionUtil.getDataChannel(clientName)).isNull();
        assertThat(SessionUtil.getSession(candidate)).isNull();
    }

    @Test
    void socketCloseCallbacksRunOutsideTheRegistryLock() throws Exception {
        try (var executor = Executors.newSingleThreadExecutor()) {
            var callback = new CompletableFuture<Void>();
            EmbeddedChannel successorData = new EmbeddedChannel();channels.add(successorData);
            EmbeddedChannel replaced = new EmbeddedChannel(new ChannelOutboundHandlerAdapter() {
                @Override public void close(ChannelHandlerContext ctx, ChannelPromise promise) {
                    try {
                        executor.submit(() -> SessionUtil.bindDataSession(new Session(clientName), successorData))
                                .get(3, TimeUnit.SECONDS);
                        callback.complete(null);
                    } catch (Exception failure) {callback.completeExceptionally(failure);}
                    finally {ctx.close(promise);}
                }
            });
            channels.add(replaced);SessionUtil.bindControlSession(new Session(clientName), replaced);

            bindControl();

            callback.get(5, TimeUnit.SECONDS);
            assertThat(SessionUtil.getDataChannel(clientName)).isSameAs(successorData);
            assertThat(successorData.isActive()).isTrue();
        }
    }

    private EmbeddedChannel bindControl() {
        EmbeddedChannel channel = new EmbeddedChannel();
        channels.add(channel);
        SessionUtil.bindControlSession(new Session(clientName), channel);
        return channel;
    }

    private EmbeddedChannel bindData() {
        EmbeddedChannel channel = new EmbeddedChannel();
        channels.add(channel);
        SessionUtil.bindDataSession(new Session(clientName), channel);
        return channel;
    }
}
