package com.theshuai.specusserver.session;

import com.theshuai.common.session.Session;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

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
