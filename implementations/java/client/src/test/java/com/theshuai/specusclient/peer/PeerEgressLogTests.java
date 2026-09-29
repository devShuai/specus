package com.theshuai.specusclient.peer;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.SocketTimeoutException;

import static org.assertj.core.api.Assertions.assertThat;

/** The egress logs why a dial failed and never where it went: exception messages carry the address. */
class PeerEgressLogTests {

    @Test
    void connectReasonNamesTheCauseWithoutTheAddress() {
        assertThat(PeerEgressRuntime.connectReason(new ConnectException("Connection refused"))).isEqualTo("refused");
        assertThat(PeerEgressRuntime.connectReason(
                new IOException("connect /203.0.113.10:80", new ConnectException("Connection refused")))).isEqualTo("refused");
        assertThat(PeerEgressRuntime.connectReason(new SocketTimeoutException("Connect timed out"))).isEqualTo("timed out");
        assertThat(PeerEgressRuntime.connectReason(new NoRouteToHostException("No route to host"))).isEqualTo("unreachable");
        assertThat(PeerEgressRuntime.connectReason(new ConnectException("Network is unreachable"))).isEqualTo("unreachable");
        assertThat(PeerEgressRuntime.connectReason(
                new PeerEgressSocketBinder.NoPhysicalRouteException("203.0.113.10"))).isEqualTo("no route outside the tunnel");
        assertThat(PeerEgressRuntime.connectReason(new IOException("203.0.113.10:80 went wrong"))).isEqualTo("error");
        assertThat(PeerEgressRuntime.connectReason(null)).isEqualTo("no socket");
    }
}
