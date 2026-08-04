package com.theshuai.common.handler;

/**
 * Directional close state for one NAT TCP stream.
 *
 * <p>The local socket input maps to the NAT direction sent by this process. A remote NAT FIN maps
 * to shutting down the local socket output. The socket may be fully closed only after both
 * directional shutdowns have completed. RST is terminal and suppresses every later FIN.
 */
public final class TcpHalfCloseState {
    public enum Transition {
        ACCEPTED,
        DUPLICATE,
        RESET
    }

    private boolean localFinStarted;
    private boolean localFinFlushed;
    private boolean remoteFinReceived;
    private boolean remoteOutputShutdown;
    private boolean reset;

    public synchronized Transition beginLocalFin() {
        if (reset) {
            return Transition.RESET;
        }
        if (localFinStarted) {
            return Transition.DUPLICATE;
        }
        localFinStarted = true;
        return Transition.ACCEPTED;
    }

    public synchronized void completeLocalFin() {
        if (localFinStarted && !reset) {
            localFinFlushed = true;
        }
    }

    public synchronized Transition receiveRemoteFin() {
        if (reset) {
            return Transition.RESET;
        }
        if (remoteFinReceived) {
            return Transition.DUPLICATE;
        }
        remoteFinReceived = true;
        return Transition.ACCEPTED;
    }

    public synchronized void completeRemoteOutputShutdown() {
        if (remoteFinReceived && !reset) {
            remoteOutputShutdown = true;
        }
    }

    public synchronized boolean canSendLocalData() {
        return !reset && !localFinStarted;
    }

    public synchronized boolean canReceiveRemoteData() {
        return !reset && !remoteFinReceived;
    }

    public synchronized boolean reset() {
        if (reset) {
            return false;
        }
        reset = true;
        return true;
    }

    public synchronized boolean isReset() {
        return reset;
    }

    /** Both FIN directions have begun, so a subsequent socket inactive event is expected. */
    public synchronized boolean isGracefulClosing() {
        return !reset && localFinStarted && remoteFinReceived;
    }

    /** Both FIN directions have been durably propagated to their respective transports. */
    public synchronized boolean isGracefullyComplete() {
        return !reset && localFinFlushed && remoteOutputShutdown;
    }
}
