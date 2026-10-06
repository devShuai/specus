package com.theshuai.specusserver.connectivity;

import java.util.Map;

/**
 * Where a connectivity check meets the device: the client's current NAT connections, and one probe
 * request at a time on its data connection (protocol/spec/service-connectivity-check.md section 5).
 */
public interface ConnectivityProbe {
    /**
     * The state of the client's connections on this server, right now: no reconnect grace, and
     * only connections this process holds count.
     */
    DeviceLink link(String clientName);

    sealed interface DeviceLink permits Offline, DataChannelDown, Online {
    }

    /** No authenticated control session. */
    record Offline() implements DeviceLink {
    }

    /** A control session, but no data connection to carry a stream. */
    record DataChannelDown() implements DeviceLink {
    }

    record Online(ProbeChannel channel) implements DeviceLink {
    }

    /** The data connection of an online client. */
    interface ProbeChannel {
        /**
         * {@code clientHttpRouteCapabilities.version} the session owning this data connection
         * announced at login; 0 for an older client.
         */
        int httpRouteCapability();

        /**
         * Sends OPEN with {@code metadata} and the request FIN, and waits at most
         * {@code timeoutMillis} for the device's first answer. A response head ends the exchange:
         * the stream is reset unless it already closed both ways, and the body is never read.
         * Without an answer in time the stream is reset as well.
         */
        Answer exchange(Map<String, Object> metadata, long timeoutMillis);
    }

    sealed interface Answer permits Head, InvalidHead, Reset, LinkLost, OpenFailed, NoAnswer {
    }

    /** The device relayed the target's response head. */
    record Head(int statusCode) implements Answer {
    }

    /** The device answered with a response OPEN this server could not accept as a head. */
    record InvalidHead() implements Answer {
    }

    /**
     * The device reset the stream before any response head. {@code failure} is its
     * {@code metadata.failure} verbatim, or null; whether to trust it depends on the capability.
     */
    record Reset(String failure) implements Answer {
    }

    /** The data connection closed, or the session was replaced, before any answer. */
    record LinkLost() implements Answer {
    }

    /**
     * The stream never reached the device: the data connection already carries as many streams as
     * the server allows ({@code streamLimit}), or the OPEN could not be written.
     */
    record OpenFailed(boolean streamLimit) implements Answer {
    }

    /** Nothing within the time given; the stream has been reset. */
    record NoAnswer() implements Answer {
    }
}
