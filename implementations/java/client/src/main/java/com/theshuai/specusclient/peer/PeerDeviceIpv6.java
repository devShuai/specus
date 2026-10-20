package com.theshuai.specusclient.peer;

import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import org.slf4j.Logger;

/**
 * Giving the TUN the device's derived IPv6 address ({@code protocol/spec/peer-egress.md}, IPv6 数据面,
 * 消费端).
 *
 * <p>The address is the mesh IPv4 inside {@code fd53:7065:6375:7300::/96}, as a /128: no on-link
 * route comes with it, so nothing reaches the TUN by IPv6 but what a rule's route sends there, and
 * the system picks it as the source for exactly that traffic. Without it an application's packet
 * would leave with some other source, which the data plane refuses as {@code ipv6-source-not-mesh}.
 *
 * <p>A failure to assign it is logged and the device stays up: the IPv4 mesh does not depend on it.
 * The device then reports no IPv6 data plane ({@link PeerVirtualDevice#ipv6Readiness}), so IPv6
 * rules are refused with {@code EGRESS_RULE_IPV6_UNSUPPORTED} and no IPv6 route is planned -- an
 * IPv6 install that would fail must not roll the IPv4 routes back.
 *
 * <p>No platform guard: the command builders are the part worth testing everywhere, and only the
 * device classes that run them are platform-specific. Thread-safe: the device's start writes the
 * state and the mesh's reconcile reads it.
 */
final class PeerDeviceIpv6 {

    /** The reason a device given no derived address carries no IPv6. */
    static final String NOT_ASKED =
            "the consumer is off or peerMeshMtu is below 1280, so the TUN was given no IPv6 address";

    /** Runs one command that gives the address, throwing when it failed. */
    interface Assignment {
        void assign(String address);
    }

    /** The derived address this device is given, or null when it is given none. */
    private final String address;
    private volatile PeerVirtualDevice.Ipv6Readiness readiness = PeerVirtualDevice.Ipv6Readiness.no(NOT_ASKED);

    PeerDeviceIpv6(PeerVirtualDeviceOptions options, ClientAuthLoginResponse.PeerMeshConfig config) {
        this.address = address(options, config == null ? null : config.getVirtualIp());
    }

    /**
     * The derived IPv6 address the TUN is given, or null when it is given none: the consumer is
     * switched off, or this device has no IPv6 data plane (its platform, or a peerMeshMtu below
     * 1280). Assigned only for the consumer -- an address on the TUN serves nothing else, and a
     * device that never asked for IPv6 should not grow one.
     */
    static String address(PeerVirtualDeviceOptions options, String virtualIp) {
        if (options == null || !options.egressIpv6()
                || !PeerEgressRouteCommanders.consumerCarriesIpv6(options.mtu())) {
            return null;
        }
        PeerEgressIpv6Packet.Address derived = PeerEgressIpv6Packet.deviceAddress(virtualIp == null ? null : virtualIp.trim());
        return derived == null ? null : derived.format();
    }

    /** The address, or null; for the device's own log line. */
    String address() {
        return address;
    }

    /**
     * Gives the device its address after it came up with its IPv4 one: before any route is pointed
     * at it, which on macOS is a requirement. A failure leaves the device without IPv6 and says so.
     *
     * @param what how the device names itself in the log and in the reason
     */
    void configure(Assignment assignment, String what, Logger log) {
        if (address == null) {
            readiness = PeerVirtualDevice.Ipv6Readiness.no(NOT_ASKED);
            return;
        }
        try {
            assignment.assign(address);
        } catch (RuntimeException failed) {
            readiness = PeerVirtualDevice.Ipv6Readiness.no(
                    "the " + what + "'s IPv6 address could not be assigned: " + failed.getMessage());
            log.warn("Peer Mesh {} IPv6 address not assigned; IPv6 rules are not in force: {}", what, failed.getMessage());
            return;
        }
        readiness = PeerVirtualDevice.Ipv6Readiness.yes();
    }

    /** The device closed: whatever it carried, it carries nothing now. */
    void closed(String what) {
        readiness = PeerVirtualDevice.Ipv6Readiness.no("the " + what + " is closed");
    }

    PeerVirtualDevice.Ipv6Readiness readiness() {
        return readiness;
    }
}
