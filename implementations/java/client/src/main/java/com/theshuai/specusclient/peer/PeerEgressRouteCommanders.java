package com.theshuai.specusclient.peer;

import com.theshuai.specusclient.peer.PeerEgressRoutePlanner.Route;
import java.io.IOException;
import java.util.Locale;

/**
 * Picking the routing table for the platform this process is running on.
 *
 * <p>Its own class rather than a factory hanging off one of the platforms: with three of them
 * implemented, a {@code forPlatform} living on the Linux commander would be a Linux class deciding
 * whether to build the other two.
 *
 * <p>{@code os.name} reports "Mac OS X" on macOS, so the match is on "mac"; "darwin" is accepted
 * as well because a JVM is free to report the kernel's name and one that did would otherwise fall
 * through to refusing every route.
 */
public final class PeerEgressRouteCommanders {

    private PeerEgressRouteCommanders() {
    }

    /**
     * Whether this platform can take over routes, and so whether this client can be an egress
     * consumer. Announced at login; answers the same question {@link #forPlatform} answers by
     * choosing a commander, from the same property, so the two cannot disagree.
     */
    public static boolean takeoverSupported() {
        String name = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        return name.contains("linux") || name.contains("win") || name.contains("mac")
                || name.contains("darwin");
    }

    /**
     * The smallest MTU IPv6 allows on any link (RFC 8200 5). A device whose Peer Mesh MTU is below it
     * has no IPv6 data plane, and a peer path that probes below it carries no IPv6.
     */
    public static final int IPV6_MINIMUM_MTU = 1280;

    /**
     * Whether this platform reads IPv6 from its TUN, gives the TUN the device's derived IPv6 address
     * and routes IPv6 into it ({@code protocol/spec/peer-egress.md}, IPv6 数据面): every platform with
     * route takeover, since the three that have it have the IPv6 commands too.
     */
    public static boolean platformCarriesIpv6() {
        return takeoverSupported();
    }

    /**
     * Whether this consumer has an IPv6 data plane as configured: the platform's support and a Peer
     * Mesh MTU of at least 1280, an unset one read as the default. Without either a well-formed IPv6
     * rule is refused with {@code EGRESS_RULE_IPV6_UNSUPPORTED}, since installing nothing for it and
     * reporting it in force would send its destinations straight out of the local interface.
     *
     * <p>This is the configuration's half. A running consumer also needs its TUN up and carrying its
     * derived address ({@link PeerEgressMesh}), and judges by that.
     */
    public static boolean consumerCarriesIpv6(int peerMeshMtu) {
        int mtu = peerMeshMtu <= 0 ? PeerVirtualDeviceOptions.DEFAULT_MTU : peerMeshMtu;
        return platformCarriesIpv6() && mtu >= IPV6_MINIMUM_MTU;
    }

    /** The commander for the platform this process is running on. */
    public static PeerEgressRouteInstaller.Commander forPlatform(String tun) {
        String name = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (name.contains("linux")) {
            return new LinuxPeerEgressRouteCommander(tun);
        }
        if (name.contains("win")) {
            return new WindowsPeerEgressRouteCommander(tun);
        }
        if (name.contains("mac") || name.contains("darwin")) {
            return new MacosPeerEgressRouteCommander(tun);
        }
        return new UnsupportedPeerEgressRouteCommander();
    }

    /**
     * The platforms without route takeover.
     *
     * <p>Linux, Windows and macOS all have it now, so what is left is whatever else a JVM runs on.
     *
     * <p>Refusing rather than doing nothing: a consumer that silently installed no routes would
     * send every destination out locally while reporting that its rules were applied, which is the
     * leak this whole feature exists to prevent.
     */
    static final class UnsupportedPeerEgressRouteCommander
            implements PeerEgressRouteInstaller.Commander {
        @Override
        public PeerEgressRouteInstaller.Conflict conflict(Route route) {
            return PeerEgressRouteInstaller.Conflict.none();
        }

        @Override
        public void install(Route route) throws IOException {
            throw new IOException("egress route takeover is not implemented on this platform");
        }

        @Override
        public void remove(Route route) throws IOException {
            throw new IOException("egress route takeover is not implemented on this platform");
        }

        @Override
        public PeerEgressRouteInstaller.Table table6() throws IOException {
            throw new IOException("egress route takeover is not implemented on this platform");
        }
    }
}
