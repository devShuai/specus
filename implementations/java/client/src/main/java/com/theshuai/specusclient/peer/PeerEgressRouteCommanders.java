package com.theshuai.specusclient.peer;

import com.theshuai.specusclient.peer.PeerEgressRoutePlanner.Route;
import java.io.IOException;
import java.util.Locale;

/**
 * Picking the routing table for the platform this process is running on.
 *
 * <p>Its own class rather than a factory hanging off one of the platforms: with Linux and Windows
 * both implemented, a {@code forPlatform} living on the Linux commander would be a Linux class
 * deciding whether to build a Windows one.
 */
public final class PeerEgressRouteCommanders {

    private PeerEgressRouteCommanders() {
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
        return new UnsupportedPeerEgressRouteCommander();
    }

    /**
     * The platforms without route takeover: macOS, and anything else this runs on.
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
    }
}
