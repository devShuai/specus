package com.theshuai.specusclient.peer;

import com.theshuai.common.peeregress.Ipv4Cidr;
import java.net.Inet4Address;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * The addresses an egress must refuse: this deployment's own endpoints, and this host's own
 * networks.
 *
 * <p>Forwarding a consumer's traffic to the control connection, STUN, TURN or the relay would let a
 * peer reach the infrastructure through the egress it is only supposed to reach the internet
 * through. Forwarding into one of this host's own networks would loop back into its capture path,
 * or reach a service the consumer was never authorised to see.
 *
 * <p>Shared vector: the {@code deploymentEndpoints} section of
 * {@code protocol/test-vectors/peer-egress-control-v1.json}.
 */
final class PeerEgressEndpoints {

    private PeerEgressEndpoints() {
    }

    /**
     * Turns this deployment's endpoints into the /32 prefixes the forced-deny list needs.
     *
     * <p>Only literal addresses are added. A hostname would have to be resolved here, and a
     * resolution taken at policy time can differ from the one the connect uses, which would make
     * the block look enforced when it is not.
     */
    static List<String> deploymentDenyCidrs(
            String serverBaseUrl, String stunHost, String turnHost, String relayAddress) {
        List<String> denied = new ArrayList<>(4);
        appendHost(denied, authorityOf(serverBaseUrl));
        appendHost(denied, stunHost);
        appendHost(denied, turnHost);
        appendHost(denied, relayAddress);
        return List.copyOf(denied);
    }

    /** The authority of a URL, or empty for anything that is not one. */
    private static String authorityOf(String url) {
        String trimmed = url == null ? "" : url.trim();
        if (trimmed.isEmpty()) {
            return "";
        }
        try {
            URI parsed = URI.create(trimmed);
            String authority = parsed.getAuthority();
            if (authority == null) {
                return "";
            }
            // Userinfo is not part of the host.
            int at = authority.lastIndexOf('@');
            return at < 0 ? authority : authority.substring(at + 1);
        } catch (IllegalArgumentException notAUrl) {
            return "";
        }
    }

    private static void appendHost(List<String> denied, String host) {
        String candidate = stripPort(host);
        if (Ipv4Cidr.parseAddress(candidate) != null) {
            denied.add(candidate + "/32");
        }
    }

    /** Removes a {@code :port} suffix, leaving an IPv6 literal in brackets alone. */
    private static String stripPort(String host) {
        String trimmed = host == null ? "" : host.trim();
        if (trimmed.isEmpty() || trimmed.startsWith("[")) {
            return trimmed;
        }
        int colon = trimmed.indexOf(':');
        if (colon < 0 || trimmed.indexOf(':', colon + 1) >= 0) {
            // No port, or more than one colon, which means an unbracketed IPv6 literal rather than
            // a host and port.
            return trimmed;
        }
        return trimmed.substring(0, colon);
    }

    /**
     * The IPv4 networks this host itself owns.
     *
     * <p>Enumerated at policy time rather than cached, because an interface can appear after
     * start-up and a stale list is a hole rather than an inconvenience.
     */
    static List<String> localInterfaceCidrs() {
        List<String> networks = new ArrayList<>();
        try {
            for (NetworkInterface device : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                for (InterfaceAddress address : device.getInterfaceAddresses()) {
                    if (!(address.getAddress() instanceof Inet4Address)) {
                        continue;
                    }
                    int prefix = address.getNetworkPrefixLength();
                    if (prefix < 0 || prefix > 32) {
                        continue;
                    }
                    Integer value = Ipv4Cidr.parseAddress(address.getAddress().getHostAddress());
                    if (value == null) {
                        continue;
                    }
                    networks.add(networkOf(value, prefix));
                }
            }
        } catch (Exception unavailable) {
            // An interface list this host will not hand over is not a reason to fail; the rest of
            // the forced-deny list still applies.
            return List.of();
        }
        return List.copyOf(networks);
    }

    /** Masks an address down to its network and renders it as a prefix. */
    static String networkOf(int address, int prefixLength) {
        int mask = prefixLength == 0 ? 0 : 0xFFFFFFFF << (32 - prefixLength);
        return Ipv4Cidr.format(address & mask) + "/" + prefixLength;
    }
}
