package com.theshuai.specusclient.bean;

import com.theshuai.common.peeregress.PeerEgressDns;
import com.theshuai.common.peeregress.PeerEgressRule;
import com.theshuai.specusclient.peer.PeerVirtualDeviceOptions;
import java.util.List;
import lombok.Data;

@Data
public class ClientStartupConfig {
    private String serverBaseUrl;
    private String apiKey;
    private String secret;
    private ControlTlsConfig controlTls = new ControlTlsConfig();
    private UpstreamTlsConfig upstreamTls = new UpstreamTlsConfig();
    private String peerMeshDevice = "noop";
    private String peerMeshTunName = "specus0";
    private int peerMeshMtu = PeerVirtualDeviceOptions.DEFAULT_MTU;
    /**
     * Destinations to send through an egress peer, from the shared {@code peerEgressRules} field.
     *
     * <p>Until this existed the field was read by the Go and .NET clients and by nothing here: the
     * Java client warned that {@code peerEgressRules} was an unknown field, ignored it, and sent
     * every destination out locally -- the leak the whole feature exists to prevent, on a client
     * whose tests all called the mesh with rules directly and so never saw it.
     */
    private List<PeerEgressRule> peerEgressRules = List.of();
    /**
     * The consumer's master switch: "take over system traffic". Off by default; the rules are then
     * kept and none is applied. Saving rules and taking over traffic are separate steps (#49).
     */
    private boolean peerEgressEnabled;
    /**
     * Phase two of peer egress, domain rules through fake IPs (protocol/spec/peer-egress-dns.md).
     * Off by default, and only ever on top of {@link #peerEgressEnabled}; off, domain rules are
     * refused exactly as in phase one.
     */
    private boolean peerEgressDnsTakeover;
    /** The pool fake IPs are handed out of: IPv4, /8 to /24, clear of the mesh and local networks. */
    private String peerEgressFakeIpCidr = PeerEgressDns.DEFAULT_FAKE_IP_CIDR;
    /** Startup + periodic catalogue check. Java phase one only notifies; it never replaces the jar. */
    private boolean updateCheckEnabled = true;
    /** Accepted for the shared cross-client schema; Java phase one deliberately never self-updates. */
    private boolean autoUpdate;
    private long updateCheckIntervalHours = 24;
    private boolean openUpdatePage = true;
}
