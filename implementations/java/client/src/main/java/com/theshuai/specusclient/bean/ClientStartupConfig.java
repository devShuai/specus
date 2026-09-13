package com.theshuai.specusclient.bean;

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
    /** Startup + periodic catalogue check. Java phase one only notifies; it never replaces the jar. */
    private boolean updateCheckEnabled = true;
    /** Accepted for the shared cross-client schema; Java phase one deliberately never self-updates. */
    private boolean autoUpdate;
    private long updateCheckIntervalHours = 24;
    private boolean openUpdatePage = true;
}
