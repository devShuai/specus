package com.theshuai.specusclient.bean;

import com.theshuai.specusclient.peer.PeerVirtualDeviceOptions;
import lombok.Data;

@Data
public class ClientStartupConfig {
    private String serverBaseUrl;
    private String apiKey;
    private String secret;
    private ControlTlsConfig controlTls = new ControlTlsConfig();
    private String peerMeshDevice = "noop";
    private String peerMeshTunName = "specus0";
    private int peerMeshMtu = PeerVirtualDeviceOptions.DEFAULT_MTU;
    /** Startup + periodic catalogue check. Java phase one only notifies; it never replaces the jar. */
    private boolean updateCheckEnabled = true;
    /** Accepted for the shared cross-client schema; Java phase one deliberately never self-updates. */
    private boolean autoUpdate;
    private long updateCheckIntervalHours = 24;
    private boolean openUpdatePage = true;
}
