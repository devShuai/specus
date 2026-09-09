package com.theshuai.common.clientauth;

import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
public class ClientEnvironmentInfo {
    private String machineFingerprint;
    private String hostname;
    private String osUser;
    private String osName;
    private String osVersion;
    private String osArch;
    private String clientVersion;
    private String javaVersion;
    private String peerPublicKey;
    private ClientMessageCapabilities clientMessageCapabilities = new ClientMessageCapabilities();
    private ClientPeerServiceCapabilities clientPeerServiceCapabilities = new ClientPeerServiceCapabilities();
    private ClientEgressCapabilities clientEgressCapabilities = new ClientEgressCapabilities();
    private List<String> localAddresses = new ArrayList<>();
    private String startedAt;

    @Data
    public static class ClientMessageCapabilities {
        private boolean sendMessages;
        private boolean receiveMessages;
        private boolean attachments;
        private boolean mediaPreview;
        private long maxAttachmentBytes;
    }

    @Data
    public static class ClientPeerServiceCapabilities {
        private int version;
        private List<String> applications = new ArrayList<>();
    }

    /**
     * Peer egress split routing. Version 0 or absent means the client cannot take part, and the
     * server must not push egress-config or egress-catalog to it.
     *
     * <p>domainTarget and ipv6Target are tracked separately from the version so that a later
     * release adding domain rules can coexist with clients that only understand address targets,
     * instead of gating on the version number alone.
     */
    @Data
    public static class ClientEgressCapabilities {
        private int version;
        private boolean consumerCapable;
        private boolean egressCapable;
        private boolean domainTargetCapable;
        private boolean ipv6TargetCapable;
    }
}
