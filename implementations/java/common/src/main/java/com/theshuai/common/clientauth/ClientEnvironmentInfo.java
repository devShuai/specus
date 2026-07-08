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
}
