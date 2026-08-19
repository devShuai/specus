package com.theshuai.common.peermesh;

import lombok.Data;

@Data
public class PeerServiceSharingStatus {
    private boolean deploymentEnabled;
    private boolean configuredEnabled;
    private boolean effectiveEnabled;
    private boolean mdnsImportEnabled;

    public static PeerServiceSharingStatus of(boolean deploymentEnabled,
                                              boolean configuredEnabled,
                                              boolean deviceEnabled) {
        return of(deploymentEnabled, configuredEnabled, deviceEnabled, false);
    }

    public static PeerServiceSharingStatus of(boolean deploymentEnabled,
                                              boolean configuredEnabled,
                                              boolean deviceEnabled,
                                              boolean mdnsImportEnabled) {
        PeerServiceSharingStatus status = new PeerServiceSharingStatus();
        status.setDeploymentEnabled(deploymentEnabled);
        status.setConfiguredEnabled(configuredEnabled);
        status.setEffectiveEnabled(deploymentEnabled && configuredEnabled && deviceEnabled);
        status.setMdnsImportEnabled(mdnsImportEnabled && deploymentEnabled && configuredEnabled && deviceEnabled);
        return status;
    }
}
