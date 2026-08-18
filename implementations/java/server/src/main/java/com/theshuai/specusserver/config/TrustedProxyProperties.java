package com.theshuai.specusserver.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Trusted reverse-proxy boundary. Forwarded headers are only honoured when the connection peer is
 * one of these CIDRs; the list is empty by default, so a deployment without an explicit boundary
 * ignores {@code X-Forwarded-For} / {@code X-Real-IP} entirely.
 */
@Component
@ConfigurationProperties(prefix = "specus")
public class TrustedProxyProperties {
    private List<String> trustedProxies = new ArrayList<>();

    public List<String> getTrustedProxies() {
        return trustedProxies;
    }

    public void setTrustedProxies(List<String> trustedProxies) {
        this.trustedProxies = trustedProxies == null ? new ArrayList<>() : trustedProxies;
    }
}
