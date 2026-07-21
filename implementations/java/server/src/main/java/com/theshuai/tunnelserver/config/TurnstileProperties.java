package com.theshuai.tunnelserver.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
@ConfigurationProperties(prefix = "tunnel.auth.turnstile")
public class TurnstileProperties {
    private boolean enabled;
    private String siteKey = "";
    private String secretKey = "";
    private String verifyUrl = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
    private List<String> allowedHostnames = new ArrayList<>();

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getSiteKey() {
        return siteKey;
    }

    public void setSiteKey(String siteKey) {
        this.siteKey = siteKey;
    }

    public String getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }

    public String getVerifyUrl() {
        return verifyUrl;
    }

    public void setVerifyUrl(String verifyUrl) {
        this.verifyUrl = verifyUrl;
    }

    public List<String> getAllowedHostnames() {
        return allowedHostnames;
    }

    public void setAllowedHostnames(List<String> allowedHostnames) {
        this.allowedHostnames = allowedHostnames == null ? new ArrayList<>() : allowedHostnames;
    }
}
