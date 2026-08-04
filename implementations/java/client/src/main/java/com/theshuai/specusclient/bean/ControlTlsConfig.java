package com.theshuai.specusclient.bean;

import lombok.Data;
import org.springframework.util.StringUtils;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;

/**
 * TLS settings for the control/data TCP connections.
 *
 * <p>When {@link #enabled} is omitted, the client follows the {@code nettyTls}
 * value advertised by the login response. Supplying any TLS-specific option also
 * enables TLS, so a custom CA can be configured without duplicating the flag.
 */
@Data
public class ControlTlsConfig {
    private Boolean enabled;
    private String caCertificatePath;
    private String serverName;
    private boolean insecureSkipVerify;

    public boolean resolveEnabled(boolean runtimeNettyTls) {
        if (enabled != null) {
            return enabled;
        }
        return runtimeNettyTls || StringUtils.hasText(caCertificatePath)
                || StringUtils.hasText(serverName) || insecureSkipVerify;
    }

    public void validate(String serverBaseUrl) {
        parseServerBaseUrl(serverBaseUrl);
        boolean tlsEnabled = resolveEnabled(false);
        boolean hasCa = StringUtils.hasText(caCertificatePath);
        boolean hasServerName = StringUtils.hasText(serverName);
        if (!tlsEnabled && (hasCa || hasServerName || insecureSkipVerify)) {
            throw new IllegalStateException(
                    "controlTls TLS options cannot be used when controlTls.enabled=false");
        }
        if (hasCa && insecureSkipVerify) {
            throw new IllegalStateException(
                    "controlTls.caCertificatePath and insecureSkipVerify cannot be used together");
        }
        validateServerName();
    }

    public String resolveServerName(String nettyHost) {
        return StringUtils.hasText(serverName) ? serverName.trim() : nettyHost;
    }

    private void validateServerName() {
        if (!StringUtils.hasText(serverName)) {
            return;
        }
        String value = serverName.trim();
        if (value.contains("://") || value.contains("/") || value.contains("\\")) {
            throw new IllegalStateException(
                    "controlTls.serverName must be a hostname or IP address without scheme or path");
        }
        if (value.startsWith("[") || value.endsWith("]")) {
            throw new IllegalStateException(
                    "controlTls.serverName must not use brackets around an IP address");
        }
        if (value.contains(":") && !isIpv6Literal(value)) {
            throw new IllegalStateException("controlTls.serverName must not include a port");
        }
    }

    private static boolean isIpv6Literal(String value) {
        try {
            return InetAddress.getByName(value) instanceof Inet6Address;
        } catch (UnknownHostException ignored) {
            return false;
        }
    }

    static URI parseServerBaseUrl(String value) {
        try {
            URI uri = URI.create(value == null ? "" : value.trim());
            String scheme = uri.getScheme();
            if (!uri.isAbsolute() || uri.getHost() == null
                    || !("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))) {
                throw new IllegalArgumentException();
            }
            return uri;
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("serverBaseUrl must be an absolute http/https URL", e);
        }
    }
}
