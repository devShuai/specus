package com.theshuai.tunnelserver.management.controller;

import com.theshuai.tunnelserver.config.PeerMeshProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

@RestController
public class PublicPeerMeshResource {
    private final PeerMeshProperties properties;

    public PublicPeerMeshResource(PeerMeshProperties properties) {
        this.properties = properties;
    }

    @GetMapping("/api/public/peer-mesh/stun-config")
    public PublicStunConfig stunConfig(HttpServletRequest request) {
        LinkedHashSet<String> servers = new LinkedHashSet<>();
        String selfHosted = properties.isEnabled() ? selfHostedStunServer(request) : "";
        if (StringUtils.hasText(selfHosted)) {
            servers.add(selfHosted);
        }
        if (properties.getPublicStunServers() != null) {
            properties.getPublicStunServers().stream()
                    .filter(StringUtils::hasText)
                    .map(this::normalizeStunUrl)
                    .filter(StringUtils::hasText)
                    .forEach(servers::add);
        }
        return new PublicStunConfig(
                properties.isEnabled(),
                selfHosted,
                new ArrayList<>(servers),
                properties.getStunTurnPort()
        );
    }

    private String selfHostedStunServer(HttpServletRequest request) {
        String host = properties.getPublicAddress();
        if (!StringUtils.hasText(host)) {
            host = forwardedHost(request);
        }
        if (!StringUtils.hasText(host)) {
            host = request.getServerName();
        }
        host = normalizeHost(host);
        if (!StringUtils.hasText(host) || properties.getStunTurnPort() <= 0) {
            return "";
        }
        return "stun:" + bracketIpv6(host) + ":" + properties.getStunTurnPort();
    }

    private String forwardedHost(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-Host");
        if (!StringUtils.hasText(forwarded)) {
            forwarded = request.getHeader("Host");
        }
        if (!StringUtils.hasText(forwarded)) {
            return "";
        }
        return forwarded.split(",", 2)[0].trim();
    }

    private String normalizeStunUrl(String value) {
        String normalized = value.trim();
        String lower = normalized.toLowerCase();
        if (lower.startsWith("stun://")) {
            normalized = normalized.substring("stun://".length());
        } else if (lower.startsWith("stun:")) {
            normalized = normalized.substring("stun:".length());
        }
        String host = normalizeHost(normalized);
        if (!StringUtils.hasText(host)) {
            return "";
        }
        int port = parsePort(normalized, 3478);
        return "stun:" + bracketIpv6(host) + ":" + port;
    }

    private String normalizeHost(String value) {
        if (!StringUtils.hasText(value)) {
            return "";
        }
        String host = value.trim();
        int scheme = host.indexOf("://");
        if (scheme >= 0) {
            host = host.substring(scheme + 3);
        }
        int slash = host.indexOf('/');
        if (slash >= 0) {
            host = host.substring(0, slash);
        }
        if (host.startsWith("[")) {
            int close = host.indexOf(']');
            return close > 0 ? host.substring(1, close) : "";
        }
        int firstColon = host.indexOf(':');
        int lastColon = host.lastIndexOf(':');
        if (firstColon > 0 && firstColon == lastColon) {
            host = host.substring(0, firstColon);
        }
        return host.trim();
    }

    private int parsePort(String value, int fallback) {
        String normalized = value.trim();
        int scheme = normalized.indexOf("://");
        if (scheme >= 0) {
            normalized = normalized.substring(scheme + 3);
        }
        int slash = normalized.indexOf('/');
        if (slash >= 0) {
            normalized = normalized.substring(0, slash);
        }
        if (normalized.startsWith("[")) {
            int close = normalized.indexOf(']');
            if (close > 0 && close + 2 < normalized.length() && normalized.charAt(close + 1) == ':') {
                return parsePortNumber(normalized.substring(close + 2), fallback);
            }
            return fallback;
        }
        int firstColon = normalized.indexOf(':');
        int lastColon = normalized.lastIndexOf(':');
        if (firstColon > 0 && firstColon == lastColon && lastColon < normalized.length() - 1) {
            return parsePortNumber(normalized.substring(lastColon + 1), fallback);
        }
        return fallback;
    }

    private int parsePortNumber(String value, int fallback) {
        try {
            int port = Integer.parseInt(value.trim());
            return port > 0 && port <= 65535 ? port : fallback;
        } catch (Exception ignored) {
            return fallback;
        }
    }

    private String bracketIpv6(String host) {
        return host.contains(":") && !host.startsWith("[") ? "[" + host + "]" : host;
    }

    public record PublicStunConfig(boolean peerMeshEnabled,
                                   String selfHostedStunServer,
                                   List<String> stunServers,
                                   int stunTurnPort) {
    }
}
