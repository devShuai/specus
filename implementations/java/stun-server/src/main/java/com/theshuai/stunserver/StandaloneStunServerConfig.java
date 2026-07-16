package com.theshuai.stunserver;

import com.theshuai.common.stun.StunEndpointTopology;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

public record StandaloneStunServerConfig(
        StunEndpointTopology topology,
        String software,
        boolean legacySingleIpOtherAddress) {
    public static final String DEFAULT_SOFTWARE = "shuai-tunnel-rfc5780-stun";

    public StandaloneStunServerConfig {
        Objects.requireNonNull(topology, "topology");
        software = software == null || software.isBlank() ? DEFAULT_SOFTWARE : software.trim();
    }

    public static StandaloneStunServerConfig fromEnvironment(Map<String, String> environment) {
        Map<String, String> env = environment == null ? Map.of() : environment;
        int primaryPort = port(env, "STUN_PRIMARY_PORT", 3478, false);
        int alternatePort = port(env, "STUN_ALTERNATE_PORT", 3479, true);
        if (alternatePort == primaryPort) {
            throw new IllegalArgumentException("STUN_ALTERNATE_PORT must differ from STUN_PRIMARY_PORT");
        }

        InetAddress primaryBind = address(
                "STUN_PRIMARY_BIND_ADDRESS",
                value(env, "STUN_PRIMARY_BIND_ADDRESS", "0.0.0.0"));
        String primaryPublicText = value(env, "STUN_PRIMARY_PUBLIC_ADDRESS", "");
        if (primaryPublicText.isBlank()) {
            if (primaryBind.isAnyLocalAddress()) {
                throw new IllegalArgumentException(
                        "STUN_PRIMARY_PUBLIC_ADDRESS is required when STUN_PRIMARY_BIND_ADDRESS is wildcard");
            }
            primaryPublicText = primaryBind.getHostAddress();
        }
        InetAddress primaryPublic = address("STUN_PRIMARY_PUBLIC_ADDRESS", primaryPublicText);

        String alternateBindText = value(env, "STUN_ALTERNATE_BIND_ADDRESS", "");
        String alternatePublicText = value(env, "STUN_ALTERNATE_PUBLIC_ADDRESS", "");
        boolean alternateConfigured = !alternateBindText.isBlank() || !alternatePublicText.isBlank();
        if (alternateConfigured && (alternateBindText.isBlank() || alternatePublicText.isBlank())) {
            throw new IllegalArgumentException(
                    "STUN_ALTERNATE_BIND_ADDRESS and STUN_ALTERNATE_PUBLIC_ADDRESS must be configured together");
        }

        StunEndpointTopology topology;
        if (alternateConfigured) {
            if (alternatePort <= 0) {
                throw new IllegalArgumentException(
                        "STUN_ALTERNATE_PORT must be enabled for RFC 5780 four-endpoint mode");
            }
            InetAddress alternateBind = address("STUN_ALTERNATE_BIND_ADDRESS", alternateBindText);
            InetAddress alternatePublic = address("STUN_ALTERNATE_PUBLIC_ADDRESS", alternatePublicText);
            topology = StunEndpointTopology.rfc5780(
                    endpoint(StunEndpointTopology.PRIMARY, primaryBind, primaryPublic, primaryPort),
                    endpoint(StunEndpointTopology.PRIMARY_ALTERNATE_PORT,
                            primaryBind, primaryPublic, alternatePort),
                    endpoint(StunEndpointTopology.ALTERNATE_PRIMARY_PORT,
                            alternateBind, alternatePublic, primaryPort),
                    endpoint(StunEndpointTopology.ALTERNATE,
                            alternateBind, alternatePublic, alternatePort));
        } else {
            StunEndpointTopology.Endpoint alternateEndpoint = alternatePort <= 0
                    ? null
                    : endpoint(StunEndpointTopology.PRIMARY_ALTERNATE_PORT,
                    primaryBind, primaryPublic, alternatePort);
            topology = StunEndpointTopology.basic(
                    endpoint(StunEndpointTopology.PRIMARY, primaryBind, primaryPublic, primaryPort),
                    alternateEndpoint);
        }

        return new StandaloneStunServerConfig(
                topology,
                value(env, "STUN_SOFTWARE", DEFAULT_SOFTWARE),
                bool(env, "STUN_LEGACY_SINGLE_IP_OTHER_ADDRESS", false));
    }

    public String describe() {
        String endpoints = topology.endpoints().stream()
                .map(endpoint -> endpoint.id()
                        + "[bind=" + endpoint.bindAddress()
                        + ", advertised=" + endpoint.advertisedAddress() + "]")
                .collect(Collectors.joining(", "));
        return "mode=" + (topology.supportsRfc5780() ? "rfc5780" : "basic")
                + ", software=" + software
                + ", endpoints=" + endpoints;
    }

    private static StunEndpointTopology.Endpoint endpoint(
            StunEndpointTopology.EndpointId id,
            InetAddress bindAddress,
            InetAddress advertisedAddress,
            int port) {
        return new StunEndpointTopology.Endpoint(
                id,
                new InetSocketAddress(bindAddress, port),
                new InetSocketAddress(advertisedAddress, port));
    }

    private static InetAddress address(String name, String value) {
        try {
            return InetAddress.getByName(value.trim());
        } catch (Exception e) {
            throw new IllegalArgumentException(name + " is not a resolvable address: " + value, e);
        }
    }

    private static int port(
            Map<String, String> environment,
            String name,
            int fallback,
            boolean allowDisabled) {
        String raw = value(environment, name, Integer.toString(fallback));
        try {
            int parsed = Integer.parseInt(raw);
            int minimum = allowDisabled ? 0 : 1;
            if (parsed < minimum || parsed > 65_535) {
                throw new IllegalArgumentException(
                        name + " must be between " + minimum + " and 65535");
            }
            return parsed;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(name + " must be an integer: " + raw, e);
        }
    }

    private static boolean bool(
            Map<String, String> environment,
            String name,
            boolean fallback) {
        String raw = value(environment, name, Boolean.toString(fallback)).toLowerCase();
        return switch (raw) {
            case "1", "true", "yes", "on" -> true;
            case "0", "false", "no", "off" -> false;
            default -> throw new IllegalArgumentException(name + " must be true or false: " + raw);
        };
    }

    private static String value(Map<String, String> environment, String name, String fallback) {
        String value = environment.get(name);
        return value == null || value.isBlank() ? fallback : value.trim();
    }
}
