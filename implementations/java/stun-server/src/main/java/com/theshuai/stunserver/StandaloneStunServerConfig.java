package com.theshuai.stunserver;

import com.theshuai.common.stun.StunEndpointTopology;
import com.theshuai.common.stun.StunMessage;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

public record StandaloneStunServerConfig(
        StunEndpointTopology topology,
        String software,
        boolean legacySingleIpOtherAddress,
        StandaloneStunProtectionConfig protection,
        StandaloneStunMetricsConfig metrics,
        StandaloneStunDistributionConfig distribution) {
    public static final String DEFAULT_SOFTWARE = "shuai-tunnel-rfc5780-stun";

    public StandaloneStunServerConfig {
        Objects.requireNonNull(topology, "topology");
        software = software == null || software.isBlank() ? DEFAULT_SOFTWARE : software.trim();
        protection = protection == null
                ? StandaloneStunProtectionConfig.defaults()
                : protection;
        metrics = metrics == null
                ? StandaloneStunMetricsConfig.disabled()
                : metrics;
        distribution = distribution == null
                ? StandaloneStunDistributionConfig.disabled()
                : distribution;
        if (distribution.enabled()) {
            if (!topology.supportsRfc5780()) {
                throw new IllegalArgumentException(
                        "distributed mode requires an RFC 5780 topology");
            }
            int controlPort = distribution.controlBindAddress().getPort();
            int peerControlPort = distribution.peerControlAddress().getPort();
            boolean portCollision = topology.endpoints().stream()
                    .mapToInt(endpoint -> endpoint.bindAddress().getPort())
                    .anyMatch(port -> port == controlPort || port == peerControlPort);
            if (portCollision) {
                throw new IllegalArgumentException(
                        "distributed control ports must differ from STUN endpoint ports");
            }
        }
    }

    public StandaloneStunServerConfig(
            StunEndpointTopology topology,
            String software,
            boolean legacySingleIpOtherAddress) {
        this(
                topology,
                software,
                legacySingleIpOtherAddress,
                StandaloneStunProtectionConfig.defaults(),
                StandaloneStunMetricsConfig.disabled(),
                StandaloneStunDistributionConfig.disabled());
    }

    public StandaloneStunServerConfig(
            StunEndpointTopology topology,
            String software,
            boolean legacySingleIpOtherAddress,
            StandaloneStunProtectionConfig protection,
            StandaloneStunMetricsConfig metrics) {
        this(
                topology,
                software,
                legacySingleIpOtherAddress,
                protection,
                metrics,
                StandaloneStunDistributionConfig.disabled());
    }

    public static StandaloneStunServerConfig fromEnvironment(Map<String, String> environment) {
        Map<String, String> env = environment == null ? Map.of() : environment;
        int primaryPort = port(env, "STUN_PRIMARY_PORT", 3478, false);
        int alternatePort = port(env, "STUN_ALTERNATE_PORT", 3479, true);
        if (alternatePort == primaryPort) {
            throw new IllegalArgumentException("STUN_ALTERNATE_PORT must differ from STUN_PRIMARY_PORT");
        }

        boolean distributedEnabled = bool(env, "STUN_DISTRIBUTED_ENABLED", false);
        StunEndpointTopology topology;
        StandaloneStunDistributionConfig distribution =
                StandaloneStunDistributionConfig.disabled();
        if (distributedEnabled) {
            if (alternatePort <= 0) {
                throw new IllegalArgumentException(
                        "STUN_ALTERNATE_PORT must be enabled in distributed RFC 5780 mode");
            }
            InetAddress stunBind = address(
                    "STUN_DISTRIBUTED_STUN_BIND_ADDRESS",
                    value(
                            env,
                            "STUN_DISTRIBUTED_STUN_BIND_ADDRESS",
                            value(env, "STUN_PRIMARY_BIND_ADDRESS", "0.0.0.0")));
            String primaryPublicText = value(env, "STUN_PRIMARY_PUBLIC_ADDRESS", "");
            String alternatePublicText = value(env, "STUN_ALTERNATE_PUBLIC_ADDRESS", "");
            if (primaryPublicText.isBlank() || alternatePublicText.isBlank()) {
                throw new IllegalArgumentException(
                        "distributed RFC 5780 mode requires both public addresses");
            }
            InetAddress primaryPublic =
                    address("STUN_PRIMARY_PUBLIC_ADDRESS", primaryPublicText);
            InetAddress alternatePublic = address("STUN_ALTERNATE_PUBLIC_ADDRESS", alternatePublicText);
            topology = StunEndpointTopology.distributedRfc5780(
                    endpoint(StunEndpointTopology.PRIMARY, stunBind, primaryPublic, primaryPort),
                    endpoint(StunEndpointTopology.PRIMARY_ALTERNATE_PORT,
                            stunBind, primaryPublic, alternatePort),
                    endpoint(StunEndpointTopology.ALTERNATE_PRIMARY_PORT,
                            stunBind, alternatePublic, primaryPort),
                    endpoint(StunEndpointTopology.ALTERNATE,
                            stunBind, alternatePublic, alternatePort));

            StunEndpointTopology.AddressSlot localSlot = addressSlot(
                    env,
                    "STUN_DISTRIBUTED_LOCAL_ADDRESS_SLOT");
            int controlPort = port(
                    env,
                    "STUN_DISTRIBUTED_CONTROL_PORT",
                    3480,
                    false);
            int peerControlPort = port(
                    env,
                    "STUN_DISTRIBUTED_PEER_CONTROL_PORT",
                    controlPort,
                    false);
            InetAddress controlBind = address(
                    "STUN_DISTRIBUTED_CONTROL_BIND_ADDRESS",
                    required(env, "STUN_DISTRIBUTED_CONTROL_BIND_ADDRESS"));
            InetAddress peerControl = address(
                    "STUN_DISTRIBUTED_PEER_CONTROL_ADDRESS",
                    required(env, "STUN_DISTRIBUTED_PEER_CONTROL_ADDRESS"));
            distribution = new StandaloneStunDistributionConfig(
                    true,
                    localSlot,
                    new InetSocketAddress(controlBind, controlPort),
                    new InetSocketAddress(peerControl, peerControlPort),
                    base64Secret(env, "STUN_DISTRIBUTED_SHARED_SECRET"),
                    integer(env, "STUN_DISTRIBUTED_MAX_CLOCK_SKEW_SECONDS", 30, 1, 300),
                    integer(env, "STUN_DISTRIBUTED_REPLAY_CACHE_SIZE", 65_536, 1, 1_000_000),
                    integer(env, "STUN_DISTRIBUTED_MAX_FORWARD_PACKET_BYTES", 4_096, 512, 65_507),
                    integer(env, "STUN_DISTRIBUTED_FORWARD_RATE_PER_SECOND", 10_000, 1, 10_000_000),
                    integer(env, "STUN_DISTRIBUTED_FORWARD_BURST", 20_000, 1, 20_000_000));
        } else {
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
            boolean alternateConfigured =
                    !alternateBindText.isBlank() || !alternatePublicText.isBlank();
            if (alternateConfigured
                    && (alternateBindText.isBlank() || alternatePublicText.isBlank())) {
                throw new IllegalArgumentException(
                        "STUN_ALTERNATE_BIND_ADDRESS and STUN_ALTERNATE_PUBLIC_ADDRESS must be configured together");
            }

            if (alternateConfigured) {
                if (alternatePort <= 0) {
                    throw new IllegalArgumentException(
                            "STUN_ALTERNATE_PORT must be enabled for RFC 5780 four-endpoint mode");
                }
                InetAddress alternateBind =
                        address("STUN_ALTERNATE_BIND_ADDRESS", alternateBindText);
                InetAddress alternatePublic =
                        address("STUN_ALTERNATE_PUBLIC_ADDRESS", alternatePublicText);
                topology = StunEndpointTopology.rfc5780(
                        endpoint(StunEndpointTopology.PRIMARY,
                                primaryBind, primaryPublic, primaryPort),
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
                        endpoint(StunEndpointTopology.PRIMARY,
                                primaryBind, primaryPublic, primaryPort),
                        alternateEndpoint);
            }
        }

        return new StandaloneStunServerConfig(
                topology,
                value(env, "STUN_SOFTWARE", DEFAULT_SOFTWARE),
                bool(env, "STUN_LEGACY_SINGLE_IP_OTHER_ADDRESS", false),
                new StandaloneStunProtectionConfig(
                        integer(env, "STUN_RATE_LIMIT_PER_SECOND", 100, 1, 1_000_000),
                        integer(env, "STUN_RATE_LIMIT_BURST", 200, 1, 2_000_000),
                        integer(env, "STUN_GLOBAL_RATE_LIMIT_PER_SECOND", 10_000, 1, 10_000_000),
                        integer(env, "STUN_GLOBAL_RATE_LIMIT_BURST", 20_000, 1, 20_000_000),
                        integer(env, "STUN_MAX_TRACKED_SOURCES", 65_536, 1, 1_000_000),
                        integer(env, "STUN_SOURCE_IDLE_SECONDS", 300, 1, 86_400),
                        integer(env, "STUN_MAX_PACKET_BYTES", 65_507, StunMessage.HEADER_BYTES, 65_507),
                        integer(env, "STUN_MAX_PADDING_RESPONSE_BYTES", 1_472, 0, 65_503)),
                new StandaloneStunMetricsConfig(
                        address(
                                "STUN_METRICS_BIND_ADDRESS",
                                value(env, "STUN_METRICS_BIND_ADDRESS", "127.0.0.1")),
                        port(env, "STUN_METRICS_PORT", 9_108, true)),
                distribution);
    }

    public List<StunEndpointTopology.Endpoint> localEndpoints() {
        if (!distribution.enabled()) {
            return List.copyOf(topology.endpoints());
        }
        return topology.endpoints().stream()
                .filter(endpoint -> distribution.isLocal(endpoint.id()))
                .toList();
    }

    public String describe() {
        String endpoints = topology.endpoints().stream()
                .map(endpoint -> endpoint.id()
                        + "[bind=" + endpoint.bindAddress()
                        + ", advertised=" + endpoint.advertisedAddress() + "]")
                .collect(Collectors.joining(", "));
        String mode = distribution.enabled()
                ? "distributed-rfc5780"
                : topology.supportsRfc5780() ? "rfc5780" : "basic";
        return "mode=" + mode
                + ", software=" + software
                + ", endpoints=" + endpoints
                + ", protection=" + protection.describe()
                + ", metrics=" + metrics.describe()
                + ", distribution=" + distribution.describe();
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

    private static StunEndpointTopology.AddressSlot addressSlot(
            Map<String, String> environment,
            String name) {
        String raw = required(environment, name).toLowerCase();
        return switch (raw) {
            case "primary", "a1" -> StunEndpointTopology.AddressSlot.PRIMARY;
            case "alternate", "a2" -> StunEndpointTopology.AddressSlot.ALTERNATE;
            default -> throw new IllegalArgumentException(
                    name + " must be primary or alternate: " + raw);
        };
    }

    private static byte[] base64Secret(Map<String, String> environment, String name) {
        String raw = required(environment, name);
        try {
            return Base64.getDecoder().decode(raw);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(name + " must be valid base64", e);
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

    private static int integer(
            Map<String, String> environment,
            String name,
            int fallback,
            int minimum,
            int maximum) {
        String raw = value(environment, name, Integer.toString(fallback));
        try {
            int parsed = Integer.parseInt(raw);
            if (parsed < minimum || parsed > maximum) {
                throw new IllegalArgumentException(
                        name + " must be between " + minimum + " and " + maximum);
            }
            return parsed;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(name + " must be an integer: " + raw, e);
        }
    }

    private static String value(Map<String, String> environment, String name, String fallback) {
        String value = environment.get(name);
        return value == null || value.isBlank() ? fallback : value.trim();
    }

    private static String required(Map<String, String> environment, String name) {
        String result = value(environment, name, "");
        if (result.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
        return result;
    }
}
