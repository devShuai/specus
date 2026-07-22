package com.theshuai.stunserver;

import java.util.Arrays;

public final class StunServerApplication {
    private StunServerApplication() {
    }

    public static void main(String[] args) {
        if (hasArgument(args, "--help") || hasArgument(args, "-h")) {
            printHelp();
            return;
        }
        try {
            rejectUnknownArguments(args);
            StandaloneStunServerConfig config =
                    StandaloneStunServerConfig.fromEnvironment(System.getenv());
            if (hasArgument(args, "--check-config")) {
                System.out.println("STUN configuration is valid: " + config.describe());
                return;
            }

            try (StandaloneStunServer server = new StandaloneStunServer(config)) {
                Runtime.getRuntime().addShutdownHook(
                        new Thread(server::close, "standalone-stun-shutdown"));
                server.start();
                server.await();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            System.err.println("STUN server failed: " + e.getMessage());
            System.exit(1);
        }
    }

    private static void rejectUnknownArguments(String[] args) {
        Arrays.stream(args == null ? new String[0] : args)
                .filter(argument -> !"--check-config".equals(argument))
                .findFirst()
                .ifPresent(argument -> {
                    throw new IllegalArgumentException("unknown argument: " + argument);
                });
    }

    private static boolean hasArgument(String[] args, String expected) {
        return args != null && Arrays.stream(args).anyMatch(expected::equals);
    }

    private static void printHelp() {
        System.out.println("""
                Shuai Tunnel standalone STUN server

                Usage:
                  java -jar stun-server.jar
                  java -jar stun-server.jar --check-config

                Environment:
                  STUN_PRIMARY_BIND_ADDRESS          Local A1 address (default 0.0.0.0)
                  STUN_PRIMARY_PUBLIC_ADDRESS        Advertised A1 address; required for wildcard bind
                  STUN_ALTERNATE_BIND_ADDRESS        Local A2 address; enables RFC 5780 with public A2
                  STUN_ALTERNATE_PUBLIC_ADDRESS      Advertised A2 address
                  STUN_PRIMARY_PORT                  P1 (default 3478)
                  STUN_ALTERNATE_PORT                P2 (default 3479; 0 disables it in basic mode)
                  STUN_SOFTWARE                      SOFTWARE attribute value
                  STUN_LEGACY_SINGLE_IP_OTHER_ADDRESS
                                                     Emit legacy single-IP alternate attributes
                  STUN_DISTRIBUTED_ENABLED           Split A1/A2 across two authenticated nodes
                  STUN_DISTRIBUTED_LOCAL_ADDRESS_SLOT
                                                     primary/A1 or alternate/A2
                  STUN_DISTRIBUTED_STUN_BIND_ADDRESS Local wildcard or interface address for P1/P2
                  STUN_DISTRIBUTED_CONTROL_BIND_ADDRESS
                                                     Private control-channel bind IP
                  STUN_DISTRIBUTED_CONTROL_PORT      Private UDP control port (default 3480)
                  STUN_DISTRIBUTED_PEER_CONTROL_ADDRESS
                                                     Peer private control-channel IP
                  STUN_DISTRIBUTED_PEER_CONTROL_PORT Peer control port (defaults to local port)
                  STUN_DISTRIBUTED_CURRENT_KEY_ID    Positive signing-key ID
                  STUN_DISTRIBUTED_CURRENT_SECRET    Base64 HMAC-SHA256 secret, at least 32 bytes
                  STUN_DISTRIBUTED_PREVIOUS_KEY_ID   Optional previous signing-key ID during rotation
                  STUN_DISTRIBUTED_PREVIOUS_SECRET   Optional previous Base64 secret during rotation
                  STUN_DISTRIBUTED_MAX_CLOCK_SKEW_SECONDS
                                                     Forward timestamp window (default 30)
                  STUN_DISTRIBUTED_REPLAY_WINDOW_SIZE Per-epoch sequence window (default 4096)
                  STUN_DISTRIBUTED_MAX_FORWARD_PACKET_BYTES
                                                     Private control datagram cap (default 4096)
                  STUN_DISTRIBUTED_FORWARD_RATE_PER_SECOND
                                                     Authenticated control rate (default 10000)
                  STUN_DISTRIBUTED_FORWARD_BURST     Control-channel burst (default 20000)
                  STUN_RATE_LIMIT_PER_SECOND         Per-source sustained request rate (default 100)
                  STUN_RATE_LIMIT_BURST              Per-source token burst (default 200)
                  STUN_GLOBAL_RATE_LIMIT_PER_SECOND  Global sustained request rate (default 10000)
                  STUN_GLOBAL_RATE_LIMIT_BURST       Global token burst (default 20000)
                  STUN_MAX_TRACKED_SOURCES           Bounded source token table (default 65536)
                  STUN_SOURCE_IDLE_SECONDS           Source token idle expiry (default 300)
                  STUN_MAX_PACKET_BYTES              Accepted UDP payload bytes (default 65507)
                  STUN_MAX_PADDING_RESPONSE_BYTES    Maximum returned PADDING value (default 1472)
                  STUN_METRICS_BIND_ADDRESS          Prometheus bind address (default 127.0.0.1)
                  STUN_METRICS_PORT                  Prometheus port (default 9108; 0 disables)

                Full RFC 5780 mode requires explicit A1/A2 bind addresses, two distinct
                advertised public IPs, and the same P1/P2 port pair on both addresses.
                Distributed mode keeps the same public topology while each node binds one
                address slot and forwards changed-IP responses over a private HMAC channel.
                """);
    }
}
