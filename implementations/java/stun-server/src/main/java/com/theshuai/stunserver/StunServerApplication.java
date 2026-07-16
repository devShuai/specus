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

                Full RFC 5780 mode requires explicit A1/A2 bind addresses, two distinct
                advertised public IPs, and the same P1/P2 port pair on both addresses.
                """);
    }
}
