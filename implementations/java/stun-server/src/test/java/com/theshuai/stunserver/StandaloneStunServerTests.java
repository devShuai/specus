package com.theshuai.stunserver;

import com.theshuai.common.stun.StunEndpointTopology;
import com.theshuai.common.stun.StunMessage;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class StandaloneStunServerTests {
    @Test
    void sendsChangeIpAndPortResponseFromTheAlternateSocket() throws Exception {
        InetAddress primary = InetAddress.getByName("127.0.0.1");
        InetAddress alternate = InetAddress.getByName("127.0.0.2");
        Assumptions.assumeTrue(canBind(alternate), "alternate loopback address is unavailable");
        int primaryPort = freePortOnBoth(primary, alternate);
        int alternatePort = freePortOnBoth(primary, alternate);
        while (alternatePort == primaryPort) {
            alternatePort = freePortOnBoth(primary, alternate);
        }

        StunEndpointTopology topology = StunEndpointTopology.rfc5780(
                endpoint(StunEndpointTopology.PRIMARY, primary, primaryPort),
                endpoint(StunEndpointTopology.PRIMARY_ALTERNATE_PORT, primary, alternatePort),
                endpoint(StunEndpointTopology.ALTERNATE_PRIMARY_PORT, alternate, primaryPort),
                endpoint(StunEndpointTopology.ALTERNATE, alternate, alternatePort));
        StandaloneStunServerConfig config =
                new StandaloneStunServerConfig(topology, "integration-test", false);

        try (StandaloneStunServer server = new StandaloneStunServer(config);
             DatagramSocket client = new DatagramSocket(new InetSocketAddress(primary, 0))) {
            server.start();
            client.setSoTimeout(2_000);
            StunMessage request = StunMessage.of(
                    StunMessage.BINDING_REQUEST,
                    StunMessage.newTransactionId(),
                    StunMessage.changeRequest(true, true));
            byte[] bytes = request.toBytes();
            client.send(new DatagramPacket(
                    bytes,
                    bytes.length,
                    new InetSocketAddress(primary, primaryPort)));

            DatagramPacket responsePacket = new DatagramPacket(new byte[2_048], 2_048);
            client.receive(responsePacket);
            StunMessage response = StunMessage.parse(
                    responsePacket.getData(),
                    responsePacket.getOffset(),
                    responsePacket.getLength());

            assertNotNull(response);
            assertEquals(StunMessage.BINDING_SUCCESS, response.type());
            assertEquals(alternate, responsePacket.getAddress());
            assertEquals(alternatePort, responsePacket.getPort());
            assertEquals(
                    new InetSocketAddress(alternate, alternatePort),
                    response.responseOrigin().orElseThrow());
            assertEquals(
                    new InetSocketAddress(alternate, alternatePort),
                    response.otherAddress().orElseThrow());
        } catch (SocketTimeoutException e) {
            throw new AssertionError("STUN response was not received", e);
        }
    }

    @Test
    void forwardsChangedIpResponsesAcrossTwoDistributedNodes() throws Exception {
        InetAddress primary = InetAddress.getByName("127.0.0.1");
        InetAddress alternate = InetAddress.getByName("127.0.0.2");
        Assumptions.assumeTrue(canBind(alternate), "alternate loopback address is unavailable");
        int primaryPort = freePortOnBoth(primary, alternate);
        int alternatePort = freePortOnBoth(primary, alternate);
        while (alternatePort == primaryPort) {
            alternatePort = freePortOnBoth(primary, alternate);
        }
        int controlPort = freePortOnBoth(primary, alternate);
        while (controlPort == primaryPort || controlPort == alternatePort) {
            controlPort = freePortOnBoth(primary, alternate);
        }
        byte[] secret =
                "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.US_ASCII);

        StandaloneStunServerConfig primaryConfig = distributedConfig(
                primary,
                primary,
                alternate,
                primaryPort,
                alternatePort,
                controlPort,
                StunEndpointTopology.AddressSlot.PRIMARY,
                primary,
                alternate,
                secret);
        StandaloneStunServerConfig alternateConfig = distributedConfig(
                alternate,
                primary,
                alternate,
                primaryPort,
                alternatePort,
                controlPort,
                StunEndpointTopology.AddressSlot.ALTERNATE,
                alternate,
                primary,
                secret);

        try (StandaloneStunServer primaryServer = new StandaloneStunServer(primaryConfig);
             StandaloneStunServer alternateServer = new StandaloneStunServer(alternateConfig);
             DatagramSocket client =
                     new DatagramSocket(new InetSocketAddress(primary, 0))) {
            alternateServer.start();
            primaryServer.start();
            client.setSoTimeout(2_000);

            StunMessage primaryResponse = exchange(
                    client,
                    new InetSocketAddress(primary, primaryPort),
                    true,
                    true);
            assertEquals(
                    new InetSocketAddress(alternate, alternatePort),
                    primaryResponse.responseOrigin().orElseThrow());
            assertEquals(
                    new InetSocketAddress(alternate, alternatePort),
                    primaryResponse.otherAddress().orElseThrow());

            StunMessage alternateResponse = exchange(
                    client,
                    new InetSocketAddress(alternate, primaryPort),
                    true,
                    true);
            assertEquals(
                    new InetSocketAddress(primary, alternatePort),
                    alternateResponse.responseOrigin().orElseThrow());
            assertEquals(
                    new InetSocketAddress(primary, alternatePort),
                    alternateResponse.otherAddress().orElseThrow());
        } catch (SocketTimeoutException e) {
            throw new AssertionError("distributed STUN response was not received", e);
        }
    }

    private static StunMessage exchange(
            DatagramSocket client,
            InetSocketAddress destination,
            boolean changeIp,
            boolean changePort) throws Exception {
        StunMessage request = StunMessage.of(
                StunMessage.BINDING_REQUEST,
                StunMessage.newTransactionId(),
                StunMessage.changeRequest(changeIp, changePort));
        byte[] bytes = request.toBytes();
        client.send(new DatagramPacket(bytes, bytes.length, destination));

        DatagramPacket responsePacket = new DatagramPacket(new byte[2_048], 2_048);
        client.receive(responsePacket);
        StunMessage response = StunMessage.parse(
                responsePacket.getData(),
                responsePacket.getOffset(),
                responsePacket.getLength());
        assertNotNull(response);
        assertEquals(StunMessage.BINDING_SUCCESS, response.type());
        assertEquals(
                response.responseOrigin().orElseThrow().getAddress(),
                responsePacket.getAddress());
        assertEquals(
                response.responseOrigin().orElseThrow().getPort(),
                responsePacket.getPort());
        return response;
    }

    private static StandaloneStunServerConfig distributedConfig(
            InetAddress bindAddress,
            InetAddress primaryPublic,
            InetAddress alternatePublic,
            int primaryPort,
            int alternatePort,
            int controlPort,
            StunEndpointTopology.AddressSlot localSlot,
            InetAddress controlBind,
            InetAddress peerControl,
            byte[] secret) {
        StunEndpointTopology topology = StunEndpointTopology.distributedRfc5780(
                endpoint(StunEndpointTopology.PRIMARY,
                        bindAddress, primaryPublic, primaryPort),
                endpoint(StunEndpointTopology.PRIMARY_ALTERNATE_PORT,
                        bindAddress, primaryPublic, alternatePort),
                endpoint(StunEndpointTopology.ALTERNATE_PRIMARY_PORT,
                        bindAddress, alternatePublic, primaryPort),
                endpoint(StunEndpointTopology.ALTERNATE,
                        bindAddress, alternatePublic, alternatePort));
        StandaloneStunDistributionConfig distribution =
                new StandaloneStunDistributionConfig(
                        true,
                        localSlot,
                        new InetSocketAddress(controlBind, controlPort),
                        new InetSocketAddress(peerControl, controlPort),
                        new StandaloneStunDistributionConfig.ForwardKey(7, secret),
                        null,
                        30,
                        128,
                        4_096,
                        1_000,
                        2_000);
        return new StandaloneStunServerConfig(
                topology,
                "distributed-integration-test",
                false,
                StandaloneStunProtectionConfig.defaults(),
                StandaloneStunMetricsConfig.disabled(),
                distribution);
    }

    private static StunEndpointTopology.Endpoint endpoint(
            StunEndpointTopology.EndpointId id,
            InetAddress address,
            int port) {
        InetSocketAddress socketAddress = new InetSocketAddress(address, port);
        return new StunEndpointTopology.Endpoint(id, socketAddress, socketAddress);
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

    private static boolean canBind(InetAddress address) {
        try (DatagramSocket ignored = new DatagramSocket(new InetSocketAddress(address, 0))) {
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static int freePortOnBoth(InetAddress primary, InetAddress alternate) throws Exception {
        for (int attempt = 0; attempt < 32; attempt++) {
            try (DatagramSocket primarySocket =
                         new DatagramSocket(new InetSocketAddress(primary, 0))) {
                int port = primarySocket.getLocalPort();
                try (DatagramSocket ignored =
                             new DatagramSocket(new InetSocketAddress(alternate, port))) {
                    return port;
                } catch (Exception ignored) {
                    // Try another ephemeral port.
                }
            }
        }
        throw new IllegalStateException("cannot find a UDP port available on both loopback addresses");
    }
}
