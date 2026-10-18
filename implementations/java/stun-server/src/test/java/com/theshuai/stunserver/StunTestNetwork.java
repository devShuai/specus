package com.theshuai.stunserver;

import java.io.IOException;
import java.net.DatagramSocket;
import java.util.List;

/** Test-owned sockets only. No retries or relaxed production bind rules. */
final class StunTestNetwork implements AutoCloseable {
    @FunctionalInterface
    interface ClientFactory {
        DatagramSocket open() throws IOException;
    }

    private final List<StandaloneStunServer> servers;
    private DatagramSocket client;

    private StunTestNetwork(List<StandaloneStunServer> servers) {
        this.servers = List.copyOf(servers);
    }

    static StunTestNetwork start(List<StandaloneStunServer> servers, ClientFactory factory)
            throws IOException {
        StunTestNetwork network = new StunTestNetwork(servers);
        try {
            // Reserve every planned endpoint first. An otherwise unrelated test
            // client binding port 0 must not take one of those probed ports.
            for (StandaloneStunServer server : network.servers) {
                server.start();
            }
            network.client = factory.open();
            return network;
        } catch (IOException | RuntimeException | Error failure) {
            network.close();
            throw failure;
        }
    }

    DatagramSocket client() {
        return client;
    }

    @Override
    public void close() {
        if (client != null) client.close();
        for (int i = servers.size() - 1; i >= 0; i--) servers.get(i).close();
    }
}
