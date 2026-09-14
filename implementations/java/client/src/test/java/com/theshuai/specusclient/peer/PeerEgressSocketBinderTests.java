package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.jna.LastErrorException;
import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.ptr.IntByReference;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.StandardProtocolFamily;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.DatagramChannel;
import java.nio.channels.NetworkChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

/**
 * The egress socket binding, against real sockets and the real routing table.
 *
 * <p>No network is needed. 127.0.0.1 is reachable only through the loopback interface, and a socket
 * the stack holds to any other interface cannot reach it -- which is what turns "the option was set"
 * into "the option is doing something". The tests that touch the operating system return early
 * everywhere but Windows and macOS.
 */
class PeerEgressSocketBinderTests {

    private static String operatingSystem() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
    }

    private static boolean windows() {
        return operatingSystem().contains("win");
    }

    private static boolean macos() {
        String name = operatingSystem();
        return name.contains("mac") || name.contains("darwin");
    }

    interface WinSock extends Library {
        int getsockopt(long socket, int level, int name, byte[] value, IntByReference length)
                throws LastErrorException;
    }

    interface LibC extends Library {
        int getsockopt(int fd, int level, int name, byte[] value, IntByReference length) throws LastErrorException;
    }

    /**
     * Reads the binding back. On Windows it comes back in host order although it has to go in in
     * network order: bound to loopback, whose index is 1, getsockopt returns 01 00 00 00.
     */
    private static int boundInterface(NetworkChannel channel) throws IOException {
        int handle = PeerEgressSocketHandles.of(channel);
        byte[] value = new byte[4];
        IntByReference length = new IntByReference(value.length);
        if (windows()) {
            Native.load("ws2_32", WinSock.class).getsockopt(handle, PeerEgressSocketBinding.IPPROTO_IP,
                    PeerEgressSocketBinding.WINDOWS_IP_UNICAST_IF, value, length);
        } else {
            Native.load("c", LibC.class).getsockopt(handle, PeerEgressSocketBinding.IPPROTO_IP,
                    PeerEgressSocketBinding.MACOS_IP_BOUND_IF, value, length);
        }
        return ByteBuffer.wrap(value).order(ByteOrder.LITTLE_ENDIAN).getInt();
    }

    private static NetworkInterface loopback() throws IOException {
        for (NetworkInterface candidate : Collections.list(NetworkInterface.getNetworkInterfaces())) {
            if (candidate.isLoopback() && candidate.isUp()) {
                return candidate;
            }
        }
        fail("no loopback interface");
        return null;
    }

    /**
     * The loopback interface as the platform's table names it, for use as a tunnel name.
     *
     * <p>Java's own name for it on Windows is "lo", which is not an adapter alias; the alias is not
     * localised, so it can be spelled here.
     */
    private static String loopbackTunnelName() throws IOException {
        return windows() ? "Loopback Pseudo-Interface 1" : loopback().getName();
    }

    /** The handle is reachable in this JVM. Every platform: the build configuration is what is tested. */
    @Test
    void theSocketHandleIsReachable() throws IOException {
        try (SocketChannel channel = SocketChannel.open(StandardProtocolFamily.INET)) {
            assertTrue(PeerEgressSocketHandles.of(channel) >= 0, "a socket handle is never negative");
        }
    }

    /** A socket to 127.0.0.1 is bound to the loopback interface, and the socket says so. */
    @Test
    void aDialIsBoundToTheInterfaceItChose() throws IOException {
        if (!windows() && !macos()) {
            return;
        }
        int expected = loopback().getIndex();
        PeerEgressSocketBinder binder = PeerEgressSocketBinder.forPlatform(() -> "");
        try (ServerSocket server = new ServerSocket()) {
            server.bind(new InetSocketAddress("127.0.0.1", 0));
            InetSocketAddress target = new InetSocketAddress("127.0.0.1", server.getLocalPort());
            try (SocketChannel channel = SocketChannel.open(StandardProtocolFamily.INET)) {
                binder.bind(channel, target);
                channel.socket().connect(target, 2000);
                assertEquals(expected, boundInterface(channel), "tcp socket's interface");
            }
            try (DatagramChannel channel = DatagramChannel.open(StandardProtocolFamily.INET)) {
                binder.bind(channel, target);
                channel.connect(target);
                assertEquals(expected, boundInterface(channel), "udp socket's interface");
            }
        }
    }

    /**
     * When the tunnel's routes are the only ones leading to a destination, the dial is refused
     * rather than left unbound.
     *
     * <p>The tunnel is named by the loopback interface's real name, so this also proves the name
     * resolves to the key the table carries. The table is cut down to the loopback routes: in the
     * real one the default route covers 127.0.0.1 too.
     */
    @Test
    void aDialIsRefusedWhenOnlyTheTunnelLeadsThere() throws IOException {
        if (!windows() && !macos()) {
            return;
        }
        String name = loopbackTunnelName();
        PeerEgressSocketBinder binder = PeerEgressSocketBinder.forPlatform(() -> name);
        String key = binder.tunnelKey(name);
        assertFalse(key.isEmpty(), "the loopback interface " + name + " did not resolve to a table key");
        List<PeerEgressSocketBinding.Route> loopbackRoutes = new ArrayList<>();
        for (PeerEgressSocketBinding.Route route : binder.routes.read()) {
            if (route.iface().equals(key)) {
                loopbackRoutes.add(route);
            }
        }
        assertEquals(key, PeerEgressSocketBinding.select(loopbackRoutes, "", "127.0.0.1"),
                "the real table's loopback routes do not lead to 127.0.0.1");
        binder.routes = () -> loopbackRoutes;

        PeerEgressSocketDialer dialer = new PeerEgressSocketDialer(binder);
        try (ServerSocket server = new ServerSocket()) {
            server.bind(new InetSocketAddress("127.0.0.1", 0));
            for (String protocol : List.of("tcp", "udp")) {
                IOException refused = assertThrows(IOException.class,
                        () -> dialer.dial(protocol, "127.0.0.1", server.getLocalPort(), 2000).close());
                assertInstanceOf(PeerEgressSocketBinder.NoPhysicalRouteException.class, refused, protocol);
            }
        }
    }

    /**
     * The stack holds the socket to the interface it was bound to.
     *
     * <p>The binder is handed a table claiming 127.0.0.0/8 is behind a physical interface. An
     * unbound socket would reach 127.0.0.1 anyway; a bound one cannot. This is the test that fails
     * if the option is never set, and it goes through the dialer, so it also fails if the dialer
     * never asks the binder.
     */
    @Test
    void theSocketIsHeldToTheBoundInterface() throws IOException {
        if (!windows() && !macos()) {
            return;
        }
        PeerEgressSocketBinder real = PeerEgressSocketBinder.forPlatform(() -> "");
        String loopbackKey = real.tunnelKey(loopbackTunnelName());
        String physical = PeerEgressSocketBinding.select(real.routes.read(), loopbackKey, "192.0.2.1");
        assertNotNull(physical, "no default route outside loopback; this test needs working networking");

        PeerEgressSocketBinder lying = PeerEgressSocketBinder.forPlatform(() -> "");
        lying.routes = () -> List.of(new PeerEgressSocketBinding.Route("127.0.0.0/8", physical, 0, true));
        PeerEgressSocketDialer dialer = new PeerEgressSocketDialer(lying);
        try (ServerSocket server = new ServerSocket()) {
            server.bind(new InetSocketAddress("127.0.0.1", 0));
            for (String protocol : List.of("tcp", "udp")) {
                IOException failure = assertThrows(IOException.class,
                        () -> dialer.dial(protocol, "127.0.0.1", server.getLocalPort(), 2000).close(),
                        protocol + " reached 127.0.0.1 while bound to " + physical);
                assertFalse(failure instanceof PeerEgressSocketBinder.NoPhysicalRouteException,
                        protocol + " was refused before any socket existed, so nothing was tested");
            }
        }
    }

    /**
     * On Windows the native table readings agree with Get-NetRoute and Get-NetIPInterface, which is
     * what keeps the offsets honest on the machine running the tests.
     */
    @Test
    void onWindowsTheNativeTablesMatchGetNetRoute() throws Exception {
        if (!windows()) {
            return;
        }
        var forward = PeerEgressSocketBinding.parseWindowsForwardTable(
                PeerEgressSocketBinder.Windows.table(true, PeerEgressSocketBinding.WINDOWS_FORWARD_ROW_SIZE));
        var interfaces = PeerEgressSocketBinding.parseWindowsInterfaceTable(
                PeerEgressSocketBinder.Windows.table(false, PeerEgressSocketBinding.WINDOWS_INTERFACE_ROW_SIZE));
        assertNotNull(forward);
        assertNotNull(interfaces);

        List<String> native_ = new ArrayList<>();
        forward.forEach(row -> native_.add(row.interfaceIndex() + " " + row.prefix() + " " + row.metric()));
        List<String> cmdlet = new ArrayList<>();
        for (JsonNode row : powershell("ConvertTo-Json -Compress -InputObject @(Get-NetRoute -AddressFamily IPv4 "
                + "-PolicyStore ActiveStore -ErrorAction SilentlyContinue|Select-Object "
                + "InterfaceIndex,DestinationPrefix,RouteMetric)")) {
            cmdlet.add(row.path("InterfaceIndex").asLong() + " " + row.path("DestinationPrefix").asText() + " "
                    + row.path("RouteMetric").asLong());
        }
        Collections.sort(native_);
        Collections.sort(cmdlet);
        assertFalse(native_.isEmpty());
        assertEquals(cmdlet, native_, "routes");

        native_.clear();
        cmdlet.clear();
        interfaces.forEach(row -> native_.add(row.interfaceIndex() + " " + row.metric() + " " + row.connected()));
        for (JsonNode row : powershell("ConvertTo-Json -Compress -InputObject @(Get-NetIPInterface -AddressFamily IPv4 "
                + "-ErrorAction SilentlyContinue|Select-Object InterfaceIndex,InterfaceMetric,"
                + "@{n='Connected';e={[string]$_.ConnectionState -eq 'Connected'}})")) {
            cmdlet.add(row.path("InterfaceIndex").asLong() + " " + row.path("InterfaceMetric").asLong() + " "
                    + row.path("Connected").asBoolean());
        }
        Collections.sort(native_);
        Collections.sort(cmdlet);
        assertEquals(cmdlet, native_, "interfaces");
    }

    private static JsonNode powershell(String script) throws Exception {
        Process process = new ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
                .redirectError(ProcessBuilder.Redirect.DISCARD).start();
        String output;
        try (var out = process.getInputStream()) {
            output = new String(out.readAllBytes(), StandardCharsets.UTF_8);
        }
        assertTrue(process.waitFor(60, TimeUnit.SECONDS), "powershell did not finish");
        return new ObjectMapper().readTree(output);
    }
}
