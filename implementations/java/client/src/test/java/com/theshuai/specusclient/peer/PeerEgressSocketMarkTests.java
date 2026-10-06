package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.jna.LastErrorException;
import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.ptr.IntByReference;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.StandardProtocolFamily;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.DatagramChannel;
import java.nio.channels.NetworkChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import org.junit.jupiter.api.Test;

/**
 * The Linux side of the egress socket: marked with {@code SO_MARK 0x5350} rather than bound, and
 * best-effort, as the Go and .NET egresses do it.
 *
 * <p>The option, the choice of binder per platform and the dialer's use of it are checked
 * everywhere. The real-socket test returns early everywhere but Linux; there it reads the mark back
 * when the process may set one, and otherwise shows the refused mark leaves the connect alone.
 */
class PeerEgressSocketMarkTests {

    /** Capability bits, from linux/capability.h. */
    private static final int CAP_NET_ADMIN = 12;
    private static final int CAP_NET_RAW = 13;

    private static boolean linux() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("linux");
    }

    interface LibC extends Library {
        int getsockopt(int fd, int level, int name, byte[] value, IntByReference length) throws LastErrorException;
    }

    /** Reads the mark back, with the option spelled out here rather than taken from the code under test. */
    private static int mark(NetworkChannel channel) throws IOException {
        int handle = PeerEgressSocketHandles.of(channel);
        byte[] value = new byte[4];
        IntByReference length = new IntByReference(value.length);
        // SOL_SOCKET, SO_MARK.
        Native.load("c", LibC.class).getsockopt(handle, 1, 36, value, length);
        return ByteBuffer.wrap(value).order(ByteOrder.nativeOrder()).getInt();
    }

    /** This process's effective capabilities, from the CapEff line of /proc/self/status. */
    private static long effectiveCapabilities() throws IOException {
        for (String line : Files.readAllLines(Path.of("/proc/self/status"))) {
            if (line.startsWith("CapEff:")) {
                return Long.parseUnsignedLong(line.substring("CapEff:".length()).trim(), 16);
            }
        }
        throw new IOException("no CapEff in /proc/self/status");
    }

    /** The mark the other two runtimes set, at the level and name Linux gives it, in host order. */
    @Test
    void theLinuxMarkIsTheOneGoAndDotNetSet() {
        assertEquals(1, PeerEgressSocketBinding.LINUX_SOL_SOCKET, "SOL_SOCKET");
        assertEquals(36, PeerEgressSocketBinding.LINUX_SO_MARK, "SO_MARK");
        assertEquals(0x5350, PeerEgressSocketBinding.LINUX_EGRESS_SOCKET_MARK, "mark");
        boolean little = ByteOrder.nativeOrder() == ByteOrder.LITTLE_ENDIAN;
        assertEquals(little ? "50530000" : "00005350",
                HexFormat.of().formatHex(PeerEgressSocketBinding.linuxSocketMarkOption(0x5350)), "SO_MARK 0x5350");
        assertEquals(little ? "78563412" : "12345678",
                HexFormat.of().formatHex(PeerEgressSocketBinding.linuxSocketMarkOption(0x12345678)),
                "SO_MARK 0x12345678");
    }

    /** Windows and macOS bind and do not mark; Linux marks and does not bind; anything else does neither. */
    @Test
    void eachPlatformGetsItsOwnOption() {
        for (String windows : List.of("Windows 11", "Windows Server 2022")) {
            PeerEgressSocketBinder binder = PeerEgressSocketBinder.forPlatform(windows, () -> "");
            assertTrue(binder.binds(), windows + " binds");
            assertFalse(binder.marks(), windows + " marks");
        }
        PeerEgressSocketBinder macos = PeerEgressSocketBinder.forPlatform("Mac OS X", () -> "");
        assertTrue(macos.binds(), "macOS binds");
        assertFalse(macos.marks(), "macOS marks");
        PeerEgressSocketBinder linux = PeerEgressSocketBinder.forPlatform("Linux", () -> "");
        assertTrue(linux.marks(), "Linux marks");
        assertFalse(linux.binds(), "Linux binds");
        for (String other : List.of("FreeBSD", "SunOS", "")) {
            PeerEgressSocketBinder binder = PeerEgressSocketBinder.forPlatform(other, () -> "");
            assertFalse(binder.binds(), "'" + other + "' binds");
            assertFalse(binder.marks(), "'" + other + "' marks");
        }
        assertFalse(PeerEgressSocketBinder.none().binds(), "none binds");
        assertFalse(PeerEgressSocketBinder.none().marks(), "none marks");
    }

    /**
     * The dialer hands the binder both protocols' sockets, and the mark is set before the socket
     * connects -- a mark set afterwards would miss the route lookup it exists to steer.
     */
    @Test
    void theDialerMarksBothProtocolsBeforeConnecting() throws IOException {
        List<String> marked = new ArrayList<>();
        PeerEgressSocketBinder recording = new PeerEgressSocketBinder(() -> "", null, name -> "", null,
                channel -> {
                    boolean connected = channel instanceof SocketChannel stream
                            ? stream.isConnected()
                            : ((DatagramChannel) channel).isConnected();
                    marked.add((channel instanceof SocketChannel ? "tcp" : "udp")
                            + (connected ? " after connect" : " before connect"));
                });
        try (ServerSocket server = new ServerSocket()) {
            server.bind(new InetSocketAddress("127.0.0.1", 0));
            PeerEgressSocketDialer dialer = new PeerEgressSocketDialer(recording);
            dialer.dial("tcp", "127.0.0.1", server.getLocalPort(), 2000).close();
            dialer.dial("udp", "127.0.0.1", server.getLocalPort(), 2000).close();
        }
        assertEquals(List.of("tcp before connect", "udp before connect"), marked);
    }

    /**
     * On Linux, a dial to 127.0.0.1 through the real binder carries the mark when this process may
     * set one, and connects regardless when it may not.
     *
     * <p>Setting a mark takes CAP_NET_ADMIN. Newer kernels accept CAP_NET_RAW as well and older ones
     * do not, so with that capability alone either outcome is right. With neither -- an ordinary user,
     * as on CI -- setsockopt is refused, the mark reads back as zero, and the connect has to have
     * gone ahead anyway: that is the half that shows the failure is ignored.
     */
    @Test
    void onLinuxADialIsMarkedWhenPermittedAndConnectsEitherWay() throws IOException {
        if (!linux()) {
            return;
        }
        long capabilities = effectiveCapabilities();
        boolean netAdmin = (capabilities & (1L << CAP_NET_ADMIN)) != 0;
        boolean netRaw = (capabilities & (1L << CAP_NET_RAW)) != 0;
        PeerEgressSocketBinder binder = PeerEgressSocketBinder.forPlatform(() -> "");
        assertTrue(binder.marks(), "the Linux binder does not mark");
        try (ServerSocket server = new ServerSocket()) {
            server.bind(new InetSocketAddress("127.0.0.1", 0));
            InetSocketAddress target = new InetSocketAddress("127.0.0.1", server.getLocalPort());
            try (SocketChannel channel = SocketChannel.open(StandardProtocolFamily.INET)) {
                binder.bind(channel, target);
                channel.socket().connect(target, 2000);
                assertTrue(channel.isConnected(), "tcp did not connect");
                assertMark(netAdmin, netRaw, mark(channel), "tcp");
            }
            try (DatagramChannel channel = DatagramChannel.open(StandardProtocolFamily.INET)) {
                binder.bind(channel, target);
                channel.connect(target);
                assertTrue(channel.isConnected(), "udp did not connect");
                assertMark(netAdmin, netRaw, mark(channel), "udp");
            }
            // And through the dialer, the path the egress takes.
            PeerEgressSocketDialer dialer = new PeerEgressSocketDialer(binder);
            dialer.dial("tcp", "127.0.0.1", server.getLocalPort(), 2000).close();
            dialer.dial("udp", "127.0.0.1", server.getLocalPort(), 2000).close();
        }
    }

    private static void assertMark(boolean netAdmin, boolean netRaw, int mark, String protocol) {
        if (netAdmin) {
            assertEquals(0x5350, mark, protocol + ": the process has CAP_NET_ADMIN but the socket is not marked");
        } else if (!netRaw) {
            assertEquals(0, mark, protocol + ": the process may not set a mark, yet the socket carries one");
        }
    }
}
