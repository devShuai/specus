package com.theshuai.specusclient.peer;

import com.sun.jna.LastErrorException;
import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.LongByReference;
import com.sun.jna.ptr.PointerByReference;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.nio.channels.NetworkChannel;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import java.util.function.Supplier;
import lombok.extern.slf4j.Slf4j;

/**
 * Binds each egress socket to the interface {@link PeerEgressSocketBinding#select} chooses:
 * {@code IP_UNICAST_IF} on Windows, {@code IP_BOUND_IF} on macOS.
 *
 * <p>On Linux nothing is bound. The socket is marked with {@code SO_MARK 0x5350} instead, the mark
 * the Go and .NET egresses set, for a policy routing rule to steer to the physical interface
 * regardless of what the tunnel did to the main table. That one is best-effort; see {@link Linux}.
 */
@Slf4j
class PeerEgressSocketBinder {

    /** Reads the candidate routes. */
    interface RouteSource {
        List<PeerEgressSocketBinding.Route> read() throws IOException;
    }

    /** Sets the option binding a socket handle to an interface, as the table names it. */
    interface Applier {
        void apply(int handle, String iface) throws IOException;
    }

    /** Marks a socket before it connects. Best-effort: it never fails the dial. */
    interface Marker {
        void mark(NetworkChannel channel);
    }

    private final Supplier<String> tunnel;
    private final Function<String, String> tunnelKey;
    private final Applier applier;
    private final Marker marker;
    /** Replaceable so the real-socket tests can hand the stack a route it has to refuse. */
    RouteSource routes;

    PeerEgressSocketBinder(Supplier<String> tunnel, RouteSource routes, Function<String, String> tunnelKey,
            Applier applier, Marker marker) {
        this.tunnel = tunnel;
        this.routes = routes;
        this.tunnelKey = tunnelKey;
        this.applier = applier;
        this.marker = marker;
    }

    /** A binder that binds and marks nothing. */
    static PeerEgressSocketBinder none() {
        return new PeerEgressSocketBinder(() -> "", null, name -> "", null, null);
    }

    static PeerEgressSocketBinder forPlatform(Supplier<String> tunnel) {
        return forPlatform(System.getProperty("os.name", ""), tunnel);
    }

    /** The binder for the operating system named as {@code os.name} names it. */
    static PeerEgressSocketBinder forPlatform(String operatingSystem, Supplier<String> tunnel) {
        String os = operatingSystem.toLowerCase(Locale.ROOT);
        if (os.contains("win")) {
            return new PeerEgressSocketBinder(tunnel, Windows::routes, Windows::interfaceKey, Windows::apply, null);
        }
        if (os.contains("mac") || os.contains("darwin")) {
            Macos table = new Macos();
            return new PeerEgressSocketBinder(tunnel, table::routes, name -> name, Macos::apply, null);
        }
        if (os.contains("linux")) {
            return new PeerEgressSocketBinder(tunnel, null, name -> "", null, Linux::mark);
        }
        return none();
    }

    /** Whether sockets are bound to an interface: Windows and macOS. */
    boolean binds() {
        return applier != null;
    }

    /** Whether sockets are marked: Linux. */
    boolean marks() {
        return marker != null;
    }

    /** Turns a tunnel name into what the table's interface column holds, or "" when there is none. */
    String tunnelKey(String name) {
        return name == null || name.isEmpty() ? "" : tunnelKey.apply(name);
    }

    /**
     * Readies channel, before it connects, for target: marks it on Linux, binds it to the interface
     * for target on Windows and macOS.
     */
    void bind(NetworkChannel channel, InetSocketAddress target) throws IOException {
        if (marker != null) {
            marker.mark(channel);
        }
        if (applier == null || leftUnbound(target.getAddress())) {
            return;
        }
        String chosen = choose(target.getAddress().getHostAddress());
        applier.apply(PeerEgressSocketHandles.of(channel), chosen);
    }

    /**
     * Whether a socket to the target is dialled without an interface binding: one to an IPv6 target.
     *
     * <p>The binding keeps forwarded traffic off routes this node's own tunnel installed, and the
     * tunnel installs no IPv6 route: the mesh is IPv4, and IPv6 consumer rules are not in force
     * ({@code EGRESS_RULE_IPV6_UNSUPPORTED}). IP_UNICAST_IF and IP_BOUND_IF are IPv4 options besides.
     * The consumer's IPv6 data plane, which will route IPv6 into the tunnel, has to bring
     * IPV6_UNICAST_IF and IPV6_BOUND_IF with it. Java never hands back an IPv4-mapped address as an
     * {@link java.net.Inet6Address}, so every IPv4 target still goes through the choice. The Linux
     * mark is applied either way.
     */
    static boolean leftUnbound(java.net.InetAddress target) {
        return target instanceof java.net.Inet6Address;
    }

    String choose(String destination) throws IOException {
        List<PeerEgressSocketBinding.Route> candidates = routes.read();
        String key = tunnelKey(tunnel == null ? "" : tunnel.get());
        String chosen = PeerEgressSocketBinding.select(candidates, key, destination);
        if (chosen == null) {
            throw new NoPhysicalRouteException(destination);
        }
        return chosen;
    }

    /**
     * Nothing but the tunnel leads to the destination. The dial is refused rather than left unbound,
     * because an unbound socket is exactly the one that would follow the tunnel route.
     */
    static final class NoPhysicalRouteException extends IOException {
        NoPhysicalRouteException(String destination) {
            super("bind egress socket for " + destination + ": no route outside the tunnel");
        }
    }

    /**
     * Windows: the table read natively on every connect, because a Get-NetRoute query costs 419 ms
     * and these two calls cost microseconds and need no cache.
     */
    static final class Windows {
        private static final int AF_INET = 2;

        interface IpHelper extends Library {
            int GetIpForwardTable2(int family, PointerByReference table);

            int GetIpInterfaceTable(int family, PointerByReference table);

            void FreeMibTable(Pointer memory);

            int ConvertInterfaceAliasToLuid(WString alias, LongByReference luid);

            int ConvertInterfaceLuidToIndex(LongByReference luid, IntByReference index);
        }

        interface WinSock extends Library {
            int setsockopt(long socket, int level, int name, byte[] value, int length) throws LastErrorException;
        }

        /** Loaded on first use, so nothing is linked on a platform without these libraries. */
        private static final class Libraries {
            static final IpHelper IPHLPAPI = Native.load("iphlpapi", IpHelper.class);
            static final WinSock WS2_32 = Native.load("ws2_32", WinSock.class);
        }

        private Windows() {
        }

        static List<PeerEgressSocketBinding.Route> routes() throws IOException {
            var forward = PeerEgressSocketBinding.parseWindowsForwardTable(
                    table(true, PeerEgressSocketBinding.WINDOWS_FORWARD_ROW_SIZE));
            if (forward == null) {
                throw new IOException("GetIpForwardTable2 returned a table shorter than its count");
            }
            var interfaces = PeerEgressSocketBinding.parseWindowsInterfaceTable(
                    table(false, PeerEgressSocketBinding.WINDOWS_INTERFACE_ROW_SIZE));
            if (interfaces == null) {
                throw new IOException("GetIpInterfaceTable returned a table shorter than its count");
            }
            return PeerEgressSocketBinding.windowsRoutes(forward, interfaces);
        }

        /** Copies one IPv4 MIB table out of the memory the API allocated, then frees it. */
        static byte[] table(boolean forward, int rowSize) throws IOException {
            PointerByReference out = new PointerByReference();
            int status = forward
                    ? Libraries.IPHLPAPI.GetIpForwardTable2(AF_INET, out)
                    : Libraries.IPHLPAPI.GetIpInterfaceTable(AF_INET, out);
            if (status != 0) {
                throw new IOException((forward ? "GetIpForwardTable2" : "GetIpInterfaceTable")
                        + " failed with " + status);
            }
            Pointer memory = out.getValue();
            try {
                long count = memory.getInt(0) & 0xFFFFFFFFL;
                return memory.getByteArray(0,
                        Math.toIntExact(PeerEgressSocketBinding.WINDOWS_TABLE_HEADER + count * rowSize));
            } finally {
                Libraries.IPHLPAPI.FreeMibTable(memory);
            }
        }

        /** An adapter's name, as the Wintun adapter was created with it, resolved to its index. */
        static String interfaceKey(String name) {
            LongByReference luid = new LongByReference();
            if (Libraries.IPHLPAPI.ConvertInterfaceAliasToLuid(new WString(name), luid) != 0) {
                return "";
            }
            IntByReference index = new IntByReference();
            if (Libraries.IPHLPAPI.ConvertInterfaceLuidToIndex(luid, index) != 0) {
                return "";
            }
            return Long.toString(index.getValue() & 0xFFFFFFFFL);
        }

        static void apply(int handle, String iface) throws IOException {
            long index;
            try {
                index = Long.parseLong(iface);
            } catch (NumberFormatException notAnIndex) {
                throw new IOException("bind egress socket: interface " + iface + " is not an index");
            }
            byte[] option = PeerEgressSocketBinding.windowsUnicastInterfaceOption(index);
            try {
                Libraries.WS2_32.setsockopt(handle, PeerEgressSocketBinding.IPPROTO_IP,
                        PeerEgressSocketBinding.WINDOWS_IP_UNICAST_IF, option, option.length);
            } catch (LastErrorException failed) {
                throw new IOException("bind egress socket to interface " + index + ": WSA error "
                        + failed.getErrorCode(), failed);
            }
        }
    }

    /**
     * macOS: the same {@code netstat -rn -f inet} the route commander reads, held for two seconds.
     *
     * <p>The choice is made on every connect and a read costs 25 ms, so a page opening twenty
     * connections would otherwise spend half a second asking. The tunnel's routes are left out of
     * the choice anyway, so the only change a held table can miss is a physical one, and a connect
     * that misses it fails rather than leaking.
     */
    static final class Macos {
        private static final long LIFETIME_NANOS = TimeUnit.SECONDS.toNanos(2);
        private static final long COMMAND_TIMEOUT_SECONDS = 10;

        interface LibC extends Library {
            int setsockopt(int fd, int level, int name, byte[] value, int length) throws LastErrorException;
        }

        private static final class Libraries {
            static final LibC LIBC = Native.load("c", LibC.class);
        }

        private List<PeerEgressSocketBinding.Route> held;
        private long readAt;

        synchronized List<PeerEgressSocketBinding.Route> routes() throws IOException {
            if (held != null && System.nanoTime() - readAt < LIFETIME_NANOS) {
                return held;
            }
            List<String> command = PeerEgressMacosRouteCommands.showTableArgs();
            Process process = new ProcessBuilder(command).redirectError(ProcessBuilder.Redirect.DISCARD).start();
            String stdout;
            try (var out = process.getInputStream()) {
                stdout = new String(out.readAllBytes(), StandardCharsets.US_ASCII);
            }
            try {
                if (!process.waitFor(COMMAND_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                    process.destroyForcibly();
                    throw new IOException(String.join(" ", command) + " did not finish");
                }
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                process.destroyForcibly();
                throw new IOException(String.join(" ", command) + " was interrupted", interrupted);
            }
            if (process.exitValue() != 0) {
                held = null;
                throw new IOException(String.join(" ", command) + " exited " + process.exitValue());
            }
            held = PeerEgressSocketBinding.macosRoutes(stdout);
            readAt = System.nanoTime();
            return held;
        }

        static void apply(int handle, String iface) throws IOException {
            NetworkInterface network = NetworkInterface.getByName(iface);
            if (network == null) {
                throw new IOException("bind egress socket: no interface named " + iface);
            }
            byte[] option = PeerEgressSocketBinding.macosBoundInterfaceOption(network.getIndex());
            try {
                Libraries.LIBC.setsockopt(handle, PeerEgressSocketBinding.IPPROTO_IP,
                        PeerEgressSocketBinding.MACOS_IP_BOUND_IF, option, option.length);
            } catch (LastErrorException failed) {
                throw new IOException("bind egress socket to " + iface + ": errno " + failed.getErrorCode(), failed);
            }
        }
    }

    /**
     * Linux: the socket is marked, not bound, and the mark is set best-effort.
     *
     * <p>A node without the matching rule, or without permission to set a mark -- it takes
     * CAP_NET_ADMIN -- still works whenever the tunnel did not claim the default route, so failing
     * the connect here would break the common case in order to protect the uncommon one. The Go and
     * .NET egresses ignore a refused mark without a word, and so does this one.
     *
     * <p>A handle this JVM cannot reach is no reason to refuse either: Linux egress never needed one
     * before the mark, and refusing would turn a missing JVM option into an egress that carries
     * nothing. The socket goes out unmarked instead. That failure is Java's own and an operator can
     * fix it, so it is logged, once, naming the option.
     */
    static final class Linux {

        interface LibC extends Library {
            int setsockopt(int fd, int level, int name, byte[] value, int length) throws LastErrorException;
        }

        private static final class Libraries {
            static final LibC LIBC = Native.load("c", LibC.class);
        }

        private static final AtomicBoolean HANDLE_UNREACHABLE_LOGGED = new AtomicBoolean();

        private Linux() {
        }

        static void mark(NetworkChannel channel) {
            int handle;
            try {
                handle = PeerEgressSocketHandles.of(channel);
            } catch (IOException unreachable) {
                if (HANDLE_UNREACHABLE_LOGGED.compareAndSet(false, true)) {
                    // The handle's own message names the missing JVM option when that is the cause.
                    log.warn("[peer-egress] egress sockets go out without SO_MARK 0x5350, so a policy routing "
                            + "rule on that mark will not steer them: the socket handle is out of reach ({})",
                            unreachable.getMessage());
                }
                return;
            }
            byte[] option = PeerEgressSocketBinding.linuxSocketMarkOption(
                    PeerEgressSocketBinding.LINUX_EGRESS_SOCKET_MARK);
            try {
                Libraries.LIBC.setsockopt(handle, PeerEgressSocketBinding.LINUX_SOL_SOCKET,
                        PeerEgressSocketBinding.LINUX_SO_MARK, option, option.length);
            } catch (LastErrorException refused) {
                // Best effort; see the class comment. EPERM without the capability is the usual one.
            } catch (LinkageError unavailable) {
                // Same: no libc to call leaves the socket unmarked, not the dial refused.
            }
        }
    }
}
