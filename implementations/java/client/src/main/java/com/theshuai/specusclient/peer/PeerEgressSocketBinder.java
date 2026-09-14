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
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Binds each egress socket to the interface {@link PeerEgressSocketBinding#select} chooses:
 * {@code IP_UNICAST_IF} on Windows, {@code IP_BOUND_IF} on macOS.
 *
 * <p>On Linux nothing is bound. The Go and .NET egresses mark their sockets there for a policy
 * routing rule to steer; that needs a handle this class could now supply, but it is a separate
 * change.
 */
class PeerEgressSocketBinder {

    /** Reads the candidate routes. */
    interface RouteSource {
        List<PeerEgressSocketBinding.Route> read() throws IOException;
    }

    /** Sets the option binding a socket handle to an interface, as the table names it. */
    interface Applier {
        void apply(int handle, String iface) throws IOException;
    }

    private final Supplier<String> tunnel;
    private final Function<String, String> tunnelKey;
    private final Applier applier;
    /** Replaceable so the real-socket tests can hand the stack a route it has to refuse. */
    RouteSource routes;

    PeerEgressSocketBinder(Supplier<String> tunnel, RouteSource routes, Function<String, String> tunnelKey,
            Applier applier) {
        this.tunnel = tunnel;
        this.routes = routes;
        this.tunnelKey = tunnelKey;
        this.applier = applier;
    }

    /** A binder that binds nothing. */
    static PeerEgressSocketBinder none() {
        return new PeerEgressSocketBinder(() -> "", null, name -> "", null);
    }

    static PeerEgressSocketBinder forPlatform(Supplier<String> tunnel) {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (os.contains("win")) {
            return new PeerEgressSocketBinder(tunnel, Windows::routes, Windows::interfaceKey, Windows::apply);
        }
        if (os.contains("mac") || os.contains("darwin")) {
            Macos table = new Macos();
            return new PeerEgressSocketBinder(tunnel, table::routes, name -> name, Macos::apply);
        }
        return none();
    }

    /** Turns a tunnel name into what the table's interface column holds, or "" when there is none. */
    String tunnelKey(String name) {
        return name == null || name.isEmpty() ? "" : tunnelKey.apply(name);
    }

    /** Binds channel, before it connects, to the interface for target. */
    void bind(NetworkChannel channel, InetSocketAddress target) throws IOException {
        if (applier == null) {
            return;
        }
        String chosen = choose(target.getAddress().getHostAddress());
        applier.apply(PeerEgressSocketHandles.of(channel), chosen);
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
}
