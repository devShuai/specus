package com.theshuai.specusclient.peer;

import java.util.ArrayList;
import java.util.List;

/**
 * Reading what macOS says about its routing table, and building the commands that change it.
 *
 * <p>Kept free of any platform guard for the same reason the Linux and Windows readings are: they
 * depend on output nobody controls, and a macOS-only file would go untested on the machines where
 * most of CI runs.
 *
 * <p>The table is read with {@code netstat -rn -f inet} and changed with {@code route}. Three
 * things about those two, all sampled from a real machine rather than taken from the manual page.
 *
 * <p>{@code route} returns 0 when it fails. A prefix that already exists, a prefix that is not in
 * the table, an interface with no address, a missing argument -- every one of those exits 0 and
 * prints a line that begins exactly like a success. What separates them is that {@code route}
 * writes nothing to stderr when it works, which is why the classification is keyed there.
 *
 * <p>netstat abbreviates the destination column, and the abbreviations are not guessable:
 * 127.0.0.0/8 prints as "127", 203.0.113.0/24 as "203.0.113", 100.64.0.0/10 as "100.64/10", the
 * default route as "default". Reading them back is what {@link #normalisePrefix(String)} does.
 *
 * <p>None of it is localised. The same commands under zh_CN, ja_JP and de_DE produce
 * byte-identical output, so parsing the keys is safe here in a way it is not on Windows, where the
 * same command prints Chinese column headers under one console code page and English under
 * another.
 *
 * <p>Nothing here is quoted or escaped, and unlike the Windows side that is not a decision about
 * character sets: these are argv arrays handed to exec, so there is no shell to reinterpret them.
 * What is left to defend against is a value that reads as an option, and a value that reads as a
 * valid prefix but is not one. The second is the one that matters:
 * {@code route -n add -net 203.0.113.0/33 192.168.64.1} is accepted, prints a success line naming
 * 203.0.113.0, exits 0, and installs 128.0/1 -- half the IPv4 address space pointed at the gateway.
 * Only the routing table says so. On Windows the same argument is refused by New-NetRoute, so
 * validating first was defence in depth; here it is the only defence there is.
 *
 * <p>Shared fixtures: {@code protocol/test-vectors/peer-egress-macos-routes-v1.json}.
 */
public final class PeerEgressMacosRouteCommands {

    /**
     * The netstat flag for an entry the kernel generated rather than one anybody configured.
     *
     * <p>Excluded from the conflict answer. BSD keeps address resolution in the routing table, so
     * every host that has been talked to recently has a /32 of its own, as do the subnet broadcast
     * address and every multicast group that has been joined. Counting those as conflicts would
     * refuse the bypass routes -- /32s for the control endpoint, STUN, TURN and the peer addresses,
     * which are exactly the addresses most likely to have been talked to already -- and a refused
     * bypass route is the leak this feature exists to prevent.
     */
    public static final String KERNEL_GENERATED_FLAG = "W";

    /** Same three names as the Windows side, so the installer reads the same on both. */
    public static final String FAILURE_PERMISSION_DENIED = "permission-denied";

    /** A routing command that failed for some other reason. */
    public static final String FAILURE_OTHER = "failed";

    /** Nothing failed. */
    public static final String FAILURE_NONE = "";

    /** What the refusal says, so a refused argument is told apart from a failed command. */
    public static final String REFUSAL = "refusing to build a route command from this argument";

    /**
     * A removal of something already gone, which is the outcome the caller asked for. It matters
     * more than it looks: the journal is walked at startup, and on a machine that has rebooted none
     * of its routes are there any more, so every entry in it reports this.
     */
    private static final String NOT_IN_TABLE = "not in table";

    /** The failure worth naming, because the fix is to run elevated. */
    private static final String MUST_BE_ROOT = "must be root";

    private PeerEgressMacosRouteCommands() {
    }

    /** One row of {@code netstat -rn}. */
    public record NetstatRoute(String prefix, String destination, String gateway, String flags,
            String netif) {
    }

    /**
     * Reads {@code route -n get <address>}, returning null when there is no usable hop.
     *
     * <p>The gateway is empty for a destination that is on-link, where {@code route} prints no
     * gateway line at all. Sampled rather than assumed: asked about the gateway's own address --
     * which has a cloned link-level entry carrying a MAC address -- it still prints no gateway
     * line, so the field never holds something that is not an address.
     */
    public static PeerEgressRouteCommands.Hop parseRouteGet(String stdout, String stderr) {
        if (stderr != null && !stderr.trim().isEmpty()) {
            return null;
        }
        String gateway = "";
        String device = "";
        for (String line : (stdout == null ? "" : stdout).split("\n", -1)) {
            int separator = line.indexOf(':');
            if (separator < 0) {
                continue;
            }
            String key = line.substring(0, separator).trim();
            String value = line.substring(separator + 1).trim();
            if (key.equals("gateway")) {
                gateway = value;
            } else if (key.equals("interface")) {
                device = value;
            }
        }
        if (device.isEmpty()) {
            return null;
        }
        if (!gateway.isEmpty() && !validAddress(gateway)) {
            // Not an address, so it cannot be a next hop. The only thing done with this value is
            // to put it back on a `route add` command line, where a non-address is either another
            // argument or an error. Treating it as on-link asks for a route out of the interface,
            // which is what an entry without a usable gateway means anyway.
            gateway = "";
        }
        return new PeerEgressRouteCommands.Hop(gateway, device);
    }

    /**
     * Turns netstat's destination column, or a rule's CIDR, into one canonical {@code a.b.c.d/len}.
     * Anything that is not IPv4 becomes empty, which is how the IPv6 half of the table is left
     * alone.
     *
     * <p>A destination with no length carries one octet per eight bits: "127" is 127.0.0.0/8 and
     * "192.168.64" is 192.168.64.0/24. A destination with a length means what it says once the
     * missing trailing octets are filled in with zeroes: "100.64/10" is 100.64.0.0/10.
     *
     * <p>The address is then masked by the length. Two spellings of one prefix have to compare
     * equal, or the conflict check is answering a different question than the one it was asked.
     */
    public static String normalisePrefix(String text) {
        String value = text == null ? "" : text.trim();
        if (value.isEmpty()) {
            return "";
        }
        if (value.equals("default")) {
            return "0.0.0.0/0";
        }
        int slash = value.indexOf('/');
        String address = slash < 0 ? value : value.substring(0, slash);
        String length = slash < 0 ? null : value.substring(slash + 1);
        String[] octets = address.split("\\.", -1);
        if (octets.length < 1 || octets.length > 4) {
            return "";
        }
        long packed = 0;
        for (int index = 0; index < 4; index++) {
            long number = 0;
            if (index < octets.length) {
                int decoded = decimalValue(octets[index], 255);
                if (decoded < 0) {
                    return "";
                }
                number = decoded;
            }
            packed |= number << (24 - 8 * index);
        }
        int bits = 8 * octets.length;
        if (length != null) {
            bits = decimalValue(length, 32);
            if (bits < 0) {
                return "";
            }
        }
        long mask = bits == 0 ? 0L : (0xFFFFFFFFL << (32 - bits)) & 0xFFFFFFFFL;
        packed &= mask;
        return (packed >>> 24 & 0xFF) + "." + (packed >>> 16 & 0xFF) + "."
                + (packed >>> 8 & 0xFF) + "." + (packed & 0xFF) + "/" + bits;
    }

    /**
     * Reads the IPv4 rows of {@code netstat -rn}.
     *
     * <p>Only the rows under the "Internet:" heading. The gate is load-bearing rather than tidy:
     * "Internet6:" has default routes of its own -- four on the sampling machine, one per utun --
     * and "default" is the one destination whose IPv6 spelling is indistinguishable from its IPv4
     * spelling. Without the gate, asking whether anything owns 0.0.0.0/0 on a machine with IPv6
     * would find phantom routes and refuse the one rule that takes over everything.
     *
     * <p>Rows carry four or five columns. The fifth is Expire, which holds a number, or "!", or
     * nothing at all, so this must not require it.
     */
    public static List<NetstatRoute> parseTable(String stdout) {
        List<NetstatRoute> routes = new ArrayList<>();
        boolean inside = false;
        for (String line : (stdout == null ? "" : stdout).split("\n", -1)) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            if (trimmed.endsWith(":")) {
                inside = trimmed.equals("Internet:");
                continue;
            }
            if (!inside || trimmed.startsWith("Destination")) {
                continue;
            }
            String[] fields = trimmed.split("\\s+");
            if (fields.length < 4) {
                continue;
            }
            String prefix = normalisePrefix(fields[0]);
            if (prefix.isEmpty()) {
                continue;
            }
            routes.add(new NetstatRoute(prefix, fields[0], fields[1], fields[2], fields[3]));
        }
        return routes;
    }

    /**
     * Whether anything already owns this exact prefix.
     *
     * <p>Exact prefix, not a longest-prefix lookup, for the same reason as on Windows: the question
     * is ownership of this prefix, not reachability of an address, and under a default route
     * everything is reachable. {@code route -n get} cannot answer it at all -- asked about an
     * unrouted address it returns the default route -- which is why the whole table is read.
     */
    public static PeerEgressRouteCommands.ExistingRoute conflictFromTable(String table,
            String prefix) {
        String wanted = normalisePrefix(prefix);
        if (wanted.isEmpty()) {
            return new PeerEgressRouteCommands.ExistingRoute(false, "");
        }
        List<NetstatRoute> matching = new ArrayList<>();
        for (NetstatRoute route : parseTable(table)) {
            if (route.prefix().equals(wanted) && !route.flags().contains(KERNEL_GENERATED_FLAG)) {
                matching.add(route);
            }
        }
        return describeRoutes(matching);
    }

    /** Turns the routes on one prefix into a presence and a description. */
    public static PeerEgressRouteCommands.ExistingRoute describeRoutes(
            List<NetstatRoute> routes) {
        if (routes.isEmpty()) {
            return new PeerEgressRouteCommands.ExistingRoute(false, "");
        }
        String description = describeRoute(routes.get(0));
        if (routes.size() > 1) {
            // The count matters to whoever has to clear the prefix: one removal is not going to be
            // enough, and retrying is a worse way to learn that. Reachable because a scoped route
            // can share a prefix with an unscoped one.
            description += " (+" + (routes.size() - 1) + " more)";
        }
        return new PeerEgressRouteCommands.ExistingRoute(true, description);
    }

    /**
     * One line an operator can match against their own {@code netstat -rn} output.
     *
     * <p>The columns are restated in netstat's own words, including calling the second one a
     * gateway when it holds an interface name: that is what the table says, and an operator
     * comparing this line against the table should not have to reconcile two vocabularies.
     */
    public static String describeRoute(NetstatRoute route) {
        return route.prefix() + " gateway " + route.gateway() + " netif " + route.netif()
                + " flags " + route.flags();
    }

    /**
     * Classifies a {@code route add} or {@code route delete} that may not have worked.
     *
     * <p>The exit status is not consulted, because it is 0 for "File exists", for "not in table",
     * for "Network is unreachable" and for "Invalid argument" -- every failure sampled except a
     * malformed address returns success. What does separate them is stderr, which is empty for
     * every successful mutation sampled and carries "route: writing to routing socket: &lt;error&gt;"
     * for every failed one.
     *
     * <p>Keyed on stderr being non-empty rather than on a list of error texts. Those errors are
     * strerror of whatever the routing socket returned, so the list has no end, and an unrecognised
     * error would otherwise read as success -- the direction that leaves a rule believed installed
     * while its traffic goes out of the physical interface. Noise on stderr fails the other way:
     * the install is reported failed, the installer withdraws a route it did install, and nothing
     * leaks.
     */
    public static String classifyFailure(String stdout, String stderr) {
        String combined = (stdout == null ? "" : stdout) + "\n" + (stderr == null ? "" : stderr);
        if (combined.contains(MUST_BE_ROOT)) {
            return FAILURE_PERMISSION_DENIED;
        }
        if (combined.contains(NOT_IN_TABLE)) {
            return FAILURE_NONE;
        }
        if (stderr != null && !stderr.trim().isEmpty()) {
            return FAILURE_OTHER;
        }
        return FAILURE_NONE;
    }

    /** Whether this is an IPv4 address and nothing else. */
    public static boolean validAddress(String value) {
        if (value == null || value.isEmpty() || !value.equals(value.trim())) {
            return false;
        }
        String[] octets = value.split("\\.", -1);
        if (octets.length != 4) {
            return false;
        }
        for (String octet : octets) {
            if (decimalValue(octet, 255) < 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * Whether this is an IPv4 prefix in full: four octets and a length.
     *
     * <p>The length is required and 33 is refused, because {@code route} does neither. A leading
     * zero is refused too, in the octets and in the length, because inet_aton would read it as
     * octal and we would not.
     */
    public static boolean validPrefix(String value) {
        if (value == null) {
            return false;
        }
        int slash = value.indexOf('/');
        if (slash < 0 || !validAddress(value.substring(0, slash))) {
            return false;
        }
        return decimalValue(value.substring(slash + 1), 32) >= 0;
    }

    /**
     * Whether a name can be read as anything but an interface.
     *
     * <p>Must start with a letter, so it can never be taken for an option, and must stay inside
     * the letters, digits, underscore and dot that real names use: en0, utun3, bridge0, vlan1. The
     * length limit is the kernel's, where IFNAMSIZ is 16 including the terminator.
     *
     * <p>Whitelisted rather than escaped, which is the opposite of what the same value gets on
     * Windows. There the adapter name reaches PowerShell as part of a script and has to be escaped,
     * because operators legitimately use spaces and non-ASCII in it. Here it is one element of an
     * argv array, so there is nothing to escape, and the only thing that can go wrong is
     * {@code route} reading the name as an address -- which it does: given an interface that does
     * not exist it reports "route: bad address: utun99".
     */
    public static boolean validInterfaceName(String value) {
        if (value == null || value.isEmpty() || value.length() > 15) {
            return false;
        }
        if (!isLetter(value.charAt(0))) {
            return false;
        }
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (isLetter(character) || (character >= '0' && character <= '9')
                    || character == '_' || character == '.') {
                continue;
            }
            return false;
        }
        return true;
    }

    /**
     * Reads the whole table. IPv4 only: the IPv6 section has a different column layout and this
     * feature does not route IPv6 yet.
     */
    public static List<String> showTableArgs() {
        return List.of("netstat", "-rn", "-f", "inet");
    }

    /**
     * Asks where an address would go right now, which is how a bypass next hop is resolved.
     *
     * <p>{@code -n} so no name lookup is attempted. It makes no difference to the output --
     * sampled both ways -- but a resolver that does not answer would hold the process for as long
     * as the resolver takes, and this runs while the tunnel is being brought up.
     */
    public static List<String> findRouteArgs(String address) {
        if (!validAddress(address)) {
            throw new IllegalArgumentException(REFUSAL + ": " + address);
        }
        return List.of("route", "-n", "get", address);
    }

    /** Sends a prefix out of an interface, which is how a rule's route reaches the TUN. */
    public static List<String> installInterfaceArgs(String prefix, String name) {
        if (!validPrefix(prefix)) {
            throw new IllegalArgumentException(REFUSAL + ": " + prefix);
        }
        if (!validInterfaceName(name)) {
            throw new IllegalArgumentException(REFUSAL + ": " + name);
        }
        return List.of("route", "-n", "add", "-net", prefix, "-interface", name);
    }

    /** Sends a prefix to a next hop, which is how a bypass keeps the transport off the tunnel. */
    public static List<String> installGatewayArgs(String prefix, String gateway) {
        if (!validPrefix(prefix)) {
            throw new IllegalArgumentException(REFUSAL + ": " + prefix);
        }
        if (!validAddress(gateway)) {
            throw new IllegalArgumentException(REFUSAL + ": " + gateway);
        }
        return List.of("route", "-n", "add", "-net", prefix, gateway);
    }

    /**
     * Withdraws a prefix.
     *
     * <p>{@code -net} for every prefix including a /32, which is sampled as working. One form means
     * the withdrawal cannot disagree with the install about what was installed.
     *
     * <p>No {@code -ifscope}, matching the install. A withdrawal without it takes the unscoped
     * route and leaves scoped ones alone, which is the right way round: this feature only ever
     * installs unscoped routes, and a scoped route on the same prefix belongs to somebody else.
     */
    public static List<String> removeArgs(String prefix) {
        if (!validPrefix(prefix)) {
            throw new IllegalArgumentException(REFUSAL + ": " + prefix);
        }
        return List.of("route", "-n", "delete", "-net", prefix);
    }

    /**
     * The value of a run of decimal digits, or -1 if it is not one or is out of range.
     *
     * <p>A leading zero is refused rather than skipped. {@code route} parses addresses with
     * inet_aton, which reads a leading zero as octal: to it, 010.0.0.1 is 8.0.0.1. Reading the same
     * text as decimal here would mean the conflict check asking about one prefix while the install
     * created another, and the way not to have two readings of one string is to accept only the
     * spelling that has one.
     */
    private static int decimalValue(String digits, int limit) {
        if (digits == null || digits.isEmpty() || digits.length() > 3) {
            return -1;
        }
        if (digits.length() > 1 && digits.charAt(0) == '0') {
            return -1;
        }
        int value = 0;
        for (int index = 0; index < digits.length(); index++) {
            char character = digits.charAt(index);
            if (character < '0' || character > '9') {
                return -1;
            }
            value = value * 10 + (character - '0');
        }
        return value <= limit ? value : -1;
    }

    private static boolean isLetter(char character) {
        return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z');
    }
}
