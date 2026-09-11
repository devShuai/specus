package com.theshuai.specusclient.peer;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;

/**
 * Reading what Windows says about its routing table.
 *
 * <p>Kept free of any platform guard for the same reason the Linux parsers are: they depend on
 * output nobody controls, and a Windows-only file would go untested on the machines where most of
 * CI runs.
 *
 * <p>The table is read through PowerShell rather than netsh or route print, because those two are
 * localised. The same {@code netsh interface ipv4 show route} prints English column headers under
 * one console code page and Chinese ones under another on the very same machine. A parser written
 * against the English table reads no routes at all on a Chinese machine, and no routes is exactly
 * the answer that means "no conflict, install it" -- which would overwrite the operator's own
 * routing while reporting success. {@code ip route} carries no translations, which is why parsing
 * its text is safe on Linux and not here.
 *
 * <p>The PowerShell layer is therefore as thin as it can be: it turns objects into JSON and decides
 * nothing. Which object in the array is the route, what a missing next hop means, whether a failure
 * was a permissions failure -- all of that is here, where the shared vector pins the three
 * implementations to one reading.
 *
 * <p>Shared fixtures: {@code protocol/test-vectors/peer-egress-windows-routes-v1.json}.
 */
public final class PeerEgressWindowsRouteCommands {

    /**
     * What Windows reports for a destination on a directly attached network. Linux says the same
     * thing by leaving {@code via} out, so both become an empty gateway and nothing downstream has
     * to know which platform answered.
     */
    public static final String ON_LINK_NEXT_HOP = "0.0.0.0";

    /**
     * The failure worth telling the operator about by name: the fix is to run elevated, and no
     * amount of retrying gets there.
     */
    public static final String FAILURE_PERMISSION_DENIED = "permission-denied";

    /** A routing command that failed for some other reason. */
    public static final String FAILURE_OTHER = "failed";

    /** Nothing failed. */
    public static final String FAILURE_NONE = "";

    /**
     * What a removal reports when the prefix is not in the table. Not a failure: the outcome the
     * caller asked for already holds.
     */
    private static final String ERROR_NOT_FOUND = "CmdletizationQuery_NotFound";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private PeerEgressWindowsRouteCommands() {
    }

    /**
     * Where a bypass address has to be sent to stay off the tunnel.
     *
     * <p>Carries the interface index, not the interface name: names are localised -- the default
     * adapter on a Chinese Windows is called 以太网 -- and the index is a number.
     *
     * @param gateway empty for an on-link destination, which is normal on a directly attached
     *                network and is not a failure to parse
     */
    public record Hop(String gateway, int interfaceIndex) {
    }

    /**
     * Reads the JSON from the find-route script, returning null when there is no usable hop.
     *
     * <p>{@code Find-NetRoute} returns two objects: the source address it would use, then the
     * route. Only the second carries a DestinationPrefix, and that is what picks it out -- taking
     * element zero yields an interface index with no next hop, which would install a route to
     * nowhere.
     */
    public static Hop parseRouteFind(String output) {
        JsonNode routes = decodeRoutes(output);
        if (routes == null) {
            return null;
        }
        for (JsonNode route : routes) {
            if (prefixOf(route).isEmpty()) {
                continue;
            }
            int index = route.path("InterfaceIndex").asInt(0);
            if (index <= 0) {
                // Zero is not an interface. Installing against it would ask the system to send
                // through nothing, so skip it and keep looking rather than give up here.
                continue;
            }
            return new Hop(gatewayOf(route), index);
        }
        return null;
    }

    /**
     * Reads the JSON from the show-route script.
     *
     * <p>Unparseable output reports no conflict, matching the Linux reading: being unable to ask is
     * not evidence of an empty table, and the install still refuses a prefix that already exists.
     */
    public static PeerEgressRouteCommands.ExistingRoute parseRouteShow(String output) {
        return describeRoutes(routesWithPrefix(output));
    }

    /**
     * Answers the same question out of one read of the whole table.
     *
     * <p>Exact string match on the prefix, not a longest-prefix lookup. What the conflict check
     * asks is whether anything already owns this exact prefix, not whether the address can be
     * routed -- under a default route the second question is always yes, and treating that as a
     * conflict would refuse every rule on any machine that has one.
     */
    public static PeerEgressRouteCommands.ExistingRoute conflictFromTable(String table, String prefix) {
        String wanted = prefix == null ? "" : prefix.trim();
        List<JsonNode> matching = new ArrayList<>();
        for (JsonNode route : routesWithPrefix(table)) {
            if (prefixOf(route).equals(wanted)) {
                matching.add(route);
            }
        }
        return describeRoutes(matching);
    }

    /** Every entry in the output that actually carries a prefix. */
    private static List<JsonNode> routesWithPrefix(String output) {
        List<JsonNode> routes = new ArrayList<>();
        JsonNode decoded = decodeRoutes(output);
        if (decoded == null) {
            return routes;
        }
        for (JsonNode route : decoded) {
            if (!prefixOf(route).isEmpty()) {
                routes.add(route);
            }
        }
        return routes;
    }

    /** Turns the routes on one prefix into a presence and a description. */
    private static PeerEgressRouteCommands.ExistingRoute describeRoutes(List<JsonNode> routes) {
        if (routes.isEmpty()) {
            return new PeerEgressRouteCommands.ExistingRoute(false, "");
        }
        String description = describe(routes.get(0));
        if (routes.size() > 1) {
            // The count matters to whoever has to clear the prefix: one removal is not going to be
            // enough, and finding that out by retrying is a worse way to learn it.
            description += " (+" + (routes.size() - 1) + " more)";
        }
        return new PeerEgressRouteCommands.ExistingRoute(true, description);
    }

    /**
     * Classifies a routing command that did not succeed.
     *
     * <p>Keyed on the id inside FullyQualifiedErrorId, never on the message: the message is
     * localised, while the id is built from the error number and the cmdlet name and is not.
     *
     * <p>A removal that found no such prefix is not a failure: the route is not in the table, which
     * is what the caller asked for. That matters more here than on Linux, because these routes go
     * into ActiveStore and do not survive a reboot -- so the first cleanup after every restart walks
     * a journal of prefixes that are all already gone, and reporting each one would bury the
     * failures that are real.
     */
    public static String parseCommandFailure(String output) {
        String trimmed = output == null ? "" : output.trim();
        if (trimmed.isEmpty()) {
            return FAILURE_NONE;
        }
        JsonNode failure;
        try {
            failure = MAPPER.readTree(trimmed);
        } catch (Exception malformed) {
            // Output that is neither empty nor JSON means something went wrong that the script did
            // not get to describe.
            return FAILURE_OTHER;
        }
        if (failure == null || !failure.isObject()) {
            return FAILURE_NONE;
        }
        String errorId = failure.path("errorId").asText("").trim();
        if (errorId.isEmpty()) {
            return FAILURE_NONE;
        }
        if (errorId.contains("Windows System Error 5")) {
            return FAILURE_PERMISSION_DENIED;
        }
        return errorId.contains(ERROR_NOT_FOUND) ? FAILURE_NONE : FAILURE_OTHER;
    }

    /**
     * Wraps an interface name, escaping the one character that needs it.
     *
     * <p>Unlike the addresses, this cannot be whitelisted: the TUN adapter's name comes from
     * operator configuration and may legitimately contain spaces and non-ASCII characters. So here
     * the escape is the defence rather than unreachable code, and it protects a value that really
     * can carry a quote. PowerShell's single-quoted strings escape a quote by doubling it.
     */
    public static String quoteName(String value) {
        return "'" + (value == null ? "" : value.replace("'", "''")) + "'";
    }

    /**
     * Resolves an adapter name to its index.
     *
     * <p>Selects the index and nothing else, and that is a requirement rather than a convenience.
     * The child process writes stdout in the console code page -- 936 on the machine this was
     * sampled on, not UTF-8 -- and in GBK the low byte of a double-byte character can be 0x5C.
     * Echoing a Chinese adapter name back into the JSON can therefore emit a bare backslash and
     * break the document. Indexes, prefixes, next hops and metrics are all ASCII, so a script that
     * selects only those is readable whatever the code page is.
     */
    public static String interfaceIndexScript(String name) {
        return "ConvertTo-Json -Compress -InputObject @(Get-NetAdapter -Name " + quoteName(name)
                + " -ErrorAction SilentlyContinue|Select-Object InterfaceIndex)";
    }

    /**
     * Reads the whole table in one query.
     *
     * <p>The conflict check asks about one prefix at a time, but the answers can all come from
     * here: 29 routes came back in 419 ms on the sampling machine, cheaper than one query per
     * prefix and leaving the checking to happen in memory.
     */
    public static String showAllRoutesScript() {
        return "ConvertTo-Json -Compress -InputObject @(Get-NetRoute -AddressFamily IPv4 "
                + "-ErrorAction SilentlyContinue|Select-Object "
                + "InterfaceIndex,DestinationPrefix,NextHop,RouteMetric)";
    }

    /**
     * Reads the adapter-index script's JSON, returning 0 when there is no usable index.
     *
     * <p>An adapter that is not there comes back as an empty array rather than an error, so the
     * absence has to be recognised here: installing against index zero would ask the system to
     * route through nothing.
     */
    public static int parseInterfaceIndex(String output) {
        JsonNode decoded = decodeRoutes(output);
        if (decoded == null) {
            return 0;
        }
        for (JsonNode route : decoded) {
            int index = route.path("InterfaceIndex").asInt(0);
            if (index > 0) {
                return index;
            }
        }
        return 0;
    }

    /**
     * Asks about every prefix in one process.
     *
     * <p>One line of JSON per prefix, in the order given. Batched because a PowerShell process costs
     * about 175 ms to start and the first NetTCPIP cmdlet another 380 ms, after which queries in the
     * same process are nearly free: twenty prefixes asked one at a time would take eleven seconds.
     *
     * @throws IllegalArgumentException if any prefix is not a plain dotted-quad CIDR
     */
    public static String showRoutesScript(List<String> prefixes) {
        return "foreach($p in @(" + quoteAll(prefixes, true) + ")){ConvertTo-Json -Compress "
                + "-InputObject @(Get-NetRoute -DestinationPrefix $p -AddressFamily IPv4 "
                + "-ErrorAction SilentlyContinue|Select-Object "
                + "InterfaceIndex,DestinationPrefix,NextHop,RouteMetric)}\nexit 0";
    }

    /**
     * Resolves every bypass address in one process.
     *
     * @throws IllegalArgumentException if any address is not a plain dotted quad
     */
    public static String findRoutesScript(List<String> addresses) {
        return "foreach($a in @(" + quoteAll(addresses, false) + ")){ConvertTo-Json -Compress "
                + "-InputObject @(Find-NetRoute -RemoteIPAddress $a "
                + "-ErrorAction SilentlyContinue|Select-Object "
                + "InterfaceIndex,DestinationPrefix,NextHop,RouteMetric)}\nexit 0";
    }

    /**
     * Adds one route.
     *
     * <p>ActiveStore rather than PersistentStore: these routes do not survive a reboot, which is
     * what this feature wants and what matches {@code ip route add} on Linux. A persistent route is
     * the one that really does get left behind, still in the table after a restart that the journal
     * no longer describes.
     *
     * <p>An empty gateway leaves {@code -NextHop} off, which Windows reads as on-link. Passing
     * 0.0.0.0 explicitly says the same thing at greater length.
     *
     * @throws IllegalArgumentException if the prefix, gateway or interface index is not usable
     */
    public static String installRouteScript(String cidr, int interfaceIndex, String gateway) {
        if (interfaceIndex <= 0) {
            throw new IllegalArgumentException("refusing to build a route command for interface "
                    + interfaceIndex);
        }
        String hop = gateway == null || gateway.isEmpty()
                ? "" : " -NextHop " + quote(gateway, false);
        return "try{New-NetRoute -DestinationPrefix " + quote(cidr, true) + hop
                + " -InterfaceIndex " + interfaceIndex
                + " -PolicyStore ActiveStore -ErrorAction Stop|Out-Null}catch{ConvertTo-Json "
                + "-Compress -InputObject @{errorId=$_.FullyQualifiedErrorId};exit 1}";
    }

    /**
     * Withdraws one route.
     *
     * <p>{@code -Confirm:$false} because Remove-NetRoute asks otherwise, and a non-interactive
     * process has nobody to ask.
     *
     * @throws IllegalArgumentException if the prefix is not a plain dotted-quad CIDR
     */
    public static String removeRouteScript(String cidr) {
        return "try{Remove-NetRoute -DestinationPrefix " + quote(cidr, true)
                + " -Confirm:$false -PolicyStore ActiveStore -ErrorAction Stop|Out-Null}catch{"
                + "ConvertTo-Json -Compress -InputObject @{errorId=$_.FullyQualifiedErrorId};"
                + "exit 1}";
    }

    /**
     * Cuts a batched query's output into one entry per input.
     *
     * <p>Every query writes exactly one compressed JSON line, including an empty result, so the
     * lines line up with the prefixes that were asked about.
     */
    public static List<String> splitScriptLines(String output) {
        List<String> lines = new ArrayList<>();
        if (output == null) {
            return lines;
        }
        for (String line : output.replace("\r\n", "\n").split("\n", -1)) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty()) {
                lines.add(trimmed);
            }
        }
        return lines;
    }

    /** Accepts a dotted-quad CIDR and nothing else. */
    public static boolean validPrefix(String value) {
        int slash = value == null ? -1 : value.indexOf('/');
        if (slash < 0) {
            return false;
        }
        String length = value.substring(slash + 1);
        if (length.isEmpty() || length.length() > 2 || !digitsOnly(length)
                || Integer.parseInt(length) > 32) {
            return false;
        }
        return validAddress(value.substring(0, slash));
    }

    /** Accepts a dotted-quad IPv4 address and nothing else. */
    public static boolean validAddress(String value) {
        if (value == null) {
            return false;
        }
        String[] octets = value.split("\\.", -1);
        if (octets.length != 4) {
            return false;
        }
        for (String octet : octets) {
            if (octet.isEmpty() || octet.length() > 3 || !digitsOnly(octet)
                    || Integer.parseInt(octet) > 255) {
                return false;
            }
        }
        return true;
    }

    private static boolean digitsOnly(String value) {
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (character < '0' || character > '9') {
                return false;
            }
        }
        return true;
    }

    private static String quoteAll(List<String> values, boolean prefixes) {
        StringBuilder joined = new StringBuilder();
        for (String value : values) {
            if (joined.length() > 0) {
                joined.append(',');
            }
            joined.append(quote(value, prefixes));
        }
        return joined.toString();
    }

    /**
     * Wraps a validated argument.
     *
     * <p>No escaping, deliberately. The allowed character set has no quote in it, so an escape step
     * here would be unreachable code that reads like a second line of defence -- and a defence that
     * cannot fire is worse than none, because it invites the first one to be relaxed.
     *
     * <p>The prefix comes from operator configuration and the bypass addresses from runtime
     * discovery. On Linux they reach {@code ip} as argv entries that no shell ever sees; here they
     * are concatenated into one command string, and this whitelist is what keeps that from being a
     * command injection.
     */
    private static String quote(String value, boolean prefix) {
        boolean valid = prefix ? validPrefix(value) : validAddress(value);
        if (!valid) {
            throw new IllegalArgumentException(
                    "refusing to build a route command from this argument");
        }
        return "'" + value + "'";
    }

    /** One line an operator can match against their own Get-NetRoute output. */
    private static String describe(JsonNode route) {
        String gateway = gatewayOf(route);
        String via = gateway.isEmpty() ? "on-link" : "nexthop " + gateway;
        StringBuilder line = new StringBuilder()
                .append(prefixOf(route)).append(' ').append(via)
                .append(" ifIndex ").append(route.path("InterfaceIndex").asInt(0));
        JsonNode metric = route.path("RouteMetric");
        if (metric.isInt()) {
            line.append(" metric ").append(metric.asInt());
        }
        return line.toString();
    }

    private static JsonNode decodeRoutes(String output) {
        String trimmed = output == null ? "" : output.trim();
        if (trimmed.isEmpty()) {
            return null;
        }
        try {
            JsonNode parsed = MAPPER.readTree(trimmed);
            return parsed != null && parsed.isArray() ? parsed : null;
        } catch (Exception malformed) {
            return null;
        }
    }

    private static String prefixOf(JsonNode route) {
        JsonNode prefix = route.path("DestinationPrefix");
        return prefix.isTextual() ? prefix.asText().trim() : "";
    }

    private static String gatewayOf(JsonNode route) {
        JsonNode hop = route.path("NextHop");
        if (!hop.isTextual()) {
            return "";
        }
        String gateway = hop.asText().trim();
        return ON_LINK_NEXT_HOP.equals(gateway) ? "" : gateway;
    }
}
