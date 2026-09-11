package com.theshuai.specusclient.peer;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

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
        JsonNode decoded = decodeRoutes(output);
        if (decoded == null) {
            return new PeerEgressRouteCommands.ExistingRoute(false, "");
        }
        JsonNode first = null;
        int count = 0;
        for (JsonNode route : decoded) {
            if (prefixOf(route).isEmpty()) {
                continue;
            }
            if (first == null) {
                first = route;
            }
            count++;
        }
        if (first == null) {
            return new PeerEgressRouteCommands.ExistingRoute(false, "");
        }
        String description = describe(first);
        if (count > 1) {
            // The count matters to whoever has to clear the prefix: one removal is not going to be
            // enough, and finding that out by retrying is a worse way to learn it.
            description += " (+" + (count - 1) + " more)";
        }
        return new PeerEgressRouteCommands.ExistingRoute(true, description);
    }

    /**
     * Classifies a routing command that did not succeed.
     *
     * <p>Keyed on the numeric Windows error inside FullyQualifiedErrorId, never on the message: the
     * message is localised, while the id is built from the error number and is not.
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
        return errorId.contains("Windows System Error 5") ? FAILURE_PERMISSION_DENIED : FAILURE_OTHER;
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
