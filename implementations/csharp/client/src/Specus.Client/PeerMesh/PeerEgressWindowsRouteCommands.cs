using System.Text;
using System.Text.Json;

namespace Specus.Client.PeerMesh;

/// <summary>
/// Where a bypass address has to be sent to stay off the tunnel, on Windows.
/// </summary>
/// <remarks>
/// Carries the interface index, not the interface name: names are localised -- the default adapter
/// on a Chinese Windows is called 以太网 -- and the index is a number.
/// </remarks>
/// <param name="Gateway">
/// Empty for an on-link destination, which is normal on a directly attached network and is not a
/// failure to parse.
/// </param>
internal readonly record struct PeerEgressWindowsRouteHop(string Gateway, int InterfaceIndex);

/// <summary>
/// Reading what Windows says about its routing table.
/// </summary>
/// <remarks>
/// Kept free of any platform guard for the same reason the Linux parsers are: they depend on output
/// nobody controls, and a Windows-only file would go untested on the machines where most of CI
/// runs.
///
/// <para>The table is read through PowerShell rather than netsh or route print, because those two
/// are localised. The same <c>netsh interface ipv4 show route</c> prints English column headers
/// under one console code page and Chinese ones under another on the very same machine. A parser
/// written against the English table reads no routes at all on a Chinese machine, and no routes is
/// exactly the answer that means "no conflict, install it" -- which would overwrite the operator's
/// own routing while reporting success. <c>ip route</c> carries no translations, which is why
/// parsing its text is safe on Linux and not here.</para>
///
/// <para>The PowerShell layer is therefore as thin as it can be: it turns objects into JSON and
/// decides nothing. Which object in the array is the route, what a missing next hop means, whether
/// a failure was a permissions failure -- all of that is here, where the shared vector pins the
/// three implementations to one reading.</para>
///
/// <para>Shared fixtures:
/// <c>protocol/test-vectors/peer-egress-windows-routes-v1.json</c>.</para>
/// </remarks>
internal static class PeerEgressWindowsRouteCommands
{
    /// <summary>
    /// What Windows reports for a destination on a directly attached network. Linux says the same
    /// thing by leaving <c>via</c> out, so both become an empty gateway and nothing downstream has
    /// to know which platform answered.
    /// </summary>
    public const string OnLinkNextHop = "0.0.0.0";

    /// <summary>
    /// The failure worth telling the operator about by name: the fix is to run elevated, and no
    /// amount of retrying gets there.
    /// </summary>
    public const string FailurePermissionDenied = "permission-denied";

    /// <summary>A routing command that failed for some other reason.</summary>
    public const string FailureOther = "failed";

    /// <summary>Nothing failed.</summary>
    public const string FailureNone = "";

    /// <summary>
    /// Reads the JSON from the find-route script, returning null when there is no usable hop.
    /// </summary>
    /// <remarks>
    /// <c>Find-NetRoute</c> returns two objects: the source address it would use, then the route.
    /// Only the second carries a DestinationPrefix, and that is what picks it out -- taking element
    /// zero yields an interface index with no next hop, which would install a route to nowhere.
    /// </remarks>
    public static PeerEgressWindowsRouteHop? ParseRouteFind(string? output)
    {
        using var decoded = DecodeRoutes(output);
        if (decoded is null)
        {
            return null;
        }
        foreach (var route in decoded.RootElement.EnumerateArray())
        {
            if (PrefixOf(route).Length == 0)
            {
                continue;
            }
            var index = IntOf(route, "InterfaceIndex");
            if (index is null or <= 0)
            {
                // Zero is not an interface. Installing against it would ask the system to send
                // through nothing, so skip it and keep looking rather than give up here.
                continue;
            }
            return new PeerEgressWindowsRouteHop(GatewayOf(route), index.Value);
        }
        return null;
    }

    /// <summary>Reads the JSON from the show-route script.</summary>
    /// <remarks>
    /// Unparseable output reports no conflict, matching the Linux reading: being unable to ask is
    /// not evidence of an empty table, and the install still refuses a prefix that already exists.
    /// </remarks>
    public static PeerEgressExistingRoute ParseRouteShow(string? output)
    {
        using var decoded = DecodeRoutes(output);
        if (decoded is null)
        {
            return new PeerEgressExistingRoute(false, "");
        }
        string? description = null;
        var count = 0;
        foreach (var route in decoded.RootElement.EnumerateArray())
        {
            if (PrefixOf(route).Length == 0)
            {
                continue;
            }
            description ??= Describe(route);
            count++;
        }
        if (description is null)
        {
            return new PeerEgressExistingRoute(false, "");
        }
        if (count > 1)
        {
            // The count matters to whoever has to clear the prefix: one removal is not going to be
            // enough, and finding that out by retrying is a worse way to learn it.
            description += $" (+{count - 1} more)";
        }
        return new PeerEgressExistingRoute(true, description);
    }

    /// <summary>Classifies a routing command that did not succeed.</summary>
    /// <remarks>
    /// Keyed on the numeric Windows error inside FullyQualifiedErrorId, never on the message: the
    /// message is localised, while the id is built from the error number and is not.
    /// </remarks>
    public static string ParseCommandFailure(string? output)
    {
        var trimmed = (output ?? "").Trim();
        if (trimmed.Length == 0)
        {
            return FailureNone;
        }
        JsonDocument failure;
        try
        {
            failure = JsonDocument.Parse(trimmed);
        }
        catch (JsonException)
        {
            // Output that is neither empty nor JSON means something went wrong that the script did
            // not get to describe.
            return FailureOther;
        }
        using (failure)
        {
            if (failure.RootElement.ValueKind != JsonValueKind.Object
                || !failure.RootElement.TryGetProperty("errorId", out var id)
                || id.ValueKind != JsonValueKind.String)
            {
                return FailureNone;
            }
            var errorId = (id.GetString() ?? "").Trim();
            if (errorId.Length == 0)
            {
                return FailureNone;
            }
            return errorId.Contains("Windows System Error 5", StringComparison.Ordinal)
                ? FailurePermissionDenied
                : FailureOther;
        }
    }

    /// <summary>One line an operator can match against their own Get-NetRoute output.</summary>
    private static string Describe(JsonElement route)
    {
        var gateway = GatewayOf(route);
        var via = gateway.Length == 0 ? "on-link" : "nexthop " + gateway;
        var line = new StringBuilder()
            .Append(PrefixOf(route)).Append(' ').Append(via)
            .Append(" ifIndex ").Append(IntOf(route, "InterfaceIndex") ?? 0);
        if (IntOf(route, "RouteMetric") is { } metric)
        {
            line.Append(" metric ").Append(metric);
        }
        return line.ToString();
    }

    private static JsonDocument? DecodeRoutes(string? output)
    {
        var trimmed = (output ?? "").Trim();
        if (trimmed.Length == 0)
        {
            return null;
        }
        JsonDocument parsed;
        try
        {
            parsed = JsonDocument.Parse(trimmed);
        }
        catch (JsonException)
        {
            return null;
        }
        if (parsed.RootElement.ValueKind != JsonValueKind.Array)
        {
            parsed.Dispose();
            return null;
        }
        return parsed;
    }

    private static string PrefixOf(JsonElement route) =>
        route.ValueKind == JsonValueKind.Object
        && route.TryGetProperty("DestinationPrefix", out var prefix)
        && prefix.ValueKind == JsonValueKind.String
            ? (prefix.GetString() ?? "").Trim()
            : "";

    private static string GatewayOf(JsonElement route)
    {
        if (route.ValueKind != JsonValueKind.Object
            || !route.TryGetProperty("NextHop", out var hop)
            || hop.ValueKind != JsonValueKind.String)
        {
            return "";
        }
        var gateway = (hop.GetString() ?? "").Trim();
        return gateway == OnLinkNextHop ? "" : gateway;
    }

    private static int? IntOf(JsonElement route, string property) =>
        route.ValueKind == JsonValueKind.Object
        && route.TryGetProperty(property, out var value)
        && value.ValueKind == JsonValueKind.Number
        && value.TryGetInt32(out var number)
            ? number
            : null;
}
