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
    /// What a removal reports when the prefix is not in the table. Not a failure: the outcome the
    /// caller asked for already holds.
    /// </summary>
    private const string ErrorNotFound = "CmdletizationQuery_NotFound";

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
    /// Keyed on the id inside FullyQualifiedErrorId, never on the message: the message is
    /// localised, while the id is built from the error number and the cmdlet name and is not.
    ///
    /// <para>A removal that found no such prefix is not a failure: the route is not in the table,
    /// which is what the caller asked for. That matters more here than on Linux, because these
    /// routes go into ActiveStore and do not survive a reboot -- so the first cleanup after every
    /// restart walks a journal of prefixes that are all already gone, and reporting each one would
    /// bury the failures that are real.</para>
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
            if (errorId.Contains("Windows System Error 5", StringComparison.Ordinal))
            {
                return FailurePermissionDenied;
            }
            return errorId.Contains(ErrorNotFound, StringComparison.Ordinal)
                ? FailureNone
                : FailureOther;
        }
    }

    /// <summary>Asks about every prefix in one process.</summary>
    /// <remarks>
    /// One line of JSON per prefix, in the order given. Batched because a PowerShell process costs
    /// about 175 ms to start and the first NetTCPIP cmdlet another 380 ms, after which queries in
    /// the same process are nearly free: twenty prefixes asked one at a time would take eleven
    /// seconds.
    /// </remarks>
    /// <exception cref="ArgumentException">a prefix is not a plain dotted-quad CIDR.</exception>
    public static string ShowRoutesScript(IReadOnlyList<string> prefixes) =>
        $"foreach($p in @({QuoteAll(prefixes, prefixes: true)})){{ConvertTo-Json -Compress "
        + "-InputObject @(Get-NetRoute -DestinationPrefix $p -AddressFamily IPv4 "
        + "-ErrorAction SilentlyContinue|Select-Object "
        + "InterfaceIndex,DestinationPrefix,NextHop,RouteMetric)}\nexit 0";

    /// <summary>Resolves every bypass address in one process.</summary>
    /// <exception cref="ArgumentException">an address is not a plain dotted quad.</exception>
    public static string FindRoutesScript(IReadOnlyList<string> addresses) =>
        $"foreach($a in @({QuoteAll(addresses, prefixes: false)})){{ConvertTo-Json -Compress "
        + "-InputObject @(Find-NetRoute -RemoteIPAddress $a "
        + "-ErrorAction SilentlyContinue|Select-Object "
        + "InterfaceIndex,DestinationPrefix,NextHop,RouteMetric)}\nexit 0";

    /// <summary>Adds one route.</summary>
    /// <remarks>
    /// ActiveStore rather than PersistentStore: these routes do not survive a reboot, which is what
    /// this feature wants and what matches <c>ip route add</c> on Linux. A persistent route is the
    /// one that really does get left behind, still in the table after a restart that the journal no
    /// longer describes.
    ///
    /// <para>An empty gateway leaves <c>-NextHop</c> off, which Windows reads as on-link. Passing
    /// 0.0.0.0 explicitly says the same thing at greater length.</para>
    /// </remarks>
    /// <exception cref="ArgumentException">
    /// the prefix, gateway or interface index is not usable.
    /// </exception>
    public static string InstallRouteScript(string cidr, int interfaceIndex, string? gateway)
    {
        if (interfaceIndex <= 0)
        {
            throw new ArgumentException(
                $"refusing to build a route command for interface {interfaceIndex}",
                nameof(interfaceIndex));
        }
        var hop = string.IsNullOrEmpty(gateway)
            ? ""
            : " -NextHop " + Quote(gateway, prefix: false);
        return $"try{{New-NetRoute -DestinationPrefix {Quote(cidr, prefix: true)}{hop}"
            + $" -InterfaceIndex {interfaceIndex}"
            + " -PolicyStore ActiveStore -ErrorAction Stop|Out-Null}catch{ConvertTo-Json "
            + "-Compress -InputObject @{errorId=$_.FullyQualifiedErrorId};exit 1}";
    }

    /// <summary>Withdraws one route.</summary>
    /// <remarks>
    /// <c>-Confirm:$false</c> because Remove-NetRoute asks otherwise, and a non-interactive process
    /// has nobody to ask.
    /// </remarks>
    /// <exception cref="ArgumentException">the prefix is not a plain dotted-quad CIDR.</exception>
    public static string RemoveRouteScript(string cidr) =>
        $"try{{Remove-NetRoute -DestinationPrefix {Quote(cidr, prefix: true)}"
        + " -Confirm:$false -PolicyStore ActiveStore -ErrorAction Stop|Out-Null}catch{"
        + "ConvertTo-Json -Compress -InputObject @{errorId=$_.FullyQualifiedErrorId};exit 1}";

    /// <summary>Cuts a batched query's output into one entry per input.</summary>
    /// <remarks>
    /// Every query writes exactly one compressed JSON line, including an empty result, so the lines
    /// line up with the prefixes that were asked about.
    /// </remarks>
    public static List<string> SplitScriptLines(string? output)
    {
        var lines = new List<string>();
        if (output is null)
        {
            return lines;
        }
        foreach (var line in output.Replace("\r\n", "\n").Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.Length > 0)
            {
                lines.Add(trimmed);
            }
        }
        return lines;
    }

    /// <summary>Accepts a dotted-quad CIDR and nothing else.</summary>
    public static bool ValidPrefix(string? value)
    {
        var slash = value?.IndexOf('/') ?? -1;
        if (value is null || slash < 0)
        {
            return false;
        }
        var length = value[(slash + 1)..];
        if (length.Length is 0 or > 2 || !DigitsOnly(length) || int.Parse(length) > 32)
        {
            return false;
        }
        return ValidAddress(value[..slash]);
    }

    /// <summary>Accepts a dotted-quad IPv4 address and nothing else.</summary>
    public static bool ValidAddress(string? value)
    {
        if (value is null)
        {
            return false;
        }
        var octets = value.Split('.');
        if (octets.Length != 4)
        {
            return false;
        }
        foreach (var octet in octets)
        {
            if (octet.Length is 0 or > 3 || !DigitsOnly(octet) || int.Parse(octet) > 255)
            {
                return false;
            }
        }
        return true;
    }

    private static bool DigitsOnly(string value)
    {
        foreach (var character in value)
        {
            if (character is < '0' or > '9')
            {
                return false;
            }
        }
        return true;
    }

    private static string QuoteAll(IReadOnlyList<string> values, bool prefixes) =>
        string.Join(",", values.Select(value => Quote(value, prefixes)));

    /// <summary>Wraps a validated argument.</summary>
    /// <remarks>
    /// No escaping, deliberately. The allowed character set has no quote in it, so an escape step
    /// here would be unreachable code that reads like a second line of defence -- and a defence
    /// that cannot fire is worse than none, because it invites the first one to be relaxed.
    ///
    /// <para>The prefix comes from operator configuration and the bypass addresses from runtime
    /// discovery. On Linux they reach <c>ip</c> as argv entries that no shell ever sees; here they
    /// are concatenated into one command string, and this whitelist is what keeps that from being a
    /// command injection.</para>
    /// </remarks>
    private static string Quote(string? value, bool prefix)
    {
        var valid = prefix ? ValidPrefix(value) : ValidAddress(value);
        if (!valid)
        {
            throw new ArgumentException(
                "refusing to build a route command from this argument", nameof(value));
        }
        return "'" + value + "'";
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
