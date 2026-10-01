using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.PeerMesh;

/// <summary>
/// One step of taking the system's DNS over or giving it back: a command line run without a shell,
/// a file written, a file put back as <see cref="PeerEgressDnsTakeoverRules.RevertResolvConf"/>
/// decides, or a macOS service put back as <see cref="PeerEgressDnsTakeoverRules.RevertMacService"/>
/// decides. Exactly one of them is set.
/// </summary>
internal sealed record PeerEgressDnsStep(
    IReadOnlyList<string>? Argv = null,
    string? Write = null,
    string? Content = null,
    string? Restore = null,
    string? RestoreService = null);

/// <summary>What takes over, and what gives back; giving back is safe to run whatever part of taking over happened.</summary>
internal sealed record PeerEgressDnsPlan(IReadOnlyList<PeerEgressDnsStep> Apply, IReadOnlyList<PeerEgressDnsStep> Revert);

/// <summary>
/// The pure parts of the system DNS takeover (protocol/spec/peer-egress-dns.md, section six; shared
/// vector <c>peer-egress-dns-takeover-v1.json</c>): reading each platform's DNS settings out of what
/// its tools print, deciding whether they can be taken over and which upstreams to forward to, the
/// exact commands, and what giving back does when someone else changed the setting meanwhile.
/// </summary>
/// <remarks>
/// Nothing here runs a command or touches a file. That is <see cref="PeerEgressDnsTakeover"/>, behind
/// a host the tests replace; what has to come out the same in three languages is all here.
/// </remarks>
internal static class PeerEgressDnsTakeoverRules
{
    public const string PlatformResolved = "linux-resolved";
    public const string PlatformResolvConf = "linux-resolvconf";
    public const string PlatformMacos = "macos";
    public const string PlatformWindows = "windows";

    public const string NrptComment = "specus-peer-egress";
    public const string ResolvConfPath = "/etc/resolv.conf";

    /// <summary>What <c>/etc/resolv.conf</c> holds while taken over; giving back checks for exactly this.</summary>
    public const string ResolvConfWritten =
        "# Written by specus for peer egress DNS takeover. The original is kept in the journal\n"
        + "# and is put back when the client stops or when `egress dns restore` runs.\n"
        + "nameserver 198.18.0.1\n";

    /// <summary>systemd-resolved's stub listeners: a resolv.conf naming only these goes through it.</summary>
    public static readonly IReadOnlyList<string> ResolvedStubs = ["127.0.0.53", "127.0.0.54"];

    /// <summary>What <c>networksetup</c> takes back to mean "use the servers DHCP gives".</summary>
    public const string MacEmpty = "Empty";

    /// <summary>The DNS servers of every connected IPv4 interface, as JSON.</summary>
    public const string WindowsReadServers =
        "$up = @(Get-NetIPInterface -AddressFamily IPv4 -ConnectionState Connected | "
        + "Select-Object -ExpandProperty InterfaceIndex); "
        + "ConvertTo-Json -Compress -Depth 3 -InputObject @(Get-DnsClientServerAddress -AddressFamily IPv4 | "
        + "Where-Object { $up -contains $_.InterfaceIndex } | "
        + "Select-Object InterfaceAlias,InterfaceIndex,ServerAddresses)";

    /// <summary>Every NRPT rule, as JSON.</summary>
    public const string WindowsReadNrpt =
        "ConvertTo-Json -Compress -Depth 3 -InputObject @(Get-DnsClientNrptRule | "
        + "Select-Object Namespace,Comment,NameServers)";

    // Refusal reasons (section six, 开启前检查).
    public const string RefusedPoolRoute = "pool-route-not-installed";
    public const string RefusedLoopback = "system-dns-loopback";
    public const string RefusedVirtual = "system-dns-virtual";
    public const string RefusedNoUpstream = "no-upstream";
    public const string RefusedResolvConfManaged = "resolv-conf-managed";
    public const string RefusedNrptRoot = "nrpt-root-occupied";
    public const string RefusedUnsupported = "unsupported-platform";

    // Warnings when giving back finds someone else's change.
    public const string WarningResolvConfChanged = "resolv-conf-changed";
    public const string WarningServiceChanged = "service-dns-changed";

    /// <summary>
    /// A server as a tool prints it, without a DNS-over-TLS name (<c>1.1.1.1#one.one.one.one</c>)
    /// or an IPv6 zone (<c>fe80::1%eth0</c>).
    /// </summary>
    public static string StripServer(string text)
    {
        var cut = text.Split('#', 2)[0];
        return cut.Split('%', 2)[0].Trim();
    }

    private static readonly Regex ResolvectlLink = new(@"^Link \d+ \(([^)]*)\):(.*)$", RegexOptions.CultureInvariant);

    /// <summary>
    /// <c>resolvectl dns</c>: the global servers, then each link's in the order printed, skipping
    /// this client's own tunnel.
    /// </summary>
    public static List<string> ParseResolvectl(string? output, string tunnel)
    {
        var servers = new List<string>();
        foreach (var raw in Lines(output))
        {
            var line = raw.Trim();
            string rest;
            if (line.StartsWith("Global:", StringComparison.Ordinal))
            {
                rest = line["Global:".Length..];
            }
            else
            {
                var match = ResolvectlLink.Match(line);
                if (!match.Success || match.Groups[1].Value == tunnel)
                {
                    continue;
                }
                rest = match.Groups[2].Value;
            }
            foreach (var item in Fields(rest))
            {
                var server = StripServer(item);
                if (server.Length > 0)
                {
                    servers.Add(server);
                }
            }
        }
        return servers;
    }

    /// <summary><c>nameserver</c> lines in order; a comment starts with # or ; and runs to the end of the line.</summary>
    public static List<string> ParseResolvConf(string? text)
    {
        var servers = new List<string>();
        foreach (var raw in Lines(text))
        {
            var cut = raw.IndexOfAny(['#', ';']);
            var fields = Fields(cut < 0 ? raw : raw[..cut]);
            if (fields.Length >= 2 && fields[0] == "nameserver")
            {
                servers.Add(StripServer(fields[1]));
            }
        }
        return servers;
    }

    /// <summary>
    /// <c>networksetup -listallnetworkservices</c>: the first line explains the asterisk, and a
    /// service whose name starts with one is disabled and left alone.
    /// </summary>
    public static List<string> ParseMacServices(string? output)
    {
        var services = new List<string>();
        foreach (var line in Lines(output).Skip(1))
        {
            var name = line.TrimEnd('\r');
            if (name.Trim().Length == 0 || name.StartsWith('*'))
            {
                continue;
            }
            services.Add(name);
        }
        return services;
    }

    /// <summary>
    /// <c>networksetup -getdnsservers &lt;service&gt;</c>: one address per line, or a sentence saying
    /// there are none, recorded as <c>Empty</c>.
    /// </summary>
    public static List<string> ParseMacDnsServers(string? output)
    {
        var servers = new List<string>();
        foreach (var line in Lines(output))
        {
            var text = line.Trim();
            if (text.Length == 0)
            {
                continue;
            }
            if (!TryParseAddress(StripServer(text), out _))
            {
                return [MacEmpty];
            }
            servers.Add(text);
        }
        return servers.Count > 0 ? servers : [MacEmpty];
    }

    private static readonly Regex ScutilResolver = new(@"^resolver #\d+$", RegexOptions.CultureInvariant);
    private static readonly Regex ScutilField = new(@"^(\w+)(?:\[(\d+)\])?\s*:\s*(.*)$", RegexOptions.CultureInvariant);

    /// <summary>
    /// <c>scutil --dns</c>: the servers of the first unscoped resolver without a <c>domain</c> line,
    /// the one every name without a more specific resolver goes to.
    /// </summary>
    public static List<string> ParseScutil(string? output)
    {
        var resolvers = new List<(bool Domain, List<string> Servers)>();
        var current = -1;
        foreach (var line in Lines(output))
        {
            var text = line.Trim();
            if (text.StartsWith("DNS configuration (for scoped queries)", StringComparison.Ordinal))
            {
                break;
            }
            if (ScutilResolver.IsMatch(text))
            {
                resolvers.Add((false, []));
                current = resolvers.Count - 1;
                continue;
            }
            if (current < 0)
            {
                continue;
            }
            var match = ScutilField.Match(text);
            if (!match.Success)
            {
                continue;
            }
            switch (match.Groups[1].Value)
            {
                case "domain":
                    resolvers[current] = (true, resolvers[current].Servers);
                    break;
                case "nameserver":
                    resolvers[current].Servers.Add(StripServer(match.Groups[3].Value));
                    break;
            }
        }
        foreach (var (domain, servers) in resolvers)
        {
            if (!domain && servers.Count > 0)
            {
                return servers;
            }
        }
        return [];
    }

    /// <summary>
    /// What <see cref="WindowsReadServers"/> prints: one object or an array of
    /// <c>{InterfaceAlias, InterfaceIndex, ServerAddresses}</c>, where ServerAddresses is a string for
    /// one address, an array for several, and null or absent for none. The tunnel's own interface is
    /// skipped: its server is the responder.
    /// </summary>
    public static List<string> ParseWindowsServers(string? text, long tunnelIndex)
    {
        var servers = new List<string>();
        foreach (var entry in JsonObjects(text))
        {
            if (entry.TryGetProperty("InterfaceIndex", out var index) && index.ValueKind == JsonValueKind.Number
                && index.TryGetInt64(out var value) && value == tunnelIndex)
            {
                continue;
            }
            foreach (var address in StringOrStrings(entry, "ServerAddresses"))
            {
                var server = StripServer(address);
                if (server.Length > 0)
                {
                    servers.Add(server);
                }
            }
        }
        return servers;
    }

    /// <summary>
    /// What <see cref="WindowsReadNrpt"/> prints: whether a rule for the root namespace that is not
    /// ours is already there. Namespace is a string or an array of strings.
    /// </summary>
    public static bool ParseWindowsNrpt(string? text)
    {
        foreach (var entry in JsonObjects(text))
        {
            var comment = entry.TryGetProperty("Comment", out var value) && value.ValueKind == JsonValueKind.String
                ? value.GetString()
                : null;
            if (StringOrStrings(entry, "Namespace").Contains(".") && comment != NrptComment)
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>
    /// Which Linux way to take over: systemd-resolved only when it runs and applications reach it
    /// through its stub; otherwise <c>/etc/resolv.conf</c> is rewritten, but only a plain file. A
    /// symlink belongs to some other program, which may write over us at any time, and giving back
    /// could not say where to.
    /// </summary>
    public static (string? Mode, string? Reason) LinuxMode(bool resolvectlOk, IReadOnlyList<string> resolvConfServers,
        bool resolvConfIsSymlink)
    {
        if (resolvectlOk && resolvConfServers.Count > 0 && resolvConfServers.All(server => ResolvedStubs.Contains(server)))
        {
            return (PlatformResolved, null);
        }
        if (resolvConfIsSymlink)
        {
            return (null, RefusedResolvConfManaged);
        }
        return (PlatformResolvConf, null);
    }

    /// <summary>
    /// The upstreams to forward to, or why the takeover is refused. A server on loopback, in the
    /// pool or the mesh, or on one of this host's tunnel interfaces means somebody else already
    /// sits where the system sends its queries; recording it as the value to put back would, on
    /// giving back, point the system at something that may be gone. IPv4 only, deduplicated in the
    /// order read; an IPv6 server is not forwarded to and not a reason to refuse, loopback aside.
    /// </summary>
    public static (List<string>? Upstreams, string? Reason) ClassifyUpstreams(IEnumerable<string> servers,
        IReadOnlyCollection<string> virtualAddresses, Ipv4Cidr pool, Ipv4Cidr mesh)
    {
        var upstreams = new List<string>();
        foreach (var text in servers)
        {
            if (!TryParseAddress(StripServer(text), out var address))
            {
                continue;
            }
            if (IPAddress.IsLoopback(address))
            {
                return (null, RefusedLoopback);
            }
            if (address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            {
                continue;
            }
            var value = (uint)System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(address.GetAddressBytes());
            if (value == 0)
            {
                continue;
            }
            var dotted = Ipv4Cidr.FormatAddress(value);
            if (pool.Contains(value) || mesh.Contains(value) || virtualAddresses.Contains(dotted))
            {
                return (null, RefusedVirtual);
            }
            if (!upstreams.Contains(dotted))
            {
                upstreams.Add(dotted);
            }
        }
        return upstreams.Count == 0 ? (null, RefusedNoUpstream) : (upstreams, null);
    }

    /// <summary>A PowerShell script as a command line, run without a profile and without prompts.</summary>
    public static IReadOnlyList<string> PowerShell(string script) =>
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script];

    /// <summary>
    /// The commands that take over and the ones that give back, for a platform; null for one this
    /// build does not know.
    /// </summary>
    public static PeerEgressDnsPlan? Plan(string platform, string listen, string tunnel, IReadOnlyList<string>? services)
    {
        switch (platform)
        {
            case PlatformResolved:
                return new PeerEgressDnsPlan(
                    [Run("resolvectl", "dns", tunnel, listen), Run("resolvectl", "domain", tunnel, "~."), Run("resolvectl", "flush-caches")],
                    [Run("resolvectl", "revert", tunnel), Run("resolvectl", "flush-caches")]);
            case PlatformResolvConf:
                return new PeerEgressDnsPlan(
                    [new PeerEgressDnsStep(Write: ResolvConfPath, Content: ResolvConfWritten)],
                    [new PeerEgressDnsStep(Restore: ResolvConfPath)]);
            case PlatformMacos:
            {
                var names = services ?? [];
                PeerEgressDnsStep[] flush = [Run("dscacheutil", "-flushcache"), Run("killall", "-HUP", "mDNSResponder")];
                return new PeerEgressDnsPlan(
                    [.. names.Select(service => Run("networksetup", "-setdnsservers", service, listen)), .. flush],
                    [.. names.Select(service => new PeerEgressDnsStep(RestoreService: service)), .. flush]);
            }
            case PlatformWindows:
                return new PeerEgressDnsPlan(
                    [new PeerEgressDnsStep(Argv: PowerShell(
                        $"Add-DnsClientNrptRule -Namespace '.' -NameServers '{listen}' -Comment '{NrptComment}'; Clear-DnsClientCache"))],
                    [new PeerEgressDnsStep(Argv: PowerShell(
                        $"Get-DnsClientNrptRule | Where-Object {{ $_.Comment -eq '{NrptComment}' }} | "
                        + "Remove-DnsClientNrptRule -Force; Clear-DnsClientCache"))]);
            default:
                return null;
        }
    }

    /// <summary>
    /// Giving <c>/etc/resolv.conf</c> back: the original only if the file still holds what we wrote.
    /// Anything else was written by somebody after us, and theirs is kept, with a warning.
    /// </summary>
    public static (bool Restore, string? Warning) RevertResolvConf(string? current) =>
        current == ResolvConfWritten ? (true, null) : (false, WarningResolvConfChanged);

    /// <summary>
    /// Giving one macOS service back: only a service still pointing at the responder alone is put
    /// back, to exactly what it had, <c>Empty</c> included. Null command means keep, with the warning.
    /// </summary>
    public static (IReadOnlyList<string>? Command, string? Warning) RevertMacService(string service,
        IReadOnlyList<string> current, IReadOnlyList<string> original, string listen) =>
        current.Count == 1 && current[0] == listen
            ? ([.. new[] { "networksetup", "-setdnsservers", service }, .. original], null)
            : (null, WarningServiceChanged);

    private static PeerEgressDnsStep Run(params string[] argv) => new(Argv: argv);

    /// <summary>
    /// An address in the strict form tools print: four canonical decimal octets for IPv4, anything
    /// .NET reads with a colon for IPv6. The lenient forms <see cref="IPAddress.TryParse(string?, out IPAddress?)"/>
    /// also takes, such as a bare <c>1</c>, are words, not servers.
    /// </summary>
    private static bool TryParseAddress(string text, out IPAddress address)
    {
        address = IPAddress.None;
        if (text.Contains(':', StringComparison.Ordinal))
        {
            if (IPAddress.TryParse(text, out var six) && six.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                address = six;
                return true;
            }
            return false;
        }
        if (!Ipv4Cidr.TryParseAddress(text, out var value))
        {
            return false;
        }
        address = new IPAddress([(byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value]);
        return true;
    }

    private static string[] Lines(string? text) =>
        (text ?? string.Empty).Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');

    private static string[] Fields(string text) => text.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);

    /// <summary>A JSON value that is one object or an array of them; empty text is none.</summary>
    private static List<JsonElement> JsonObjects(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return [];
        }
        using var document = JsonDocument.Parse(text);
        var root = document.RootElement;
        var items = root.ValueKind == JsonValueKind.Array ? root.EnumerateArray().ToList() : [root];
        return [.. items.Where(item => item.ValueKind == JsonValueKind.Object).Select(item => item.Clone())];
    }

    private static List<string> StringOrStrings(JsonElement entry, string name)
    {
        if (!entry.TryGetProperty(name, out var value))
        {
            return [];
        }
        return value.ValueKind switch
        {
            JsonValueKind.String => [value.GetString()!],
            JsonValueKind.Array => [.. value.EnumerateArray().Where(item => item.ValueKind == JsonValueKind.String)
                .Select(item => item.GetString()!)],
            _ => [],
        };
    }
}
