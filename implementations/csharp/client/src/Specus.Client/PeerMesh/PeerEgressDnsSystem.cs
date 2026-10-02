using System.Diagnostics;
using System.Globalization;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.PeerMesh;

/// <summary>One network interface as the tunnel-interface test reads it.</summary>
/// <param name="Type">The interface type number: Windows' IfType, 53 virtual and 131 tunnel.</param>
/// <param name="PointToPoint">Linux: the interface carries <c>IFF_POINTOPOINT</c>.</param>
internal sealed record PeerEgressDnsInterface(string Name, int Type, bool PointToPoint, IReadOnlyList<string> Addresses);

/// <summary>
/// The machine, for the system DNS takeover: commands run without a shell, files, interfaces, and
/// the network fingerprint.
/// </summary>
/// <remarks>
/// Only the running client uses this. Every test drives <see cref="PeerEgressDnsTakeover"/> with a
/// fake instead, since running any of this would change the DNS of the machine the tests run on.
/// </remarks>
internal sealed class PeerEgressDnsSystem : IPeerEgressDnsHost
{
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(30);

    /// <summary>Linux's <c>IFF_POINTOPOINT</c> in <c>/sys/class/net/*/flags</c>.</summary>
    private const int LinuxPointToPoint = 0x10;

    public string Platform =>
        OperatingSystem.IsLinux() ? "linux"
        : OperatingSystem.IsMacOS() ? "macos"
        : OperatingSystem.IsWindows() ? "windows"
        : RuntimeInformation.OSDescription;

    public string Run(IReadOnlyList<string> argv)
    {
        var start = new ProcessStartInfo(argv[0])
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var argument in argv.Skip(1))
        {
            start.ArgumentList.Add(argument);
        }
        using var process = Process.Start(start) ?? throw new IOException($"{argv[0]} did not start");
        var stderr = process.StandardError.ReadToEndAsync();
        var stdout = process.StandardOutput.ReadToEnd();
        if (!process.WaitForExit(CommandTimeout))
        {
            process.Kill(entireProcessTree: true);
            throw new PeerEgressDnsCommandException(argv, string.Empty, $"{argv[0]} did not finish in {CommandTimeout.TotalSeconds} s");
        }
        var errors = stderr.GetAwaiter().GetResult();
        if (process.ExitCode != 0)
        {
            // What it said on stderr first: that is where a tool says why.
            throw new PeerEgressDnsCommandException(argv, errors.Trim().Length > 0 ? errors + "\n" + stdout : stdout,
                $"{argv[0]} exited {process.ExitCode}");
        }
        if (IsPowerShell(argv[0]) && errors.Trim().Length > 0)
        {
            // A script's exit code is its last statement's: in `A; Clear-DnsClientCache` a failed A
            // exits 0 and says so only on stderr.
            throw new PeerEgressDnsCommandException(argv, errors + "\n" + stdout, $"{argv[0]} reported errors");
        }
        return stdout;
    }

    private static bool IsPowerShell(string program)
    {
        var name = Path.GetFileNameWithoutExtension(program);
        return name.Equals("powershell", StringComparison.OrdinalIgnoreCase) || name.Equals("pwsh", StringComparison.OrdinalIgnoreCase);
    }

    public string? ReadFile(string path) => File.Exists(path) ? File.ReadAllText(path) : null;

    /// <summary>In place, so the file keeps its owner, its mode and whatever links to it.</summary>
    public void WriteFile(string path, string content) => File.WriteAllText(path, content);

    public bool IsSymlink(string path) => new FileInfo(path).LinkTarget is not null;

    public bool LinkExists(string name) =>
        NetworkInterface.GetAllNetworkInterfaces().Any(device => device.Name == name);

    public long InterfaceIndex(string name)
    {
        foreach (var device in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (device.Name == name && device.Supports(NetworkInterfaceComponent.IPv4))
            {
                return device.GetIPProperties().GetIPv4Properties()?.Index ?? 0;
            }
        }
        return 0;
    }

    public IReadOnlyList<string> TunnelInterfaceAddresses(string ownTunnel) =>
        TunnelAddresses(Platform, Interfaces(), ownTunnel);

    public string NetworkFingerprint(string ownTunnel)
    {
        IReadOnlyList<PeerEgressBindRoute> routes;
        var tunnelKey = ownTunnel;
        if (OperatingSystem.IsWindows())
        {
            routes = PeerEgressSocketBinder.Windows.Routes();
            tunnelKey = PeerEgressSocketBinder.Windows.InterfaceKey(ownTunnel);
        }
        else if (OperatingSystem.IsMacOS())
        {
            routes = new PeerEgressSocketBinder.MacosTable().Routes();
        }
        else
        {
            routes = LinuxDefaultRoutes(File.Exists("/proc/net/route") ? File.ReadAllText("/proc/net/route") : string.Empty);
        }
        var addresses = new List<uint>();
        foreach (var device in Interfaces())
        {
            foreach (var text in device.Addresses)
            {
                if (Ipv4Cidr.TryParseAddress(text, out var address))
                {
                    addresses.Add(address);
                }
            }
        }
        return Fingerprint(routes, tunnelKey, addresses);
    }

    /// <summary>Every interface with its IPv4 addresses, its type, and on Linux its point-to-point flag.</summary>
    private static List<PeerEgressDnsInterface> Interfaces()
    {
        var interfaces = new List<PeerEgressDnsInterface>();
        foreach (var device in NetworkInterface.GetAllNetworkInterfaces())
        {
            var addresses = device.GetIPProperties().UnicastAddresses
                .Where(address => address.Address.AddressFamily == AddressFamily.InterNetwork)
                .Select(address => address.Address.ToString())
                .ToList();
            var pointToPoint = false;
            if (OperatingSystem.IsLinux())
            {
                var flags = Path.Combine("/sys/class/net", device.Name, "flags");
                if (File.Exists(flags) && int.TryParse(File.ReadAllText(flags).Trim().Replace("0x", "", StringComparison.Ordinal),
                        NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var value))
                {
                    pointToPoint = (value & LinuxPointToPoint) != 0;
                }
            }
            interfaces.Add(new PeerEgressDnsInterface(device.Name, (int)device.NetworkInterfaceType, pointToPoint, addresses));
        }
        return interfaces;
    }

    /// <summary>
    /// The addresses of this machine's tunnel-type interfaces, this client's own excepted
    /// (protocol/spec/peer-egress-dns.md, section six): Linux interfaces flagged point-to-point, macOS
    /// interfaces named utun, ipsec or ppp, Windows interfaces of type 53 (virtual) or 131 (tunnel).
    /// </summary>
    internal static List<string> TunnelAddresses(string platform, IEnumerable<PeerEgressDnsInterface> interfaces, string ownTunnel)
    {
        var addresses = new List<string>();
        foreach (var device in interfaces)
        {
            if (device.Name == ownTunnel)
            {
                continue;
            }
            var tunnel = platform switch
            {
                "linux" => device.PointToPoint,
                "macos" => device.Name.StartsWith("utun", StringComparison.Ordinal)
                           || device.Name.StartsWith("ipsec", StringComparison.Ordinal)
                           || device.Name.StartsWith("ppp", StringComparison.Ordinal),
                "windows" => device.Type is 53 or 131,
                _ => false,
            };
            if (tunnel)
            {
                addresses.AddRange(device.Addresses);
            }
        }
        return addresses;
    }

    /// <summary>
    /// The network as the change check compares it: the interface the default route leaves by (the
    /// usable one with the lowest metric, the tunnel's own excepted) and every local IPv4 address in
    /// order. A different network has a different one of either.
    /// </summary>
    internal static string Fingerprint(IReadOnlyList<PeerEgressBindRoute> routes, string tunnelKey, IEnumerable<uint> addresses)
    {
        var defaultInterface = string.Empty;
        var best = long.MaxValue;
        foreach (var route in routes)
        {
            if (route.Prefix != "0.0.0.0/0" || !route.Usable || route.Interface.Length == 0 || route.Interface == tunnelKey)
            {
                continue;
            }
            if (route.Metric < best)
            {
                defaultInterface = route.Interface;
                best = route.Metric;
            }
        }
        return defaultInterface + "|" + string.Join(",", addresses.Distinct().Order().Select(Ipv4Cidr.FormatAddress));
    }

    /// <summary>
    /// The default routes in Linux's <c>/proc/net/route</c>: destination and mask zero, usable when
    /// flagged up. Addresses there are little-endian hexadecimal.
    /// </summary>
    internal static List<PeerEgressBindRoute> LinuxDefaultRoutes(string table)
    {
        var routes = new List<PeerEgressBindRoute>();
        foreach (var line in table.Split('\n').Skip(1))
        {
            var fields = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length < 8 || fields[1] != "00000000" || fields[7] != "00000000")
            {
                continue;
            }
            if (!int.TryParse(fields[3], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var flags)
                || !long.TryParse(fields[6], NumberStyles.Integer, CultureInfo.InvariantCulture, out var metric))
            {
                continue;
            }
            routes.Add(new PeerEgressBindRoute("0.0.0.0/0", fields[0], fields[2], metric, (flags & 0x1) != 0));
        }
        return routes;
    }
}
