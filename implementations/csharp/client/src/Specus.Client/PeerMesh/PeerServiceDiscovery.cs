using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Specus.Client.Configuration;

namespace Specus.Client.PeerMesh;

internal static class PeerServiceDiscovery
{
    // Version 2 adds publisher-side data-plane ACL enforcement.
    public const int ProtocolVersion = 2;
    public static readonly string[] Applications = ["http", "https", "ssh", "tcp", "udp"];
    public static readonly TimeSpan CatalogTtl = TimeSpan.FromMinutes(5);

    public static bool IsSourceAllowed(IPAddress address, LocalPeerService service) =>
        NormalizeAllowedPeerAddresses(service).Contains(NormalizeAddress(address));

    public static bool SameAllowedPeers(LocalPeerService left, LocalPeerService right) =>
        NormalizeAllowedPeerAddresses(left).SetEquals(NormalizeAllowedPeerAddresses(right));

    private static HashSet<IPAddress> NormalizeAllowedPeerAddresses(LocalPeerService service)
    {
        var addresses = new HashSet<IPAddress>();
        foreach (var raw in service.AllowedPeerVirtualIps ?? [])
        {
            if (IPAddress.TryParse(raw?.Trim(), out var parsed))
            {
                addresses.Add(NormalizeAddress(parsed));
            }
        }
        return addresses;
    }

    private static IPAddress NormalizeAddress(IPAddress address) =>
        address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

    public static bool Probe(LocalPeerService local, int timeoutMillis)
    {
        if (!IsLocalInterfaceTarget(local.TargetHost))
        {
            return false;
        }
        if (string.Equals(local.Transport, "udp", StringComparison.OrdinalIgnoreCase)
            || string.Equals(local.Application, "udp", StringComparison.OrdinalIgnoreCase))
        {
            return ProbeUdp(local.TargetHost, local.TargetPort, timeoutMillis);
        }
        return ProbeTcp(local.TargetHost, local.TargetPort, timeoutMillis);
    }

    public static bool ProbeTcp(string? host, int port, int timeoutMillis)
    {
        if (!TryResolveLocalInterfaceTarget(host, out var target) || port is < 1 or > 65535)
        {
            return false;
        }
        try
        {
            using var client = new TcpClient();
            var task = client.ConnectAsync(target, port);
            return task.Wait(Math.Max(50, timeoutMillis)) && client.Connected;
        }
        catch
        {
            return false;
        }
    }

    public static bool ProbeUdp(string? host, int port, int timeoutMillis)
    {
        if (!TryResolveLocalInterfaceTarget(host, out var target) || port is < 1 or > 65535)
        {
            return false;
        }
        try
        {
            using var client = new UdpClient();
            client.Client.ReceiveTimeout = Math.Max(50, timeoutMillis);
            client.Connect(target, port);
            client.Send([0], 1);
            var remote = new IPEndPoint(IPAddress.Any, 0);
            return client.Receive(ref remote).Length > 0;
        }
        catch
        {
            return false;
        }
    }

    public static bool IsLocalInterfaceTarget(string? host) => TryResolveLocalInterfaceTarget(host, out _);

    public static bool TryResolveLocalInterfaceTarget(string? host, out IPAddress address)
    {
        if (string.Equals(host?.Trim(), "localhost", StringComparison.OrdinalIgnoreCase))
        {
            address = IPAddress.Loopback;
            return true;
        }
        if (!IPAddress.TryParse(host?.Trim(), out var parsed))
        {
            address = IPAddress.None;
            return false;
        }
        parsed = NormalizeAddress(parsed);
        if (IPAddress.IsLoopback(parsed))
        {
            address = parsed;
            return true;
        }
        try
        {
            var found = NetworkInterface.GetAllNetworkInterfaces()
                .SelectMany(item => item.GetIPProperties().UnicastAddresses)
                .Select(item => NormalizeAddress(item.Address))
                .Contains(parsed);
            address = found ? parsed : IPAddress.None;
            return found;
        }
        catch (NetworkInformationException)
        {
            address = IPAddress.None;
            return false;
        }
    }

    public static string AccessUrl(string? virtualIp, AdvertisedService service)
    {
        if (string.IsNullOrWhiteSpace(virtualIp) || service is null)
        {
            return "";
        }
        var application = service.Application ?? "";
        if (application is "http" or "https")
        {
            var path = string.IsNullOrWhiteSpace(service.Path) ? "/" : service.Path;
            return $"{application}://{virtualIp}:{service.PublishedPort}{path}";
        }
        return $"{virtualIp}:{service.PublishedPort}";
    }
}
