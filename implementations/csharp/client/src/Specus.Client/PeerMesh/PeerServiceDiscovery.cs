using System.Net.Sockets;
using Specus.Client.Configuration;

namespace Specus.Client.PeerMesh;

internal static class PeerServiceDiscovery
{
    public const int ProtocolVersion = 1;
    public static readonly string[] Applications = ["http", "https", "ssh", "tcp", "udp"];
    public static readonly TimeSpan CatalogTtl = TimeSpan.FromMinutes(5);

    public static bool Probe(LocalPeerService local, int timeoutMillis)
    {
        if (string.Equals(local.Transport, "udp", StringComparison.OrdinalIgnoreCase)
            || string.Equals(local.Application, "udp", StringComparison.OrdinalIgnoreCase))
        {
            return ProbeUdp(local.TargetHost, local.TargetPort, timeoutMillis);
        }
        return ProbeTcp(local.TargetHost, local.TargetPort, timeoutMillis);
    }

    public static bool ProbeTcp(string? host, int port, int timeoutMillis)
    {
        if (string.IsNullOrWhiteSpace(host) || port is < 1 or > 65535)
        {
            return false;
        }
        try
        {
            using var client = new TcpClient();
            var task = client.ConnectAsync(host, port);
            return task.Wait(Math.Max(50, timeoutMillis)) && client.Connected;
        }
        catch
        {
            return false;
        }
    }

    public static bool ProbeUdp(string? host, int port, int timeoutMillis)
    {
        if (string.IsNullOrWhiteSpace(host) || port is < 1 or > 65535)
        {
            return false;
        }
        try
        {
            using var client = new UdpClient();
            client.Client.ReceiveTimeout = Math.Max(50, timeoutMillis);
            client.Connect(host, port);
            client.Send([0], 1);
            return true;
        }
        catch
        {
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
