using ShuaiTunnel.Client.Configuration;

namespace ShuaiTunnel.Client.Runtime;

public interface ITunnelClientObserver
{
    void OnStatusChanged(TunnelClientStatusSnapshot snapshot) { }

    void OnRoutesChanged(TunnelClientRoutesSnapshot snapshot) { }

    void OnPeerMeshChanged(TunnelPeerMeshSnapshot snapshot) { }
}

public sealed class TunnelClientStatusSnapshot
{
    public bool Running { get; init; }

    public bool ControlConnected { get; init; }

    public bool LoggedIn { get; init; }

    public string Phase { get; init; } = "";

    public string Detail { get; init; } = "";

    public string? TenantId { get; init; }

    public long ClientId { get; init; }

    public string? ClientName { get; init; }

    public long ClientSessionId { get; init; }

    public string? TunnelEndpoint { get; init; }

    public bool PeerMeshEnabled { get; init; }

    public string? VirtualIp { get; init; }

    public DateTimeOffset UpdatedAt { get; init; } = DateTimeOffset.Now;

    public static TunnelClientStatusSnapshot FromRuntime(
        TunnelRuntimeState? runtime,
        string phase,
        string detail,
        bool running,
        bool controlConnected,
        bool loggedIn)
    {
        return new TunnelClientStatusSnapshot
        {
            Running = running,
            ControlConnected = controlConnected,
            LoggedIn = loggedIn,
            Phase = phase,
            Detail = detail,
            TenantId = runtime?.TenantId,
            ClientId = runtime?.ClientId ?? 0,
            ClientName = runtime?.ClientName,
            ClientSessionId = runtime?.ClientSessionId ?? 0,
            TunnelEndpoint = runtime is null ? null : $"{runtime.NettyHost}:{runtime.NettyPort}",
            PeerMeshEnabled = runtime?.PeerMesh.Enabled == true,
            VirtualIp = runtime?.PeerMesh.VirtualIp,
            UpdatedAt = DateTimeOffset.Now,
        };
    }
}

public sealed class TunnelClientRoutesSnapshot
{
    public IReadOnlyList<TcpRouteSnapshot> TcpRoutes { get; init; } = Array.Empty<TcpRouteSnapshot>();

    public IReadOnlyList<HttpRouteSnapshot> HttpRoutes { get; init; } = Array.Empty<HttpRouteSnapshot>();

    public DateTimeOffset UpdatedAt { get; init; } = DateTimeOffset.Now;

    public static TunnelClientRoutesSnapshot FromRuntime(TunnelRuntimeState? runtime)
    {
        return FromRoutes(runtime?.TunnelConfigList, runtime?.HttpTunnelConfigList);
    }

    public static TunnelClientRoutesSnapshot FromRoutes(
        IEnumerable<TunnelConfigEntry>? tcpRoutes,
        IEnumerable<HttpTunnelConfigEntry>? httpRoutes)
    {
        return new TunnelClientRoutesSnapshot
        {
            TcpRoutes = tcpRoutes?
                .Select(item => new TcpRouteSnapshot
                {
                    PublicPort = item.Port,
                    TargetAddress = item.TunnelAddress,
                    TargetPort = item.TunnelPort,
                })
                .OrderBy(item => item.PublicPort)
                .ToList()
                ?? [],
            HttpRoutes = httpRoutes?
                .Select(item => new HttpRouteSnapshot
                {
                    Route = item.Route,
                    TargetBaseUrl = item.TargetBaseUrl,
                })
                .OrderBy(item => item.Route, StringComparer.OrdinalIgnoreCase)
                .ToList()
                ?? [],
            UpdatedAt = DateTimeOffset.Now,
        };
    }
}

public sealed class TcpRouteSnapshot
{
    public int PublicPort { get; init; }

    public string TargetAddress { get; init; } = "";

    public int TargetPort { get; init; }

    public string Target => $"{TargetAddress}:{TargetPort}";
}

public sealed class HttpRouteSnapshot
{
    public string Route { get; init; } = "";

    public string TargetBaseUrl { get; init; } = "";
}

public sealed class TunnelPeerMeshSnapshot
{
    public bool Enabled { get; init; }

    public string? VirtualIp { get; init; }

    public string? Cidr { get; init; }

    public string DeviceMode { get; init; } = "";

    public string DeviceName { get; init; } = "";

    public string DeviceStatus { get; init; } = "";

    public IReadOnlyList<PeerRouteSnapshot> Peers { get; init; } = Array.Empty<PeerRouteSnapshot>();

    public IReadOnlyList<PeerSessionSnapshot> Sessions { get; init; } = Array.Empty<PeerSessionSnapshot>();

    public DateTimeOffset UpdatedAt { get; init; } = DateTimeOffset.Now;

    public static TunnelPeerMeshSnapshot Disabled(string deviceMode, string deviceName)
    {
        return new TunnelPeerMeshSnapshot
        {
            Enabled = false,
            DeviceMode = deviceMode,
            DeviceName = deviceName,
            DeviceStatus = "DISABLED",
            UpdatedAt = DateTimeOffset.Now,
        };
    }
}

public sealed class PeerRouteSnapshot
{
    public long ClientId { get; init; }

    public string? ClientName { get; init; }

    public string? VirtualIp { get; init; }

    public bool Online { get; init; }

    public int CandidateCount { get; init; }
}

public sealed class PeerSessionSnapshot
{
    public long SessionId { get; init; }

    public long PeerId { get; init; }

    public string? PeerName { get; init; }

    public string? PeerVirtualIp { get; init; }

    public string? PathType { get; init; }

    public string? RemoteEndpoint { get; init; }

    public long? RttMillis { get; init; }

    public DateTimeOffset ExpiresAt { get; init; }
}
