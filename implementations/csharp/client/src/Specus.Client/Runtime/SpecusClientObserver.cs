using Specus.Client.Configuration;

namespace Specus.Client.Runtime;

public interface ISpecusClientObserver
{
    void OnStatusChanged(SpecusClientStatusSnapshot snapshot) { }

    void OnRoutesChanged(SpecusClientRoutesSnapshot snapshot) { }

    void OnPeerMeshChanged(SpecusPeerMeshSnapshot snapshot) { }

    void OnClientMessage(ClientMessageSnapshot snapshot) { }

    /// <summary>
    /// Receives the raw client message body before display transformation
    /// (STMSG envelopes are already unwrapped). Return true to consume the
    /// message (e.g. file transfer frames) and suppress the normal chat entry.
    /// </summary>
    bool OnRawClientMessage(string fromClientName, string body) => false;
}

public sealed class SpecusClientStatusSnapshot
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

    public string? SpecusEndpoint { get; init; }

    public bool PeerMeshEnabled { get; init; }

    public string? VirtualIp { get; init; }

    public DateTimeOffset UpdatedAt { get; init; } = DateTimeOffset.Now;

    public static SpecusClientStatusSnapshot FromRuntime(
        SpecusRuntimeState? runtime,
        string phase,
        string detail,
        bool running,
        bool controlConnected,
        bool loggedIn)
    {
        return new SpecusClientStatusSnapshot
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
            SpecusEndpoint = runtime is null ? null : $"{runtime.NettyHost}:{runtime.NettyPort}",
            PeerMeshEnabled = runtime?.PeerMesh.Enabled == true,
            VirtualIp = runtime?.PeerMesh.VirtualIp,
            UpdatedAt = DateTimeOffset.Now,
        };
    }
}

public sealed class SpecusClientRoutesSnapshot
{
    public IReadOnlyList<TcpRouteSnapshot> TcpRoutes { get; init; } = Array.Empty<TcpRouteSnapshot>();

    public IReadOnlyList<HttpRouteSnapshot> HttpRoutes { get; init; } = Array.Empty<HttpRouteSnapshot>();

    public DateTimeOffset UpdatedAt { get; init; } = DateTimeOffset.Now;

    public static SpecusClientRoutesSnapshot FromRuntime(SpecusRuntimeState? runtime)
    {
        return FromRoutes(runtime?.SpecusConfigList, runtime?.HttpSpecusConfigList);
    }

    public static SpecusClientRoutesSnapshot FromRoutes(
        IEnumerable<SpecusConfigEntry>? tcpRoutes,
        IEnumerable<HttpSpecusConfigEntry>? httpRoutes)
    {
        return new SpecusClientRoutesSnapshot
        {
            TcpRoutes = tcpRoutes?
                .Select(item => new TcpRouteSnapshot
                {
                    PublicPort = item.Port,
                    TargetAddress = item.SpecusAddress,
                    TargetPort = item.SpecusPort,
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

public sealed class ClientMessageSnapshot
{
    public string Id { get; init; } = "";

    public string Direction { get; init; } = "";

    public string FromClientName { get; init; } = "";

    public string ToClientName { get; init; } = "";

    public string Message { get; init; } = "";

    public string Transport { get; init; } = "";

    public string Status { get; init; } = "";

    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.Now;
}

public sealed class ClientMessageSendResult
{
    public string MessageId { get; init; } = "";

    public string Transport { get; init; } = "";

    public bool FallbackUsed { get; init; }
}

public sealed class SpecusPeerMeshSnapshot
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

    public static SpecusPeerMeshSnapshot Disabled(string deviceMode, string deviceName)
    {
        return new SpecusPeerMeshSnapshot
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

    public bool MessageSendCapable { get; init; }

    public bool MessageReceiveCapable { get; init; }

    public bool MessageAttachmentsCapable { get; init; }

    public bool MessageMediaPreviewCapable { get; init; }

    public long MessageMaxAttachmentBytes { get; init; }

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
