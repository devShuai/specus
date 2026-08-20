using System.Collections.Concurrent;

namespace Specus.Server.PeerMesh;

/// <summary>
/// Process-wide state for the session-scoped Peer service catalog. PeerMeshService itself remains
/// scoped because it owns an EF DbContext; this state must outlive an individual API/control-message scope.
/// </summary>
public sealed class PeerMeshServiceState
{
    internal ConcurrentDictionary<(string TenantId, long ClientId, long SessionId), PeerMeshServiceCatalogSnapshot>
        ServiceCatalogs { get; } = new();

    internal ConcurrentDictionary<(string TenantId, long ClientId, long SessionId), long>
        ServiceCatalogRevisions { get; } = new();

    internal ConcurrentQueue<PeerMeshAuditEvent> Audits { get; } = new();

    internal ConcurrentDictionary<long, ConcurrentQueue<long>> ServiceReportWindows { get; } = new();
}

internal sealed record PeerMeshServiceCatalogSnapshot(long Revision, string InstanceId,
    DateTimeOffset GeneratedAt, DateTimeOffset ExpiresAt, IReadOnlyList<AdvertisedService> Services,
    string PublisherClientName, IReadOnlyList<PeerServiceStats> Stats, IReadOnlyList<PeerMdnsCandidate> Mdns);
