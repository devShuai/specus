using System.Collections.Concurrent;

namespace Specus.Server.PeerMesh;

/// <summary>
/// Process-wide, in-memory state for the session-scoped Peer service catalog. PeerMeshService itself remains
/// scoped because it owns an EF DbContext; this state must outlive an individual API/control-message scope.
/// A process restart intentionally starts with an empty catalog. Connected clients rebuild it by sending their
/// current full snapshot after reconnect/configuration refresh, while disconnect cleanup prevents old sessions
/// from leaking into a replacement process lifetime.
/// </summary>
public sealed class PeerMeshServiceState
{
    internal ConcurrentDictionary<(string TenantId, long ClientId, long SessionId), PeerMeshServiceCatalogSnapshot>
        ServiceCatalogs { get; } = new();

    internal ConcurrentDictionary<(string TenantId, long ClientId, long SessionId), long>
        ServiceCatalogRevisions { get; } = new();

    internal ConcurrentDictionary<(string TenantId, long ClientId, long SessionId), long>
        ServiceReportRevisions { get; } = new();

    internal ConcurrentQueue<PeerMeshAuditEvent> Audits { get; } = new();

    internal ConcurrentDictionary<long, ConcurrentQueue<long>> ServiceReportWindows { get; } = new();

    internal ConcurrentDictionary<(string TenantId, long ClientId, long SessionId), SemaphoreSlim>
        ServiceCatalogMutationGates { get; } = new();
}

internal sealed record PeerMeshServiceCatalogSnapshot(long Revision, string InstanceId,
    DateTimeOffset GeneratedAt, DateTimeOffset ExpiresAt, IReadOnlyList<AdvertisedService> Services,
    string PublisherClientName, IReadOnlyList<PeerServiceStats> Stats, IReadOnlyList<PeerMdnsCandidate> Mdns);
