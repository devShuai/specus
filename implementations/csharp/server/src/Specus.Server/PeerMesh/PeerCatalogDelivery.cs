using Microsoft.EntityFrameworkCore;
using Specus.Server.Data.Entities;

namespace Specus.Server.PeerMesh;

public sealed partial class PeerMeshService
{
    private PeerReceiver? CaptureCatalogPublisher(ClientAccount publisher, long sessionId, string? channel)
    {
        // Never let a new physical connection republish a previous connection's snapshot,
        // even when reconnect reused the persisted session ID.
        var origin = CapturePeerReceiver(publisher);
        return channel is not null && origin?.SessionId == sessionId && origin.Channel == channel ? origin : null;
    }

    private Task SendPreparedCatalogAsync(PeerReceiver receiver, ClientAccount publisherHint, long sessionId,
        long revision, IReadOnlyList<AdvertisedService> reported, DateTimeOffset expiresAt,
        PeerReceiver? origin, CancellationToken ct) => SendPreparedPeerPushAsync(receiver, async (recipient, token) =>
    {
        var publisher = origin is null ? null : await ReadPeerReceiverAsync(origin, token).ConfigureAwait(false);
        var visible = new List<AdvertisedService>();
        if (publisher is not null && expiresAt > DateTimeOffset.UtcNow
            && await EffectiveSharingAsync(publisher.Account, token).ConfigureAwait(false)
            && await CanPeerAsync(publisher.Account, recipient.Account, token).ConfigureAwait(false))
        {
            // Reports carry membership, not an authority to retain old definition values.
            // Rebuild the public fields from current SQL only after taking the wire turn.
            foreach (var service in reported)
            {
                var definition = await _db.PeerMeshSharedServices.AsNoTracking().SingleOrDefaultAsync(row =>
                    row.TenantId == origin!.Tenant && row.ClientId == origin.ClientId
                    && row.ServiceId == service.ServiceId, token).ConfigureAwait(false);
                if (definition is not { Enabled: true } || definition.TenantId != origin!.Tenant
                    || definition.ServiceId != service.ServiceId) continue;
                var allowed = DecodeClientIds(definition.AllowedClientIds);
                var canSee = string.Equals(definition.Visibility, "OWNER", StringComparison.OrdinalIgnoreCase)
                    ? publisher.Account.OwnerUsername == recipient.Account.OwnerUsername
                    : allowed.Count == 0 || allowed.Contains(recipient.Account.Id);
                if (canSee) visible.Add(FromDefinition(definition));
            }
            // A publisher invalidated while building may only withdraw this session's key.
            var latest = await ReadPeerReceiverAsync(origin!, token).ConfigureAwait(false);
            if (latest is null || latest.Account.OwnerUsername != publisher.Account.OwnerUsername
                || latest.Account.UpdatedAt != publisher.Account.UpdatedAt) visible.Clear();
        }
        return new PeerControlMessage
        {
            Type = TypeServiceCatalog,
            PublisherClientId = publisherHint.Id,
            PublisherClientName = publisher?.Account.ClientName ?? publisherHint.ClientName,
            PublisherSessionId = sessionId,
            Revision = revision,
            ExpiresAt = expiresAt.ToString("O"),
            Services = visible,
            CreatedAtMillis = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
        };
    }, ct);
}
