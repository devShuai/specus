using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using Specus.Server.Persistence;

namespace Specus.Server.PeerMesh;

public sealed partial class PeerMeshService
{
    private Task<IDbContextTransaction> BeginPeerWriteAsync(CancellationToken ct)
    {
        if (_db.ChangeTracker.HasChanges()) throw new InvalidOperationException("Peer write requires a clean pending scope");
        return ClientOwnershipWrite.BeginAsync(_db, ct);
    }

    private Task<ManagementContext> LockPeerActorAsync(ManagementContext original, CancellationToken ct) =>
        ManagementWriteAuthorization.LockAsync(_db, _managementAuth, original, ct);

    private Task LockPeerRowAsync<T>(long id, ManagementContext context, CancellationToken ct) =>
        ClientOwnershipWrite.LockAsync<T>(_db, id, context.TenantId, ct);

    private async Task<Dictionary<long, ClientAccount>> LockPeerClientsAsync(ManagementContext context,
        IEnumerable<long> ids, CancellationToken ct)
    {
        var result = new Dictionary<long, ClientAccount>();
        // Reciprocal ACLs must take both clients in the same order as transfer/deletion.
        foreach (var id in ids.Distinct().Order())
        {
            await LockPeerRowAsync<ClientAccount>(id, context, ct).ConfigureAwait(false);
            var current = await _db.ClientAccounts.AsNoTracking().SingleOrDefaultAsync(c => c.Id == id && c.TenantId == context.TenantId, ct).ConfigureAwait(false);
            if (current is not null && current.TenantId == context.TenantId) result.Add(id, TrackPeerCurrent(current, id));
        }
        return result;
    }

    private static ClientAccount RequirePeerClient(IReadOnlyDictionary<long, ClientAccount> clients, long id) =>
        clients.TryGetValue(id, out var client) ? client : throw new ArgumentException("client not found");

    private T TrackPeerCurrent<T>(T current, long id) where T : class
    {
        var tracked = _db.ChangeTracker.Entries<T>().SingleOrDefault(e => Equals(e.Property("Id").CurrentValue, id));
        if (tracked is null) { _db.Attach(current); return current; }
        tracked.CurrentValues.SetValues(current);
        tracked.OriginalValues.SetValues(current);
        tracked.State = EntityState.Unchanged;
        return tracked.Entity;
    }
}
