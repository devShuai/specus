using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
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

    private T TrackPeerCurrent<T>(T current, object id, string property = "Id") where T : class
    {
        var tracked = _db.ChangeTracker.Entries<T>().SingleOrDefault(e => Equals(e.Property(property).CurrentValue, id));
        if (tracked is null) { _db.Attach(current); return current; }
        tracked.CurrentValues.SetValues(current);
        tracked.OriginalValues.SetValues(current);
        tracked.State = EntityState.Unchanged;
        return tracked.Entity;
    }

    private T CopyPeerValues<T>(T current) where T : class, new()
    {
        var copy = new T();
        _db.Entry(copy).CurrentValues.SetValues(current);
        return copy;
    }

    private async Task EnsurePeerTenantSettingAsync<T>(T initial, ManagementContext context, CancellationToken ct) where T : class
    {
        // An absent row cannot be protected by SELECT FOR UPDATE on supported RC providers.
        // Atomic insert/no-op establishes the unique tenant row before locking and rereading it.
        var entity = _db.Model.FindEntityType(typeof(T))!;
        var store = StoreObjectIdentifier.Table(entity.GetTableName()!, entity.GetSchema());
        var sql = _db.GetService<ISqlGenerationHelper>();
        var (table, key) = ClientOwnershipWrite.Identifiers<T>(_db, "TenantId");
        var properties = entity.GetProperties().ToArray();
        var names = properties.Select((_, index) => "@p" + index).ToArray();
        var columns = properties.Select(property => sql.DelimitIdentifier(property.GetColumnName(store)!));
        var parameters = properties.Select((property, index) =>
        {
            var raw = property.PropertyInfo!.GetValue(initial);
            var converter = property.GetTypeMapping().Converter;
            return (names[index], converter is null ? raw : converter.ConvertToProvider(raw));
        }).ToArray();
        var conflict = _db.Database.ProviderName == "MySql.EntityFrameworkCore"
            ? $" ON DUPLICATE KEY UPDATE {key}={key}"
            : $" ON CONFLICT ({key}) DO NOTHING";
        await using var command = ClientOwnershipWrite.Command(_db,
            $"INSERT INTO {table} ({string.Join(',', columns)}) VALUES ({string.Join(',', names)})" + conflict, parameters);
        _ = await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        await ClientOwnershipWrite.LockAsync<T>(_db, context.TenantId, context.TenantId, ct, "TenantId").ConfigureAwait(false);
    }

    private async Task<PeerMeshServiceSharing?> LockPeerSharingAsync(ManagementContext context, bool create, CancellationToken ct)
    {
        if (create)
            await EnsurePeerTenantSettingAsync(new PeerMeshServiceSharing { TenantId = context.TenantId, UpdatedAt = DateTimeOffset.UtcNow }, context, ct).ConfigureAwait(false);
        else
            await ClientOwnershipWrite.LockAsync<PeerMeshServiceSharing>(_db, context.TenantId, context.TenantId, ct, "TenantId").ConfigureAwait(false);
        var current = await _db.PeerMeshServiceSharings.AsNoTracking().SingleOrDefaultAsync(row => row.TenantId == context.TenantId, ct).ConfigureAwait(false);
        if (current is not null && current.TenantId != context.TenantId) throw new InvalidOperationException("共享策略租户不匹配");
        if (create && current is null) throw new InvalidOperationException("共享策略行未建立");
        return current;
    }

    private async Task<(PeerMeshSharedService Row, ClientAccount? Parent)> LockSharedDefinitionAsync(ManagementContext context, long id, bool requireParent, CancellationToken ct)
    {
        var hint = await _db.PeerMeshSharedServices.AsNoTracking().SingleOrDefaultAsync(row => row.Id == id && row.TenantId == context.TenantId, ct).ConfigureAwait(false);
        if (hint is null || hint.TenantId != context.TenantId) throw new ArgumentException("service not found");
        var parents = await LockPeerClientsAsync(context, [hint.ClientId], ct).ConfigureAwait(false);
        var parent = parents.GetValueOrDefault(hint.ClientId);
        if (requireParent && parent is null) throw new ArgumentException("service not found");
        await LockPeerRowAsync<PeerMeshSharedService>(id, context, ct).ConfigureAwait(false);
        var current = await _db.PeerMeshSharedServices.AsNoTracking().SingleOrDefaultAsync(row => row.Id == id && row.TenantId == context.TenantId, ct).ConfigureAwait(false);
        if (current is null || current.TenantId != context.TenantId) throw new ArgumentException("service not found");
        if (current.ClientId != hint.ClientId) throw new InvalidOperationException("共享服务关联已变更，请刷新后重试");
        return (current, parent);
    }
}
