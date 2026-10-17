using Microsoft.EntityFrameworkCore;
using Specus.Server.Data.Conversion;
using Specus.Server.Data.Entities;
using Specus.Server.Persistence;

namespace Specus.Server.PeerMesh;

public sealed partial class PeerMeshService
{
    public async Task ReconcileOwnershipAsync(string tenant, IReadOnlyList<long> clients, CancellationToken ct)
    {
        // Empty credential groups are not a request to reset the entire tenant.
        if (clients.Count == 0) return;
        if (_db.ChangeTracker.HasChanges()) throw new InvalidOperationException("ownership reconciliation requires a clean pending scope");
        var rows = new Dictionary<long, PeerMeshSession>();
        foreach (var chunk in clients.Distinct().Chunk(250))
        {
            if (chunk.Any(id => id <= 0)) throw new ArgumentException("invalid ownership client id");
            // Include CLOSED history: another node may have closed SQL while this node
            // still holds an old cache or failed to notify its own connected clients.
            foreach (var row in await _db.PeerMeshSessions.AsNoTracking().Where(s => s.TenantId == tenant
                && (chunk.Contains(s.SourceClientId) || chunk.Contains(s.TargetClientId))).ToListAsync(ct).ConfigureAwait(false))
                if (row.TenantId == tenant) rows[row.Id] = row;
        }
        _state.InvalidateRelayAuthorizations();
        var closed = new List<PeerMeshSessionView>();
        try
        {
            foreach (var hint in rows.Values.OrderBy(s => s.Id))
            {
                await using var tx = await ClientOwnershipWrite.BeginAsync(_db, ct).ConfigureAwait(false);
                foreach (var id in new[] { hint.SourceClientId, hint.TargetClientId }.Distinct().Order())
                    await ClientOwnershipWrite.LockAsync<ClientAccount>(_db, id, tenant, ct).ConfigureAwait(false);
                await ClientOwnershipWrite.LockAsync<PeerMeshSession>(_db, hint.Id, tenant, ct).ConfigureAwait(false);
                var current = await _db.PeerMeshSessions.AsNoTracking().SingleOrDefaultAsync(s => s.Id == hint.Id && s.TenantId == tenant, ct).ConfigureAwait(false);
                if (current is null || current.TenantId != tenant) { await tx.CommitAsync(ct).ConfigureAwait(false); continue; }
                if (current.SourceClientId != hint.SourceClientId || current.TargetClientId != hint.TargetClientId)
                    throw new InvalidOperationException("ownership session participants changed");
                var source = await _db.ClientAccounts.AsNoTracking().SingleOrDefaultAsync(a => a.Id == current.SourceClientId && a.TenantId == tenant, ct).ConfigureAwait(false);
                var target = await _db.ClientAccounts.AsNoTracking().SingleOrDefaultAsync(a => a.Id == current.TargetClientId && a.TenantId == tenant, ct).ConfigureAwait(false);
                var allowed = source is { Enabled: true } && source.TenantId == tenant
                    && target is { Enabled: true } && target.TenantId == tenant
                    && await CanPeerAsync(source, target, ct).ConfigureAwait(false);
                if (current.Status != StatusClosed && (!allowed || current.ExpiresAt <= DateTimeOffset.UtcNow))
                {
                    var now = DateTimeOffset.UtcNow;
                    var stamp = IsoDateTimeOffsetConverter.Format(now);
                    await _db.Database.ExecuteSqlInterpolatedAsync($"UPDATE peer_mesh_session SET status={StatusClosed},closed_at=COALESCE(closed_at,{stamp}),updated_at={stamp} WHERE id={current.Id} AND tenant_id={tenant} AND status<>{StatusClosed}", ct).ConfigureAwait(false);
                    current.Status = StatusClosed; current.ClosedAt ??= now; current.UpdatedAt = now;
                }
                if (current.Status == StatusClosed) closed.Add(SessionView(current));
                await tx.CommitAsync(ct).ConfigureAwait(false);
            }
        }
        finally { _state.InvalidateRelayAuthorizations(); }
        // Network work never runs under the ownership/session transaction. Failures leave
        // the durable event unacknowledged; retry re-evaluates CURRENT policy, not old owners.
        var failures = new List<Exception>();
        async Task Attempt(Func<CancellationToken, Task> action)
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(2));
            try { await action(timeout.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception error) { failures.Add(error); }
        }
        foreach (var item in closed)
        {
            RemoveRelaySession(item.Id);
            await Attempt(token => SendCloseAsync(item, token, "owner-transfer")).ConfigureAwait(false);
        }
        var accounts = await _db.ClientAccounts.AsNoTracking().Where(a => a.TenantId == tenant).ToListAsync(ct).ConfigureAwait(false);
        foreach (var account in accounts)
        {
            if (account.TenantId != tenant) continue;
            if (CapturePeerReceiver(account) is null) continue;
            await Attempt(token => PushConfigAsync(account, token)).ConfigureAwait(false);
            await Attempt(token => PushRosterAsync(account, token)).ConfigureAwait(false);
            await Attempt(token => PushEgressAsync(account, token)).ConfigureAwait(false);
        }
        try { await OnAuthorizationChangedAsync(tenant, ct, TimeSpan.FromSeconds(2)).ConfigureAwait(false); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception error) { failures.Add(error); }
        if (failures.Count > 0) throw new AggregateException(failures);
    }
}
