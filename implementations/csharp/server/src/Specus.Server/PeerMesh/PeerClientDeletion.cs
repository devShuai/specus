using Microsoft.EntityFrameworkCore;
using Specus.Server.Data.Entities;

namespace Specus.Server.PeerMesh;

public sealed partial class PeerMeshService
{
    internal async Task<PendingPeerClientDeletion> ForgetClientReferencesAsync(ClientAccount account,
        CancellationToken cancellationToken)
    {
        if (_db.Database.CurrentTransaction is null)
            throw new InvalidOperationException("Client references must be removed in the deletion transaction");

        var tenant = account.TenantId;
        var id = account.Id;
        var now = DateTimeOffset.UtcNow;
        var sessions = await _db.PeerMeshSessions.Where(row => row.TenantId == tenant
                && row.Status != StatusClosed && (row.SourceClientId == id || row.TargetClientId == id))
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        foreach (var session in sessions)
        {
            // Cache eviction belongs after commit; MarkClosed also evicts caches immediately.
            session.Status = StatusClosed;
            session.ClosedAt ??= now;
            session.UpdatedAt = now;
        }
        await _db.PeerMeshAcls.Where(row => row.TenantId == tenant
                && (row.SourceClientId == id || row.TargetClientId == id))
            .ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);
        await _db.PeerMeshDevices.Where(row => row.TenantId == tenant && row.ClientId == id)
            .ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);
        await _db.PeerMeshEgressPolicies.Where(row => row.TenantId == tenant && row.EgressClientId == id)
            .ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);
        await _db.PeerMeshSharedServices.Where(row => row.TenantId == tenant && row.ClientId == id)
            .ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);

        var policies = await _db.PeerMeshEgressPolicies.Where(row => row.TenantId == tenant)
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        foreach (var policy in policies)
        {
            var allowed = DecodeClientIds(policy.AllowedConsumerClientIds);
            if (!allowed.Contains(id)) continue;
            policy.AllowedConsumerClientIds = EncodeClientIds(allowed.Where(value => value != id));
            policy.UpdatedAt = now;
        }
        var services = await _db.PeerMeshSharedServices.Where(row => row.TenantId == tenant)
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        foreach (var service in services)
        {
            var allowed = DecodeClientIds(service.AllowedClientIds);
            if (!allowed.Contains(id)) continue;
            var remaining = allowed.Where(value => value != id).ToArray();
            service.AllowedClientIds = EncodeClientIds(remaining);
            if (remaining.Length == 0 && !string.Equals(service.Visibility, "OWNER", StringComparison.OrdinalIgnoreCase))
                service.Enabled = false;
            service.UpdatedAt = now;
        }
        return new PendingPeerClientDeletion(tenant, id, account.ClientName,
            sessions.Select(SessionView).ToArray());
    }

    // The API calls this only after successful commit. Publication never needs a new database
    // transaction inside a commit callback and cannot turn a committed deletion into HTTP 500.
    internal void QueueClientDeletion(PendingPeerClientDeletion deletion) =>
        _state.ClientDeletions.Enqueue(deletion);

    internal async Task DrainClientDeletionsAsync(CancellationToken cancellationToken)
    {
        if (!await _state.ClientDeletionDispatchGate.WaitAsync(0, cancellationToken).ConfigureAwait(false)) return;
        try
        {
            for (var count = 0; count < 64 && _state.ClientDeletions.TryDequeue(out var deletion); count++)
            {
                try
                {
                    await DispatchClientDeletionAsync(deletion, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception error)
                {
                    _state.ClientDeletions.Enqueue(deletion);
                    if (error is OperationCanceledException && cancellationToken.IsCancellationRequested) throw;
                    _logger.LogWarning(error, "Peer cleanup notification for deleted client {ClientId} failed; retrying",
                        deletion.ClientId);
                    return;
                }
            }
        }
        finally
        {
            _state.ClientDeletionDispatchGate.Release();
        }
    }

    private async Task DispatchClientDeletionAsync(PendingPeerClientDeletion deletion,
        CancellationToken cancellationToken)
    {
        var keys = _serviceCatalogs.Keys.Concat(_serviceCatalogRevisions.Keys).Concat(_serviceReportRevisions.Keys)
            .Concat(_serviceCatalogMutationGates.Keys)
            .Where(key => key.TenantId == deletion.TenantId && key.ClientId == deletion.ClientId).Distinct().ToArray();
        foreach (var key in keys)
        {
            var gate = CatalogMutationGate(key);
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                // Retain the withdrawal revision in the queued event before removing state.
                // A failed socket write must not make the next attempt forget what to withdraw.
                if (!deletion.Withdrawals.ContainsKey(key))
                    deletion.Withdrawals[key] = NextCatalogRevision(key);
                _serviceCatalogs.TryRemove(key, out _);
                _serviceCatalogRevisions.TryRemove(key, out _);
                _serviceReportRevisions.TryRemove(key, out _);
                _serviceReportWindows.TryRemove(key.SessionId, out _);
            }
            finally { gate.Release(); }
        }
        foreach (var session in deletion.ClosedSessions) RemoveRelaySession(session.Id);

        var recipients = await _db.ClientAccounts.AsNoTracking().Where(row => row.TenantId == deletion.TenantId)
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        List<Exception> failures = [];
        async Task Attempt(Func<Task> action)
        {
            try { await action().ConfigureAwait(false); }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception error) { failures.Add(error); }
        }
        foreach (var recipient in recipients)
        {
            var connection = _sessions.Find(recipient.ClientName);
            if (connection is not null && !connection.Lifetime.IsCancellationRequested)
            {
                foreach (var session in deletion.ClosedSessions.Where(row =>
                             row.SourceClientId == recipient.Id || row.TargetClientId == recipient.Id))
                {
                    await Attempt(async () => await SendSignalAsync(connection, "server", recipient.ClientName,
                        new PeerControlMessage
                        {
                            Type = TypeClose,
                            SessionId = session.Id,
                            SourceClientId = session.SourceClientId,
                            SourceClientName = session.SourceClientName,
                            TargetClientId = session.TargetClientId,
                            TargetClientName = session.TargetClientName,
                            Status = StatusClosed,
                            Reason = "client-deleted",
                            CreatedAtMillis = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        }, cancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
                }
                foreach (var withdrawal in deletion.Withdrawals)
                {
                    await Attempt(async () => await SendSignalAsync(connection, "server", recipient.ClientName,
                        new PeerControlMessage
                        {
                            Type = TypeServiceCatalog,
                            PublisherClientId = deletion.ClientId,
                            PublisherClientName = deletion.ClientName,
                            PublisherSessionId = withdrawal.Key.SessionId,
                            Revision = withdrawal.Value,
                            Services = [],
                            ExpiresAt = DateTimeOffset.UtcNow.ToString("O"),
                            CreatedAtMillis = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        }, cancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
                }
            }
            await Attempt(() => PushConfigAsync(recipient, cancellationToken)).ConfigureAwait(false);
            await Attempt(() => PushRosterAsync(recipient, cancellationToken)).ConfigureAwait(false);
            await Attempt(() => PushEgressAsync(recipient, cancellationToken)).ConfigureAwait(false);
        }
        await Attempt(() => OnAuthorizationChangedAsync(deletion.TenantId, cancellationToken)).ConfigureAwait(false);
        if (failures.Count > 0) throw new AggregateException(failures);
        foreach (var key in deletion.Withdrawals.Keys) _serviceCatalogMutationGates.TryRemove(key, out _);
    }
}

internal sealed record PendingPeerClientDeletion(string TenantId, long ClientId, string ClientName,
    IReadOnlyList<PeerMeshSessionView> ClosedSessions)
{
    internal Dictionary<(string TenantId, long ClientId, long SessionId), long> Withdrawals { get; } = new();
}
