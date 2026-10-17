using System.Globalization;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Specus.Server.Data;
using Specus.Server.Data.Conversion;
using Specus.Server.Data.Entities;
using Specus.Server.Persistence;

namespace Specus.Server.Management;

public interface IOwnerTransferReconciler
{
    Task ReconcileOwnershipAsync(string tenant, IReadOnlyList<long> clients, CancellationToken cancellationToken);
}

// Ownership/audit commit first. Each process incarnation independently reads that durable
// journal; hints only reduce latency. A receipt means current-state convergence succeeded,
// not that a remote client acknowledged delivery or that access keys were rotated.
public sealed class OwnerTransferNotifications(IServiceScopeFactory services,
    ILogger<OwnerTransferNotifications> logger, IHostApplicationLifetime? lifetime = null) : BackgroundService
{
    internal string NodeId { get; } = Guid.NewGuid().ToString("N");
    private readonly SemaphoreSlim _drain = new(1, 1);
    private readonly SemaphoreSlim _wake = new(0, 1);
    private long _after;

    internal void Committed()
    {
        try { _wake.Release(); } catch (SemaphoreFullException) { }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            if (lifetime is not null)
            {
                var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                using var registration = lifetime.ApplicationStarted.Register(() => ready.TrySetResult());
                await ready.Task.WaitAsync(stoppingToken).ConfigureAwait(false);
            }
            while (!stoppingToken.IsCancellationRequested)
            {
                try { await DrainAsync(stoppingToken).ConfigureAwait(false); }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { throw; }
                catch (Exception error) { logger.LogWarning("Ownership journal scan pending: error={ErrorType}", error.GetType().Name); }
                await _wake.WaitAsync(TimeSpan.FromMilliseconds(250), stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
    }

    internal async Task<int> DrainAsync(CancellationToken ct)
    {
        if (!await _drain.WaitAsync(0, ct).ConfigureAwait(false)) return 0;
        try
        {
            await using var scope = services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            async Task<List<ClientOwnerTransferAudit>> ReadAsync() => await db.ClientOwnerTransferAudits.AsNoTracking()
                .Where(a => a.Id > _after && !db.ClientOwnerTransferReceipts.Any(r => r.NodeId == NodeId && r.EventId == a.Id))
                .OrderBy(a => a.Id).Take(32).ToListAsync(ct).ConfigureAwait(false);
            var events = await ReadAsync().ConfigureAwait(false);
            // Fairness cursor only: lower IDs can commit late, and failed events must retry.
            if (events.Count == 0 && _after != 0) { _after = 0; events = await ReadAsync().ConfigureAwait(false); }
            var acknowledged = 0;
            foreach (var entry in events)
            {
                ct.ThrowIfCancellationRequested();
                _after = entry.Id;
                try
                {
                    var ids = ParseClients(entry.DetailJson);
                    if (string.IsNullOrWhiteSpace(entry.TenantId)) throw new InvalidDataException("missing ownership tenant");
                    await scope.ServiceProvider.GetRequiredService<IOwnerTransferReconciler>()
                        .ReconcileOwnershipAsync(entry.TenantId, ids, ct).ConfigureAwait(false);
                    await AcknowledgeAsync(db, entry, ct).ConfigureAwait(false);
                    acknowledged++;
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (Exception error)
                {
                    // Never print historical JSON, a connection string or a provider exception payload.
                    logger.LogWarning("Ownership reconciliation pending: event={EventId} error={ErrorType}", entry.Id, error.GetType().Name);
                }
            }
            return acknowledged;
        }
        finally { _drain.Release(); }
    }

    internal static IReadOnlyList<long> ParseClients(string json)
    {
        using var document = JsonDocument.Parse(json);
        if (document.RootElement.ValueKind != JsonValueKind.Object
            || !document.RootElement.TryGetProperty("affectedClientIds", out var array) || array.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("invalid ownership client list");
        var ids = new SortedSet<long>();
        foreach (var item in array.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Number || !item.TryGetInt64(out var id) || id is <= 0 or > ClientOwnerTransferPlan.MaxSafeId)
                throw new InvalidDataException("invalid ownership client id");
            ids.Add(id);
        }
        return ids.ToArray();
    }

    private async Task AcknowledgeAsync(SpecusDbContext db, ClientOwnerTransferAudit entry, CancellationToken ct)
    {
        await using var tx = await ClientOwnershipWrite.BeginAsync(db, ct).ConfigureAwait(false);
        await ClientOwnershipWrite.LockAsync<ClientOwnerTransferAudit>(db, entry.Id, entry.TenantId, ct).ConfigureAwait(false);
        var current = await db.ClientOwnerTransferAudits.AsNoTracking().SingleOrDefaultAsync(a => a.Id == entry.Id, ct).ConfigureAwait(false);
        if (current is null || current.TenantId != entry.TenantId || current.DetailJson != entry.DetailJson)
            throw new InvalidOperationException("ownership journal event changed");
        var id = NodeId + ":" + entry.Id.ToString(CultureInfo.InvariantCulture);
        var stamp = IsoDateTimeOffsetConverter.Format(DateTimeOffset.UtcNow);
        if (db.Database.ProviderName == "MySql.EntityFrameworkCore")
            await db.Database.ExecuteSqlInterpolatedAsync($"INSERT INTO client_owner_transfer_receipt (id,node_id,event_id,processed_at) VALUES ({id},{NodeId},{entry.Id},{stamp}) ON DUPLICATE KEY UPDATE id=id", ct).ConfigureAwait(false);
        else
            await db.Database.ExecuteSqlInterpolatedAsync($"INSERT INTO client_owner_transfer_receipt (id,node_id,event_id,processed_at) VALUES ({id},{NodeId},{entry.Id},{stamp}) ON CONFLICT(id) DO NOTHING", ct).ConfigureAwait(false);
        if (!await db.ClientOwnerTransferReceipts.AsNoTracking().AnyAsync(r => r.Id == id && r.NodeId == NodeId && r.EventId == entry.Id, ct).ConfigureAwait(false))
            throw new InvalidOperationException("ownership receipt identity mismatch");
        await tx.CommitAsync(ct).ConfigureAwait(false);
    }
}
