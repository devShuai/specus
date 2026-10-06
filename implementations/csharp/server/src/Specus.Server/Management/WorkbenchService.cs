using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Specus.Server.Data;
using Specus.Server.Data.Entities;

namespace Specus.Server.Management;

/// <summary>
/// The three service kinds a workbench reference can name, in the fixed order that breaks ties
/// (protocol/spec/service-workbench.md 4.1 and 6.2).
/// </summary>
public static class WorkbenchKinds
{
    public const string HttpRoute = "http-route";
    public const string TcpMapping = "tcp-mapping";
    public const string PeerService = "peer-service";

    /// <summary>Exact, case-sensitive match: <c>HTTP-ROUTE</c> or <c>route</c> is not a kind.</summary>
    public static bool IsKnown(string? kind) => kind is HttpRoute or TcpMapping or PeerService;

    public static int Order(string kind) => kind switch
    {
        HttpRoute => 0,
        TcpMapping => 1,
        PeerService => 2,
        _ => 3,
    };
}

public static class WorkbenchLists
{
    public const string Favorite = "favorite";
    public const string Recent = "recent";
}

public static class WorkbenchCodes
{
    public const string RequestInvalid = "WORKBENCH_REQUEST_INVALID";
    public const string RateLimited = "WORKBENCH_RATE_LIMITED";
    public const string Unavailable = "WORKBENCH_UNAVAILABLE";
    public const string TargetNotFound = "WORKBENCH_TARGET_NOT_FOUND";
    public const string FavoritesFull = "WORKBENCH_FAVORITES_FULL";
}

/// <summary>
/// The one millisecond clock the workbench reads: the service stamps and filters with it, the
/// rate limiter and the retention sweep measure with it. Its own type rather than the shared
/// <see cref="TimeProvider"/> registration so a test can move workbench time without moving the
/// clock token expiry and every other service read.
/// </summary>
public class WorkbenchClock
{
    private readonly TimeProvider _time;

    public WorkbenchClock(TimeProvider time)
    {
        _time = time;
    }

    public long NowMs() => _time.GetUtcNow().ToUnixTimeMilliseconds();
}

/// <summary>
/// GCRA limiter for the two growth operations (adding a favourite, recording an open), one key
/// per identity: interval 1000 ms, burst 30, tolerance (burst - 1) * interval. A refused request
/// consumes nothing; an admitted one costs even when it then fails. In memory and per instance,
/// like the other limiters, with at most <see cref="MaxKeys"/> keys.
/// </summary>
public sealed class WorkbenchRateLimiter
{
    public const long IntervalMs = 1_000;
    public const int Burst = 30;
    public const long ToleranceMs = (Burst - 1) * IntervalMs;
    public const int MaxKeys = 10_000;

    private readonly Dictionary<string, long> _tat = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    /// <summary>
    /// Admits or refuses one growth request of (<paramref name="tenantId"/>,
    /// <paramref name="username"/>) at <paramref name="nowMs"/>. On refusal
    /// <paramref name="retryAfterSeconds"/> is the wait in whole seconds, rounded up, at least 1.
    /// </summary>
    public bool TryAcquire(string tenantId, string username, long nowMs, out int retryAfterSeconds)
    {
        var key = tenantId + "\n" + username;
        lock (_gate)
        {
            if (_tat.TryGetValue(key, out var tat))
            {
                var waitMs = Math.Max(0, tat - ToleranceMs - nowMs);
                if (waitMs > 0)
                {
                    retryAfterSeconds = (int)Math.Max(1, (waitMs + 999) / 1000);
                    return false;
                }
                _tat[key] = Math.Max(tat, nowMs) + IntervalMs;
                retryAfterSeconds = 0;
                return true;
            }

            if (_tat.Count >= MaxKeys)
            {
                // An entry whose TAT is not after now behaves exactly like an absent one, so it can
                // go whenever room is needed. If every entry is still live, refuse the newcomer.
                foreach (var stale in _tat.Where(entry => entry.Value <= nowMs).Select(entry => entry.Key)
                             .ToList())
                {
                    _tat.Remove(stale);
                }
                if (_tat.Count >= MaxKeys)
                {
                    retryAfterSeconds = 1;
                    return false;
                }
            }
            _tat[key] = nowMs + IntervalMs;
            retryAfterSeconds = 0;
            return true;
        }
    }

    /// <summary>Forgets every key. Tests start each scenario from an empty limiter.</summary>
    public void Reset()
    {
        lock (_gate)
        {
            _tat.Clear();
        }
    }
}

public sealed record WorkbenchLimits(int MaxFavorites, int MaxRecents, int RecentRetentionDays);

public sealed record WorkbenchFavoriteView(string Kind, long Id, string AddedAt);

public sealed record WorkbenchRecentView(string Kind, long Id, string VisitedAt);

public sealed record WorkbenchDocument(
    int SchemaVersion,
    WorkbenchLimits Limits,
    IReadOnlyList<WorkbenchFavoriteView> Favorites,
    IReadOnlyList<WorkbenchRecentView> Recents);

public sealed record WorkbenchError(string Code, string Error);

/// <summary>What one workbench operation produced: a document (200) or a refusal code.</summary>
public sealed record WorkbenchResult(int StatusCode, WorkbenchDocument? Document, string? Code)
{
    public static WorkbenchResult Ok(WorkbenchDocument document) => new(StatusCodes.Status200OK, document, null);

    public static WorkbenchResult Refused(int statusCode, string code) => new(statusCode, null, code);
}

/// <summary>
/// Favourites and recent opens of one management identity (protocol/spec/service-workbench.md).
/// The identity is the authenticated <see cref="ManagementContext"/>'s tenant and canonical
/// username; nothing in a request can name another one, so no caller -- administrators included --
/// can read or change someone else's lists. Every request reads the database; nothing is cached.
/// </summary>
public sealed class WorkbenchService
{
    public const int SchemaVersion = 1;
    public const int MaxFavorites = 50;
    public const int MaxRecents = 20;
    public const int RecentRetentionDays = 30;
    public const long RecentRetentionMs = RecentRetentionDays * 24L * 3600 * 1000;
    public const long MaxObjectId = 9_007_199_254_740_991L;

    private static readonly WorkbenchLimits Limits = new(MaxFavorites, MaxRecents, RecentRetentionDays);

    private readonly SpecusDbContext _db;
    private readonly WorkbenchClock _clock;
    private readonly ILogger<WorkbenchService> _logger;

    public WorkbenchService(SpecusDbContext db, WorkbenchClock clock, ILogger<WorkbenchService> logger)
    {
        _db = db;
        _clock = clock;
        _logger = logger;
    }

    /// <summary>
    /// Decimal ASCII digits without sign, whitespace or leading zero, 1..2^53-1. The path segment
    /// is checked as text so <c>042</c> or <c>+1</c> can never be read as a valid id.
    /// </summary>
    public static bool TryParseObjectId(string? text, out long id)
    {
        id = 0;
        if (string.IsNullOrEmpty(text) || text.Length > 16 || text[0] == '0')
        {
            return false;
        }
        foreach (var c in text)
        {
            if (c is < '0' or > '9')
            {
                return false;
            }
        }
        var value = long.Parse(text, NumberStyles.None, CultureInfo.InvariantCulture);
        if (value > MaxObjectId)
        {
            return false;
        }
        id = value;
        return true;
    }

    /// <summary>RFC 3339 UTC with exactly three fractional digits.</summary>
    public static string FormatInstant(long epochMs) =>
        DateTimeOffset.FromUnixTimeMilliseconds(epochMs).UtcDateTime
            .ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);

    /// <summary>Reads the caller's two lists. Never writes: expired and over-bound rows are only filtered.</summary>
    public async Task<WorkbenchResult> GetAsync(ManagementContext context, CancellationToken cancellationToken)
    {
        var now = _clock.NowMs();
        try
        {
            return WorkbenchResult.Ok(await ReadDocumentAsync(context, now, cancellationToken)
                .ConfigureAwait(false));
        }
        catch (Exception error) when (IsStoreFailure(error, cancellationToken))
        {
            return Unavailable(context, "get");
        }
    }

    /// <summary>
    /// Adds a favourite. The caller has passed validation and the rate limiter already; the store
    /// is touched before the visibility check so a broken store answers 503 whatever the target.
    /// </summary>
    public async Task<WorkbenchResult> AddFavoriteAsync(ManagementContext context, string kind, long id,
        CancellationToken cancellationToken)
    {
        var now = _clock.NowMs();
        try
        {
            await using var transaction = await _db.Database.BeginTransactionAsync(cancellationToken)
                .ConfigureAwait(false);
            var favorites = await IdentityRows(context, WorkbenchLists.Favorite)
                .Select(row => new { row.Kind, row.ObjectId })
                .ToListAsync(cancellationToken)
                .ConfigureAwait(false);
            if (!await IsVisibleAsync(context, kind, id, cancellationToken).ConfigureAwait(false))
            {
                return NotFound();
            }
            if (!favorites.Any(row => row.Kind == kind && row.ObjectId == id))
            {
                // An explicit choice is never evicted: a full list refuses instead. Stores that
                // cannot serialize two concurrent adds may end one over the bound; reads still return
                // every favourite and adding stays refused until the list is below it.
                if (favorites.Count >= MaxFavorites)
                {
                    return WorkbenchResult.Refused(StatusCodes.Status409Conflict, WorkbenchCodes.FavoritesFull);
                }
                await InsertFavoriteAsync(context, kind, id, now, cancellationToken).ConfigureAwait(false);
            }
            return await FinishWriteAsync(context, now, transaction, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception error) when (IsStoreFailure(error, cancellationToken))
        {
            return Unavailable(context, "add-favorite");
        }
    }

    /// <summary>
    /// Records an explicit open. One row per reference; a clock behind the stored time (another
    /// instance) never moves the entry back.
    /// </summary>
    public async Task<WorkbenchResult> RecordVisitAsync(ManagementContext context, string kind, long id,
        CancellationToken cancellationToken)
    {
        var now = _clock.NowMs();
        try
        {
            await using var transaction = await _db.Database.BeginTransactionAsync(cancellationToken)
                .ConfigureAwait(false);
            _ = await IdentityRows(context, WorkbenchLists.Recent)
                .AnyAsync(cancellationToken)
                .ConfigureAwait(false);
            if (!await IsVisibleAsync(context, kind, id, cancellationToken).ConfigureAwait(false))
            {
                return NotFound();
            }
            await UpsertVisitAsync(context, kind, id, now, cancellationToken).ConfigureAwait(false);
            return await FinishWriteAsync(context, now, transaction, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception error) when (IsStoreFailure(error, cancellationToken))
        {
            return Unavailable(context, "record-visit");
        }
    }

    /// <summary>
    /// Removes one reference of the caller's list. No visibility check: a reference the caller can
    /// no longer see must still be removable. Absent is not an error.
    /// </summary>
    public async Task<WorkbenchResult> RemoveAsync(ManagementContext context, string list, string kind, long id,
        CancellationToken cancellationToken)
    {
        var now = _clock.NowMs();
        try
        {
            await using var transaction = await _db.Database.BeginTransactionAsync(cancellationToken)
                .ConfigureAwait(false);
            await IdentityRows(context, list)
                .Where(row => row.Kind == kind && row.ObjectId == id)
                .ExecuteDeleteAsync(cancellationToken)
                .ConfigureAwait(false);
            return await FinishWriteAsync(context, now, transaction, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception error) when (IsStoreFailure(error, cancellationToken))
        {
            return Unavailable(context,
                list == WorkbenchLists.Favorite ? "remove-favorite" : "remove-recent");
        }
    }

    /// <summary>Deletes every row of the caller's list.</summary>
    public async Task<WorkbenchResult> ClearAsync(ManagementContext context, string list,
        CancellationToken cancellationToken)
    {
        var now = _clock.NowMs();
        try
        {
            await using var transaction = await _db.Database.BeginTransactionAsync(cancellationToken)
                .ConfigureAwait(false);
            await IdentityRows(context, list)
                .ExecuteDeleteAsync(cancellationToken)
                .ConfigureAwait(false);
            return await FinishWriteAsync(context, now, transaction, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception error) when (IsStoreFailure(error, cancellationToken))
        {
            return Unavailable(context,
                list == WorkbenchLists.Favorite ? "clear-favorites" : "clear-recents");
        }
    }

    /// <summary>
    /// The global retention sweep: deletes every identity's recent entries that are 30 days old or
    /// older. Idempotent, so several instances may run it at once.
    /// </summary>
    public Task<int> SweepExpiredRecentsAsync(CancellationToken cancellationToken)
    {
        var cutoff = _clock.NowMs() - RecentRetentionMs;
        return _db.ManagementWorkbenchItems
            .Where(row => row.List == WorkbenchLists.Recent && row.AtMs <= cutoff)
            .ExecuteDeleteAsync(cancellationToken);
    }

    /// <summary>
    /// Cascade for a deleted route, mapping or Peer service: every identity's references to it go,
    /// so an id handed out again later never inherits them. Runs inside the caller's transaction.
    /// </summary>
    public static Task<int> DeleteObjectReferencesAsync(SpecusDbContext db, string kind, long objectId,
        CancellationToken cancellationToken) =>
        db.ManagementWorkbenchItems
            .Where(row => row.Kind == kind && row.ObjectId == objectId)
            .ExecuteDeleteAsync(cancellationToken);

    /// <summary>
    /// Cascade for a deleted client: the references to each of its routes, mappings and Peer
    /// services, for every identity -- whether or not those object rows outlive the client.
    /// </summary>
    public static async Task DeleteClientReferencesAsync(SpecusDbContext db, long clientId,
        CancellationToken cancellationToken)
    {
        var routes = await db.HttpRouteMappings.AsNoTracking()
            .Where(row => row.ClientId == clientId)
            .Select(row => row.Id)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        var mappings = await db.SpecusMappings.AsNoTracking()
            .Where(row => row.ClientId == clientId)
            .Select(row => row.Id)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        var services = await db.PeerMeshSharedServices.AsNoTracking()
            .Where(row => row.ClientId == clientId)
            .Select(row => row.Id)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        foreach (var (kind, ids) in new[]
                 {
                     (WorkbenchKinds.HttpRoute, routes),
                     (WorkbenchKinds.TcpMapping, mappings),
                     (WorkbenchKinds.PeerService, services),
                 })
        {
            if (ids.Count == 0)
            {
                continue;
            }
            await db.ManagementWorkbenchItems
                .Where(row => row.Kind == kind && ids.Contains(row.ObjectId))
                .ExecuteDeleteAsync(cancellationToken)
                .ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Cascade for a deleted account: both lists of that identity, so an account created later
    /// under the same name starts empty.
    /// </summary>
    public static Task<int> DeleteIdentityAsync(SpecusDbContext db, string tenantId, string username,
        CancellationToken cancellationToken) =>
        db.ManagementWorkbenchItems
            .Where(row => row.TenantId == tenantId && row.Username == username)
            .ExecuteDeleteAsync(cancellationToken);

    private IQueryable<ManagementWorkbenchItem> IdentityRows(ManagementContext context, string list) =>
        _db.ManagementWorkbenchItems.Where(row =>
            row.TenantId == context.TenantId && row.Username == context.Username && row.List == list);

    /// <summary>
    /// The visibility rule of the kind's own list endpoint, evaluated now: the object exists, its
    /// client is in the caller's tenant, and the caller is an administrator (current role) or owns
    /// that client. Missing, other tenant and other owner are indistinguishable to the caller.
    /// </summary>
    private async Task<bool> IsVisibleAsync(ManagementContext context, string kind, long id,
        CancellationToken cancellationToken)
    {
        switch (kind)
        {
            case WorkbenchKinds.HttpRoute:
            {
                var clientId = await _db.HttpRouteMappings.AsNoTracking()
                    .Where(row => row.Id == id)
                    .Select(row => (long?)row.ClientId)
                    .FirstOrDefaultAsync(cancellationToken)
                    .ConfigureAwait(false);
                return clientId is not null
                    && await ClientVisibleAsync(context, clientId.Value, cancellationToken).ConfigureAwait(false);
            }
            case WorkbenchKinds.TcpMapping:
            {
                var clientId = await _db.SpecusMappings.AsNoTracking()
                    .Where(row => row.Id == id)
                    .Select(row => (long?)row.ClientId)
                    .FirstOrDefaultAsync(cancellationToken)
                    .ConfigureAwait(false);
                return clientId is not null
                    && await ClientVisibleAsync(context, clientId.Value, cancellationToken).ConfigureAwait(false);
            }
            case WorkbenchKinds.PeerService:
            {
                // GET /api/admin/peer-mesh/services: the tenant's services for an administrator,
                // the services of the caller's own clients otherwise.
                var clientId = await _db.PeerMeshSharedServices.AsNoTracking()
                    .Where(row => row.Id == id && row.TenantId == context.TenantId)
                    .Select(row => (long?)row.ClientId)
                    .FirstOrDefaultAsync(cancellationToken)
                    .ConfigureAwait(false);
                return clientId is not null
                    && (context.IsAdmin
                        || await ClientVisibleAsync(context, clientId.Value, cancellationToken)
                            .ConfigureAwait(false));
            }
            default:
                return false;
        }
    }

    private Task<bool> ClientVisibleAsync(ManagementContext context, long clientId,
        CancellationToken cancellationToken)
    {
        var isAdmin = context.IsAdmin;
        return _db.ClientAccounts.AsNoTracking()
            .AnyAsync(account => account.Id == clientId
                && account.TenantId == context.TenantId
                && (isAdmin || account.OwnerUsername == context.Username), cancellationToken);
    }

    private Task InsertFavoriteAsync(ManagementContext context, string kind, long id, long now,
        CancellationToken cancellationToken)
    {
        // A concurrent add of the same reference must stay a no-op, not a key violation.
        var sql = Dialect() == "mysql"
            ? "INSERT INTO management_workbench_item (tenant_id, username, list, kind, object_id, at_ms) "
              + "VALUES ({0}, {1}, {2}, {3}, {4}, {5}) ON DUPLICATE KEY UPDATE at_ms = at_ms"
            : "INSERT INTO management_workbench_item (tenant_id, username, list, kind, object_id, at_ms) "
              + "VALUES ({0}, {1}, {2}, {3}, {4}, {5}) "
              + "ON CONFLICT (tenant_id, username, list, kind, object_id) DO NOTHING";
        return _db.Database.ExecuteSqlRawAsync(sql,
            [context.TenantId, context.Username, WorkbenchLists.Favorite, kind, id, now], cancellationToken);
    }

    private Task UpsertVisitAsync(ManagementContext context, string kind, long id, long now,
        CancellationToken cancellationToken)
    {
        // visitedAt = max(stored, now) in one statement, so concurrent opens of the same service
        // leave one row with the latest time.
        var sql = Dialect() switch
        {
            "mysql" => "INSERT INTO management_workbench_item (tenant_id, username, list, kind, object_id, at_ms) "
                       + "VALUES ({0}, {1}, {2}, {3}, {4}, {5}) "
                       + "ON DUPLICATE KEY UPDATE at_ms = GREATEST(at_ms, VALUES(at_ms))",
            "postgresql" => "INSERT INTO management_workbench_item (tenant_id, username, list, kind, object_id, at_ms) "
                            + "VALUES ({0}, {1}, {2}, {3}, {4}, {5}) "
                            + "ON CONFLICT (tenant_id, username, list, kind, object_id) "
                            + "DO UPDATE SET at_ms = GREATEST(management_workbench_item.at_ms, EXCLUDED.at_ms)",
            _ => "INSERT INTO management_workbench_item (tenant_id, username, list, kind, object_id, at_ms) "
                 + "VALUES ({0}, {1}, {2}, {3}, {4}, {5}) "
                 + "ON CONFLICT (tenant_id, username, list, kind, object_id) "
                 + "DO UPDATE SET at_ms = MAX(management_workbench_item.at_ms, excluded.at_ms)",
        };
        return _db.Database.ExecuteSqlRawAsync(sql,
            [context.TenantId, context.Username, WorkbenchLists.Recent, kind, id, now], cancellationToken);
    }

    /// <summary>
    /// Every successful write ends the same way: the identity's recents are brought back within
    /// retention and bound -- the deleted rows are gone, not hidden -- and the full document is
    /// read in the same transaction.
    /// </summary>
    private async Task<WorkbenchResult> FinishWriteAsync(ManagementContext context, long now,
        Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction transaction,
        CancellationToken cancellationToken)
    {
        var cutoff = now - RecentRetentionMs;
        await IdentityRows(context, WorkbenchLists.Recent)
            .Where(row => row.AtMs <= cutoff)
            .ExecuteDeleteAsync(cancellationToken)
            .ConfigureAwait(false);
        var recents = await IdentityRows(context, WorkbenchLists.Recent)
            .AsNoTracking()
            .Select(row => new { row.Kind, row.ObjectId, row.AtMs })
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        foreach (var extra in recents
                     .OrderByDescending(row => row.AtMs)
                     .ThenBy(row => WorkbenchKinds.Order(row.Kind))
                     .ThenBy(row => row.ObjectId)
                     .Skip(MaxRecents))
        {
            await IdentityRows(context, WorkbenchLists.Recent)
                .Where(row => row.Kind == extra.Kind && row.ObjectId == extra.ObjectId)
                .ExecuteDeleteAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        var document = await ReadDocumentAsync(context, now, cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return WorkbenchResult.Ok(document);
    }

    private async Task<WorkbenchDocument> ReadDocumentAsync(ManagementContext context, long now,
        CancellationToken cancellationToken)
    {
        var rows = await _db.ManagementWorkbenchItems.AsNoTracking()
            .Where(row => row.TenantId == context.TenantId && row.Username == context.Username)
            .Select(row => new { row.List, row.Kind, row.ObjectId, row.AtMs })
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        var favorites = rows
            .Where(row => row.List == WorkbenchLists.Favorite)
            .OrderBy(row => row.AtMs)
            .ThenBy(row => WorkbenchKinds.Order(row.Kind))
            .ThenBy(row => row.ObjectId)
            .Select(row => new WorkbenchFavoriteView(row.Kind, row.ObjectId, FormatInstant(row.AtMs)))
            .ToList();
        var recents = rows
            .Where(row => row.List == WorkbenchLists.Recent && now - row.AtMs < RecentRetentionMs)
            .OrderByDescending(row => row.AtMs)
            .ThenBy(row => WorkbenchKinds.Order(row.Kind))
            .ThenBy(row => row.ObjectId)
            .Take(MaxRecents)
            .Select(row => new WorkbenchRecentView(row.Kind, row.ObjectId, FormatInstant(row.AtMs)))
            .ToList();
        return new WorkbenchDocument(SchemaVersion, Limits, favorites, recents);
    }

    private static WorkbenchResult NotFound() =>
        WorkbenchResult.Refused(StatusCodes.Status404NotFound, WorkbenchCodes.TargetNotFound);

    private WorkbenchResult Unavailable(ManagementContext context, string operation)
    {
        // The only workbench log line: who and which operation, never the reference or the cause's
        // payload, so failures cannot be turned into an access log.
        _logger.LogWarning("[workbench] tenant={TenantId} user={Username} op={Operation} code={Code}",
            context.TenantId, context.Username, operation, WorkbenchCodes.Unavailable);
        return WorkbenchResult.Refused(StatusCodes.Status503ServiceUnavailable, WorkbenchCodes.Unavailable);
    }

    /// <summary>Anything the store throws is a 503, except the request itself being cancelled.</summary>
    private static bool IsStoreFailure(Exception error, CancellationToken cancellationToken) =>
        !(error is OperationCanceledException && cancellationToken.IsCancellationRequested);

    private string Dialect()
    {
        var provider = _db.Database.ProviderName ?? string.Empty;
        if (provider.Contains("Npgsql", StringComparison.OrdinalIgnoreCase)
            || provider.Contains("PostgreSQL", StringComparison.OrdinalIgnoreCase))
        {
            return "postgresql";
        }
        return provider.Contains("MySql", StringComparison.OrdinalIgnoreCase) ? "mysql" : "sqlite";
    }
}

/// <summary>
/// Runs the global recent-entry retention sweep shortly after startup and then hourly, so an
/// expired entry is gone within a day even for identities that never write again.
/// </summary>
public sealed class WorkbenchRetentionSweepService : BackgroundService
{
    private static readonly TimeSpan FirstRunDelay = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan Interval = TimeSpan.FromHours(1);

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<WorkbenchRetentionSweepService> _logger;

    public WorkbenchRetentionSweepService(IServiceScopeFactory scopeFactory,
        ILogger<WorkbenchRetentionSweepService> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await Task.Delay(FirstRunDelay, stoppingToken).ConfigureAwait(false);
            using var timer = new PeriodicTimer(Interval);
            do
            {
                await SweepAsync(stoppingToken).ConfigureAwait(false);
            }
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Normal host shutdown.
        }
    }

    private async Task SweepAsync(CancellationToken cancellationToken)
    {
        try
        {
            await using var scope = _scopeFactory.CreateAsyncScope();
            var service = scope.ServiceProvider.GetRequiredService<WorkbenchService>();
            await service.SweepExpiredRecentsAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception error)
        {
            // The sweep names no identity or reference, so its failure can be logged in full. The
            // next hourly run retries.
            _logger.LogWarning(error, "[workbench] retention sweep failed");
        }
    }
}
