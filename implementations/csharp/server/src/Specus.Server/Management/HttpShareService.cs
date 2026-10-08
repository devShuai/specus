using System.Globalization;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Options;
using Specus.Server.Configuration;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Http;

namespace Specus.Server.Management;

/// <summary>
/// Temporary HTTP shares (protocol/spec/temporary-http-share.md): creation, listing, revocation,
/// the audit trail, the token exchange, the per-request authorization of the share path, the
/// hooks that end shares when their route, client or creator changes, and the sweep. Nothing is
/// cached: every decision reads the share, its route, client and creator from the database, so a
/// revoke on any instance is honoured by every instance on the next request.
/// </summary>
public sealed class HttpShareService
{
    internal static readonly JsonSerializerOptions JsonOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private static readonly HashSet<string> CreateFields = new(StringComparer.Ordinal)
    {
        "expiresInSeconds", "access", "pathPrefix", "label",
    };

    private readonly SpecusDbContext _db;
    private readonly AuthOptions _auth;
    private readonly HttpShareClock _clock;
    private readonly IHttpShareRandom _random;
    private readonly HttpShareStreamRegistry _streams;
    private readonly ILogger<HttpShareService> _logger;

    public HttpShareService(SpecusDbContext db, IOptions<AuthOptions> auth, HttpShareClock clock,
        IHttpShareRandom random, HttpShareStreamRegistry streams, ILogger<HttpShareService> logger)
    {
        _db = db;
        _auth = auth.Value;
        _clock = clock;
        _random = random;
        _streams = streams;
        _logger = logger;
    }

    // ----------------------------------------------------------------------------------------------
    // Who may manage a route

    /// <summary>A management principal as the database (or the configuration) says it is now.</summary>
    internal sealed record SharePrincipal(string Username, string TenantId, bool Admin);

    /// <summary>
    /// Re-reads a user by its identity: the tenant and the login name, as a share's creator or a
    /// management context records them (Java <c>lookupActor</c>). The configured built-in admin is
    /// not a row of the user table: it counts as an enabled ADMIN of its configured tenant while the
    /// server would accept it as a principal, i.e. while password login is enabled with a password set.
    /// </summary>
    internal async Task<SharePrincipal?> LoadPrincipalAsync(string? tenantId, string? username,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(tenantId) || string.IsNullOrWhiteSpace(username))
        {
            return null;
        }
        var tenant = ManagementContext.NormalizeTenant(tenantId);
        var normalized = username.Trim();
        var defaultTenant = ManagementContext.NormalizeTenant(_auth.TenantId);
        if (string.Equals(normalized, _auth.Username, StringComparison.OrdinalIgnoreCase)
            && string.Equals(tenant, defaultTenant, StringComparison.Ordinal))
        {
            return _auth.PasswordLoginEnabled && !string.IsNullOrWhiteSpace(_auth.Password)
                ? new SharePrincipal(_auth.Username, defaultTenant, true)
                : null;
        }
        var user = await ManagementUserService.FindByLoginNameAsync(_db.ManagementUsers.AsNoTracking(),
                tenant, normalized, cancellationToken)
            .ConfigureAwait(false);
        return user is { Enabled: true }
            ? new SharePrincipal(user.EffectiveLoginName(), ManagementContext.NormalizeTenant(user.TenantId),
                user.Role == ManagementRole.Admin)
            : null;
    }

    internal static bool CanManage(SharePrincipal? principal, HttpRouteMapping route, ClientAccount? client) =>
        principal is not null
        && ManagementContext.SameTenant(principal.TenantId, route.TenantId)
        && (principal.Admin
            || (client is not null
                && string.Equals(client.OwnerUsername, principal.Username, StringComparison.Ordinal)));

    internal static string Exposure(HttpRouteMapping route) =>
        HttpShareProtocol.Exposure(route.Enabled, route.AuthEnabled);

    /// <summary>Why a share that is neither revoked nor expired can no longer be honoured, or null.</summary>
    internal static string? LapseReason(ShareContext context)
    {
        var route = context.Route;
        if (route is null || !ManagementContext.SameTenant(route.TenantId, context.Share.TenantId))
        {
            return HttpShareProtocol.ReasonRouteDeleted;
        }
        if (context.Client is null)
        {
            return HttpShareProtocol.ReasonClientDeleted;
        }
        if (!context.Client.Enabled)
        {
            return HttpShareProtocol.ReasonClientDisabled;
        }
        var exposure = Exposure(route);
        if (exposure == HttpShareProtocol.ExposureDisabled)
        {
            return HttpShareProtocol.ReasonRouteDisabled;
        }
        if (exposure == HttpShareProtocol.ExposurePublic)
        {
            return HttpShareProtocol.ReasonRouteMadePublic;
        }
        return CanManage(context.Creator, route, context.Client)
            ? null
            : HttpShareProtocol.ReasonCreatorLostAccess;
    }

    internal static string Status(HttpShare share, long nowMs) =>
        share.RevokedAt is not null ? "revoked"
        : nowMs >= share.ExpiresAt * 1000 ? "expired"
        : "active";

    /// <summary>A share with the current state of everything that decides whether it still holds.</summary>
    internal sealed record ShareContext(HttpShare Share, HttpRouteMapping? Route, ClientAccount? Client,
        SharePrincipal? Creator);

    internal async Task<ShareContext?> LoadContextAsync(string shareId, CancellationToken cancellationToken)
    {
        var share = await _db.HttpShares.AsNoTracking()
            .FirstOrDefaultAsync(s => s.ShareId == shareId, cancellationToken)
            .ConfigureAwait(false);
        return share is null ? null : await ContextOfAsync(share, null, cancellationToken).ConfigureAwait(false);
    }

    private async Task<ShareContext> ContextOfAsync(HttpShare share, ContextCache? cache,
        CancellationToken cancellationToken)
    {
        cache ??= new ContextCache();
        if (!cache.Routes.TryGetValue(share.RouteId, out var route))
        {
            route = await _db.HttpRouteMappings.AsNoTracking()
                .FirstOrDefaultAsync(r => r.Id == share.RouteId, cancellationToken)
                .ConfigureAwait(false);
            cache.Routes[share.RouteId] = route;
        }
        ClientAccount? client = null;
        if (route is not null && !cache.Clients.TryGetValue(route.ClientId, out client))
        {
            client = await _db.ClientAccounts.AsNoTracking()
                .FirstOrDefaultAsync(c => c.Id == route.ClientId, cancellationToken)
                .ConfigureAwait(false);
            cache.Clients[route.ClientId] = client;
        }
        // A creator is the login name in the share's tenant; the same name in another tenant is
        // someone else.
        var creatorKey = share.TenantId + "\0" + share.CreatedBy;
        if (!cache.Principals.TryGetValue(creatorKey, out var creator))
        {
            creator = await LoadPrincipalAsync(share.TenantId, share.CreatedBy, cancellationToken)
                .ConfigureAwait(false);
            cache.Principals[creatorKey] = creator;
        }
        return new ShareContext(share, route, client, creator);
    }

    private sealed class ContextCache
    {
        public Dictionary<long, HttpRouteMapping?> Routes { get; } = [];
        public Dictionary<long, ClientAccount?> Clients { get; } = [];
        public Dictionary<string, SharePrincipal?> Principals { get; } = new(StringComparer.Ordinal);
    }

    // ----------------------------------------------------------------------------------------------
    // Management API

    /// <summary>A JSON answer of the share API.</summary>
    public sealed record ShareResponse(int StatusCode, JsonObject Body, string? SetCookie = null,
        long? RetryAfterSeconds = null)
    {
        public static ShareResponse Error(int statusCode, string code) =>
            new(statusCode, new JsonObject { ["code"] = code });
    }

    internal sealed record CreateRequest(long ExpiresInSeconds, string Access, string PathPrefix, string? Label);

    /// <summary>The normalized fields of a create body, or null for 400 (spec §4.1).</summary>
    internal static CreateRequest? ValidateCreateBody(ReadOnlySpan<byte> body)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(body.ToArray());
        }
        catch (JsonException)
        {
            return null;
        }
        using (document)
        {
            try
            {
                return ValidateCreateBody(document.RootElement);
            }
            catch (InvalidOperationException)
            {
                // A string with an unpaired surrogate escape cannot be read as text.
                return null;
            }
        }
    }

    private static CreateRequest? ValidateCreateBody(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object)
        {
            return null;
        }
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in root.EnumerateObject())
        {
            // Unknown fields are refused, so a client never believes a limit is enforced when it
            // is not; a repeated field has no single meaning.
            if (!CreateFields.Contains(property.Name) || !seen.Add(property.Name))
            {
                return null;
            }
        }
        if (!root.TryGetProperty("expiresInSeconds", out var expires)
            || expires.ValueKind != JsonValueKind.Number)
        {
            return null;
        }
        var raw = expires.GetRawText();
        if (raw.IndexOfAny(['.', 'e', 'E']) >= 0 || !expires.TryGetInt64(out var seconds)
            || seconds is < HttpShareProtocol.MinExpiresInSeconds or > HttpShareProtocol.MaxExpiresInSeconds)
        {
            return null;
        }
        var access = HttpShareProtocol.AccessRead;
        if (root.TryGetProperty("access", out var accessElement))
        {
            access = accessElement.ValueKind == JsonValueKind.String ? accessElement.GetString()! : string.Empty;
            if (access is not (HttpShareProtocol.AccessRead or HttpShareProtocol.AccessFull))
            {
                return null;
            }
        }
        var prefixValue = "/";
        if (root.TryGetProperty("pathPrefix", out var prefixElement))
        {
            if (prefixElement.ValueKind != JsonValueKind.String)
            {
                return null;
            }
            prefixValue = prefixElement.GetString()!;
        }
        var prefix = HttpShareProtocol.CanonicalPrefix(prefixValue);
        if (prefix is null)
        {
            return null;
        }
        string? label = null;
        if (root.TryGetProperty("label", out var labelElement) && labelElement.ValueKind != JsonValueKind.Null)
        {
            if (labelElement.ValueKind != JsonValueKind.String)
            {
                return null;
            }
            label = labelElement.GetString()!.Trim(' ');
            var codePoints = 0;
            foreach (var rune in label.EnumerateRunes())
            {
                if (rune.Value < 0x20 || rune.Value == 0x7F)
                {
                    return null;
                }
                codePoints++;
            }
            if (codePoints > HttpShareProtocol.LabelMaxCodePoints)
            {
                return null;
            }
            label = label.Length == 0 ? null : label;
        }
        return new CreateRequest(seconds, access, prefix, label);
    }

    public async Task<ShareResponse> CreateAsync(ManagementContext context, string routeIdText,
        ReadOnlyMemory<byte>? body, CancellationToken cancellationToken)
    {
        var request = body is null ? null : ValidateCreateBody(body.Value.Span);
        if (request is null)
        {
            return ShareResponse.Error(StatusCodes.Status400BadRequest, HttpShareCodes.RequestInvalid);
        }
        if (!TryParseId(routeIdText, out var routeId))
        {
            return ShareResponse.Error(StatusCodes.Status404NotFound, HttpShareCodes.RouteNotFound);
        }
        var nowMs = _clock.NowMs;
        var nowSeconds = FloorSeconds(nowMs);
        RouteView? view;
        try
        {
            view = await LoadRouteForCallerAsync(context, routeId, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception error) when (IsStoreFailure(error, cancellationToken))
        {
            return Unavailable(error);
        }
        if (view is null)
        {
            return ShareResponse.Error(StatusCodes.Status404NotFound, HttpShareCodes.RouteNotFound);
        }
        if (!view.Route.Enabled)
        {
            return ShareResponse.Error(StatusCodes.Status409Conflict, HttpShareCodes.RouteDisabled);
        }
        if (view.Client is not { Enabled: true })
        {
            return ShareResponse.Error(StatusCodes.Status409Conflict, HttpShareCodes.ClientDisabled);
        }
        if (!view.Route.AuthEnabled)
        {
            return ShareResponse.Error(StatusCodes.Status409Conflict, HttpShareCodes.RoutePublic);
        }

        try
        {
            await using var transaction = await _db.Database.BeginTransactionAsync(cancellationToken)
                .ConfigureAwait(false);
            await LockRouteForCreationAsync(routeId, cancellationToken).ConfigureAwait(false);
            var active = await _db.HttpShares.AsNoTracking()
                .CountAsync(s => s.RouteId == routeId && s.RevokedAt == null && s.ExpiresAt > nowSeconds,
                    cancellationToken)
                .ConfigureAwait(false);
            if (active >= HttpShareProtocol.MaxActiveSharesPerRoute)
            {
                return ShareResponse.Error(StatusCodes.Status409Conflict, HttpShareCodes.LimitReached);
            }
            var (shareId, token) = await NewTokenAsync(cancellationToken).ConfigureAwait(false);
            var share = new HttpShare
            {
                ShareId = shareId,
                TenantId = ManagementContext.NormalizeTenant(view.Route.TenantId),
                RouteId = routeId,
                TokenSha256 = HttpShareProtocol.TokenHash(token),
                Access = request.Access,
                PathPrefix = request.PathPrefix,
                Label = request.Label,
                CreatedBy = view.Caller.Username,
                CreatedAt = nowSeconds,
                ExpiresAt = nowSeconds + request.ExpiresInSeconds,
            };
            _db.HttpShares.Add(share);
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            _db.Entry(share).State = EntityState.Detached;
            await WriteAuditAsync(share.TenantId, nowSeconds, view.Caller.Username,
                HttpShareProtocol.ActionShareCreated, routeId, shareId, new JsonObject
                {
                    ["access"] = share.Access,
                    ["pathPrefix"] = share.PathPrefix,
                    ["expiresAt"] = HttpShareProtocol.Stamp(share.ExpiresAt),
                }, cancellationToken).ConfigureAwait(false);
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            return new ShareResponse(StatusCodes.Status201Created, new JsonObject
            {
                ["share"] = View(share, nowMs),
                ["token"] = token,
                ["linkPath"] = HttpShareProtocol.LinkPath(token),
            });
        }
        catch (Exception error) when (IsStoreFailure(error, cancellationToken))
        {
            return Unavailable(error);
        }
    }

    /// <summary>
    /// The statement that holds a route row until the end of the transaction, with the route id as
    /// its only parameter, or null where none is taken: SQLite has no <c>FOR UPDATE</c>, and its
    /// single writer already serializes the creation. Table and column names come from the model,
    /// quoted as the provider quotes them.
    /// </summary>
    internal static string? RouteLockSql(DbContext db)
    {
        var provider = db.Database.ProviderName ?? string.Empty;
        if (!provider.Contains("MySql", StringComparison.OrdinalIgnoreCase)
            && !provider.Contains("Npgsql", StringComparison.OrdinalIgnoreCase)
            && !provider.Contains("PostgreSQL", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }
        var entity = db.Model.FindEntityType(typeof(HttpRouteMapping))!;
        var table = StoreObjectIdentifier.Table(entity.GetTableName()!, entity.GetSchema());
        var sql = db.GetService<ISqlGenerationHelper>();
        var id = sql.DelimitIdentifier(entity.FindProperty(nameof(HttpRouteMapping.Id))!.GetColumnName(table)!);
        return $"SELECT {id} FROM {sql.DelimitIdentifier(table.Name, table.Schema)} WHERE {id} = {{0}} FOR UPDATE";
    }

    /// <summary>
    /// Serializes the share creations of one route, on every instance, so that two of them cannot
    /// both count the same number of active shares. It must be the transaction's first statement:
    /// MySQL's REPEATABLE READ snapshot then starts only after the lock is granted, so the count
    /// sees the share committed by the creation that held it. A route that is gone has no row to
    /// lock, and the creation goes on as it would without the lock.
    /// </summary>
    private async Task LockRouteForCreationAsync(long routeId, CancellationToken cancellationToken)
    {
        var sql = RouteLockSql(_db);
        if (sql is not null)
        {
            await _db.Database.ExecuteSqlRawAsync(sql, [routeId], cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task<(string ShareId, string Token)> NewTokenAsync(CancellationToken cancellationToken)
    {
        var shareIdBytes = new byte[HttpShareProtocol.ShareIdBytes];
        var secretBytes = new byte[HttpShareProtocol.SecretBytes];
        for (var attempt = 0; ; attempt++)
        {
            _random.Fill(shareIdBytes);
            _random.Fill(secretBytes);
            var made = HttpShareProtocol.MakeToken(shareIdBytes, secretBytes);
            var taken = await _db.HttpShares.AsNoTracking()
                .AnyAsync(s => s.ShareId == made.ShareId, cancellationToken)
                .ConfigureAwait(false);
            if (!taken)
            {
                return made;
            }
            if (attempt == 4)
            {
                throw new InvalidOperationException("could not draw an unused share id");
            }
        }
    }

    public async Task<ShareResponse> ListAsync(ManagementContext context, string routeIdText,
        CancellationToken cancellationToken)
    {
        if (!TryParseId(routeIdText, out var routeId))
        {
            return ShareResponse.Error(StatusCodes.Status404NotFound, HttpShareCodes.RouteNotFound);
        }
        try
        {
            var view = await LoadRouteForCallerAsync(context, routeId, cancellationToken).ConfigureAwait(false);
            if (view is null)
            {
                return ShareResponse.Error(StatusCodes.Status404NotFound, HttpShareCodes.RouteNotFound);
            }
            var rows = await RevokeLapsedOfRouteAsync(routeId, null, cancellationToken).ConfigureAwait(false);
            var nowMs = _clock.NowMs;
            var shares = new JsonArray();
            foreach (var share in rows.OrderByDescending(static s => s.CreatedAt)
                         .ThenByDescending(static s => s.ShareId, StringComparer.Ordinal))
            {
                shares.Add(View(share, nowMs));
            }
            return new ShareResponse(StatusCodes.Status200OK, new JsonObject { ["shares"] = shares });
        }
        catch (Exception error) when (IsStoreFailure(error, cancellationToken))
        {
            return Unavailable(error);
        }
    }

    public async Task<ShareResponse> GetAsync(ManagementContext context, string routeIdText, string shareId,
        CancellationToken cancellationToken)
    {
        if (!TryParseId(routeIdText, out var routeId))
        {
            return ShareResponse.Error(StatusCodes.Status404NotFound, HttpShareCodes.RouteNotFound);
        }
        try
        {
            var view = await LoadRouteForCallerAsync(context, routeId, cancellationToken).ConfigureAwait(false);
            if (view is null)
            {
                return ShareResponse.Error(StatusCodes.Status404NotFound, HttpShareCodes.RouteNotFound);
            }
            var rows = await RevokeLapsedOfRouteAsync(routeId, shareId, cancellationToken).ConfigureAwait(false);
            var share = rows.FirstOrDefault(s => string.Equals(s.ShareId, shareId, StringComparison.Ordinal));
            return share is null
                ? ShareResponse.Error(StatusCodes.Status404NotFound, HttpShareCodes.NotFound)
                : new ShareResponse(StatusCodes.Status200OK,
                    new JsonObject { ["share"] = View(share, _clock.NowMs) });
        }
        catch (Exception error) when (IsStoreFailure(error, cancellationToken))
        {
            return Unavailable(error);
        }
    }

    /// <summary>
    /// Rows of the route (or one share of it), after revoking every share that is still active but
    /// has lapsed, so a listing never shows as active a share that can no longer be used.
    /// </summary>
    private async Task<List<HttpShare>> RevokeLapsedOfRouteAsync(long routeId, string? shareId,
        CancellationToken cancellationToken)
    {
        var query = _db.HttpShares.AsNoTracking().Where(s => s.RouteId == routeId);
        if (shareId is not null)
        {
            query = query.Where(s => s.ShareId == shareId);
        }
        var rows = await query.ToListAsync(cancellationToken).ConfigureAwait(false);
        var nowMs = _clock.NowMs;
        var cache = new ContextCache();
        var changed = false;
        foreach (var share in rows.Where(s => Status(s, nowMs) == "active"))
        {
            var shareContext = await ContextOfAsync(share, cache, cancellationToken).ConfigureAwait(false);
            var reason = LapseReason(shareContext);
            if (reason is not null)
            {
                await ReadTimeRevokeAsync(share, reason, cancellationToken).ConfigureAwait(false);
                changed = true;
            }
        }
        return changed ? await query.ToListAsync(cancellationToken).ConfigureAwait(false) : rows;
    }

    public async Task<ShareResponse> RevokeAsync(ManagementContext context, string routeIdText,
        string shareId, ReadOnlyMemory<byte>? body, CancellationToken cancellationToken)
    {
        if (!IsEmptyRevokeBody(body))
        {
            return ShareResponse.Error(StatusCodes.Status400BadRequest, HttpShareCodes.RequestInvalid);
        }
        if (!TryParseId(routeIdText, out var routeId))
        {
            return ShareResponse.Error(StatusCodes.Status404NotFound, HttpShareCodes.RouteNotFound);
        }
        try
        {
            var view = await LoadRouteForCallerAsync(context, routeId, cancellationToken).ConfigureAwait(false);
            if (view is null)
            {
                return ShareResponse.Error(StatusCodes.Status404NotFound, HttpShareCodes.RouteNotFound);
            }
            var share = await _db.HttpShares.AsNoTracking()
                .FirstOrDefaultAsync(s => s.ShareId == shareId, cancellationToken)
                .ConfigureAwait(false);
            if (share is null || share.RouteId != routeId)
            {
                return ShareResponse.Error(StatusCodes.Status404NotFound, HttpShareCodes.NotFound);
            }
            var nowMs = _clock.NowMs;
            if (Status(share, nowMs) == "active")
            {
                // Revocation is idempotent: an ended share is answered as it is, nothing written.
                var caller = view.Caller.Username;
                var revoked = await InTransactionAsync(() => RevokeAsync(share, caller,
                    HttpShareProtocol.ReasonRevokedByUser, cancellationToken), cancellationToken).ConfigureAwait(false);
                if (revoked)
                {
                    _streams.Cut(share.ShareId);
                }
                share = await _db.HttpShares.AsNoTracking()
                    .FirstAsync(s => s.ShareId == shareId, cancellationToken)
                    .ConfigureAwait(false);
            }
            return new ShareResponse(StatusCodes.Status200OK, new JsonObject { ["share"] = View(share, nowMs) });
        }
        catch (Exception error) when (IsStoreFailure(error, cancellationToken))
        {
            return Unavailable(error);
        }
    }

    private static bool IsEmptyRevokeBody(ReadOnlyMemory<byte>? body)
    {
        if (body is null)
        {
            return false;
        }
        var span = body.Value.Span;
        if (span.Trim(" \t\r\n"u8).IsEmpty)
        {
            return true;
        }
        try
        {
            using var document = JsonDocument.Parse(body.Value);
            return document.RootElement.ValueKind == JsonValueKind.Object
                   && !document.RootElement.EnumerateObject().Any();
        }
        catch (JsonException)
        {
            return false;
        }
    }

    public async Task<ShareResponse> RouteAuditAsync(ManagementContext context, string routeIdText,
        string? limitText, string? beforeText, CancellationToken cancellationToken)
    {
        if (!TryParseLimit(limitText, out var limit) || !TryParseBefore(beforeText, out var before))
        {
            return ShareResponse.Error(StatusCodes.Status400BadRequest, HttpShareCodes.RequestInvalid);
        }
        if (!TryParseId(routeIdText, out var routeId))
        {
            return ShareResponse.Error(StatusCodes.Status404NotFound, HttpShareCodes.RouteNotFound);
        }
        try
        {
            var view = await LoadRouteForCallerAsync(context, routeId, cancellationToken).ConfigureAwait(false);
            if (view is null)
            {
                return ShareResponse.Error(StatusCodes.Status404NotFound, HttpShareCodes.RouteNotFound);
            }
            return await AuditPageAsync(view.Caller.TenantId, routeId, limit, before, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception error) when (IsStoreFailure(error, cancellationToken))
        {
            return Unavailable(error);
        }
    }

    public async Task<ShareResponse> TenantAuditAsync(ManagementContext context, string? routeIdText,
        string? limitText, string? beforeText, CancellationToken cancellationToken)
    {
        long? routeId = null;
        if (routeIdText is not null)
        {
            if (!TryParseId(routeIdText, out var parsed))
            {
                return ShareResponse.Error(StatusCodes.Status400BadRequest, HttpShareCodes.RequestInvalid);
            }
            routeId = parsed;
        }
        if (!TryParseLimit(limitText, out var limit) || !TryParseBefore(beforeText, out var before))
        {
            return ShareResponse.Error(StatusCodes.Status400BadRequest, HttpShareCodes.RequestInvalid);
        }
        try
        {
            var caller = await LoadPrincipalAsync(context.TenantId, context.Username, cancellationToken)
                .ConfigureAwait(false);
            if (caller is not { Admin: true })
            {
                return ShareResponse.Error(StatusCodes.Status403Forbidden, HttpShareCodes.Forbidden);
            }
            return await AuditPageAsync(caller.TenantId, routeId, limit, before, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception error) when (IsStoreFailure(error, cancellationToken))
        {
            return Unavailable(error);
        }
    }

    private async Task<ShareResponse> AuditPageAsync(string tenantId, long? routeId, int limit, long? before,
        CancellationToken cancellationToken)
    {
        var query = _db.HttpAccessAudits.AsNoTracking().Where(a => a.TenantId == tenantId);
        if (routeId is not null)
        {
            query = query.Where(a => a.RouteId == routeId.Value);
        }
        if (before is not null)
        {
            query = query.Where(a => a.Id < before.Value);
        }
        var rows = await query.OrderByDescending(a => a.Id).Take(limit + 1)
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        var page = rows.Take(limit).ToList();
        var entries = new JsonArray();
        foreach (var row in page)
        {
            entries.Add(AuditView(row));
        }
        return new ShareResponse(StatusCodes.Status200OK, new JsonObject
        {
            ["entries"] = entries,
            ["nextBefore"] = rows.Count > limit ? page[^1].Id : null,
        });
    }

    internal static JsonObject AuditView(HttpAccessAudit row) => new()
    {
        ["auditId"] = row.Id,
        ["at"] = HttpShareProtocol.Stamp(row.OccurredAt),
        ["actor"] = row.Actor,
        ["action"] = row.Action,
        ["routeId"] = row.RouteId,
        ["shareId"] = row.ShareId,
        ["detail"] = JsonNode.Parse(row.DetailJson) ?? new JsonObject(),
    };

    internal static JsonObject View(HttpShare share, long nowMs) => new()
    {
        ["shareId"] = share.ShareId,
        ["routeId"] = share.RouteId,
        ["label"] = share.Label,
        ["access"] = share.Access,
        ["pathPrefix"] = share.PathPrefix,
        ["sharePath"] = HttpShareProtocol.SharePath(share.ShareId),
        ["createdAt"] = HttpShareProtocol.Stamp(share.CreatedAt),
        ["createdBy"] = share.CreatedBy,
        ["expiresAt"] = HttpShareProtocol.Stamp(share.ExpiresAt),
        ["status"] = Status(share, nowMs),
        ["revokedAt"] = share.RevokedAt is { } revokedAt ? HttpShareProtocol.Stamp(revokedAt) : null,
        ["revokedBy"] = share.RevokedBy,
        ["revokeReason"] = share.RevokeReason,
    };

    private sealed record RouteView(SharePrincipal Caller, HttpRouteMapping Route, ClientAccount? Client);

    /// <summary>The route when the caller, re-read from the database, may manage it now.</summary>
    private async Task<RouteView?> LoadRouteForCallerAsync(ManagementContext context, long routeId,
        CancellationToken cancellationToken)
    {
        var caller = await LoadPrincipalAsync(context.TenantId, context.Username, cancellationToken)
            .ConfigureAwait(false);
        var route = await _db.HttpRouteMappings.AsNoTracking()
            .FirstOrDefaultAsync(r => r.Id == routeId, cancellationToken)
            .ConfigureAwait(false);
        if (route is null || caller is null)
        {
            return null;
        }
        var client = await _db.ClientAccounts.AsNoTracking()
            .FirstOrDefaultAsync(c => c.Id == route.ClientId, cancellationToken)
            .ConfigureAwait(false);
        return CanManage(caller, route, client) ? new RouteView(caller, route, client) : null;
    }

    // ----------------------------------------------------------------------------------------------
    // Exchange and the share path

    /// <summary>
    /// Exchanges a token from a link fragment for the share cookie (spec §5.2, steps 4-10). The
    /// endpoint has already checked the media type, the body and the source-address limit.
    /// </summary>
    public async Task<ShareResponse> ExchangeAsync(string token, CancellationToken cancellationToken)
    {
        var shareId = HttpShareProtocol.ParseToken(token);
        if (shareId is null)
        {
            return ShareResponse.Error(StatusCodes.Status404NotFound, HttpShareCodes.NotFound);
        }
        ShareContext? shareContext;
        try
        {
            shareContext = await LoadContextAsync(shareId, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception error) when (IsStoreFailure(error, cancellationToken))
        {
            return Unavailable(error);
        }
        if (shareContext is null
            || !HttpShareProtocol.HashEquals(shareContext.Share.TokenSha256, HttpShareProtocol.TokenHash(token)))
        {
            return ShareResponse.Error(StatusCodes.Status404NotFound, HttpShareCodes.NotFound);
        }
        var nowMs = _clock.NowMs;
        var ended = await EndedAsync(shareContext, nowMs, cancellationToken).ConfigureAwait(false);
        if (ended is not null)
        {
            return ShareResponse.Error(StatusCodes.Status410Gone, ended);
        }
        var share = shareContext.Share;
        var maxAge = (share.ExpiresAt * 1000 - nowMs + 999) / 1000;
        return new ShareResponse(StatusCodes.Status200OK, new JsonObject
        {
            ["shareId"] = share.ShareId,
            ["location"] = HttpShareProtocol.SharePathRoot + share.ShareId + share.PathPrefix,
            ["expiresAt"] = HttpShareProtocol.Stamp(share.ExpiresAt),
            ["access"] = share.Access,
            ["pathPrefix"] = share.PathPrefix,
        }, HttpShareProtocol.SetCookieHeader(share.ShareId, token, maxAge));
    }

    /// <summary>The outcome of steps 3-7 of the share path (spec §6.1).</summary>
    public sealed record VisitorDecision(int StatusCode, string? Code, bool ClearCookie,
        HttpShare? Share, HttpRouteMapping? Route, ClientAccount? Client)
    {
        public bool Admitted => Code is null;
    }

    public async Task<VisitorDecision> AuthorizeVisitorAsync(string shareId, IEnumerable<string?> cookieHeaders,
        CancellationToken cancellationToken)
    {
        ShareContext? shareContext;
        try
        {
            shareContext = await LoadContextAsync(shareId, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception error) when (IsStoreFailure(error, cancellationToken))
        {
            _logger.LogWarning(error, "http share {ShareId} could not be read", shareId);
            return new VisitorDecision(StatusCodes.Status503ServiceUnavailable, HttpShareCodes.Unavailable,
                false, null, null, null);
        }
        if (shareContext is null)
        {
            return new VisitorDecision(StatusCodes.Status404NotFound, HttpShareCodes.NotFound, false,
                null, null, null);
        }
        // "No share", "no cookie" and "wrong cookie" are one answer: holding the share id alone
        // tells nothing.
        var candidates = HttpShareProtocol.CredentialCandidates(cookieHeaders, shareId);
        var proven = false;
        foreach (var candidate in candidates)
        {
            proven |= HttpShareProtocol.HashEquals(shareContext.Share.TokenSha256,
                HttpShareProtocol.TokenHash(candidate));
        }
        if (!proven)
        {
            return new VisitorDecision(StatusCodes.Status404NotFound, HttpShareCodes.NotFound, false,
                null, null, null);
        }
        var ended = await EndedAsync(shareContext, _clock.NowMs, cancellationToken).ConfigureAwait(false);
        if (ended is not null)
        {
            return new VisitorDecision(StatusCodes.Status410Gone, ended, true, shareContext.Share,
                null, null);
        }
        return new VisitorDecision(StatusCodes.Status200OK, null, false, shareContext.Share,
            shareContext.Route, shareContext.Client);
    }

    /// <summary>
    /// The 410 code for a share that has ended, or null when it still holds. A share that lapsed
    /// is revoked on the spot (and stays revoked even if the cause is undone); when that write
    /// fails the request is still refused.
    /// </summary>
    private async Task<string?> EndedAsync(ShareContext shareContext, long nowMs,
        CancellationToken cancellationToken)
    {
        switch (Status(shareContext.Share, nowMs))
        {
            case "revoked":
                return HttpShareCodes.Revoked;
            case "expired":
                return HttpShareCodes.Expired;
        }
        var reason = LapseReason(shareContext);
        if (reason is null)
        {
            return null;
        }
        try
        {
            await ReadTimeRevokeAsync(shareContext.Share, reason, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception error) when (IsStoreFailure(error, cancellationToken))
        {
            _logger.LogWarning(error, "read-time revoke of http share {ShareId} failed", shareContext.Share.ShareId);
        }
        return HttpShareCodes.Revoked;
    }

    /// <summary>
    /// Re-reads a share that has in-flight streams on this instance: true when they must be cut
    /// (the row is gone, revoked, expired, or lapsed — which revokes it now).
    /// </summary>
    public async Task<bool> HasEndedAsync(string shareId, CancellationToken cancellationToken)
    {
        var shareContext = await LoadContextAsync(shareId, cancellationToken).ConfigureAwait(false);
        if (shareContext is null)
        {
            return true;
        }
        return await EndedAsync(shareContext, _clock.NowMs, cancellationToken).ConfigureAwait(false) is not null;
    }

    // ----------------------------------------------------------------------------------------------
    // Revocation

    /// <summary>
    /// The system revoke of a lapsed share: a conditional update, and the audit entry only when
    /// this call changed the row, so concurrent instances write one entry between them.
    /// </summary>
    private async Task<bool> ReadTimeRevokeAsync(HttpShare share, string reason, CancellationToken cancellationToken)
    {
        var revoked = await InTransactionAsync(
            () => RevokeAsync(share, null, reason, cancellationToken), cancellationToken).ConfigureAwait(false);
        if (revoked)
        {
            _streams.Cut(share.ShareId);
        }
        return revoked;
    }

    /// <summary>Conditionally revokes one share and audits it; the caller owns the transaction.</summary>
    private async Task<bool> RevokeAsync(HttpShare share, string? actor, string reason,
        CancellationToken cancellationToken)
    {
        var nowSeconds = _clock.NowSeconds;
        var updated = await _db.HttpShares
            .Where(s => s.ShareId == share.ShareId && s.RevokedAt == null && s.ExpiresAt > nowSeconds)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(s => s.RevokedAt, nowSeconds)
                .SetProperty(s => s.RevokedBy, actor)
                .SetProperty(s => s.RevokeReason, reason), cancellationToken)
            .ConfigureAwait(false);
        if (updated != 1)
        {
            return false;
        }
        await WriteAuditAsync(share.TenantId, nowSeconds, actor, HttpShareProtocol.ActionShareRevoked,
            share.RouteId, share.ShareId, new JsonObject { ["reason"] = reason }, cancellationToken)
            .ConfigureAwait(false);
        return true;
    }

    /// <summary>
    /// Revokes the active shares of the given routes with one reason (ordered by creation, then
    /// id) inside the caller's transaction. Returns the ids to cut once the change commits.
    /// </summary>
    private async Task<List<string>> RevokeActiveOfRoutesAsync(IReadOnlyCollection<long> routeIds,
        string actor, string reason, CancellationToken cancellationToken)
    {
        var revoked = new List<string>();
        if (routeIds.Count == 0)
        {
            return revoked;
        }
        var nowSeconds = _clock.NowSeconds;
        var shares = await _db.HttpShares.AsNoTracking()
            .Where(s => routeIds.Contains(s.RouteId) && s.RevokedAt == null && s.ExpiresAt > nowSeconds)
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        foreach (var share in OrderByCreation(shares))
        {
            if (await RevokeAsync(share, actor, reason, cancellationToken).ConfigureAwait(false))
            {
                revoked.Add(share.ShareId);
            }
        }
        return revoked;
    }

    private static IEnumerable<HttpShare> OrderByCreation(IEnumerable<HttpShare> shares) =>
        shares.OrderBy(static s => s.CreatedAt).ThenBy(static s => s.ShareId, StringComparer.Ordinal);

    /// <summary>Cuts this instance's streams of shares a committed change has revoked.</summary>
    public void CutStreams(IEnumerable<string> shareIds)
    {
        foreach (var shareId in shareIds)
        {
            _streams.Cut(shareId);
        }
    }

    // ----------------------------------------------------------------------------------------------
    // Hooks: run inside the transaction of the route, client or user change (spec §7.3)

    public Task OnRouteCreatedAsync(string actor, HttpRouteMapping route, CancellationToken cancellationToken) =>
        WriteAuditAsync(ManagementContext.NormalizeTenant(route.TenantId), _clock.NowSeconds, actor,
            HttpShareProtocol.ActionRouteCreated, route.Id, null,
            new JsonObject { ["exposure"] = Exposure(route) }, cancellationToken);

    public async Task<List<string>> OnRouteUpdatedAsync(string actor, HttpRouteMapping route,
        string exposureBefore, bool credentialsChanged, CancellationToken cancellationToken)
    {
        var tenant = ManagementContext.NormalizeTenant(route.TenantId);
        var nowSeconds = _clock.NowSeconds;
        var exposureAfter = Exposure(route);
        if (exposureBefore != exposureAfter)
        {
            await WriteAuditAsync(tenant, nowSeconds, actor, HttpShareProtocol.ActionRouteExposureChanged,
                route.Id, null, new JsonObject { ["from"] = exposureBefore, ["to"] = exposureAfter },
                cancellationToken).ConfigureAwait(false);
        }
        if (credentialsChanged)
        {
            await WriteAuditAsync(tenant, nowSeconds, actor, HttpShareProtocol.ActionRouteCredentialsChanged,
                route.Id, null, new JsonObject(), cancellationToken).ConfigureAwait(false);
        }
        if (exposureAfter == HttpShareProtocol.ExposureProtected)
        {
            return [];
        }
        var reason = exposureAfter == HttpShareProtocol.ExposureDisabled
            ? HttpShareProtocol.ReasonRouteDisabled
            : HttpShareProtocol.ReasonRouteMadePublic;
        return await RevokeActiveOfRoutesAsync([route.Id], actor, reason, cancellationToken).ConfigureAwait(false);
    }

    public async Task<List<string>> OnRouteDeletedAsync(string actor, HttpRouteMapping route,
        string exposureBefore, CancellationToken cancellationToken)
    {
        await WriteAuditAsync(ManagementContext.NormalizeTenant(route.TenantId), _clock.NowSeconds, actor,
            HttpShareProtocol.ActionRouteDeleted, route.Id, null,
            new JsonObject { ["exposure"] = exposureBefore }, cancellationToken).ConfigureAwait(false);
        return await RevokeActiveOfRoutesAsync([route.Id], actor, HttpShareProtocol.ReasonRouteDeleted,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<List<string>> OnClientDisabledAsync(string actor, long clientId,
        CancellationToken cancellationToken)
    {
        var routeIds = await _db.HttpRouteMappings.AsNoTracking()
            .Where(r => r.ClientId == clientId)
            .Select(r => r.Id)
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        return await RevokeActiveOfRoutesAsync(routeIds, actor, HttpShareProtocol.ReasonClientDisabled,
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Deleting a client deletes its route rows (no orphan routes are left behind), writes
    /// <c>route.deleted</c> for each in ascending route id, then ends the shares of those routes.
    /// </summary>
    public async Task<List<string>> OnClientDeletedAsync(string actor, long clientId,
        CancellationToken cancellationToken)
    {
        var routes = await _db.HttpRouteMappings.AsNoTracking()
            .Where(r => r.ClientId == clientId)
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        var nowSeconds = _clock.NowSeconds;
        foreach (var route in routes.OrderBy(static r => r.Id))
        {
            await WriteAuditAsync(ManagementContext.NormalizeTenant(route.TenantId), nowSeconds, actor,
                HttpShareProtocol.ActionRouteDeleted, route.Id, null,
                new JsonObject { ["exposure"] = Exposure(route) }, cancellationToken).ConfigureAwait(false);
        }
        await _db.HttpRouteMappings.Where(r => r.ClientId == clientId)
            .ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);
        return await RevokeActiveOfRoutesAsync(routes.Select(static r => r.Id).ToList(), actor,
            HttpShareProtocol.ReasonClientDeleted, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// After a user was disabled, deleted or changed role: ends that user's own active shares whose
    /// creator can no longer manage the route. The change itself is already saved in the transaction.
    /// </summary>
    public async Task<List<string>> OnUserChangedAsync(string actor, string username, string tenantId,
        CancellationToken cancellationToken)
    {
        var tenant = ManagementContext.NormalizeTenant(tenantId);
        var nowSeconds = _clock.NowSeconds;
        var shares = await _db.HttpShares.AsNoTracking()
            .Where(s => s.CreatedBy == username && s.TenantId == tenant && s.RevokedAt == null
                        && s.ExpiresAt > nowSeconds)
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        var revoked = new List<string>();
        var cache = new ContextCache();
        foreach (var share in OrderByCreation(shares))
        {
            var shareContext = await ContextOfAsync(share, cache, cancellationToken).ConfigureAwait(false);
            if (LapseReason(shareContext) == HttpShareProtocol.ReasonCreatorLostAccess
                && await RevokeAsync(share, actor, HttpShareProtocol.ReasonCreatorLostAccess, cancellationToken)
                    .ConfigureAwait(false))
            {
                revoked.Add(share.ShareId);
            }
        }
        return revoked;
    }

    // ----------------------------------------------------------------------------------------------
    // Sweep (spec §7.5)

    /// <summary>
    /// One sweep: records each expiry once (stamped with expiresAt, in expiry order), revokes
    /// active shares that lapsed without any request or hook noticing, and drops ended shares
    /// after 30 days and audit entries after 180 days. Safe to run on many instances at once.
    /// </summary>
    public async Task SweepAsync(CancellationToken cancellationToken)
    {
        var nowSeconds = _clock.NowSeconds;
        var expired = await _db.HttpShares.AsNoTracking()
            .Where(s => s.RevokedAt == null && s.ExpiryRecorded == 0 && s.ExpiresAt <= nowSeconds)
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        foreach (var share in expired.OrderBy(static s => s.ExpiresAt)
                     .ThenBy(static s => s.ShareId, StringComparer.Ordinal))
        {
            await InTransactionAsync(async () =>
            {
                var updated = await _db.HttpShares
                    .Where(s => s.ShareId == share.ShareId && s.RevokedAt == null && s.ExpiryRecorded == 0)
                    .ExecuteUpdateAsync(setters => setters.SetProperty(s => s.ExpiryRecorded, (sbyte)1),
                        cancellationToken)
                    .ConfigureAwait(false);
                if (updated == 1)
                {
                    await WriteAuditAsync(share.TenantId, share.ExpiresAt, null,
                        HttpShareProtocol.ActionShareExpired, share.RouteId, share.ShareId, new JsonObject(),
                        cancellationToken).ConfigureAwait(false);
                }
                return updated == 1;
            }, cancellationToken).ConfigureAwait(false);
        }

        var active = await _db.HttpShares.AsNoTracking()
            .Where(s => s.RevokedAt == null && s.ExpiresAt > nowSeconds)
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        var cache = new ContextCache();
        foreach (var share in OrderByCreation(active))
        {
            var shareContext = await ContextOfAsync(share, cache, cancellationToken).ConfigureAwait(false);
            var reason = LapseReason(shareContext);
            if (reason is not null)
            {
                await ReadTimeRevokeAsync(share, reason, cancellationToken).ConfigureAwait(false);
            }
        }

        var shareCutoff = nowSeconds - HttpShareProtocol.ShareRetentionDays * 86_400L;
        await _db.HttpShares
            .Where(s => (s.RevokedAt != null && s.RevokedAt < shareCutoff)
                        || (s.RevokedAt == null && s.ExpiresAt < shareCutoff))
            .ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);
        var auditCutoff = nowSeconds - HttpShareProtocol.AuditRetentionDays * 86_400L;
        await _db.HttpAccessAudits.Where(a => a.OccurredAt < auditCutoff)
            .ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);
    }

    // ----------------------------------------------------------------------------------------------
    // Helpers

    /// <summary>Writes one audit entry now, so entries keep the order of the events they describe.</summary>
    private async Task WriteAuditAsync(string tenantId, long at, string? actor, string action, long routeId,
        string? shareId, JsonObject detail, CancellationToken cancellationToken)
    {
        var entry = new HttpAccessAudit
        {
            TenantId = tenantId,
            OccurredAt = at,
            Actor = actor,
            Action = action,
            RouteId = routeId,
            ShareId = shareId,
            DetailJson = detail.ToJsonString(JsonOptions),
        };
        _db.HttpAccessAudits.Add(entry);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        _db.Entry(entry).State = EntityState.Detached;
    }

    /// <summary>Joins the ambient transaction (a hook), or runs <paramref name="work"/> in its own.</summary>
    private async Task<T> InTransactionAsync<T>(Func<Task<T>> work, CancellationToken cancellationToken)
    {
        if (_db.Database.CurrentTransaction is not null)
        {
            return await work().ConfigureAwait(false);
        }
        await using var transaction = await _db.Database.BeginTransactionAsync(cancellationToken)
            .ConfigureAwait(false);
        var result = await work().ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return result;
    }

    private ShareResponse Unavailable(Exception error)
    {
        _logger.LogWarning(error, "http share store unavailable");
        return ShareResponse.Error(StatusCodes.Status503ServiceUnavailable, HttpShareCodes.Unavailable);
    }

    private static bool IsStoreFailure(Exception error, CancellationToken cancellationToken) =>
        error is not OperationCanceledException || !cancellationToken.IsCancellationRequested;

    private static long FloorSeconds(long epochMs) => epochMs >= 0 ? epochMs / 1000 : (epochMs - 999) / 1000;

    private static bool TryParseId(string? text, out long value) =>
        long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out value);

    private static bool TryParseLimit(string? text, out int limit)
    {
        limit = 50;
        if (text is null)
        {
            return true;
        }
        return int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out limit)
               && limit is >= 1 and <= 200;
    }

    private static bool TryParseBefore(string? text, out long? before)
    {
        before = null;
        if (text is null)
        {
            return true;
        }
        if (!long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) || parsed < 1)
        {
            return false;
        }
        before = parsed;
        return true;
    }
}
