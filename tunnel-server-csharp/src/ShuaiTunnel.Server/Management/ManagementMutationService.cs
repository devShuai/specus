using Microsoft.EntityFrameworkCore;
using ShuaiTunnel.Server.Authentication;
using ShuaiTunnel.Server.Data;
using ShuaiTunnel.Server.Data.Entities;
using ShuaiTunnel.Server.Nat;
using ShuaiTunnel.Server.Sessions;

namespace ShuaiTunnel.Server.Management;

public sealed class ManagementMutationService
{
    private readonly TunnelDbContext _db;
    private readonly SessionRegistry _sessions;
    private readonly NatControlService _natControl;

    public ManagementMutationService(TunnelDbContext db, SessionRegistry sessions,
        NatControlService natControl)
    {
        _db = db;
        _sessions = sessions;
        _natControl = natControl;
    }

    public async Task<CredentialResult> CreateClientAsync(ClientMutation request, CancellationToken cancellationToken)
    {
        var clientName = RequireClientName(request.ClientName);
        var password = string.IsNullOrWhiteSpace(request.Password)
            ? PasswordHasher.GeneratePassword()
            : request.Password;
        var now = DateTimeOffset.UtcNow;
        var account = new ClientAccount
        {
            Id = ClientIdGenerator.NewId(),
            ClientName = clientName,
            PasswordHash = PasswordHasher.Hash(password),
            Enabled = request.Enabled ?? true,
            ConnectionRateLimitPerMinute = NormalizeRateLimit(request.ConnectionRateLimitPerMinute, 30),
            CreatedAt = now,
            UpdatedAt = now,
        };

        _db.ClientAccounts.Add(account);
        await SaveChangesMappingDuplicateAsync(cancellationToken).ConfigureAwait(false);
        return new CredentialResult(ToClientView(account, upload: 0, download: 0), password);
    }

    public async Task<CredentialResult> UpdateClientAsync(long id, ClientMutation request,
        CancellationToken cancellationToken)
    {
        var account = await FindClientAsync(id, cancellationToken).ConfigureAwait(false);
        var oldName = account.ClientName;

        if (!string.IsNullOrWhiteSpace(request.ClientName))
        {
            account.ClientName = RequireClientName(request.ClientName);
        }
        if (!string.IsNullOrWhiteSpace(request.Password))
        {
            account.PasswordHash = PasswordHasher.Hash(request.Password);
        }
        if (request.Enabled is not null)
        {
            account.Enabled = request.Enabled.Value;
        }
        account.ConnectionRateLimitPerMinute = NormalizeRateLimit(
            request.ConnectionRateLimitPerMinute, account.ConnectionRateLimitPerMinute);
        account.UpdatedAt = DateTimeOffset.UtcNow;

        await SaveChangesMappingDuplicateAsync(cancellationToken).ConfigureAwait(false);
        if (!account.Enabled || !string.Equals(oldName, account.ClientName, StringComparison.Ordinal))
        {
            CloseOnlineChannel(oldName, account.Enabled ? DisconnectReason.AdminRenamed : DisconnectReason.AdminDisabled);
        }

        var totals = await ReadTrafficTotalsAsync(account.Id, cancellationToken).ConfigureAwait(false);
        return new CredentialResult(ToClientView(account, totals.Upload, totals.Download), request.Password);
    }

    public async Task DeleteClientAsync(long id, CancellationToken cancellationToken)
    {
        var account = await FindClientAsync(id, cancellationToken).ConfigureAwait(false);
        CloseOnlineChannel(account.ClientName, DisconnectReason.AdminDeleted);
        _db.ClientAccounts.Remove(account);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<TunnelMappingView>> ListTunnelsAsync(long? clientId,
        CancellationToken cancellationToken)
    {
        var query = _db.TunnelMappings.AsNoTracking();
        if (clientId is not null)
        {
            query = query.Where(t => t.ClientId == clientId.Value);
        }
        var rows = await query.OrderByDescending(t => t.Id).ToListAsync(cancellationToken).ConfigureAwait(false);
        return rows.Select(ToTunnelView).ToList();
    }

    public async Task<TunnelMappingView> CreateTunnelAsync(long clientId, TunnelMappingMutation request,
        CancellationToken cancellationToken)
    {
        var account = await FindClientAsync(clientId, cancellationToken).ConfigureAwait(false);
        var listenPort = RequirePort(request.ListenPort, "listenPort");
        await EnsureListenPortAvailableAsync(listenPort, existingId: null, cancellationToken).ConfigureAwait(false);

        var now = DateTimeOffset.UtcNow;
        var mapping = new TunnelMapping
        {
            Id = ClientIdGenerator.NewId(),
            ClientId = account.Id,
            ClientName = account.ClientName,
            ListenPort = listenPort,
            TargetAddress = RequireTargetAddress(request.TargetAddress),
            TargetPort = RequirePort(request.TargetPort, "targetPort"),
            Enabled = request.Enabled ?? true,
            CreatedAt = now,
            UpdatedAt = now,
        };
        _db.TunnelMappings.Add(mapping);
        await SaveChangesMappingDuplicateAsync(cancellationToken).ConfigureAwait(false);
        await _natControl.PushSnapshotIfOnlineAsync(account.Id, cancellationToken).ConfigureAwait(false);
        return ToTunnelView(mapping);
    }

    public async Task<TunnelMappingView> UpdateTunnelAsync(long id, TunnelMappingMutation request,
        CancellationToken cancellationToken)
    {
        var mapping = await _db.TunnelMappings.FirstOrDefaultAsync(t => t.Id == id, cancellationToken)
            .ConfigureAwait(false) ?? throw new ArgumentException($"mapping not found: {id}");
        var listenPort = RequirePort(request.ListenPort, "listenPort");
        if (listenPort != mapping.ListenPort)
        {
            await EnsureListenPortAvailableAsync(listenPort, mapping.Id, cancellationToken).ConfigureAwait(false);
        }

        mapping.ListenPort = listenPort;
        mapping.TargetAddress = RequireTargetAddress(request.TargetAddress);
        mapping.TargetPort = RequirePort(request.TargetPort, "targetPort");
        mapping.Enabled = request.Enabled ?? true;
        mapping.UpdatedAt = DateTimeOffset.UtcNow;
        await SaveChangesMappingDuplicateAsync(cancellationToken).ConfigureAwait(false);
        await _natControl.PushSnapshotIfOnlineAsync(mapping.ClientId, cancellationToken).ConfigureAwait(false);
        return ToTunnelView(mapping);
    }

    public async Task DeleteTunnelAsync(long id, CancellationToken cancellationToken)
    {
        var mapping = await _db.TunnelMappings.FirstOrDefaultAsync(t => t.Id == id, cancellationToken)
            .ConfigureAwait(false) ?? throw new ArgumentException($"mapping not found: {id}");
        var clientId = mapping.ClientId;
        _db.TunnelMappings.Remove(mapping);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await _natControl.PushSnapshotIfOnlineAsync(clientId, cancellationToken).ConfigureAwait(false);
    }

    public async Task<NatControlPushResponse> PushNatControlAsync(long clientId,
        CancellationToken cancellationToken)
    {
        var result = await _natControl.PushToClientAsync(clientId, cancellationToken).ConfigureAwait(false);
        return new NatControlPushResponse(result.Tunnels, result.Tunnels, result.HttpRoutes);
    }

    public async Task<IReadOnlyList<HttpRouteView>> ListHttpRoutesAsync(long? clientId,
        CancellationToken cancellationToken)
    {
        var query = _db.HttpRouteMappings.AsNoTracking();
        if (clientId is not null)
        {
            query = query.Where(r => r.ClientId == clientId.Value);
        }
        var rows = await query.OrderByDescending(r => r.Id).ToListAsync(cancellationToken).ConfigureAwait(false);
        return rows.Select(ToHttpRouteView).ToList();
    }

    public async Task<HttpRouteView> CreateHttpRouteAsync(long clientId, HttpRouteMutation request,
        CancellationToken cancellationToken)
    {
        var account = await FindClientAsync(clientId, cancellationToken).ConfigureAwait(false);
        var route = RequireRoute(request.Route);
        await EnsureRouteAvailableAsync(account.Id, route, existingId: null, cancellationToken).ConfigureAwait(false);

        var now = DateTimeOffset.UtcNow;
        var row = new HttpRouteMapping
        {
            Id = ClientIdGenerator.NewId(),
            ClientId = account.Id,
            ClientName = account.ClientName,
            Route = route,
            TargetBaseUrl = RequireTargetBaseUrl(request.TargetBaseUrl),
            Enabled = request.Enabled ?? true,
            CreatedAt = now,
            UpdatedAt = now,
        };
        _db.HttpRouteMappings.Add(row);
        await SaveChangesMappingDuplicateAsync(cancellationToken).ConfigureAwait(false);
        await _natControl.PushSnapshotIfOnlineAsync(account.Id, cancellationToken).ConfigureAwait(false);
        return ToHttpRouteView(row);
    }

    public async Task<HttpRouteView> UpdateHttpRouteAsync(long id, HttpRouteMutation request,
        CancellationToken cancellationToken)
    {
        var row = await _db.HttpRouteMappings.FirstOrDefaultAsync(r => r.Id == id, cancellationToken)
            .ConfigureAwait(false) ?? throw new ArgumentException($"http route not found: {id}");
        var route = RequireRoute(request.Route);
        if (!string.Equals(route, row.Route, StringComparison.Ordinal))
        {
            await EnsureRouteAvailableAsync(row.ClientId, route, row.Id, cancellationToken).ConfigureAwait(false);
        }

        row.Route = route;
        row.TargetBaseUrl = RequireTargetBaseUrl(request.TargetBaseUrl);
        row.Enabled = request.Enabled ?? true;
        row.UpdatedAt = DateTimeOffset.UtcNow;
        await SaveChangesMappingDuplicateAsync(cancellationToken).ConfigureAwait(false);
        await _natControl.PushSnapshotIfOnlineAsync(row.ClientId, cancellationToken).ConfigureAwait(false);
        return ToHttpRouteView(row);
    }

    public async Task DeleteHttpRouteAsync(long id, CancellationToken cancellationToken)
    {
        var row = await _db.HttpRouteMappings.FirstOrDefaultAsync(r => r.Id == id, cancellationToken)
            .ConfigureAwait(false) ?? throw new ArgumentException($"http route not found: {id}");
        var clientId = row.ClientId;
        _db.HttpRouteMappings.Remove(row);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await _natControl.PushSnapshotIfOnlineAsync(clientId, cancellationToken).ConfigureAwait(false);
    }

    private async Task<ClientAccount> FindClientAsync(long id, CancellationToken cancellationToken) =>
        await _db.ClientAccounts.FirstOrDefaultAsync(c => c.Id == id, cancellationToken).ConfigureAwait(false)
        ?? throw new ArgumentException($"client not found: {id}");

    private async Task<(long Upload, long Download)> ReadTrafficTotalsAsync(long clientId,
        CancellationToken cancellationToken)
    {
        var rows = await _db.TrafficUsages.AsNoTracking()
            .Where(t => t.ClientId == clientId)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        return (rows.Sum(t => t.UploadBytes), rows.Sum(t => t.DownloadBytes));
    }

    private void CloseOnlineChannel(string clientName, DisconnectReason reason)
    {
        var context = _sessions.Find(clientName);
        if (context is null)
        {
            return;
        }

        context.MarkDisconnectIfAbsent(reason);
        context.CloseAsync();
    }

    private static ClientAccountView ToClientView(ClientAccount account, long upload, long download) => new(
        account.Id,
        account.ClientName,
        account.Enabled,
        account.ConnectionRateLimitPerMinute,
        Online: false,
        ConnectedSinceMs: null,
        upload,
        download,
        account.CreatedAt.ToString("O"),
        account.UpdatedAt.ToString("O"));

    private static TunnelMappingView ToTunnelView(TunnelMapping mapping) => new(
        mapping.Id,
        mapping.ClientId,
        mapping.ClientName,
        mapping.ListenPort,
        mapping.TargetAddress,
        mapping.TargetPort,
        mapping.Enabled,
        mapping.CreatedAt.ToString("O"),
        mapping.UpdatedAt.ToString("O"));

    private static HttpRouteView ToHttpRouteView(HttpRouteMapping row) => new(
        row.Id,
        row.ClientId,
        row.ClientName,
        row.Route,
        row.TargetBaseUrl,
        row.Enabled,
        row.CreatedAt.ToString("O"),
        row.UpdatedAt.ToString("O"));

    private async Task EnsureListenPortAvailableAsync(int listenPort, long? existingId,
        CancellationToken cancellationToken)
    {
        var duplicate = await _db.TunnelMappings.AsNoTracking()
            .FirstOrDefaultAsync(t => t.ListenPort == listenPort, cancellationToken)
            .ConfigureAwait(false);
        if (duplicate is not null && duplicate.Id != existingId)
        {
            throw new ArgumentException($"公网端口 {listenPort} 已被占用");
        }
    }

    private async Task EnsureRouteAvailableAsync(long clientId, string route, long? existingId,
        CancellationToken cancellationToken)
    {
        var duplicate = await _db.HttpRouteMappings.AsNoTracking()
            .FirstOrDefaultAsync(r => r.ClientId == clientId && r.Route == route, cancellationToken)
            .ConfigureAwait(false);
        if (duplicate is not null && duplicate.Id != existingId)
        {
            throw new ArgumentException($"route {route} 已存在于该客户端下");
        }
    }

    private async Task SaveChangesMappingDuplicateAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (DbUpdateException ex)
        {
            throw new ArgumentException("客户端名称已存在或数据不符合约束", ex);
        }
    }

    private static string RequireClientName(string? clientName)
    {
        if (string.IsNullOrWhiteSpace(clientName))
        {
            throw new ArgumentException("clientName cannot be blank");
        }
        var normalized = clientName.Trim();
        if (normalized.Length > 120)
        {
            throw new ArgumentException("clientName is too long");
        }
        return normalized;
    }

    private static int NormalizeRateLimit(int? rateLimit, int defaultValue)
    {
        var normalized = rateLimit ?? defaultValue;
        if (normalized is < 0 or > 10_000)
        {
            throw new ArgumentException("connectionRateLimitPerMinute must be between 0 and 10000");
        }
        return normalized;
    }

    private static int RequirePort(int? port, string field)
    {
        if (port is null or < 1 or > 65_535)
        {
            throw new ArgumentException($"{field} must be between 1 and 65535");
        }
        return port.Value;
    }

    private static string RequireTargetAddress(string? targetAddress)
    {
        if (string.IsNullOrWhiteSpace(targetAddress))
        {
            throw new ArgumentException("targetAddress cannot be blank");
        }
        var normalized = targetAddress.Trim();
        if (normalized.Length > 255)
        {
            throw new ArgumentException("targetAddress is too long");
        }
        return normalized;
    }

    private static string RequireRoute(string? route)
    {
        if (string.IsNullOrWhiteSpace(route))
        {
            throw new ArgumentException("route cannot be blank");
        }
        var normalized = route.Trim();
        if (normalized.Length > 60)
        {
            throw new ArgumentException("route is too long (max 60)");
        }
        if (normalized.Contains('/', StringComparison.Ordinal))
        {
            throw new ArgumentException("route must not contain '/'");
        }
        return normalized;
    }

    private static string RequireTargetBaseUrl(string? targetBaseUrl)
    {
        if (string.IsNullOrWhiteSpace(targetBaseUrl))
        {
            throw new ArgumentException("targetBaseUrl cannot be blank");
        }
        var normalized = targetBaseUrl.Trim();
        if (normalized.Length > 512)
        {
            throw new ArgumentException("targetBaseUrl is too long (max 512)");
        }
        if (!Uri.TryCreate(normalized, UriKind.Absolute, out var uri)
            || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
            || string.IsNullOrWhiteSpace(uri.Host))
        {
            throw new ArgumentException("targetBaseUrl must be an absolute http(s) URL");
        }
        return normalized;
    }
}
