using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Specus.Server.Authentication;
using Specus.Server.Configuration;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Nat;
using Specus.Server.Sessions;

namespace Specus.Server.Management;

public sealed class ManagementMutationService
{
    private static readonly HashSet<string> AllowedDownloadImplementations =
        new(StringComparer.OrdinalIgnoreCase) { "java", "go", "csharp" };
    private static readonly HashSet<string> AllowedDownloadPlatforms =
        new(StringComparer.OrdinalIgnoreCase) { "windows", "linux", "macos", "any" };
    private static readonly HashSet<string> AllowedDownloadArchitectures =
        new(StringComparer.OrdinalIgnoreCase) { "x64", "arm64", "any" };

    private readonly SpecusDbContext _db;
    private readonly SessionRegistry _sessions;
    private readonly NatControlService _natControl;
    private readonly ClientAuthOptions _clientAuth;

    public ManagementMutationService(SpecusDbContext db, SessionRegistry sessions,
        NatControlService natControl, IOptions<ClientAuthOptions> clientAuth)
    {
        _db = db;
        _sessions = sessions;
        _natControl = natControl;
        _clientAuth = clientAuth.Value;
    }

    public async Task<ClientResult> CreateClientAsync(ManagementContext context, ClientMutation request,
        CancellationToken cancellationToken)
    {
        var clientName = RequireClientName(request.ClientName);
        var now = DateTimeOffset.UtcNow;
        var account = new ClientAccount
        {
            Id = ClientIdGenerator.NewId(),
            TenantId = context.TenantId,
            OwnerUsername = context.Username,
            ClientName = clientName,
            PasswordHash = PasswordHasher.Hash(Guid.NewGuid().ToString("N")),
            Enabled = request.Enabled ?? true,
            ConnectionRateLimitPerMinute = NormalizeRateLimit(request.ConnectionRateLimitPerMinute, 30),
            CreatedAt = now,
            UpdatedAt = now,
        };

        _db.ClientAccounts.Add(account);
        await SaveChangesMappingDuplicateAsync(cancellationToken).ConfigureAwait(false);
        return new ClientResult(ToClientView(account, upload: 0, download: 0));
    }

    public async Task<ClientResult> UpdateClientAsync(ManagementContext context, long id, ClientMutation request,
        CancellationToken cancellationToken)
    {
        var account = await FindClientAsync(context, id, cancellationToken).ConfigureAwait(false);
        var oldName = account.ClientName;

        if (!string.IsNullOrWhiteSpace(request.ClientName))
        {
            account.ClientName = RequireClientName(request.ClientName);
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

        var totals = await ReadTrafficTotalsAsync(context, account.Id, cancellationToken).ConfigureAwait(false);
        return new ClientResult(ToClientView(account, totals.Upload, totals.Download));
    }

    public async Task DeleteClientAsync(ManagementContext context, long id, CancellationToken cancellationToken)
    {
        var account = await FindClientAsync(context, id, cancellationToken).ConfigureAwait(false);
        CloseOnlineChannel(account.ClientName, DisconnectReason.AdminDeleted);
        _db.ClientAccounts.Remove(account);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<ClientNameAvailability> ClientNameAvailabilityAsync(ManagementContext context,
        string? clientNameValue, long? excludeClientId, CancellationToken cancellationToken)
    {
        var clientName = RequireClientName(clientNameValue);
        if (excludeClientId is not null)
        {
            var excluded = await _db.ClientAccounts.AsNoTracking()
                .FirstOrDefaultAsync(row => row.Id == excludeClientId.Value, cancellationToken)
                .ConfigureAwait(false);
            if (excluded is null || !context.CanAccess(excluded))
            {
                throw new ArgumentException($"client not found: {excludeClientId.Value}");
            }
        }

        var existingId = await _db.ClientAccounts.AsNoTracking()
            .Where(row => row.ClientName == clientName)
            .Select(row => (long?)row.Id)
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);
        return new ClientNameAvailability(clientName,
            existingId is null || existingId == excludeClientId);
    }

    public async Task<IReadOnlyList<ClientCredentialView>> ListCredentialsAsync(ManagementContext context,
        CancellationToken cancellationToken)
    {
        var rows = await _db.ClientCredentials.AsNoTracking()
            .Where(c => c.TenantId == context.TenantId
                && (context.IsAdmin || c.OwnerUsername == context.Username))
            .OrderByDescending(c => c.Id)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        return rows.Select(ToCredentialView).ToList();
    }

    public async Task<CredentialResult> CreateCredentialAsync(ManagementContext context, CredentialMutation request,
        CancellationToken cancellationToken)
    {
        var apiKey = string.IsNullOrWhiteSpace(request.ApiKey)
            ? "ck_" + Guid.NewGuid().ToString("N")
            : NormalizeApiKey(request.ApiKey);
        if (await _db.ClientCredentials.AsNoTracking()
                .AnyAsync(c => c.ApiKey == apiKey, cancellationToken)
                .ConfigureAwait(false))
        {
            throw new ArgumentException("apiKey already exists");
        }

        var secret = string.IsNullOrWhiteSpace(request.Secret)
            ? PasswordHasher.GeneratePassword()
            : request.Secret.Trim();
        var now = DateTimeOffset.UtcNow;
        var credential = new ClientCredential
        {
            Id = ClientIdGenerator.NewId(),
            TenantId = context.TenantId,
            OwnerUsername = context.Username,
            ApiKey = apiKey,
            SecretHash = PasswordHasher.Hash(secret),
            Enabled = request.Enabled ?? true,
            MaxOnlineInstances = NormalizeMaxOnline(request.MaxOnlineInstances,
                _clientAuth.DefaultMaxOnlineInstances),
            CreatedAt = now,
            UpdatedAt = now,
        };
        _db.ClientCredentials.Add(credential);
        await SaveChangesMappingDuplicateAsync(cancellationToken).ConfigureAwait(false);
        return new CredentialResult(ToCredentialView(credential), secret);
    }

    public async Task<CredentialResult> UpdateCredentialAsync(ManagementContext context, long id,
        CredentialMutation request,
        CancellationToken cancellationToken)
    {
        var credential = await _db.ClientCredentials.FirstOrDefaultAsync(c => c.Id == id, cancellationToken)
            .ConfigureAwait(false) ?? throw new ArgumentException($"credential not found: {id}");
        EnsureCredentialAccess(context, credential);
        if (!string.IsNullOrWhiteSpace(request.ApiKey))
        {
            var apiKey = NormalizeApiKey(request.ApiKey);
            if (!string.Equals(apiKey, credential.ApiKey, StringComparison.Ordinal))
            {
                if (await _db.ClientCredentials.AsNoTracking()
                        .AnyAsync(c => c.ApiKey == apiKey, cancellationToken)
                        .ConfigureAwait(false))
                {
                    throw new ArgumentException("apiKey already exists");
                }
                credential.ApiKey = apiKey;
            }
        }

        string? revealedSecret = null;
        if (!string.IsNullOrWhiteSpace(request.Secret))
        {
            revealedSecret = request.Secret.Trim();
            credential.SecretHash = PasswordHasher.Hash(revealedSecret);
        }
        if (request.Enabled is not null)
        {
            credential.Enabled = request.Enabled.Value;
        }
        if (request.MaxOnlineInstances is not null)
        {
            credential.MaxOnlineInstances = NormalizeMaxOnline(request.MaxOnlineInstances,
                _clientAuth.DefaultMaxOnlineInstances);
        }
        credential.UpdatedAt = DateTimeOffset.UtcNow;
        await SaveChangesMappingDuplicateAsync(cancellationToken).ConfigureAwait(false);
        return new CredentialResult(ToCredentialView(credential), revealedSecret);
    }

    public async Task DeleteCredentialAsync(ManagementContext context, long id, CancellationToken cancellationToken)
    {
        var credential = await _db.ClientCredentials.FirstOrDefaultAsync(c => c.Id == id, cancellationToken)
            .ConfigureAwait(false) ?? throw new ArgumentException($"credential not found: {id}");
        EnsureCredentialAccess(context, credential);
        _db.ClientCredentials.Remove(credential);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<ClientDownloadLinkView>> ListClientDownloadsAsync(
        ManagementContext context,
        CancellationToken cancellationToken)
    {
        ManagementUserService.RequireAdmin(context);
        var rows = await _db.ClientDownloadLinks.AsNoTracking()
            .OrderBy(link => link.DisplayOrder)
            .ThenBy(link => link.Id)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        return rows.Select(ToClientDownloadLinkView).ToList();
    }

    public async Task<ClientDownloadLinkView> CreateClientDownloadAsync(
        ManagementContext context,
        ClientDownloadLinkMutation request,
        CancellationToken cancellationToken)
    {
        ManagementUserService.RequireAdmin(context);
        var now = DateTimeOffset.UtcNow;
        var link = new ClientDownloadLink
        {
            Id = ClientIdGenerator.NewId(),
            DisplayOrder = request.DisplayOrder ?? 0,
            Enabled = request.Enabled ?? true,
            CreatedAt = now,
            UpdatedAt = now,
        };
        ApplyClientDownloadMutation(link, request);
        link.CreatedAt = now;
        _db.ClientDownloadLinks.Add(link);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return ToClientDownloadLinkView(link);
    }

    public async Task<ClientDownloadLinkView> UpdateClientDownloadAsync(
        ManagementContext context,
        long id,
        ClientDownloadLinkMutation request,
        CancellationToken cancellationToken)
    {
        ManagementUserService.RequireAdmin(context);
        var link = await _db.ClientDownloadLinks.FirstOrDefaultAsync(row => row.Id == id, cancellationToken)
            .ConfigureAwait(false) ?? throw new ArgumentException($"client download link not found: {id}");
        ApplyClientDownloadMutation(link, request);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return ToClientDownloadLinkView(link);
    }

    public async Task DeleteClientDownloadAsync(ManagementContext context, long id,
        CancellationToken cancellationToken)
    {
        ManagementUserService.RequireAdmin(context);
        var link = await _db.ClientDownloadLinks.FirstOrDefaultAsync(row => row.Id == id, cancellationToken)
            .ConfigureAwait(false) ?? throw new ArgumentException($"client download link not found: {id}");
        _db.ClientDownloadLinks.Remove(link);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<SpecusMappingView>> ListSpecusMappingsAsync(ManagementContext context, long? clientId,
        CancellationToken cancellationToken)
    {
        var visibleIds = await VisibleClientIdsAsync(context, cancellationToken).ConfigureAwait(false);
        var query = _db.SpecusMappings.AsNoTracking();
        if (clientId is not null)
        {
            EnsureVisibleClient(visibleIds, clientId.Value);
            query = query.Where(t => t.ClientId == clientId.Value);
        }
        else
        {
            query = query.Where(t => visibleIds.Contains(t.ClientId));
        }
        var rows = await query.OrderByDescending(t => t.Id).ToListAsync(cancellationToken).ConfigureAwait(false);
        return rows.Select(ToSpecusView).ToList();
    }

    public async Task<SpecusMappingView> CreateSpecusAsync(ManagementContext context, long clientId,
        SpecusMappingMutation request,
        CancellationToken cancellationToken)
    {
        var account = await FindClientAsync(context, clientId, cancellationToken).ConfigureAwait(false);
        var listenPort = RequirePort(request.ListenPort, "listenPort");
        await EnsureListenPortAvailableAsync(listenPort, existingId: null, cancellationToken).ConfigureAwait(false);

        var now = DateTimeOffset.UtcNow;
        var mapping = new SpecusMapping
        {
            Id = ClientIdGenerator.NewId(),
            ClientId = account.Id,
            ClientName = account.ClientName,
            ListenPort = listenPort,
            TargetAddress = RequireTargetAddress(request.TargetAddress),
            TargetPort = RequirePort(request.TargetPort, "targetPort"),
            Enabled = request.Enabled ?? true,
            DetailCaptureEnabled = request.DetailCaptureEnabled ?? false,
            CreatedAt = now,
            UpdatedAt = now,
        };
        _db.SpecusMappings.Add(mapping);
        await SaveChangesMappingDuplicateAsync(cancellationToken).ConfigureAwait(false);
        await _natControl.PushSnapshotIfOnlineAsync(account.Id, cancellationToken).ConfigureAwait(false);
        return ToSpecusView(mapping);
    }

    public async Task<SpecusMappingView> UpdateSpecusAsync(ManagementContext context, long id,
        SpecusMappingMutation request,
        CancellationToken cancellationToken)
    {
        var mapping = await _db.SpecusMappings.FirstOrDefaultAsync(t => t.Id == id, cancellationToken)
            .ConfigureAwait(false) ?? throw new ArgumentException($"mapping not found: {id}");
        await EnsureClientAccessAsync(context, mapping.ClientId, cancellationToken).ConfigureAwait(false);
        var listenPort = RequirePort(request.ListenPort, "listenPort");
        if (listenPort != mapping.ListenPort)
        {
            await EnsureListenPortAvailableAsync(listenPort, mapping.Id, cancellationToken).ConfigureAwait(false);
        }

        mapping.ListenPort = listenPort;
        mapping.TargetAddress = RequireTargetAddress(request.TargetAddress);
        mapping.TargetPort = RequirePort(request.TargetPort, "targetPort");
        mapping.Enabled = request.Enabled ?? mapping.Enabled;
        mapping.DetailCaptureEnabled = request.DetailCaptureEnabled ?? mapping.DetailCaptureEnabled;
        mapping.UpdatedAt = DateTimeOffset.UtcNow;
        await SaveChangesMappingDuplicateAsync(cancellationToken).ConfigureAwait(false);
        await _natControl.PushSnapshotIfOnlineAsync(mapping.ClientId, cancellationToken).ConfigureAwait(false);
        return ToSpecusView(mapping);
    }

    public async Task DeleteSpecusAsync(ManagementContext context, long id, CancellationToken cancellationToken)
    {
        var mapping = await _db.SpecusMappings.FirstOrDefaultAsync(t => t.Id == id, cancellationToken)
            .ConfigureAwait(false) ?? throw new ArgumentException($"mapping not found: {id}");
        await EnsureClientAccessAsync(context, mapping.ClientId, cancellationToken).ConfigureAwait(false);
        var clientId = mapping.ClientId;
        _db.SpecusMappings.Remove(mapping);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await _natControl.PushSnapshotIfOnlineAsync(clientId, cancellationToken).ConfigureAwait(false);
    }

    public async Task<NatControlPushResponse> PushNatControlAsync(ManagementContext context, long clientId,
        CancellationToken cancellationToken)
    {
        await EnsureClientAccessAsync(context, clientId, cancellationToken).ConfigureAwait(false);
        var result = await _natControl.PushToClientAsync(clientId, cancellationToken).ConfigureAwait(false);
        return new NatControlPushResponse(result.SpecusMappings, result.SpecusMappings, result.HttpRoutes);
    }

    public async Task<IReadOnlyList<HttpRouteView>> ListHttpRoutesAsync(ManagementContext context, long? clientId,
        CancellationToken cancellationToken)
    {
        var visibleIds = await VisibleClientIdsAsync(context, cancellationToken).ConfigureAwait(false);
        var query = _db.HttpRouteMappings.AsNoTracking();
        if (clientId is not null)
        {
            EnsureVisibleClient(visibleIds, clientId.Value);
            query = query.Where(r => r.ClientId == clientId.Value);
        }
        else
        {
            query = query.Where(r => visibleIds.Contains(r.ClientId));
        }
        var rows = await query.OrderByDescending(r => r.Id).ToListAsync(cancellationToken).ConfigureAwait(false);
        return rows.Select(ToHttpRouteView).ToList();
    }

    public async Task<HttpRouteView> CreateHttpRouteAsync(ManagementContext context, long clientId,
        HttpRouteMutation request,
        CancellationToken cancellationToken)
    {
        var account = await FindClientAsync(context, clientId, cancellationToken).ConfigureAwait(false);
        var route = RequireRoute(request.Route);
        await EnsureRouteAvailableAsync(account.Id, route, existingId: null, cancellationToken).ConfigureAwait(false);

        var now = DateTimeOffset.UtcNow;
        var authEnabled = request.AuthEnabled ?? false;
        var authUsername = NormalizeAuthUsername(request.AuthUsername);
        var authPasswordHash = HashAuthPasswordIfPresent(request.AuthPassword);
        ValidateAuthConfiguration(authEnabled, authUsername, authPasswordHash);
        var row = new HttpRouteMapping
        {
            Id = ClientIdGenerator.NewId(),
            ClientId = account.Id,
            ClientName = account.ClientName,
            Route = route,
            TargetBaseUrl = RequireTargetBaseUrl(request.TargetBaseUrl),
            Enabled = request.Enabled ?? true,
            DetailCaptureEnabled = request.DetailCaptureEnabled ?? false,
            MediaCaptureEnabled = request.MediaCaptureEnabled ?? false,
            PathRewriteEnabled = request.PathRewriteEnabled ?? false,
            AuthEnabled = authEnabled,
            AuthUsername = authUsername,
            AuthPasswordHash = authPasswordHash,
            CreatedAt = now,
            UpdatedAt = now,
        };
        _db.HttpRouteMappings.Add(row);
        await SaveChangesMappingDuplicateAsync(cancellationToken).ConfigureAwait(false);
        await _natControl.PushSnapshotIfOnlineAsync(account.Id, cancellationToken).ConfigureAwait(false);
        return ToHttpRouteView(row);
    }

    public async Task<HttpRouteView> UpdateHttpRouteAsync(ManagementContext context, long id,
        HttpRouteMutation request,
        CancellationToken cancellationToken)
    {
        var row = await _db.HttpRouteMappings.FirstOrDefaultAsync(r => r.Id == id, cancellationToken)
            .ConfigureAwait(false) ?? throw new ArgumentException($"http route not found: {id}");
        await EnsureClientAccessAsync(context, row.ClientId, cancellationToken).ConfigureAwait(false);
        var route = RequireRoute(request.Route);
        if (!string.Equals(route, row.Route, StringComparison.Ordinal))
        {
            await EnsureRouteAvailableAsync(row.ClientId, route, row.Id, cancellationToken).ConfigureAwait(false);
        }

        row.Route = route;
        row.TargetBaseUrl = RequireTargetBaseUrl(request.TargetBaseUrl);
        row.Enabled = request.Enabled ?? row.Enabled;
        row.DetailCaptureEnabled = request.DetailCaptureEnabled ?? row.DetailCaptureEnabled;
        row.MediaCaptureEnabled = request.MediaCaptureEnabled ?? row.MediaCaptureEnabled;
        row.PathRewriteEnabled = request.PathRewriteEnabled ?? row.PathRewriteEnabled;
        row.AuthEnabled = request.AuthEnabled ?? row.AuthEnabled;
        if (request.AuthUsername is not null)
        {
            row.AuthUsername = NormalizeAuthUsername(request.AuthUsername);
        }
        var authPasswordHash = HashAuthPasswordIfPresent(request.AuthPassword);
        if (authPasswordHash is not null)
        {
            row.AuthPasswordHash = authPasswordHash;
        }
        ValidateAuthConfiguration(row.AuthEnabled, row.AuthUsername, row.AuthPasswordHash);
        row.UpdatedAt = DateTimeOffset.UtcNow;
        await SaveChangesMappingDuplicateAsync(cancellationToken).ConfigureAwait(false);
        await _natControl.PushSnapshotIfOnlineAsync(row.ClientId, cancellationToken).ConfigureAwait(false);
        return ToHttpRouteView(row);
    }

    public async Task DeleteHttpRouteAsync(ManagementContext context, long id, CancellationToken cancellationToken)
    {
        var row = await _db.HttpRouteMappings.FirstOrDefaultAsync(r => r.Id == id, cancellationToken)
            .ConfigureAwait(false) ?? throw new ArgumentException($"http route not found: {id}");
        await EnsureClientAccessAsync(context, row.ClientId, cancellationToken).ConfigureAwait(false);
        var clientId = row.ClientId;
        _db.HttpRouteMappings.Remove(row);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await _natControl.PushSnapshotIfOnlineAsync(clientId, cancellationToken).ConfigureAwait(false);
    }

    private async Task<ClientAccount> FindClientAsync(ManagementContext context, long id,
        CancellationToken cancellationToken)
    {
        var account = await _db.ClientAccounts.FirstOrDefaultAsync(c => c.Id == id, cancellationToken)
            .ConfigureAwait(false) ?? throw new ArgumentException($"client not found: {id}");
        if (!context.CanAccess(account))
        {
            throw new UnauthorizedAccessException("无权访问客户端");
        }
        return account;
    }

    private async Task EnsureClientAccessAsync(ManagementContext context, long clientId,
        CancellationToken cancellationToken)
    {
        _ = await FindClientAsync(context, clientId, cancellationToken).ConfigureAwait(false);
    }

    private async Task<IReadOnlyList<long>> VisibleClientIdsAsync(ManagementContext context,
        CancellationToken cancellationToken) =>
        await _db.ClientAccounts.AsNoTracking()
            .Where(c => c.TenantId == context.TenantId
                && (context.IsAdmin || c.OwnerUsername == context.Username))
            .Select(c => c.Id)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

    private static void EnsureVisibleClient(IReadOnlyList<long> visibleIds, long clientId)
    {
        if (!visibleIds.Contains(clientId))
        {
            throw new UnauthorizedAccessException("无权访问客户端");
        }
    }

    private static void EnsureCredentialAccess(ManagementContext context, ClientCredential credential)
    {
        if (!context.CanAccess(credential))
        {
            throw new UnauthorizedAccessException("无权访问客户端凭证");
        }
    }

    private async Task<(long Upload, long Download)> ReadTrafficTotalsAsync(ManagementContext context, long clientId,
        CancellationToken cancellationToken)
    {
        var rows = await _db.TrafficUsages.AsNoTracking()
            .Where(t => t.ClientId == clientId
                        && (t.TenantId == context.TenantId
                            || t.TenantId == null
                            || t.TenantId == string.Empty))
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
        account.OwnerUsername,
        account.Enabled,
        account.ConnectionRateLimitPerMinute,
        Online: false,
        ConnectedSinceMs: null,
        MessageSendCapable: false,
        MessageReceiveCapable: false,
        MessageAttachmentsCapable: false,
        MessageMediaPreviewCapable: false,
        MessageMaxAttachmentBytes: 0L,
        upload,
        download,
        account.CreatedAt.ToString("O"),
        account.UpdatedAt.ToString("O"));

    private static ClientCredentialView ToCredentialView(ClientCredential credential) => new(
        credential.Id,
        credential.ApiKey,
        credential.OwnerUsername,
        credential.Enabled,
        credential.MaxOnlineInstances,
        credential.CreatedAt.ToString("O"),
        credential.UpdatedAt.ToString("O"));

    private static ClientDownloadLinkView ToClientDownloadLinkView(ClientDownloadLink link) => new(
        link.Id,
        link.Implementation,
        link.Platform,
        link.Arch,
        link.DisplayName,
        link.DownloadUrl,
        link.Description,
        link.DisplayOrder,
        link.Enabled,
        link.CreatedAt.ToString("O"),
        link.UpdatedAt.ToString("O"));

    private static SpecusMappingView ToSpecusView(SpecusMapping mapping) => new(
        mapping.Id,
        mapping.ClientId,
        mapping.ClientName,
        mapping.ListenPort,
        mapping.TargetAddress,
        mapping.TargetPort,
        mapping.Enabled,
        mapping.DetailCaptureEnabled,
        mapping.CreatedAt.ToString("O"),
        mapping.UpdatedAt.ToString("O"));

    private static HttpRouteView ToHttpRouteView(HttpRouteMapping row) => new(
        row.Id,
        row.ClientId,
        row.ClientName,
        row.Route,
        row.TargetBaseUrl,
        row.Enabled,
        row.DetailCaptureEnabled,
        row.MediaCaptureEnabled,
        row.PathRewriteEnabled,
        row.AuthEnabled,
        row.AuthUsername ?? string.Empty,
        !string.IsNullOrWhiteSpace(row.AuthPasswordHash),
        row.CreatedAt.ToString("O"),
        row.UpdatedAt.ToString("O"));

    private static string? NormalizeAuthUsername(string? username)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return null;
        }
        var normalized = username.Trim();
        if (normalized.Length > 120)
        {
            throw new ArgumentException("authUsername is too long (max 120)");
        }
        if (normalized.IndexOfAny([':', '\r', '\n']) >= 0)
        {
            throw new ArgumentException("authUsername must not contain ':', CR, or LF");
        }
        return normalized;
    }

    private static string? HashAuthPasswordIfPresent(string? password)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            return null;
        }
        if (password.Length > 256)
        {
            throw new ArgumentException("authPassword is too long (max 256)");
        }
        return PasswordHasher.Hash(password);
    }

    private static void ValidateAuthConfiguration(bool enabled, string? username, string? passwordHash)
    {
        if (!enabled)
        {
            return;
        }
        if (string.IsNullOrWhiteSpace(username))
        {
            throw new ArgumentException("authUsername cannot be blank when authentication is enabled");
        }
        if (string.IsNullOrWhiteSpace(passwordHash))
        {
            throw new ArgumentException("authPassword is required when authentication is enabled");
        }
    }

    private async Task EnsureListenPortAvailableAsync(int listenPort, long? existingId,
        CancellationToken cancellationToken)
    {
        var duplicate = await _db.SpecusMappings.AsNoTracking()
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

    private static int NormalizeMaxOnline(int? maxOnlineInstances, int defaultValue)
    {
        var normalized = maxOnlineInstances ?? defaultValue;
        if (normalized is < 1 or > 10_000)
        {
            throw new ArgumentException("maxOnlineInstances must be between 1 and 10000");
        }
        return normalized;
    }

    private static string NormalizeApiKey(string? apiKey)
    {
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            throw new ArgumentException("apiKey cannot be blank");
        }
        var normalized = apiKey.Trim();
        if (normalized.Length is < 3 or > 120)
        {
            throw new ArgumentException("apiKey length must be between 3 and 120");
        }
        return normalized;
    }

    private static void ApplyClientDownloadMutation(ClientDownloadLink link, ClientDownloadLinkMutation request)
    {
        link.Implementation = RequireDownloadEnum(request.Implementation, AllowedDownloadImplementations,
            "implementation must be one of [java go csharp]");
        link.Platform = RequireDownloadEnum(request.Platform, AllowedDownloadPlatforms,
            "platform must be one of [windows linux macos any]");
        link.Arch = RequireDownloadEnum(request.Arch, AllowedDownloadArchitectures,
            "arch must be one of [x64 arm64 any]");
        link.DisplayName = RequireDisplayName(request.DisplayName);
        link.DownloadUrl = RequireDownloadUrl(request.DownloadUrl);
        link.Description = NormalizeDownloadDescription(request.Description);
        if (request.DisplayOrder is not null)
        {
            link.DisplayOrder = request.DisplayOrder.Value;
        }
        if (request.Enabled is not null)
        {
            link.Enabled = request.Enabled.Value;
        }
        link.UpdatedAt = DateTimeOffset.UtcNow;
    }

    private static string RequireDownloadEnum(string? value, IReadOnlySet<string> allowed, string message)
    {
        var normalized = value?.Trim().ToLowerInvariant() ?? string.Empty;
        if (!allowed.Contains(normalized))
        {
            throw new ArgumentException(message);
        }
        return normalized;
    }

    private static string RequireDisplayName(string? displayName)
    {
        if (string.IsNullOrWhiteSpace(displayName))
        {
            throw new ArgumentException("displayName cannot be blank");
        }
        var normalized = displayName.Trim();
        if (normalized.Length > 120)
        {
            throw new ArgumentException("displayName is too long (max 120)");
        }
        return normalized;
    }

    private static string RequireDownloadUrl(string? downloadUrl)
    {
        if (string.IsNullOrWhiteSpace(downloadUrl))
        {
            throw new ArgumentException("downloadUrl cannot be blank");
        }
        var normalized = downloadUrl.Trim();
        if (normalized.Length > 1024)
        {
            throw new ArgumentException("downloadUrl is too long (max 1024)");
        }
        if (!Uri.TryCreate(normalized, UriKind.Absolute, out var uri)
            || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
            || string.IsNullOrWhiteSpace(uri.Host))
        {
            throw new ArgumentException("downloadUrl must be an absolute http(s) URL");
        }
        return normalized;
    }

    private static string? NormalizeDownloadDescription(string? description)
    {
        if (string.IsNullOrWhiteSpace(description))
        {
            return null;
        }
        var normalized = description.Trim();
        return normalized.Length > 512 ? normalized[..512] : normalized;
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
