using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Specus.Server.Data;
using Specus.Server.Data.Conversion;
using Specus.Server.Data.Entities;
using Specus.Server.Management;

namespace Specus.Server.Security;

public sealed class WebSocketTicketService
{
    public const string ConnectionsScope = "connections";
    public const string ClientMessagesScope = "client-messages";
    public const string PublicTransferScope = "public-transfer";
    private static readonly TimeSpan TicketLifetime = TimeSpan.FromSeconds(45);

    private readonly IServiceScopeFactory _scopeFactory;

    public WebSocketTicketService(IServiceScopeFactory scopeFactory)
    {
        _scopeFactory = scopeFactory;
    }

    public async Task<IssuedWebSocketTicket> IssueAsync(string scope, string remoteAddress,
        WebSocketTicketClaims claims, CancellationToken cancellationToken)
    {
        RequireScope(scope);
        var token = Base64Url(RandomNumberGenerator.GetBytes(32));
        var now = DateTimeOffset.UtcNow;
        var row = new WebSocketTicket
        {
            AccountKey = claims.AccountKey,
            TokenHash = Digest(token),
            Scope = scope,
            Username = NullIfEmpty(claims.Username),
            TenantId = NullIfEmpty(claims.TenantId),
            IsAdmin = claims.Admin,
            RoomId = NullIfEmpty(claims.RoomId),
            RoomKey = NullIfEmpty(claims.RoomKey),
            RoomRole = NullIfEmpty(claims.RoomRole),
            PeerId = NullIfEmpty(claims.PeerId),
            DisplayName = NullIfEmpty(claims.DisplayName),
            SharedRoom = claims.SharedRoom,
            Discoverable = claims.Discoverable,
            RemoteAddressHash = Digest(remoteAddress),
            CreatedAt = now,
            ExpiresAt = now.Add(TicketLifetime),
        };
        await using var serviceScope = _scopeFactory.CreateAsyncScope();
        var db = serviceScope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        // Oracle EF's DELETE alias is rejected by supported MariaDB. Preserve the
        // model's exact UTC ISO conversion when binding the portable SQL cutoff.
        var cutoff = IsoDateTimeOffsetConverter.Format(now);
        await db.Database.ExecuteSqlInterpolatedAsync($"DELETE FROM specus_websocket_ticket WHERE expires_at <= {cutoff}",
            cancellationToken).ConfigureAwait(false);
        db.WebSocketTickets.Add(row);
        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return new IssuedWebSocketTicket(token, row.ExpiresAt);
    }

    public async Task<WebSocketTicketClaims?> ConsumeAsync(string? ticket, string scope,
        string remoteAddress, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(ticket) || ticket.Length is < 32 or > 128)
        {
            return null;
        }
        RequireScope(scope);
        var now = DateTimeOffset.UtcNow;
        var tokenHash = Digest(ticket.Trim());
        var addressHash = Digest(remoteAddress);
        await using var serviceScope = _scopeFactory.CreateAsyncScope();
        var db = serviceScope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var row = await db.WebSocketTickets.AsNoTracking()
            .SingleOrDefaultAsync(item => item.TokenHash == tokenHash, cancellationToken)
            .ConfigureAwait(false);
        if (row is null || row.Scope != scope || row.RemoteAddressHash != addressHash
            || row.ExpiresAt <= now)
        {
            return null;
        }
        var cutoff = IsoDateTimeOffsetConverter.Format(now);
        var consumed = await db.Database.ExecuteSqlInterpolatedAsync($"""
            DELETE FROM specus_websocket_ticket
            WHERE token_hash={tokenHash} AND scope={scope}
              AND remote_address_hash={addressHash} AND expires_at>{cutoff}
            """, cancellationToken).ConfigureAwait(false);
        if (consumed != 1)
        {
            return null;
        }
        return new WebSocketTicketClaims(row.Username, row.TenantId, row.IsAdmin, row.RoomId,
            row.RoomKey, row.PeerId, row.DisplayName, row.SharedRoom, row.RoomRole,
            row.Discoverable, row.AccountKey);
    }

    public static string? ExtractTicket(HttpRequest request)
    {
        if (request.Query.Count != 1 || !request.Query.TryGetValue("ticket", out var values)
            || values.Count != 1)
        {
            return null;
        }
        var ticket = values[0]?.Trim();
        return string.IsNullOrWhiteSpace(ticket) ? null : ticket;
    }

    /// <summary>
    /// Must produce the same binding for the ticket POST and the upgrade. Both go through the shared
    /// trusted-proxy boundary so a forged header cannot rebind someone else's ticket.
    /// </summary>
    public static string RequestAddress(ClientAddressResolver resolver, HttpContext context) =>
        resolver.Resolve(context);

    public static string RoomKey(string roomToken) =>
        "token:" + Digest(roomToken).ToLowerInvariant();

    private static void RequireScope(string scope)
    {
        if (scope is not (ConnectionsScope or ClientMessagesScope or PublicTransferScope))
        {
            throw new ArgumentException("unsupported websocket ticket scope", nameof(scope));
        }
    }

    private static string Digest(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    private static string Base64Url(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string? NullIfEmpty(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}

public sealed record WebSocketTicketClaims(string? Username = null, string? TenantId = null,
    bool Admin = false, string? RoomId = null, string? RoomKey = null, string? PeerId = null,
    string? DisplayName = null, bool SharedRoom = false, string? RoomRole = null,
    bool Discoverable = true, string? AccountKey = null)
{
    public ClaimsPrincipal ToPrincipal()
    {
        var identity = new ClaimsIdentity("WebSocketTicket");
        var username = Username?.Trim() ?? string.Empty;
        if (username.Length > 0)
        {
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, username));
            identity.AddClaim(new Claim(ClaimTypes.Name, username));
        }
        identity.AddClaim(new Claim("tenant_id", ManagementContext.NormalizeTenant(TenantId)));
        if (!string.IsNullOrEmpty(AccountKey))
        {
            identity.AddClaim(new Claim(LocalTokenService.AccountKeyClaim, AccountKey));
        }
        identity.AddClaim(new Claim(ClaimTypes.Role, Admin ? "ADMIN" : "USER"));
        return new ClaimsPrincipal(identity);
    }
}

public sealed record IssuedWebSocketTicket(string Ticket, DateTimeOffset ExpiresAt);
