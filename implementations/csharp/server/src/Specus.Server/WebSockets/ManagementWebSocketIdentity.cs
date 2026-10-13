using Specus.Server.Data.Entities;
using Specus.Server.Management;
using Specus.Server.Security;

namespace Specus.Server.WebSockets;

/// <summary>Resolve the ticket against current state before upgrade and after registration.</summary>
public sealed class ManagementWebSocketIdentity(IServiceScopeFactory scopes)
{
    public const string Revoked = "identity revoked";

    public async Task<bool> CurrentAsync(WebSocketTicketClaims claims, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(claims.Username) || string.IsNullOrWhiteSpace(claims.TenantId))
        {
            return false;
        }
        await using var scope = scopes.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<ManagementUserService>();
        var current = await users.ResolveLocalTokenUserAsync(claims.Username, claims.TenantId,
            claims.AccountKey, cancellationToken).ConfigureAwait(false);
        return current is not null && (current.Role == ManagementRole.Admin) == claims.Admin;
    }
}
