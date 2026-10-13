using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Specus.Server.Data;
using Specus.Server.Security;

namespace Specus.Server.WebSockets;

/// <summary>Account mutation commits first; local and remote management sessions then close.</summary>
public sealed class ManagementAccessRevocations : IHostedService
{
    public const string Deleted = "deleted";
    public const string Disabled = "disabled";
    public const string RoleChanged = "role-changed";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly ClientMessagesHub _messages;
    private readonly ConnectionEventsHub _connections;
    private readonly PublicTransferCoordinationService _coordination;
    private readonly ILogger<ManagementAccessRevocations> _logger;

    public ManagementAccessRevocations(ClientMessagesHub messages, ConnectionEventsHub connections,
        PublicTransferCoordinationService coordination, ILogger<ManagementAccessRevocations> logger)
    {
        _messages = messages;
        _connections = connections;
        _coordination = coordination;
        _logger = logger;
        coordination.AddListener(HandleClusterEventAsync);
    }

    // Eager construction subscribes every instance, including instances handling only WebSockets.
    public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public static Task RevokeTicketsAsync(SpecusDbContext db, string tenantId, string username,
        CancellationToken cancellationToken) => db.WebSocketTickets
        .Where(ticket => (ticket.Scope == WebSocketTicketService.ConnectionsScope
            || ticket.Scope == WebSocketTicketService.ClientMessagesScope)
            && ticket.TenantId == tenantId && ticket.Username == username)
        .ExecuteDeleteAsync(cancellationToken);

    public async Task CommittedAsync(string tenantId, string username, string reason)
    {
        await CloseLocalAsync(tenantId, username, reason).ConfigureAwait(false);
        if (!_coordination.Enabled) return;
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await _coordination.PublishManagementRevocationAsync(tenantId,
                JsonSerializer.SerializeToUtf8Bytes(new Revocation(tenantId, username, reason), JsonOptions),
                timeout.Token).ConfigureAwait(false);
        }
        catch (Exception error)
        {
            // Pub/Sub is best effort. The committed account state still rejects later handshakes.
            _logger.LogWarning(error, "publishing management revocation failed; remote connections may remain open");
        }
    }

    private Task CloseLocalAsync(string tenantId, string username, string reason)
    {
        var closeReason = reason switch
        {
            Deleted => "account deleted",
            Disabled => "account disabled",
            RoleChanged => "account role changed",
            _ => "account revoked",
        };
        return Task.WhenAll(_messages.CloseIdentityAsync(tenantId, username, closeReason),
            _connections.CloseIdentityAsync(tenantId, username, closeReason));
    }

    private async Task HandleClusterEventAsync(PublicTransferClusterEvent frame)
    {
        if (frame.Kind != PublicTransferClusterFrame.KindManagementRevocation) return;
        try
        {
            var value = JsonSerializer.Deserialize<Revocation>(frame.Payload, JsonOptions);
            if (value is null || string.IsNullOrWhiteSpace(value.TenantId)
                || string.IsNullOrEmpty(value.Username)
                || !string.Equals(frame.GroupId, PublicTransferCoordinationService.ManagementGroupId(value.TenantId),
                    StringComparison.Ordinal))
            {
                _logger.LogWarning("discarding management revocation with invalid identity binding");
                return;
            }
            await CloseLocalAsync(value.TenantId, value.Username, value.Reason).ConfigureAwait(false);
        }
        catch (JsonException error)
        {
            _logger.LogWarning(error, "discarding invalid management revocation payload");
        }
    }

    private sealed record Revocation(string TenantId, string Username, string Reason);
}
