using System.Security.Claims;
using Specus.Server.Management;
using Specus.Server.Security;

namespace Specus.Server.WebSockets;

public static class WebSocketTicketEndpoints
{
    public static void MapWebSocketTicketApi(this WebApplication app)
    {
        app.MapPost("/api/admin/ws-tickets", async (HttpContext context,
            AdminWebSocketTicketRequest? request, WebSocketTicketService tickets,
            ClientAddressResolver addressResolver,
            CancellationToken cancellationToken) =>
        {
            var scope = request?.Endpoint?.Trim() switch
            {
                WebSocketTicketService.ConnectionsScope => WebSocketTicketService.ConnectionsScope,
                WebSocketTicketService.ClientMessagesScope => WebSocketTicketService.ClientMessagesScope,
                _ => throw new ArgumentException("unsupported websocket endpoint"),
            };
            var username = context.User.Identity?.Name
                ?? context.User.FindFirstValue(ClaimTypes.NameIdentifier)
                ?? throw new UnauthorizedAccessException("missing management identity");
            var tenantId = ManagementContext.NormalizeTenant(
                context.User.FindFirst("tenant_id")?.Value);
            var role = context.User.FindFirstValue(ClaimTypes.Role)
                ?? context.User.FindFirst("role")?.Value;
            context.Response.Headers.CacheControl = "no-store";
            return Results.Ok(await tickets.IssueAsync(scope,
                WebSocketTicketService.RequestAddress(addressResolver, context),
                new WebSocketTicketClaims(username, tenantId,
                    string.Equals(role, "ADMIN", StringComparison.OrdinalIgnoreCase)),
                cancellationToken).ConfigureAwait(false));
        });

        app.MapPost("/api/public/transfer/ws-tickets", async (HttpContext context,
            PublicWebSocketTicketRequest? request, WebSocketTicketService tickets,
            PublicTransferRoomService rooms, ClientAddressResolver addressResolver,
            CancellationToken cancellationToken) =>
        {
            if (request is null)
            {
                throw new ArgumentException("ticket request is required");
            }
            var roomId = Truncate(request.RoomId, 120, "nearby");
            var peerId = Truncate(request.PeerId, 120,
                "web-" + Guid.NewGuid().ToString("N")[..8]);
            var displayName = Truncate(request.DisplayName, 120, "web");
            var roomToken = Truncate(request.RoomToken, 512, string.Empty);
            var sharedRoom = roomToken.Length > 0;
            var requestAddress = WebSocketTicketService.RequestAddress(addressResolver, context);
            var roomKey = "public:" + requestAddress;
            var roomRole = PublicTransferRoomService.RoomRole.Editor;
            if (sharedRoom)
            {
                var access = await rooms.ResolveAsync(roomId, roomToken, peerId, cancellationToken)
                    .ConfigureAwait(false);
                roomKey = "room:" + access.RoomId;
                roomRole = access.Role;
            }
            context.Response.Headers.CacheControl = "no-store";
            return Results.Ok(await tickets.IssueAsync(WebSocketTicketService.PublicTransferScope,
                requestAddress,
                new WebSocketTicketClaims(RoomId: roomId,
                    RoomKey: roomKey, PeerId: peerId, DisplayName: displayName,
                    SharedRoom: sharedRoom, RoomRole: roomRole.ToString().ToUpperInvariant(),
                    Discoverable: request.Discoverable ?? true),
                cancellationToken).ConfigureAwait(false));
        });

        app.MapGet("/api/public/transfer/clients/name-availability", async (
            string clientName, string? excludePeerId, PublicTransferDiscoveryHub hub,
            CancellationToken cancellationToken) => Results.Ok(
                await hub.CheckClientNameAvailabilityAsync(clientName, excludePeerId,
                    cancellationToken).ConfigureAwait(false)));
    }

    private static string Truncate(string? value, int maxLength, string fallback)
    {
        var normalized = value?.Trim() ?? string.Empty;
        if (normalized.Length == 0)
        {
            return fallback;
        }
        if (normalized.Length <= maxLength)
        {
            return normalized;
        }
        var end = maxLength;
        if (end > 0 && char.IsHighSurrogate(normalized[end - 1])
            && end < normalized.Length && char.IsLowSurrogate(normalized[end]))
        {
            end--;
        }
        return normalized[..end];
    }
}

public sealed record AdminWebSocketTicketRequest(string? Endpoint);

public sealed class PublicWebSocketTicketRequest
{
    public string? RoomId { get; init; }
    public string? RoomToken { get; init; }
    public string? PeerId { get; init; }
    public string? DisplayName { get; init; }
    public bool? Discoverable { get; init; }
}
