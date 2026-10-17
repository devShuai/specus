using System.Text.Json;
using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Specus.Server.Configuration;
using static Specus.Server.Management.ClientOwnerTransferPlan;

namespace Specus.Server.Management;

internal static class ClientOwnerTransferEndpoints
{
    internal static void MapOwnerTransferWrites(this WebApplication app)
    {
        app.MapPost("/api/admin/clients/{id}/owner-transfer", (HttpContext context, string id, IOptions<AuthOptions> auth,
            ClientOwnerTransferWriter writer, OwnerTransferNotifications notifications, CancellationToken ct) =>
            CommitAsync(context, id, PathScope.Single, auth.Value, writer, notifications, ct));
        app.MapPost("/api/admin/client-credentials/{id}/owner-transfer", (HttpContext context, string id, IOptions<AuthOptions> auth,
            ClientOwnerTransferWriter writer, OwnerTransferNotifications notifications, CancellationToken ct) =>
            CommitAsync(context, id, PathScope.CredentialGroup, auth.Value, writer, notifications, ct));
    }

    private static async Task<IResult> CommitAsync(HttpContext context, string id, PathScope scope, AuthOptions auth,
        ClientOwnerTransferWriter writer, OwnerTransferNotifications notifications, CancellationToken ct)
    {
        context.Response.Headers.CacheControl = "private, no-store";
        var actor = OwnerTransferActor.From(context, auth);
        ClientOwnerTransferService.ParseId(actor.Context, id); // role/path before body
        using var body = new MemoryStream();
        var buffer = new byte[8192];
        const int limit = 64 * 1024;
        while (true)
        {
            var count = await context.Request.Body.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, limit + 1 - (int)body.Length)), ct).ConfigureAwait(false);
            if (count == 0) break;
            body.Write(buffer, 0, count);
            if (body.Length > limit) throw new ClientOwnerTransferException(400, "INVALID_TRANSFER_REQUEST");
        }
        JsonDocument document;
        try { document = JsonDocument.Parse(body.GetBuffer().AsMemory(0, (int)body.Length)); }
        catch (JsonException) { throw new ClientOwnerTransferException(400, "INVALID_TRANSFER_REQUEST"); }
        using (document)
        {
            OwnerTransferWriteOutcome outcome;
            try { outcome = await writer.CommitAsync(actor, scope, id, document.RootElement, ct).ConfigureAwait(false); }
            catch (Exception error) when (error is DbException or DbUpdateException or InvalidOperationException)
            {
                context.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("ClientOwnerTransfer")
                    .LogError("Ownership transfer could not complete: error={ErrorType}", error.GetType().Name);
                return Results.Json(new { error = "Ownership transfer could not complete; re-read current ownership before retrying." }, statusCode: 500);
            }
            if (outcome.AuditId.HasValue) notifications.Committed();
            return Results.Json(outcome.Response);
        }
    }
}
