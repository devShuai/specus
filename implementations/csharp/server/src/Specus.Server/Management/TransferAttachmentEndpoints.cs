using Microsoft.Extensions.Options;
using Specus.Server.Configuration;

namespace Specus.Server.Management;

public static class TransferAttachmentEndpoints
{
    public static void MapTransferAttachmentApi(this WebApplication app)
    {
        app.MapPost("/api/public/transfer/oss-callback",
            async (HttpContext context, TransferAttachmentService service,
                CancellationToken cancellationToken) =>
            {
                if (context.Request.ContentLength is > 64 * 1024)
                {
                    return Results.Json(new { error = "OSS callback body is too large" },
                        statusCode: StatusCodes.Status413PayloadTooLarge);
                }
                using var body = new MemoryStream();
                var buffer = new byte[4096];
                while (body.Length <= 64 * 1024)
                {
                    var read = await context.Request.Body.ReadAsync(buffer, cancellationToken)
                        .ConfigureAwait(false);
                    if (read == 0)
                    {
                        break;
                    }
                    body.Write(buffer, 0, read);
                }
                if (body.Length > 64 * 1024)
                {
                    return Results.Json(new { error = "OSS callback body is too large" },
                        statusCode: StatusCodes.Status413PayloadTooLarge);
                }
                var requestTarget = context.Request.PathBase + context.Request.Path
                    + context.Request.QueryString;
                var attachment = await service.CompleteUploadCallbackAsync(requestTarget,
                    body.ToArray(), context.Request.Headers.Authorization,
                    context.Request.Headers["x-oss-pub-key-url"], cancellationToken)
                    .ConfigureAwait(false);
                return Results.Ok(new
                {
                    Status = "OK",
                    attachmentId = attachment.AttachmentId,
                    objectId = attachment.ObjectId,
                });
            });

        app.MapMethods("/api/public/transfer/downloads/{token}",
            new[] { HttpMethods.Head }, (HttpContext context) =>
            {
                context.Response.Headers.Allow = HttpMethods.Get;
                context.Response.Headers.CacheControl = "no-store";
                return Results.StatusCode(StatusCodes.Status405MethodNotAllowed);
            });

        app.MapGet("/api/public/transfer/downloads/{token}",
            async (HttpContext context, string token, TransferAttachmentService service,
                CancellationToken cancellationToken) =>
            {
                if (!HttpMethods.IsGet(context.Request.Method))
                {
                    context.Response.Headers.Allow = HttpMethods.Get;
                    context.Response.Headers.CacheControl = "no-store";
                    return Results.StatusCode(StatusCodes.Status405MethodNotAllowed);
                }
                var directUrl = await service.ConsumeDownloadGrantAsync(token, cancellationToken)
                    .ConfigureAwait(false);
                if (directUrl is null)
                {
                    return Results.Json(new { error = "download link is expired or already used" },
                        statusCode: StatusCodes.Status410Gone);
                }
                context.Response.Headers.CacheControl = "private, no-store";
                context.Response.Headers.Pragma = "no-cache";
                context.Response.Headers["Referrer-Policy"] = "no-referrer";
                return Results.Redirect(directUrl);
            });

        app.MapPost("/api/public/transfer/attachments/presign-upload",
            async (HttpContext context, PresignUploadRequest request,
                IOptions<AuthOptions> auth, PublicTransferRateLimiter rateLimiter,
                TransferAttachmentService service,
                CancellationToken cancellationToken) =>
            {
                await rateLimiter.CheckPresignUploadAsync(ClientIp(context), cancellationToken)
                    .ConfigureAwait(false);
                return Results.Ok(await service.CreatePublicUploadAsync(
                    ManagementContext.From(context, auth.Value), request, cancellationToken)
                    .ConfigureAwait(false));
            });

        app.MapPost("/api/public/transfer/attachments/{attachmentId:long}/complete",
            async (HttpContext context, long attachmentId, CompleteAttachmentRequest request,
                IOptions<AuthOptions> auth, TransferAttachmentService service,
                CancellationToken cancellationToken) =>
                Results.Ok(await service.CompletePublicAsync(
                    ManagementContext.From(context, auth.Value), attachmentId, request,
                    cancellationToken).ConfigureAwait(false)));

        app.MapPost("/api/public/transfer/attachments/{attachmentId:long}/presign-download",
            async (HttpContext context, long attachmentId, PresignDownloadRequest request,
                IOptions<AuthOptions> auth, TransferAttachmentService service,
                CancellationToken cancellationToken) =>
                Results.Ok(await service.CreatePublicDownloadAsync(
                    ManagementContext.From(context, auth.Value), attachmentId, request,
                    cancellationToken).ConfigureAwait(false)));

        app.MapPost("/api/admin/client-messages/attachments/presign-upload",
            async (HttpContext context, PresignUploadRequest request, IOptions<AuthOptions> auth,
                TransferAttachmentService service, CancellationToken cancellationToken) =>
                Results.Ok(await service.CreateAdminUploadAsync(ManagementContext.From(context, auth.Value),
                    request, cancellationToken).ConfigureAwait(false)));

        app.MapPost("/api/admin/client-messages/attachments/{attachmentId:long}/complete",
            async (HttpContext context, long attachmentId, IOptions<AuthOptions> auth,
                TransferAttachmentService service, CancellationToken cancellationToken) =>
                Results.Ok(await service.CompleteAdminAsync(ManagementContext.From(context, auth.Value),
                    attachmentId, cancellationToken).ConfigureAwait(false)));

        app.MapPost("/api/admin/client-messages/attachments/{attachmentId:long}/presign-download",
            async (HttpContext context, long attachmentId, IOptions<AuthOptions> auth,
                TransferAttachmentService service, CancellationToken cancellationToken) =>
                Results.Ok(await service.CreateAdminDownloadAsync(ManagementContext.From(context, auth.Value),
                    attachmentId, cancellationToken).ConfigureAwait(false)));
    }

    private static string ClientIp(HttpContext context)
    {
        var realIp = context.Request.Headers["X-Real-IP"].FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(realIp))
        {
            return realIp.Trim();
        }
        var forwarded = context.Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(forwarded))
        {
            var last = forwarded.Split(',').LastOrDefault()?.Trim();
            if (!string.IsNullOrWhiteSpace(last))
            {
                return last;
            }
        }
        return context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    }
}
