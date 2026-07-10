using Microsoft.Extensions.Options;
using ShuaiTunnel.Server.Configuration;

namespace ShuaiTunnel.Server.Management;

public static class TransferAttachmentEndpoints
{
    public static void MapTransferAttachmentApi(this WebApplication app)
    {
        app.MapPost("/api/public/transfer/attachments/presign-upload",
            async (HttpContext context, PresignUploadRequest request,
                PublicTransferRateLimiter rateLimiter, TransferAttachmentService service,
                CancellationToken cancellationToken) =>
            {
                rateLimiter.CheckPresignUpload(ClientIp(context));
                return Results.Ok(await service.CreatePublicUploadAsync(request, cancellationToken)
                    .ConfigureAwait(false));
            });

        app.MapPost("/api/public/transfer/attachments/{attachmentId:long}/complete",
            async (long attachmentId, CompleteAttachmentRequest request,
                TransferAttachmentService service, CancellationToken cancellationToken) =>
                Results.Ok(await service.CompletePublicAsync(attachmentId, request, cancellationToken)
                    .ConfigureAwait(false)));

        app.MapPost("/api/public/transfer/attachments/{attachmentId:long}/presign-download",
            async (long attachmentId, PresignDownloadRequest request,
                TransferAttachmentService service, CancellationToken cancellationToken) =>
                Results.Ok(await service.CreatePublicDownloadAsync(attachmentId, request,
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
