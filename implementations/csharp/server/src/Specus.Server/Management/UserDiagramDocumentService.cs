using Microsoft.EntityFrameworkCore;
using Specus.Server.Authentication;
using Specus.Server.Data;
using Specus.Server.Data.Entities;

namespace Specus.Server.Management;

public sealed class ResourceNotFoundException(string message) : Exception(message);

public sealed class UserDiagramDocumentService
{
    private const int MaxDocumentsPerUser = 100;
    private const int MaxSnapshotBytes = 3 * 1024 * 1024;

    private readonly SpecusDbContext _db;

    public UserDiagramDocumentService(SpecusDbContext db)
    {
        _db = db;
    }

    public async Task<IReadOnlyList<DiagramDocumentView>> ListAsync(ManagementContext context,
        CancellationToken cancellationToken)
    {
        var owner = Owner(context);
        var rows = await _db.UserDiagramDocuments.AsNoTracking()
            .Where(row => row.TenantId == owner.TenantId && row.OwnerUsername == owner.Username)
            .OrderByDescending(row => row.UpdatedAt)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        return rows.Select(View).ToList();
    }

    public async Task<DiagramDocumentDetail> GetAsync(ManagementContext context, long id,
        CancellationToken cancellationToken)
    {
        var document = await RequireOwnedAsync(context, id, tracking: false, cancellationToken)
            .ConfigureAwait(false);
        return new DiagramDocumentDetail(View(document), Convert.ToBase64String(document.SnapshotData));
    }

    public async Task<DiagramDocumentView> CreateAsync(ManagementContext context,
        DiagramDocumentMutation request, CancellationToken cancellationToken)
    {
        var owner = Owner(context);
        if (await _db.UserDiagramDocuments.AsNoTracking()
                .LongCountAsync(row => row.TenantId == owner.TenantId
                    && row.OwnerUsername == owner.Username, cancellationToken)
                .ConfigureAwait(false) >= MaxDocumentsPerUser)
        {
            throw new InvalidOperationException("云端流程图数量已达到 100 个上限");
        }

        var snapshot = DecodeSnapshot(request.Update);
        var now = DateTimeOffset.UtcNow;
        var document = new UserDiagramDocument
        {
            Id = await NewUniqueIdAsync(cancellationToken).ConfigureAwait(false),
            TenantId = owner.TenantId,
            OwnerUsername = owner.Username,
            Name = RequireText(request.Name, "name", 120),
            SnapshotData = snapshot,
            SizeBytes = snapshot.LongLength,
            Revision = 0,
            CreatedAt = now,
            UpdatedAt = now,
        };
        _db.UserDiagramDocuments.Add(document);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return View(document);
    }

    public async Task<DiagramDocumentView> UpdateAsync(ManagementContext context, long id,
        DiagramDocumentMutation request, CancellationToken cancellationToken)
    {
        var document = await RequireOwnedAsync(context, id, tracking: true, cancellationToken)
            .ConfigureAwait(false);
        if (request.Revision is null || request.Revision.Value != document.Revision)
        {
            throw Conflict();
        }

        var snapshot = DecodeSnapshot(request.Update);
        document.Name = RequireText(request.Name, "name", 120);
        document.SnapshotData = snapshot;
        document.SizeBytes = snapshot.LongLength;
        document.Revision++;
        document.UpdatedAt = DateTimeOffset.UtcNow;
        try
        {
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (DbUpdateConcurrencyException conflict)
        {
            throw Conflict(conflict);
        }
        return View(document);
    }

    public async Task DeleteAsync(ManagementContext context, long id,
        CancellationToken cancellationToken)
    {
        var document = await RequireOwnedAsync(context, id, tracking: true, cancellationToken)
            .ConfigureAwait(false);
        _db.UserDiagramDocuments.Remove(document);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task<UserDiagramDocument> RequireOwnedAsync(ManagementContext context, long id,
        bool tracking, CancellationToken cancellationToken)
    {
        var owner = Owner(context);
        var query = _db.UserDiagramDocuments
            .Where(row => row.Id == id && row.TenantId == owner.TenantId
                && row.OwnerUsername == owner.Username);
        if (!tracking)
        {
            query = query.AsNoTracking();
        }
        return await query.FirstOrDefaultAsync(cancellationToken).ConfigureAwait(false)
            ?? throw new ResourceNotFoundException("云端流程图不存在");
    }

    private async Task<long> NewUniqueIdAsync(CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < 8; attempt++)
        {
            var id = ClientIdGenerator.NewId();
            if (!await _db.UserDiagramDocuments.AsNoTracking()
                    .AnyAsync(row => row.Id == id, cancellationToken).ConfigureAwait(false))
            {
                return id;
            }
        }
        throw new InvalidOperationException("无法生成云端流程图 ID");
    }

    private static byte[] DecodeSnapshot(string? encoded)
    {
        if (string.IsNullOrWhiteSpace(encoded) || encoded.Length > 4 * 1024 * 1024 + 16)
        {
            throw new ArgumentException("流程图数据无效或超过限制");
        }
        byte[] decoded;
        try
        {
            decoded = Convert.FromBase64String(encoded);
        }
        catch (FormatException exception)
        {
            throw new ArgumentException("流程图数据不是有效的 Base64", exception);
        }
        if (decoded.Length == 0 || decoded.Length > MaxSnapshotBytes)
        {
            throw new ArgumentException("流程图数据无效或超过 3 MB");
        }
        return decoded;
    }

    private static (string TenantId, string Username) Owner(ManagementContext context) =>
        (RequireText(context.TenantId, "tenantId", 80),
            RequireText(context.Username, "username", 160));

    private static string RequireText(string? value, string field, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException($"{field} 不能为空");
        }
        var normalized = value.Trim();
        if (normalized.Length > maxLength)
        {
            throw new ArgumentException($"字段长度不能超过 {maxLength}");
        }
        if (normalized.Contains('\r') || normalized.Contains('\n'))
        {
            throw new ArgumentException("字段不能包含换行");
        }
        return normalized;
    }

    private static InvalidOperationException Conflict(Exception? inner = null) =>
        new("云端文件已被其他会话更新，请重新打开后再保存", inner);

    private static DiagramDocumentView View(UserDiagramDocument document) => new(
        document.Id, document.Name, document.SizeBytes, document.Revision,
        Iso(document.CreatedAt), Iso(document.UpdatedAt));

    private static string Iso(DateTimeOffset value) => value.UtcDateTime.ToString("O");
}

public sealed record DiagramDocumentMutation(string? Name, string? Update, long? Revision);

public sealed record DiagramDocumentView(
    long Id,
    string Name,
    long SizeBytes,
    long Revision,
    string CreatedAt,
    string UpdatedAt);

public sealed record DiagramDocumentDetail(DiagramDocumentView Document, string Update);
