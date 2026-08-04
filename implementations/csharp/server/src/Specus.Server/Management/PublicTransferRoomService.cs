using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Specus.Server.Authentication;
using Specus.Server.Configuration;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Security;

namespace Specus.Server.Management;

public sealed class PublicTransferRoomService
{
    private const int MaxSnapshotBytes = 3 * 1024 * 1024;
    private const int MaxVersionsPerRoom = 50;
    private const int MaxAccessTokensPerRoom = 20;
    private const long MinAccessTokenTtlSeconds = 300;
    private const long MaxAccessTokenTtlSeconds = 7 * 24 * 60 * 60;
    private const long PairingAccessTokenTtlSeconds = 24 * 60 * 60;
    private const int MaxPairingCodeUses = 5;

    private readonly SpecusDbContext _db;
    private readonly PublicTransferOptions _options;
    private readonly LocalTokenService _localTokens;

    public PublicTransferRoomService(SpecusDbContext db, IOptions<PublicTransferOptions> options,
        LocalTokenService localTokens)
    {
        _db = db;
        _options = options.Value;
        _localTokens = localTokens;
    }

    public async Task<IReadOnlyList<AccessTokenView>> ListAccessTokensAsync(RoomCredential credential,
        CancellationToken cancellationToken)
    {
        var owner = await RequireRoleAsync(credential.RoomId, credential, RoomRole.Owner, cancellationToken)
            .ConfigureAwait(false);
        var rows = await _db.PublicTransferRoomAccesses.AsNoTracking()
            .Where(row => row.RoomId == owner.RoomId)
            .OrderByDescending(row => row.CreatedAt)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        return rows.Select(AccessView).ToList();
    }

    public async Task<CreatedAccessToken> CreateAccessTokenAsync(CreateAccessTokenRequest request,
        CancellationToken cancellationToken)
    {
        var credential = request.Credential();
        var owner = await RequireRoleAsync(request.RoomId, credential, RoomRole.Owner, cancellationToken)
            .ConfigureAwait(false);
        var role = ParseInviteRole(request.Role);
        var room = await _db.PublicTransferRooms.AsNoTracking()
            .FirstOrDefaultAsync(row => row.Id == owner.RoomId, cancellationToken)
            .ConfigureAwait(false)
            ?? throw new ResourceNotFoundException("房间不存在");
        await RequireAccessTokenCapacityAsync(room.Id, cancellationToken).ConfigureAwait(false);
        var now = DateTimeOffset.UtcNow;
        return await IssueAccessTokenAsync(room, role,
                NormalizeText(request.Label, role == RoomRole.Editor ? "编辑者邀请" : "访客邀请", 80),
                now, AccessTokenExpiry(request.ExpiresInSeconds, now), cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<AccessTokenView> RevokeAccessTokenAsync(long accessId,
        RoomCredential credential, CancellationToken cancellationToken)
    {
        var owner = await RequireRoleAsync(credential.RoomId, credential, RoomRole.Owner, cancellationToken)
            .ConfigureAwait(false);
        var access = await _db.PublicTransferRoomAccesses
            .FirstOrDefaultAsync(row => row.Id == accessId && row.RoomId == owner.RoomId,
                cancellationToken).ConfigureAwait(false)
            ?? throw new ResourceNotFoundException("邀请 Token 不存在");
        if (access.RevokedAt is null)
        {
            access.RevokedAt = DateTimeOffset.UtcNow;
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
        return AccessView(access);
    }

    public async Task<CreatePairingCodeResponse> CreatePairingCodeAsync(
        CreatePairingCodeRequest request, CancellationToken cancellationToken)
    {
        var owner = await RequireRoleAsync(request.RoomId, request.Credential(), RoomRole.Owner,
                cancellationToken).ConfigureAwait(false);
        var role = ParseInviteRole(request.Role);
        var maxUses = NormalizePairingCodeUses(request.MaxUses);
        if (!await _db.PublicTransferRooms.AsNoTracking()
                .AnyAsync(row => row.Id == owner.RoomId, cancellationToken).ConfigureAwait(false))
        {
            throw new ResourceNotFoundException("房间不存在");
        }

        var now = DateTimeOffset.UtcNow;
        var ttlSeconds = Math.Clamp(_options.PairingCodeTtlSeconds, 60L, 900L);
        var plainCode = await NewUniquePairingCodeAsync(cancellationToken).ConfigureAwait(false);
        var pairing = new PublicTransferRoomPairingCode
        {
            Id = await NewUniqueIdAsync(_db.PublicTransferRoomPairingCodes, cancellationToken)
                .ConfigureAwait(false),
            RoomId = owner.RoomId,
            CodeHash = _localTokens.PairingCodeHash(plainCode),
            Role = WireRole(role),
            Label = NormalizeText(request.Label,
                role == RoomRole.Editor ? "编辑者配对" : "访客配对", 80),
            CreatedAt = now,
            ExpiresAt = now.AddSeconds(ttlSeconds),
            MaxUses = maxUses,
            UsedCount = 0,
        };
        _db.PublicTransferRoomPairingCodes.Add(pairing);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return new CreatePairingCodeResponse(pairing.Id, plainCode, pairing.Role, pairing.Label,
            Iso(pairing.CreatedAt), Iso(pairing.ExpiresAt), pairing.MaxUses, pairing.UsedCount);
    }

    public async Task<RedeemPairingCodeResponse> RedeemPairingCodeAsync(
        RedeemPairingCodeRequest request, CancellationToken cancellationToken)
    {
        _ = NormalizeText(request.PeerId, "web", 120);
        var code = NormalizePairingCode(request.Code);
        var codeHash = _localTokens.PairingCodeHash(code);
        var now = DateTimeOffset.UtcNow;

        await using var transaction = await _db.Database.BeginTransactionAsync(cancellationToken)
            .ConfigureAwait(false);
        var consumed = await _db.PublicTransferRoomPairingCodes
            .Where(row => row.CodeHash == codeHash && row.RevokedAt == null
                && row.ExpiresAt > now && row.UsedCount < row.MaxUses)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(row => row.UsedCount, row => row.UsedCount + 1), cancellationToken)
            .ConfigureAwait(false);
        if (consumed != 1)
        {
            throw InvalidPairingCode();
        }

        var pairing = await _db.PublicTransferRoomPairingCodes.AsNoTracking()
            .FirstOrDefaultAsync(row => row.CodeHash == codeHash, cancellationToken)
            .ConfigureAwait(false) ?? throw InvalidPairingCode();
        var role = ParseInviteRole(pairing.Role);
        var room = await _db.PublicTransferRooms.AsNoTracking()
            .FirstOrDefaultAsync(row => row.Id == pairing.RoomId, cancellationToken)
            .ConfigureAwait(false) ?? throw InvalidPairingCode();
        await RequireAccessTokenCapacityAsync(room.Id, cancellationToken).ConfigureAwait(false);
        var expiresAt = now.AddSeconds(PairingAccessTokenTtlSeconds);
        var created = await IssueAccessTokenAsync(room, role, pairing.Label, now, expiresAt,
                cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return new RedeemPairingCodeResponse(room.RoomName, WireRole(role), created.Token,
            Iso(expiresAt));
    }

    public async Task<IReadOnlyList<DiagramVersionView>> ListVersionsAsync(RoomCredential credential,
        CancellationToken cancellationToken)
    {
        var access = await ResolveAsync(credential.RoomId, credential.RoomToken,
                credential.PeerId, cancellationToken).ConfigureAwait(false);
        var rows = await _db.PublicTransferDiagramVersions.AsNoTracking()
            .Where(row => row.RoomId == access.RoomId)
            .OrderByDescending(row => row.CreatedAt)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        return rows.Select(VersionView).ToList();
    }

    public async Task<DiagramVersionView> CreateVersionAsync(CreateDiagramVersionRequest request,
        CancellationToken cancellationToken)
    {
        var access = await ResolveAsync(request.RoomId, request.RoomToken, request.PeerId,
                cancellationToken).ConfigureAwait(false);
        if (access.Role == RoomRole.Viewer)
        {
            throw new UnauthorizedAccessException("访客不能创建流程图版本");
        }
        var snapshot = DecodeSnapshot(request.Update);
        if (!await _db.PublicTransferRooms.AsNoTracking()
                .AnyAsync(row => row.Id == access.RoomId, cancellationToken).ConfigureAwait(false))
        {
            throw new ResourceNotFoundException("房间不存在");
        }

        await using var transaction = await _db.Database.BeginTransactionAsync(cancellationToken)
            .ConfigureAwait(false);
        var version = new PublicTransferDiagramVersion
        {
            Id = await NewUniqueIdAsync(_db.PublicTransferDiagramVersions, cancellationToken)
                .ConfigureAwait(false),
            RoomId = access.RoomId,
            Name = RequireText(request.Name, "name", 80),
            AuthorPeerId = NormalizeText(request.PeerId, "web", 120),
            SnapshotData = snapshot,
            SizeBytes = snapshot.LongLength,
            CreatedAt = DateTimeOffset.UtcNow,
        };
        _db.PublicTransferDiagramVersions.Add(version);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        var stale = await _db.PublicTransferDiagramVersions
            .Where(row => row.RoomId == access.RoomId)
            .OrderByDescending(row => row.CreatedAt)
            .Skip(MaxVersionsPerRoom)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        if (stale.Count > 0)
        {
            _db.PublicTransferDiagramVersions.RemoveRange(stale);
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return VersionView(version);
    }

    public async Task<DiagramVersionDetail> GetVersionAsync(long versionId,
        RoomCredential credential, CancellationToken cancellationToken)
    {
        var access = await ResolveAsync(credential.RoomId, credential.RoomToken,
                credential.PeerId, cancellationToken).ConfigureAwait(false);
        var version = await _db.PublicTransferDiagramVersions.AsNoTracking()
            .FirstOrDefaultAsync(row => row.Id == versionId && row.RoomId == access.RoomId,
                cancellationToken).ConfigureAwait(false)
            ?? throw new ResourceNotFoundException("流程图版本不存在");
        return new DiagramVersionDetail(VersionView(version),
            Convert.ToBase64String(version.SnapshotData));
    }

    public async Task DeleteVersionAsync(long versionId, RoomCredential credential,
        CancellationToken cancellationToken)
    {
        var owner = await RequireRoleAsync(credential.RoomId, credential, RoomRole.Owner,
                cancellationToken).ConfigureAwait(false);
        var version = await _db.PublicTransferDiagramVersions
            .FirstOrDefaultAsync(row => row.Id == versionId && row.RoomId == owner.RoomId,
                cancellationToken).ConfigureAwait(false)
            ?? throw new ResourceNotFoundException("流程图版本不存在");
        _db.PublicTransferDiagramVersions.Remove(version);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<RoomAccess> ResolveAsync(string? roomNameValue, string? tokenValue,
        string? peerIdValue, CancellationToken cancellationToken)
    {
        var roomName = RequireText(roomNameValue, "roomId", 120);
        var token = RequireText(tokenValue, "roomToken", 512);
        var peerId = NormalizeText(peerIdValue, "web", 120);
        var tokenHash = Sha256(token);

        var ownerRoom = await _db.PublicTransferRooms.AsNoTracking()
            .FirstOrDefaultAsync(row => row.RoomName == roomName && row.OwnerTokenHash == tokenHash,
                cancellationToken).ConfigureAwait(false);
        if (ownerRoom is not null)
        {
            return new RoomAccess(ownerRoom.Id, RoomRole.Owner, roomName);
        }

        var invited = await _db.PublicTransferRoomAccesses.AsNoTracking()
            .FirstOrDefaultAsync(row => row.TokenHash == tokenHash, cancellationToken)
            .ConfigureAwait(false);
        if (invited is not null)
        {
            return await RequireUsableInviteAsync(roomName, invited, cancellationToken)
                .ConfigureAwait(false);
        }
        if (token.StartsWith("st-editor-", StringComparison.Ordinal)
            || token.StartsWith("st-viewer-", StringComparison.Ordinal))
        {
            throw new UnauthorizedAccessException("房间凭证无效");
        }

        var now = DateTimeOffset.UtcNow;
        var room = new PublicTransferRoom
        {
            Id = await NewUniqueIdAsync(_db.PublicTransferRooms, cancellationToken).ConfigureAwait(false),
            RoomName = roomName,
            OwnerTokenHash = tokenHash,
            CreatedByPeerId = peerId,
            CreatedAt = now,
            UpdatedAt = now,
        };
        _db.PublicTransferRooms.Add(room);
        try
        {
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            return new RoomAccess(room.Id, RoomRole.Owner, roomName);
        }
        catch (DbUpdateException)
        {
            _db.Entry(room).State = EntityState.Detached;
            var existing = await _db.PublicTransferRooms.AsNoTracking()
                .FirstOrDefaultAsync(row => row.RoomName == roomName
                    && row.OwnerTokenHash == tokenHash, cancellationToken).ConfigureAwait(false);
            if (existing is not null)
            {
                return new RoomAccess(existing.Id, RoomRole.Owner, roomName);
            }
            throw;
        }
    }

    public async Task<RoomAccess> AuthenticateAsync(string? roomNameValue, string? tokenValue,
        string? peerIdValue, CancellationToken cancellationToken)
    {
        var roomName = RequireText(roomNameValue, "roomId", 120);
        var token = RequireText(tokenValue, "roomToken", 512);
        _ = NormalizeText(peerIdValue, "web", 120);
        var tokenHash = Sha256(token);

        var ownerRoom = await _db.PublicTransferRooms.AsNoTracking()
            .FirstOrDefaultAsync(row => row.RoomName == roomName && row.OwnerTokenHash == tokenHash,
                cancellationToken).ConfigureAwait(false);
        if (ownerRoom is not null)
        {
            return new RoomAccess(ownerRoom.Id, RoomRole.Owner, roomName);
        }

        var invited = await _db.PublicTransferRoomAccesses.AsNoTracking()
            .FirstOrDefaultAsync(row => row.TokenHash == tokenHash, cancellationToken)
            .ConfigureAwait(false);
        if (invited is not null)
        {
            return await RequireUsableInviteAsync(roomName, invited, cancellationToken)
                .ConfigureAwait(false);
        }
        throw new UnauthorizedAccessException("房间凭证无效");
    }

    private async Task<RoomAccess> RequireRoleAsync(string? roomName, RoomCredential credential,
        RoomRole required, CancellationToken cancellationToken)
    {
        var access = await ResolveAsync(roomName, credential.RoomToken, credential.PeerId,
                cancellationToken).ConfigureAwait(false);
        if (access.Role != required)
        {
            throw new UnauthorizedAccessException("需要房主权限");
        }
        return access;
    }

    private async Task<RoomAccess> RequireUsableInviteAsync(string roomName,
        PublicTransferRoomAccess access, CancellationToken cancellationToken)
    {
        var room = await _db.PublicTransferRooms.AsNoTracking()
            .FirstOrDefaultAsync(row => row.Id == access.RoomId, cancellationToken)
            .ConfigureAwait(false);
        if (room is null || !string.Equals(room.RoomName, roomName, StringComparison.Ordinal)
            || !IsUsable(access, DateTimeOffset.UtcNow))
        {
            throw new UnauthorizedAccessException("房间凭证无效");
        }
        return new RoomAccess(room.Id, ParseStoredRole(access.Role), roomName);
    }

    private async Task RequireAccessTokenCapacityAsync(long roomId,
        CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        var active = await _db.PublicTransferRoomAccesses.AsNoTracking()
            .LongCountAsync(row => row.RoomId == roomId && row.RevokedAt == null
                && (row.ExpiresAt == null || row.ExpiresAt > now), cancellationToken)
            .ConfigureAwait(false);
        if (active >= MaxAccessTokensPerRoom)
        {
            throw new InvalidOperationException("房间有效邀请 Token 已达到 20 个上限");
        }
    }

    private async Task<CreatedAccessToken> IssueAccessTokenAsync(PublicTransferRoom room,
        RoomRole role, string label, DateTimeOffset createdAt, DateTimeOffset? expiresAt,
        CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < 4; attempt++)
        {
            var plainToken = NewAccessToken(role);
            var access = new PublicTransferRoomAccess
            {
                Id = await NewUniqueIdAsync(_db.PublicTransferRoomAccesses, cancellationToken)
                    .ConfigureAwait(false),
                RoomId = room.Id,
                TokenHash = Sha256(plainToken),
                Role = WireRole(role),
                Label = label,
                CreatedAt = createdAt,
                ExpiresAt = expiresAt,
            };
            _db.PublicTransferRoomAccesses.Add(access);
            try
            {
                await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
                return new CreatedAccessToken(AccessView(access), plainToken);
            }
            catch (DbUpdateException) when (attempt < 3)
            {
                _db.Entry(access).State = EntityState.Detached;
            }
        }
        throw new InvalidOperationException("无法生成邀请 Token");
    }

    private async Task<string> NewUniquePairingCodeAsync(CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < 16; attempt++)
        {
            var code = RandomNumberGenerator.GetInt32(100_000_000)
                .ToString("D8", CultureInfo.InvariantCulture);
            var hash = _localTokens.PairingCodeHash(code);
            if (!await _db.PublicTransferRoomPairingCodes.AsNoTracking()
                    .AnyAsync(row => row.CodeHash == hash, cancellationToken).ConfigureAwait(false))
            {
                return code;
            }
        }
        throw new InvalidOperationException("无法生成唯一配对码");
    }

    private static async Task<long> NewUniqueIdAsync<TEntity>(DbSet<TEntity> set,
        CancellationToken cancellationToken) where TEntity : class
    {
        for (var attempt = 0; attempt < 8; attempt++)
        {
            var id = ClientIdGenerator.NewId();
            if (await set.FindAsync([id], cancellationToken).ConfigureAwait(false) is null)
            {
                return id;
            }
        }
        throw new InvalidOperationException("无法生成唯一 ID");
    }

    private static byte[] DecodeSnapshot(string? encoded)
    {
        if (string.IsNullOrWhiteSpace(encoded) || encoded.Length > 4 * 1024 * 1024 + 16)
        {
            throw new ArgumentException("流程图版本数据无效或超过限制");
        }
        byte[] decoded;
        try
        {
            decoded = Convert.FromBase64String(encoded);
        }
        catch (FormatException exception)
        {
            throw new ArgumentException("流程图版本数据不是有效的 Base64", exception);
        }
        if (decoded.Length == 0 || decoded.Length > MaxSnapshotBytes)
        {
            throw new ArgumentException("流程图版本数据无效或超过 3 MB");
        }
        return decoded;
    }

    private static string RequireText(string? value, string field, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException($"{field} 不能为空");
        }
        return NormalizeText(value, string.Empty, maxLength);
    }

    private static string NormalizeText(string? value, string fallback, int maxLength)
    {
        var normalized = string.IsNullOrWhiteSpace(value) ? fallback : value.Trim();
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

    private static RoomRole ParseInviteRole(string? value)
    {
        var normalized = NormalizeText(value, string.Empty, 16);
        if (string.Equals(normalized, "EDITOR", StringComparison.OrdinalIgnoreCase))
        {
            return RoomRole.Editor;
        }
        if (string.Equals(normalized, "VIEWER", StringComparison.OrdinalIgnoreCase))
        {
            return RoomRole.Viewer;
        }
        throw new ArgumentException("邀请角色必须是 EDITOR 或 VIEWER");
    }

    private static RoomRole ParseStoredRole(string value) => value.ToUpperInvariant() switch
    {
        "EDITOR" => RoomRole.Editor,
        "VIEWER" => RoomRole.Viewer,
        "OWNER" => RoomRole.Owner,
        _ => throw new ArgumentException("房间凭证无效"),
    };

    private static int NormalizePairingCodeUses(int? value)
    {
        var normalized = value ?? 1;
        if (normalized is < 1 or > MaxPairingCodeUses)
        {
            throw new ArgumentException("配对码可用次数必须在 1 到 5 之间");
        }
        return normalized;
    }

    private static string NormalizePairingCode(string? value)
    {
        var code = value?.Trim() ?? string.Empty;
        if (code.Length != 8 || code.Any(character => character is < '0' or > '9'))
        {
            throw InvalidPairingCode();
        }
        return code;
    }

    private static DateTimeOffset? AccessTokenExpiry(long? expiresInSeconds, DateTimeOffset now)
    {
        if (expiresInSeconds is null)
        {
            return null;
        }
        if (expiresInSeconds.Value is < MinAccessTokenTtlSeconds or > MaxAccessTokenTtlSeconds)
        {
            throw new ArgumentException("邀请有效期必须在 300 到 604800 秒之间");
        }
        return now.AddSeconds(expiresInSeconds.Value);
    }

    private static string NewAccessToken(RoomRole role)
    {
        var random = RandomNumberGenerator.GetBytes(32);
        var encoded = Convert.ToBase64String(random).TrimEnd('=')
            .Replace('+', '-').Replace('/', '_');
        return $"st-{WireRole(role).ToLowerInvariant()}-{encoded}";
    }

    private static bool IsUsable(PublicTransferRoomAccess access, DateTimeOffset now) =>
        access.RevokedAt is null && (access.ExpiresAt is null || access.ExpiresAt > now);

    private static string Sha256(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    private static ArgumentException InvalidPairingCode() =>
        new("配对码无效或已过期");

    private static string WireRole(RoomRole role) => role switch
    {
        RoomRole.Owner => "OWNER",
        RoomRole.Editor => "EDITOR",
        _ => "VIEWER",
    };

    private static AccessTokenView AccessView(PublicTransferRoomAccess access) => new(
        access.Id, access.Role, access.Label, Iso(access.CreatedAt),
        Iso(access.ExpiresAt), Iso(access.RevokedAt));

    private static DiagramVersionView VersionView(PublicTransferDiagramVersion version) => new(
        version.Id, version.Name, version.AuthorPeerId, version.SizeBytes, Iso(version.CreatedAt));

    private static string Iso(DateTimeOffset value) => value.UtcDateTime.ToString("O");
    private static string? Iso(DateTimeOffset? value) => value?.UtcDateTime.ToString("O");

    public enum RoomRole
    {
        Owner,
        Editor,
        Viewer,
    }

    public sealed record RoomAccess(long RoomId, RoomRole Role, string RoomName)
    {
        public bool CanEdit => Role is RoomRole.Owner or RoomRole.Editor;
    }
}

public sealed record RoomCredential(string? RoomId, string? RoomToken, string? PeerId);

public sealed record CreateAccessTokenRequest(
    string? RoomId,
    string? RoomToken,
    string? PeerId,
    string? Role,
    string? Label,
    long? ExpiresInSeconds)
{
    public RoomCredential Credential() => new(RoomId, RoomToken, PeerId);
}

public sealed record AccessTokenView(
    long Id,
    string Role,
    string Label,
    string CreatedAt,
    string? ExpiresAt,
    string? RevokedAt);

public sealed record CreatedAccessToken(AccessTokenView Access, string Token);

public sealed record CreatePairingCodeRequest(
    string? RoomId,
    string? RoomToken,
    string? PeerId,
    string? Role,
    string? Label,
    int? MaxUses)
{
    public RoomCredential Credential() => new(RoomId, RoomToken, PeerId);
}

public sealed record CreatePairingCodeResponse(
    long Id,
    string Code,
    string Role,
    string Label,
    string CreatedAt,
    string ExpiresAt,
    int MaxUses,
    int UsedCount);

public sealed record RedeemPairingCodeRequest(string? Code, string? PeerId);

public sealed record RedeemPairingCodeResponse(
    string RoomId,
    string Role,
    string RoomToken,
    string ExpiresAt);

public sealed record CreateDiagramVersionRequest(
    string? RoomId,
    string? RoomToken,
    string? PeerId,
    string? Name,
    string? Update);

public sealed record DiagramVersionView(
    long Id,
    string Name,
    string AuthorPeerId,
    long SizeBytes,
    string CreatedAt);

public sealed record DiagramVersionDetail(DiagramVersionView Version, string Update);
