namespace Specus.Server.Data.Entities;

/// <summary>
/// Mirrors <c>http_share</c>: a temporary, revocable grant for one protected HTTP route
/// (protocol/spec/temporary-http-share.md). Every instant is integer epoch seconds UTC so the
/// servers that share one database compare them as numbers, never as strings. Only the SHA-256
/// of the token is stored.
/// </summary>
public sealed class HttpShare
{
    public string ShareId { get; set; } = string.Empty;
    public string TenantId { get; set; } = string.Empty;
    public long RouteId { get; set; }
    public string TokenSha256 { get; set; } = string.Empty;
    public string Access { get; set; } = "read";
    public string PathPrefix { get; set; } = "/";
    public string? Label { get; set; }
    public string CreatedBy { get; set; } = string.Empty;
    public long CreatedAt { get; set; }
    public long ExpiresAt { get; set; }
    public long? RevokedAt { get; set; }

    /// <summary>The revoking user; null when the system ended the share.</summary>
    public string? RevokedBy { get; set; }

    public string? RevokeReason { get; set; }

    /// <summary>0/1 integer, not a bool, so every server and dialect agrees on the column type.</summary>
    public sbyte ExpiryRecorded { get; set; }
}

/// <summary>
/// Mirrors <c>http_access_audit</c>: who changed whose access, and when. Never holds a token, its
/// hash, a label, Basic credentials, a target address or anything about visitors.
/// </summary>
public sealed class HttpAccessAudit
{
    public long Id { get; set; }
    public string TenantId { get; set; } = string.Empty;
    public long OccurredAt { get; set; }

    /// <summary>The acting user; null for system actions (sweep, read-time revoke, expiry).</summary>
    public string? Actor { get; set; }

    public string Action { get; set; } = string.Empty;
    public long RouteId { get; set; }
    public string? ShareId { get; set; }
    public string DetailJson { get; set; } = "{}";
}
