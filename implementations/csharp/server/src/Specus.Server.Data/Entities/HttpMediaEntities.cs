namespace Specus.Server.Data.Entities;

/// <summary>Metadata for a media response externalized to S3-compatible storage.</summary>
public sealed class HttpMediaCapture
{
    public long Id { get; set; }
    public string TenantId { get; set; } = "default";
    public long ClientId { get; set; }
    public string ClientName { get; set; } = string.Empty;
    public string Route { get; set; } = string.Empty;
    public long? ResourceId { get; set; }
    public string SourceUrl { get; set; } = "/";
    public string ResourceKey { get; set; } = string.Empty;
    public string? DeduplicationKey { get; set; }
    public string Method { get; set; } = "GET";
    public int StatusCode { get; set; }
    public string? ContentType { get; set; }
    public string? ContentEncoding { get; set; }
    public string MediaKind { get; set; } = string.Empty;
    public string? EntityTag { get; set; }
    public string? LastModified { get; set; }
    public long? ContentRangeStart { get; set; }
    public long? ContentRangeEnd { get; set; }
    public long? TotalBytes { get; set; }
    public long CapturedBytes { get; set; }
    public long? SegmentSequence { get; set; }
    public bool InitializationSegment { get; set; }
    public bool LiveStream { get; set; }
    public string ObjectKey { get; set; } = string.Empty;
    public string? UploadId { get; set; }
    public string? ObjectEtag { get; set; }
    public string State { get; set; } = "STARTING";
    public string? FailureReason { get; set; }
    public string? ResponseHeaders { get; set; }
    public DateTimeOffset CapturedAt { get; set; }
    public DateTimeOffset? CompletedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
}

/// <summary>A URI referenced by a captured HLS or DASH manifest.</summary>
public sealed class HttpMediaReference
{
    public long Id { get; set; }
    public string TenantId { get; set; } = "default";
    public long ManifestCaptureId { get; set; }
    public string RelationType { get; set; } = string.Empty;
    public long? SequenceIndex { get; set; }
    public string OriginalUri { get; set; } = string.Empty;
    public string ResolvedSourceUrl { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; }
}
