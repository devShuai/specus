namespace Specus.Server.Management;

public sealed record HttpMediaCaptureView(
    long Id,
    long ClientId,
    string ClientName,
    string Route,
    long? ResourceId,
    string SourceUrl,
    string Method,
    int StatusCode,
    string? ContentType,
    string MediaKind,
    string? EntityTag,
    long? ContentRangeStart,
    long? ContentRangeEnd,
    long? TotalBytes,
    long CapturedBytes,
    long? SegmentSequence,
    bool InitializationSegment,
    bool LiveStream,
    string State,
    string? FailureReason,
    bool Playable,
    bool OfflineReady,
    string? PlaybackMessage,
    string CapturedAt,
    string? CompletedAt,
    string ExpiresAt);

public sealed record HttpMediaCapturePage(
    IReadOnlyList<HttpMediaCaptureView> Items,
    long Total,
    int Page,
    int Size,
    int TotalPages);

public sealed record PlaybackByteRange(long Start, long End);

public sealed record HttpMediaPlaybackTicketView(
    string Ticket,
    string MediaKind,
    string PlayUrl,
    string ManifestUrl,
    long TotalBytes,
    long? InitialRangeStart,
    long? InitialRangeEnd,
    IReadOnlyList<PlaybackByteRange> CachedRanges,
    bool BackfillMissing,
    string ExpiresAt);
