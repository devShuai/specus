namespace Specus.Server.Configuration;

/// <summary>
/// S3-compatible storage used exclusively by HTTP media capture. Capture remains disabled unless
/// both <see cref="Enabled"/> and every required storage credential are configured.
/// </summary>
public sealed class MediaCaptureOptions
{
    public const string SectionName = "Specus:MediaCapture";

    public bool Enabled { get; set; }
    public string Endpoint { get; set; } = string.Empty;
    public string Region { get; set; } = "us-east-1";
    public string Bucket { get; set; } = string.Empty;
    public string AccessKeyId { get; set; } = string.Empty;
    public string AccessKeySecret { get; set; } = string.Empty;
    public string ObjectPrefix { get; set; } = "specus/http-media";
    public bool PathStyle { get; set; } = true;
    public bool CreateBucketIfMissing { get; set; }
    public long PartSizeBytes { get; set; } = 8L * 1024 * 1024;
    public int MaxInflightParts { get; set; } = 4;
    public int UploadThreads { get; set; } = 4;
    public long RetentionSeconds { get; set; } = 7L * 24 * 60 * 60;
    public long LiveWindowSeconds { get; set; } = 5L * 60;
    public long ManifestMaxBytes { get; set; } = 16L * 1024 * 1024;
    public long PlaybackTicketTtlSeconds { get; set; } = 900;
    public long CleanupIntervalMs { get; set; } = 60_000;

    public bool IsReady => Enabled
        && !string.IsNullOrWhiteSpace(Endpoint)
        && !string.IsNullOrWhiteSpace(Bucket)
        && !string.IsNullOrWhiteSpace(AccessKeyId)
        && !string.IsNullOrWhiteSpace(AccessKeySecret);

    public long NormalizedPartSizeBytes => Math.Max(5L * 1024 * 1024, PartSizeBytes);
    public int NormalizedMaxInflightParts => Math.Max(1, MaxInflightParts);
    public int NormalizedUploadThreads => Math.Max(1, UploadThreads);
}
