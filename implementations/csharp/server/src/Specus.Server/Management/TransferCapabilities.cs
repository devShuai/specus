namespace Specus.Server.Management;

public sealed record TransferCapabilities(int SchemaVersion, DateTimeOffset CheckedAt, bool StorageEnabled,
    long MaxAttachmentBytes, long RetentionHours, long StorageQuotaBytes, long StorageUsedBytes,
    long StorageRemainingBytes, long MonthlyDownloadQuotaBytes, long MonthlyDownloadUsedBytes,
    long MonthlyDownloadRemainingBytes, string DownloadUsageMonth, DateTimeOffset DownloadResetsAt,
    bool DownloadGrantSingleUse);
