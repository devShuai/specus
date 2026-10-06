using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Specus.Server.Configuration;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using Specus.Server.Security;

namespace Specus.IntegrationTests;

/// <summary>
/// Replays protocol/test-vectors/transfer-capabilities-v1.json: the rows of each case go into the
/// SQLite store through the EF Core model the upload and download paths write with, the service
/// clock is fixed at the case instant, and the snapshot must match the vector field by field.
/// </summary>
public sealed class TransferCapabilitiesVectorTests
{
    // The vector's two scopes stand for two distinct attachment scopes: usage is account-wide.
    private static readonly Dictionary<string, string> Scopes = new(StringComparer.Ordinal)
    {
        ["ROOM"] = TransferAttachmentService.ScopePublicTransfer,
        ["LINK"] = TransferAttachmentService.ScopeAdminClientMessage,
    };

    public static TheoryData<string> CaseNames()
    {
        var names = new TheoryData<string>();
        foreach (var testCase in LoadVector().RootElement.GetProperty("cases").EnumerateArray())
        {
            names.Add(testCase.GetProperty("name").GetString()!);
        }
        return names;
    }

    [Theory]
    [MemberData(nameof(CaseNames))]
    public async Task SnapshotMatchesTheSharedVector(string name)
    {
        using var vector = LoadVector();
        var testCase = vector.RootElement.GetProperty("cases").EnumerateArray()
            .Single(c => c.GetProperty("name").GetString() == name);
        var now = Instant(testCase.GetProperty("now"));

        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var db = new SpecusDbContext(new DbContextOptionsBuilder<SpecusDbContext>()
            .UseSqlite(connection)
            .Options);
        await db.Database.EnsureCreatedAsync();
        var id = 0L;
        foreach (var row in testCase.GetProperty("attachments").EnumerateArray())
        {
            id++;
            db.TransferAttachments.Add(new TransferAttachment
            {
                Id = id,
                TenantId = row.GetProperty("tenantId").GetString(),
                OwnerUsername = row.GetProperty("username").GetString(),
                Scope = Scopes[row.GetProperty("scope").GetString()!],
                ObjectKey = $"vector/{id}",
                FileName = "vector.bin",
                Status = row.GetProperty("status").GetString()!,
                SizeBytes = row.GetProperty("sizeBytes").GetInt64(),
                CreatedAt = now,
                UpdatedAt = now,
                UploadExpiresAt = Instant(row.GetProperty("uploadExpiresAt")),
                ExpiresAt = Instant(row.GetProperty("expiresAt")),
            });
        }
        foreach (var row in testCase.GetProperty("downloadUsage").EnumerateArray())
        {
            id++;
            db.TransferAttachmentDownloadUsages.Add(new TransferAttachmentDownloadUsage
            {
                Id = id,
                TenantId = row.GetProperty("tenantId").GetString()!,
                Username = row.GetProperty("username").GetString()!,
                AttachmentId = 1,
                SizeBytes = row.GetProperty("sizeBytes").GetInt64(),
                UsageMonth = row.GetProperty("usageMonth").GetString()!,
                CreatedAt = now,
            });
        }
        await db.SaveChangesAsync();

        var config = testCase.GetProperty("config");
        var options = new ObjectStorageOptions
        {
            MaxAttachmentBytes = config.GetProperty("maxAttachmentBytes").GetInt64(),
            RetentionHours = config.GetProperty("retentionHours").GetInt64(),
            PerUserStorageQuotaBytes = config.GetProperty("storageQuotaBytes").GetInt64(),
            PerUserMonthlyDownloadQuotaBytes = config.GetProperty("monthlyDownloadQuotaBytes").GetInt64(),
        };
        if (config.GetProperty("storageEnabled").GetBoolean())
        {
            options.Provider = "aliyun-oss";
            options.Endpoint = "storage.test";
            options.Region = "cn-hangzhou";
            options.Bucket = "bucket";
            options.AccessKeyId = "key";
            options.AccessKeySecret = "secret";
        }
        var clock = new FixedTimeProvider(now);
        using var http = new HttpClient();
        var publicOptions = Options.Create(new PublicTransferOptions());
        var rooms = new PublicTransferRoomService(db, publicOptions,
            new LocalTokenService(Options.Create(new AuthOptions { JwtSecret = "capabilities-vector-secret" })));
        var service = new TransferAttachmentService(db, new AliyunOssObjectStorageService(options, http, clock),
            Options.Create(options), publicOptions, rooms, clock);

        var account = testCase.GetProperty("account");
        var snapshot = await service.CapabilitiesAsync(new ManagementContext(
            account.GetProperty("tenantId").GetString()!, account.GetProperty("username").GetString()!,
            ManagementRole.User, false), CancellationToken.None);

        var expect = testCase.GetProperty("expect");
        Assert.Equal(expect.GetProperty("schemaVersion").GetInt32(), snapshot.SchemaVersion);
        Assert.Equal(Instant(expect.GetProperty("checkedAt")), snapshot.CheckedAt);
        Assert.Equal(expect.GetProperty("storageEnabled").GetBoolean(), snapshot.StorageEnabled);
        Assert.Equal(expect.GetProperty("maxAttachmentBytes").GetInt64(), snapshot.MaxAttachmentBytes);
        Assert.Equal(expect.GetProperty("retentionHours").GetInt64(), snapshot.RetentionHours);
        Assert.Equal(expect.GetProperty("storageQuotaBytes").GetInt64(), snapshot.StorageQuotaBytes);
        Assert.Equal(expect.GetProperty("storageUsedBytes").GetInt64(), snapshot.StorageUsedBytes);
        Assert.Equal(expect.GetProperty("storageRemainingBytes").GetInt64(), snapshot.StorageRemainingBytes);
        Assert.Equal(expect.GetProperty("monthlyDownloadQuotaBytes").GetInt64(), snapshot.MonthlyDownloadQuotaBytes);
        Assert.Equal(expect.GetProperty("monthlyDownloadUsedBytes").GetInt64(), snapshot.MonthlyDownloadUsedBytes);
        Assert.Equal(expect.GetProperty("monthlyDownloadRemainingBytes").GetInt64(),
            snapshot.MonthlyDownloadRemainingBytes);
        Assert.Equal(expect.GetProperty("downloadUsageMonth").GetString(), snapshot.DownloadUsageMonth);
        Assert.Equal(Instant(expect.GetProperty("downloadResetsAt")), snapshot.DownloadResetsAt);
        Assert.Equal(expect.GetProperty("downloadGrantSingleUse").GetBoolean(), snapshot.DownloadGrantSingleUse);
    }

    // DateTimeOffset equality compares instants, not offsets.
    private static DateTimeOffset Instant(JsonElement value) =>
        DateTimeOffset.Parse(value.GetString()!, System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal);

    private static JsonDocument LoadVector() => JsonDocument.Parse(File.ReadAllText(FindVector()));

    private static string FindVector()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        for (var depth = 0; directory is not null && depth < 12; depth++, directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, "protocol", "test-vectors",
                "transfer-capabilities-v1.json");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }
        throw new FileNotFoundException("cannot locate transfer-capabilities-v1.json");
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
