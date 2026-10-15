using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;

namespace Specus.IntegrationTests;

public sealed class DisconnectReasonsVectorTests
{
    [Fact]
    public async Task SharedReasonsSurvivePersistenceAndManagementJson()
    {
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "protocol", "test-vectors", "disconnect-reasons-v1.json")))
            root = root.Parent;
        Assert.NotNull(root);
        using var vector = JsonDocument.Parse(await File.ReadAllTextAsync(
            Path.Combine(root!.FullName, "protocol", "test-vectors", "disconnect-reasons-v1.json")));
        Assert.Equal(1, vector.RootElement.GetProperty("version").GetInt32());
        var reasons = vector.RootElement.GetProperty("reasons").EnumerateArray().ToArray();
        Assert.Equal(17, reasons.Length);
        Assert.Equal(17, reasons.Select(r => r.GetProperty("code").GetString()).Distinct().Count());
        Assert.Equal(14, (int)DisconnectReason.Unknown); // Existing enum values are not renumbered.
        Assert.Equal(Enum.GetValues<DisconnectReason>().Select(r => r.ToWireString()).Order(),
            reasons.Select(r => r.GetProperty("code").GetString()!).Order());
        await using var server = await TestServerFixture.StartAsync();
        await using (var seed = server.HostServices.CreateAsyncScope())
        {
            var db = seed.ServiceProvider.GetRequiredService<SpecusDbContext>();
            foreach (var code in reasons.Select(r => r.GetProperty("code").GetString()).Append(null).Append("FUTURE_REASON"))
            {
                db.ConnectionRecords.Add(new ConnectionRecord
                {
                    TenantId = "reason-vector", ClientName = "vector-client", ChannelId = code ?? "unmarked",
                    ConnectedAt = DateTimeOffset.UtcNow.AddMinutes(-1), DisconnectedAt = code is null ? null : DateTimeOffset.UtcNow,
                    Success = true, DisconnectReason = code,
                });
            }
            await db.SaveChangesAsync();
        }
        await using var read = server.HostServices.CreateAsyncScope();
        var query = read.ServiceProvider.GetRequiredService<ManagementQueryService>();
        var page = await query.ListConnectionsAsync(new ManagementContext("reason-vector", "admin", ManagementRole.Admin, false),
            null, null, null, null, 0, 100, CancellationToken.None);
        Assert.Equal(19, page.Total);
        using var json = JsonDocument.Parse(JsonSerializer.Serialize(page, new JsonSerializerOptions(JsonSerializerDefaults.Web)));
        var rows = json.RootElement.GetProperty("items").EnumerateArray().ToArray();
        foreach (var expected in reasons)
        {
            var code = expected.GetProperty("code").GetString();
            Assert.Equal(code, DisconnectReasonExtensions.Parse(code)!.Value.ToWireString());
            var actual = Assert.Single(rows, r => r.GetProperty("channelId").GetString() == code);
            Assert.Equal(code, actual.GetProperty("disconnectReason").GetString());
            Assert.Equal(expected.GetProperty("text").GetString(), actual.GetProperty("disconnectReasonText").GetString());
        }
        var unmarked = Assert.Single(rows, r => r.GetProperty("channelId").GetString() == "unmarked");
        Assert.Equal(JsonValueKind.Null, unmarked.GetProperty("disconnectReason").ValueKind);
        Assert.Equal(JsonValueKind.Null, unmarked.GetProperty("disconnectReasonText").ValueKind);
        var future = Assert.Single(rows, r => r.GetProperty("channelId").GetString() == "FUTURE_REASON");
        Assert.Equal("UNKNOWN", future.GetProperty("disconnectReason").GetString());
        Assert.Equal("未知", future.GetProperty("disconnectReasonText").GetString());
    }
}
