using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;

namespace Specus.IntegrationTests;

public sealed class PeerClientDeletionVectorTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ReplaysSharedDeletionAndRollbackVector(bool rollback)
    {
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "protocol", "test-vectors", "client-peer-deletion-v1.json")))
            root = root.Parent;
        Assert.NotNull(root);
        using var vector = JsonDocument.Parse(await File.ReadAllTextAsync(
            Path.Combine(root!.FullName, "protocol", "test-vectors", "client-peer-deletion-v1.json")));
        var data = vector.RootElement;
        Assert.Equal(1, data.GetProperty("version").GetInt32());
        Assert.Equal(7, data.GetProperty("setup").GetArrayLength());
        Assert.Equal(23, data.GetProperty("checks").GetArrayLength());
        await using var server = await TestServerFixture.StartAsync();
        await using (var seed = server.HostServices.CreateAsyncScope())
        {
            var db = seed.ServiceProvider.GetRequiredService<SpecusDbContext>();
            foreach (var sql in data.GetProperty("setup").EnumerateArray())
                await db.Database.ExecuteSqlRawAsync(SqlFor(sql.GetString()!));
            if (rollback)
                await db.Database.ExecuteSqlRawAsync("CREATE TRIGGER fail_vector_delete BEFORE DELETE ON specus_client_account WHEN OLD.id=1001 BEGIN SELECT RAISE(ABORT,'injected failure'); END");
        }
        await using (var change = server.HostServices.CreateAsyncScope())
        {
            var mutation = change.ServiceProvider.GetRequiredService<ManagementMutationService>();
            var context = new ManagementContext(data.GetProperty("tenantId").GetString()!,
                data.GetProperty("actor").GetString()!, ManagementRole.Admin, false);
            if (rollback)
                await Assert.ThrowsAsync<DbUpdateException>(() => mutation.DeleteClientAsync(context,
                    data.GetProperty("clientId").GetInt64(), CancellationToken.None));
            else
                await mutation.DeleteClientAsync(context, data.GetProperty("clientId").GetInt64(), CancellationToken.None);
        }
        await using var verify = server.HostServices.CreateAsyncScope();
        var persisted = verify.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var connection = persisted.Database.GetDbConnection();
        await connection.OpenAsync();
        foreach (var check in data.GetProperty("checks").EnumerateArray())
        {
            await using var command = connection.CreateCommand();
            command.CommandText = SqlFor(check.GetProperty("query").GetString()!);
            var actual = Convert.ToInt64(await command.ExecuteScalarAsync());
            Assert.True(actual == check.GetProperty(rollback ? "retained" : "deleted").GetInt64(),
                $"{check.GetProperty("name").GetString()}: actual count {actual}");
        }
    }

    private static string SqlFor(string sql) => sql.Replace("client_account", "specus_client_account", StringComparison.Ordinal);
}
