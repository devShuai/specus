using System.Data.Common;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Specus.Protocol.Packets;
using Specus.Server.ControlChannel;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using Specus.Server.Networking;
using Specus.Server.Sessions;
using Specus.Server.Security;

namespace Specus.IntegrationTests;

public sealed class ClientConfigurationBoundaryTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ForeignParentIdsAreNotDisclosedByConfigurationErrors(bool http)
    {
        await using var server = await TestServerFixture.StartAsync(new Dictionary<string, string?> { ["Specus:Database:SeedDemoClient"] = "false" });
        await using (var scope = server.HostServices.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            db.ClientAccounts.Add(new ClientAccount { Id = 1001, TenantId = "foreign", OwnerUsername = "foreign-owner", ClientName = "laptop", PasswordHash = "retained", Enabled = true });
            ClientConfigurationOwnershipTests.SeedConfiguration(db);
            await db.SaveChangesAsync();
        }
        using var client = server.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", server.HostServices.GetRequiredService<LocalTokenService>().IssueToken("admin"));
        using var response = http
            ? await client.PutAsJsonAsync("/api/admin/http-routes/4301", new HttpRouteMutation("existing", "http://127.0.0.1:8001", false, false, false, false, null, null))
            : await client.PutAsJsonAsync("/api/admin/specus-mappings/4201", new SpecusMappingMutation(24861, "127.0.0.1", 81, false, false));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var text = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("1001", text);
        Assert.Contains(http ? "4301" : "4201", text);
    }

    [Theory]
    [InlineData("tcp-create")]
    [InlineData("tcp-update")]
    [InlineData("tcp-delete")]
    [InlineData("http-create")]
    [InlineData("http-update")]
    [InlineData("http-delete")]
    public async Task ActualCommitFailureRollsBackConfigurationAndNeverPublishesItsSnapshot(string operation)
    {
        var fault = new CommitFault();
        await using var server = await TestServerFixture.StartAsync(new Dictionary<string, string?> { ["Specus:Database:SeedDemoClient"] = "false" },
            services => services.ConfigureDbContext<SpecusDbContext>((_, options) => options.AddInterceptors(fault)));
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        await SeedAsync(db);
        var actor = await OwnerTransferWriterProof.ActorAsync(server, scope.ServiceProvider);
        var auditBefore = await db.HttpAccessAudits.CountAsync();
        using var lifetime = new CancellationTokenSource();
        var writer = new RecordingWriter();
        var context = Bind(server, writer, lifetime.Token);
        fault.Armed = true;
        try
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() => ChangeAsync(scope.ServiceProvider.GetRequiredService<ManagementMutationService>(), actor.Context, operation));
            Assert.True(fault.Triggered); Assert.Equal(0, writer.Writes);
            Assert.Equal(1, await db.SpecusMappings.CountAsync()); Assert.Equal(1, await db.HttpRouteMappings.CountAsync());
            Assert.Equal(80, (await db.SpecusMappings.AsNoTracking().SingleAsync()).TargetPort);
            Assert.Equal("http://127.0.0.1:8000", (await db.HttpRouteMappings.AsNoTracking().SingleAsync()).TargetBaseUrl);
            Assert.Equal(auditBefore, await db.HttpAccessAudits.CountAsync());
        }
        finally { server.HostServices.GetRequiredService<SessionRegistry>().Unbind("laptop", context); lifetime.Cancel(); }
    }

    [Theory]
    [InlineData("tcp-update")]
    [InlineData("http-update")]
    public async Task CommittedConfigurationIsVisibleBeforeRuntimePublication(string operation)
    {
        await using var server = await TestServerFixture.StartAsync(new Dictionary<string, string?> { ["Specus:Database:SeedDemoClient"] = "false" });
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        await SeedAsync(db);
        var actor = await OwnerTransferWriterProof.ActorAsync(server, scope.ServiceProvider);
        using var lifetime = new CancellationTokenSource();
        var writer = new RecordingWriter(async () =>
        {
            await using var observer = server.HostServices.CreateAsyncScope();
            var current = observer.ServiceProvider.GetRequiredService<SpecusDbContext>();
            if (operation == "tcp-update") Assert.Equal(81, (await current.SpecusMappings.AsNoTracking().SingleAsync()).TargetPort);
            else Assert.Equal("http://127.0.0.1:8001", (await current.HttpRouteMappings.AsNoTracking().SingleAsync()).TargetBaseUrl);
        });
        var context = Bind(server, writer, lifetime.Token);
        try
        {
            await ChangeAsync(scope.ServiceProvider.GetRequiredService<ManagementMutationService>(), actor.Context, operation);
            Assert.Equal(1, writer.Writes);
        }
        finally { server.HostServices.GetRequiredService<SessionRegistry>().Unbind("laptop", context); lifetime.Cancel(); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task LegacyNullTenantConfigurationRemainsBoundToItsCurrentParent(bool http)
    {
        await using var server = await TestServerFixture.StartAsync(new Dictionary<string, string?> { ["Specus:Database:SeedDemoClient"] = "false", ["Specus:Auth:TenantId"] = "tenant-a" });
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        db.ClientAccounts.Add(new ClientAccount { Id = 1001, TenantId = "tenant-a", OwnerUsername = "admin", ClientName = "laptop", Enabled = true, PasswordHash = "retained" });
        ClientConfigurationOwnershipTests.SeedConfiguration(db);
        db.SpecusMappings.Local.Single().TenantId = null; db.HttpRouteMappings.Local.Single().TenantId = null;
        await db.SaveChangesAsync();
        var actor = await OwnerTransferWriterProof.ActorAsync(server, scope.ServiceProvider);
        await ChangeAsync(scope.ServiceProvider.GetRequiredService<ManagementMutationService>(), actor.Context, http ? "http-update" : "tcp-update");
        if (http) Assert.Equal("tenant-a", (await db.HttpRouteMappings.AsNoTracking().SingleAsync()).TenantId);
        else Assert.Equal("tenant-a", (await db.SpecusMappings.AsNoTracking().SingleAsync()).TenantId);
    }

    private static async Task SeedAsync(SpecusDbContext db)
    { await OwnerTransferWriterProof.SeedAsync(db, "default"); ClientConfigurationOwnershipTests.SeedConfiguration(db); await db.SaveChangesAsync(); }

    private static SpecusConnectionContext Bind(TestServerFixture server, IFrameWriter writer, CancellationToken lifetime)
    {
        var context = new SpecusConnectionContext("retained-control", "127.0.0.1:12345", writer, lifetime, () => { }, new ReadGate(lifetime), new WriteBackpressureGate(64 * 1024, 1024 * 1024));
        context.OnLoginSuccess("laptop", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), clientSessionId: 901, clientId: 1001);
        server.HostServices.GetRequiredService<SessionRegistry>().Replace("laptop", context);
        return context;
    }

    private static async Task ChangeAsync(ManagementMutationService service, ManagementContext actor, string operation)
    {
        switch (operation)
        {
            case "tcp-create": await service.CreateSpecusAsync(actor, 1001, new SpecusMappingMutation(24862, "127.0.0.1", 81, false, false), CancellationToken.None); break;
            case "tcp-update": await service.UpdateSpecusAsync(actor, 4201, new SpecusMappingMutation(24861, "127.0.0.1", 81, false, false), CancellationToken.None); break;
            case "tcp-delete": await service.DeleteSpecusAsync(actor, 4201, CancellationToken.None); break;
            case "http-create": await service.CreateHttpRouteAsync(actor, 1001, new HttpRouteMutation("new-route", "http://127.0.0.1:8001", false, false, false, false, null, null), CancellationToken.None); break;
            case "http-update": await service.UpdateHttpRouteAsync(actor, 4301, new HttpRouteMutation("existing", "http://127.0.0.1:8001", false, false, false, false, null, null), CancellationToken.None); break;
            case "http-delete": await service.DeleteHttpRouteAsync(actor, 4301, CancellationToken.None); break;
        }
    }

    private sealed class RecordingWriter(Func<Task>? observe = null) : IFrameWriter
    {
        internal int Writes { get; private set; }
        public async ValueTask WriteAsync(Packet packet, CancellationToken cancellationToken = default)
        { Writes++; if (observe is not null) await observe(); }
    }

    private sealed class CommitFault : DbTransactionInterceptor
    {
        internal bool Armed { get; set; }
        internal bool Triggered { get; private set; }
        public override ValueTask<InterceptionResult> TransactionCommittingAsync(DbTransaction transaction, TransactionEventData eventData,
            InterceptionResult result, CancellationToken cancellationToken = default)
        {
            if (Armed) { Triggered = true; throw new InvalidOperationException("owned configuration commit fixture failure"); }
            return ValueTask.FromResult(result);
        }
    }
}
