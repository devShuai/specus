using System.Collections.Concurrent;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;

namespace Specus.IntegrationTests;

public sealed class OwnerTransferJournalTests
{
    [Fact]
    public async Task FailureRetriesLowerIdsCommittedLateAndRestartReplaysIndependently()
    {
        await using var server = await ClientOwnerTransferWriterTests.StartAsync();
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        db.ClientOwnerTransferAudits.Add(Audit(30, "[1001]")); await db.SaveChangesAsync();
        var fake = new Reconciler { FailNext = true };
        await using var local = new ServiceCollection().AddDbContext<SpecusDbContext>(options => options.UseSqlite(db.Database.GetConnectionString()))
            .AddSingleton<IOwnerTransferReconciler>(fake).BuildServiceProvider();
        using var first = new OwnerTransferNotifications(local.GetRequiredService<IServiceScopeFactory>(), NullLogger<OwnerTransferNotifications>.Instance);
        Assert.Equal(0, await first.DrainAsync(CancellationToken.None));
        Assert.False(await db.ClientOwnerTransferReceipts.AnyAsync(r => r.NodeId == first.NodeId));
        Assert.Equal(1, await first.DrainAsync(CancellationToken.None));
        // A lower ID commits AFTER the high ID has already been acknowledged.
        db.ClientOwnerTransferAudits.Add(Audit(10, "[1002,1002]")); await db.SaveChangesAsync();
        Assert.Equal(1, await first.DrainAsync(CancellationToken.None));
        Assert.Equal(0, await first.DrainAsync(CancellationToken.None));
        using var restarted = new OwnerTransferNotifications(local.GetRequiredService<IServiceScopeFactory>(), NullLogger<OwnerTransferNotifications>.Instance);
        Assert.NotEqual(first.NodeId, restarted.NodeId);
        Assert.Equal(2, await restarted.DrainAsync(CancellationToken.None));
        Assert.Equal(2, await db.ClientOwnerTransferReceipts.CountAsync(r => r.NodeId == first.NodeId));
        Assert.Equal(2, await db.ClientOwnerTransferReceipts.CountAsync(r => r.NodeId == restarted.NodeId));
        Assert.Contains(fake.Calls, call => call.SequenceEqual(new long[] { 1002 }));
    }

    [Fact]
    public async Task MalformedEventsRemainPendingWithoutBlockingOtherEvents()
    {
        await using var server = await ClientOwnerTransferWriterTests.StartAsync();
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        db.ClientOwnerTransferAudits.AddRange(Audit(1, "[0]"), Audit(2, "[]")); await db.SaveChangesAsync();
        var fake = new Reconciler();
        await using var local = new ServiceCollection().AddDbContext<SpecusDbContext>(options => options.UseSqlite(db.Database.GetConnectionString()))
            .AddSingleton<IOwnerTransferReconciler>(fake).BuildServiceProvider();
        using var consumer = new OwnerTransferNotifications(local.GetRequiredService<IServiceScopeFactory>(), NullLogger<OwnerTransferNotifications>.Instance);
        Assert.Equal(1, await consumer.DrainAsync(CancellationToken.None));
        Assert.False(await db.ClientOwnerTransferReceipts.AnyAsync(r => r.NodeId == consumer.NodeId && r.EventId == 1));
        Assert.True(await db.ClientOwnerTransferReceipts.AnyAsync(r => r.NodeId == consumer.NodeId && r.EventId == 2));
        Assert.Empty(Assert.Single(fake.Calls));
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"affectedClientIds\":null}")]
    [InlineData("{\"affectedClientIds\":[\"1\"]}")]
    [InlineData("{\"affectedClientIds\":[1.5]}")]
    [InlineData("{\"affectedClientIds\":[9007199254740992]}")]
    public void JournalDoesNotCoerceOrGuessAffectedClients(string json) =>
        Assert.Throws<InvalidDataException>(() => OwnerTransferNotifications.ParseClients(json));

    private static ClientOwnerTransferAudit Audit(long id, string ids) => new()
    {
        Id = id, TenantId = "tenant-a", Actor = "admin", Scope = "single", PathId = 1001,
        TargetUsername = "historical-owner-must-not-be-applied", OccurredAt = DateTimeOffset.UtcNow,
        DetailJson = "{\"affectedClientIds\":" + ids + "}",
    };

    private sealed class Reconciler : IOwnerTransferReconciler
    {
        internal bool FailNext;
        internal ConcurrentQueue<long[]> Calls { get; } = new();
        public Task ReconcileOwnershipAsync(string tenant, IReadOnlyList<long> clients, CancellationToken ct)
        {
            Assert.Equal("tenant-a", tenant);
            Calls.Enqueue(clients.ToArray());
            if (FailNext) { FailNext = false; throw new IOException("injected runtime failure"); }
            return Task.CompletedTask;
        }
    }
}
