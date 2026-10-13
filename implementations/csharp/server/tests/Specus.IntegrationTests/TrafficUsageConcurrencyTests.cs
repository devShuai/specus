using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Hosting;
using Specus.Server.Nat;

namespace Specus.IntegrationTests;

public sealed class TrafficUsageConcurrencyTests
{
    private const int Port = 19001;
    private static readonly TimeSpan GateTimeout = TimeSpan.FromSeconds(5);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ASecondFlushWaitsForTheInFlightDatabaseWrite(bool resource)
    {
        var gate = new SaveGate(resource);
        await using var server = await StartAsync(gate);
        var traffic = server.HostServices.GetRequiredService<TrafficUsageService>();
        await SeedAsync(traffic);
        gate.Hold();
        Record(traffic, 100, 80);
        var first = traffic.FlushAsync(CancellationToken.None);
        Task? second = null;
        var overlapping = false;
        var returnedEarly = false;
        try
        {
            await gate.Entered.Task.WaitAsync(GateTimeout);
            Record(traffic, 200, 160);
            second = traffic.FlushAsync(CancellationToken.None);
            // A store save is deliberately held, not merely slow. Neither a second DB writer
            // nor a flush result may pass it. The final exact sums also detect lost updates.
            await Task.WhenAny(second, gate.SecondWriter.Task, Task.Delay(250));
            overlapping = gate.SecondWriter.Task.IsCompleted;
            returnedEarly = second.IsCompleted;
        }
        finally
        {
            gate.Release();
            await first.WaitAsync(GateTimeout);
            if (second is not null) await second.WaitAsync(GateTimeout);
        }
        await AssertTotalsAsync(server, 307, 251);
        Assert.False(overlapping,
            "two flush callers reached the same statistics row before its first save finished");
        Assert.False(returnedEarly, "flush returned while an earlier snapshot was not durable");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AFailedSaveRestoresOnlyItsUncommittedSnapshot(bool resource)
    {
        var gate = new SaveGate(resource);
        await using var server = await StartAsync(gate);
        var traffic = server.HostServices.GetRequiredService<TrafficUsageService>();
        await SeedAsync(traffic);
        gate.FailNext();
        Record(traffic, 100, 80);
        await Assert.ThrowsAsync<InvalidOperationException>(() => traffic.FlushAsync(CancellationToken.None));
        Record(traffic, 200, 160);
        await traffic.FlushAsync(CancellationToken.None);
        await AssertTotalsAsync(server, 307, 251);
        await traffic.FlushAsync(CancellationToken.None);
        await AssertTotalsAsync(server, 307, 251);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CancellingAQueuedFlushDoesNotConsumeCountersOrReleaseAnotherCallersGate(bool resource)
    {
        var gate = new SaveGate(resource);
        await using var server = await StartAsync(gate);
        var traffic = server.HostServices.GetRequiredService<TrafficUsageService>();
        await SeedAsync(traffic);
        gate.Hold();
        Record(traffic, 100, 80);
        var first = traffic.FlushAsync(CancellationToken.None);
        try
        {
            await gate.Entered.Task.WaitAsync(GateTimeout);
            Record(traffic, 200, 160);
            using var cancelled = new CancellationTokenSource();
            var waiting = traffic.FlushAsync(cancelled.Token);
            cancelled.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting);
            Assert.False(first.IsCompleted);
            Assert.False(gate.SecondWriter.Task.IsCompleted);
        }
        finally
        {
            gate.Release();
            await first.WaitAsync(GateTimeout);
        }
        await traffic.FlushAsync(CancellationToken.None);
        await AssertTotalsAsync(server, 307, 251);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CancellingAnInFlightSaveRestoresItsSnapshotAndAllowsTheNextFlush(bool resource)
    {
        var gate = new SaveGate(resource);
        await using var server = await StartAsync(gate);
        var traffic = server.HostServices.GetRequiredService<TrafficUsageService>();
        await SeedAsync(traffic);
        gate.Hold();
        Record(traffic, 100, 80);
        using var cancelled = new CancellationTokenSource();
        var first = traffic.FlushAsync(cancelled.Token);
        try
        {
            await gate.Entered.Task.WaitAsync(GateTimeout);
            Record(traffic, 200, 160);
            cancelled.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first);
        }
        finally
        {
            gate.Release();
        }
        await traffic.FlushAsync(CancellationToken.None);
        await AssertTotalsAsync(server, 307, 251);
    }

    [Fact]
    public async Task ShutdownWaitsForAnEarlierFlushAndPersistsTheRemainingCounters()
    {
        var gate = new SaveGate(resource: false);
        await using var server = await StartAsync(gate);
        var traffic = server.HostServices.GetRequiredService<TrafficUsageService>();
        await SeedAsync(traffic);
        gate.Hold();
        Record(traffic, 100, 80);
        var first = traffic.FlushAsync(CancellationToken.None);
        Task? stopping = null;
        try
        {
            await gate.Entered.Task.WaitAsync(GateTimeout);
            Record(traffic, 200, 160);
            stopping = traffic.StopAsync(CancellationToken.None);
            await Task.WhenAny(stopping, gate.SecondWriter.Task, Task.Delay(250));
            Assert.False(gate.SecondWriter.Task.IsCompleted);
            Assert.False(stopping.IsCompleted, "shutdown returned before the earlier snapshot was durable");
        }
        finally
        {
            gate.Release();
            await first.WaitAsync(GateTimeout);
            if (stopping is not null) await stopping.WaitAsync(GateTimeout);
        }
        await AssertTotalsAsync(server, 307, 251);
    }

    private static Task<TestServerFixture> StartAsync(SaveGate gate) =>
        TestServerFixture.StartAsync(new Dictionary<string, string?>
        {
            // Explicit callers simulate periodic/manual flushes without a wall-clock race.
            ["Specus:Traffic:FlushIntervalMs"] = "3600000",
        }, services => services.ConfigureDbContext<SpecusDbContext>(
            (_, options) => options.AddInterceptors(gate)));

    private static async Task SeedAsync(TrafficUsageService traffic)
    {
        Record(traffic, 7, 11);
        await traffic.FlushAsync(CancellationToken.None);
    }

    private static void Record(TrafficUsageService traffic, long upload, long download)
    {
        traffic.RecordTcpUpload(DatabaseInitializer.DemoClientName, Port, upload);
        traffic.RecordTcpDownload(DatabaseInitializer.DemoClientName, Port, download);
    }

    private static async Task AssertTotalsAsync(TestServerFixture server, long upload, long download)
    {
        Assert.Equal((upload, download), await server.ReadTrafficTotalsAsync(DatabaseInitializer.DemoClientName));
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var resource = await db.ResourceTrafficUsages.AsNoTracking().SingleAsync(
            row => row.ClientName == DatabaseInitializer.DemoClientName && row.ResourceKey == $"tcp:{Port}");
        Assert.Equal(upload, resource.UploadBytes);
        Assert.Equal(download, resource.DownloadBytes);
        Assert.Equal("default", resource.TenantId);
    }

    // Interception is after EF read the row and before its real SQLite write. Two independent
    // flush scopes therefore expose the old read/modify/save lost-update window deterministically.
    internal sealed class SaveGate(bool resource, TimeSpan? holdTimeout = null) : SaveChangesInterceptor
    {
        private int _mode;
        private int _writes;
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource SecondWriter { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public (long Upload, long Download)? HeldTotals { get; private set; }
        private TaskCompletionSource Resume { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public void Hold() => Volatile.Write(ref _mode, 1);
        public void FailNext() => Volatile.Write(ref _mode, 2);
        public void Release()
        {
            Volatile.Write(ref _mode, 0);
            Resume.TrySetResult();
        }

        public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(
            DbContextEventData eventData, InterceptionResult<int> result,
            CancellationToken cancellationToken = default)
        {
            var matches = eventData.Context?.ChangeTracker.Entries().Any(entry =>
                entry.State is EntityState.Added or EntityState.Modified
                && (resource ? entry.Entity is ResourceTrafficUsage : entry.Entity is TrafficUsage)) == true;
            var mode = Volatile.Read(ref _mode);
            if (!matches || mode == 0) return result;
            if (mode == 2 && Interlocked.CompareExchange(ref _mode, 0, 2) == 2)
                throw new InvalidOperationException("traffic save unavailable (test)");
            if (Interlocked.Increment(ref _writes) == 1)
            {
                HeldTotals = resource
                    ? eventData.Context!.ChangeTracker.Entries<ResourceTrafficUsage>()
                        .Where(entry => entry.State is EntityState.Added or EntityState.Modified)
                        .Select(entry => (entry.Entity.UploadBytes, entry.Entity.DownloadBytes)).Single()
                    : eventData.Context!.ChangeTracker.Entries<TrafficUsage>()
                        .Where(entry => entry.State is EntityState.Added or EntityState.Modified)
                        .Select(entry => (entry.Entity.UploadBytes, entry.Entity.DownloadBytes)).Single();
                Entered.TrySetResult();
                await Resume.Task.WaitAsync(holdTimeout ?? GateTimeout, cancellationToken);
            }
            else
            {
                SecondWriter.TrySetResult();
            }
            return result;
        }
    }
}
