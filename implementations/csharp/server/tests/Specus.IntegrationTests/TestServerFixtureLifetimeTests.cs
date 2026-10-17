using System.Runtime.CompilerServices;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Data;

namespace Specus.IntegrationTests;

public sealed class TestServerFixtureLifetimeTests
{
    private sealed record DisposedHost(WeakReference Owner, WeakReference Provider, string DatabasePath);

    [Fact]
    public async Task DisposedHostsReleaseTheirPoolsWithoutClearingUnrelatedPools()
    {
        var path=Path.Combine(Path.GetTempPath(),$"specus-fixture-pool-proof-{Guid.NewGuid():N}.db");
        await using var survivor=new SqliteConnection($"Data Source={path}");
        var hosts=new List<DisposedHost>();
        try
        {
            await survivor.OpenAsync();
            var handle=survivor.Handle;
            await using(var command=survivor.CreateCommand())
            {
                command.CommandText="CREATE TABLE sentinel(value INTEGER); INSERT INTO sentinel VALUES(42)";
                await command.ExecuteNonQueryAsync();
            }
            await survivor.CloseAsync();
            for(var i=0;i<20;i++) hosts.Add(await CreateAndDisposeAsync());

            // Leave the last disposal's inline completion stack before checking liveness.
            await Task.Yield();

            // Only this dedicated lifetime regression forces collection; existing timeout
            // gates must not gain forced collections or relaxed assertions/deadlines.
            GC.Collect(2,GCCollectionMode.Forced,blocking:true,compacting:true);
            GC.WaitForPendingFinalizers();
            GC.Collect(2,GCCollectionMode.Forced,blocking:true,compacting:true);
            Assert.All(hosts,host=>Assert.False(host.Owner.IsAlive,"Disposed fixture retained by a pooled timer"));
            Assert.All(hosts,host=>Assert.False(host.Provider.IsAlive,"Disposed service container retained"));
            Assert.All(hosts,host=>Assert.False(File.Exists(host.DatabasePath),"Owned database file was not removed"));

            await survivor.OpenAsync();
            Assert.Same(handle,survivor.Handle);
            await using var read=survivor.CreateCommand();
            read.CommandText="SELECT value FROM sentinel";
            Assert.Equal(42L,await read.ExecuteScalarAsync());
        }
        finally
        {
            await survivor.CloseAsync();
            SqliteConnection.ClearPool(survivor);
            File.Delete(path);
            // Also clean generated files after the old-code negative control fails.
            foreach(var host in hosts)
            {
                using var owned=new SqliteConnection($"Data Source={host.DatabasePath}");
                SqliteConnection.ClearPool(owned);
                File.Delete(host.DatabasePath);
            }
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static async Task<DisposedHost> CreateAndDisposeAsync()
    {
        await using var fixture=await TestServerFixture.StartAsync();
        string path;
        using(var scope=fixture.HostServices.CreateScope())
        {
            var db=scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            path=new SqliteConnectionStringBuilder(db.Database.GetConnectionString()).DataSource;
        }
        using var client=fixture.CreateClient();
        using var response=await client.GetAsync("/health");
        response.EnsureSuccessStatusCode();
        return new DisposedHost(new WeakReference(fixture),new WeakReference(fixture.HostServices),path);
    }

    [Fact]
    public async Task HandlersAreReusedWithinAHostAndTheirScopesAreDisposedWithOnlyThatHost()
    {
        var firstState=new HandlerScopeState();
        var secondState=new HandlerScopeState();
        var first=await StartAsync(firstState);
        var second=await StartAsync(secondState);
        try
        {
            var firstFactory=first.HostServices.GetRequiredService<IHttpMessageHandlerFactory>();
            var secondFactory=second.HostServices.GetRequiredService<IHttpMessageHandlerFactory>();
            Assert.Same(firstFactory.CreateHandler("fixture-scope-proof"),firstFactory.CreateHandler("fixture-scope-proof"));
            Assert.Same(secondFactory.CreateHandler("fixture-scope-proof"),secondFactory.CreateHandler("fixture-scope-proof"));
            Assert.Equal(1,firstState.Created);
            Assert.Equal(1,secondState.Created);
            Assert.Equal(0,firstState.Disposed);
            Assert.Equal(0,secondState.Disposed);

            await first.DisposeAsync();
            Assert.Equal(1,firstState.Disposed);
            Assert.Equal(0,secondState.Disposed);
            using var client=second.CreateClient();
            using var response=await client.GetAsync("/health");
            response.EnsureSuccessStatusCode();
            await second.DisposeAsync();
            Assert.Equal(1,secondState.Disposed);
        }
        finally
        {
            await first.DisposeAsync();
            await second.DisposeAsync();
        }

        static Task<TestServerFixture> StartAsync(HandlerScopeState state) => TestServerFixture.StartAsync(
            configureServices:services=>
            {
                services.AddSingleton(state);
                services.AddScoped<HandlerScopeResource>();
                services.AddTransient<ScopeHandler>();
                services.AddHttpClient("fixture-scope-proof").AddHttpMessageHandler<ScopeHandler>();
            });
    }

    private sealed class HandlerScopeState { internal int Created; internal int Disposed; }
    private sealed class HandlerScopeResource : IDisposable
    {
        private readonly HandlerScopeState _state;
        public HandlerScopeResource(HandlerScopeState state) { _state=state; Interlocked.Increment(ref _state.Created); }
        public void Dispose() => Interlocked.Increment(ref _state.Disposed);
    }
    private sealed class ScopeHandler : DelegatingHandler
    {
        public ScopeHandler(HandlerScopeResource resource) { _=resource; }
    }
}
