using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using MySql.Data.MySqlClient;
using Specus.Server.Data;
using Specus.Server.Data.MySql;

namespace Specus.IntegrationTests;

internal static class MySqlTlsCancellationProviderProof
{
    internal static async Task VerifyAsync(string original)
    {
        var settings = new MySqlConnectionStringBuilder(original) { SslMode = MySqlSslMode.Required, Pooling = false };
        // Verify encryption on the real owned database first. The proxy never downgrades
        // the greeting or terminates TLS: it only holds an actual server TLS record.
        await using (var encrypted = new MySqlConnection(settings.ConnectionString))
        {
            await encrypted.OpenAsync();
            await using var command = encrypted.CreateCommand(); command.CommandText = "SHOW SESSION STATUS LIKE 'Ssl_cipher'";
            await using var reader = await command.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync()); Assert.False(string.IsNullOrWhiteSpace(reader.GetString(1)));
        }
        await using var proxy = new TlsGateProxy(settings.Server, checked((int)settings.Port));
        settings.Server = "127.0.0.1"; settings.Port = checked((uint)proxy.Port);
        using var host = Host.CreateDefaultBuilder().ConfigureLogging(logging => logging.ClearProviders())
            .ConfigureServices(services =>
            {
                services.AddDbContext<SpecusDbContext>(options => MySqlDatabaseCompatibility.Configure(options, settings.ConnectionString));
                services.AddHostedService<OpeningWorker>();
            }).Build();
        var worker = host.Services.GetServices<IHostedService>().OfType<OpeningWorker>().Single();
        await host.StartAsync();
        Task? stopping = null;
        try
        {
            await proxy.ServerTlsRecordHeld.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.False(worker.Completed.Task.IsCompleted);
            stopping = host.StopAsync(CancellationToken.None);
            await worker.CancellationObserved.Task.WaitAsync(TimeSpan.FromSeconds(10));
            // Before the fix, this throws AggregateException from the connector's
            // cancellation callback on the Host.StopAsync invocation thread.
            await stopping.WaitAsync(TimeSpan.FromSeconds(10));
            await worker.Completed.Task.WaitAsync(TimeSpan.FromSeconds(10));
            var canceled = Assert.IsAssignableFrom<OperationCanceledException>(worker.Error);
            Assert.Equal(worker.StoppingToken, canceled.CancellationToken);
            Assert.True(worker.ConnectionClosed);
        }
        finally
        {
            proxy.Release();
            if (stopping is not null) try { await stopping; } catch (Exception) { }
            try { await worker.Completed.Task.WaitAsync(TimeSpan.FromSeconds(10)); } catch (Exception) { }
        }
    }

    private sealed class OpeningWorker(IServiceScopeFactory scopes) : BackgroundService
    {
        internal TaskCompletionSource CancellationObserved { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Completed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal CancellationToken StoppingToken { get; private set; }
        internal Exception? Error { get; private set; }
        internal bool ConnectionClosed { get; private set; }
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            StoppingToken = stoppingToken;
            using var registration = stoppingToken.UnsafeRegister(_ => CancellationObserved.TrySetResult(), null);
            System.Data.Common.DbConnection? connection = null;
            try
            {
                await using (var scope = scopes.CreateAsyncScope())
                {
                    var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
                    connection = db.Database.GetDbConnection();
                    try { await db.Database.OpenConnectionAsync(stoppingToken); }
                    catch (Exception error) { Error = error; }
                }
                ConnectionClosed = connection.State == System.Data.ConnectionState.Closed;
            }
            catch (Exception error) { Error ??= error; }
            finally { Completed.TrySetResult(); }
        }
    }

    private sealed class TlsGateProxy : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _lifetime = new();
        private readonly TaskCompletionSource _held = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly Task _run;
        private TcpClient? _client;
        private TcpClient? _upstream;
        internal int Port { get; }
        internal Task ServerTlsRecordHeld => _held.Task;
        internal TlsGateProxy(string upstreamHost, int upstreamPort)
        {
            _listener.Start(); Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            _run = RunAsync(upstreamHost, upstreamPort);
        }
        internal void Release() => _release.TrySetResult();
        private async Task RunAsync(string host, int port)
        {
            var ct = _lifetime.Token;
            try
            {
                _client = await _listener.AcceptTcpClientAsync(ct);
                _upstream = new TcpClient(); await _upstream.ConnectAsync(host, port, ct);
                var down = _client.GetStream(); var up = _upstream.GetStream();
                await down.WriteAsync(await ReadMySqlPacketAsync(up, ct), ct);
                var request = await ReadMySqlPacketAsync(down, ct);
                Assert.Equal(36, request.Length);
                Assert.NotEqual(0u, BinaryPrimitives.ReadUInt32LittleEndian(request.AsSpan(4, 4)) & 0x0800u);
                await up.WriteAsync(request, ct);
                var hello = await ReadTlsRecordAsync(down, ct); Assert.Equal(22, hello[0]);
                await up.WriteAsync(hello, ct);
                var held = await ReadTlsRecordAsync(up, ct); Assert.Equal(22, held[0]);
                _held.TrySetResult();
                await _release.Task.WaitAsync(ct);
                await down.WriteAsync(held, ct);
                await Task.WhenAll(up.CopyToAsync(down, ct), down.CopyToAsync(up, ct));
            }
            catch (Exception error) { _held.TrySetException(error); if (!_lifetime.IsCancellationRequested) throw; }
        }
        private static async Task<byte[]> ReadMySqlPacketAsync(Stream stream, CancellationToken ct)
        {
            var header = new byte[4]; await stream.ReadExactlyAsync(header, ct);
            var length = header[0] | header[1] << 8 | header[2] << 16;
            Assert.InRange(length, 1, 65536);
            var packet = new byte[4 + length]; header.CopyTo(packet, 0);
            await stream.ReadExactlyAsync(packet.AsMemory(4), ct); return packet;
        }
        private static async Task<byte[]> ReadTlsRecordAsync(Stream stream, CancellationToken ct)
        {
            var header = new byte[5]; await stream.ReadExactlyAsync(header, ct);
            var length = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(3, 2));
            Assert.InRange(length, 1, 18432);
            var record = new byte[5 + length]; header.CopyTo(record, 0);
            await stream.ReadExactlyAsync(record.AsMemory(5), ct); return record;
        }
        public async ValueTask DisposeAsync()
        {
            Release(); _lifetime.Cancel(); _client?.Dispose(); _upstream?.Dispose(); _listener.Stop();
            try { await _run; } catch (Exception) when (_lifetime.IsCancellationRequested) { }
            _lifetime.Dispose();
        }
    }
}
