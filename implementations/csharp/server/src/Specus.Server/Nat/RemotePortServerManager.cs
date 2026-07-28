using System.Collections.Concurrent;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Specus.Server.Configuration;

namespace Specus.Server.Nat;

public sealed class RemotePortServerManager : IHostedService, IAsyncDisposable
{
    private readonly ConcurrentDictionary<int, RemotePortServer> _servers = new();
    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger<RemotePortServerManager> _logger;
    private readonly NettyServerOptions _options;

    private int _activeExternalConnections;
    private long _rejectedExternalConnections;

    public RemotePortServerManager(IOptions<NettyServerOptions> options,
        ILoggerFactory loggerFactory, ILogger<RemotePortServerManager> logger)
    {
        _options = options.Value;
        _loggerFactory = loggerFactory;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        await DisposeAsync().ConfigureAwait(false);
    }

    public async Task<RemotePortBinding> BindAsync(int port,
        Func<System.Net.Sockets.Socket, CancellationToken, Task> accepted,
        CancellationToken cancellationToken)
    {
        var server = new RemotePortServer(port, accepted, _loggerFactory.CreateLogger<RemotePortServer>());
        if (!_servers.TryAdd(port, server))
        {
            await server.DisposeAsync().ConfigureAwait(false);
            throw new InvalidOperationException($"port {port} already in use");
        }

        try
        {
            await server.StartAsync(cancellationToken).ConfigureAwait(false);
            _logger.LogInformation("remote port {Port} bound", port);
            return new RemotePortBinding(port, this, server);
        }
        catch
        {
            _servers.TryRemove(port, out _);
            await server.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    internal async ValueTask ReleaseBindingAsync(int port, RemotePortServer server)
    {
        if (_servers.TryRemove(new KeyValuePair<int, RemotePortServer>(port, server)))
        {
            await server.DisposeAsync().ConfigureAwait(false);
            _logger.LogInformation("remote port {Port} released", port);
        }
    }

    public bool TryAcquireExternalConnection()
    {
        var max = _options.MaxExternalConnections;
        if (max <= 0)
        {
            Interlocked.Increment(ref _activeExternalConnections);
            return true;
        }

        while (true)
        {
            var current = Volatile.Read(ref _activeExternalConnections);
            if (current >= max)
            {
                RecordRejectedExternalConnection();
                return false;
            }
            if (Interlocked.CompareExchange(ref _activeExternalConnections, current + 1, current) == current)
            {
                return true;
            }
        }
    }

    public void ReleaseExternalConnection()
    {
        while (true)
        {
            var current = Volatile.Read(ref _activeExternalConnections);
            if (current <= 0)
            {
                return;
            }
            if (Interlocked.CompareExchange(ref _activeExternalConnections, current - 1, current) == current)
            {
                return;
            }
        }
    }

    public void RecordRejectedExternalConnection() =>
        Interlocked.Increment(ref _rejectedExternalConnections);

    public int ActiveExternalConnections => Volatile.Read(ref _activeExternalConnections);

    public long RejectedExternalConnections => Volatile.Read(ref _rejectedExternalConnections);

    /// <summary>
    /// Test/visibility hook — true once <see cref="BindAsync"/> has successfully started a
    /// <see cref="RemotePortServer"/> on this port. Does not imply anything about the bound
    /// server's current health; it can return false transiently during teardown.
    /// </summary>
    public bool HasBinding(int port) => _servers.ContainsKey(port);

    public async ValueTask DisposeAsync()
    {
        var bindings = _servers.ToArray();
        _servers.Clear();
        foreach (var (_, server) in bindings)
        {
            await server.DisposeAsync().ConfigureAwait(false);
        }
    }
}

public sealed class RemotePortBinding : IAsyncDisposable
{
    private readonly RemotePortServerManager _owner;
    private readonly RemotePortServer _server;
    private int _disposed;

    internal RemotePortBinding(int port, RemotePortServerManager owner, RemotePortServer server)
    {
        Port = port;
        _owner = owner;
        _server = server;
    }

    public int Port { get; }

    public ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            return _owner.ReleaseBindingAsync(Port, _server);
        }
        return ValueTask.CompletedTask;
    }
}
