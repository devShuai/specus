using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;

namespace Specus.Server.Nat;

internal sealed class RemotePortServer : IAsyncDisposable
{
    private readonly int _port;
    private readonly Func<Socket, CancellationToken, Task> _accepted;
    private readonly ILogger _logger;
    private readonly CancellationTokenSource _shutdown = new();

    private TcpListener? _listener;
    private Task? _acceptLoop;

    public RemotePortServer(int port, Func<Socket, CancellationToken, Task> accepted, ILogger logger)
    {
        _port = port;
        _accepted = accepted;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _listener = new TcpListener(IPAddress.Any, _port);
        _listener.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        _listener.Start(backlog: 8192);
        _acceptLoop = Task.Run(AcceptLoopAsync, cancellationToken);
        return Task.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        _shutdown.Cancel();
        try { _listener?.Stop(); } catch { /* listener already down */ }
        if (_acceptLoop is not null)
        {
            try { await _acceptLoop.ConfigureAwait(false); } catch { /* shutdown path */ }
        }
        _shutdown.Dispose();
    }

    private async Task AcceptLoopAsync()
    {
        var token = _shutdown.Token;
        while (!token.IsCancellationRequested)
        {
            Socket socket;
            try
            {
                socket = await _listener!.AcceptSocketAsync(token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (SocketException ex)
            {
                _logger.LogWarning(ex, "external accept failed on port {Port}", _port);
                continue;
            }

            socket.NoDelay = true;
            try
            {
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
            }
            catch (SocketException)
            {
                // Best effort, same as the control listener.
            }

            _ = Task.Run(() => _accepted(socket, token), token);
        }
    }
}
