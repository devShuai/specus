using System.Net;
using System.Net.Sockets;
using System.Text;

namespace ShuaiTunnel.StunServer;

internal sealed class StunMetricsHttpServer : IAsyncDisposable
{
    private readonly StunMetricsConfig _config;
    private readonly Func<string> _content;
    private TcpListener? _listener;
    private CancellationTokenSource? _shutdown;
    private Task? _worker;

    public StunMetricsHttpServer(StunMetricsConfig config, Func<string> content)
    {
        _config = config;
        _content = content;
    }

    public void Start(CancellationToken cancellationToken)
    {
        if (!_config.Enabled)
        {
            return;
        }
        _listener = new TcpListener(_config.BindAddress, _config.Port);
        _listener.Start(16);
        _shutdown = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _worker = AcceptLoopAsync(_shutdown.Token);
    }

    private async Task AcceptLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested && _listener is not null)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            await HandleAsync(client, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task HandleAsync(TcpClient client, CancellationToken cancellationToken)
    {
        await using var stream = client.GetStream();
        using (client)
        using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
        {
            timeout.CancelAfter(TimeSpan.FromSeconds(2));
            var buffer = new byte[4_096];
            int bytes;
            try
            {
                bytes = await stream.ReadAsync(buffer, timeout.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            var firstLine = Encoding.ASCII.GetString(buffer, 0, bytes)
                .Split("\r\n", 2, StringSplitOptions.None)[0];
            var valid = firstLine.StartsWith("GET /metrics ", StringComparison.Ordinal);
            var body = valid ? Encoding.UTF8.GetBytes(_content()) : [];
            var status = valid ? "200 OK" : "404 Not Found";
            var headers = Encoding.ASCII.GetBytes(
                $"HTTP/1.1 {status}\r\n"
                + "Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
                + "Cache-Control: no-store\r\n"
                + $"Content-Length: {body.Length}\r\n"
                + "Connection: close\r\n\r\n");
            await stream.WriteAsync(headers, cancellationToken).ConfigureAwait(false);
            if (body.Length > 0)
            {
                await stream.WriteAsync(body, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_shutdown is not null)
        {
            await _shutdown.CancelAsync().ConfigureAwait(false);
        }
        _listener?.Stop();
        if (_worker is not null)
        {
            try
            {
                await _worker.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Normal shutdown.
            }
        }
        _shutdown?.Dispose();
        _shutdown = null;
        _listener = null;
        _worker = null;
    }
}
