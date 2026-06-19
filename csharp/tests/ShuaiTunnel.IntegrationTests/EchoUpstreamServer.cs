using System.Net;
using System.Net.Sockets;

namespace ShuaiTunnel.IntegrationTests;

/// <summary>
/// Tiny TCP echo server used as the upstream target for the Java tunnel-client's
/// <c>tunnelConfigList</c>. Each accepted socket gets its own read loop that copies every
/// received byte straight back to the writer until the peer closes.
/// </summary>
internal sealed class EchoUpstreamServer : IAsyncDisposable
{
    private readonly TcpListener _listener;

    public int BoundPort { get; }

    public EchoUpstreamServer()
    {
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        BoundPort = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _ = Task.Run(AcceptLoopAsync);
    }

    private async Task AcceptLoopAsync()
    {
        while (true)
        {
            Socket socket;
            try { socket = await _listener.AcceptSocketAsync(); }
            catch (ObjectDisposedException) { return; }
            catch (SocketException) { return; }
            _ = Task.Run(() => ServeAsync(socket));
        }
    }

    private static async Task ServeAsync(Socket socket)
    {
        var stream = new NetworkStream(socket, ownsSocket: false);
        var buffer = new byte[4096];
        try
        {
            int read;
            while ((read = await stream.ReadAsync(buffer)) > 0)
            {
                await stream.WriteAsync(buffer.AsMemory(0, read));
                await stream.FlushAsync();
            }
        }
        catch (IOException) { /* peer closed */ }
        finally
        {
            try { socket.Close(); } catch { /* ignore */ }
        }
    }

    public ValueTask DisposeAsync()
    {
        _listener.Stop();
        return ValueTask.CompletedTask;
    }
}