using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using ShuaiTunnel.Client.Control;
using ShuaiTunnel.Protocol;
using ShuaiTunnel.Protocol.Packets;
using ShuaiTunnel.Protocol.Flow;

namespace ShuaiTunnel.Client.Nat;

/// <summary>
/// One local TCP connection bridging a server-allocated <c>channelId</c> to a target on the
/// internal network. The read loop forwards bytes upstream as <c>NatMessage.Data</c>; downstream
/// bytes from the server are written by <see cref="WriteAsync"/>. Pauses reads while the
/// control channel is backpressured to avoid unbounded buffering.
/// </summary>
internal sealed class LocalTunnelChannel : IAsyncDisposable
{
    private const int ReadBufferSize = 16 * 1024;

    private readonly TcpClient _tcp;
    private readonly NetworkStream _stream;
    private readonly FrameWriter _controlWriter;
    private readonly ILogger _logger;
    private readonly Action<LocalTunnelChannel> _onClosed;
    private readonly CancellationTokenSource _cts = new();
    private readonly StreamSendWindow _sendWindow = new();

    public string ChannelId { get; }
    public uint StreamId { get; }
    public int Port { get; }
    private readonly ManualResetEventSlim _writableGate = new(initialState: true);

    public LocalTunnelChannel(
        uint streamId,
        string channelId,
        int port,
        TcpClient tcp,
        FrameWriter controlWriter,
        ILogger logger,
        Action<LocalTunnelChannel> onClosed)
    {
        StreamId = streamId;
        ChannelId = channelId;
        Port = port;
        _tcp = tcp;
        _stream = tcp.GetStream();
        _controlWriter = controlWriter;
        _logger = logger;
        _onClosed = onClosed;
    }

    public void SetControlWritable(bool writable)
    {
        if (writable)
        {
            _writableGate.Set();
        }
        else
        {
            _writableGate.Reset();
        }
    }

    /// <summary>Pumps bytes from the local socket to the control channel until EOF or error.</summary>
    public async Task PumpAsync(CancellationToken cancellationToken)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token, cancellationToken);
        var token = linked.Token;
        var buffer = new byte[ReadBufferSize];
        try
        {
            while (!token.IsCancellationRequested)
            {
                if (!_writableGate.IsSet)
                {
                    // Backpressure: wait on a 1s budget so cancellation propagates promptly.
                    _writableGate.Wait(TimeSpan.FromSeconds(1));
                    continue;
                }
                var read = await _stream.ReadAsync(buffer, token).ConfigureAwait(false);
                if (read <= 0)
                {
                    break;
                }
                var payload = new byte[read];
                Buffer.BlockCopy(buffer, 0, payload, 0, read);
                if (!await _sendWindow.ConsumeAsync(payload.Length, token).ConfigureAwait(false))
                {
                    break;
                }
                var packet = new NatMessagePacket
                {
                    NatMessageType = NatMessageType.Data,
                    StreamId = StreamId,
                    Data = payload,
                };
                try
                {
                    await _controlWriter.WriteAsync(packet, token).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogDebug(ex, "channel {channel}: write to control failed", ChannelId);
                    break;
                }
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogDebug(ex, "channel {channel}: local pump aborted", ChannelId);
        }
        finally
        {
            _onClosed(this);
            await DisposeAsync().ConfigureAwait(false);
        }
    }

    public async ValueTask WriteAsync(byte[] data, CancellationToken cancellationToken)
    {
        try
        {
            await _stream.WriteAsync(data, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogDebug(ex, "channel {channel}: local write failed", ChannelId);
            Close();
        }
    }

    public void Close()
    {
        _sendWindow.Close();
        try { _cts.Cancel(); }
        catch (ObjectDisposedException) { }
        try { _tcp.Close(); }
        catch { /* best effort */ }
    }

    public bool AddSendCredit(uint credit) => _sendWindow.Add(credit);

    public async ValueTask DisposeAsync()
    {
        Close();
        await _stream.DisposeAsync().ConfigureAwait(false);
        _tcp.Dispose();
        _writableGate.Dispose();
        _cts.Dispose();
    }
}
