using System.Net.WebSockets;
using Microsoft.Extensions.Logging;
using ShuaiTunnel.Client.Control;
using ShuaiTunnel.Protocol;
using ShuaiTunnel.Protocol.Packets;

namespace ShuaiTunnel.Client.Nat;

/// <summary>
/// One local WebSocket connection bridged through NAT <c>DATA</c> frames. The first byte of each
/// tunneled payload mirrors the Java client/server convention: <c>0x01</c> text, <c>0x02</c> binary.
/// </summary>
internal sealed class WebSocketTunnelChannel : IAsyncDisposable
{
    internal const byte FrameText = 0x01;
    internal const byte FrameBinary = 0x02;
    private const int BufferSize = 16 * 1024;
    private const int MaxMessageBytes = 16 * 1024 * 1024;

    private readonly ClientWebSocket _socket;
    private readonly FrameWriter _controlWriter;
    private readonly ILogger _logger;
    private readonly Action<WebSocketTunnelChannel> _onClosed;
    private readonly CancellationTokenSource _cts = new();
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly ManualResetEventSlim _writableGate = new(initialState: true);

    public WebSocketTunnelChannel(
        string channelId,
        ClientWebSocket socket,
        FrameWriter controlWriter,
        ILogger logger,
        Action<WebSocketTunnelChannel> onClosed)
    {
        ChannelId = channelId;
        _socket = socket;
        _controlWriter = controlWriter;
        _logger = logger;
        _onClosed = onClosed;
    }

    public string ChannelId { get; }

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

    public async Task PumpAsync(CancellationToken cancellationToken)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token, cancellationToken);
        var token = linked.Token;
        var buffer = new byte[BufferSize];
        MemoryStream? current = null;
        WebSocketMessageType currentType = WebSocketMessageType.Binary;
        try
        {
            while (!token.IsCancellationRequested && _socket.State == WebSocketState.Open)
            {
                if (!_writableGate.IsSet)
                {
                    _writableGate.Wait(TimeSpan.FromSeconds(1));
                    continue;
                }

                var result = await _socket.ReceiveAsync(buffer.AsMemory(), token).ConfigureAwait(false);
                if (result.MessageType == WebSocketMessageType.Close)
                {
                    break;
                }
                if (result.MessageType is not WebSocketMessageType.Text and not WebSocketMessageType.Binary)
                {
                    continue;
                }

                current ??= new MemoryStream();
                if (current.Length == 0)
                {
                    currentType = result.MessageType;
                }
                current.Write(buffer, 0, result.Count);
                if (current.Length > MaxMessageBytes)
                {
                    _logger.LogDebug("ws channel {channel}: local message exceeds limit", ChannelId);
                    break;
                }
                if (!result.EndOfMessage)
                {
                    continue;
                }

                var data = current.ToArray();
                current.Dispose();
                current = null;
                var payload = new byte[data.Length + 1];
                payload[0] = currentType == WebSocketMessageType.Text ? FrameText : FrameBinary;
                Buffer.BlockCopy(data, 0, payload, 1, data.Length);
                var packet = new NatMessagePacket
                {
                    NatMessageType = NatMessageType.Data,
                    MetaData = new Dictionary<string, object?> { ["channelId"] = ChannelId, ["source"] = "ws" },
                    Data = payload,
                };
                try
                {
                    await _controlWriter.WriteAsync(packet, token).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogDebug(ex, "ws channel {channel}: write to control failed", ChannelId);
                    break;
                }
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogDebug(ex, "ws channel {channel}: local pump aborted", ChannelId);
        }
        finally
        {
            current?.Dispose();
            _onClosed(this);
            await DisposeAsync().ConfigureAwait(false);
        }
    }

    public async ValueTask WriteAsync(byte[] data, CancellationToken cancellationToken)
    {
        if (data.Length == 0 || _socket.State != WebSocketState.Open)
        {
            return;
        }
        var frameType = data[0];
        var messageType = frameType switch
        {
            FrameText => WebSocketMessageType.Text,
            FrameBinary => WebSocketMessageType.Binary,
            _ => (WebSocketMessageType?)null,
        };
        if (messageType is null)
        {
            return;
        }
        try
        {
            await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                await _socket.SendAsync(
                    data.AsMemory(1),
                    messageType.Value,
                    endOfMessage: true,
                    cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _writeLock.Release();
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogDebug(ex, "ws channel {channel}: local write failed", ChannelId);
            Close();
        }
    }

    public void Close()
    {
        try { _cts.Cancel(); }
        catch (ObjectDisposedException) { }
        try { _socket.Abort(); }
        catch { /* best effort */ }
    }

    public ValueTask DisposeAsync()
    {
        Close();
        _socket.Dispose();
        _writeLock.Dispose();
        _writableGate.Dispose();
        _cts.Dispose();
        return ValueTask.CompletedTask;
    }
}
