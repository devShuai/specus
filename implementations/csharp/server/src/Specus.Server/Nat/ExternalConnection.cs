using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using Specus.Protocol;
using Specus.Protocol.Packets;
using Specus.Protocol.Flow;
using Specus.Server.Configuration;
using Specus.Server.ControlChannel;
using Specus.Server.Management;
using Specus.Server.Networking;

namespace Specus.Server.Nat;

internal sealed class ExternalConnection : IAsyncDisposable
{
    private const int BufferSize = 16 * 1024;

    private readonly Socket _socket;
    private readonly NetworkStream _stream;
    private readonly SpecusConnectionContext _control;
    private readonly TrafficUsageService _traffic;
    private readonly TrafficInspectionService _inspection;
    private readonly ILogger _logger;
    private readonly ReadGate _readGate;
    private readonly WriteBackpressureGate _writeBackpressure;
    private readonly StreamSendWindow _sendWindow = new();
    private int _closed;

    public ExternalConnection(Socket socket, uint streamId, int port, string clientName,
        SpecusConnectionContext control, TrafficUsageService traffic,
        TrafficInspectionService inspection, NettyServerOptions options, ILogger logger)
    {
        _socket = socket;
        _stream = new NetworkStream(socket, ownsSocket: false);
        Port = port;
        StreamId = streamId;
        ClientName = clientName;
        _control = control;
        _traffic = traffic;
        _inspection = inspection;
        _logger = logger;
        ChannelId = Guid.NewGuid().ToString("N");
        _readGate = new ReadGate(_control.Lifetime);
        _writeBackpressure = new WriteBackpressureGate(
            options.WriteBufferLowWaterMark, options.WriteBufferHighWaterMark);
    }

    public int Port { get; }
    public uint StreamId { get; }
    public string ClientName { get; }
    public string ChannelId { get; }
    public ReadGate ReadGate => _readGate;
    public WriteBackpressureGate WriteBackpressure => _writeBackpressure;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        try
        {
            await SendControlAsync(NatMessageType.Open, new Dictionary<string, object?>
            {
                ["channelId"] = ChannelId,
                ["port"] = Port,
            }, null, cancellationToken).ConfigureAwait(false);

            var buffer = new byte[BufferSize];
            while (!cancellationToken.IsCancellationRequested && !_control.Lifetime.IsCancellationRequested)
            {
                try
                {
                    await _readGate.WaitIfPausedAsync(_control.Lifetime).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (_control.Lifetime.IsCancellationRequested)
                {
                    break;
                }

                var read = await _stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                var payload = buffer.AsSpan(0, read).ToArray();
                if (!await _sendWindow.ConsumeAsync(payload.Length, cancellationToken).ConfigureAwait(false))
                {
                    break;
                }
                _traffic.RecordTcpDownload(ClientName, Port, payload.Length);
                var (sourceAddress, sourcePort) = Endpoint(_socket.RemoteEndPoint);
                var (destinationAddress, destinationPort) = Endpoint(_socket.LocalEndPoint);
                await _inspection.RecordTcpFrameAsync(new TcpFrameCapture(
                        ClientName,
                        Port,
                        ChannelId,
                        TrafficInspectionService.DirectionPublicToClient,
                        sourceAddress,
                        sourcePort,
                        destinationAddress,
                        destinationPort,
                        payload), cancellationToken)
                    .ConfigureAwait(false);
                await SendControlAsync(NatMessageType.Data, null, payload, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException
            or OperationCanceledException)
        {
            _logger.LogDebug(ex, "external channel {ChannelId} closed", ChannelId);
        }
        finally
        {
            await DisposeAsync().ConfigureAwait(false);
            await TrySendFinAsync(CancellationToken.None).ConfigureAwait(false);
        }
    }

    public async Task WriteFromClientAsync(byte[] data, CancellationToken cancellationToken)
    {
        if (data.Length == 0)
        {
            return;
        }

        var trackedBytes = _writeBackpressure.AddPending(data.Length);
        try
        {
            await _stream.WriteAsync(data, cancellationToken).ConfigureAwait(false);
            await _stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            _traffic.RecordTcpUpload(ClientName, Port, data.Length);
            var (sourceAddress, sourcePort) = Endpoint(_socket.LocalEndPoint);
            var (destinationAddress, destinationPort) = Endpoint(_socket.RemoteEndPoint);
            await _inspection.RecordTcpFrameAsync(new TcpFrameCapture(
                    ClientName,
                    Port,
                    ChannelId,
                    TrafficInspectionService.DirectionClientToPublic,
                    sourceAddress,
                    sourcePort,
                    destinationAddress,
                    destinationPort,
                    data), cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException
            or OperationCanceledException)
        {
            _logger.LogDebug(ex, "write to external channel {ChannelId} failed", ChannelId);
            await DisposeAsync().ConfigureAwait(false);
        }
        finally
        {
            _writeBackpressure.ReleasePending(trackedBytes);
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _closed, 1) == 0)
        {
            _sendWindow.Close();
            try { _stream.Dispose(); } catch { /* already gone */ }
            try { _socket.Close(); } catch { /* already gone */ }
        }
        await ValueTask.CompletedTask;
    }

    private async Task TrySendFinAsync(CancellationToken cancellationToken)
    {
        if (_control.Lifetime.IsCancellationRequested)
        {
            return;
        }

        try
        {
            await SendControlAsync(NatMessageType.Fin, null, null, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException
            or OperationCanceledException)
        {
            _logger.LogDebug(ex, "failed to send DISCONNECTED for {ChannelId}", ChannelId);
        }
    }

    private ValueTask SendControlAsync(NatMessageType type, Dictionary<string, object?>? meta,
        byte[]? data, CancellationToken cancellationToken)
    {
        var message = new NatMessagePacket
        {
            NatMessageType = type,
            StreamId = StreamId,
            MetaData = meta,
            Data = data,
        };
        return _control.Writer.WriteAsync(message, cancellationToken);
    }

    public bool AddSendCredit(uint credit) => _sendWindow.Add(credit);

    private static (string? Address, int? Port) Endpoint(EndPoint? endpoint)
    {
        if (endpoint is IPEndPoint ip)
        {
            return (ip.Address.ToString(), ip.Port);
        }
        return (endpoint?.ToString(), null);
    }
}
