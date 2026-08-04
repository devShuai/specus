using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using Specus.Protocol;
using Specus.Protocol.Flow;
using Specus.Protocol.Packets;
using Specus.Server.Configuration;
using Specus.Server.ControlChannel;
using Specus.Server.Management;
using Specus.Server.Networking;

namespace Specus.Server.Nat;

internal enum ExternalWriteResult
{
    Written,
    DataAfterFin,
    Reset,
}

internal enum ExternalFinResult
{
    Accepted,
    Completed,
    Invalid,
    Reset,
}

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
    private readonly object _stateLock = new();
    private readonly TaskCompletionSource _completed = new(TaskCreationOptions.RunContinuationsAsynchronously);

    private bool _publicFinished;
    private bool _clientFinished;
    private int _finSent;
    private int _resetSent;
    private int _closed;
    private int _disposed;

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

    internal bool PublicFinished
    {
        get
        {
            lock (_stateLock)
            {
                return _publicFinished;
            }
        }
    }

    internal bool ClientFinished
    {
        get
        {
            lock (_stateLock)
            {
                return _clientFinished;
            }
        }
    }

    internal bool IsClosed => Volatile.Read(ref _closed) != 0;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken, _control.Lifetime);
        var token = linked.Token;
        try
        {
            await SendControlAsync(NatMessageType.Open, new Dictionary<string, object?>
            {
                ["channelId"] = ChannelId,
                ["port"] = Port,
            }, null, token).ConfigureAwait(false);

            var buffer = new byte[BufferSize];
            while (!token.IsCancellationRequested)
            {
                await _readGate.WaitIfPausedAsync(token).ConfigureAwait(false);

                var read = await _stream.ReadAsync(buffer, token).ConfigureAwait(false);
                if (read == 0)
                {
                    if (!await TrySendFinAsync(CancellationToken.None).ConfigureAwait(false))
                    {
                        return;
                    }
                    if (MarkPublicFinished())
                    {
                        _completed.TrySetResult();
                    }
                    await _completed.Task.WaitAsync(token).ConfigureAwait(false);
                    return;
                }

                var payload = buffer.AsSpan(0, read).ToArray();
                if (!await _sendWindow.ConsumeAsync(payload.Length, token).ConfigureAwait(false))
                {
                    return;
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
                        payload), token)
                    .ConfigureAwait(false);
                await SendControlAsync(NatMessageType.Data, null, payload, token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            // Control/listener shutdown tears down both directions without emitting a terminal frame.
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
        {
            if (!IsClosed)
            {
                _logger.LogDebug(ex, "external channel {ChannelId} failed", ChannelId);
                await SendResetAsync(40, "public TCP read failed", CancellationToken.None)
                    .ConfigureAwait(false);
            }
        }
        finally
        {
            await DisposeAsync().ConfigureAwait(false);
        }
    }

    public async Task<ExternalWriteResult> WriteFromClientAsync(
        byte[] data, CancellationToken cancellationToken)
    {
        lock (_stateLock)
        {
            if (_clientFinished)
            {
                return ExternalWriteResult.DataAfterFin;
            }
            if (IsClosed)
            {
                return ExternalWriteResult.Reset;
            }
        }

        if (data.Length == 0)
        {
            return ExternalWriteResult.Written;
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
            return ExternalWriteResult.Written;
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException
            or OperationCanceledException)
        {
            _logger.LogDebug(ex, "write to external channel {ChannelId} failed", ChannelId);
            AbortCore();
            return ExternalWriteResult.Reset;
        }
        finally
        {
            _writeBackpressure.ReleasePending(trackedBytes);
        }
    }

    /// <summary>Consumes a client FIN by shutting down only the public socket send direction.</summary>
    public ExternalFinResult FinishClientDirection()
    {
        bool completed;
        lock (_stateLock)
        {
            if (_clientFinished || IsClosed)
            {
                return ExternalFinResult.Invalid;
            }
            try
            {
                _socket.Shutdown(SocketShutdown.Send);
            }
            catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
            {
                _logger.LogDebug(ex, "external channel {ChannelId} send shutdown failed", ChannelId);
                AbortCore();
                return ExternalFinResult.Reset;
            }
            _clientFinished = true;
            completed = _publicFinished;
        }

        if (completed)
        {
            _completed.TrySetResult();
            return ExternalFinResult.Completed;
        }
        return ExternalFinResult.Accepted;
    }

    /// <summary>Consumes a client RST and immediately terminates both TCP directions.</summary>
    public void ResetFromClient() => AbortCore();

    public async Task SendResetAsync(uint errorCode, string reason, CancellationToken cancellationToken)
    {
        if (Interlocked.Exchange(ref _resetSent, 1) == 0 && !_control.Lifetime.IsCancellationRequested)
        {
            try
            {
                await SendControlAsync(NatMessageType.Rst,
                    new Dictionary<string, object?> { ["reason"] = reason },
                    null,
                    cancellationToken,
                    errorCode).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException
                or OperationCanceledException)
            {
                _logger.LogDebug(ex, "failed to send RST for {ChannelId}", ChannelId);
            }
        }
        AbortCore();
    }

    public bool AddSendCredit(uint credit) => _sendWindow.Add(credit);

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }
        AbortCore();
        try { await _stream.DisposeAsync().ConfigureAwait(false); }
        catch (ObjectDisposedException) { }
        try { _socket.Dispose(); }
        catch { /* already gone */ }
    }

    private bool MarkPublicFinished()
    {
        lock (_stateLock)
        {
            _publicFinished = true;
            return _clientFinished;
        }
    }

    private async Task<bool> TrySendFinAsync(CancellationToken cancellationToken)
    {
        if (_control.Lifetime.IsCancellationRequested || Interlocked.Exchange(ref _finSent, 1) != 0)
        {
            return false;
        }

        try
        {
            await SendControlAsync(NatMessageType.Fin, null, null, cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException
            or OperationCanceledException)
        {
            _logger.LogDebug(ex, "failed to send FIN for {ChannelId}", ChannelId);
            AbortCore();
            return false;
        }
    }

    private void AbortCore()
    {
        if (Interlocked.Exchange(ref _closed, 1) != 0)
        {
            return;
        }
        _sendWindow.Close();
        _completed.TrySetResult();
        try { _socket.Close(); }
        catch { /* best effort */ }
    }

    private ValueTask SendControlAsync(NatMessageType type, Dictionary<string, object?>? meta,
        byte[]? data, CancellationToken cancellationToken, uint value = 0)
    {
        var message = new NatMessagePacket
        {
            NatMessageType = type,
            StreamId = StreamId,
            Value = value,
            MetaData = meta,
            Data = data,
        };
        return _control.Writer.WriteAsync(message, cancellationToken);
    }

    private static (string? Address, int? Port) Endpoint(EndPoint? endpoint)
    {
        if (endpoint is IPEndPoint ip)
        {
            return (ip.Address.ToString(), ip.Port);
        }
        return (endpoint?.ToString(), null);
    }
}
