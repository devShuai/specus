using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using Specus.Client.Control;
using Specus.Protocol;
using Specus.Protocol.Flow;
using Specus.Protocol.Packets;

namespace Specus.Client.Nat;

internal enum LocalSpecusPumpResult
{
    LocalFin,
    Reset,
    Canceled,
}

internal enum LocalSpecusWriteResult
{
    Written,
    DataAfterFin,
    Reset,
}

internal enum LocalSpecusRemoteFinResult
{
    Accepted,
    Completed,
    Invalid,
    Reset,
}

/// <summary>
/// One local TCP connection bridging a server-allocated <c>channelId</c> to a target on the
/// internal network. Each TCP direction closes independently: local EOF sends a tunnel FIN but
/// keeps accepting remote DATA, while a remote FIN only shuts down the socket send direction.
/// The socket is released after both FINs, or immediately on RST/I/O failure.
/// </summary>
internal sealed class LocalSpecusChannel : IAsyncDisposable
{
    private const int ReadBufferSize = 16 * 1024;

    private readonly TcpClient _tcp;
    private readonly NetworkStream _stream;
    private readonly FrameWriter _controlWriter;
    private readonly ILogger _logger;
    private readonly Action<LocalSpecusChannel> _onClosed;
    private readonly CancellationTokenSource _cts = new();
    private readonly StreamSendWindow _sendWindow = new();
    private readonly ManualResetEventSlim _writableGate = new(initialState: true);
    private readonly object _stateLock = new();
    private readonly TaskCompletionSource _pumpStopped = new(TaskCreationOptions.RunContinuationsAsynchronously);

    private bool _localFinished;
    private bool _remoteFinished;
    private int _pumpStarted;
    private int _closed;
    private int _disposed;

    public string ChannelId { get; }
    public uint StreamId { get; }
    public int Port { get; }

    internal bool LocalFinished
    {
        get
        {
            lock (_stateLock)
            {
                return _localFinished;
            }
        }
    }

    internal bool RemoteFinished
    {
        get
        {
            lock (_stateLock)
            {
                return _remoteFinished;
            }
        }
    }

    internal bool IsClosed => Volatile.Read(ref _closed) != 0;

    public LocalSpecusChannel(
        uint streamId,
        string channelId,
        int port,
        TcpClient tcp,
        FrameWriter controlWriter,
        ILogger logger,
        Action<LocalSpecusChannel> onClosed)
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

    /// <summary>Pumps bytes from the local socket until the local direction reaches EOF or fails.</summary>
    public async Task<LocalSpecusPumpResult> PumpAsync(CancellationToken cancellationToken)
    {
        if (Interlocked.Exchange(ref _pumpStarted, 1) != 0)
        {
            throw new InvalidOperationException("local TCP pump already started");
        }

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
                    TryShutdown(SocketShutdown.Receive);
                    var completed = MarkLocalFinished();
                    if (completed)
                    {
                        CloseCore();
                    }
                    return LocalSpecusPumpResult.LocalFin;
                }
                var payload = new byte[read];
                Buffer.BlockCopy(buffer, 0, payload, 0, read);
                if (!await _sendWindow.ConsumeAsync(payload.Length, token).ConfigureAwait(false))
                {
                    return LocalSpecusPumpResult.Canceled;
                }
                var packet = new NatMessagePacket
                {
                    NatMessageType = NatMessageType.Data,
                    StreamId = StreamId,
                    Data = payload,
                };
                await _controlWriter.WriteAsync(packet, token).ConfigureAwait(false);
            }
            return LocalSpecusPumpResult.Canceled;
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            return LocalSpecusPumpResult.Canceled;
        }
        catch (Exception ex)
        {
            if (IsClosed || token.IsCancellationRequested)
            {
                return LocalSpecusPumpResult.Canceled;
            }
            _logger.LogDebug(ex, "channel {channel}: local pump aborted", ChannelId);
            CloseCore();
            return LocalSpecusPumpResult.Reset;
        }
        finally
        {
            _pumpStopped.TrySetResult();
        }
    }

    public async ValueTask<LocalSpecusWriteResult> WriteAsync(
        byte[] data, CancellationToken cancellationToken)
    {
        lock (_stateLock)
        {
            if (_remoteFinished)
            {
                return LocalSpecusWriteResult.DataAfterFin;
            }
            if (IsClosed)
            {
                return LocalSpecusWriteResult.Reset;
            }
        }

        try
        {
            await _stream.WriteAsync(data, cancellationToken).ConfigureAwait(false);
            return LocalSpecusWriteResult.Written;
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
        {
            _logger.LogDebug(ex, "channel {channel}: local write failed", ChannelId);
            CloseCore();
            return LocalSpecusWriteResult.Reset;
        }
    }

    /// <summary>Consumes a remote FIN without terminating the still-open local read direction.</summary>
    public LocalSpecusRemoteFinResult FinishRemoteDirection()
    {
        bool completed;
        lock (_stateLock)
        {
            if (_remoteFinished || IsClosed)
            {
                return LocalSpecusRemoteFinResult.Invalid;
            }
            try
            {
                _tcp.Client.Shutdown(SocketShutdown.Send);
            }
            catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
            {
                _logger.LogDebug(ex, "channel {channel}: local send shutdown failed", ChannelId);
                CloseCore();
                return LocalSpecusRemoteFinResult.Reset;
            }
            _remoteFinished = true;
            completed = _localFinished;
        }

        if (completed)
        {
            CloseCore();
            return LocalSpecusRemoteFinResult.Completed;
        }
        return LocalSpecusRemoteFinResult.Accepted;
    }

    /// <summary>Immediately terminates both directions, as required for RST.</summary>
    public void Reset() => CloseCore();

    public bool AddSendCredit(uint credit) => _sendWindow.Add(credit);

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        CloseCore();
        if (Volatile.Read(ref _pumpStarted) != 0)
        {
            await _pumpStopped.Task.ConfigureAwait(false);
        }
        await _stream.DisposeAsync().ConfigureAwait(false);
        _tcp.Dispose();
        _writableGate.Dispose();
        _cts.Dispose();
    }

    private bool MarkLocalFinished()
    {
        lock (_stateLock)
        {
            _localFinished = true;
            return _remoteFinished;
        }
    }

    private void TryShutdown(SocketShutdown direction)
    {
        try
        {
            _tcp.Client.Shutdown(direction);
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
        {
            _logger.LogTrace(ex, "channel {channel}: socket direction already closed", ChannelId);
        }
    }

    private void CloseCore()
    {
        if (Interlocked.Exchange(ref _closed, 1) != 0)
        {
            return;
        }
        _sendWindow.Close();
        try { _cts.Cancel(); }
        catch (ObjectDisposedException) { }
        try { _tcp.Close(); }
        catch { /* best effort */ }
        _onClosed(this);
    }
}
