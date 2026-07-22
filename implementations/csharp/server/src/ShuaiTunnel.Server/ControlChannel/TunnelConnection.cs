using System.IO.Pipelines;
using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using ShuaiTunnel.Protocol.Codec;
using ShuaiTunnel.Protocol.Packets;
using ShuaiTunnel.Server.Configuration;
using ShuaiTunnel.Server.Data.Entities;
using ShuaiTunnel.Server.Networking;

namespace ShuaiTunnel.Server.ControlChannel;

/// <summary>
/// One control connection. Owns a background read loop and serializes writes through a
/// per-connection <see cref="SemaphoreSlim"/>. The lifecycle:
/// <list type="number">
/// <item>Listener accepts → constructs <see cref="TunnelConnection"/> and immediately
/// awaits <see cref="RunAsync"/>.</item>
/// <item>Read loop pulls packets via <see cref="FrameReader"/> and dispatches through
/// <see cref="IControlChannelDispatcher"/>. An idle watchdog runs in parallel and stamps
/// <c>IDLE_TIMEOUT</c> after 60s with no read or sends a heartbeat after 30s of write quiet.
/// Reads honor <see cref="TunnelConnectionContext.ReadGate"/> — when the downstream sink is
/// over capacity, the loop suspends <c>ReadAsync</c> calls until something Resumes.</item>
/// <item>Any error or peer FIN drains the loop → calls <see cref="IControlChannelDispatcher.OnConnectionClosed"/>
/// once → disposes the socket.</item>
/// </list>
///
/// <para>This class deliberately does NOT speak login policy or session bookkeeping — that's
/// the dispatcher's job (<see cref="ControlChannelDispatcher"/> in <c>Services/</c>).</para>
/// </summary>
internal sealed class TunnelConnection : IFrameWriter, IAsyncDisposable
{
    /// <summary>Match Java <c>SocketIdleStateHandler</c>: 60s read-idle, 30s write-idle.</summary>
    private static readonly TimeSpan ReaderIdle = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan WriterIdle = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan IdleTickInterval = TimeSpan.FromSeconds(1);

    private readonly Socket _socket;
    private readonly Stream _stream;
    private readonly PipeReader _reader;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly Channel<QueuedFrame> _priorityWrites = Channel.CreateBounded<QueuedFrame>(
        new BoundedChannelOptions(256) { FullMode = BoundedChannelFullMode.Wait, SingleReader = true });
    private readonly Task _priorityWriterTask;
    private readonly CancellationTokenSource _lifetimeCts;
    private readonly ILogger _logger;
    private readonly int _maxFrameSize;
    private readonly IControlChannelDispatcher _dispatcher;

    private long _lastReadTicks;
    private long _lastWriteTicks;

    public TunnelConnectionContext Context { get; }

    public TunnelConnection(Socket socket, Stream stream, IControlChannelDispatcher dispatcher,
        ILogger logger, NettyServerOptions options, CancellationToken hostStopping)
    {
        _socket = socket;
        _stream = stream;
        _reader = PipeReader.Create(_stream);
        _dispatcher = dispatcher;
        _logger = logger;
        _maxFrameSize = options.MaxFrameSize;
        _lifetimeCts = CancellationTokenSource.CreateLinkedTokenSource(hostStopping);

        var channelId = Guid.NewGuid().ToString("N");
        var remote = socket.RemoteEndPoint?.ToString();

        var readGate = new ReadGate(_lifetimeCts.Token);
        var writeBackpressure = new WriteBackpressureGate(
            options.WriteBufferLowWaterMark, options.WriteBufferHighWaterMark);
        Context = new TunnelConnectionContext(channelId, remote, this, _lifetimeCts.Token,
            closeCallback: CloseTransport,
            readGate: readGate,
            writeBackpressure: writeBackpressure);

        _priorityWriterTask = Task.Run(PriorityWriterLoopAsync);

        var now = Environment.TickCount64;
        _lastReadTicks = now;
        _lastWriteTicks = now;
    }

    public async Task RunAsync()
    {
        // Idle watchdog runs in parallel; the read loop only owns its own cancellation.
        var idleTask = Task.Run(IdleWatchdogLoopAsync);
        try
        {
            await _dispatcher.OnConnectionOpenedAsync(Context).ConfigureAwait(false);

            while (!_lifetimeCts.IsCancellationRequested)
            {
                try
                {
                    await Context.ReadGate.WaitIfPausedAsync(_lifetimeCts.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (_lifetimeCts.IsCancellationRequested)
                {
                    break;
                }

                Packet? packet;
                try
                {
                    var preAuth = Context.ClientName is null;
                    var frameLimit = preAuth ? PacketCodec.PreAuthMaxFrameSize : _maxFrameSize;
                    packet = await FrameReader.ReadFrameAsync(_reader, frameLimit, _lifetimeCts.Token)
                        .ConfigureAwait(false);
                    if (Context.ClientName is null && packet is not null && packet is not LoginRequestPacket)
                    {
                        throw new InvalidDataException("only LOGIN_REQUEST is allowed before authentication");
                    }
                }
                catch (OperationCanceledException) when (_lifetimeCts.IsCancellationRequested)
                {
                    break;
                }
                catch (InvalidDataException ex)
                {
                    Context.MarkDisconnectIfAbsent(DisconnectReason.ProtocolViolation);
                    _logger.LogWarning("[{ChannelId}] protocol violation: {Reason}", Context.ChannelId, ex.Message);
                    break;
                }
                catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
                {
                    Context.MarkDisconnectIfAbsent(DisconnectReason.IoError);
                    _logger.LogDebug(ex, "[{ChannelId}] connection IO error", Context.ChannelId);
                    break;
                }

                if (packet is null)
                {
                    // Clean peer FIN — ChannelInactive handler may stamp CLIENT_CLOSED.
                    break;
                }

                Volatile.Write(ref _lastReadTicks, Environment.TickCount64);

                try
                {
                    await _dispatcher.DispatchAsync(Context, packet).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    Context.MarkDisconnectIfAbsent(DisconnectReason.IoError);
                    _logger.LogError(ex, "[{ChannelId}] unhandled error in dispatcher", Context.ChannelId);
                    break;
                }
            }
        }
        finally
        {
            _lifetimeCts.Cancel();
            try { await idleTask.ConfigureAwait(false); } catch { /* swallow — already going down */ }
            try
            {
                await _dispatcher.OnConnectionClosedAsync(Context).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[{ChannelId}] dispatcher onClose threw", Context.ChannelId);
            }
            await _reader.CompleteAsync().ConfigureAwait(false);
            await DisposeAsync().ConfigureAwait(false);
        }
    }

    private async Task IdleWatchdogLoopAsync()
    {
        while (!_lifetimeCts.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(IdleTickInterval, _lifetimeCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            var now = Environment.TickCount64;
            var sinceRead = TimeSpan.FromMilliseconds(now - Volatile.Read(ref _lastReadTicks));
            var sinceWrite = TimeSpan.FromMilliseconds(now - Volatile.Read(ref _lastWriteTicks));

            if (sinceRead >= ReaderIdle)
            {
                Context.MarkDisconnectIfAbsent(DisconnectReason.IdleTimeout);
                _logger.LogInformation("[{ChannelId}] read-idle for {Sec}s, closing",
                    Context.ChannelId, (int)sinceRead.TotalSeconds);
                _lifetimeCts.Cancel();
                return;
            }

            if (sinceWrite >= WriterIdle)
            {
                try
                {
                    // Java's SocketIdleStateHandler sends a HeartBeatResponsePacket — yes, response,
                    // not request. It's just keep-alive bytes; the client doesn't decode it as
                    // anything that triggers an ack.
                    await WriteAsync(new HeartbeatResponsePacket(), _lifetimeCts.Token)
                        .ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException
                    or OperationCanceledException)
                {
                    Context.MarkDisconnectIfAbsent(DisconnectReason.HeartbeatWriteFailed);
                    _logger.LogDebug(ex, "[{ChannelId}] heartbeat send failed", Context.ChannelId);
                    _lifetimeCts.Cancel();
                    return;
                }
            }
        }
    }

    public async ValueTask WriteAsync(Packet packet, CancellationToken cancellationToken = default)
    {
        var bytes = PacketCodec.Encode(packet);
        var trackedBytes = Context.WriteBackpressure.AddPending(bytes.Length);
        try
        {
            await WriteEncodedAsync(bytes, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            Context.WriteBackpressure.ReleasePending(trackedBytes);
        }
    }

    public async ValueTask WritePriorityAsync(Packet packet, CancellationToken cancellationToken = default)
    {
        var bytes = PacketCodec.Encode(packet);
        var trackedBytes = Context.WriteBackpressure.AddPending(bytes.Length);
        try
        {
            await _priorityWrites.Writer.WriteAsync(new QueuedFrame(bytes, trackedBytes), cancellationToken)
                .ConfigureAwait(false);
        }
        catch
        {
            Context.WriteBackpressure.ReleasePending(trackedBytes);
            throw;
        }
    }

    private async Task WriteEncodedAsync(byte[] bytes, CancellationToken cancellationToken)
    {
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await _stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
            await _stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            Volatile.Write(ref _lastWriteTicks, Environment.TickCount64);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private async Task PriorityWriterLoopAsync()
    {
        try
        {
            await foreach (var queued in _priorityWrites.Reader.ReadAllAsync(_lifetimeCts.Token)
                               .ConfigureAwait(false))
            {
                try
                {
                    await WriteEncodedAsync(queued.Bytes, _lifetimeCts.Token).ConfigureAwait(false);
                }
                finally
                {
                    Context.WriteBackpressure.ReleasePending(queued.TrackedBytes);
                }
            }
        }
        catch (OperationCanceledException) when (_lifetimeCts.IsCancellationRequested)
        {
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
        {
            Context.MarkDisconnectIfAbsent(DisconnectReason.IoError);
            _logger.LogDebug(ex, "[{ChannelId}] priority write failed", Context.ChannelId);
            CloseTransport();
        }
        finally
        {
            while (_priorityWrites.Reader.TryRead(out var queued))
            {
                Context.WriteBackpressure.ReleasePending(queued.TrackedBytes);
            }
        }
    }

    private void CloseTransport()
    {
        _lifetimeCts.Cancel();
        try { _socket.Dispose(); } catch { }
    }

    public async ValueTask DisposeAsync()
    {
        _priorityWrites.Writer.TryComplete();
        CloseTransport();
        try { await _priorityWriterTask.ConfigureAwait(false); } catch { }
        _writeLock.Dispose();
        try { _stream.Dispose(); } catch { /* swallow — already gone */ }
        try { _socket.Close(); } catch { /* same */ }
        _lifetimeCts.Dispose();
    }

    private readonly record struct QueuedFrame(byte[] Bytes, long TrackedBytes);
}

/// <summary>
/// Surface the control-channel listener calls into. One implementation per process; gets
/// invoked on the read loop's task. Implementations must be thread-safe per-connection (they
/// can be called from multiple connection tasks at the same time).
/// </summary>
public interface IControlChannelDispatcher
{
    Task OnConnectionOpenedAsync(TunnelConnectionContext context);
    Task DispatchAsync(TunnelConnectionContext context, Packet packet);
    Task OnConnectionClosedAsync(TunnelConnectionContext context);
}
