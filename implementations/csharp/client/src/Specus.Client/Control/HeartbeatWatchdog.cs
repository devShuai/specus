using Microsoft.Extensions.Logging;
using Specus.Protocol.Packets;

namespace Specus.Client.Control;

/// <summary>
/// Drives 60s reader-idle (close connection) and 5s writer-idle (send HeartbeatRequest)
/// timers, matching the Java client's <c>ClientSocketIdleStateHandler</c>. A 1s tick
/// granularity is precise enough to honor the watermarks without dedicating a per-event timer.
/// </summary>
internal sealed class HeartbeatWatchdog : IAsyncDisposable
{
    private static readonly TimeSpan ReaderIdle = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan WriterIdle = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan Tick = TimeSpan.FromSeconds(1);

    private readonly FrameWriter _writer;
    private readonly ILogger _logger;
    private readonly Action<string> _closeOnIdle;
    private readonly CancellationTokenSource _cts = new();

    private long _lastReadTicks;
    private long _lastWriteTicks;
    private Task? _loop;

    public HeartbeatWatchdog(FrameWriter writer, ILogger logger, Action<string> closeOnIdle)
    {
        _writer = writer;
        _logger = logger;
        _closeOnIdle = closeOnIdle;
        var now = Environment.TickCount64;
        _lastReadTicks = now;
        _lastWriteTicks = now;
        _writer.PacketWritten += MarkWrite;
    }

    public void Start(CancellationToken linkedToken)
    {
        var combined = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token, linkedToken);
        _loop = Task.Run(() => RunAsync(combined.Token), combined.Token);
    }

    public void MarkRead() => Volatile.Write(ref _lastReadTicks, Environment.TickCount64);

    public void MarkWrite() => Volatile.Write(ref _lastWriteTicks, Environment.TickCount64);

    private async Task RunAsync(CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                await Task.Delay(Tick, cancellationToken).ConfigureAwait(false);
                var now = Environment.TickCount64;
                if (now - Volatile.Read(ref _lastReadTicks) >= ReaderIdle.TotalMilliseconds)
                {
                    _logger.LogWarning("60秒内未读到数据, 关闭连接");
                    _closeOnIdle("IDLE_TIMEOUT");
                    return;
                }
                if (now - Volatile.Read(ref _lastWriteTicks) >= WriterIdle.TotalMilliseconds)
                {
                    try
                    {
                        await _writer.WriteAsync(new HeartbeatRequestPacket(), cancellationToken)
                            .ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "HEARTBEAT_WRITE_FAILED");
                        _closeOnIdle("HEARTBEAT_WRITE_FAILED");
                        return;
                    }
                }
            }
        }
        catch (OperationCanceledException)
        {
            // expected on shutdown
        }
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        _writer.PacketWritten -= MarkWrite;
        if (_loop is not null)
        {
            try
            {
                await _loop.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
        }
        _cts.Dispose();
    }
}
