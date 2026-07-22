using ShuaiTunnel.Protocol.Codec;
using ShuaiTunnel.Protocol.Packets;
using System.Threading.Channels;

namespace ShuaiTunnel.Client.Control;

/// <summary>
/// Serializes outbound packets onto a single <see cref="Stream"/>. A <c>SemaphoreSlim</c>
/// ensures one writer at a time, mirroring Netty's per-channel write ordering. A coarse
/// pending-byte counter drives <see cref="IsBackpressured"/> so NAT local readers can pause
/// when the control channel is saturated (high water 64 KiB, low water 32 KiB, matching the
/// Java client's <c>WriteBufferWaterMark(32k, 64k)</c>).
/// </summary>
internal sealed class FrameWriter : IAsyncDisposable
{
    public const int HighWaterMark = 64 * 1024;
    public const int LowWaterMark = 32 * 1024;

    private readonly Stream _stream;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly CancellationTokenSource _lifetime = new();
    private readonly Channel<QueuedFrame> _priorityWrites = Channel.CreateBounded<QueuedFrame>(
        new BoundedChannelOptions(256) { FullMode = BoundedChannelFullMode.Wait, SingleReader = true });
    private readonly Task _priorityWriterTask;
    private long _pendingBytes;
    private bool _backpressured;

    public event Action<bool>? WritabilityChanged;
    public event Action? PacketWritten;

    public FrameWriter(Stream stream)
    {
        _stream = stream;
        _priorityWriterTask = Task.Run(PriorityWriterLoopAsync);
    }

    public bool IsBackpressured => Volatile.Read(ref _backpressured);

    public async ValueTask WriteAsync(Packet packet, CancellationToken cancellationToken)
    {
        var bytes = PacketCodec.Encode(packet);
        Interlocked.Add(ref _pendingBytes, bytes.Length);
        UpdateBackpressure();
        try
        {
            await WriteEncodedAsync(bytes, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            Interlocked.Add(ref _pendingBytes, -bytes.Length);
            UpdateBackpressure();
        }
    }

    public async ValueTask WritePriorityAsync(Packet packet, CancellationToken cancellationToken)
    {
        var bytes = PacketCodec.Encode(packet);
        Interlocked.Add(ref _pendingBytes, bytes.Length);
        UpdateBackpressure();
        try
        {
            await _priorityWrites.Writer.WriteAsync(new QueuedFrame(bytes), cancellationToken)
                .ConfigureAwait(false);
        }
        catch
        {
            Interlocked.Add(ref _pendingBytes, -bytes.Length);
            UpdateBackpressure();
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
            PacketWritten?.Invoke();
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
            await foreach (var queued in _priorityWrites.Reader.ReadAllAsync(_lifetime.Token)
                               .ConfigureAwait(false))
            {
                try
                {
                    await WriteEncodedAsync(queued.Bytes, _lifetime.Token).ConfigureAwait(false);
                }
                finally
                {
                    Interlocked.Add(ref _pendingBytes, -queued.Bytes.Length);
                    UpdateBackpressure();
                }
            }
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
        {
        }
        finally
        {
            while (_priorityWrites.Reader.TryRead(out var queued))
            {
                Interlocked.Add(ref _pendingBytes, -queued.Bytes.Length);
            }
            UpdateBackpressure();
        }
    }

    private void UpdateBackpressure()
    {
        var pending = Interlocked.Read(ref _pendingBytes);
        if (_backpressured && pending <= LowWaterMark)
        {
            _backpressured = false;
            WritabilityChanged?.Invoke(true);
        }
        else if (!_backpressured && pending >= HighWaterMark)
        {
            _backpressured = true;
            WritabilityChanged?.Invoke(false);
        }
    }

    public async ValueTask DisposeAsync()
    {
        _priorityWrites.Writer.TryComplete();
        _lifetime.Cancel();
        try { await _priorityWriterTask.ConfigureAwait(false); } catch { }
        _writeLock.Dispose();
        _lifetime.Dispose();
        await _stream.DisposeAsync().ConfigureAwait(false);
    }

    private readonly record struct QueuedFrame(byte[] Bytes);
}
