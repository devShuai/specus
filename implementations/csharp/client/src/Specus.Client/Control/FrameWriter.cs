using Specus.Protocol;
using Specus.Protocol.Codec;
using Specus.Protocol.Packets;
using System.Threading.Channels;

namespace Specus.Client.Control;

/// <summary>
/// Serializes outbound packets onto a single <see cref="Stream"/>. NAT DATA/FIN frames use a
/// connection-local round-robin queue so one busy stream cannot monopolize the data channel;
/// control frames still take the direct/priority paths. A coarse pending-byte counter drives
/// <see cref="IsBackpressured"/> so NAT local readers can pause when the control channel is
/// saturated (high water 64 KiB, low water 32 KiB, matching the Java client).
/// </summary>
internal sealed class FrameWriter : IAsyncDisposable
{
    public const int HighWaterMark = 64 * 1024;
    public const int LowWaterMark = 32 * 1024;
    public const int MaximumPendingBytesPerStream = 4 * 1024 * 1024;

    private readonly Stream _stream;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly CancellationTokenSource _lifetime = new();
    private readonly SemaphoreSlim _streamWriteSignal = new(0);
    private readonly StreamRoundRobinQueue<QueuedStreamFrame> _streamWrites = new(
        MaximumPendingBytesPerStream, static frame => frame.Bytes.Length);
    private readonly Channel<QueuedFrame> _priorityWrites = Channel.CreateBounded<QueuedFrame>(
        new BoundedChannelOptions(256) { FullMode = BoundedChannelFullMode.Wait, SingleReader = true });
    private readonly Task _priorityWriterTask;
    private readonly Task _streamWriterTask;
    private long _pendingBytes;
    private bool _backpressured;

    public event Action<bool>? WritabilityChanged;
    public event Action? PacketWritten;

    public FrameWriter(Stream stream)
    {
        _stream = stream;
        _priorityWriterTask = Task.Run(PriorityWriterLoopAsync);
        _streamWriterTask = Task.Run(StreamWriterLoopAsync);
    }

    public bool IsBackpressured => Volatile.Read(ref _backpressured);

    public ValueTask WriteAsync(Packet packet, CancellationToken cancellationToken)
    {
        var bytes = PacketCodec.Encode(packet);
        if (packet is NatMessagePacket
            {
                NatMessageType: NatMessageType.Data or NatMessageType.Fin,
                StreamId: not 0,
            } streamPacket)
        {
            return QueueStreamWriteAsync(streamPacket.StreamId, bytes, cancellationToken);
        }
        return WriteDirectAsync(bytes, cancellationToken);
    }

    private async ValueTask WriteDirectAsync(byte[] bytes, CancellationToken cancellationToken)
    {
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

    private ValueTask QueueStreamWriteAsync(
        uint streamId, byte[] bytes, CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return ValueTask.FromCanceled(cancellationToken);
        }
        var queued = new QueuedStreamFrame(bytes, cancellationToken);
        queued.RegisterCancellation();
        Interlocked.Add(ref _pendingBytes, bytes.Length);
        UpdateBackpressure();
        var result = _streamWrites.TryEnqueue(streamId, queued);
        if (result != StreamQueueEnqueueResult.Enqueued)
        {
            queued.DisposeRegistration();
            Interlocked.Add(ref _pendingBytes, -bytes.Length);
            UpdateBackpressure();
            return result == StreamQueueEnqueueResult.Completed
                ? ValueTask.FromException(new ObjectDisposedException(nameof(FrameWriter)))
                : ValueTask.FromException(new InvalidOperationException(
                    $"stream {streamId} send queue exceeded {MaximumPendingBytesPerStream} bytes"));
        }
        _streamWriteSignal.Release();
        return new ValueTask(queued.Completion.Task);
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

    private async Task StreamWriterLoopAsync()
    {
        try
        {
            while (true)
            {
                await _streamWriteSignal.WaitAsync(_lifetime.Token).ConfigureAwait(false);
                if (!_streamWrites.TryDequeue(out var queued) || queued is null)
                {
                    continue;
                }
                try
                {
                    if (queued.CancellationToken.IsCancellationRequested)
                    {
                        queued.Completion.TrySetCanceled(queued.CancellationToken);
                        continue;
                    }
                    using var writeCts = CancellationTokenSource.CreateLinkedTokenSource(
                        queued.CancellationToken, _lifetime.Token);
                    await WriteEncodedAsync(queued.Bytes, writeCts.Token).ConfigureAwait(false);
                    queued.Completion.TrySetResult();
                }
                catch (OperationCanceledException) when (queued.CancellationToken.IsCancellationRequested)
                {
                    queued.Completion.TrySetCanceled(queued.CancellationToken);
                }
                catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
                {
                    queued.Completion.TrySetException(
                        new ObjectDisposedException(nameof(FrameWriter)));
                    break;
                }
                catch (Exception error)
                {
                    queued.Completion.TrySetException(error);
                }
                finally
                {
                    queued.DisposeRegistration();
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
            foreach (var queued in _streamWrites.CompleteAndDrain())
            {
                queued.Completion.TrySetException(new ObjectDisposedException(nameof(FrameWriter)));
                queued.DisposeRegistration();
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
        _streamWrites.Complete();
        _priorityWrites.Writer.TryComplete();
        _lifetime.Cancel();
        try { await _priorityWriterTask.ConfigureAwait(false); } catch { }
        try { await _streamWriterTask.ConfigureAwait(false); } catch { }
        _writeLock.Dispose();
        _streamWriteSignal.Dispose();
        _lifetime.Dispose();
        await _stream.DisposeAsync().ConfigureAwait(false);
    }

    private readonly record struct QueuedFrame(byte[] Bytes);

    private sealed class QueuedStreamFrame(byte[] bytes, CancellationToken cancellationToken)
    {
        private CancellationTokenRegistration _registration;

        public byte[] Bytes { get; } = bytes;
        public CancellationToken CancellationToken { get; } = cancellationToken;
        public TaskCompletionSource Completion { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public void RegisterCancellation()
        {
            if (!CancellationToken.CanBeCanceled)
            {
                return;
            }
            _registration = CancellationToken.Register(static state =>
            {
                var frame = (QueuedStreamFrame)state!;
                frame.Completion.TrySetCanceled(frame.CancellationToken);
            }, this);
        }

        public void DisposeRegistration() => _registration.Dispose();
    }
}

internal enum StreamQueueEnqueueResult
{
    Enqueued,
    CapacityExceeded,
    Completed,
}

/// <summary>
/// A bounded queue that rotates stream IDs after every item. The implementation is deliberately
/// independent from the transport worker so fairness and capacity can be tested deterministically.
/// </summary>
internal sealed class StreamRoundRobinQueue<T>(int maximumBytesPerStream, Func<T, int> sizeOf)
{
    private readonly object _gate = new();
    private readonly Dictionary<uint, StreamState> _streams = new();
    private readonly Queue<uint> _readyStreams = new();
    private bool _completed;

    public StreamQueueEnqueueResult TryEnqueue(uint streamId, T item)
    {
        var size = sizeOf(item);
        if (size < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(item), "queued item size cannot be negative");
        }
        lock (_gate)
        {
            if (_completed)
            {
                return StreamQueueEnqueueResult.Completed;
            }
            if (!_streams.TryGetValue(streamId, out var state))
            {
                state = new StreamState();
                _streams.Add(streamId, state);
                _readyStreams.Enqueue(streamId);
            }
            if (state.PendingBytes > maximumBytesPerStream - size)
            {
                if (state.Items.Count == 0)
                {
                    _streams.Remove(streamId);
                }
                return StreamQueueEnqueueResult.CapacityExceeded;
            }
            state.Items.Enqueue(item);
            state.PendingBytes += size;
            return StreamQueueEnqueueResult.Enqueued;
        }
    }

    public bool TryDequeue(out T? item)
    {
        lock (_gate)
        {
            while (_readyStreams.TryDequeue(out var streamId))
            {
                if (!_streams.TryGetValue(streamId, out var state) || state.Items.Count == 0)
                {
                    _streams.Remove(streamId);
                    continue;
                }
                item = state.Items.Dequeue();
                state.PendingBytes -= sizeOf(item);
                if (state.Items.Count == 0)
                {
                    _streams.Remove(streamId);
                }
                else
                {
                    _readyStreams.Enqueue(streamId);
                }
                return true;
            }
        }
        item = default;
        return false;
    }

    public void Complete()
    {
        lock (_gate)
        {
            _completed = true;
        }
    }

    public IReadOnlyList<T> CompleteAndDrain()
    {
        var drained = new List<T>();
        lock (_gate)
        {
            _completed = true;
            while (_readyStreams.TryDequeue(out var streamId))
            {
                if (!_streams.TryGetValue(streamId, out var state))
                {
                    continue;
                }
                while (state.Items.TryDequeue(out var queued))
                {
                    drained.Add(queued);
                }
            }
            _streams.Clear();
        }
        return drained;
    }

    private sealed class StreamState
    {
        public Queue<T> Items { get; } = new();
        public int PendingBytes { get; set; }
    }
}
