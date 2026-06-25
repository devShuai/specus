using ShuaiTunnel.Protocol.Codec;
using ShuaiTunnel.Protocol.Packets;

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
    private long _pendingBytes;
    private bool _backpressured;

    public event Action<bool>? WritabilityChanged;
    public event Action? PacketWritten;

    public FrameWriter(Stream stream)
    {
        _stream = stream;
    }

    public bool IsBackpressured => Volatile.Read(ref _backpressured);

    public async ValueTask WriteAsync(Packet packet, CancellationToken cancellationToken)
    {
        var bytes = PacketCodec.Encode(packet);
        Interlocked.Add(ref _pendingBytes, bytes.Length);
        UpdateBackpressure();
        try
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
        finally
        {
            Interlocked.Add(ref _pendingBytes, -bytes.Length);
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
        _writeLock.Dispose();
        await _stream.DisposeAsync().ConfigureAwait(false);
    }
}
