using Specus.Protocol;
using Specus.Protocol.Packets;
using Specus.Server.ControlChannel;

namespace Specus.IntegrationTests;

public sealed class PeerObservedWriterTests
{
    [Fact]
    public async Task BackgroundPauseDoesNotDelayTheObservedProducerAndResumesExactlyOnce()
    {
        var inner = new CountingWriter();
        var observer = new PeerCatalogDeliveryAuthorityTests.ObservingWriter(inner);
        using var pause = observer.PauseBackgroundWrites();
        var background = observer.WriteAsync(new MessageResponsePacket()).AsTask();
        Assert.False(background.IsCompleted); Assert.Equal(0, inner.Writes);
        observer.OwnCall.Value = true;
        await observer.WriteAsync(new MessageResponsePacket());
        observer.OwnCall.Value = false;
        Assert.True(observer.Entered.Task.IsCompletedSuccessfully); Assert.Equal(1, inner.Writes);
        pause.Dispose(); pause.Dispose();
        await background.WaitAsync(TimeSpan.FromSeconds(10)); Assert.Equal(2, inner.Writes);
    }

    [Fact]
    public async Task PausedBackgroundDoesNotPrepareUntilItReachesTheRealWriter()
    {
        var inner = new CountingWriter();
        var observer = new PeerCatalogDeliveryAuthorityTests.ObservingWriter(inner);
        using var pause = observer.PauseBackgroundWrites();
        var prepared = 0;
        var pending = observer.WritePreparedAsync(_ =>
        {
            Interlocked.Increment(ref prepared);
            return ValueTask.FromResult<Packet?>(new MessageResponsePacket());
        }).AsTask();
        Assert.False(pending.IsCompleted); Assert.Equal(0, prepared); Assert.Equal(0, inner.Writes);
        pause.Dispose();
        Assert.True(await pending.WaitAsync(TimeSpan.FromSeconds(10)));
        Assert.Equal(1, prepared); Assert.Equal(1, inner.Writes);
    }

    [Fact]
    public async Task CancelledBackgroundNeverPreparesOrWritesAfterResume()
    {
        var inner = new CountingWriter();
        var observer = new PeerCatalogDeliveryAuthorityTests.ObservingWriter(inner);
        using var pause = observer.PauseBackgroundWrites();
        using var cancellation = new CancellationTokenSource();
        var prepared = 0;
        var pending = observer.WritePreparedAsync(_ =>
        {
            Interlocked.Increment(ref prepared);
            return ValueTask.FromResult<Packet?>(new MessageResponsePacket());
        }, cancellation.Token).AsTask();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
        pause.Dispose(); Assert.Equal(0, prepared); Assert.Equal(0, inner.Writes);
    }

    private sealed class CountingWriter : IFrameWriter
    {
        internal int Writes;
        public ValueTask WriteAsync(Packet packet, CancellationToken cancellationToken = default)
        { cancellationToken.ThrowIfCancellationRequested(); Interlocked.Increment(ref Writes); return ValueTask.CompletedTask; }
    }
}
