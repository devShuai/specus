using ShuaiTunnel.Server.Networking;

namespace ShuaiTunnel.IntegrationTests;

public sealed class BackpressureGateTests
{
    [Fact]
    public async Task ReadGate_DoesNotMissResumeThatHappensBeforeWait()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(1));
        var gate = new ReadGate(cts.Token);

        gate.Pause();
        Assert.True(gate.Resume());

        await gate.WaitIfPausedAsync(cts.Token);
        Assert.False(gate.IsPaused);
    }

    [Fact]
    public async Task ReadGate_BlocksUntilResume()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        var gate = new ReadGate(cts.Token);

        gate.Pause();
        var wait = gate.WaitIfPausedAsync(cts.Token).AsTask();
        Assert.False(wait.IsCompleted);

        Assert.True(gate.Resume());
        await wait;
    }

    [Fact]
    public void WriteBackpressureGate_FiresAtHighAndLowWaterMarks()
    {
        var gate = new WriteBackpressureGate(lowWaterMark: 10, highWaterMark: 20);
        var transitions = new List<bool>();
        gate.BackpressureChanged += transitions.Add;

        gate.AddPending(15);
        Assert.Empty(transitions);
        gate.AddPending(5);
        Assert.Equal(new[] { true }, transitions);
        Assert.True(gate.IsBackpressured);

        gate.ReleasePending(9);
        Assert.Equal(new[] { true }, transitions);
        gate.ReleasePending(1);
        Assert.Equal(new[] { true, false }, transitions);
        Assert.False(gate.IsBackpressured);
    }
}
