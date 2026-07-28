using Specus.Protocol.Flow;

namespace Specus.Protocol.Tests;

public sealed class StreamSendWindowTests
{
    [Fact]
    public async Task AddIgnoresValidCreditThatArrivesAfterClose()
    {
        var window = new StreamSendWindow();
        Assert.True(await window.ConsumeAsync(1024, CancellationToken.None));

        window.Close();

        Assert.True(window.Add(1024));
    }

    [Fact]
    public void AddStillRejectsInvalidCreditOnActiveWindow()
    {
        var window = new StreamSendWindow();

        Assert.False(window.Add(1));
        Assert.False(window.Add(0));
        Assert.False(window.Add((uint)StreamSendWindow.MaximumBytes + 1));
    }
}
