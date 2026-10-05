using System.Text.Json;
using Specus.Protocol.PeerEgress;

namespace Specus.Protocol.Tests;

/// <summary>
/// Replays <c>peer-egress-rate-v1.json</c> against the .NET new-flow token bucket.
/// </summary>
/// <remarks>
/// Every event asks for its flows one at a time at its instant, as a burst of SYNs that all passed
/// every other check would. Runtimes that disagreed by a single token at a boundary would refuse a
/// flow the others open.
/// </remarks>
public class PeerEgressRateVectorTests
{
    private static JsonDocument ReadVector()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(
                directory.FullName, "protocol", "test-vectors", "peer-egress-rate-v1.json");
            if (File.Exists(candidate))
            {
                return JsonDocument.Parse(File.ReadAllText(candidate));
            }
            directory = directory.Parent;
        }
        throw new FileNotFoundException("cannot locate peer-egress-rate-v1.json");
    }

    [Fact]
    public void ConstantsMatchSharedVector()
    {
        using var vector = ReadVector();
        var root = vector.RootElement;
        Assert.Equal(PeerEgressFlowRate.Capacity, root.GetProperty("capacity").GetInt32());
        Assert.Equal(PeerEgressFlowRate.RefillPerSecond, root.GetProperty("refillPerSecond").GetInt32());
        Assert.Equal(PeerEgressCodes.LimitExceeded, root.GetProperty("refusalCode").GetString());
    }

    [Fact]
    public void AdmissionsMatchSharedVector()
    {
        using var vector = ReadVector();
        var events = vector.RootElement.GetProperty("events");
        Assert.True(events.GetArrayLength() > 0, "rate vector carried no events");

        var rate = new PeerEgressFlowRate();
        var step = 0;
        foreach (var item in events.EnumerateArray())
        {
            var atMs = item.GetProperty("atMs").GetInt64();
            var consumer = item.GetProperty("consumer").GetInt64();
            var flows = item.GetProperty("flows").GetInt32();
            var admitted = 0;
            for (var flow = 0; flow < flows; flow++)
            {
                if (rate.TryTake(consumer, atMs))
                {
                    admitted++;
                }
            }
            var label = $"event {step} (atMs={atMs} consumer={consumer})";
            Assert.True(item.GetProperty("admitted").GetInt32() == admitted, $"{label}: admitted {admitted}");
            Assert.True(item.GetProperty("refused").GetInt32() == flows - admitted, $"{label}: refused {flows - admitted}");
            step++;
        }
    }

    /// <summary>
    /// Forgetting a bucket once it is full again is what keeps the map bounded, and must change no
    /// outcome: a consumer forgotten and one remembered with a full bucket admit the same burst.
    /// </summary>
    [Fact]
    public void ForgetsFullBucketsWithoutChangingOutcomes()
    {
        var rate = new PeerEgressFlowRate();
        for (var consumer = 1L; consumer <= 100; consumer++)
        {
            Assert.True(rate.TryTake(consumer, 0), $"consumer {consumer} refused its first flow");
        }
        Assert.Equal(100, rate.Tracked);

        // Each token came back 16 ms later. Two seconds on, every bucket is full and forgotten, and
        // consumer 1 draws a whole burst from a fresh one.
        var admitted = 0;
        for (var flow = 0; flow < PeerEgressFlowRate.Capacity + 1; flow++)
        {
            if (rate.TryTake(1, 2_000))
            {
                admitted++;
            }
        }
        Assert.Equal(PeerEgressFlowRate.Capacity, admitted);
        Assert.Equal(1, rate.Tracked);
    }
}
