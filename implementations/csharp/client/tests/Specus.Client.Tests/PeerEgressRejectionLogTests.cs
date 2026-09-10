using Specus.Client.PeerMesh;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.Tests;

/// <summary>
/// Refusal accounting.
/// </summary>
/// <remarks>
/// No shared vector here. What leaves the node is an aggregate per error code, which the report
/// schema already pins; the rest is local rate limiting, where two runtimes disagreeing changes how
/// much an operator reads on their own machine and produces no interop failure.
/// </remarks>
public class PeerEgressRejectionLogTests
{
    private const long Epoch = 1_800_000_000_000L;

    /// <summary>
    /// Rate limiting governs what an operator reads. It must never govern what the report counts,
    /// or a busy period would look like the refusals had stopped.
    /// </summary>
    [Fact]
    public void CountsEveryRefusalRegardlessOfLimiting()
    {
        var log = new PeerEgressRejectionLog();
        var emitted = 0;
        for (var attempt = 0; attempt < PeerEgressRejectionLog.PerWindow * 3; attempt++)
        {
            if (log.Record(7, PeerEgressCodes.DestinationDenied, Epoch).ShouldLog)
            {
                emitted++;
            }
        }
        Assert.Equal(PeerEgressRejectionLog.PerWindow, emitted);

        var counts = log.DrainCounts();
        Assert.True(counts[PeerEgressCodes.DestinationDenied] == PeerEgressRejectionLog.PerWindow * 3,
            "the aggregate must count every refusal");
    }

    /// <summary>
    /// The spec limits by subject and reason together. One consumer hammering one rule must not
    /// silence a different rule, or a different consumer.
    /// </summary>
    [Fact]
    public void LimitsPerSubjectAndReason()
    {
        var log = new PeerEgressRejectionLog();
        for (var attempt = 0; attempt < PeerEgressRejectionLog.PerWindow; attempt++)
        {
            log.Record(7, PeerEgressCodes.DestinationDenied, Epoch);
        }
        Assert.False(log.Record(7, PeerEgressCodes.DestinationDenied, Epoch).ShouldLog,
            "the exhausted subject and reason still emitted");
        Assert.True(log.Record(7, PeerEgressCodes.PortDenied, Epoch).ShouldLog,
            "a different reason was silenced by an exhausted one");
        Assert.True(log.Record(9, PeerEgressCodes.DestinationDenied, Epoch).ShouldLog,
            "a different consumer was silenced by another consumer's traffic");
    }

    /// <summary>
    /// A gap in the log with no explanation reads as the problem having gone away, so the next line
    /// that does get written says how many it stands for.
    /// </summary>
    [Fact]
    public void ReportsWhatItSuppressed()
    {
        var log = new PeerEgressRejectionLog();
        for (var attempt = 0; attempt < PeerEgressRejectionLog.PerWindow; attempt++)
        {
            Assert.True(log.Record(7, PeerEgressCodes.DestinationDenied, Epoch).Suppressed == 0,
                "reported a suppression before anything was dropped");
        }
        for (var attempt = 0; attempt < 5; attempt++)
        {
            log.Record(7, PeerEgressCodes.DestinationDenied, Epoch);
        }

        var rolled = log.Record(
            7, PeerEgressCodes.DestinationDenied, Epoch + PeerEgressRejectionLog.WindowMs);
        Assert.True(rolled.ShouldLog, "the window did not roll over");
        Assert.Equal(5, rolled.Suppressed);

        // The count belongs to the line that carried it, so the line after starts clean.
        var next = log.Record(7, PeerEgressCodes.DestinationDenied, Epoch + PeerEgressRejectionLog.WindowMs);
        Assert.True(next.Suppressed == 0, "the suppression count was reported twice");
    }

    /// <summary>
    /// A peer that varies its identity would otherwise turn the limiter into a memory leak, which
    /// is a worse outcome than the flooding the limiter exists to prevent.
    /// </summary>
    [Fact]
    public void BoundsItsSubjectTable()
    {
        var log = new PeerEgressRejectionLog();
        const long attempts = PeerEgressRejectionLog.MaxSubjects + 500L;
        for (long consumer = 0; consumer < attempts; consumer++)
        {
            log.Record(consumer, PeerEgressCodes.ConsumerDenied, Epoch);
        }
        Assert.True(log.SubjectCount <= PeerEgressRejectionLog.MaxSubjects,
            $"subject table held {log.SubjectCount} entries");
        Assert.True(log.Limited, "hitting the cap was not recorded");

        // Reaching the cap costs diagnostic lines, never accuracy.
        Assert.True(log.DrainCounts()[PeerEgressCodes.ConsumerDenied] == attempts,
            "the aggregate must count every refusal even at the cap");
    }

    /// <summary>
    /// Once the windows behind those entries elapse, the cap must stop biting rather than leaving
    /// the limiter permanently full.
    /// </summary>
    [Fact]
    public void RecoversAfterTheWindowElapses()
    {
        var log = new PeerEgressRejectionLog();
        for (long consumer = 0; consumer < PeerEgressRejectionLog.MaxSubjects; consumer++)
        {
            log.Record(consumer, PeerEgressCodes.ConsumerDenied, Epoch);
        }
        var later = Epoch + PeerEgressRejectionLog.WindowMs + 1000;
        Assert.True(log.Record(999_999, PeerEgressCodes.ConsumerDenied, later).ShouldLog,
            "a new subject was refused a line after every stale window had elapsed");
    }

    /// <summary>
    /// Consecutive reports have to describe consecutive intervals. A running total would leave the
    /// server differencing values it was never told were cumulative.
    /// </summary>
    [Fact]
    public void DrainResetsTheInterval()
    {
        var log = new PeerEgressRejectionLog();
        log.Record(7, PeerEgressCodes.DestinationDenied, Epoch);
        log.Record(7, PeerEgressCodes.PortDenied, Epoch);

        var first = log.DrainCounts();
        Assert.Equal(1, first[PeerEgressCodes.DestinationDenied]);
        Assert.Equal(1, first[PeerEgressCodes.PortDenied]);
        Assert.Empty(log.DrainCounts());

        log.Record(7, PeerEgressCodes.DestinationDenied, Epoch);
        var third = log.DrainCounts();
        Assert.True(third.Count == 1, "the third interval carried more than its own refusal");
        Assert.Equal(1, third[PeerEgressCodes.DestinationDenied]);
    }
}
