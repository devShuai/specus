using Specus.Client.PeerMesh;

namespace Specus.Client.Tests;

/// <summary>
/// The lab's lossy-download stall, replayed without randomness.
/// </summary>
/// <remarks>
/// A 512 KiB download through an egress was caught with the consumer holding everything after one
/// hole, the egress's 64 KiB send buffer full and its upstream read paused, and nothing resent for
/// seconds. The timer was firing; the timeout it fired on had grown with every recovery, because the
/// ACK that filled each hole was also taken as a round-trip sample for the segments sent beside the
/// lost one. This replays a short run of losses and holds the egress to resending promptly.
/// </remarks>
public class PeerEgressLossReplayTests
{
    private const uint ConsumerIp = 0x64600002;
    private const uint TargetIp = 0xCB00710A;
    private const int PlaneTickMs = 100;

    private sealed record Replay(bool Intact, long DurationMs, long LongestSilenceMs);

    private sealed record Packet(bool ToEgress, byte[] Bytes);

    private static byte[] AckFor(uint next) => PeerEgressSegment.Build(new PeerEgressSegment.Segment(
        ConsumerIp, TargetIp, 40000, 80, 1001, next, PeerEgressSegment.FlagAck, 65535, 0, []));

    /// <summary>
    /// One 512 KiB response through the egress with the chosen segments lost once on their way to
    /// the consumer and nothing else random: the upstream hands over everything the send buffer has
    /// room for and then its end of stream, the consumer acknowledges only in-order data (a
    /// duplicate ACK for anything after a hole), the link takes 1 ms each way, and time advances on
    /// the plane's 100 ms tick.
    /// </summary>
    private static Replay ReplayScriptedLoss(params int[] lostSegments)
    {
        const int responseBytes = 524_445; // the lab's 512 KiB body and its headers
        long now = 0;
        var first = new PeerEgressTcpConnection.Output();
        var egress = PeerEgressTcpConnection.Accept(new PeerEgressSegment.Segment(
            ConsumerIp, TargetIp, 40000, 80, 1000, 0, PeerEgressSegment.FlagSyn, 65535, 1240, []),
            7777, 1272, 60_000, now, first);
        var dataStart = PeerEgressSegment.Parse(first.Segments[0])!.Seq + 1;
        egress.OnSegment(PeerEgressSegment.Parse(AckFor(dataStart))!, now);

        var response = new byte[responseBytes];
        new Random(responseBytes).NextBytes(response);
        var toLose = new HashSet<int>(lostSegments);
        var link = new PriorityQueue<Packet, (long At, long Order)>();
        long order = 0;
        var read = 0;
        var endOfStream = false;
        var finished = false;
        var rcvNxt = dataStart;
        uint? finAt = null;
        var held = new Dictionary<uint, byte[]>();
        using var received = new MemoryStream();
        long lastHeard = 0;
        long longestSilence = 0;
        long nextTick = PlaneTickMs;
        var pending = new List<byte[]>();
        while (now < 120_000 && !finished)
        {
            foreach (var packet in pending)
            {
                var segment = PeerEgressSegment.Parse(packet)!;
                var index = (int)(segment.Seq - dataStart) / egress.SendMss;
                if (segment.Payload.Length > 0 && toLose.Remove(index))
                {
                    continue;
                }
                link.Enqueue(new Packet(false, packet), (now + 1, order++));
            }
            pending.Clear();
            var credit = egress.AppReadCredit();
            if (credit > 0 && read < responseBytes)
            {
                var n = Math.Min(credit, Math.Min(32 * 1024, responseBytes - read));
                pending.AddRange(egress.OnAppData(response[read..(read + n)], now).Segments);
                read += n;
                continue;
            }
            if (read == responseBytes && !endOfStream)
            {
                endOfStream = true;
                pending.AddRange(egress.OnAppClose(now).Segments);
                continue;
            }
            if (!link.TryPeek(out _, out var head) || head.At > nextTick)
            {
                now = nextTick;
                nextTick += PlaneTickMs;
                pending.AddRange(egress.OnTick(now).Segments);
                if (egress.IsDone)
                {
                    break;
                }
                continue;
            }
            var next = link.Dequeue();
            now = head.At;
            var arrived = PeerEgressSegment.Parse(next.Bytes)!;
            if (next.ToEgress)
            {
                pending.AddRange(egress.OnSegment(arrived, now).Segments);
                continue;
            }
            longestSilence = Math.Max(longestSilence, now - lastHeard);
            lastHeard = now;
            if (arrived.Payload.Length > 0
                && PeerEgressSegment.SeqLess(rcvNxt, arrived.Seq + (uint)arrived.Payload.Length))
            {
                held[arrived.Seq] = arrived.Payload;
            }
            if (arrived.Has(PeerEgressSegment.FlagFin))
            {
                finAt = arrived.Seq + (uint)arrived.Payload.Length;
            }
            for (var progress = true; progress;)
            {
                progress = false;
                foreach (var (start, payload) in held.ToList())
                {
                    var end = start + (uint)payload.Length;
                    if (PeerEgressSegment.SeqLessEqual(end, rcvNxt))
                    {
                        held.Remove(start);
                    }
                    else if (PeerEgressSegment.SeqLessEqual(start, rcvNxt))
                    {
                        received.Write(payload, (int)(rcvNxt - start), (int)(end - rcvNxt));
                        rcvNxt = end;
                        held.Remove(start);
                        progress = true;
                    }
                }
            }
            if (finAt == rcvNxt)
            {
                rcvNxt++;
                finished = true;
            }
            link.Enqueue(new Packet(true, AckFor(rcvNxt)), (now + 1, order++));
        }
        return new Replay(finished && received.ToArray().AsSpan().SequenceEqual(response), now, longestSilence);
    }

    /// <summary>
    /// Six segments lost a few apart, about 1.4% of the response, mid-stream and at the tail (there
    /// with the upstream already at end of stream and the last, partial segment among the lost).
    /// Sampling the recoveries' ACKs left the consumer without a segment for 11.6 s and 9.6 s and
    /// stretched the response to 21.3 s and 17.7 s; now the longest silence is about 0.3 s and each
    /// takes under 2 s.
    /// </summary>
    [Fact]
    public void ARunOfLossesDoesNotStretchTheRetransmissionTimeout()
    {
        var slow = new List<string>();
        foreach (var lost in new[] { new[] { 100, 106, 112, 118, 124, 130 }, new[] { 395, 401, 407, 413, 419, 425 } })
        {
            var replay = ReplayScriptedLoss(lost);
            // The lab's gate allows 10 s for the whole response; a hole should be resent within a
            // tick or two of the 200 ms floor, not after a second of silence.
            if (!replay.Intact || replay.LongestSilenceMs > 1_000 || replay.DurationMs > 10_000)
            {
                slow.Add($"losing segments [{string.Join(", ", lost)}]: {replay}");
            }
        }
        Assert.True(slow.Count == 0, string.Join("\n", slow));
    }
}
