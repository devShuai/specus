namespace Specus.Protocol.PeerEgress;

/// <summary>
/// How fast an egress lets one consumer open new flows: a token bucket per consumer, as defined by
/// protocol/spec/peer-egress.md (资源上限) and <c>protocol/test-vectors/peer-egress-rate-v1.json</c>.
/// </summary>
/// <remarks>
/// The concurrency caps bound the flows that exist at once, not how fast a consumer churns through
/// short ones, so a scan made of one-packet flows would pass them at network speed. Tokens are counted
/// in integer thousandths against an integer millisecond clock so every runtime lands on the same side
/// of a boundary.
///
/// <para>The caller asks only for a flow every other check already admitted, so a refused attempt
/// costs nothing, and the caller supplies the time. It has to come from a monotonic clock: a wall
/// clock stepped forward would refill every bucket at once.</para>
/// </remarks>
public sealed class PeerEgressFlowRate
{
    public const int Capacity = 128;
    public const int RefillPerSecond = 64;

    private const long MilliCapacity = Capacity * 1000L;
    private const long MilliPerFlow = 1000L;

    /// <summary>How long an empty bucket takes to fill, so how often a sweep can find anything to forget.</summary>
    private const long FillMs = MilliCapacity / RefillPerSecond;

    private readonly Lock _lock = new();
    private readonly Dictionary<long, (long Milli, long AtMs)> _buckets = [];
    private long _sweptAtMs;

    /// <summary>The consumers whose buckets are remembered; any other consumer's bucket is full.</summary>
    public int Tracked
    {
        get
        {
            lock (_lock)
            {
                return _buckets.Count;
            }
        }
    }

    /// <summary>
    /// Takes one token for a new flow, or reports that the consumer has none left. A consumer seen
    /// for the first time starts with a full bucket.
    /// </summary>
    public bool TryTake(long consumer, long nowMs)
    {
        lock (_lock)
        {
            Sweep(nowMs);
            var milli = _buckets.TryGetValue(consumer, out var bucket) ? Refilled(bucket, nowMs) : MilliCapacity;
            if (milli < MilliPerFlow)
            {
                _buckets[consumer] = (milli, nowMs);
                return false;
            }
            _buckets[consumer] = (milli - MilliPerFlow, nowMs);
            return true;
        }
    }

    private static long Refilled((long Milli, long AtMs) bucket, long nowMs) =>
        Math.Min(MilliCapacity, bucket.Milli + Math.Max(0, nowMs - bucket.AtMs) * RefillPerSecond);

    /// <summary>
    /// Forgets the buckets that have filled again. A full bucket and a forgotten one admit the same
    /// flows, so this changes no outcome; it keeps the map to the consumers active in the last few
    /// seconds rather than every consumer that ever opened a flow.
    /// </summary>
    private void Sweep(long nowMs)
    {
        if (nowMs - _sweptAtMs < FillMs)
        {
            return;
        }
        _sweptAtMs = nowMs;
        List<long>? full = null;
        foreach (var (consumer, bucket) in _buckets)
        {
            if (Refilled(bucket, nowMs) >= MilliCapacity)
            {
                (full ??= []).Add(consumer);
            }
        }
        foreach (var consumer in full ?? [])
        {
            _buckets.Remove(consumer);
        }
    }
}
