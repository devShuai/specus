namespace Specus.Client.PeerMesh;

/// <summary>
/// Refusal accounting for the egress side.
/// </summary>
/// <remarks>
/// Two jobs that must not be conflated. The <c>egress-report</c> carries a count per error code and
/// nothing else: no destination, no domain, no payload. A report that named destinations would hand
/// the server a browsing history it has no reason to hold, so the aggregate is the only thing that
/// leaves this node.
///
/// <para>Local diagnostic logging may name the destination, because it stays on the operator's own
/// machine. It is rate limited by subject and reason, so a consumer retrying a refused flow in a
/// loop cannot bury the one refusal an operator needs to see.</para>
///
/// <para>Time arrives as an argument, so the windows are deterministic under test. Not safe for
/// concurrent use; the data plane serialises access through its own loop.</para>
/// </remarks>
internal sealed class PeerEgressRejectionLog
{
    /// <summary>
    /// Bounds diagnostic lines for one subject and reason. Twenty a minute is enough to show a
    /// pattern; the count in the suppression note carries the volume.
    /// </summary>
    public const long WindowMs = 60_000L;

    public const int PerWindow = 20;

    /// <summary>
    /// The process-wide hard cap the spec requires on the audit cache. Without it a peer that
    /// varies its identity turns a rate limiter into a memory leak, which is a worse outcome than
    /// the flooding the limiter exists to prevent.
    /// </summary>
    public const int MaxSubjects = 4096;

    /// <summary>
    /// Whether to write a diagnostic line, and how many refusals it stands for beyond itself.
    /// </summary>
    internal readonly record struct Decision(bool ShouldLog, long Suppressed)
    {
        public static Decision Silent { get; } = new(false, 0);
    }

    private readonly record struct Key(long Consumer, string Code);

    private sealed class Bucket(long startedAtMs)
    {
        public long StartedAtMs { get; set; } = startedAtMs;
        public int Logged { get; set; }

        /// <summary>
        /// Refusals dropped since the last line that was emitted, so that line can say how much it
        /// stands for instead of leaving the gap unexplained.
        /// </summary>
        public long Suppressed { get; set; }
    }

    private Dictionary<string, long> _counts = [];

    /// <summary>The same tally for the status surface, which nothing resets.</summary>
    /// <remarks>
    /// Separate from <c>_counts</c> on purpose. That one belongs to the periodic report and is
    /// drained so consecutive reports describe consecutive intervals; a status reading it would
    /// answer "since whenever the last report went out", which is not a question anybody asked and
    /// changes meaning the day the report is wired up. Two counters cost a dictionary.
    /// </remarks>
    private readonly Dictionary<string, long> _cumulative = [];
    private readonly Dictionary<Key, Bucket> _recent = [];

    /// <summary>How many refusals the current interval has seen, across every code.</summary>
    public long Total { get; private set; }

    /// <summary>Whether the subject cap dropped a diagnostic line during this interval.</summary>
    public bool Limited { get; private set; }

    /// <summary>How many subject-and-reason pairs the rate limiter is currently tracking.</summary>
    public int SubjectCount => _recent.Count;

    /// <summary>
    /// Registers one refusal.
    /// </summary>
    /// <remarks>
    /// The aggregate is incremented unconditionally: rate limiting governs what an operator reads,
    /// never what the report counts. A report that undercounted because logging was busy would be
    /// worse than no report, since it would look like the refusals stopped.
    /// </remarks>
    public Decision Record(long consumer, string code, long nowMs)
    {
        _counts[code] = _counts.GetValueOrDefault(code) + 1;
        _cumulative[code] = _cumulative.GetValueOrDefault(code) + 1;
        Total++;

        var key = new Key(consumer, code);
        if (!_recent.TryGetValue(key, out var bucket))
        {
            if (_recent.Count >= MaxSubjects)
            {
                Sweep(nowMs);
            }
            if (_recent.Count >= MaxSubjects)
            {
                // At the cap with every window still live. The refusal stays in the aggregate, so
                // nothing is lost from the report; only the diagnostic line is dropped.
                Limited = true;
                return Decision.Silent;
            }
            bucket = new Bucket(nowMs);
            _recent[key] = bucket;
        }

        if (nowMs - bucket.StartedAtMs >= WindowMs)
        {
            bucket.StartedAtMs = nowMs;
            bucket.Logged = 0;
        }
        if (bucket.Logged >= PerWindow)
        {
            bucket.Suppressed++;
            return Decision.Silent;
        }
        bucket.Logged++;
        var suppressed = bucket.Suppressed;
        bucket.Suppressed = 0;
        return new Decision(true, suppressed);
    }

    /// <summary>
    /// Drops windows that have already elapsed. Called only when the cap is reached, because until
    /// then an expired window costs one map entry and reusing it costs nothing.
    /// </summary>
    private void Sweep(long nowMs)
    {
        var elapsed = new List<Key>();
        foreach (var (key, bucket) in _recent)
        {
            if (nowMs - bucket.StartedAtMs >= WindowMs)
            {
                elapsed.Add(key);
            }
        }
        foreach (var key in elapsed)
        {
            _recent.Remove(key);
        }
    }

    /// <summary>
    /// Returns the per-code totals for one <c>egress-report</c> and resets them, so consecutive
    /// reports describe consecutive intervals rather than a running sum the server has to
    /// difference.
    /// </summary>
    /// <summary>The per-code totals since this runtime started. A copy; this log goes on counting.</summary>
    public IReadOnlyDictionary<string, long> CumulativeCounts() =>
        new Dictionary<string, long>(_cumulative);

    /// <summary>Drains the report's tally. The cumulative one above is deliberately left alone.</summary>
    public IReadOnlyDictionary<string, long> DrainCounts()
    {
        if (_counts.Count == 0)
        {
            return new Dictionary<string, long>();
        }
        var drained = _counts;
        _counts = [];
        Total = 0;
        Limited = false;
        return drained;
    }
}
