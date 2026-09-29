using Microsoft.Extensions.Logging;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.PeerMesh;

/// <summary>
/// The fake-IP pool of phase two: which address each name was handed out as, and which addresses
/// are resting before they may stand for another name.
/// </summary>
/// <remarks>
/// protocol/spec/peer-egress-dns.md, section four; shared vector <c>peer-egress-dns-v1.json</c>,
/// section <c>pool</c>.
///
/// <para>A mapping lives by use, not by DNS TTL. Answers carry a one-second TTL, and an application
/// caches them as long as it likes; a mapping recycled when the TTL ran out would send that
/// application's next connection to an address with no name behind it. So a mapping used in the
/// last six hours is never taken, and one is taken only when the pool has nothing else to give.
/// An address that was taken rests for thirty minutes before it stands for another name, so a
/// connection still open to the old name does not arrive at the new one.</para>
///
/// <para>Two callers: the consumer steering a packet sent into the pool, and (from step four) the
/// DNS responder answering a query. They run on different threads, so the pool has its own lock
/// and calls nothing outside itself while holding it. Time comes from the injected clock unless the
/// caller passes it, which the consumer does so the pool and its flow table read the same moment.</para>
/// </remarks>
internal sealed class PeerEgressFakeIpPool
{
    /// <summary>A mapping used this recently is never taken for another name.</summary>
    internal const long MinLifetimeMs = 6 * 3600 * 1000L;

    /// <summary>How long a taken address rests before it may stand for another name.</summary>
    internal const long QuarantineMs = 30 * 60 * 1000L;

    /// <summary>What a query got: an address, or nothing because the pool is exhausted.</summary>
    /// <param name="Evicted">The names taken to make room, in address order.</param>
    internal readonly record struct Answer(uint Address, bool Exhausted, IReadOnlyList<string> Evicted);

    private sealed class Mapping(uint address, long lastUsedMs)
    {
        public uint Address { get; } = address;

        public long LastUsedMs { get; set; } = lastUsedMs;
    }

    private readonly object _gate = new();
    private readonly Func<long> _clock;
    private readonly ILogger? _logger;
    // Kept wide so the arithmetic cannot wrap at either end of the address space.
    private readonly long _first;
    private readonly long _last;
    private long _cursor;
    private readonly Dictionary<string, Mapping> _byName = new(StringComparer.Ordinal);
    private readonly Dictionary<uint, string> _byAddress = [];

    // An address resting after it was taken, and until when. The queue holds the same entries in
    // the order they were added, which is the order they end in while the clock runs forward, so
    // releasing what has ended looks only at the front.
    private readonly Dictionary<uint, long> _quarantine = [];
    private readonly Queue<(uint Address, long UntilMs)> _quarantineOrder = new();
    private bool _exhaustedLogged;

    /// <summary>
    /// A pool over a prefix. Any prefix is taken here, including the narrow ones the shared vector
    /// uses; which prefixes a configuration may name is <see cref="PeerEgressRules.FakeIpPoolProblem"/>.
    /// </summary>
    public PeerEgressFakeIpPool(Ipv4Cidr cidr, Func<long>? clock = null, ILogger? logger = null)
    {
        Cidr = cidr;
        _clock = clock ?? (() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        _logger = logger;
        var broadcast = cidr.Network | (cidr.PrefixLength == 0 ? uint.MaxValue : ~(uint.MaxValue << (32 - cidr.PrefixLength)));
        // The network address, the responder's address right after it, and the broadcast address are
        // never handed out.
        Listen = unchecked(cidr.Network + 1);
        _first = (long)cidr.Network + 2;
        _last = (long)broadcast - 1;
        _cursor = _first;
    }

    public Ipv4Cidr Cidr { get; }

    /// <summary>The responder's address: the pool's first usable address, never handed out.</summary>
    public uint Listen { get; }

    /// <summary>How many addresses can be handed out at all; none in a /31 or /32.</summary>
    private long Span => _last >= _first ? _last - _first + 1 : 0;

    public bool Contains(uint address) => Cidr.Contains(address);

    /// <summary>The address for a query name, now by the pool's clock.</summary>
    public Answer Query(string name) => Query(name, _clock());

    /// <summary>
    /// The address for a query name: the one it already has, refreshed, or a new one. When the pool
    /// is full every mapping idle for six hours is taken, and the query tries again; when that
    /// still finds nothing it is exhausted and no existing mapping is touched.
    /// </summary>
    public Answer Query(string name, long nowMs)
    {
        var normalized = PeerEgressNames.Normalize(name);
        lock (_gate)
        {
            if (_byName.TryGetValue(normalized, out var existing))
            {
                existing.LastUsedMs = nowMs;
                return new Answer(existing.Address, false, []);
            }
            var address = Scan(nowMs);
            var evicted = new List<string>();
            if (address is null)
            {
                foreach (var (other, mapping) in _byName.OrderBy(entry => entry.Value.Address))
                {
                    if (nowMs - mapping.LastUsedMs >= MinLifetimeMs)
                    {
                        evicted.Add(other);
                    }
                }
                foreach (var other in evicted)
                {
                    var mapping = _byName[other];
                    _byName.Remove(other);
                    _byAddress.Remove(mapping.Address);
                    var until = nowMs + QuarantineMs;
                    _quarantine[mapping.Address] = until;
                    _quarantineOrder.Enqueue((mapping.Address, until));
                    // The address and how long it sat unused, not the name: a name in the log is a
                    // line of the user's browsing history.
                    _logger?.LogInformation(
                        "[peer-egress-consumer] fake-IP mapping {Address} recycled after {Minutes} min unused",
                        Ipv4Cidr.FormatAddress(mapping.Address), (nowMs - mapping.LastUsedMs) / 60_000);
                }
                address = Scan(nowMs);
            }
            if (address is not { } allocated)
            {
                if (!_exhaustedLogged)
                {
                    // Once per stretch of exhaustion rather than per query: an application retrying
                    // would otherwise write this line as fast as it asks.
                    _exhaustedLogged = true;
                    _logger?.LogWarning(
                        "[peer-egress-consumer] fake-IP pool exhausted: {Mappings} mappings in use, {Quarantined} resting",
                        _byName.Count, _quarantine.Count);
                }
                return new Answer(0, true, evicted);
            }
            _exhaustedLogged = false;
            _byName[normalized] = new Mapping(allocated, nowMs);
            _byAddress[allocated] = normalized;
            return new Answer(allocated, false, evicted);
        }
    }

    /// <summary>
    /// The name an address stands for, refreshing its mapping, or null when it stands for none. For
    /// traffic sent to the address: using a mapping keeps it as surely as asking for it again.
    /// </summary>
    public string? Use(uint address, long nowMs)
    {
        lock (_gate)
        {
            if (!_byAddress.TryGetValue(address, out var name))
            {
                return null;
            }
            _byName[name].LastUsedMs = nowMs;
            return name;
        }
    }

    /// <summary>
    /// The name an address stands for without refreshing it. For looking again at a flow after a
    /// rule change, which is not traffic, and for the reverse lookup a responder answers.
    /// </summary>
    public string? NameFor(uint address)
    {
        lock (_gate)
        {
            return _byAddress.GetValueOrDefault(address);
        }
    }

    /// <summary>The mappings held now.</summary>
    public int Mappings
    {
        get
        {
            lock (_gate)
            {
                return _byName.Count;
            }
        }
    }

    /// <summary>The addresses still resting at a given moment.</summary>
    public int Quarantined(long nowMs)
    {
        lock (_gate)
        {
            var resting = 0;
            foreach (var until in _quarantine.Values)
            {
                if (nowMs < until)
                {
                    resting++;
                }
            }
            return resting;
        }
    }

    /// <summary>The addresses still resting now, by the pool's clock.</summary>
    public int QuarantinedNow() => Quarantined(_clock());

    /// <summary>
    /// The first free address from the cursor on, in address order and round again, moving the
    /// cursor past it; null when there is none. Called with the lock held.
    /// </summary>
    private uint? Scan(long nowMs)
    {
        var span = Span;
        if (span == 0)
        {
            return null;
        }
        ReleaseRested(nowMs);
        if (_byAddress.Count + _quarantine.Count >= span)
        {
            // Nothing free unless a rest ended out of order, which only a clock stepping back leaves
            // behind the front of the queue. Looked for in full here, where it is cheap to be sure,
            // rather than by walking every address of a full pool.
            foreach (var (address, until) in _quarantine.ToList())
            {
                if (nowMs >= until)
                {
                    _quarantine.Remove(address);
                }
            }
            if (_byAddress.Count + _quarantine.Count >= span)
            {
                return null;
            }
        }
        for (long step = 0; step < span; step++)
        {
            var candidate = (uint)(_first + (_cursor - _first + step) % span);
            if (_byAddress.ContainsKey(candidate))
            {
                continue;
            }
            if (_quarantine.TryGetValue(candidate, out var until))
            {
                if (nowMs < until)
                {
                    continue;
                }
                _quarantine.Remove(candidate);
            }
            _cursor = _first + (candidate - _first + 1) % span;
            return candidate;
        }
        return null;
    }

    /// <summary>Ends the rests that are over, from the front of the queue.</summary>
    private void ReleaseRested(long nowMs)
    {
        while (_quarantineOrder.TryPeek(out var head) && nowMs >= head.UntilMs)
        {
            _quarantineOrder.Dequeue();
            // The address may have been freed already and rest again since; only the entry this
            // queue item describes is ended.
            if (_quarantine.TryGetValue(head.Address, out var until) && until == head.UntilMs)
            {
                _quarantine.Remove(head.Address);
            }
        }
    }
}
