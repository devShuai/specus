using Specus.Protocol.PeerEgress;

namespace Specus.Client.PeerMesh;

/// <summary>
/// What the catalogue says about one egress a rule names (protocol/spec/peer-egress.md, 能力不支持;
/// shared vector <c>peer-egress-standing-v1.json</c>), and which flows each standing stops.
/// </summary>
/// <remarks>
/// A rule names its egress by client id, and whether that egress could take a flow used to be read
/// from the mesh roster alone. An online egress running a client without peer egress was sent flows
/// it dropped without a word, and the status had nothing to say about why. The catalogue can say:
/// whether the egress is offered to this device at all, and whether its online session announced
/// peer egress.
/// </remarks>
internal static class PeerEgressStanding
{
    /// <summary>No catalogue accepted in this control session; an older server never sends one.</summary>
    internal const string Unknown = "unknown";

    /// <summary>A catalogue was accepted and does not list the egress.</summary>
    internal const string NotOffered = "not-offered";

    /// <summary>Listed, and its online session announced no peer egress: <c>egressVersion</c> 0.</summary>
    internal const string Unsupported = "unsupported";

    /// <summary>Listed with <c>egressVersion</c> 1 or more, or without the field (an older server).</summary>
    internal const string Offered = "offered";

    /// <summary>The blocked reason, and the status's counter, for a flow to an online not-offered egress.</summary>
    internal const string BlockedNotOffered = "egress-not-offered";

    /// <summary>The blocked reason for a flow to an online egress whose client does not support peer egress.</summary>
    internal const string BlockedUnsupported = "egress-unsupported";

    /// <summary>The standing of one egress.</summary>
    /// <remarks>
    /// Without a catalogue in this session the answer is unknown, and unknown sends: blocking on it
    /// would break every deployment that works today behind a server too old to send one.
    /// </remarks>
    internal static string Of(bool catalogReceived, bool listed, long? egressVersion)
    {
        if (!catalogReceived)
        {
            return Unknown;
        }
        if (!listed)
        {
            return NotOffered;
        }
        return egressVersion is { } version && version < 1 ? Unsupported : Offered;
    }

    /// <summary>
    /// Why a flow to an online egress of this standing is blocked, or null when it goes out. Whether
    /// the egress is online is decided before this and wins: the catalogue cannot speak for a device
    /// that is not there.
    /// </summary>
    internal static string? BlockedReason(string standing) => standing switch
    {
        NotOffered => BlockedNotOffered,
        Unsupported => BlockedUnsupported,
        _ => null,
    };
}

/// <summary>
/// The catalogue as the consumer decides by it: whether one was accepted in this control session,
/// and the egresses the last accepted one listed.
/// </summary>
/// <param name="Received">Whether a catalogue was accepted in this control session.</param>
/// <param name="Listed">
/// The last accepted catalogue's entries. Kept across a new session, as the domain capability always
/// was, but with <paramref name="Received"/> false they no longer decide a standing.
/// </param>
internal sealed record PeerEgressCatalogSnapshot(bool Received, IReadOnlyDictionary<long, PeerEgressCatalogListing> Listed)
{
    /// <summary>Before any catalogue: nothing listed, nothing received.</summary>
    public static PeerEgressCatalogSnapshot None { get; } = new(false, new Dictionary<long, PeerEgressCatalogListing>());

    /// <summary>The standing of one egress.</summary>
    public string StandingOf(long egress) =>
        PeerEgressStanding.Of(Received, Listed.TryGetValue(egress, out var listing), listing.EgressVersion);
}

/// <summary>
/// What this consumer has learned from <c>egress-catalog</c>: which egresses it lists, the
/// <c>egressVersion</c> each announced, which resolve names, and whether one arrived in this control
/// session at all.
/// </summary>
/// <remarks>
/// The revision works as it does for <c>egress-config</c>: rising within one control session, a
/// snapshot at or below the last accepted one ignored, the floor reset when a new session starts.
/// An accepted catalogue replaces what was known whole, so an egress it no longer lists is one that
/// does not resolve names. A new session resets the floor and whether a catalogue arrived; what was
/// learned stays until the next catalogue replaces it, because the reconnect that starts the
/// session says nothing about the egresses. Shared vector: <c>peer-egress-dns-v1.json</c>, section
/// <c>catalog</c>.
///
/// <para>It also keeps when the control session authenticated, because a server that has not sent a
/// catalogue 30 seconds after that is most likely too old to send one, and the status says so.</para>
///
/// <para>Read from the control connection and from the consumer's own reconcile, so it has its own
/// lock and calls nothing while holding it.</para>
/// </remarks>
/// <param name="clock">
/// Milliseconds on the clock the 30 seconds are measured on, or null for the wall clock. Injected so
/// a test can step through the wait without sitting in it.
/// </param>
internal sealed class PeerEgressCatalog(Func<long>? clock = null)
{
    /// <summary>
    /// How long after control authentication the status stops saying <c>waiting</c> and says the
    /// server sent no catalogue (<c>catalogWaitSeconds</c> in the shared vector).
    /// </summary>
    internal const long CatalogWaitMs = 30_000;

    // The values of the status's consumer.catalog.
    internal const string StateWaiting = "waiting";
    internal const string StateNone = "none";
    internal const string StateReceived = "received";

    private readonly Func<long> _clock = clock ?? (() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
    private readonly object _gate = new();
    private long? _floor;
    private Dictionary<long, PeerEgressCatalogListing> _listed = [];
    private bool _received;
    private long? _authenticatedAtMs;

    /// <summary>The last accepted revision, or zero before any.</summary>
    public long Revision
    {
        get
        {
            lock (_gate)
            {
                return _floor ?? 0;
            }
        }
    }

    /// <summary>Reads one push, reporting whether it was accepted and replaced what was known.</summary>
    public bool Read(string? payload)
    {
        var message = PeerEgressCatalogMessage.Decode(payload);
        if (message is null)
        {
            return false;
        }
        lock (_gate)
        {
            if (_floor is { } floor && message.Revision <= floor)
            {
                return false;
            }
            _floor = message.Revision;
            _listed = new Dictionary<long, PeerEgressCatalogListing>(message.Egresses);
            _received = true;
            return true;
        }
    }

    /// <summary>
    /// A new control session: the next catalogue is accepted whatever its revision, none has arrived
    /// in it yet, and the session has not authenticated.
    /// </summary>
    /// <remarks>
    /// Not having a catalogue again is what turns every standing back to unknown. The last session's
    /// catalogue describes a server this client may no longer be talking to; until the new one
    /// speaks, the egresses are judged as an older server would leave them, by being online.
    /// </remarks>
    public void NewSession()
    {
        lock (_gate)
        {
            _floor = null;
            _received = false;
            _authenticatedAtMs = null;
        }
    }

    /// <summary>The control session authenticated now: the wait for its catalogue starts.</summary>
    public void ControlAuthenticated()
    {
        var now = _clock();
        lock (_gate)
        {
            _authenticatedAtMs = now;
        }
    }

    /// <summary>
    /// <c>received</c> once a catalogue was accepted in this session; <c>none</c> when none was
    /// 30 seconds after the session authenticated; <c>waiting</c> until then, and before any session
    /// authenticated.
    /// </summary>
    public string State()
    {
        var now = _clock();
        lock (_gate)
        {
            if (_received)
            {
                return StateReceived;
            }
            return _authenticatedAtMs is { } authenticated && now - authenticated >= CatalogWaitMs
                ? StateNone
                : StateWaiting;
        }
    }

    /// <summary>What the consumer decides by, taken at once so the two halves agree.</summary>
    public PeerEgressCatalogSnapshot Snapshot()
    {
        lock (_gate)
        {
            return new PeerEgressCatalogSnapshot(_received, new Dictionary<long, PeerEgressCatalogListing>(_listed));
        }
    }

    /// <summary>The egresses that resolve names, in order.</summary>
    public List<long> CapableIds()
    {
        lock (_gate)
        {
            return [.. _listed.Where(entry => entry.Value.DomainTargetCapable).Select(entry => entry.Key).Order()];
        }
    }

    /// <summary>Every egress the last catalogue listed, in order.</summary>
    public List<long> ListedIds()
    {
        lock (_gate)
        {
            return [.. _listed.Keys.Order()];
        }
    }

    /// <summary>The usable <c>egressVersion</c> of each listed egress that carried one.</summary>
    public SortedDictionary<long, long> EgressVersions()
    {
        lock (_gate)
        {
            var versions = new SortedDictionary<long, long>();
            foreach (var (egress, listing) in _listed)
            {
                if (listing.EgressVersion is { } version)
                {
                    versions[egress] = version;
                }
            }
            return versions;
        }
    }
}
