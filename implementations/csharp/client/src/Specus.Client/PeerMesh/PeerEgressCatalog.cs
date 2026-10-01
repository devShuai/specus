using Specus.Protocol.PeerEgress;

namespace Specus.Client.PeerMesh;

/// <summary>
/// What this consumer has learned from <c>egress-catalog</c>: which egress devices resolve names.
/// </summary>
/// <remarks>
/// The revision works as it does for <c>egress-config</c>: rising within one control session, a
/// snapshot at or below the last accepted one ignored, the floor reset when a new session starts.
/// An accepted catalogue replaces what was known whole, so an egress it no longer lists is one that
/// does not resolve names. A new session resets only the floor; what was learned stays until the
/// next catalogue replaces it, because the reconnect that starts the session says nothing about the
/// egresses. Shared vector: <c>peer-egress-dns-v1.json</c>, section <c>catalog</c>.
///
/// <para>Read from the control connection and from the consumer's own reconcile, so it has its own
/// lock and calls nothing while holding it.</para>
/// </remarks>
internal sealed class PeerEgressCatalog
{
    private readonly object _gate = new();
    private long? _floor;
    private Dictionary<long, bool> _capable = [];

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
            _capable = new Dictionary<long, bool>(message.DomainTargetCapable);
            return true;
        }
    }

    /// <summary>A new control session: the next catalogue is accepted whatever its revision.</summary>
    public void NewSession()
    {
        lock (_gate)
        {
            _floor = null;
        }
    }

    /// <summary>Every egress the last catalogue listed, and whether it resolves names.</summary>
    public IReadOnlyDictionary<long, bool> Capabilities()
    {
        lock (_gate)
        {
            return new Dictionary<long, bool>(_capable);
        }
    }

    /// <summary>The egresses that resolve names, in order.</summary>
    public List<long> CapableIds()
    {
        lock (_gate)
        {
            return [.. _capable.Where(entry => entry.Value).Select(entry => entry.Key).Order()];
        }
    }
}
