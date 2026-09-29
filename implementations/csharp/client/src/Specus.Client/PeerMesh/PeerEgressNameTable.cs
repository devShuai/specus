namespace Specus.Client.PeerMesh;

/// <summary>
/// The names consumers bound to their fake addresses with name-bind, kept by most recent use.
/// </summary>
/// <remarks>
/// Phase two of peer egress on the egress side (protocol/spec/peer-egress-dns.md). A binding is a few
/// bytes and is only read when a flow opens, so the caps bound memory against a consumer that binds
/// without end rather than being reached in use. Not thread-safe; the runtime's lock covers it.
/// </remarks>
internal sealed class PeerEgressNameTable
{
    internal const int Capacity = 65_536;
    internal const int CapacityPerConsumer = 4_096;

    private readonly record struct Key(long Consumer, uint Address);

    private sealed record Entry(Key Key, string Name)
    {
        public string Name { get; set; } = Name;
    }

    // Front is the most recently used.
    private readonly LinkedList<Entry> _order = new();
    private readonly Dictionary<Key, LinkedListNode<Entry>> _entries = [];
    private readonly Dictionary<long, int> _perConsumer = [];

    public int Count => _entries.Count;

    /// <summary>Records or replaces a consumer's name for an address. The name must already be valid.</summary>
    public void Bind(long consumer, uint address, string name)
    {
        var key = new Key(consumer, address);
        if (_entries.TryGetValue(key, out var existing))
        {
            existing.Value.Name = name;
            _order.Remove(existing);
            _order.AddFirst(existing);
            return;
        }
        while (_perConsumer.GetValueOrDefault(consumer) >= CapacityPerConsumer)
        {
            EvictOldest(entry => entry.Key.Consumer == consumer);
        }
        while (_entries.Count >= Capacity)
        {
            EvictOldest(_ => true);
        }
        _entries[key] = _order.AddFirst(new Entry(key, name));
        _perConsumer[consumer] = _perConsumer.GetValueOrDefault(consumer) + 1;
    }

    private void EvictOldest(Func<Entry, bool> selects)
    {
        for (var node = _order.Last; node is not null; node = node.Previous)
        {
            if (selects(node.Value))
            {
                Remove(node);
                return;
            }
        }
    }

    private void Remove(LinkedListNode<Entry> node)
    {
        _order.Remove(node);
        _entries.Remove(node.Value.Key);
        var consumer = node.Value.Key.Consumer;
        var remaining = _perConsumer.GetValueOrDefault(consumer) - 1;
        if (remaining > 0)
        {
            _perConsumer[consumer] = remaining;
        }
        else
        {
            _perConsumer.Remove(consumer);
        }
    }

    /// <summary>The name a consumer bound to an address, refreshing it, or null.</summary>
    public string? Lookup(long consumer, uint address)
    {
        if (!_entries.TryGetValue(new Key(consumer, address), out var node))
        {
            return null;
        }
        _order.Remove(node);
        _order.AddFirst(node);
        return node.Value.Name;
    }

    /// <summary>Forgets every binding of a consumer, for when it is revoked.</summary>
    public void DropConsumer(long consumer)
    {
        for (var node = _order.First; node is not null;)
        {
            var next = node.Next;
            if (node.Value.Key.Consumer == consumer)
            {
                Remove(node);
            }
            node = next;
        }
    }
}
