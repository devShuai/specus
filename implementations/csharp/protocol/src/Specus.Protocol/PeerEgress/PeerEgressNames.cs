namespace Specus.Protocol.PeerEgress;

/// <summary>
/// Names in phase two of peer egress: how a query name, a rule match and a bound name are compared,
/// and which names are well formed.
/// </summary>
/// <remarks>
/// See protocol/spec/peer-egress-dns.md; the same rules as the Go and Java clients, checked against
/// protocol/test-vectors/peer-egress-dns-v1.json.
/// </remarks>
public static class PeerEgressNames
{
    /// <summary>No trailing dot, lower case.</summary>
    public static string Normalize(string? name)
    {
        var text = (name ?? string.Empty).Trim();
        if (text.EndsWith('.'))
        {
            text = text[..^1];
        }
        return text.ToLowerInvariant();
    }

    /// <summary>
    /// Whether a name is one to resolve: ASCII labels of 1-63 bytes from a-z, 0-9 and '-', not
    /// starting or ending with '-', at least two labels, at most 253 bytes, and not all digits (which
    /// would be an address). IDN must arrive as punycode.
    /// </summary>
    public static bool Valid(string? name)
    {
        var text = Normalize(name);
        if (text.Length == 0 || text.Length > 253)
        {
            return false;
        }
        var labels = text.Split('.');
        if (labels.Length < 2)
        {
            return false;
        }
        var numeric = true;
        foreach (var label in labels)
        {
            if (label.Length is 0 or > 63 || label[0] == '-' || label[^1] == '-')
            {
                return false;
            }
            foreach (var c in label)
            {
                if (c is >= 'a' and <= 'z' or '-')
                {
                    numeric = false;
                }
                else if (c is < '0' or > '9')
                {
                    return false;
                }
            }
        }
        return !numeric;
    }
}
