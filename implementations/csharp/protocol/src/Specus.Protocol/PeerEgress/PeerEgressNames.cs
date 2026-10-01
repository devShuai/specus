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
    /// <summary>No trailing dots, lower case.</summary>
    /// <remarks>
    /// Every trailing dot goes, as in the reference and the other clients: a name written with two
    /// would otherwise be a different name here and the same name there.
    /// </remarks>
    public static string Normalize(string? name) => (name ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();

    /// <summary>
    /// Whether a name is one to resolve: ASCII labels of 1-63 bytes from a-z, 0-9 and '-', not
    /// starting or ending with '-', at least two labels, at most 253 bytes, and not all digits (which
    /// would be an address). IDN must arrive as punycode.
    /// </summary>
    public static bool Valid(string? name) => ValidNormalized(Normalize(name));

    /// <summary>
    /// Whether a rule's match is a well-formed domain: <c>name</c> or <c>*.name</c>, where the
    /// name is one <see cref="Valid"/> accepts and the wildcard is the whole leftmost label, once.
    /// </summary>
    /// <remarks>
    /// Anything outside ASCII is refused before the name is lower-cased. IDN must be written as
    /// punycode, and lower-casing first would let a character such as the Kelvin sign fold into an
    /// ASCII letter and pass as a name the operator never wrote.
    /// </remarks>
    public static bool ValidMatch(string? match)
    {
        var raw = match ?? string.Empty;
        foreach (var c in raw)
        {
            if (c > 127)
            {
                return false;
            }
        }
        var text = Normalize(raw);
        if (text.StartsWith("*.", StringComparison.Ordinal))
        {
            text = text[2..];
        }
        return !text.Contains('*', StringComparison.Ordinal) && ValidNormalized(text);
    }

    private static bool ValidNormalized(string text)
    {
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
