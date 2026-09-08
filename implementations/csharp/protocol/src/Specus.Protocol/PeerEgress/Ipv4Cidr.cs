namespace Specus.Protocol.PeerEgress;

/// <summary>
/// An IPv4 prefix.
/// </summary>
/// <remarks>
/// Parsing is strict on purpose: a prefix whose host bits are set is rejected rather than masked,
/// and a leading-zero octet is rejected rather than tolerated. Runtimes disagree about 010 --
/// decimal ten or octal eight -- and an access rule that means different things in different
/// implementations is worse than one the operator has to rewrite.
/// </remarks>
public readonly record struct Ipv4Cidr(uint Network, int PrefixLength)
{
    /// <summary>The widest IPv4 prefix length.</summary>
    public const int MaxPrefix = 32;

    /// <summary>
    /// Reads an IPv4 address or prefix. A bare address becomes a /32.
    /// </summary>
    public static bool TryParse(string? text, out Ipv4Cidr cidr)
    {
        cidr = default;
        var trimmed = text?.Trim() ?? string.Empty;
        if (trimmed.Length == 0)
        {
            return false;
        }
        var slash = trimmed.IndexOf('/');
        var addressPart = slash < 0 ? trimmed : trimmed[..slash];
        if (!TryParseAddress(addressPart, out var address))
        {
            return false;
        }
        if (slash < 0)
        {
            cidr = new Ipv4Cidr(address, MaxPrefix);
            return true;
        }
        var prefixPart = trimmed[(slash + 1)..];
        if (prefixPart.Length is 0 or > 2)
        {
            return false;
        }
        if (prefixPart.Length > 1 && prefixPart[0] == '0')
        {
            return false;
        }
        var prefix = 0;
        foreach (var c in prefixPart)
        {
            if (c is < '0' or > '9')
            {
                return false;
            }
            prefix = (prefix * 10) + (c - '0');
        }
        if (prefix > MaxPrefix)
        {
            return false;
        }
        if ((address & ~MaskFor(prefix)) != 0)
        {
            return false;
        }
        cidr = new Ipv4Cidr(address, prefix);
        return true;
    }

    /// <summary>
    /// Reads four canonical dotted-decimal octets.
    /// </summary>
    public static bool TryParseAddress(string? text, out uint address)
    {
        address = 0;
        if (text is null)
        {
            return false;
        }
        uint value = 0;
        var octets = 0;
        var start = 0;
        for (var i = 0; i <= text.Length; i++)
        {
            if (i != text.Length && text[i] != '.')
            {
                continue;
            }
            var digits = i - start;
            if (digits is < 1 or > 3 || octets > 3)
            {
                return false;
            }
            if (digits > 1 && text[start] == '0')
            {
                return false;
            }
            var part = 0;
            for (var j = start; j < i; j++)
            {
                var c = text[j];
                if (c is < '0' or > '9')
                {
                    return false;
                }
                part = (part * 10) + (c - '0');
            }
            if (part > 255)
            {
                return false;
            }
            value = (value << 8) | (uint)part;
            octets++;
            start = i + 1;
        }
        if (octets != 4)
        {
            return false;
        }
        address = value;
        return true;
    }

    /// <summary>Renders an address in dotted-decimal form.</summary>
    public static string FormatAddress(uint value) =>
        $"{(value >> 24) & 0xFF}.{(value >> 16) & 0xFF}.{(value >> 8) & 0xFF}.{value & 0xFF}";

    /// <summary>Reports whether the address falls inside the prefix.</summary>
    public bool Contains(uint address)
    {
        var mask = MaskFor(PrefixLength);
        return (address & mask) == (Network & mask);
    }

    /// <summary>Reports whether the two prefixes share any address.</summary>
    public bool Overlaps(Ipv4Cidr other)
    {
        var mask = MaskFor(Math.Min(PrefixLength, other.PrefixLength));
        return (Network & mask) == (other.Network & mask);
    }

    /// <summary>Renders the prefix in canonical form.</summary>
    public override string ToString() => $"{FormatAddress(Network)}/{PrefixLength}";

    internal static bool ContainedIn(uint address, IEnumerable<string> cidrs)
    {
        foreach (var text in cidrs)
        {
            if (TryParse(text, out var cidr) && cidr.Contains(address))
            {
                return true;
            }
        }
        return false;
    }

    private static uint MaskFor(int prefixLength) =>
        prefixLength == 0 ? 0u : uint.MaxValue << (MaxPrefix - prefixLength);
}
