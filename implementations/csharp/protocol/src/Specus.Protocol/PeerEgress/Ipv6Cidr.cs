using System.Globalization;
using System.Text;

namespace Specus.Protocol.PeerEgress;

/// <summary>
/// An IPv6 prefix with its host bits clear, read with the spelling protocol/spec/peer-egress.md
/// pins (IPv6 写法) for a consumer rule's match and an egress policy's destination rule alike.
/// </summary>
/// <remarks>
/// Written out rather than taken from <see cref="System.Net.IPAddress"/>, which also reads a dotted
/// IPv4 tail, a zone index and several other spellings, and writes some addresses in dotted form.
/// The other implementations parse the same way; the ipv6Prefixes section of
/// protocol/test-vectors/peer-egress-rules-v1.json pins every refusal a runtime parser lets through.
/// </remarks>
public readonly record struct Ipv6Cidr(UInt128 Network, int PrefixLength)
{
    /// <summary>The widest IPv6 prefix length.</summary>
    public const int MaxPrefix = 128;

    /// <summary>
    /// Reads RFC 4291 2.2 forms 1 and 2: eight groups of one to four hex digits, at most one
    /// <c>::</c> standing for one or more zero groups. No dotted IPv4 tail, no zone, no brackets,
    /// no surrounding space.
    /// </summary>
    public static bool TryParseAddress(string? text, out UInt128 address)
    {
        address = UInt128.Zero;
        if (string.IsNullOrEmpty(text) || text.Length > 39)
        {
            return false;
        }
        foreach (var c in text)
        {
            if (!IsHexDigit(c) && c != ':')
            {
                return false;
            }
        }
        if (text.Contains(":::", StringComparison.Ordinal))
        {
            return false;
        }
        var compressed = text.IndexOf("::", StringComparison.Ordinal);
        if (compressed >= 0 && text.IndexOf("::", compressed + 1, StringComparison.Ordinal) >= 0)
        {
            return false;
        }
        List<ushort>? groups;
        if (compressed >= 0)
        {
            var high = HexGroups(text[..compressed]);
            var low = HexGroups(text[(compressed + 2)..]);
            if (high is null || low is null || high.Count + low.Count > 7)
            {
                return false;
            }
            groups = new List<ushort>(high);
            groups.AddRange(new ushort[8 - high.Count - low.Count]);
            groups.AddRange(low);
        }
        else
        {
            groups = HexGroups(text);
            if (groups is null || groups.Count != 8)
            {
                return false;
            }
        }
        foreach (var group in groups)
        {
            address = (address << 16) | group;
        }
        return true;
    }

    /// <summary>
    /// Reads an IPv6 address or address/length: the length 0-128 in decimal without a leading zero,
    /// the host bits clear. A bare address is a /128.
    /// </summary>
    public static bool TryParse(string? text, out Ipv6Cidr cidr) => TryParse(text, out cidr, out _);

    /// <summary>
    /// As <see cref="TryParse(string?, out Ipv6Cidr)"/>, also saying whether a length was written,
    /// which is all a server needs to store the spelling back.
    /// </summary>
    public static bool TryParse(string? text, out Ipv6Cidr cidr, out bool hadLength)
    {
        cidr = default;
        hadLength = false;
        if (text is null)
        {
            return false;
        }
        var slash = text.IndexOf('/');
        if (!TryParseAddress(slash < 0 ? text : text[..slash], out var address))
        {
            return false;
        }
        if (slash < 0)
        {
            cidr = new Ipv6Cidr(address, MaxPrefix);
            return true;
        }
        var lengthPart = text[(slash + 1)..];
        if (lengthPart.Length is 0 or > 3 || (lengthPart.Length > 1 && lengthPart[0] == '0'))
        {
            return false;
        }
        var length = 0;
        foreach (var c in lengthPart)
        {
            if (c is < '0' or > '9')
            {
                return false;
            }
            length = (length * 10) + (c - '0');
        }
        if (length > MaxPrefix || (address & ~MaskFor(length)) != UInt128.Zero)
        {
            // Host bits set. Refused rather than masked, as for IPv4.
            return false;
        }
        cidr = new Ipv6Cidr(address, length);
        hadLength = true;
        return true;
    }

    /// <summary>Whether an address lies in the prefix.</summary>
    public bool Contains(UInt128 address) => (address & MaskFor(PrefixLength)) == Network;

    /// <summary>
    /// Whether the prefix lies in <c>::ffff:0:0/96</c>, where IPv4 destinations are spelled in IPv6
    /// APIs. No packet carries one, so a consumer rule there would never match anything.
    /// </summary>
    public bool Mapped => Network >> 32 == 0xFFFFUL;

    /// <summary>
    /// Writes RFC 5952 section 4: lower case, no leading zeros in a group, the longest run of two or
    /// more zero groups (the leftmost of equal runs) as <c>::</c>. Never the dotted form of section 5,
    /// so what it writes reads back through <see cref="TryParseAddress"/>.
    /// </summary>
    public static string FormatAddress(UInt128 address)
    {
        var groups = new ushort[8];
        for (var index = 0; index < 8; index++)
        {
            groups[index] = (ushort)(address >> (112 - (16 * index)));
        }
        int bestStart = -1, bestLength = 0;
        for (var index = 0; index < 8;)
        {
            if (groups[index] != 0)
            {
                index++;
                continue;
            }
            var end = index;
            while (end < 8 && groups[end] == 0)
            {
                end++;
            }
            if (end - index > bestLength)
            {
                bestStart = index;
                bestLength = end - index;
            }
            index = end;
        }
        string Hex(int from, int to)
        {
            var text = new StringBuilder();
            for (var index = from; index < to; index++)
            {
                if (index > from)
                {
                    text.Append(':');
                }
                text.Append(groups[index].ToString("x", CultureInfo.InvariantCulture));
            }
            return text.ToString();
        }
        return bestLength < 2 ? Hex(0, 8) : Hex(0, bestStart) + "::" + Hex(bestStart + bestLength, 8);
    }

    /// <summary>
    /// What a server stores for an egress policy's destination CIDR, already trimmed: an IPv4 one as
    /// written, since it has one spelling, and an IPv6 one in RFC 5952 form with the /length kept only
    /// when it was written. Null when the egress could not read it
    /// (protocol/test-vectors/peer-egress-management-v1.json).
    /// </summary>
    public static string? StoredDestinationCidr(string text)
    {
        if (!text.Contains(':', StringComparison.Ordinal))
        {
            return Ipv4Cidr.TryParse(text, out _) ? text : null;
        }
        if (!TryParse(text, out var cidr, out var hadLength))
        {
            return null;
        }
        var stored = FormatAddress(cidr.Network);
        return hadLength ? stored + "/" + cidr.PrefixLength.ToString(CultureInfo.InvariantCulture) : stored;
    }

    private static UInt128 MaskFor(int length) =>
        length == 0 ? UInt128.Zero : UInt128.MaxValue << (MaxPrefix - length);

    private static bool IsHexDigit(char c) => c is (>= '0' and <= '9') or (>= 'a' and <= 'f') or (>= 'A' and <= 'F');

    private static List<ushort>? HexGroups(string part)
    {
        var groups = new List<ushort>();
        if (part.Length == 0)
        {
            return groups;
        }
        foreach (var group in part.Split(':'))
        {
            if (group.Length is < 1 or > 4)
            {
                return null;
            }
            groups.Add(ushort.Parse(group, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture));
        }
        return groups;
    }

    /// <inheritdoc />
    public override string ToString() =>
        FormatAddress(Network) + "/" + PrefixLength.ToString(CultureInfo.InvariantCulture);
}
