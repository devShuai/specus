using Specus.Protocol.PeerEgress;

namespace Specus.Protocol.Tests;

/// <summary>
/// The address parser sits in front of every access decision, so its rejections matter as much as
/// its accepts. Anything it accepts loosely here is a difference the other runtimes can disagree on.
/// </summary>
public sealed class PeerEgressCidrTests
{
    [Fact]
    public void ParseAddressAcceptsCanonicalForms()
    {
        foreach (var text in new[] { "0.0.0.0", "255.255.255.255", "203.0.113.200", "0.1.2.3" })
        {
            Assert.True(Ipv4Cidr.TryParseAddress(text, out _), text);
        }
        Assert.True(Ipv4Cidr.TryParseAddress("203.0.113.200", out var value));
        Assert.Equal("203.0.113.200", Ipv4Cidr.FormatAddress(value));
    }

    [Fact]
    public void ParseAddressRejectsLeadingZeroOctets()
    {
        // Runtimes disagree on 010: decimal ten or octal eight. A rule must not be able to mean
        // different things in different implementations.
        foreach (var text in new[] { "010.1.1.1", "1.02.3.4", "1.2.3.00" })
        {
            Assert.False(Ipv4Cidr.TryParseAddress(text, out _), text);
        }
    }

    [Fact]
    public void ParseAddressRejectsMalformedInput()
    {
        foreach (var text in new[]
                 {
                     "", "1.2.3", "1.2.3.4.5", "1.2.3.", ".1.2.3",
                     "1.2.3.256", "1.2.3.4444", "1.2.3.-4", "1.2.3.4 ", "::1",
                 })
        {
            Assert.False(Ipv4Cidr.TryParseAddress(text, out _), text);
        }
    }

    [Fact]
    public void ParseCidrRejectsHostBitsAndBadPrefixes()
    {
        Assert.True(Ipv4Cidr.TryParse("203.0.113.0/24", out _));
        foreach (var text in new[] { "203.0.113.1/24", "203.0.113.0/33", "203.0.113.0/08", "203.0.113.0/" })
        {
            Assert.False(Ipv4Cidr.TryParse(text, out _), text);
        }
    }

    [Fact]
    public void BareAddressBecomesAHostPrefix()
    {
        Assert.True(Ipv4Cidr.TryParse("203.0.113.9", out var cidr));
        Assert.Equal(Ipv4Cidr.MaxPrefix, cidr.PrefixLength);
        Assert.Equal("203.0.113.9/32", cidr.ToString());
    }

    [Fact]
    public void ContainsAndOverlapsFollowPrefixLength()
    {
        Assert.True(Ipv4Cidr.TryParse("203.0.113.0/24", out var slash24));
        Assert.True(Ipv4Cidr.TryParse("203.0.113.128/25", out var slash25));
        Assert.True(Ipv4Cidr.TryParse("198.51.100.0/24", out var other));
        Assert.True(Ipv4Cidr.TryParse("0.0.0.0/0", out var everything));

        Assert.True(Ipv4Cidr.TryParseAddress("203.0.113.255", out var broadcast));
        Assert.True(Ipv4Cidr.TryParseAddress("203.0.113.127", out var below));
        Assert.True(Ipv4Cidr.TryParseAddress("8.8.8.8", out var anywhere));

        Assert.True(slash24.Contains(broadcast));
        Assert.False(slash25.Contains(below));
        Assert.True(slash24.Overlaps(slash25));
        Assert.True(slash25.Overlaps(slash24));
        Assert.False(slash24.Overlaps(other));
        Assert.True(everything.Contains(anywhere));
    }
}
