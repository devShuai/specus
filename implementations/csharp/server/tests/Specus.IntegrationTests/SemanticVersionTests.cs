using Specus.Server.Management;

namespace Specus.IntegrationTests;

public sealed class SemanticVersionTests
{
    [Theory]
    [InlineData("1.0.0", "1.0.0", 0)]
    [InlineData("v1.2.3", "1.2.3", 0)]
    [InlineData("1.0.0+build.2", "1.0.0+build.1", 0)]
    [InlineData("v1.2.3-alpha.1+build.01", "1.2.3-alpha.1", 0)]
    [InlineData("1.0.0", "1.0.0-rc.1", 1)]
    [InlineData("1.0.0-alpha.2", "1.0.0-alpha.10", -1)]
    [InlineData("2.0.0", "1.999999999999999999999.9", 1)]
    [InlineData("999999999999999999999.0.0", "999999999999999999998.999.999", 1)]
    public void ComparisonImplementsStrictSemVer20Precedence(string left, string right, int sign)
    {
        Assert.True(SemanticVersion.TryParse(left, out var leftVersion));
        Assert.True(SemanticVersion.TryParse(right, out var rightVersion));
        Assert.Equal(sign, Math.Sign(leftVersion.CompareTo(rightVersion)));
    }

    [Theory]
    [InlineData("")]
    [InlineData("V1.0.0")]
    [InlineData("1")]
    [InlineData("1.0")]
    [InlineData("1.0.0.0")]
    [InlineData("01.0.0")]
    [InlineData("1.01.0")]
    [InlineData("1.0.01")]
    [InlineData("1.0.0-")]
    [InlineData("1.0.0-01")]
    [InlineData("1.0.0-alpha..1")]
    [InlineData("1.0.0+")]
    [InlineData("1.0.0+build..1")]
    [InlineData("1.0.0+!!!")]
    [InlineData("1.0.0+one+two")]
    [InlineData("1.0.0-α")]
    public void ParserRejectsLooseOrAmbiguousVersions(string value)
    {
        Assert.False(SemanticVersion.TryParse(value, out _));
    }

    [Fact]
    public void ParserLimitsCanonicalVersionTo32Characters()
    {
        var canonical = $"{new string('9', 28)}.0.0";
        Assert.Equal(32, canonical.Length);
        Assert.True(SemanticVersion.TryParse($"v{canonical}", out _));
        Assert.False(SemanticVersion.TryParse($"{new string('9', 29)}.0.0", out _));
    }
}
