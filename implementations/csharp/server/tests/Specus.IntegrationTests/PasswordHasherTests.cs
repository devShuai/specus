using System.Security.Cryptography;
using System.Text;
using Specus.Server.Authentication;

namespace Specus.IntegrationTests;

public sealed class PasswordHasherTests
{
    private const string LegacyPassword = "legacy-password";

    [Fact]
    public void HashesAreSaltedAndCarryTheirOwnParameters()
    {
        var first = PasswordHasher.Hash("correct horse battery staple");
        var second = PasswordHasher.Hash("correct horse battery staple");

        Assert.NotEqual(first, second);
        Assert.StartsWith("$pbkdf2-sha256$v=1$i=210000$", first, StringComparison.Ordinal);
        Assert.Equal(6, first.Split('$').Length);
        Assert.True(PasswordHasher.Matches("correct horse battery staple", first));
        Assert.False(PasswordHasher.Matches("correct horse battery stapl", first));
    }

    [Fact]
    public void CurrentCostHashesAreNotRewritten()
    {
        var result = PasswordHasher.Verify("s3cret", PasswordHasher.Hash("s3cret"));

        Assert.True(result.Matches);
        Assert.False(result.NeedsUpgrade);
        Assert.Null(result.UpgradedHash);
        Assert.False(result.StoredIsLegacy);
    }

    /// <summary>
    /// Existing databases hold bare SHA-256. Those users must not be locked out, and the login is
    /// where the stored hash gets replaced.
    /// </summary>
    [Fact]
    public void LegacyHashesVerifyAndAreScheduledForUpgrade()
    {
        var legacy = LegacyDigest(LegacyPassword);

        Assert.True(PasswordHasher.IsLegacyHash(legacy));
        var result = PasswordHasher.Verify(LegacyPassword, legacy);
        Assert.True(result.Matches);
        Assert.True(result.NeedsUpgrade);
        Assert.True(result.StoredIsLegacy);
        Assert.NotNull(result.UpgradedHash);
        Assert.StartsWith("$pbkdf2-sha256$", result.UpgradedHash!, StringComparison.Ordinal);

        var next = PasswordHasher.Verify(LegacyPassword, result.UpgradedHash!);
        Assert.True(next.Matches);
        Assert.False(next.NeedsUpgrade);

        Assert.True(PasswordHasher.Matches(LegacyPassword, legacy.ToUpperInvariant()));
        Assert.False(PasswordHasher.Matches("wrong", legacy));
    }

    [Fact]
    public void UnderCostHashesAreUpgraded()
    {
        var weak = PasswordHasher.Hash("s3cret", PasswordHasher.MinIterations);
        var result = PasswordHasher.Verify("s3cret", weak);

        Assert.True(result.Matches);
        Assert.True(result.NeedsUpgrade);
        Assert.Contains($"i={PasswordHasher.DefaultIterations}$", result.UpgradedHash!,
            StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("$")]
    [InlineData("$pbkdf2-sha256$v=1$i=210000$onlythree")]
    [InlineData("$pbkdf2-sha256$v=2$i=210000$c2FsdA$a2V5")]
    [InlineData("$argon2id$v=1$i=210000$c2FsdA$a2V5")]
    [InlineData("$pbkdf2-sha256$v=1$i=1$c2FsdA$a2V5")]
    [InlineData("$pbkdf2-sha256$v=1$i=notanumber$c2FsdA$a2V5")]
    [InlineData("$pbkdf2-sha256$v=1$i=210000$!!!$a2V5")]
    [InlineData("$pbkdf2-sha256$v=1$i=210000$c2FsdA$!!!")]
    public void MalformedStoredHashesNeverVerify(string stored)
    {
        Assert.False(PasswordHasher.Matches("anything", stored));
    }

    /// <summary>
    /// Machine secrets keep the plain digest. That is required, not merely cheaper: the HMAC client
    /// login uses the 32 raw bytes of the digest as its key, so the format is part of the protocol.
    /// </summary>
    [Fact]
    public void TokenHashingStaysADeterministicDigest()
    {
        var token = PasswordHasher.HashToken("a-high-entropy-token");

        Assert.Equal(64, token.Length);
        Assert.Equal(token, PasswordHasher.HashToken("a-high-entropy-token"));
        Assert.DoesNotContain('$', token);
        Assert.Equal(token, PasswordHasher.DigestKey("a-high-entropy-token"));
        Assert.True(PasswordHasher.TokenMatches("a-high-entropy-token", token));
        Assert.False(PasswordHasher.TokenMatches("other", token));
        // A password-format hash must never satisfy a token check.
        Assert.False(PasswordHasher.TokenMatches("x", PasswordHasher.Hash("x")));
    }

    /// <summary>
    /// A hash written by one implementation has to verify on the others. The vector comes from an
    /// independent PBKDF2-HMAC-SHA256 implementation; Go and Java assert the same two strings.
    /// </summary>
    [Theory]
    [InlineData("$pbkdf2-sha256$v=1$i=1000$AAECAwQFBgcICQoLDA0ODw$vnwYtUA8UXxNgCLy7OdAY+f7T+TtG4qdlahTjY1KU5g")]
    [InlineData("$pbkdf2-sha256$v=1$i=210000$AAECAwQFBgcICQoLDA0ODw$BiTFCvEUdO2zrZt0s1Zd0ipbGH5+WaSosMi6WavHxbI")]
    public void SharedCrossLanguageVectorVerifies(string vector)
    {
        Assert.True(PasswordHasher.Matches("specus-shared-password", vector));
        Assert.False(PasswordHasher.Matches("specus-shared-passwordx", vector));
    }

    private static string LegacyDigest(string password)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(password))).ToLowerInvariant();
}
