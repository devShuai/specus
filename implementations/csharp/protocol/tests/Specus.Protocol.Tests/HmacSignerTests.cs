using Specus.Protocol.Security;

namespace Specus.Protocol.Tests;

public class HmacSignerTests
{
    [Fact]
    public void Sha256_MatchesKnownVector()
    {
        // SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        var hash = HmacSigner.Sha256("hello");
        Assert.Equal(
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            Convert.ToHexString(hash).ToLowerInvariant());
    }

    [Fact]
    public void HmacSha256_MatchesKnownVector()
    {
        // RFC 4231 test case 1
        var key = new byte[20];
        Array.Fill(key, (byte)0x0b);
        var hex = Convert.ToHexString(HmacSigner.HmacSha256(key, "Hi There")).ToLowerInvariant();
        Assert.Equal("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", hex);
    }

    [Fact]
    public void SignClientStartup_DerivesKeyFromSecret_AndProducesStableHex()
    {
        var secret = "test1234";
        var key = HmacSigner.Sha256(secret);
        var sig = HmacSigner.SignClientStartup(
            "Demo client",
            "1700000000000",
            "fixture-nonce",
            "m_fixture",
            "tester",
            key);
        Assert.Equal(64, sig.Length);
        Assert.Matches("^[0-9a-f]{64}$", sig);

        var msg = $"Demo client\n1700000000000\nfixture-nonce\nm_fixture\ntester";
        var raw = HmacSigner.HmacSha256(key, msg);
        Assert.Equal(Convert.ToHexString(raw).ToLowerInvariant(), sig);
    }

    [Fact]
    public void DecodeHex_RejectsOddLength()
    {
        Assert.Throws<ArgumentException>(() => HmacSigner.DecodeHex("abc"));
    }
}
