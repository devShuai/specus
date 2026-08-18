using System.IO.Compression;
using System.Text;
using Specus.Server.Http;

namespace Specus.IntegrationTests;

public sealed class DecompressionLimitsTests
{
    [Fact]
    public void OrdinaryBodiesDecompressUnchanged()
    {
        var payload = Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat("the quick brown fox. ", 2000)));
        var compressed = Gzip(payload);

        using var source = new MemoryStream(compressed);
        using var decoder = new GZipStream(source, CompressionMode.Decompress);
        Assert.Equal(payload, DecompressionLimits.ReadAllBounded(decoder, compressed.Length));
    }

    /// <summary>A few kilobytes of crafted gzip expands to gigabytes; reading to the end would end the process.</summary>
    [Fact]
    public void DecompressionBombIsRefused()
    {
        var bomb = Gzip(new byte[32 * 1024 * 1024]);

        using var source = new MemoryStream(bomb);
        using var decoder = new GZipStream(source, CompressionMode.Decompress);
        Assert.Throws<DecompressionLimits.LimitExceededException>(
            () => DecompressionLimits.ReadAllBounded(decoder, bomb.Length));
    }

    [Fact]
    public void LimitCombinesTheAbsoluteAndRatioCaps()
    {
        // Tiny inputs get the flat allowance, so framing overhead cannot make the ratio meaningless.
        Assert.Equal(DecompressionLimits.MinRatioAllowanceBytes, DecompressionLimits.LimitFor(0));
        Assert.Equal(DecompressionLimits.MinRatioAllowanceBytes, DecompressionLimits.LimitFor(-1));

        // In the middle the ratio binds.
        Assert.Equal(256 * 1024 * DecompressionLimits.MaxRatio,
            DecompressionLimits.LimitFor(256 * 1024));

        // Past that the absolute cap binds, including for a size large enough to overflow a naive
        // multiplication.
        Assert.Equal(DecompressionLimits.MaxDecompressedBytes,
            DecompressionLimits.LimitFor(1024 * 1024));
        Assert.Equal(DecompressionLimits.MaxDecompressedBytes,
            DecompressionLimits.LimitFor(int.MaxValue));
    }

    /// <summary>A body that exactly fills its allowance is legitimate and must not be rejected.</summary>
    [Fact]
    public void BodyWithinTheAllowanceIsAccepted()
    {
        var payload = new byte[DecompressionLimits.MinRatioAllowanceBytes];
        Array.Fill(payload, (byte)'x');
        var compressed = Gzip(payload);

        using var source = new MemoryStream(compressed);
        using var decoder = new GZipStream(source, CompressionMode.Decompress);
        Assert.Equal(payload.Length,
            DecompressionLimits.ReadAllBounded(decoder, compressed.Length).Length);
    }

    private static byte[] Gzip(byte[] payload)
    {
        using var buffer = new MemoryStream();
        using (var compressor = new GZipStream(buffer, CompressionMode.Compress, leaveOpen: true))
        {
            compressor.Write(payload, 0, payload.Length);
        }
        return buffer.ToArray();
    }
}
