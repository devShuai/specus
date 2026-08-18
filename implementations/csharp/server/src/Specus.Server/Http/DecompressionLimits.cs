namespace Specus.Server.Http;

/// <summary>
/// Bounds on how much a compressed body may expand.
///
/// <para>Decompression is the one place where a small input costs unbounded memory. A few kilobytes
/// of crafted gzip expands to gigabytes, so reading a decompressor to the end hands any upstream —
/// or any peer able to influence one — a way to end the process.</para>
///
/// <para>Two limits, because either alone leaves a gap. The absolute cap bounds what a single body
/// can cost. The ratio cap catches a bomb that stays under the absolute cap but is still wildly
/// disproportionate to its input, which is the signature of a bomb rather than of real content.</para>
/// </summary>
public static class DecompressionLimits
{
    /// <summary>Matches the largest body the proxy carries anyway, so no legitimate payload is lost.</summary>
    public const int MaxDecompressedBytes = 64 * 1024 * 1024;

    /// <summary>Generous next to real text, which rarely exceeds 20:1.</summary>
    public const int MaxRatio = 100;

    /// <summary>Keeps the ratio from rejecting tiny inputs, where framing overhead dominates.</summary>
    public const int MinRatioAllowanceBytes = 64 * 1024;

    /// <summary>Thrown when a body exceeds either limit.</summary>
    public sealed class LimitExceededException(long produced, int compressedSize)
        : IOException($"decompressed body exceeded its limit: {produced} bytes from {compressedSize} compressed");

    /// <summary>Returns the smaller of the absolute cap and the ratio allowance.</summary>
    public static int LimitFor(int compressedSize)
    {
        if (compressedSize <= 0)
        {
            return MinRatioAllowanceBytes;
        }
        var scaled = (long)compressedSize * MaxRatio;
        var allowance = Math.Max(MinRatioAllowanceBytes, scaled);
        return (int)Math.Min(allowance, MaxDecompressedBytes);
    }

    /// <summary>
    /// Reads the decompressor, refusing anything past the byte or ratio cap.
    /// </summary>
    /// <param name="compressedSize">
    /// Size of the input handed to the decompressor, which is what makes the ratio check possible.
    /// </param>
    public static byte[] ReadAllBounded(Stream decoder, int compressedSize)
    {
        var limit = LimitFor(compressedSize);
        using var output = new MemoryStream();
        var buffer = new byte[8192];
        long produced = 0;
        int read;
        while ((read = decoder.Read(buffer, 0, buffer.Length)) > 0)
        {
            produced += read;
            if (produced > limit)
            {
                throw new LimitExceededException(produced, compressedSize);
            }
            output.Write(buffer, 0, read);
        }
        return output.ToArray();
    }
}
