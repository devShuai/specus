using System.IO.Compression;
using ShuaiTunnel.Protocol.Codec;

namespace ShuaiTunnel.Protocol.Tests;

public sealed class CompactBinaryInflateTests
{
    private const int MaximumInflatedSize = 16 * 1024 * 1024;

    [Fact]
    public void CompleteRawDeflateAtMaximumInflatedSizeIsAllowed()
    {
        var raw = RepeatedBytes(MaximumInflatedSize);

        var decoded = CompactBinarySerializer.DecodePayload(AsDeflatedPayload(CompleteDeflate(raw)));

        Assert.Equal(MaximumInflatedSize, decoded.Length);
        Assert.Equal((byte)'A', decoded[0]);
        Assert.Equal((byte)'A', decoded[^1]);
    }

    [Fact]
    public void CompleteRawDeflateOneByteOverMaximumIsRejected()
    {
        var raw = RepeatedBytes(MaximumInflatedSize + 1);

        var exception = Assert.Throws<InvalidDataException>(() =>
            CompactBinarySerializer.DecodePayload(AsDeflatedPayload(CompleteDeflate(raw))));

        Assert.Contains("exceeds limit", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TruncatedRawDeflateIsRejectedInsteadOfReturningPartialOutput()
    {
        var complete = CompleteDeflate(RepeatedBytes(4096));
        var truncated = complete[..^1];

        var exception = Assert.Throws<InvalidDataException>(() =>
            CompactBinarySerializer.DecodePayload(AsDeflatedPayload(truncated)));

        Assert.Equal("invalid deflated payload", exception.Message);
    }

    [Fact]
    public void FlushedButNotFinishedRawDeflateIsRejected()
    {
        var flushed = FlushWithoutFinish(RepeatedBytes(4096));

        var exception = Assert.Throws<InvalidDataException>(() =>
            CompactBinarySerializer.DecodePayload(AsDeflatedPayload(flushed)));

        Assert.Equal("invalid deflated payload", exception.Message);
    }

    private static byte[] RepeatedBytes(int length)
    {
        var bytes = new byte[length];
        Array.Fill(bytes, (byte)'A');
        return bytes;
    }

    private static byte[] CompleteDeflate(byte[] bytes)
    {
        using var output = new MemoryStream();
        using (var deflate = new DeflateStream(output, CompressionLevel.SmallestSize, leaveOpen: true))
        {
            deflate.Write(bytes);
        }
        return output.ToArray();
    }

    private static byte[] FlushWithoutFinish(byte[] bytes)
    {
        using var output = new MemoryStream();
        using var deflate = new DeflateStream(output, CompressionLevel.SmallestSize, leaveOpen: true);
        deflate.Write(bytes);
        deflate.Flush();
        return output.ToArray();
    }

    private static byte[] AsDeflatedPayload(byte[] rawDeflate)
    {
        var payload = new byte[rawDeflate.Length + 1];
        payload[0] = 1;
        rawDeflate.CopyTo(payload, 1);
        return payload;
    }
}
