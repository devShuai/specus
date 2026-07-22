using System.Buffers.Binary;
using System.IO.Pipelines;
using ShuaiTunnel.Protocol;
using ShuaiTunnel.Client.Control;
using ShuaiTunnel.Protocol.Codec;

namespace ShuaiTunnel.Client.Tests;

public sealed class FrameSizeBoundaryTests
{
    private const int JavaMaxFrameSize = 32 * 1024 * 1024;

    [Fact]
    public async Task ClientFrameLimitIncludesElevenByteHeader()
    {
        var maxLegalBody = JavaMaxFrameSize - PacketCodec.HeaderSize;
        var exact = PipeReader.Create(new MemoryStream(Header(maxLegalBody)));
        var incomplete = await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await FrameReader.ReadFrameAsync(exact, JavaMaxFrameSize, CancellationToken.None));
        Assert.Equal("control channel closed mid-frame", incomplete.Message);

        var oversized = PipeReader.Create(new MemoryStream(Header(maxLegalBody + 1)));
        var rejected = await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await FrameReader.ReadFrameAsync(oversized, JavaMaxFrameSize, CancellationToken.None));
        Assert.Equal(
            $"command {Command.NatMessage} body exceeds limit: {maxLegalBody + 1}/{maxLegalBody}",
            rejected.Message);
    }

    private static byte[] Header(int bodyLength)
    {
        var header = new byte[PacketCodec.HeaderSize];
        BinaryPrimitives.WriteInt32BigEndian(header.AsSpan(0, 4), PacketCodec.MagicNumber);
        header[4] = PacketCodec.ProtocolVersion;
        header[5] = 4;
        header[6] = unchecked((byte)Command.NatMessage);
        BinaryPrimitives.WriteInt32BigEndian(header.AsSpan(7, 4), bodyLength);
        return header;
    }
}
