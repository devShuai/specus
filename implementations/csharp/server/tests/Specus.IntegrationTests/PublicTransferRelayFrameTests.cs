using System.Buffers.Binary;
using System.Text;
using Specus.Server.WebSockets;

namespace Specus.IntegrationTests;

public sealed class PublicTransferRelayFrameTests
{
    [Fact]
    public void ClientFrameIsStrictAndServerAddsAuthenticatedSource()
    {
        var app = AppFrame(2, [1, 2, 3]);
        var client = RelayFrame("peer-b", string.Empty, app);

        var decoded = PublicTransferRelayFrame.DecodeClient(client);

        Assert.Equal("peer-b", decoded.TargetPeerId);
        Assert.Equal(2, decoded.AppType);
        Assert.Equal(app, decoded.AppFrame);
        Assert.Equal(RelayFrame("peer-b", "peer-a", app),
            PublicTransferRelayFrame.EncodeServer("peer-b", "peer-a", app));
    }

    [Fact]
    public void SpoofedSourceAndTrailingAppBytesAreRejected()
    {
        var app = AppFrame(1, [4]);
        Assert.Throws<ArgumentException>(() =>
            PublicTransferRelayFrame.DecodeClient(RelayFrame("peer-b", "spoofed", app)));
        Assert.Throws<ArgumentException>(() =>
            PublicTransferRelayFrame.DecodeClient(
                RelayFrame("peer-b", string.Empty, [.. app, 0])));
    }

    private static byte[] RelayFrame(string targetPeerId, string sourcePeerId, byte[] app)
    {
        var target = Encoding.UTF8.GetBytes(targetPeerId);
        var source = Encoding.UTF8.GetBytes(sourcePeerId);
        var result = new byte[14 + target.Length + source.Length + app.Length];
        "STWR"u8.CopyTo(result);
        result[4] = 2;
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(6, 2), (ushort)target.Length);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(8, 2), (ushort)source.Length);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(10, 4), (uint)app.Length);
        var offset = 14;
        target.CopyTo(result, offset);
        offset += target.Length;
        source.CopyTo(result, offset);
        offset += source.Length;
        app.CopyTo(result, offset);
        return result;
    }

    private static byte[] AppFrame(byte appType, byte[] payload)
    {
        var result = new byte[72 + payload.Length];
        "STAP"u8.CopyTo(result);
        result[4] = 2;
        result[5] = appType;
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(28, 4), 1);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(32, 4), (uint)payload.Length);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(36, 4), (uint)payload.Length);
        payload.CopyTo(result, 72);
        return result;
    }
}
