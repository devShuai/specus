using System.Buffers.Binary;
using System.Text;
using Specus.Client.PeerMesh;
using Specus.Protocol;

namespace Specus.Client.Tests;

public sealed class ApplicationProtocolVectorTests
{
    [Fact]
    public void WebSocketSpecusFrameMatchesCentralSws2Vector()
    {
        var vectors = ReadVectors();
        var vector = vectors.WebSocket;
        var expected = Convert.FromHexString(vector.FrameHex);
        var encoded = new WebSocketSpecusFrame(
            vector.Opcode,
            vector.FinalFragment,
            vector.Rsv,
            vector.CloseCode,
            Encoding.UTF8.GetBytes(vector.PayloadUtf8)).Encode();

        Assert.Equal(expected, encoded);
        var decoded = WebSocketSpecusFrame.Decode(expected);
        Assert.Equal(vector.Opcode, decoded.Opcode);
        Assert.Equal(vector.FinalFragment, decoded.FinalFragment);
        Assert.Equal(vector.Rsv, decoded.Rsv);
        Assert.Equal(vector.CloseCode, decoded.CloseCode);
        Assert.Equal(vector.PayloadUtf8, Encoding.UTF8.GetString(decoded.Payload));
        Assert.Throws<InvalidDataException>(() =>
            WebSocketSpecusFrame.Decode(Convert.FromHexString(vector.InvalidMagicHex)));
        Assert.Throws<InvalidDataException>(() =>
            WebSocketSpecusFrame.Decode(Convert.FromHexString(vector.TruncatedHex)));
        Assert.Throws<InvalidDataException>(() =>
            WebSocketSpecusFrame.Decode(Convert.FromHexString(vector.TrailingHex)));

        foreach (var closeCode in vector.WireForbiddenCloseCodes)
        {
            Assert.Throws<ArgumentException>(() => new WebSocketSpecusFrame(
                WebSocketSpecusFrame.OpcodeClose, true, 0, closeCode, []));

            var wireFrame = new byte[WebSocketSpecusFrame.HeaderBytes];
            "SWS2"u8.CopyTo(wireFrame);
            wireFrame[4] = WebSocketSpecusFrame.OpcodeClose;
            wireFrame[5] = 1;
            BinaryPrimitives.WriteUInt16BigEndian(wireFrame.AsSpan(6, 2), closeCode);
            Assert.Throws<InvalidDataException>(() => WebSocketSpecusFrame.Decode(wireFrame));
        }
    }

    [Fact]
    public void PeerAppMessageMatchesCentralStmsg2Vector()
    {
        var vector = ReadVectors().ClientMessage;
        var message = new PeerAppMessage
        {
            Type = vector.Type,
            Id = vector.Id,
            FromClientId = vector.FromClientId,
            FromClientName = vector.FromClientName,
            ToClientId = vector.ToClientId,
            ToClientName = vector.ToClientName,
            Message = vector.Message,
            CreatedAtMillis = vector.CreatedAtMillis,
        };

        var expected = Convert.FromHexString(vector.PayloadHex);
        Assert.Equal(expected, PeerAppMessageCodec.Encode(message));
        Assert.True(PeerAppMessageCodec.TryDecode(expected, out var decoded));
        Assert.Equal(vector.Type, decoded.Type);
        Assert.Equal(vector.Id, decoded.Id);
        Assert.Equal(vector.FromClientId, decoded.FromClientId);
        Assert.Equal(vector.FromClientName, decoded.FromClientName);
        Assert.Equal(vector.ToClientId, decoded.ToClientId);
        Assert.Equal(vector.ToClientName, decoded.ToClientName);
        Assert.Equal(vector.Message, decoded.Message);
        Assert.Equal(vector.CreatedAtMillis, decoded.CreatedAtMillis);
    }

    private static ApplicationProtocolVectors ReadVectors()
    {
        return ProtocolVectorTestHelper.Read<ApplicationProtocolVectors>(
            "protocol/test-vectors/application-protocol-v2.json");
    }

    private sealed class ApplicationProtocolVectors
    {
        public required WebSocketVector WebSocket { get; init; }
        public required ClientMessageVector ClientMessage { get; init; }
    }

    private sealed class WebSocketVector
    {
        public byte Opcode { get; init; }
        public bool FinalFragment { get; init; }
        public byte Rsv { get; init; }
        public ushort CloseCode { get; init; }
        public required string PayloadUtf8 { get; init; }
        public required string FrameHex { get; init; }
        public required string InvalidMagicHex { get; init; }
        public required string TruncatedHex { get; init; }
        public required string TrailingHex { get; init; }
        public required ushort[] WireForbiddenCloseCodes { get; init; }
    }

    private sealed class ClientMessageVector
    {
        public required string Type { get; init; }
        public required string Id { get; init; }
        public long FromClientId { get; init; }
        public required string FromClientName { get; init; }
        public long ToClientId { get; init; }
        public required string ToClientName { get; init; }
        public required string Message { get; init; }
        public long CreatedAtMillis { get; init; }
        public required string PayloadHex { get; init; }
    }
}
