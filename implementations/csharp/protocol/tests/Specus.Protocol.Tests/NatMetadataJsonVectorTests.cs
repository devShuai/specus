using System.Buffers.Binary;
using System.Text.Json;
using System.Text.Json.Serialization;
using Specus.Protocol.Codec;
using Specus.Protocol.Packets;

namespace Specus.Protocol.Tests;

/// <summary>
/// Replays <c>protocol/test-vectors/nat-metadata-json-v1.json</c>: the metadata of an OPEN is read
/// strictly by RFC 8259 as one UTF-8 JSON object, and every refused case is a malformed body.
/// </summary>
public sealed class NatMetadataJsonVectorTests
{
    [Fact]
    public void AcceptsAndRefusesTheSharedCases()
    {
        var vector = ReadVector();
        Assert.Equal(1, vector.Version);
        foreach (var testCase in vector.Accepted)
        {
            Assert.True(PacketCodec.TryDecode(OpenFrame(testCase.MetadataHex), out var packet, out _),
                testCase.Name);
            Assert.IsType<NatMessagePacket>(packet);
        }
        foreach (var testCase in vector.Rejected)
        {
            var frame = OpenFrame(testCase.MetadataHex);
            var exception = Record.Exception(() => PacketCodec.TryDecode(frame, out _, out _));
            Assert.True(exception is InvalidDataException, $"{testCase.Name}: {exception?.GetType().Name ?? "accepted"}");
        }
        Assert.Equal(8, vector.Accepted.Count);
        Assert.Equal(34, vector.Rejected.Count);
    }

    private static byte[] OpenFrame(string metadataHex)
    {
        var metadata = Convert.FromHexString(metadataHex);
        var body = new byte[16 + metadata.Length];
        body[0] = (byte)NatMessageType.Open;
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(2, 2), (ushort)metadata.Length);
        BinaryPrimitives.WriteUInt32BigEndian(body.AsSpan(4, 4), 1);
        metadata.CopyTo(body, 16);
        var frame = new byte[PacketCodec.HeaderSize + body.Length];
        BinaryPrimitives.WriteInt32BigEndian(frame.AsSpan(0, 4), PacketCodec.MagicNumber);
        frame[4] = PacketCodec.ProtocolVersion;
        frame[5] = SerializerAlgorithm.CompactBinary;
        frame[6] = unchecked((byte)Command.NatMessage);
        BinaryPrimitives.WriteInt32BigEndian(frame.AsSpan(7, 4), body.Length);
        body.CopyTo(frame, PacketCodec.HeaderSize);
        return frame;
    }

    private static MetadataVector ReadVector()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        for (var depth = 0; directory is not null && depth < 12; depth++, directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, "protocol", "test-vectors", "nat-metadata-json-v1.json");
            if (File.Exists(candidate))
            {
                return JsonSerializer.Deserialize<MetadataVector>(File.ReadAllText(candidate))
                    ?? throw new InvalidDataException("nat-metadata-json-v1.json decoded to null");
            }
        }
        throw new FileNotFoundException("cannot locate nat-metadata-json-v1.json");
    }

    private sealed record MetadataVector
    {
        [JsonPropertyName("version")]
        public int Version { get; init; }

        [JsonPropertyName("accepted")]
        public List<MetadataCase> Accepted { get; init; } = [];

        [JsonPropertyName("rejected")]
        public List<MetadataCase> Rejected { get; init; } = [];
    }

    private sealed record MetadataCase
    {
        [JsonPropertyName("name")]
        public string Name { get; init; } = "";

        [JsonPropertyName("metadataHex")]
        public string MetadataHex { get; init; } = "";
    }
}
