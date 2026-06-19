using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ShuaiTunnel.Protocol.Packets;

namespace ShuaiTunnel.Protocol.Codec;

/// <summary>
/// Wire-format codec — see <c>com.theshuai.common.protocol.PacketCodec</c>. Frame layout:
/// <code>
/// +-------+--------+------------+---------+--------+----------+
/// | magic | ver=1  | serializer | command | length | body     |
/// |  4B   |  1B    |    1B      |   1B    |  4B BE | N bytes  |
/// +-------+--------+------------+---------+--------+----------+
/// </code>
/// All multi-byte integers in the header are big-endian. Default <c>serializer</c> is
/// <see cref="SerializerAlgorithm.CompactBinary"/> = 4; NAT_MESSAGE uses <see cref="SerializerAlgorithm.FastJson"/> = 1
/// for the metadata, but the wrapping frame still records FastJson — the body has its own custom layout.
/// </summary>
public static class PacketCodec
{
    public const int MagicNumber = 0x14353565;
    public const int HeaderSize = 11;

    private static readonly Dictionary<sbyte, Func<byte[], Packet>> CommandToDecoder = new()
    {
        [Command.LoginRequest] = bytes => CompactBinarySerializer.Deserialize<LoginRequestPacket>(bytes),
        [Command.LoginResponse] = bytes => CompactBinarySerializer.Deserialize<LoginResponsePacket>(bytes),
        [Command.MessageRequest] = bytes => CompactBinarySerializer.Deserialize<MessageRequestPacket>(bytes),
        [Command.MessageResponse] = bytes => CompactBinarySerializer.Deserialize<MessageResponsePacket>(bytes),
        [Command.LogoutRequest] = bytes => CompactBinarySerializer.Deserialize<LogoutRequestPacket>(bytes),
        [Command.LogoutResponse] = bytes => CompactBinarySerializer.Deserialize<LogoutResponsePacket>(bytes),
        [Command.HeartbeatRequest] = bytes => CompactBinarySerializer.Deserialize<HeartbeatRequestPacket>(bytes),
        [Command.HeartbeatResponse] = bytes => CompactBinarySerializer.Deserialize<HeartbeatResponsePacket>(bytes),
        [Command.HttpRequest] = bytes => CompactBinarySerializer.Deserialize<HttpRequestPacket>(bytes),
        [Command.HttpResponse] = bytes => CompactBinarySerializer.Deserialize<HttpResponsePacket>(bytes),
        [Command.DirectHttpRequest] = bytes => CompactBinarySerializer.Deserialize<DirectHttpRequestPacket>(bytes),
        [Command.DirectHttpResponse] = bytes => CompactBinarySerializer.Deserialize<DirectHttpResponsePacket>(bytes),
    };

    /// <summary>
    /// Encodes a single packet into a fresh byte array suitable for direct writing to a stream.
    /// </summary>
    public static byte[] Encode(Packet packet)
    {
        if (packet is null)
        {
            throw new ArgumentNullException(nameof(packet));
        }

        using var ms = new MemoryStream();
        // Reserve 11-byte header for fixup.
        ms.Write(new byte[HeaderSize], 0, HeaderSize);

        byte serializer;
        int bodyLen;

        if (packet is NatMessagePacket nat)
        {
            // NAT_MESSAGE serializer byte mirrors Java: forced to FASTJSON regardless of caller's choice.
            serializer = SerializerAlgorithm.FastJson;
            bodyLen = WriteNatBody(ms, nat);
        }
        else
        {
            serializer = SerializerAlgorithm.CompactBinary;
            var bodyBytes = CompactBinarySerializer.Serialize(packet);
            ms.Write(bodyBytes, 0, bodyBytes.Length);
            bodyLen = bodyBytes.Length;
        }

        var buffer = ms.GetBuffer();
        BinaryPrimitives.WriteInt32BigEndian(buffer.AsSpan(0, 4), MagicNumber);
        buffer[4] = packet.Version;
        buffer[5] = serializer;
        buffer[6] = (byte)(sbyte)packet.Command;
        BinaryPrimitives.WriteInt32BigEndian(buffer.AsSpan(7, 4), bodyLen);

        var result = new byte[HeaderSize + bodyLen];
        Buffer.BlockCopy(buffer, 0, result, 0, HeaderSize + bodyLen);
        return result;
    }

    /// <summary>
    /// Tries to decode one full frame from <paramref name="input"/>. Returns <c>false</c> if more
    /// bytes are needed; on a malformed magic number throws <see cref="InvalidDataException"/>.
    /// </summary>
    public static bool TryDecode(ReadOnlySpan<byte> input, out Packet? packet, out int consumed)
    {
        packet = null;
        consumed = 0;
        if (input.Length < HeaderSize)
        {
            return false;
        }
        var magic = BinaryPrimitives.ReadInt32BigEndian(input[..4]);
        if (magic != MagicNumber)
        {
            throw new InvalidDataException($"bad magic: 0x{magic:X8}");
        }
        // version at [4] is reserved — currently always 1, ignored on read.
        var serializer = input[5];
        var command = (sbyte)input[6];
        var length = BinaryPrimitives.ReadInt32BigEndian(input.Slice(7, 4));
        if (length < 0)
        {
            throw new InvalidDataException("negative frame length");
        }
        if (input.Length < HeaderSize + length)
        {
            return false;
        }

        var body = input.Slice(HeaderSize, length).ToArray();
        packet = command == Command.NatMessage
            ? DecodeNatBody(body)
            : DecodeRegularBody(command, serializer, body);
        consumed = HeaderSize + length;
        return true;
    }

    private static Packet DecodeRegularBody(sbyte command, byte serializer, byte[] body)
    {
        if (serializer != SerializerAlgorithm.CompactBinary)
        {
            // Server-side we only implement CompactBinary — Jackson/FastJson/Protobuf are not on
            // the wire by default and would require porting those Java codecs as well. Reject loudly.
            throw new NotSupportedException(
                $"unsupported serializer for command {command}: {serializer}; only CompactBinary (4) is implemented");
        }
        if (!CommandToDecoder.TryGetValue(command, out var decoder))
        {
            throw new InvalidDataException($"unknown command byte: {command}");
        }
        return decoder(body);
    }

    private static int WriteNatBody(MemoryStream ms, NatMessagePacket nat)
    {
        var bodyStart = ms.Position;

        // int32 type (BE)
        Span<byte> intBuf = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(intBuf, nat.NatMessageType.Code());
        ms.Write(intBuf);

        // metadata: utf-8 JSON of the metaData map. Java side serializes via FastJson; we use
        // System.Text.Json with no extra knobs. Java only treats this as a Map<String,Object> on
        // both sides so trivially-shaped JSON round-trips correctly.
        var metaJson = SerializeMeta(nat.MetaData);
        BinaryPrimitives.WriteInt32BigEndian(intBuf, metaJson.Length);
        ms.Write(intBuf);
        ms.Write(metaJson, 0, metaJson.Length);

        // optional payload — if Data present, wrap with the same 2-byte payload-type prefix +
        // optional deflate that the per-class compact-binary codec uses for whole-packet bodies.
        if (nat.Data is { Length: > 0 } data)
        {
            var encoded = CompactBinarySerializer.EncodePayload(data);
            ms.Write(encoded, 0, encoded.Length);
        }

        return (int)(ms.Position - bodyStart);
    }

    private static NatMessagePacket DecodeNatBody(byte[] body)
    {
        if (body.Length < 8)
        {
            throw new InvalidDataException("NAT_MESSAGE body too short");
        }
        var type = BinaryPrimitives.ReadInt32BigEndian(body.AsSpan(0, 4));
        var natType = NatMessageTypeExtensions.FromCode(type)
            ?? throw new InvalidDataException($"unknown NAT message type: {type}");

        var metaLen = BinaryPrimitives.ReadInt32BigEndian(body.AsSpan(4, 4));
        if (metaLen < 0 || 8 + metaLen > body.Length)
        {
            throw new InvalidDataException("NAT_MESSAGE metadata length out of range");
        }
        var metaJson = body.AsSpan(8, metaLen);
        var metaData = DeserializeMeta(metaJson);

        byte[]? payload = null;
        if (8 + metaLen < body.Length)
        {
            var trailing = body.AsSpan(8 + metaLen).ToArray();
            payload = CompactBinarySerializer.DecodePayload(trailing);
        }

        return new NatMessagePacket
        {
            NatMessageType = natType,
            MetaData = metaData,
            Data = payload,
        };
    }

    private static byte[] SerializeMeta(Dictionary<string, object?>? metaData)
    {
        // Empty map (not null) — Java FastJson with default config emits "{}" for null too,
        // but we mirror exact behavior: null map emits "null".
        if (metaData is null)
        {
            return Encoding.UTF8.GetBytes("null");
        }
        var node = new JsonObject();
        foreach (var kv in metaData)
        {
            node[kv.Key] = ToJsonNode(kv.Value);
        }
        return Encoding.UTF8.GetBytes(node.ToJsonString());
    }

    private static JsonNode? ToJsonNode(object? value) => value switch
    {
        null => null,
        string s => JsonValue.Create(s),
        bool b => JsonValue.Create(b),
        int i => JsonValue.Create(i),
        long l => JsonValue.Create(l),
        double d => JsonValue.Create(d),
        float f => JsonValue.Create(f),
        decimal m => JsonValue.Create(m),
        JsonNode n => n.DeepClone(),
        _ => JsonValue.Create(value.ToString()),
    };

    private static Dictionary<string, object?>? DeserializeMeta(ReadOnlySpan<byte> json)
    {
        if (json.Length == 0)
        {
            return null;
        }
        var node = JsonNode.Parse(Encoding.UTF8.GetString(json));
        if (node is null)
        {
            return null;
        }
        if (node is not JsonObject obj)
        {
            throw new InvalidDataException("NAT metadata is not a JSON object");
        }
        var map = new Dictionary<string, object?>(obj.Count);
        foreach (var kv in obj)
        {
            map[kv.Key] = FromJsonNode(kv.Value);
        }
        return map;
    }

    private static object? FromJsonNode(JsonNode? node)
    {
        if (node is null)
        {
            return null;
        }
        if (node is JsonValue value)
        {
            // Probe the underlying primitive — JsonValue boxes one of: bool, string, numerics.
            // We unwrap to the matching CLR type so callers can do `(string?)map["k"]` etc.
            if (value.TryGetValue<bool>(out var b))
            {
                return b;
            }
            if (value.TryGetValue<long>(out var l))
            {
                return l;
            }
            if (value.TryGetValue<double>(out var d))
            {
                return d;
            }
            if (value.TryGetValue<string>(out var s))
            {
                return s;
            }
        }
        return node;
    }
}
