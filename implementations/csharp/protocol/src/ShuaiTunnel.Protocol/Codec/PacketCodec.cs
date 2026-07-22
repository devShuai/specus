using System.Buffers.Binary;
using System.Collections.Frozen;
using System.Text;
using System.Text.Json.Nodes;
using ShuaiTunnel.Protocol.Packets;

namespace ShuaiTunnel.Protocol.Codec;

/// <summary>
/// Strict control protocol v2 codec. The frame header is
/// magic(4), version(1), serializer(1), command(1), bodyLength(4), all integers big-endian.
/// CompactBinary (wire id 4) is the sole serializer. NAT data is never compressed.
/// </summary>
public static class PacketCodec
{
    public const int MagicNumber = 0x14353565;
    public const byte ProtocolVersion = 2;
    public const int HeaderSize = 11;
    public const int MaxFrameSize = 32 * 1024 * 1024;
    public const int PreAuthMaxFrameSize = 16 * 1024;
    public const int MaxMessageBodySize = 1024 * 1024;
    public const int MaxNatMetadataSize = ushort.MaxValue;

    public const int NatBodyHeaderSize = 16;
    public const byte NatFlagEndStream = 1;

    private static readonly FrozenDictionary<sbyte, Func<byte[], Packet>> CommandToDecoder =
        new Dictionary<sbyte, Func<byte[], Packet>>
        {
            [Command.LoginRequest] = CompactBinarySerializer.Deserialize<LoginRequestPacket>,
            [Command.LoginResponse] = CompactBinarySerializer.Deserialize<LoginResponsePacket>,
            [Command.MessageRequest] = CompactBinarySerializer.Deserialize<MessageRequestPacket>,
            [Command.MessageResponse] = CompactBinarySerializer.Deserialize<MessageResponsePacket>,
            [Command.LogoutRequest] = CompactBinarySerializer.Deserialize<LogoutRequestPacket>,
            [Command.LogoutResponse] = CompactBinarySerializer.Deserialize<LogoutResponsePacket>,
            [Command.HeartbeatRequest] = CompactBinarySerializer.Deserialize<HeartbeatRequestPacket>,
            [Command.HeartbeatResponse] = CompactBinarySerializer.Deserialize<HeartbeatResponsePacket>,
        }.ToFrozenDictionary();

    public static byte[] Encode(Packet packet)
    {
        ArgumentNullException.ThrowIfNull(packet);
        if (packet.Version != ProtocolVersion)
        {
            throw new InvalidDataException($"unsupported protocol version: {packet.Version}");
        }
        if (!IsKnownCommand(packet.Command))
        {
            throw new InvalidDataException($"unknown command byte: {packet.Command}");
        }

        var body = packet is NatMessagePacket nat
            ? EncodeNatBody(nat)
            : CompactBinarySerializer.Serialize(packet);
        ValidateBodyLength(packet.Command, body.Length);

        var result = new byte[HeaderSize + body.Length];
        BinaryPrimitives.WriteInt32BigEndian(result.AsSpan(0, 4), MagicNumber);
        result[4] = ProtocolVersion;
        result[5] = SerializerAlgorithm.CompactBinary;
        result[6] = unchecked((byte)packet.Command);
        BinaryPrimitives.WriteInt32BigEndian(result.AsSpan(7, 4), body.Length);
        body.CopyTo(result.AsSpan(HeaderSize));
        return result;
    }

    /// <summary>
    /// Decodes the first complete frame in <paramref name="input"/>. Additional bytes belong to
    /// the next stream frame and are reported through <paramref name="consumed"/>.
    /// </summary>
    public static bool TryDecode(ReadOnlySpan<byte> input, out Packet? packet, out int consumed)
    {
        packet = null;
        consumed = 0;
        if (input.Length < HeaderSize)
        {
            return false;
        }
        var (command, length) = DecodeHeader(input[..HeaderSize]);
        if (input.Length < HeaderSize + length)
        {
            return false;
        }

        var body = input.Slice(HeaderSize, length).ToArray();
        try
        {
            packet = command == Command.NatMessage
                ? DecodeNatBody(body)
                : CommandToDecoder[command](body);
        }
        catch (InvalidDataException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw new InvalidDataException($"malformed body for command {command}", exception);
        }
        packet.Version = ProtocolVersion;
        consumed = HeaderSize + length;
        return true;
    }

    /// <summary>Decodes exactly one frame and rejects truncation or trailing bytes.</summary>
    public static Packet DecodeExact(ReadOnlySpan<byte> input)
    {
        if (!TryDecode(input, out var packet, out var consumed))
        {
            throw new InvalidDataException("frame is truncated");
        }
        if (consumed != input.Length)
        {
            throw new InvalidDataException("frame has trailing bytes");
        }
        return packet ?? throw new InvalidDataException("frame did not contain a packet");
    }

    public static (sbyte Command, int BodyLength) DecodeHeader(ReadOnlySpan<byte> header)
    {
        if (header.Length < HeaderSize)
        {
            throw new InvalidDataException("frame header is truncated");
        }
        var magic = BinaryPrimitives.ReadInt32BigEndian(header[..4]);
        if (magic != MagicNumber)
        {
            throw new InvalidDataException($"bad magic: 0x{magic:X8}");
        }
        if (header[4] != ProtocolVersion)
        {
            throw new InvalidDataException($"unsupported protocol version: {header[4]}");
        }
        if (header[5] != SerializerAlgorithm.CompactBinary)
        {
            throw new InvalidDataException($"unsupported serializer: {header[5]}");
        }
        var command = unchecked((sbyte)header[6]);
        if (!IsKnownCommand(command))
        {
            throw new InvalidDataException($"unknown command byte: {command}");
        }
        var length = BinaryPrimitives.ReadInt32BigEndian(header.Slice(7, 4));
        ValidateBodyLength(command, length);
        return (command, length);
    }

    public static void ValidateBodyLength(sbyte command, int length)
    {
        var maximum = command switch
        {
            Command.LoginRequest or Command.LoginResponse => PreAuthMaxFrameSize - HeaderSize,
            Command.MessageRequest or Command.MessageResponse => MaxMessageBodySize,
            _ => MaxFrameSize - HeaderSize,
        };
        if (length < 0 || length > maximum)
        {
            throw new InvalidDataException($"command {command} body exceeds limit: {length}/{maximum}");
        }
    }

    private static byte[] EncodeNatBody(NatMessagePacket nat)
    {
        if (NatMessageTypeExtensions.FromCode(nat.NatMessageType.Code()) is null)
        {
            throw new InvalidDataException($"unknown NAT message type: {(int)nat.NatMessageType}");
        }
        var metadata = SerializeMeta(nat.MetaData ?? new Dictionary<string, object?>());
        if (nat.MetaData is null or { Count: 0 })
        {
            metadata = Array.Empty<byte>();
        }
        if (metadata.Length > MaxNatMetadataSize)
        {
            throw new InvalidDataException("NAT metadata exceeds limit");
        }
        var data = nat.Data ?? Array.Empty<byte>();
        ValidateNatSemantics(nat.NatMessageType, nat.Flags, nat.StreamId, nat.Value, metadata.Length, data.Length);
        if ((long)NatBodyHeaderSize + metadata.Length + data.Length > MaxFrameSize - HeaderSize)
        {
            throw new InvalidDataException("NAT body exceeds frame limit");
        }
        var body = new byte[NatBodyHeaderSize + metadata.Length + data.Length];
        body[0] = checked((byte)nat.NatMessageType.Code());
        body[1] = nat.Flags;
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(2, 2), checked((ushort)metadata.Length));
        BinaryPrimitives.WriteUInt32BigEndian(body.AsSpan(4, 4), nat.StreamId);
        BinaryPrimitives.WriteUInt32BigEndian(body.AsSpan(8, 4), nat.Value);
        BinaryPrimitives.WriteUInt32BigEndian(body.AsSpan(12, 4), checked((uint)data.Length));
        metadata.CopyTo(body.AsSpan(NatBodyHeaderSize));
        data.CopyTo(body.AsSpan(NatBodyHeaderSize + metadata.Length));
        return body;
    }

    private static NatMessagePacket DecodeNatBody(ReadOnlySpan<byte> body)
    {
        if (body.Length < NatBodyHeaderSize)
        {
            throw new InvalidDataException("NAT_MESSAGE body too short");
        }
        var natType = NatMessageTypeExtensions.FromCode(body[0])
            ?? throw new InvalidDataException($"unknown NAT message type: {body[0]}");
        var flags = body[1];
        if ((flags & ~NatFlagEndStream) != 0)
        {
            throw new InvalidDataException($"unknown NAT flags: {flags}");
        }
        var metadataLength = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(2, 2));
        var streamId = BinaryPrimitives.ReadUInt32BigEndian(body.Slice(4, 4));
        var value = BinaryPrimitives.ReadUInt32BigEndian(body.Slice(8, 4));
        var dataLength = BinaryPrimitives.ReadUInt32BigEndian(body.Slice(12, 4));
        var expectedLength = (long)NatBodyHeaderSize + metadataLength + dataLength;
        if (expectedLength != body.Length)
        {
            throw new InvalidDataException("NAT_MESSAGE metadata/data length mismatch");
        }
        var metadata = metadataLength == 0
            ? new Dictionary<string, object?>()
            : DeserializeMeta(body.Slice(NatBodyHeaderSize, metadataLength))
                ?? throw new InvalidDataException("NAT metadata must be a JSON object");
        var data = dataLength == 0
            ? null
            : body.Slice(NatBodyHeaderSize + metadataLength, checked((int)dataLength)).ToArray();
        ValidateNatSemantics(natType, flags, streamId, value, metadataLength, checked((int)dataLength));
        return new NatMessagePacket
        {
            NatMessageType = natType,
            Flags = flags,
            StreamId = streamId,
            Value = value,
            MetaData = metadata,
            Data = data,
        };
    }

    private static void ValidateNatSemantics(
        NatMessageType type,
        byte flags,
        uint streamId,
        uint value,
        int metadataLength,
        int dataLength)
    {
        var streamFrame = type is NatMessageType.Open or NatMessageType.Fin or NatMessageType.Data
            or NatMessageType.Rst or NatMessageType.WindowUpdate;
        if (streamFrame == (streamId == 0))
        {
            throw new InvalidDataException(streamFrame
                ? "stream frame requires a non-zero stream id"
                : "connection frame requires stream id zero");
        }
        if (type != NatMessageType.Data && flags != 0)
        {
            throw new InvalidDataException("flags are only valid on DATA");
        }
        if (type == NatMessageType.Data && (metadataLength != 0 || value != 0))
        {
            throw new InvalidDataException("DATA cannot carry metadata/value");
        }
        if (type == NatMessageType.Fin && (dataLength != 0 || flags != 0))
        {
            throw new InvalidDataException("FIN cannot carry binary data/flags");
        }
        if (type == NatMessageType.WindowUpdate &&
            (metadataLength != 0 || dataLength != 0 || flags != 0))
        {
            throw new InvalidDataException("WINDOW_UPDATE cannot carry payload");
        }
        if (type == NatMessageType.WindowUpdate && value == 0)
        {
            throw new InvalidDataException("WINDOW_UPDATE credit must be positive");
        }
        if (type == NatMessageType.Fin && value != 0)
        {
            throw new InvalidDataException("FIN value must be zero");
        }
        if (type == NatMessageType.Rst && dataLength != 0)
        {
            throw new InvalidDataException("RST cannot carry binary data");
        }
        if (!streamFrame && (value != 0 || flags != 0 || dataLength != 0))
        {
            throw new InvalidDataException("connection control frame cannot carry stream value/data");
        }
    }

    private static bool IsKnownCommand(sbyte command) =>
        command == Command.NatMessage || CommandToDecoder.ContainsKey(command);

    private static byte[] SerializeMeta(Dictionary<string, object?> metaData)
    {
        var node = new JsonObject();
        foreach (var (key, value) in metaData)
        {
            node[key] = ToJsonNode(value);
        }
        return Encoding.UTF8.GetBytes(node.ToJsonString());
    }

    private static JsonNode? ToJsonNode(object? value) => value switch
    {
        null => null,
        string text => JsonValue.Create(text),
        bool boolean => JsonValue.Create(boolean),
        int integer => JsonValue.Create(integer),
        long longValue => JsonValue.Create(longValue),
        double doubleValue => JsonValue.Create(doubleValue),
        float floatValue => JsonValue.Create(floatValue),
        decimal decimalValue => JsonValue.Create(decimalValue),
        JsonNode jsonNode => jsonNode.DeepClone(),
        IEnumerable<string> strings => new JsonArray(strings
            .Select(static item => (JsonNode?)JsonValue.Create(item)).ToArray()),
        IEnumerable<object?> objects => new JsonArray(objects.Select(ToJsonNode).ToArray()),
        IReadOnlyDictionary<string, object?> map => new JsonObject(
            map.Select(static pair => KeyValuePair.Create(pair.Key, ToJsonNode(pair.Value)))),
        _ => JsonValue.Create(value.ToString()),
    };

    private static Dictionary<string, object?>? DeserializeMeta(ReadOnlySpan<byte> json)
    {
        if (json.IsEmpty)
        {
            throw new InvalidDataException("NAT JSON metadata is empty");
        }
        var node = JsonNode.Parse(Encoding.UTF8.GetString(json));
        if (node is not JsonObject obj)
        {
            return null;
        }
        var map = new Dictionary<string, object?>(obj.Count);
        foreach (var (key, value) in obj)
        {
            map[key] = FromJsonNode(value);
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
            if (value.TryGetValue<bool>(out var boolean)) return boolean;
            if (value.TryGetValue<long>(out var integer)) return integer;
            if (value.TryGetValue<double>(out var number)) return number;
            if (value.TryGetValue<string>(out var text)) return text;
        }
        if (node is JsonArray array)
        {
            return array.Select(FromJsonNode).ToList();
        }
        if (node is JsonObject obj)
        {
            return obj.ToDictionary(
                static pair => pair.Key,
                static pair => FromJsonNode(pair.Value),
                StringComparer.Ordinal);
        }
        throw new InvalidDataException("unsupported NAT metadata JSON value");
    }
}
