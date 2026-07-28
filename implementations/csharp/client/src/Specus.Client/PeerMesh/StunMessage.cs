using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Specus.Client.PeerMesh;

internal sealed class StunMessage
{
    public const uint MagicCookie = 0x2112A442;
    public const int HeaderBytes = 20;
    public const int TransactionIdBytes = 12;

    public const ushort BindingRequest = 0x0001;
    public const ushort BindingSuccess = 0x0101;
    public const ushort BindingError = 0x0111;
    public const ushort AllocateRequest = 0x0003;
    public const ushort AllocateSuccess = 0x0103;
    public const ushort AllocateError = 0x0113;
    public const ushort RefreshRequest = 0x0004;
    public const ushort RefreshSuccess = 0x0104;
    public const ushort RefreshError = 0x0114;
    public const ushort CreatePermissionRequest = 0x0008;
    public const ushort CreatePermissionSuccess = 0x0108;
    public const ushort CreatePermissionError = 0x0118;
    public const ushort ChannelBindRequest = 0x0009;
    public const ushort ChannelBindSuccess = 0x0109;
    public const ushort ChannelBindError = 0x0119;
    public const ushort SendIndication = 0x0016;
    public const ushort DataIndication = 0x0017;

    public const ushort AttrMappedAddress = 0x0001;
    public const ushort AttrChangeRequest = 0x0003;
    public const ushort AttrUsername = 0x0006;
    public const ushort AttrMessageIntegrity = 0x0008;
    public const ushort AttrErrorCode = 0x0009;
    public const ushort AttrUnknownAttributes = 0x000A;
    public const ushort AttrLifetime = 0x000D;
    public const ushort AttrChannelNumber = 0x000C;
    public const ushort AttrXorPeerAddress = 0x0012;
    public const ushort AttrData = 0x0013;
    public const ushort AttrRealm = 0x0014;
    public const ushort AttrNonce = 0x0015;
    public const ushort AttrXorRelayedAddress = 0x0016;
    public const ushort AttrRequestedTransport = 0x0019;
    public const ushort AttrXorMappedAddress = 0x0020;
    public const ushort AttrSoftware = 0x8022;
    public const ushort AttrResponseOrigin = 0x802B;
    public const ushort AttrOtherAddress = 0x802C;

    private const byte TransportUdp = 17;

    public StunMessage(ushort type, byte[] transactionId, IReadOnlyList<StunAttribute>? attributes = null)
    {
        Type = type;
        TransactionId = NormalizeTransactionId(transactionId);
        Attributes = attributes?.Select(item => new StunAttribute(item.Type, item.Value)).ToList() ?? [];
    }

    public ushort Type { get; }
    public byte[] TransactionId { get; }
    public IReadOnlyList<StunAttribute> Attributes { get; }
    public string TransactionIdHex => Convert.ToHexString(TransactionId).ToLowerInvariant();

    public static StunMessage Of(ushort type, byte[] transactionId, params StunAttribute[] attributes) =>
        new(type, transactionId, attributes);

    public static byte[] NewTransactionId()
    {
        var bytes = new byte[TransactionIdBytes];
        RandomNumberGenerator.Fill(bytes);
        return bytes;
    }

    public static bool LooksLike(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < HeaderBytes || (packet[0] & 0xC0) != 0)
        {
            return false;
        }
        var declaredLength = BinaryPrimitives.ReadUInt16BigEndian(packet[2..4]);
        var cookie = BinaryPrimitives.ReadUInt32BigEndian(packet[4..8]);
        return cookie == MagicCookie && HeaderBytes + declaredLength == packet.Length;
    }

    public static StunMessage? Parse(ReadOnlySpan<byte> packet)
    {
        if (!LooksLike(packet))
        {
            return null;
        }
        var type = BinaryPrimitives.ReadUInt16BigEndian(packet[..2]);
        var length = BinaryPrimitives.ReadUInt16BigEndian(packet[2..4]);
        var end = HeaderBytes + length;
        var transactionId = packet[8..20].ToArray();
        var attributes = new List<StunAttribute>();
        var offset = HeaderBytes;
        while (offset < end)
        {
            if (end - offset < 4)
            {
                return null;
            }
            var attrType = BinaryPrimitives.ReadUInt16BigEndian(packet[offset..(offset + 2)]);
            var attrLength = BinaryPrimitives.ReadUInt16BigEndian(packet[(offset + 2)..(offset + 4)]);
            offset += 4;
            if (attrLength > end - offset)
            {
                return null;
            }
            attributes.Add(new StunAttribute(attrType, packet.Slice(offset, attrLength).ToArray()));
            offset += attrLength + Padding(attrLength);
        }
        return new StunMessage(type, transactionId, attributes);
    }

    public byte[] ToBytes()
    {
        return ToBytes(null);
    }

    public byte[] ToBytes(byte[]? messageIntegrityKey)
    {
        var length = Attributes.Sum(attr => 4 + attr.Value.Length + Padding(attr.Value.Length));
        if (messageIntegrityKey is { Length: > 0 })
        {
            var beforeIntegrity = Serialize(length + 24, Attributes);
            using var hmac = new HMACSHA1(messageIntegrityKey);
            var digest = hmac.ComputeHash(beforeIntegrity);
            var packetWithIntegrity = new byte[beforeIntegrity.Length + 24];
            beforeIntegrity.CopyTo(packetWithIntegrity, 0);
            var offset = beforeIntegrity.Length;
            BinaryPrimitives.WriteUInt16BigEndian(packetWithIntegrity.AsSpan(offset, 2), AttrMessageIntegrity);
            BinaryPrimitives.WriteUInt16BigEndian(packetWithIntegrity.AsSpan(offset + 2, 2), (ushort)digest.Length);
            digest.CopyTo(packetWithIntegrity.AsSpan(offset + 4));
            return packetWithIntegrity;
        }
        return Serialize(length, Attributes);
    }

    private byte[] Serialize(int declaredLength, IReadOnlyList<StunAttribute> attributes)
    {
        var length = attributes.Sum(attr => 4 + attr.Value.Length + Padding(attr.Value.Length));
        var packet = new byte[HeaderBytes + length];
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(0, 2), Type);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), (ushort)declaredLength);
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(4, 4), MagicCookie);
        TransactionId.CopyTo(packet.AsSpan(8, TransactionIdBytes));
        var offset = HeaderBytes;
        foreach (var attr in attributes)
        {
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(offset, 2), attr.Type);
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(offset + 2, 2), (ushort)attr.Value.Length);
            offset += 4;
            attr.Value.CopyTo(packet.AsSpan(offset, attr.Value.Length));
            offset += attr.Value.Length + Padding(attr.Value.Length);
        }
        return packet;
    }

    public StunAttribute? First(ushort type) => Attributes.FirstOrDefault(attr => attr.Type == type);
    public string? TextAttribute(ushort type)
    {
        var value = First(type)?.Value;
        return value is { Length: > 0 } ? Encoding.UTF8.GetString(value) : null;
    }

    public int ErrorCode()
    {
        var value = First(AttrErrorCode)?.Value;
        if (value is not { Length: >= 4 })
        {
            return -1;
        }
        return (value[2] & 0x07) * 100 + value[3];
    }

    public IReadOnlyList<ushort> UnknownAttributes()
    {
        var value = First(AttrUnknownAttributes)?.Value;
        if (value is not { Length: >= 2 })
        {
            return [];
        }
        var result = new List<ushort>(value.Length / 2);
        for (var offset = 0; offset + 2 <= value.Length; offset += 2)
        {
            result.Add(BinaryPrimitives.ReadUInt16BigEndian(value.AsSpan(offset, 2)));
        }
        return result;
    }

    public StunChangeRequest? ChangeRequest()
    {
        var value = First(AttrChangeRequest)?.Value;
        if (value is not { Length: 4 })
        {
            return null;
        }
        var flags = BinaryPrimitives.ReadUInt32BigEndian(value);
        return new StunChangeRequest((flags & 0x04) != 0, (flags & 0x02) != 0);
    }

    public IPEndPoint? MappedAddress() => DecodeAddress(First(AttrMappedAddress)?.Value);
    public IPEndPoint? XorMappedAddress() => DecodeXorAddress(First(AttrXorMappedAddress)?.Value);
    public IPEndPoint? XorRelayedAddress() => DecodeXorAddress(First(AttrXorRelayedAddress)?.Value);
    public IPEndPoint? XorPeerAddress() => DecodeXorAddress(First(AttrXorPeerAddress)?.Value);
    public IPEndPoint? ResponseOrigin() => DecodeAddress(First(AttrResponseOrigin)?.Value);
    public IPEndPoint? OtherAddress() => DecodeAddress(First(AttrOtherAddress)?.Value);
    public IPEndPoint? LegacyXorResponseOrigin() => DecodeXorAddress(First(AttrResponseOrigin)?.Value);
    public IPEndPoint? LegacyXorOtherAddress() => DecodeXorAddress(First(AttrOtherAddress)?.Value);
    public byte[]? Data() => First(AttrData)?.Value.ToArray();

    public long LifetimeSeconds(long fallback)
    {
        var value = First(AttrLifetime)?.Value;
        return value is { Length: 4 } ? BinaryPrimitives.ReadUInt32BigEndian(value) : fallback;
    }

    public ushort? ChannelNumber()
    {
        var value = First(AttrChannelNumber)?.Value;
        if (value is not { Length: 4 })
        {
            return null;
        }
        var channel = BinaryPrimitives.ReadUInt16BigEndian(value);
        return channel is >= TurnChannelData.MinChannel and <= TurnChannelData.MaxChannel ? channel : null;
    }

    public bool RequestedUdpTransport()
    {
        var value = First(AttrRequestedTransport)?.Value;
        return value is { Length: > 0 } && value[0] == TransportUdp;
    }

    public static StunAttribute XorMappedAddress(IPEndPoint endpoint, byte[] transactionId) =>
        new(AttrXorMappedAddress, EncodeXorAddress(endpoint, transactionId));

    public static StunAttribute XorRelayedAddress(IPEndPoint endpoint, byte[] transactionId) =>
        new(AttrXorRelayedAddress, EncodeXorAddress(endpoint, transactionId));

    public static StunAttribute XorPeerAddress(IPEndPoint endpoint, byte[] transactionId) =>
        new(AttrXorPeerAddress, EncodeXorAddress(endpoint, transactionId));

    public static StunAttribute MappedAddress(IPEndPoint endpoint) =>
        new(AttrMappedAddress, EncodeAddress(endpoint));

    public static StunAttribute OtherAddress(IPEndPoint endpoint, byte[] transactionId) =>
        new(AttrOtherAddress, EncodeAddress(endpoint));

    public static StunAttribute ResponseOrigin(IPEndPoint endpoint, byte[] transactionId) =>
        new(AttrResponseOrigin, EncodeAddress(endpoint));

    public static StunAttribute ChangeRequest(bool changeIp, bool changePort)
    {
        var flags = (changeIp ? 0x04u : 0u) | (changePort ? 0x02u : 0u);
        var value = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(value, flags);
        return new StunAttribute(AttrChangeRequest, value);
    }

    public static StunAttribute UnknownAttributes(params ushort[] types)
    {
        var normalized = types ?? [];
        var value = new byte[normalized.Length * 2];
        for (var index = 0; index < normalized.Length; index++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(index * 2, 2), normalized[index]);
        }
        return new StunAttribute(AttrUnknownAttributes, value);
    }

    public static StunAttribute Data(byte[] payload) => new(AttrData, payload);

    public static StunAttribute ChannelNumber(ushort channel)
    {
        var value = new byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(value, channel);
        return new StunAttribute(AttrChannelNumber, value);
    }

    public static StunAttribute Lifetime(long seconds)
    {
        var normalized = Math.Clamp(seconds, 0L, uint.MaxValue);
        var value = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(value, (uint)normalized);
        return new StunAttribute(AttrLifetime, value);
    }

    public static StunAttribute RequestedUdpTransportAttribute() =>
        new(AttrRequestedTransport, [TransportUdp, 0, 0, 0]);

    public static StunAttribute Software(string value) =>
        new(AttrSoftware, Encoding.UTF8.GetBytes(value));

    public static StunAttribute Username(string value) =>
        new(AttrUsername, Encoding.UTF8.GetBytes(value));

    public static StunAttribute Realm(string value) =>
        new(AttrRealm, Encoding.UTF8.GetBytes(value));

    public static StunAttribute Nonce(string value) =>
        new(AttrNonce, Encoding.UTF8.GetBytes(value));

    public static StunAttribute ErrorCode(int code, string reason)
    {
        var klass = Math.Clamp(code / 100, 3, 6);
        var number = Math.Clamp(code % 100, 0, 99);
        var reasonBytes = Encoding.UTF8.GetBytes(reason);
        var value = new byte[4 + reasonBytes.Length];
        value[2] = (byte)klass;
        value[3] = (byte)number;
        reasonBytes.CopyTo(value.AsSpan(4));
        return new StunAttribute(AttrErrorCode, value);
    }

    private static IPEndPoint? DecodeAddress(byte[]? value)
    {
        if (value is null || (value.Length != 8 && value.Length != 20))
        {
            return null;
        }
        var port = BinaryPrimitives.ReadUInt16BigEndian(value.AsSpan(2, 2));
        if (value[1] == 0x01 && value.Length == 8)
        {
            return new IPEndPoint(new IPAddress(value.AsSpan(4, 4)), port);
        }
        if (value[1] == 0x02 && value.Length == 20)
        {
            return new IPEndPoint(new IPAddress(value.AsSpan(4, 16)), port);
        }
        return null;
    }

    private IPEndPoint? DecodeXorAddress(byte[]? value)
    {
        if (value is null || (value.Length != 8 && value.Length != 20))
        {
            return null;
        }
        var port = BinaryPrimitives.ReadUInt16BigEndian(value.AsSpan(2, 2)) ^ (MagicCookie >> 16);
        if (value[1] == 0x01 && value.Length >= 8)
        {
            var raw = new byte[4];
            Span<byte> cookie = [0x21, 0x12, 0xA4, 0x42];
            for (var i = 0; i < raw.Length; i++)
            {
                raw[i] = (byte)(value[4 + i] ^ cookie[i]);
            }
            return new IPEndPoint(new IPAddress(raw), (int)port);
        }
        if (value[1] == 0x02 && value.Length >= 20)
        {
            var mask = new byte[16];
            BinaryPrimitives.WriteUInt32BigEndian(mask.AsSpan(0, 4), MagicCookie);
            TransactionId.CopyTo(mask.AsSpan(4));
            var raw = new byte[16];
            for (var i = 0; i < raw.Length; i++)
            {
                raw[i] = (byte)(value[4 + i] ^ mask[i]);
            }
            return new IPEndPoint(new IPAddress(raw), (int)port);
        }
        return null;
    }

    private static byte[] EncodeXorAddress(IPEndPoint endpoint, byte[] transactionId)
    {
        var address = endpoint.Address.AddressFamily == AddressFamily.InterNetworkV6
            ? endpoint.Address.GetAddressBytes()
            : endpoint.Address.MapToIPv4().GetAddressBytes();
        var result = new byte[address.Length == 4 ? 8 : 20];
        result[1] = address.Length == 4 ? (byte)0x01 : (byte)0x02;
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(2, 2),
            (ushort)(endpoint.Port ^ (MagicCookie >> 16)));
        if (address.Length == 4)
        {
            Span<byte> cookie = [0x21, 0x12, 0xA4, 0x42];
            for (var i = 0; i < address.Length; i++)
            {
                result[4 + i] = (byte)(address[i] ^ cookie[i]);
            }
        }
        else
        {
            var mask = new byte[16];
            BinaryPrimitives.WriteUInt32BigEndian(mask.AsSpan(0, 4), MagicCookie);
            NormalizeTransactionId(transactionId).CopyTo(mask.AsSpan(4));
            for (var i = 0; i < address.Length; i++)
            {
                result[4 + i] = (byte)(address[i] ^ mask[i]);
            }
        }
        return result;
    }

    private static byte[] EncodeAddress(IPEndPoint endpoint)
    {
        var address = endpoint.Address.AddressFamily == AddressFamily.InterNetworkV6
            ? endpoint.Address.GetAddressBytes()
            : endpoint.Address.MapToIPv4().GetAddressBytes();
        var result = new byte[address.Length == 4 ? 8 : 20];
        result[1] = address.Length == 4 ? (byte)0x01 : (byte)0x02;
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(2, 2), (ushort)endpoint.Port);
        address.CopyTo(result.AsSpan(4));
        return result;
    }

    private static byte[] NormalizeTransactionId(byte[]? transactionId)
    {
        if (transactionId is { Length: TransactionIdBytes })
        {
            return transactionId.ToArray();
        }
        return NewTransactionId();
    }

    private static int Padding(int length) => (4 - length % 4) % 4;
}

internal sealed record StunAttribute(ushort Type, byte[] Value)
{
    public byte[] Value { get; init; } = Value.ToArray();
}

internal sealed record StunChangeRequest(bool ChangeIp, bool ChangePort);
