using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Specus.StunServer;

public sealed record StunAttribute(ushort Type, byte[] Value)
{
    public byte[] Value { get; init; } = Value.ToArray();
}

public readonly record struct ChangeRequest(bool ChangeIp, bool ChangePort);

public sealed class StunMessage
{
    public const uint MagicCookie = 0x2112A442;
    public const int HeaderBytes = 20;
    public const int TransactionIdBytes = 12;

    public const ushort BindingRequest = 0x0001;
    public const ushort BindingSuccess = 0x0101;
    public const ushort BindingError = 0x0111;

    public const ushort AttrMappedAddress = 0x0001;
    public const ushort AttrChangeRequest = 0x0003;
    public const ushort AttrErrorCode = 0x0009;
    public const ushort AttrUnknownAttributes = 0x000A;
    public const ushort AttrXorMappedAddress = 0x0020;
    public const ushort AttrPadding = 0x0026;
    public const ushort AttrResponsePort = 0x0027;
    public const ushort AttrSoftware = 0x8022;
    public const ushort AttrResponseOrigin = 0x802B;
    public const ushort AttrOtherAddress = 0x802C;

    public StunMessage(ushort type, byte[] transactionId, IReadOnlyList<StunAttribute>? attributes = null)
    {
        Type = type;
        TransactionId = transactionId.Length == TransactionIdBytes
            ? transactionId.ToArray()
            : throw new ArgumentException("transaction ID must contain 12 bytes", nameof(transactionId));
        Attributes = attributes?.Select(item => new StunAttribute(item.Type, item.Value)).ToList() ?? [];
    }

    public ushort Type { get; }
    public byte[] TransactionId { get; }
    public IReadOnlyList<StunAttribute> Attributes { get; }

    public static byte[] NewTransactionId()
    {
        var value = new byte[TransactionIdBytes];
        RandomNumberGenerator.Fill(value);
        return value;
    }

    public static StunMessage? Parse(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < HeaderBytes
            || (packet[0] & 0xC0) != 0
            || BinaryPrimitives.ReadUInt32BigEndian(packet[4..8]) != MagicCookie)
        {
            return null;
        }
        var messageLength = BinaryPrimitives.ReadUInt16BigEndian(packet[2..4]);
        var end = HeaderBytes + messageLength;
        if (end > packet.Length)
        {
            return null;
        }
        var transactionId = packet[8..20].ToArray();
        var attributes = new List<StunAttribute>();
        for (var offset = HeaderBytes; offset < end;)
        {
            if (end - offset < 4)
            {
                return null;
            }
            var type = BinaryPrimitives.ReadUInt16BigEndian(packet[offset..(offset + 2)]);
            var length = BinaryPrimitives.ReadUInt16BigEndian(packet[(offset + 2)..(offset + 4)]);
            offset += 4;
            if (length > end - offset)
            {
                return null;
            }
            attributes.Add(new StunAttribute(type, packet.Slice(offset, length).ToArray()));
            offset += length + AlignmentPadding(length);
            if (offset > end)
            {
                return null;
            }
        }
        return new StunMessage(
            BinaryPrimitives.ReadUInt16BigEndian(packet[..2]),
            transactionId,
            attributes);
    }

    public byte[] ToBytes()
    {
        var attributeBytes = Attributes.Sum(
            attribute => 4 + attribute.Value.Length + AlignmentPadding(attribute.Value.Length));
        if (attributeBytes > ushort.MaxValue)
        {
            throw new InvalidOperationException("STUN message attributes exceed 65535 bytes");
        }
        var packet = new byte[HeaderBytes + attributeBytes];
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(0, 2), Type);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), (ushort)attributeBytes);
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(4, 4), MagicCookie);
        TransactionId.CopyTo(packet.AsSpan(8, TransactionIdBytes));
        var offset = HeaderBytes;
        foreach (var attribute in Attributes)
        {
            if (attribute.Value.Length > ushort.MaxValue)
            {
                throw new InvalidOperationException(
                    $"STUN attribute 0x{attribute.Type:x4} exceeds 65535 bytes");
            }
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(offset, 2), attribute.Type);
            BinaryPrimitives.WriteUInt16BigEndian(
                packet.AsSpan(offset + 2, 2),
                (ushort)attribute.Value.Length);
            offset += 4;
            attribute.Value.CopyTo(packet.AsSpan(offset, attribute.Value.Length));
            offset += attribute.Value.Length + AlignmentPadding(attribute.Value.Length);
        }
        return packet;
    }

    public StunAttribute? First(ushort type) => Attributes.FirstOrDefault(item => item.Type == type);

    public bool Has(ushort type) => Attributes.Any(item => item.Type == type);

    public ChangeRequest? ChangeRequestValue()
    {
        var value = First(AttrChangeRequest)?.Value;
        if (value is not { Length: 4 })
        {
            return null;
        }
        var flags = BinaryPrimitives.ReadUInt32BigEndian(value);
        return new ChangeRequest((flags & 0x04) != 0, (flags & 0x02) != 0);
    }

    public int? ResponsePortValue()
    {
        var value = First(AttrResponsePort)?.Value;
        return value is { Length: 2 }
            ? BinaryPrimitives.ReadUInt16BigEndian(value)
            : null;
    }

    public int ErrorCodeValue()
    {
        var value = First(AttrErrorCode)?.Value;
        return value is { Length: >= 4 }
            ? (value[2] & 0x07) * 100 + value[3]
            : -1;
    }

    public IPEndPoint? MappedAddressValue() => DecodeAddress(First(AttrMappedAddress)?.Value);
    public IPEndPoint? XorMappedAddressValue() => DecodeXorAddress(First(AttrXorMappedAddress)?.Value);
    public IPEndPoint? ResponseOriginValue() => DecodeAddress(First(AttrResponseOrigin)?.Value);
    public IPEndPoint? OtherAddressValue() => DecodeAddress(First(AttrOtherAddress)?.Value);

    public static StunAttribute MappedAddress(IPEndPoint endpoint) =>
        new(AttrMappedAddress, EncodeAddress(endpoint));

    public static StunAttribute XorMappedAddress(IPEndPoint endpoint, byte[] transactionId) =>
        new(AttrXorMappedAddress, EncodeXorAddress(endpoint, transactionId));

    public static StunAttribute ResponseOrigin(IPEndPoint endpoint) =>
        new(AttrResponseOrigin, EncodeAddress(endpoint));

    public static StunAttribute OtherAddress(IPEndPoint endpoint) =>
        new(AttrOtherAddress, EncodeAddress(endpoint));

    public static StunAttribute ChangeRequestAttribute(bool changeIp, bool changePort)
    {
        var value = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(
            value,
            (changeIp ? 0x04U : 0U) | (changePort ? 0x02U : 0U));
        return new StunAttribute(AttrChangeRequest, value);
    }

    public static StunAttribute ResponsePort(int port)
    {
        if (port is < 0 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(port));
        }
        var value = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(value, (ushort)port);
        return new StunAttribute(AttrResponsePort, value);
    }

    public static StunAttribute Padding(int length) =>
        new(AttrPadding, new byte[Math.Clamp(length, 0, 65_503)]);

    public static StunAttribute Software(string value) =>
        new(AttrSoftware, Encoding.UTF8.GetBytes(value));

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

    public static StunAttribute UnknownAttributes(params ushort[] types)
    {
        var value = new byte[types.Length * 2];
        for (var index = 0; index < types.Length; index++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(index * 2, 2), types[index]);
        }
        return new StunAttribute(AttrUnknownAttributes, value);
    }

    internal static byte[] XorAddressValue(IPEndPoint endpoint, byte[] transactionId) =>
        EncodeXorAddress(endpoint, transactionId);

    private static byte[] EncodeAddress(IPEndPoint endpoint)
    {
        var address = endpoint.Address.AddressFamily == AddressFamily.InterNetworkV6
            ? endpoint.Address.GetAddressBytes()
            : endpoint.Address.MapToIPv4().GetAddressBytes();
        var value = new byte[address.Length == 4 ? 8 : 20];
        value[1] = address.Length == 4 ? (byte)0x01 : (byte)0x02;
        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(2, 2), (ushort)endpoint.Port);
        address.CopyTo(value.AsSpan(4));
        return value;
    }

    private static IPEndPoint? DecodeAddress(byte[]? value)
    {
        if (value is null || (value.Length != 8 && value.Length != 20))
        {
            return null;
        }
        var port = BinaryPrimitives.ReadUInt16BigEndian(value.AsSpan(2, 2));
        return value[1] switch
        {
            0x01 when value.Length == 8 => new IPEndPoint(new IPAddress(value.AsSpan(4, 4)), port),
            0x02 when value.Length == 20 => new IPEndPoint(new IPAddress(value.AsSpan(4, 16)), port),
            _ => null,
        };
    }

    private static byte[] EncodeXorAddress(IPEndPoint endpoint, byte[] transactionId)
    {
        var value = EncodeAddress(endpoint);
        var port = BinaryPrimitives.ReadUInt16BigEndian(value.AsSpan(2, 2));
        BinaryPrimitives.WriteUInt16BigEndian(
            value.AsSpan(2, 2),
            (ushort)(port ^ (MagicCookie >> 16)));
        Span<byte> mask = stackalloc byte[16];
        BinaryPrimitives.WriteUInt32BigEndian(mask[..4], MagicCookie);
        transactionId.CopyTo(mask[4..]);
        for (var index = 4; index < value.Length; index++)
        {
            value[index] ^= mask[index - 4];
        }
        return value;
    }

    private IPEndPoint? DecodeXorAddress(byte[]? value)
    {
        if (value is null || (value.Length != 8 && value.Length != 20))
        {
            return null;
        }
        var decoded = value.ToArray();
        var port = BinaryPrimitives.ReadUInt16BigEndian(decoded.AsSpan(2, 2));
        BinaryPrimitives.WriteUInt16BigEndian(
            decoded.AsSpan(2, 2),
            (ushort)(port ^ (MagicCookie >> 16)));
        Span<byte> mask = stackalloc byte[16];
        BinaryPrimitives.WriteUInt32BigEndian(mask[..4], MagicCookie);
        TransactionId.CopyTo(mask[4..]);
        for (var index = 4; index < decoded.Length; index++)
        {
            decoded[index] ^= mask[index - 4];
        }
        return DecodeAddress(decoded);
    }

    private static int AlignmentPadding(int length) => (4 - length % 4) % 4;
}
