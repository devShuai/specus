using System.Text;

namespace Specus.Protocol.Codec;

internal interface IValueCodec
{
    void Write(CompactWriter writer, object? value);
    object? Read(CompactReader reader);
}

internal sealed class StringValueCodec : IValueCodec
{
    public void Write(CompactWriter writer, object? value) => writer.WriteString((string?)value);
    public object? Read(CompactReader reader) => reader.ReadString();
}

internal sealed class BooleanValueCodec : IValueCodec
{
    public void Write(CompactWriter writer, object? value) =>
        writer.WriteByte((value is true) ? (byte)1 : (byte)0);

    public object? Read(CompactReader reader)
    {
        var raw = reader.ReadUnsignedByte();
        if (raw > 1)
        {
            throw new InvalidDataException($"invalid boolean value: {raw}");
        }
        return raw == 1;
    }
}

internal sealed class IntegerValueCodec : IValueCodec
{
    public void Write(CompactWriter writer, object? value) => writer.WriteVarInt((int)value!);
    public object? Read(CompactReader reader) => reader.ReadVarInt();
}

internal sealed class LongValueCodec : IValueCodec
{
    public void Write(CompactWriter writer, object? value)
    {
        if (value is null)
        {
            writer.WriteByte(0);
            return;
        }
        writer.WriteByte(1);
        writer.WriteVarLong(ZigZagEncode((long)value));
    }

    public object? Read(CompactReader reader)
    {
        var marker = reader.ReadUnsignedByte();
        return marker switch
        {
            0 => null,
            1 => ZigZagDecode(reader.ReadVarLong()),
            _ => throw new InvalidDataException("invalid long type"),
        };
    }

    private static long ZigZagEncode(long value) => (value << 1) ^ (value >> 63);

    private static long ZigZagDecode(long value)
    {
        var unsigned = (long)((ulong)value >> 1);
        return unsigned ^ -(value & 1L);
    }
}

internal sealed class ByteArrayValueCodec : IValueCodec
{
    public void Write(CompactWriter writer, object? value) => writer.WriteByteArray((byte[]?)value);
    public object? Read(CompactReader reader) => reader.ReadByteArray();
}

internal sealed class NumericStringValueCodec : IValueCodec
{
    public void Write(CompactWriter writer, object? value)
    {
        if (value is null)
        {
            writer.WriteByte(0);
            return;
        }
        var str = (string)value;
        if (long.TryParse(str, System.Globalization.NumberStyles.AllowLeadingSign,
                System.Globalization.CultureInfo.InvariantCulture, out var longValue))
        {
            writer.WriteByte(1);
            writer.WriteVarLong(ZigZagEncode(longValue));
        }
        else
        {
            writer.WriteByte(2);
            writer.WriteString(str);
        }
    }

    public object? Read(CompactReader reader)
    {
        var marker = reader.ReadUnsignedByte();
        return marker switch
        {
            0 => null,
            1 => ZigZagDecode(reader.ReadVarLong()).ToString(System.Globalization.CultureInfo.InvariantCulture),
            2 => reader.ReadString(),
            _ => throw new InvalidDataException("invalid numeric string type"),
        };
    }

    private static long ZigZagEncode(long value) => (value << 1) ^ (value >> 63);

    private static long ZigZagDecode(long value)
    {
        // Java: value >>> 1 ^ -(value & 1) — match unsigned right shift.
        var unsigned = (long)((ulong)value >> 1);
        return unsigned ^ -(value & 1L);
    }
}

internal sealed class FixedHexStringValueCodec : IValueCodec
{
    private readonly int _byteLength;

    internal FixedHexStringValueCodec(int byteLength)
    {
        _byteLength = byteLength;
    }

    public void Write(CompactWriter writer, object? value)
    {
        var str = (string?)value;
        if (str is null)
        {
            writer.WriteByte(0);
        }
        else if (IsFixedHex(str, false))
        {
            writer.WriteByte(1);
            writer.WriteBytes(DecodeHex(str));
        }
        else if (IsFixedHex(str, true))
        {
            writer.WriteByte(2);
            writer.WriteBytes(DecodeHex(str));
        }
        else
        {
            writer.WriteByte(3);
            writer.WriteString(str);
        }
    }

    public object? Read(CompactReader reader)
    {
        var marker = reader.ReadUnsignedByte();
        return marker switch
        {
            0 => null,
            1 => EncodeHex(reader.ReadBytes(_byteLength), false),
            2 => EncodeHex(reader.ReadBytes(_byteLength), true),
            3 => reader.ReadString(),
            _ => throw new InvalidDataException("invalid hexadecimal string type"),
        };
    }

    private bool IsFixedHex(string value, bool uppercase)
    {
        if (value.Length != _byteLength * 2)
        {
            return false;
        }
        foreach (var ch in value)
        {
            if (HexDigit(ch) < 0)
            {
                return false;
            }
            if (char.IsLetter(ch) && char.IsUpper(ch) != uppercase)
            {
                return false;
            }
        }
        return true;
    }

    private static int HexDigit(char ch) => ch switch
    {
        >= '0' and <= '9' => ch - '0',
        >= 'a' and <= 'f' => ch - 'a' + 10,
        >= 'A' and <= 'F' => ch - 'A' + 10,
        _ => -1,
    };

    private static byte[] DecodeHex(string value)
    {
        var bytes = new byte[value.Length / 2];
        for (var i = 0; i < bytes.Length; i++)
        {
            var high = HexDigit(value[i * 2]);
            var low = HexDigit(value[i * 2 + 1]);
            bytes[i] = (byte)((high << 4) | low);
        }
        return bytes;
    }

    private static string EncodeHex(byte[] bytes, bool uppercase)
    {
        var alphabet = uppercase ? "0123456789ABCDEF" : "0123456789abcdef";
        var sb = new StringBuilder(bytes.Length * 2);
        foreach (var b in bytes)
        {
            sb.Append(alphabet[(b >> 4) & 0x0F]);
            sb.Append(alphabet[b & 0x0F]);
        }
        return sb.ToString();
    }
}

internal sealed class UuidStringValueCodec : IValueCodec
{
    public void Write(CompactWriter writer, object? value)
    {
        var str = (string?)value;
        if (str is null)
        {
            writer.WriteByte(0);
            return;
        }
        if (TryParseJavaUuid(str, out var msb, out var lsb))
        {
            writer.WriteByte(1);
            writer.WriteLong(msb);
            writer.WriteLong(lsb);
            return;
        }
        writer.WriteByte(2);
        writer.WriteString(str);
    }

    public object? Read(CompactReader reader)
    {
        var marker = reader.ReadUnsignedByte();
        return marker switch
        {
            0 => null,
            1 => FormatJavaUuid(reader.ReadLong(), reader.ReadLong()),
            2 => reader.ReadString(),
            _ => throw new InvalidDataException("invalid UUID string type"),
        };
    }

    /// <summary>
    /// Java's <c>UUID.fromString</c> requires the canonical 8-4-4-4-12 layout and round-trips
    /// to the same string. We mimic that strictness so we only take the binary path when the
    /// string would round-trip on the Java side.
    /// </summary>
    private static bool TryParseJavaUuid(string value, out long msb, out long lsb)
    {
        msb = 0;
        lsb = 0;
        if (!Guid.TryParseExact(value, "D", out var guid))
        {
            return false;
        }
        // Java toString() is lower-case hex; reject upper-case to match Java's equality check.
        if (!guid.ToString("D").Equals(value, StringComparison.Ordinal))
        {
            return false;
        }
        // Big-endian byte layout: GUID has its first three groups in little-endian on Windows.
        Span<byte> bytes = stackalloc byte[16];
        if (!guid.TryWriteBytes(bytes, bigEndian: true, out _))
        {
            return false;
        }
        msb = System.Buffers.Binary.BinaryPrimitives.ReadInt64BigEndian(bytes[..8]);
        lsb = System.Buffers.Binary.BinaryPrimitives.ReadInt64BigEndian(bytes[8..]);
        return true;
    }

    private static string FormatJavaUuid(long msb, long lsb)
    {
        Span<byte> bytes = stackalloc byte[16];
        System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(bytes[..8], msb);
        System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(bytes[8..], lsb);
        return new Guid(bytes, bigEndian: true).ToString("D");
    }
}

internal sealed class HttpMethodValueCodec : IValueCodec
{
    private static readonly string[] Methods = { "GET", "POST", "PUT", "DELETE" };

    public void Write(CompactWriter writer, object? value)
    {
        var method = (string?)value;
        if (method is null)
        {
            writer.WriteByte(0);
            return;
        }
        var idx = Array.IndexOf(Methods, method);
        if (idx >= 0)
        {
            writer.WriteByte((byte)(idx + 1));
        }
        else
        {
            writer.WriteByte((byte)(Methods.Length + 1));
            writer.WriteString(method);
        }
    }

    public object? Read(CompactReader reader)
    {
        var type = reader.ReadUnsignedByte();
        if (type == 0)
        {
            return null;
        }
        if (type <= Methods.Length)
        {
            return Methods[type - 1];
        }
        if (type == Methods.Length + 1)
        {
            return reader.ReadString();
        }
        throw new InvalidDataException("invalid HTTP method type");
    }
}

internal sealed class MessageTypeValueCodec : IValueCodec
{
    public void Write(CompactWriter writer, object? value)
    {
        if (value is null)
        {
            writer.WriteVarInt(0);
            return;
        }
        var type = (MessageType)value;
        if (!Enum.IsDefined(type))
        {
            throw new InvalidDataException($"unknown message type: {(int)type}");
        }
        writer.WriteVarInt((int)type);
    }

    public object? Read(CompactReader reader)
    {
        var wireId = reader.ReadVarInt();
        if (wireId == 0)
        {
            return null;
        }
        return Enum.IsDefined(typeof(MessageType), wireId)
            ? (MessageType)wireId
            : throw new InvalidDataException($"unknown message type wire id: {wireId}");
    }
}

internal sealed class StringMapValueCodec : IValueCodec
{
    public void Write(CompactWriter writer, object? value)
    {
        if (value is null)
        {
            writer.WriteVarInt(0);
            return;
        }
        var map = (Dictionary<string, string>)value;
        writer.WriteVarInt(map.Count + 1);
        foreach (var kv in map)
        {
            writer.WriteString(kv.Key);
            writer.WriteString(kv.Value);
        }
    }

    public object? Read(CompactReader reader)
    {
        var sizeMarker = reader.ReadVarInt();
        if (sizeMarker == 0)
        {
            return null;
        }
        // Preserves insertion order — Dictionary<string,string> in modern .NET keeps insertion
        // order on enumeration, matching Java's LinkedHashMap.
        var map = new Dictionary<string, string>(sizeMarker - 1);
        for (var i = 0; i < sizeMarker - 1; i++)
        {
            var key = reader.ReadString() ?? throw new InvalidDataException("null map key");
            var val = reader.ReadString() ?? throw new InvalidDataException("null map value");
            map[key] = val;
        }
        return map;
    }
}

internal sealed class StringListValueCodec : IValueCodec
{
    public void Write(CompactWriter writer, object? value)
    {
        if (value is null)
        {
            writer.WriteVarInt(0);
            return;
        }
        var list = (List<string>)value;
        writer.WriteVarInt(list.Count + 1);
        foreach (var item in list)
        {
            writer.WriteString(item);
        }
    }

    public object? Read(CompactReader reader)
    {
        var sizeMarker = reader.ReadVarInt();
        if (sizeMarker == 0)
        {
            return null;
        }
        var list = new List<string>(sizeMarker - 1);
        for (var i = 0; i < sizeMarker - 1; i++)
        {
            list.Add(reader.ReadString() ?? throw new InvalidDataException("null list element"));
        }
        return list;
    }
}
