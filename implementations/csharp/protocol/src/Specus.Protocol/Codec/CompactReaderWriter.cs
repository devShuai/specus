using System.Buffers.Binary;
using System.Text;

namespace Specus.Protocol.Codec;

/// <summary>
/// Mirrors the <c>CompactOutput</c> private class in <c>CompactBinarySerializer.java</c>.
/// Field layout helpers — varint, UTF-8 string, byte array — must match Java byte-for-byte.
/// </summary>
internal sealed class CompactWriter
{
    private readonly MemoryStream _output = new();

    internal long Length => _output.Length;

    internal void WriteByte(byte value) => _output.WriteByte(value);

    internal void WriteBytes(ReadOnlySpan<byte> bytes) => _output.Write(bytes);

    internal void WriteString(string? value)
    {
        if (value is null)
        {
            WriteVarInt(0);
            return;
        }
        var bytes = Encoding.UTF8.GetBytes(value);
        WriteVarInt(bytes.Length + 1);
        WriteBytes(bytes);
    }

    internal void WriteByteArray(byte[]? value)
    {
        if (value is null)
        {
            WriteVarInt(0);
            return;
        }
        WriteVarInt(value.Length + 1);
        WriteBytes(value);
    }

    internal void WriteVarInt(int value)
    {
        if (value < 0)
        {
            throw new ArgumentException("variable-length integer cannot be negative", nameof(value));
        }
        // Java semantics: write 7 bits at a time, top bit = continuation.
        var unsigned = (uint)value;
        while ((unsigned & ~0x7Fu) != 0)
        {
            WriteByte((byte)((unsigned & 0x7Fu) | 0x80u));
            unsigned >>= 7;
        }
        WriteByte((byte)unsigned);
    }

    internal void WriteVarLong(long value)
    {
        // Mirrors Java's writeVarLong — operates on the raw 64-bit pattern. Negative
        // longs would require 10 bytes; in practice this only sees zigzag-encoded values.
        var unsigned = unchecked((ulong)value);
        while ((unsigned & ~0x7FuL) != 0)
        {
            WriteByte((byte)((unsigned & 0x7FuL) | 0x80uL));
            unsigned >>= 7;
        }
        WriteByte((byte)unsigned);
    }

    internal void WriteLong(long value)
    {
        Span<byte> buf = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(buf, value);
        WriteBytes(buf);
    }

    internal byte[] ToByteArray() => _output.ToArray();
}

/// <summary>
/// Mirrors <c>CompactInput</c>. Methods throw <see cref="InvalidDataException"/> on truncation
/// to match Java's <c>IllegalArgumentException</c> in spirit (bounded at the codec edge).
/// </summary>
internal sealed class CompactReader
{
    private readonly byte[] _bytes;
    private int _index;

    internal CompactReader(byte[] bytes)
    {
        _bytes = bytes;
    }

    internal int ReadUnsignedByte()
    {
        EnsureRemaining(1);
        return _bytes[_index++];
    }

    internal byte[] ReadBytes(int length)
    {
        if (length < 0 || _bytes.Length - _index < length)
        {
            throw new InvalidDataException("unexpected end of compact binary payload");
        }
        var result = _bytes.AsSpan(_index, length).ToArray();
        _index += length;
        return result;
    }

    internal string? ReadString()
    {
        var lengthMarker = ReadVarInt();
        if (lengthMarker == 0)
        {
            return null;
        }
        return Encoding.UTF8.GetString(ReadBytes(lengthMarker - 1));
    }

    internal byte[]? ReadByteArray()
    {
        var lengthMarker = ReadVarInt();
        return lengthMarker == 0 ? null : ReadBytes(lengthMarker - 1);
    }

    internal int ReadVarInt()
    {
        var value = 0;
        for (var shift = 0; shift < 32; shift += 7)
        {
            var b = ReadUnsignedByte();
            value |= (b & 0x7F) << shift;
            if ((b & 0x80) == 0)
            {
                return value;
            }
        }
        throw new InvalidDataException("variable-length integer is too long");
    }

    internal long ReadVarLong()
    {
        long value = 0;
        for (var shift = 0; shift < 64; shift += 7)
        {
            var b = ReadUnsignedByte();
            value |= (long)(b & 0x7F) << shift;
            if ((b & 0x80) == 0)
            {
                return value;
            }
        }
        throw new InvalidDataException("variable-length long is too long");
    }

    internal long ReadLong()
    {
        EnsureRemaining(8);
        var value = BinaryPrimitives.ReadInt64BigEndian(_bytes.AsSpan(_index, 8));
        _index += 8;
        return value;
    }

    internal bool HasRemaining => _index < _bytes.Length;

    private void EnsureRemaining(int count)
    {
        if (_bytes.Length - _index < count)
        {
            throw new InvalidDataException("unexpected end of compact binary payload");
        }
    }
}
