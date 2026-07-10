namespace ShuaiTunnel.Protocol.Codec;

/// <summary>
/// Structural raw-DEFLATE validator used to distinguish a real final block from
/// an input stream that merely ran out of bytes. Payload bytes are still decoded
/// by <see cref="System.IO.Compression.DeflateStream"/>; this class only walks the
/// RFC 1951 grammar far enough to prove that BFINAL and its end-of-block symbol
/// were present.
/// </summary>
internal static class RawDeflateValidator
{
    private static readonly int[] CodeLengthOrder =
    [
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
    ];

    private static readonly int[] LengthExtraBits =
    [
        0, 0, 0, 0, 0, 0, 0, 0,
        1, 1, 1, 1,
        2, 2, 2, 2,
        3, 3, 3, 3,
        4, 4, 4, 4,
        5, 5, 5, 5,
        0,
    ];

    private static readonly int[] DistanceExtraBits =
    [
        0, 0, 0, 0,
        1, 1,
        2, 2,
        3, 3,
        4, 4,
        5, 5,
        6, 6,
        7, 7,
        8, 8,
        9, 9,
        10, 10,
        11, 11,
        12, 12,
        13, 13,
    ];

    public static void EnsureFinished(byte[] bytes)
    {
        try
        {
            var reader = new BitReader(bytes);
            var finalBlock = false;
            while (!finalBlock)
            {
                finalBlock = reader.ReadBits(1) != 0;
                switch (reader.ReadBits(2))
                {
                    case 0:
                        ReadStoredBlock(reader);
                        break;
                    case 1:
                        ReadCompressedBlock(reader, HuffmanTree.FixedLiteralLength, HuffmanTree.FixedDistance);
                        break;
                    case 2:
                        var (literalLength, distance) = ReadDynamicTrees(reader);
                        ReadCompressedBlock(reader, literalLength, distance);
                        break;
                    default:
                        throw InvalidPayload();
                }
            }
        }
        catch (EndOfStreamException exception)
        {
            throw InvalidPayload(exception);
        }
    }

    private static void ReadStoredBlock(BitReader reader)
    {
        reader.AlignToByte();
        var length = reader.ReadBits(16);
        var complement = reader.ReadBits(16);
        if (complement != ((~length) & 0xffff))
        {
            throw InvalidPayload();
        }
        reader.SkipBytes(length);
    }

    private static (HuffmanTree LiteralLength, HuffmanTree Distance) ReadDynamicTrees(BitReader reader)
    {
        var literalLengthCount = reader.ReadBits(5) + 257;
        var distanceCount = reader.ReadBits(5) + 1;
        var codeLengthCount = reader.ReadBits(4) + 4;
        if (literalLengthCount > 286)
        {
            throw InvalidPayload();
        }

        var codeLengthLengths = new int[19];
        for (var index = 0; index < codeLengthCount; index++)
        {
            codeLengthLengths[CodeLengthOrder[index]] = reader.ReadBits(3);
        }
        var codeLengthTree = HuffmanTree.Create(codeLengthLengths, 7, allowEmpty: false);

        var lengths = new int[literalLengthCount + distanceCount];
        var position = 0;
        while (position < lengths.Length)
        {
            var symbol = codeLengthTree.Decode(reader);
            switch (symbol)
            {
                case <= 15:
                    lengths[position++] = symbol;
                    break;
                case 16:
                    if (position == 0)
                    {
                        throw InvalidPayload();
                    }
                    Repeat(lengths, ref position, lengths[position - 1], reader.ReadBits(2) + 3);
                    break;
                case 17:
                    Repeat(lengths, ref position, 0, reader.ReadBits(3) + 3);
                    break;
                case 18:
                    Repeat(lengths, ref position, 0, reader.ReadBits(7) + 11);
                    break;
                default:
                    throw InvalidPayload();
            }
        }

        var literalLengthLengths = lengths[..literalLengthCount];
        if (literalLengthLengths[256] == 0)
        {
            throw InvalidPayload();
        }
        return (
            HuffmanTree.Create(literalLengthLengths, 15, allowEmpty: false),
            HuffmanTree.Create(lengths[literalLengthCount..], 15, allowEmpty: true));
    }

    private static void Repeat(int[] target, ref int position, int value, int count)
    {
        if (count > target.Length - position)
        {
            throw InvalidPayload();
        }
        Array.Fill(target, value, position, count);
        position += count;
    }

    private static void ReadCompressedBlock(BitReader reader, HuffmanTree literalLength, HuffmanTree distance)
    {
        while (true)
        {
            var symbol = literalLength.Decode(reader);
            if (symbol < 256)
            {
                continue;
            }
            if (symbol == 256)
            {
                return;
            }
            if (symbol is < 257 or > 285)
            {
                throw InvalidPayload();
            }

            reader.SkipBits(LengthExtraBits[symbol - 257]);
            var distanceSymbol = distance.Decode(reader);
            if (distanceSymbol is < 0 or > 29)
            {
                throw InvalidPayload();
            }
            reader.SkipBits(DistanceExtraBits[distanceSymbol]);
        }
    }

    private static InvalidDataException InvalidPayload(Exception? inner = null) =>
        new("invalid deflated payload", inner);

    private sealed class BitReader
    {
        private readonly byte[] _bytes;
        private long _bitOffset;

        public BitReader(byte[] bytes)
        {
            _bytes = bytes;
        }

        public int ReadBits(int count)
        {
            if (count < 0 || count > 24 || _bitOffset > ((long)_bytes.Length * 8) - count)
            {
                throw new EndOfStreamException();
            }
            var value = 0;
            for (var bit = 0; bit < count; bit++, _bitOffset++)
            {
                value |= ((_bytes[_bitOffset >> 3] >> (int)(_bitOffset & 7)) & 1) << bit;
            }
            return value;
        }

        public void SkipBits(int count) => _ = ReadBits(count);

        public void AlignToByte()
        {
            _bitOffset = (_bitOffset + 7) & ~7L;
        }

        public void SkipBytes(int count)
        {
            if ((_bitOffset & 7) != 0 || count < 0 || _bitOffset > ((long)_bytes.Length - count) * 8)
            {
                throw new EndOfStreamException();
            }
            _bitOffset += (long)count * 8;
        }
    }

    private sealed class HuffmanTree
    {
        private readonly Dictionary<int, int> _symbols;
        private readonly int _maximumCodeLength;

        public static HuffmanTree FixedLiteralLength { get; } = Create(BuildFixedLiteralLengths(), 15, false);
        public static HuffmanTree FixedDistance { get; } = Create(Enumerable.Repeat(5, 32).ToArray(), 15, false);

        private HuffmanTree(Dictionary<int, int> symbols, int maximumCodeLength)
        {
            _symbols = symbols;
            _maximumCodeLength = maximumCodeLength;
        }

        public static HuffmanTree Create(int[] lengths, int allowedMaximum, bool allowEmpty)
        {
            var actualMaximum = lengths.Length == 0 ? 0 : lengths.Max();
            if (actualMaximum > allowedMaximum)
            {
                throw InvalidPayload();
            }
            if (actualMaximum == 0)
            {
                if (!allowEmpty)
                {
                    throw InvalidPayload();
                }
                return new HuffmanTree([], 0);
            }

            var counts = new int[actualMaximum + 1];
            foreach (var length in lengths)
            {
                if (length < 0)
                {
                    throw InvalidPayload();
                }
                if (length > 0)
                {
                    counts[length]++;
                }
            }

            var remaining = 1;
            for (var bits = 1; bits <= actualMaximum; bits++)
            {
                remaining = (remaining << 1) - counts[bits];
                if (remaining < 0)
                {
                    throw InvalidPayload();
                }
            }

            var nextCodes = new int[actualMaximum + 1];
            var code = 0;
            for (var bits = 1; bits <= actualMaximum; bits++)
            {
                code = (code + counts[bits - 1]) << 1;
                nextCodes[bits] = code;
            }

            var symbols = new Dictionary<int, int>();
            for (var symbol = 0; symbol < lengths.Length; symbol++)
            {
                var length = lengths[symbol];
                if (length == 0)
                {
                    continue;
                }
                var reversedCode = ReverseBits(nextCodes[length]++, length);
                symbols.Add((length << 16) | reversedCode, symbol);
            }
            return new HuffmanTree(symbols, actualMaximum);
        }

        public int Decode(BitReader reader)
        {
            if (_maximumCodeLength == 0)
            {
                throw InvalidPayload();
            }
            var code = 0;
            for (var length = 1; length <= _maximumCodeLength; length++)
            {
                code |= reader.ReadBits(1) << (length - 1);
                if (_symbols.TryGetValue((length << 16) | code, out var symbol))
                {
                    return symbol;
                }
            }
            throw InvalidPayload();
        }

        private static int ReverseBits(int value, int count)
        {
            var reversed = 0;
            for (var bit = 0; bit < count; bit++)
            {
                reversed = (reversed << 1) | ((value >> bit) & 1);
            }
            return reversed;
        }

        private static int[] BuildFixedLiteralLengths()
        {
            var lengths = new int[288];
            Array.Fill(lengths, 8, 0, 144);
            Array.Fill(lengths, 9, 144, 112);
            Array.Fill(lengths, 7, 256, 24);
            Array.Fill(lengths, 8, 280, 8);
            return lengths;
        }
    }
}
