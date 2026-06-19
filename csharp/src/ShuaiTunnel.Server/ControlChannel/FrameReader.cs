using System.Buffers;
using System.Buffers.Binary;
using System.IO.Pipelines;
using ShuaiTunnel.Protocol.Codec;
using ShuaiTunnel.Protocol.Packets;

namespace ShuaiTunnel.Server.ControlChannel;

/// <summary>
/// Reads length-prefixed frames off a <see cref="PipeReader"/> and decodes each into a
/// <see cref="Packet"/>. Mirrors what Netty's <c>Spliter + PacketCodecHandler</c> do upstream
/// of the application handlers in Java.
///
/// <para>The 11-byte header lets us peek the frame size without allocating; only complete
/// frames advance <see cref="PipeReader"/>'s consumed pointer, which keeps the buffered tail
/// under <c>maxFrameSize</c> when the wire is fragmented.</para>
/// </summary>
internal static class FrameReader
{
    /// <summary>
    /// Pulls the next packet off the reader. Returns <c>null</c> when the peer closed cleanly.
    /// Throws <see cref="InvalidDataException"/> on a bad magic number, oversized frame, or
    /// negative length — caller should treat that as a protocol violation and close.
    /// </summary>
    public static async ValueTask<Packet?> ReadFrameAsync(PipeReader reader, int maxFrameSize,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            var result = await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            var buffer = result.Buffer;

            if (TryReadFrame(buffer, maxFrameSize, out var packet, out var consumed))
            {
                reader.AdvanceTo(consumed);
                return packet;
            }

            // No complete frame yet — tell the pipe we examined the whole buffer so it
            // delivers more bytes next iteration.
            reader.AdvanceTo(buffer.Start, buffer.End);

            if (result.IsCompleted)
            {
                if (!buffer.IsEmpty)
                {
                    // Peer closed mid-frame — surface as a protocol error so the connection
                    // gets stamped IO_ERROR.
                    throw new InvalidDataException("connection closed mid-frame");
                }
                return null;
            }
        }
    }

    private static bool TryReadFrame(ReadOnlySequence<byte> buffer, int maxFrameSize,
        out Packet? packet, out SequencePosition consumed)
    {
        packet = null;
        consumed = buffer.Start;

        if (buffer.Length < PacketCodec.HeaderSize)
        {
            return false;
        }

        // Peek the header to learn body length without copying the whole buffer.
        Span<byte> header = stackalloc byte[PacketCodec.HeaderSize];
        buffer.Slice(0, PacketCodec.HeaderSize).CopyTo(header);

        var magic = BinaryPrimitives.ReadInt32BigEndian(header[..4]);
        if (magic != PacketCodec.MagicNumber)
        {
            throw new InvalidDataException($"bad magic: 0x{magic:X8}");
        }
        var length = BinaryPrimitives.ReadInt32BigEndian(header.Slice(7, 4));
        if (length < 0 || length > maxFrameSize)
        {
            throw new InvalidDataException($"frame length {length} exceeds limit {maxFrameSize}");
        }

        var totalLength = PacketCodec.HeaderSize + length;
        if (buffer.Length < totalLength)
        {
            return false;
        }

        // Copy the whole frame into a contiguous array — tens of KB at most for the heaviest
        // packet (NAT DATA), and we don't try to dodge the copy because the codec needs full
        // random access.
        var frameBytes = buffer.Slice(0, totalLength).ToArray();
        if (!PacketCodec.TryDecode(frameBytes, out packet, out var consumedBytes))
        {
            // TryDecode should not return false when we already verified totalLength; treat as bug.
            throw new InvalidDataException("frame decoder reported incomplete after length check");
        }
        consumed = buffer.GetPosition(consumedBytes);
        return true;
    }
}
