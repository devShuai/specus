using System.Buffers;
using System.IO.Pipelines;
using ShuaiTunnel.Protocol.Codec;
using ShuaiTunnel.Protocol.Packets;

namespace ShuaiTunnel.Client.Control;

/// <summary>
/// Reads framed packets from a <see cref="PipeReader"/>. Mirrors the server's frame reader
/// (which is internal in <c>ShuaiTunnel.Server</c>) but lives in the client module so the
/// client can stay decoupled from the server project.
/// </summary>
internal static class FrameReader
{
    /// <summary>
    /// Awaits one full framed packet on <paramref name="reader"/>, returning <c>null</c>
    /// when the peer closes cleanly. Validates magic and length bounds and rethrows codec errors.
    /// </summary>
    public static async ValueTask<Packet?> ReadFrameAsync(
        PipeReader reader,
        int maxFrameSize,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            var result = await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            var buffer = result.Buffer;
            if (TryParseFrame(ref buffer, maxFrameSize, out var packet, out var consumed))
            {
                reader.AdvanceTo(consumed);
                return packet;
            }
            if (result.IsCompleted)
            {
                if (buffer.IsEmpty)
                {
                    return null;
                }
                throw new InvalidDataException("control channel closed mid-frame");
            }
            reader.AdvanceTo(buffer.Start, buffer.End);
        }
    }

    private static bool TryParseFrame(
        ref ReadOnlySequence<byte> buffer,
        int maxFrameSize,
        out Packet? packet,
        out SequencePosition consumed)
    {
        if (buffer.Length < PacketCodec.HeaderSize)
        {
            packet = null;
            consumed = buffer.Start;
            return false;
        }
        Span<byte> header = stackalloc byte[PacketCodec.HeaderSize];
        buffer.Slice(0, PacketCodec.HeaderSize).CopyTo(header);
        var (_, length) = PacketCodec.DecodeHeader(header);
        var total = (long)PacketCodec.HeaderSize + length;
        if (length < 0 || total > maxFrameSize)
        {
            throw new InvalidDataException(
                $"invalid frame length: {total} (body {length}, limit {maxFrameSize})");
        }
        if (buffer.Length < total)
        {
            packet = null;
            consumed = buffer.Start;
            return false;
        }
        var frame = buffer.Slice(0, total);
        var input = frame.IsSingleSegment ? frame.FirstSpan : frame.ToArray();
        if (!PacketCodec.TryDecode(input, out packet, out _))
        {
            throw new InvalidDataException("frame decode failed");
        }
        consumed = buffer.GetPosition(total);
        return true;
    }
}
