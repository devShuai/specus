using System.Buffers.Binary;
using System.Text;

namespace Specus.Server.WebSockets;

/// <summary>Internal Redis Pub/Sub envelope. Browser-facing STWR2/STAP2 bytes are unchanged.</summary>
internal static class PublicTransferClusterFrame
{
    internal const byte KindRoster = 1;
    internal const byte KindText = 2;
    internal const byte KindBinary = 3;
    internal const byte KindManagement = 4;
    private const byte FlagExcludeSource = 1;
    private const int HeaderBytes = 26;
    private const int MaxGroupBytes = 128;
    private const int MaxIdBytes = 512;
    private const int MaxPayloadBytes = 256 * 1024;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    internal static byte[] Encode(PublicTransferClusterEvent clusterEvent)
    {
        ArgumentNullException.ThrowIfNull(clusterEvent);
        ValidateKind(clusterEvent.Kind);
        var group = StrictUtf8.GetBytes(clusterEvent.GroupId ?? string.Empty);
        var target = StrictUtf8.GetBytes(clusterEvent.TargetPeerId ?? string.Empty);
        var sourceLease = StrictUtf8.GetBytes(clusterEvent.SourceLeaseId ?? string.Empty);
        var payload = clusterEvent.Payload ?? [];
        ValidateLength("group", group.Length, MaxGroupBytes);
        ValidateLength("target", target.Length, MaxIdBytes);
        ValidateLength("source lease", sourceLease.Length, MaxIdBytes);
        ValidateLength("payload", payload.Length, MaxPayloadBytes);
        if (group.Length == 0)
        {
            throw new ArgumentException("cluster event group is required");
        }
        if (clusterEvent.Kind == KindRoster && payload.Length != 0)
        {
            throw new ArgumentException("roster event payload must be empty");
        }
        if (clusterEvent.Kind == KindBinary && target.Length == 0)
        {
            throw new ArgumentException("binary event target is required");
        }
        if (clusterEvent.Kind == KindManagement && (payload.Length == 0 || target.Length != 0
            || sourceLease.Length != 0 || clusterEvent.Revision != 0 || clusterEvent.ExcludeSource))
        {
            throw new ArgumentException("management event shape is invalid");
        }

        var result = new byte[HeaderBytes + group.Length + target.Length + sourceLease.Length
            + payload.Length];
        "STCE"u8.CopyTo(result);
        result[4] = 2;
        result[5] = clusterEvent.Kind;
        result[6] = clusterEvent.ExcludeSource ? FlagExcludeSource : (byte)0;
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(8, 8), clusterEvent.Revision);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(16, 2), checked((ushort)group.Length));
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(18, 2), checked((ushort)target.Length));
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(20, 2), checked((ushort)sourceLease.Length));
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(22, 4), checked((uint)payload.Length));
        var offset = HeaderBytes;
        group.CopyTo(result, offset);
        offset += group.Length;
        target.CopyTo(result, offset);
        offset += target.Length;
        sourceLease.CopyTo(result, offset);
        offset += sourceLease.Length;
        payload.CopyTo(result, offset);
        return result;
    }

    internal static PublicTransferClusterEvent Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length < HeaderBytes || !encoded[..4].SequenceEqual("STCE"u8)
            || encoded[4] != 2)
        {
            throw new ArgumentException("unsupported or truncated cluster event");
        }
        var kind = encoded[5];
        ValidateKind(kind);
        var flags = encoded[6];
        if ((flags & ~FlagExcludeSource) != 0 || encoded[7] != 0)
        {
            throw new ArgumentException("invalid cluster event flags");
        }
        var groupLength = BinaryPrimitives.ReadUInt16BigEndian(encoded[16..18]);
        var targetLength = BinaryPrimitives.ReadUInt16BigEndian(encoded[18..20]);
        var sourceLength = BinaryPrimitives.ReadUInt16BigEndian(encoded[20..22]);
        var payloadLengthValue = BinaryPrimitives.ReadUInt32BigEndian(encoded[22..26]);
        if (payloadLengthValue > int.MaxValue)
        {
            throw new ArgumentException("payload length is invalid");
        }
        var payloadLength = (int)payloadLengthValue;
        ValidateLength("group", groupLength, MaxGroupBytes);
        ValidateLength("target", targetLength, MaxIdBytes);
        ValidateLength("source lease", sourceLength, MaxIdBytes);
        ValidateLength("payload", payloadLength, MaxPayloadBytes);
        var expectedLength = (long)HeaderBytes + groupLength + targetLength + sourceLength
            + payloadLength;
        if (groupLength == 0 || expectedLength != encoded.Length)
        {
            throw new ArgumentException("cluster event length mismatch");
        }
        var offset = HeaderBytes;
        var groupId = ReadUtf8(encoded.Slice(offset, groupLength));
        offset += groupLength;
        var targetPeerId = ReadUtf8(encoded.Slice(offset, targetLength));
        offset += targetLength;
        var sourceLeaseId = ReadUtf8(encoded.Slice(offset, sourceLength));
        offset += sourceLength;
        var payload = encoded[offset..].ToArray();
        if (string.IsNullOrWhiteSpace(groupId))
        {
            throw new ArgumentException("cluster event group is required");
        }
        if (kind == KindRoster && payload.Length != 0)
        {
            throw new ArgumentException("roster event payload must be empty");
        }
        if (kind == KindBinary && string.IsNullOrWhiteSpace(targetPeerId))
        {
            throw new ArgumentException("binary event target is required");
        }
        var revision = BinaryPrimitives.ReadUInt64BigEndian(encoded[8..16]);
        if (kind == KindManagement && (payload.Length == 0 || targetPeerId.Length != 0
            || sourceLeaseId.Length != 0 || revision != 0 || (flags & FlagExcludeSource) != 0))
        {
            throw new ArgumentException("management event shape is invalid");
        }
        return new PublicTransferClusterEvent(kind, (flags & FlagExcludeSource) != 0,
            revision, groupId, targetPeerId, sourceLeaseId, payload);
    }

    private static string ReadUtf8(ReadOnlySpan<byte> value)
    {
        try
        {
            return StrictUtf8.GetString(value);
        }
        catch (DecoderFallbackException exception)
        {
            throw new ArgumentException("cluster event contains invalid UTF-8", exception);
        }
    }

    private static void ValidateKind(byte kind)
    {
        if (kind is not (KindRoster or KindText or KindBinary or KindManagement))
        {
            throw new ArgumentException("unsupported cluster event kind");
        }
    }

    private static void ValidateLength(string field, int length, int maximum)
    {
        if (length < 0 || length > maximum)
        {
            throw new ArgumentException($"{field} length is invalid");
        }
    }
}

internal sealed record PublicTransferClusterEvent(byte Kind, bool ExcludeSource, ulong Revision,
    string GroupId, string TargetPeerId, string SourceLeaseId, byte[] Payload);
