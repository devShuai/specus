using System.Text;
using System.Text.Json;

namespace Specus.Client.PeerMesh;

/// <summary>Bounded, exception-free decoder for unauthenticated UDP connectivity probes.</summary>
internal static class PeerUdpProbeCodec
{
    internal const int MaxPacketBytes = 2_048;
    internal const string Magic = "specus-peer-mesh";

    private static readonly byte[] MagicBytes = Encoding.ASCII.GetBytes(Magic);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    internal static PeerMeshClient.PeerUdpProbe? Decode(ReadOnlySpan<byte> packet)
    {
        if (!LooksPlausible(packet))
        {
            return null;
        }
        try
        {
            var probe = JsonSerializer.Deserialize<PeerMeshClient.PeerUdpProbe>(packet, JsonOptions);
            return probe is not null && string.Equals(probe.Magic, Magic, StringComparison.Ordinal)
                ? probe
                : null;
        }
        catch (Exception ex) when (ex is JsonException or NotSupportedException)
        {
            return null;
        }
    }

    private static bool LooksPlausible(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < MagicBytes.Length + 8
            || packet.Length > MaxPacketBytes
            || packet[0] != (byte)'{'
            || packet[^1] != (byte)'}')
        {
            return false;
        }
        var searchLength = Math.Min(packet.Length, 160);
        return packet[..searchLength].IndexOf(MagicBytes) >= 0;
    }
}
