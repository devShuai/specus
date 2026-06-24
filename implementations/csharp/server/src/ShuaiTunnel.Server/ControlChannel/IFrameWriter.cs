using ShuaiTunnel.Protocol.Packets;

namespace ShuaiTunnel.Server.ControlChannel;

/// <summary>
/// Async-friendly write surface for one control channel. Single producer per call site is fine,
/// but multiple producers contend, so the implementation MUST serialize writes (Phase 2 uses a
/// per-connection async lock — <see cref="TunnelConnection"/>).
/// </summary>
public interface IFrameWriter
{
    /// <summary>Encode + flush one packet. Awaiting completes once the bytes are in the
    /// socket layer (network may still buffer). Throws if the connection is already closed.</summary>
    ValueTask WriteAsync(Packet packet, CancellationToken cancellationToken = default);
}
