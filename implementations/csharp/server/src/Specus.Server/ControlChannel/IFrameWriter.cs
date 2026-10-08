using Specus.Protocol.Packets;

namespace Specus.Server.ControlChannel;

/// <summary>
/// Async-friendly write surface for one control channel. Single producer per call site is fine,
/// but multiple producers contend, so the implementation MUST serialize writes (Phase 2 uses a
/// per-connection async lock — <see cref="SpecusConnection"/>).
/// </summary>
public interface IFrameWriter
{
    /// <summary>Encode + flush one packet. Awaiting completes once the bytes are in the
    /// socket layer (network may still buffer). Throws if the connection is already closed.
    /// <paramref name="cancellationToken"/> can only drop the packet before it starts going out; a
    /// frame is never cut short by it, and one whose write fails closes the connection.</summary>
    ValueTask WriteAsync(Packet packet, CancellationToken cancellationToken = default);

    /// <summary>Queues a small flow-control frame so a blocked DATA write cannot stop reads.</summary>
    ValueTask WritePriorityAsync(Packet packet, CancellationToken cancellationToken = default) =>
        WriteAsync(packet, cancellationToken);

    /// <summary>
    /// Runs <paramref name="commit"/> and then writes <paramref name="packet"/> with no other write
    /// able to start in between, so a frame another producer sends because of what the commit
    /// published (such as a stream OPEN on a connection the commit just registered) always follows
    /// the packet on the wire. The commit must not write to this connection. It does not run when
    /// the wait for the write turn is cancelled. A writer shared between producers must override
    /// this; the default suits a writer only one producer uses.
    /// </summary>
    async ValueTask CommitAndWriteAsync(Action? commit, Packet packet,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        commit?.Invoke();
        await WriteAsync(packet, cancellationToken).ConfigureAwait(false);
    }
}
