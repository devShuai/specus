namespace Specus.Server.PeerMesh;

/// <summary>
/// A peer signal that could not reach its target for a reason the sender could not have avoided:
/// the target went offline, is gone, no longer permits the sender, or its connection closed under
/// the write.
/// </summary>
/// <remarks>
/// It is not a protocol violation and must not be answered as one. The read loop closes a
/// connection on any exception the dispatcher lets through, so throwing the ordinary exceptions for
/// these cases disconnected every client that signalled a device in the seconds after that device
/// left -- a consumer announcing candidates to an egress that had just stopped was thrown off its
/// own control connection for it.
/// </remarks>
public sealed class PeerSignalUndeliverableException : Exception
{
    public PeerSignalUndeliverableException(string message)
        : base(message)
    {
    }

    public PeerSignalUndeliverableException(string message, Exception inner)
        : base(message, inner)
    {
    }
}
