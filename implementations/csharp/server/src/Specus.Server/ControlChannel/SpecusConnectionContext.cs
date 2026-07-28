using Specus.Server.Data.Entities;
using Specus.Server.Networking;

namespace Specus.Server.ControlChannel;

/// <summary>
/// The Java side hangs every per-channel attribute off Netty's <c>AttributeKey</c> system.
/// On .NET we lean on shared mutable state on a single object handed to every handler that
/// needs it — simpler, no global registry. The lifecycle: created on accept, mutated through
/// login, read on close to write the audit row.
///
/// <para>Threads: writes happen on the read loop or a worker thread; reads on whichever code
/// path closes the connection. Mutators are atomic where it matters
/// (<see cref="MarkDisconnectIfAbsent"/>) so the "first reason wins" invariant from Java is
/// preserved across data races.</para>
/// </summary>
public sealed class SpecusConnectionContext
{
    private long _disconnectReasonRaw = -1;

    /// <summary>Stable channel identifier — recorded in the audit row.</summary>
    public string ChannelId { get; }

    /// <summary>Peer endpoint the kernel reports — formatted similarly to Java's <c>remoteAddress.toString()</c>.</summary>
    public string? RemoteAddress { get; }

    /// <summary>Owns the writes back out — held by the reader so it can answer heartbeats without plumbing a callback.</summary>
    public IFrameWriter Writer { get; }

    /// <summary>Cancels everything when the connection is going down.</summary>
    public CancellationToken Lifetime { get; }

    /// <summary>Hook the connection installs so dispatcher code can ask the read loop to exit.
    /// Equivalent to Java's <c>ChannelFutureListener.CLOSE</c>.</summary>
    public Action CloseAsync { get; }

    /// <summary>
    /// Backpressure for inbound frames. NAT consumers flip this when the downstream sink can't
    /// keep up, matching Java's <c>setAutoRead(channel, false)</c> on the control channel.
    /// </summary>
    public ReadGate ReadGate { get; }

    /// <summary>
    /// Backpressure for outbound frames written to the Java control connection. NAT mirrors
    /// this into external-channel auto-read, matching Netty's channel writability signal.
    /// </summary>
    public WriteBackpressureGate WriteBackpressure { get; }

    /// <summary>Set after a successful HMAC login. Null while the connection is still anonymous.</summary>
    public string? ClientName { get; private set; }

    /// <summary>UTC ms snapshot when login succeeded — used by overview/online metrics.</summary>
    public long? LoginTimeMs { get; private set; }

    public long? ClientSessionId { get; private set; }

    public string? ConnectionRole { get; private set; }

    /// <summary>Audit row id populated only on a successful login. Null → close path skips DB write.</summary>
    public long? ConnectionRecordId { get; set; }

    public SpecusConnectionContext(string channelId, string? remoteAddress,
        IFrameWriter writer, CancellationToken lifetime, Action closeCallback,
        ReadGate readGate, WriteBackpressureGate writeBackpressure)
    {
        ChannelId = channelId;
        RemoteAddress = remoteAddress;
        Writer = writer;
        Lifetime = lifetime;
        CloseAsync = closeCallback;
        ReadGate = readGate;
        WriteBackpressure = writeBackpressure;
    }

    public void OnLoginSuccess(string clientName, long loginTimeMs, long? clientSessionId = null,
        string connectionRole = Specus.Protocol.ConnectionRole.Control)
    {
        ClientName = clientName;
        LoginTimeMs = loginTimeMs;
        ClientSessionId = clientSessionId;
        ConnectionRole = connectionRole;
    }

    /// <summary>Returns true on the FIRST stamp; subsequent attempts are silently ignored so
    /// the late-firing IO error doesn't overwrite the real cause.</summary>
    public bool MarkDisconnectIfAbsent(DisconnectReason reason)
    {
        var encoded = (long)reason;
        return Interlocked.CompareExchange(ref _disconnectReasonRaw, encoded, -1) == -1;
    }

    public DisconnectReason? ReadDisconnectReason()
    {
        var raw = Interlocked.Read(ref _disconnectReasonRaw);
        return raw == -1 ? null : (DisconnectReason)raw;
    }
}
