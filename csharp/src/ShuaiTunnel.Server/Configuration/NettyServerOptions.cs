namespace ShuaiTunnel.Server.Configuration;

/// <summary>
/// Mirrors a strict subset of <c>tunnel.netty.*</c> from the Java <c>NettyServerProperties</c>.
/// Phase 2 only needs <see cref="Port"/> and <see cref="MaxFrameSize"/> — the per-tunnel listener,
/// backpressure thresholds, and connection caps land in Phase 3.
/// </summary>
public sealed class NettyServerOptions
{
    public const string SectionName = "Tunnel:Netty";

    public int Port { get; set; } = 7010;

    /// <summary>
    /// Hard cap on a single decoded frame (bytes). The reader closes the connection if it sees
    /// a header advertising a length above this — protects against runaway memory on a malformed
    /// peer.
    /// </summary>
    public int MaxFrameSize { get; set; } = 32 * 1024 * 1024;
}

/// <summary>Login pipeline thresholds. The defaults mirror Java's bounded executor.</summary>
public sealed class LoginExecutorOptions
{
    public const string SectionName = "Tunnel:Login";

    public int ExecutorCoreSize { get; set; } = 8;
    public int ExecutorMaxSize { get; set; } = 32;
    public int ExecutorQueueCapacity { get; set; } = 20_000;
}

public sealed class DatabaseOptions
{
    public const string SectionName = "Tunnel:Database";

    public bool SeedDemoClient { get; set; } = true;
}
