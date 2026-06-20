namespace ShuaiTunnel.Server.Configuration;

/// <summary>
/// Mirrors a strict subset of <c>tunnel.netty.*</c> from the Java <c>NettyServerProperties</c>.
/// Phase 2 only needs <see cref="Port"/> and <see cref="MaxFrameSize"/>. Phase 3 adds per-tunnel
/// listeners, write-buffer watermarks, and connection caps.
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

    public int WriteBufferLowWaterMark { get; set; } = 32 * 1024;

    public int WriteBufferHighWaterMark { get; set; } = 64 * 1024;

    public int MaxExternalConnections { get; set; } = 10_000;

    public int MaxExternalConnectionsPerClient { get; set; } = 10_000;

    public int MaxExternalConnectionsPerPort { get; set; } = 10_000;
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

public sealed class TunnelOptions
{
    public const string SectionName = "Tunnel";

    public string? PublicAddress { get; set; }
}

public sealed class AuthOptions
{
    public const string SectionName = "Tunnel:Auth";

    public bool PasswordLoginEnabled { get; set; } = true;
    public string Username { get; set; } = "admin";
    public string Password { get; set; } = "admin";
    public string? JwtSecret { get; set; }
    public int TokenTtlSeconds { get; set; } = 8 * 60 * 60;
}

public sealed class TrafficOptions
{
    public const string SectionName = "Tunnel:Traffic";

    public int FlushIntervalMs { get; set; } = 5_000;
}

public sealed class DirectHttpOptions
{
    public const string SectionName = "Tunnel:Http";

    public int TimeoutMs { get; set; } = 30_000;
    public int MaxRequestBodySize { get; set; } = 16 * 1024 * 1024;
}
