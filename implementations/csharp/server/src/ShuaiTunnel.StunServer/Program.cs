namespace ShuaiTunnel.StunServer;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        if (args.Any(argument => argument is "--help" or "-h"))
        {
            PrintHelp();
            return 0;
        }
        var unknown = args.FirstOrDefault(argument => argument != "--check-config");
        if (unknown is not null)
        {
            Console.Error.WriteLine($"Unknown argument: {unknown}");
            return 1;
        }
        try
        {
            var config = StunServerConfig.FromEnvironment();
            if (args.Contains("--check-config", StringComparer.Ordinal))
            {
                Console.WriteLine($"STUN configuration is valid: {config.Describe()}");
                return 0;
            }

            using var shutdown = new CancellationTokenSource();
            Console.CancelKeyPress += (_, eventArgs) =>
            {
                eventArgs.Cancel = true;
                shutdown.Cancel();
            };
            AppDomain.CurrentDomain.ProcessExit += (_, _) => shutdown.Cancel();
            await using var server = new StandaloneStunServer(config);
            await server.RunAsync(shutdown.Token).ConfigureAwait(false);
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"STUN server failed: {exception.Message}");
            return 1;
        }
    }

    private static void PrintHelp()
    {
        Console.WriteLine(
            """
            Shuai Tunnel standalone RFC 5780 STUN server

            Usage:
              dotnet ShuaiTunnel.StunServer.dll
              dotnet ShuaiTunnel.StunServer.dll --check-config

            Uses the same STUN_* environment variables as the Java and Go standalone servers:
              STUN_PRIMARY_BIND_ADDRESS / STUN_PRIMARY_PUBLIC_ADDRESS
              STUN_ALTERNATE_BIND_ADDRESS / STUN_ALTERNATE_PUBLIC_ADDRESS
              STUN_PRIMARY_PORT / STUN_ALTERNATE_PORT
              STUN_RATE_LIMIT_PER_SECOND / STUN_RATE_LIMIT_BURST
              STUN_GLOBAL_RATE_LIMIT_PER_SECOND / STUN_GLOBAL_RATE_LIMIT_BURST
              STUN_MAX_TRACKED_SOURCES / STUN_SOURCE_IDLE_SECONDS
              STUN_MAX_PACKET_BYTES / STUN_MAX_PADDING_RESPONSE_BYTES
              STUN_METRICS_BIND_ADDRESS / STUN_METRICS_PORT
            """);
    }
}
