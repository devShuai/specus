using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Specus.Protocol;
using Specus.Protocol.Packets;
using Specus.Server.Configuration;
using Specus.Server.ControlChannel;
using Specus.Server.Nat;
using Specus.Server.Networking;

namespace Specus.IntegrationTests;

public sealed class NatRegistrationIsolationTests
{
    [Fact]
    public async Task BindFailureKeepsDataSessionForAnotherMapping()
    {
        using var occupied = new TcpListener(IPAddress.Any, 0);
        if (OperatingSystem.IsWindows())
        {
            occupied.Server.ExclusiveAddressUse = true;
        }
        occupied.Start();
        var occupiedPort = ((IPEndPoint)occupied.LocalEndpoint).Port;
        var availablePort = FreeTcpPort();

        var options = Options.Create(new NettyServerOptions());
        await using var remotePorts = new RemotePortServerManager(
            options,
            NullLoggerFactory.Instance,
            NullLogger<RemotePortServerManager>.Instance);
        var writer = new CapturingFrameWriter();
        var closeCount = 0;
        using var lifetime = new CancellationTokenSource();
        var context = new SpecusConnectionContext(
            "data-channel",
            "127.0.0.1",
            writer,
            lifetime.Token,
            () => Interlocked.Increment(ref closeCount),
            new ReadGate(lifetime.Token),
            new WriteBackpressureGate(32 * 1024, 64 * 1024));
        context.OnLoginSuccess(
            "client-a",
            DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            1,
            ConnectionRole.Data);
        await using var nat = new NatClientSession(
            context,
            remotePorts,
            null!,
            null!,
            options,
            NullLoggerFactory.Instance,
            NullLogger<NatClientSession>.Instance);

        await nat.HandleAsync(Register(occupiedPort));

        Assert.Equal(0, closeCount);
        var failed = Assert.IsType<NatMessagePacket>(Assert.Single(writer.Packets));
        Assert.Equal(NatMessageType.RegisterResult, failed.NatMessageType);
        Assert.False(Assert.IsType<bool>(failed.MetaData!["success"]));

        await nat.HandleAsync(Register(availablePort));

        Assert.Equal(0, closeCount);
        Assert.True(remotePorts.HasBinding(availablePort));
        var succeeded = Assert.IsType<NatMessagePacket>(writer.Packets[1]);
        Assert.True(Assert.IsType<bool>(succeeded.MetaData!["success"]));
    }

    private static NatMessagePacket Register(int port) => new()
    {
        NatMessageType = NatMessageType.Register,
        MetaData = new Dictionary<string, object?>
        {
            ["port"] = port,
            ["specusPort"] = 8080,
            ["specusAddress"] = "127.0.0.1",
            ["clientName"] = "client-a",
        },
    };

    private static int FreeTcpPort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private sealed class CapturingFrameWriter : IFrameWriter
    {
        public List<Packet> Packets { get; } = [];

        public ValueTask WriteAsync(Packet packet, CancellationToken cancellationToken = default)
        {
            Packets.Add(packet);
            return ValueTask.CompletedTask;
        }
    }
}
