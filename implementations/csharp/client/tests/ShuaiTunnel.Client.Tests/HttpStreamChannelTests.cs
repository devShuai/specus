using Microsoft.Extensions.Logging.Abstractions;
using ShuaiTunnel.Client.Configuration;
using ShuaiTunnel.Client.Control;
using ShuaiTunnel.Client.DirectHttp;
using ShuaiTunnel.Client.Nat;
using ShuaiTunnel.Protocol;
using ShuaiTunnel.Protocol.Packets;

namespace ShuaiTunnel.Client.Tests;

public sealed class HttpStreamChannelTests
{
    [Fact]
    public async Task DuplicateFinAndLateDataAreIgnoredAfterRequestEnds()
    {
        await using var transport = new MemoryStream();
        await using var writer = new FrameWriter(transport);
        using var http = new HttpClient();
        var routes = new DirectHttpHandler(
            new[]
            {
                new HttpTunnelConfigEntry
                {
                    Route = "web",
                    TargetBaseUrl = "http://127.0.0.1:8080",
                },
            },
            writer,
            new DirectHttpForwarder(http),
            NullLogger<DirectHttpHandler>.Instance);
        await using var channel = new HttpStreamChannel(
            7,
            new Dictionary<string, object?>
            {
                ["method"] = "GET",
                ["route"] = "web",
            },
            routes,
            "http://127.0.0.1:8080",
            writer,
            NullLogger.Instance,
            CancellationToken.None,
            _ => { });

        await channel.FinishRequestAsync(null, CancellationToken.None);
        await channel.FinishRequestAsync(null, CancellationToken.None);
        await channel.OfferRequestDataAsync([1, 2, 3], CancellationToken.None);
    }

    [Fact]
    public async Task UnknownRouteIsRejectedAsAStreamErrorWithoutBreakingLaterFrames()
    {
        await using var transport = new MemoryStream();
        await using var writer = new FrameWriter(transport);
        using var http = new HttpClient();
        var routes = new DirectHttpHandler(
            Array.Empty<HttpTunnelConfigEntry>(),
            writer,
            new DirectHttpForwarder(http),
            NullLogger<DirectHttpHandler>.Instance);
        await using var nat = new NatClientHandler(
            Array.Empty<TunnelConfigEntry>(),
            "test-client",
            writer,
            routes,
            NullLogger<NatClientHandler>.Instance);
        nat.Bind(CancellationToken.None);

        await nat.HandleAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.Open,
            StreamId = 9,
            MetaData = new Dictionary<string, object?>
            {
                ["source"] = "http",
                ["phase"] = "request",
                ["method"] = "GET",
                ["route"] = "missing",
            },
        });
        await nat.HandleAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.Data,
            StreamId = 9,
            Data = [1],
        });
        await nat.HandleAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.Fin,
            StreamId = 9,
        });

        Assert.True(transport.Length > 0);
    }
}
