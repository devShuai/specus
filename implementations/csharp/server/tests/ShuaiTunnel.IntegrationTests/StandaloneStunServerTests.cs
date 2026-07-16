using System.Net;
using System.Net.Sockets;
using ShuaiTunnel.StunServer;

namespace ShuaiTunnel.IntegrationTests;

public sealed class StandaloneStunServerTests
{
    [Fact]
    public void ConfigurationCreatesRfc5780TopologyAndReadsProtection()
    {
        var config = StunServerConfig.FromDictionary(new Dictionary<string, string>
        {
            ["STUN_PRIMARY_BIND_ADDRESS"] = "10.0.0.10",
            ["STUN_PRIMARY_PUBLIC_ADDRESS"] = "203.0.113.10",
            ["STUN_ALTERNATE_BIND_ADDRESS"] = "10.0.0.11",
            ["STUN_ALTERNATE_PUBLIC_ADDRESS"] = "203.0.113.11",
            ["STUN_PRIMARY_PORT"] = "3478",
            ["STUN_ALTERNATE_PORT"] = "3479",
            ["STUN_RATE_LIMIT_PER_SECOND"] = "25",
            ["STUN_RATE_LIMIT_BURST"] = "40",
            ["STUN_GLOBAL_RATE_LIMIT_PER_SECOND"] = "1000",
            ["STUN_GLOBAL_RATE_LIMIT_BURST"] = "2000",
            ["STUN_MAX_TRACKED_SOURCES"] = "1234",
            ["STUN_SOURCE_IDLE_SECONDS"] = "30",
            ["STUN_MAX_PACKET_BYTES"] = "4096",
            ["STUN_MAX_PADDING_RESPONSE_BYTES"] = "1200",
            ["STUN_METRICS_BIND_ADDRESS"] = "127.0.0.2",
            ["STUN_METRICS_PORT"] = "9191",
        });

        Assert.True(config.Topology.SupportsRfc5780);
        Assert.Equal(4, config.Topology.Endpoints().Count);
        Assert.Equal(25, config.Protection.SourceRatePerSecond);
        Assert.Equal(40, config.Protection.SourceBurst);
        Assert.Equal(1_200, config.Protection.MaxPaddingResponseBytes);
        Assert.Equal(9_191, config.Metrics.Port);
    }

    [Fact]
    public void BindingRoutesChangeResponsePortAndPadding()
    {
        var config = RfcConfig();
        var service = new StunBindingService(config.Topology, "test-stun", false, 64);
        var remote = new IPEndPoint(IPAddress.Parse("198.51.100.25"), 53_000);
        var request = new StunMessage(
            StunMessage.BindingRequest,
            [1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [
                StunMessage.ChangeRequestAttribute(true, true),
                StunMessage.ResponsePort(54_321),
            ]);

        var result = service.Process(request, remote, StunEndpointId.Primary, 64);

        Assert.Equal(StunEndpointId.Alternate, result.ResponseEndpoint);
        Assert.Equal(54_321, result.ResponseTarget.Port);
        Assert.Equal(IPAddress.Parse("203.0.113.11"), result.Response.ResponseOriginValue()!.Address);
        Assert.Equal(3_479, result.Response.ResponseOriginValue()!.Port);

        var padded = new StunMessage(
            StunMessage.BindingRequest,
            [4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [StunMessage.Padding(256)]);
        var paddedResult = service.Process(padded, remote, StunEndpointId.Primary, 300);
        Assert.Equal(64, paddedResult.Response.First(StunMessage.AttrPadding)!.Value.Length);

        var invalid = new StunMessage(
            StunMessage.BindingRequest,
            [7, 8, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [StunMessage.ResponsePort(54_321), StunMessage.Padding(16)]);
        var invalidResult = service.Process(invalid, remote, StunEndpointId.Primary, 64);
        Assert.Equal(400, invalidResult.Response.ErrorCodeValue());
        Assert.Equal(remote.Port, invalidResult.ResponseTarget.Port);
    }

    [Fact]
    public void LimiterBoundsBurstAndSourceTableAndMetricsExposeCounters()
    {
        var defaults = StunProtectionConfig.Default;
        var limiter = new StunRequestLimiter(defaults with
        {
            SourceRatePerSecond = 1,
            SourceBurst = 2,
            GlobalRatePerSecond = 100,
            GlobalBurst = 100,
            MaxTrackedSources = 1,
        });
        var first = IPAddress.Parse("198.51.100.1");
        var second = IPAddress.Parse("198.51.100.2");

        Assert.Equal(StunLimitDecision.Allowed, limiter.Allow(first));
        Assert.Equal(StunLimitDecision.Allowed, limiter.Allow(first));
        Assert.Equal(StunLimitDecision.SourceRateLimit, limiter.Allow(first));
        Assert.Equal(StunLimitDecision.SourceTableFull, limiter.Allow(second));

        var metrics = new StunMetrics();
        metrics.RecordPacket(20);
        metrics.RecordAcceptedRequest();
        metrics.RecordFeature("padding");
        metrics.RecordResponse(200, 64);
        var rendered = metrics.Render(limiter.TrackedSources());
        Assert.Contains("stun_packets_received_total 1", rendered, StringComparison.Ordinal);
        Assert.Contains(
            "stun_feature_requests_total{feature=\"padding\"} 1",
            rendered,
            StringComparison.Ordinal);
        Assert.Contains(
            "stun_responses_total{code=\"200\"} 1",
            rendered,
            StringComparison.Ordinal);
        Assert.Contains("stun_tracked_sources 1", rendered, StringComparison.Ordinal);
    }

    [Fact]
    public async Task StandaloneServerSendsBindingResponse()
    {
        var port = FreeUdpPort();
        var config = StunServerConfig.FromDictionary(new Dictionary<string, string>
        {
            ["STUN_PRIMARY_BIND_ADDRESS"] = "127.0.0.1",
            ["STUN_PRIMARY_PUBLIC_ADDRESS"] = "127.0.0.1",
            ["STUN_PRIMARY_PORT"] = port.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["STUN_ALTERNATE_PORT"] = "0",
            ["STUN_METRICS_PORT"] = "0",
        });
        using var shutdown = new CancellationTokenSource();
        await using var server = new StandaloneStunServer(config);
        var runTask = server.RunAsync(shutdown.Token);
        try
        {
            await Task.Delay(50);
            using var client = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            var request = new StunMessage(
                StunMessage.BindingRequest,
                [9, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

            await client.SendAsync(
                request.ToBytes(),
                new IPEndPoint(IPAddress.Loopback, port),
                CancellationToken.None);
            using var receiveTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            var packet = await client.ReceiveAsync(receiveTimeout.Token);
            var response = StunMessage.Parse(packet.Buffer);

            Assert.NotNull(response);
            Assert.Equal(StunMessage.BindingSuccess, response.Type);
        }
        finally
        {
            await shutdown.CancelAsync();
            await runTask;
        }
    }

    private static StunServerConfig RfcConfig() =>
        StunServerConfig.FromDictionary(new Dictionary<string, string>
        {
            ["STUN_PRIMARY_BIND_ADDRESS"] = "10.0.0.10",
            ["STUN_PRIMARY_PUBLIC_ADDRESS"] = "203.0.113.10",
            ["STUN_ALTERNATE_BIND_ADDRESS"] = "10.0.0.11",
            ["STUN_ALTERNATE_PUBLIC_ADDRESS"] = "203.0.113.11",
            ["STUN_PRIMARY_PORT"] = "3478",
            ["STUN_ALTERNATE_PORT"] = "3479",
            ["STUN_METRICS_PORT"] = "0",
        });

    private static int FreeUdpPort()
    {
        using var socket = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)socket.Client.LocalEndPoint!).Port;
    }
}
