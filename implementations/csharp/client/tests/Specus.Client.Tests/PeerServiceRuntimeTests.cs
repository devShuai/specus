using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Nodes;
using Specus.Client.Configuration;
using Specus.Client.Control;
using Specus.Client.PeerMesh;

namespace Specus.Client.Tests;

public class PeerServiceRuntimeTests
{
    [Fact]
    public void DoesNotProbeOrReportWhenSharingIsOff()
    {
        var port = FreePort();
        using var listener = Listen(port);
        var sent = new List<string>();
        using var runtime = new PeerServiceRuntime(sent.Add);
        runtime.SetHasAuthorizedOnlinePeer(true);
        runtime.ApplyConfig(Config(sharing: false, port, enabled: true));
        Thread.Sleep(50);
        Assert.Empty(sent);
    }

    [Fact]
    public void DoesNotProbeWithoutAuthorizedOnlinePeer()
    {
        var port = FreePort();
        using var listener = Listen(port);
        var sent = new List<string>();
        using var runtime = new PeerServiceRuntime(sent.Add);
        runtime.SetHasAuthorizedOnlinePeer(false);
        runtime.ApplyConfig(Config(sharing: true, port, enabled: true));
        Thread.Sleep(50);
        Assert.Empty(sent);
    }

    [Fact]
    public void ReportsReachableEnabledServiceAndBuildsSafeCatalogUrl()
    {
        var port = FreePort();
        using var listener = Listen(port);
        var sent = new List<string>();
        using var runtime = new PeerServiceRuntime(sent.Add);
        runtime.SetRosterLookup(_ => new PeerServiceRuntime.RosterHint("100.96.0.2", true));
        runtime.SetHasAuthorizedOnlinePeer(true);
        var config = Config(sharing: true, port, enabled: true);
        config.LocalServices![0].ServiceId = "svc-wire01";
        config.LocalServices[0].Name = "fixture-http";
        config.LocalServices[0].Description = "wire fixture";
        config.LocalServices[0].Path = "/health";
        runtime.ApplyConfig(config);
        WaitUntil(() => sent.Count > 0);
        Assert.Contains("service-report", sent[0]);
        Assert.Contains("svc-wire01", sent[0]);
        Assert.DoesNotContain("targetHost", sent[0]);
        var actualReport = JsonNode.Parse(sent[0])!.AsObject();
        var vectors = ProtocolVectorTestHelper.Read<PeerServiceWireVectors>(
            "protocol/test-vectors/peer-service-discovery-v2.json");
        var expectedReport = JsonNode.Parse(vectors.ServiceReports["dotnet"].GetRawText())!.AsObject();
        foreach (var field in new[] { "revision", "instanceId", "generatedAt", "expiresAt", "createdAtMillis" })
        {
            expectedReport[field] = actualReport[field]?.DeepClone();
        }
        Assert.True(JsonNode.DeepEquals(expectedReport, actualReport),
            $"real .NET service-report differs from shared fixture: {actualReport}");

        runtime.ApplyCatalog(2, "client-b", 9, 1, DateTimeOffset.UtcNow.AddMinutes(1).ToString("O"),
        [
            new AdvertisedService
            {
                ServiceId = "svc-http01",
                Name = "web",
                Transport = "tcp",
                Application = "http",
                PublishedPort = 8080,
                Path = "/app",
            },
        ]);
        var views = runtime.RemoteServices();
        Assert.Single(views);
        Assert.True(views[0].Openable);
        Assert.Equal("http://100.96.0.2:8080/app", views[0].AccessTarget);
        Assert.DoesNotContain("evil", views[0].AccessTarget);
    }

    [Fact]
    public void EmptyCatalogWithdrawsAndOfflinePublisherDisablesOpen()
    {
        using var runtime = new PeerServiceRuntime(_ => { });
        runtime.SetRosterLookup(_ => new PeerServiceRuntime.RosterHint("100.96.0.2", false));
        runtime.ApplyConfig(Config(sharing: true, FreePort(), enabled: false));
        runtime.ApplyCatalog(2, "client-b", 9, 1, DateTimeOffset.UtcNow.AddMinutes(1).ToString("O"),
        [
            new AdvertisedService
            {
                ServiceId = "svc-http01",
                Name = "web",
                Transport = "tcp",
                Application = "http",
                PublishedPort = 8080,
                Path = "/app",
            },
        ]);
        Assert.False(runtime.RemoteServices()[0].Openable);
        Assert.Contains("离线", runtime.RemoteServices()[0].UnavailableReason);

        runtime.ApplyCatalog(2, "client-b", 9, 2, DateTimeOffset.UtcNow.AddMinutes(1).ToString("O"), []);
        Assert.Empty(runtime.RemoteServices());
    }

    [Fact]
    public void SharedCatalogFaultVectorsRejectRollbackAndLateRevival()
    {
        var vectors = ProtocolVectorTestHelper.Read<CatalogFaultVectors>(
            "protocol/test-vectors/peer-service-catalog-faults.json");
        Assert.NotEmpty(vectors.Cases);

        foreach (var testCase in vectors.Cases)
        {
            using var runtime = new PeerServiceRuntime(_ => { });
            runtime.SetRosterLookup(_ => new PeerServiceRuntime.RosterHint("100.96.0.2", true));
            runtime.ApplyConfig(Config(sharing: true, FreePort(), enabled: false));
            runtime.SetHasAuthorizedOnlinePeer(true);
            var service = new AdvertisedService
            {
                ServiceId = "svc-http01", Name = "web", Transport = "tcp", Application = "http",
                PublishedPort = 8080, Path = "/app",
            };

            foreach (var faultEvent in testCase.Events)
            {
                runtime.ApplyCatalog(
                    2,
                    "client-b",
                    9,
                    faultEvent.Revision,
                    DateTimeOffset.UtcNow.AddMinutes(1).ToString("O"),
                    faultEvent.ServicePresent ? [service] : []);
            }

            Assert.Equal(testCase.ExpectedServiceCount, runtime.RemoteServices().Count);
        }
    }

    [Fact]
    public void ReconnectClearsCatalogRevisionHighWaterAndAcceptsCurrentSnapshot()
    {
        using var runtime = new PeerServiceRuntime(_ => { });
        runtime.SetRosterLookup(_ => new PeerServiceRuntime.RosterHint("100.96.0.2", true));
        runtime.ApplyConfig(Config(sharing: true, FreePort(), enabled: false));
        runtime.SetHasAuthorizedOnlinePeer(true);
        var service = new AdvertisedService
        {
            ServiceId = "svc-http01", Name = "web", Transport = "tcp", Application = "http",
            PublishedPort = 8080, Path = "/app",
        };
        runtime.ApplyCatalog(2, "client-b", 9, 7, DateTimeOffset.UtcNow.AddMinutes(1).ToString("O"), [service]);
        Assert.Single(runtime.RemoteServices());

        runtime.SetHasAuthorizedOnlinePeer(false);
        Assert.Empty(runtime.RemoteServices());
        runtime.SetHasAuthorizedOnlinePeer(true);
        runtime.ApplyCatalog(2, "client-b", 9, 7, DateTimeOffset.UtcNow.AddMinutes(1).ToString("O"), [service]);

        Assert.Single(runtime.RemoteServices());
    }

    [Fact]
    public void StableCatalogIsRenewedAcrossMultipleLeaseTtls()
    {
        var port = FreePort();
        using var listener = Listen(port);
        var sent = new List<string>();
        using var runtime = new PeerServiceRuntime(sent.Add);
        runtime.SetHasAuthorizedOnlinePeer(true);
        runtime.ApplyConfig(Config(sharing: true, port, enabled: true));
        WaitUntil(() => sent.Count > 0);
        sent.Clear();
        runtime.ProbeAndReport();
        Assert.Empty(sent);
        for (var elapsedTtls = 1; elapsedTtls <= 3; elapsedTtls++)
        {
            runtime.ForceReportRefreshForTest();
            runtime.ProbeAndReport();
            Assert.Equal(elapsedTtls, sent.Count);
        }
    }

    [Fact]
    public void ProbeTcpDetectsOpenAndClosedPorts()
    {
        Assert.False(PeerServiceDiscovery.IsLocalInterfaceTarget("10.255.255.254"));
        var port = FreePort();
        Assert.False(PeerServiceDiscovery.ProbeTcp("127.0.0.1", port, 200));
        using var listener = Listen(port);
        Assert.True(PeerServiceDiscovery.ProbeTcp("127.0.0.1", port, 400));
    }

    [Fact]
    public void LocalPauseStopsReportingWithoutChangingServerConfig()
    {
        var port = FreePort();
        using var listener = Listen(port);
        var sent = new List<string>();
        using var runtime = new PeerServiceRuntime(sent.Add);
        runtime.SetHasAuthorizedOnlinePeer(true);
        runtime.ApplyConfig(Config(sharing: true, port, enabled: true));
        WaitUntil(() => sent.Count > 0);
        sent.Clear();
        runtime.SetLocalPublished("svc-http01", false);
        WaitUntil(() => sent.Exists(item => item.Contains("\"enabled\":false") || item.Contains("\"services\":[]")));
        Assert.False(runtime.IsLocallyPublished("svc-http01"));
    }

    [Fact]
    public void TurningSharingOffWithdrawsPreviousReport()
    {
        var port = FreePort();
        using var listener = Listen(port);
        var sent = new List<string>();
        using var runtime = new PeerServiceRuntime(sent.Add);
        runtime.SetHasAuthorizedOnlinePeer(true);
        runtime.ApplyConfig(Config(sharing: true, port, enabled: true));
        WaitUntil(() => sent.Count > 0);
        sent.Clear();
        runtime.ApplyConfig(Config(sharing: false, port, enabled: true));
        WaitUntil(() => sent.Exists(item => item.Contains("\"enabled\":false")));
        Assert.Contains("service-report", sent[^1]);
    }

    [Fact]
    public void DesktopSnapshotKeepsPublisherSessionAndServiceIdentity()
    {
        using var runtime = new PeerServiceRuntime(_ => { });
        runtime.SetRosterLookup(_ => new PeerServiceRuntime.RosterHint("100.96.0.2", true));
        runtime.ApplyConfig(Config(sharing: true, FreePort(), enabled: false));
        runtime.SetHasAuthorizedOnlinePeer(true);
        runtime.ApplyCatalog(22, "same-name", 901, 1, DateTimeOffset.UtcNow.AddMinutes(1).ToString("O"),
        [
            new AdvertisedService
            {
                ServiceId = "svc-desktop01",
                Name = "Desktop status",
                Transport = "tcp",
                Application = "http",
                PublishedPort = 8080,
                Path = "/status",
            },
        ]);

        var snapshot = Assert.Single(PeerServiceSnapshotPresenter.Remote(runtime));
        Assert.Equal(22, snapshot.PublisherClientId);
        Assert.Equal(901, snapshot.PublisherSessionId);
        Assert.Equal("svc-desktop01", snapshot.ServiceId);
        Assert.Equal("Desktop status", snapshot.Name);
        Assert.True(snapshot.Openable);
    }

    [Fact]
    public void DesktopSnapshotShowsConfiguredServiceAsNotPublishedWhenGlobalSharingIsOff()
    {
        using var runtime = new PeerServiceRuntime(_ => { });
        runtime.ApplyConfig(Config(sharing: false, FreePort(), enabled: true));

        var snapshot = Assert.Single(PeerServiceSnapshotPresenter.Local(runtime));
        Assert.True(snapshot.ConfigEnabled);
        Assert.False(snapshot.CanToggle);
        Assert.False(snapshot.LocallyPublished);
        Assert.Equal("已配置但未发布 · 全局共享关闭", snapshot.PublicationStatus);
    }

    [Fact]
    public async Task OnlineConfigCreatesReplacesAndClosesBridgeWithinFiveSeconds()
    {
        using var firstTarget = Listen(0);
        using var secondTarget = Listen(0);
        var firstPublishedPort = FreePort();
        var secondPublishedPort = FreePort();
        using var runtime = new PeerServiceRuntime(_ => { });
        runtime.SetHasAuthorizedOnlinePeer(true);

        var first = Config(sharing: true, ((IPEndPoint)firstTarget.LocalEndpoint).Port, enabled: true);
        first.LocalServices![0].PublishedPort = firstPublishedPort;
        first.LocalServices[0].AllowedPeerVirtualIps = ["127.0.0.1"];
        var started = DateTimeOffset.UtcNow;
        runtime.ApplyConfig(first);
        using var firstCaller = new TcpClient();
        await firstCaller.ConnectAsync(IPAddress.Loopback, firstPublishedPort);
        using var firstAcceptTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var firstForwarded = await firstTarget.AcceptTcpClientAsync(firstAcceptTimeout.Token);
        Assert.True(DateTimeOffset.UtcNow - started < TimeSpan.FromSeconds(5));

        var replacement = Config(sharing: true, ((IPEndPoint)secondTarget.LocalEndpoint).Port, enabled: true);
        replacement.LocalServices![0].PublishedPort = secondPublishedPort;
        replacement.LocalServices[0].AllowedPeerVirtualIps = ["127.0.0.1"];
        runtime.ApplyConfig(replacement);
        Assert.True(await ReadClosedAsync(firstCaller));
        await Assert.ThrowsAnyAsync<SocketException>(async () =>
        {
            using var retry = new TcpClient();
            await retry.ConnectAsync(IPAddress.Loopback, firstPublishedPort);
        });

        using var secondCaller = new TcpClient();
        await secondCaller.ConnectAsync(IPAddress.Loopback, secondPublishedPort);
        using var secondAcceptTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var secondForwarded = await secondTarget.AcceptTcpClientAsync(secondAcceptTimeout.Token);
        replacement.LocalServices[0].Enabled = false;
        runtime.ApplyConfig(replacement);
        Assert.True(await ReadClosedAsync(secondCaller));
        await Assert.ThrowsAnyAsync<SocketException>(async () =>
        {
            using var retry = new TcpClient();
            await retry.ConnectAsync(IPAddress.Loopback, secondPublishedPort);
        });
    }

    [Fact]
    public void CollectedEnvironmentAdvertisesPeerServiceCapabilities()
    {
        var environment = ClientEnvironmentInfo.Collect(Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance);
        var vectors = ProtocolVectorTestHelper.Read<PeerServiceWireVectors>(
            "protocol/test-vectors/peer-service-discovery-v2.json");
        Assert.Equal(vectors.ProtocolVersion, environment.ClientPeerServiceCapabilities.Version);
        Assert.Equal(vectors.Applications, environment.ClientPeerServiceCapabilities.Applications);
    }

    [Fact]
    public async Task PeerMeshClientIgnoresUnknownFutureControlMessage()
    {
        var vectors = ProtocolVectorTestHelper.Read<PeerServiceWireVectors>(
            "protocol/test-vectors/peer-service-discovery-v2.json");
        await using var client = new PeerMeshClient(
            new SpecusClientConfig(),
            Microsoft.Extensions.Logging.Abstractions.NullLogger<PeerMeshClient>.Instance);
        await using var writer = new FrameWriter(new MemoryStream());

        await client.HandleControlAsync(
            vectors.LegacyCompatibility.UnknownMessage.GetRawText(),
            new SpecusRuntimeState(),
            writer,
            CancellationToken.None);
    }

    [Fact]
    public async Task TcpBridgeEnforcesServerAuthoredSourceAcl()
    {
        using var target = Listen(0);
        var targetPort = ((IPEndPoint)target.LocalEndpoint).Port;
        var publishedPort = FreePort();
        var service = new LocalPeerService
        {
            ServiceId = "svc-acl01", Transport = "tcp", Application = "tcp",
            TargetHost = "127.0.0.1", TargetPort = targetPort, PublishedPort = publishedPort,
            AllowedPeerVirtualIps = ["127.0.0.2"],
        };
        using (var bridge = PeerServiceBridge.Bind("127.0.0.1", service, null))
        using (var caller = new TcpClient())
        {
            await caller.ConnectAsync(IPAddress.Loopback, publishedPort);
            using var timeout = new CancellationTokenSource(TimeSpan.FromMilliseconds(250));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                await target.AcceptTcpClientAsync(timeout.Token));
        }

        publishedPort = FreePort();
        service.PublishedPort = publishedPort;
        service.AllowedPeerVirtualIps = ["127.0.0.1"];
        using var allowedBridge = PeerServiceBridge.Bind("127.0.0.1", service, null);
        using var allowedCaller = new TcpClient();
        await allowedCaller.ConnectAsync(IPAddress.Loopback, publishedPort);
        using var forwarded = await target.AcceptTcpClientAsync();
        Assert.True(forwarded.Connected);
    }

    [Fact]
    public async Task UdpProbeRequiresReplyAndResourceBudgetsRecover()
    {
        using (var silent = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)))
        {
            Assert.False(PeerServiceDiscovery.ProbeUdp("127.0.0.1",
                ((IPEndPoint)silent.Client.LocalEndPoint!).Port, 100));
        }
        using (var echo = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)))
        {
            var responder = Task.Run(async () =>
            {
                var request = await echo.ReceiveAsync();
                await echo.SendAsync([1], 1, request.RemoteEndPoint);
            });
            Assert.True(PeerServiceDiscovery.ProbeUdp("localhost",
                ((IPEndPoint)echo.Client.LocalEndPoint!).Port, 500));
            await responder;
        }
        Assert.False(PeerServiceDiscovery.TryResolveLocalInterfaceTarget("example.invalid", out _));
        Assert.False(PeerServiceDiscovery.TryResolveLocalInterfaceTarget("10.255.255.254", out _));

        var tcp = new List<PeerServiceResourceLimiter.Lease>();
        for (var index = 0; index < PeerServiceResourceLimiter.MaxTcpPerSource; index++)
        {
            var lease = PeerServiceResourceLimiter.TryAcquireTcp(IPAddress.Loopback);
            Assert.NotNull(lease);
            tcp.Add(lease);
        }
        Assert.Null(PeerServiceResourceLimiter.TryAcquireTcp(IPAddress.Loopback));
        tcp.ForEach(item => item.Dispose());
        using (var recovered = PeerServiceResourceLimiter.TryAcquireTcp(IPAddress.Loopback))
        {
            Assert.NotNull(recovered);
        }

        var udp = new List<PeerServiceResourceLimiter.Lease>();
        for (var index = 0; index < PeerServiceResourceLimiter.MaxUdpPerSource; index++)
        {
            udp.Add(PeerServiceResourceLimiter.TryAcquireUdp(IPAddress.Loopback)!);
        }
        Assert.Null(PeerServiceResourceLimiter.TryAcquireUdp(IPAddress.Loopback));
        udp.ForEach(item => item.Dispose());

        var globalTcp = new List<PeerServiceResourceLimiter.Lease>();
        for (var source = 1; source <= PeerServiceResourceLimiter.MaxTcpGlobal
                / PeerServiceResourceLimiter.MaxTcpPerSource; source++)
        {
            var address = IPAddress.Parse($"127.0.1.{source}");
            for (var slot = 0; slot < PeerServiceResourceLimiter.MaxTcpPerSource; slot++)
            {
                globalTcp.Add(PeerServiceResourceLimiter.TryAcquireTcp(address)!);
            }
        }
        Assert.DoesNotContain(globalTcp, item => item is null);
        Assert.Null(PeerServiceResourceLimiter.TryAcquireTcp(IPAddress.Parse("127.0.2.1")));
        globalTcp.ForEach(item => item.Dispose());

        var globalUdp = new List<PeerServiceResourceLimiter.Lease>();
        for (var source = 1; source <= PeerServiceResourceLimiter.MaxUdpGlobal
                / PeerServiceResourceLimiter.MaxUdpPerSource; source++)
        {
            var address = IPAddress.Parse($"127.0.3.{source}");
            for (var slot = 0; slot < PeerServiceResourceLimiter.MaxUdpPerSource; slot++)
            {
                globalUdp.Add(PeerServiceResourceLimiter.TryAcquireUdp(address)!);
            }
        }
        Assert.DoesNotContain(globalUdp, item => item is null);
        Assert.Null(PeerServiceResourceLimiter.TryAcquireUdp(IPAddress.Parse("127.0.4.1")));
        globalUdp.ForEach(item => item.Dispose());
    }

    [Fact]
    public async Task TcpBridgeSeparatesThreePeersAndRevocationClosesTheActiveFlow()
    {
        using var target = Listen(0);
        var targetPort = ((IPEndPoint)target.LocalEndpoint).Port;
        var publishedPort = FreePort();
        var service = new LocalPeerService
        {
            ServiceId = "svc-acl-three", Transport = "tcp", Application = "tcp",
            TargetHost = "127.0.0.1", TargetPort = targetPort, PublishedPort = publishedPort,
            AllowedPeerVirtualIps = ["127.0.0.2"],
        };
        using var bridge = PeerServiceBridge.Bind("127.0.0.1", service, null);

        using var denied = await ConnectFromAsync("127.0.0.3", publishedPort);
        using (var deniedTimeout = new CancellationTokenSource(TimeSpan.FromMilliseconds(250)))
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                await target.AcceptTcpClientAsync(deniedTimeout.Token));
        }

        using var allowed = await ConnectFromAsync("127.0.0.2", publishedPort);
        using var forwarded = await target.AcceptTcpClientAsync();
        Assert.True(forwarded.Connected);

        bridge.Dispose();
        var activeFlowClosed = false;
        try
        {
            using var readTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(1));
            activeFlowClosed = await allowed.GetStream().ReadAsync(new byte[1], readTimeout.Token) == 0;
        }
        catch (Exception exception) when (exception is IOException or SocketException)
        {
            activeFlowClosed = true;
        }
        Assert.True(activeFlowClosed);
        await Assert.ThrowsAnyAsync<SocketException>(async () =>
        {
            using var retry = await ConnectFromAsync("127.0.0.2", publishedPort);
        });
    }

    [Fact]
    public async Task UdpBridgeAppliesTheSameAclAndRevocationBoundary()
    {
        using var target = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        using var portProbe = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var publishedPort = ((IPEndPoint)portProbe.Client.LocalEndPoint!).Port;
        portProbe.Dispose();
        var service = new LocalPeerService
        {
            ServiceId = "svc-udp-acl", Transport = "udp", Application = "udp",
            TargetHost = "127.0.0.1",
            TargetPort = ((IPEndPoint)target.Client.LocalEndPoint!).Port,
            PublishedPort = publishedPort,
            AllowedPeerVirtualIps = ["127.0.0.2"],
        };
        using var bridge = PeerServiceUdpBridge.Bind("127.0.0.1", service, null);
        using var denied = new UdpClient(new IPEndPoint(IPAddress.Parse("127.0.0.3"), 0));
        using var allowed = new UdpClient(new IPEndPoint(IPAddress.Parse("127.0.0.2"), 0));
        var destination = new IPEndPoint(IPAddress.Loopback, publishedPort);
        var payload = new byte[] { 1, 2, 3 };

        await denied.SendAsync(payload, destination);
        using (var deniedTimeout = new CancellationTokenSource(TimeSpan.FromMilliseconds(250)))
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                await target.ReceiveAsync(deniedTimeout.Token));
        }

        await allowed.SendAsync(payload, destination);
        using (var allowedTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(1)))
        {
            var forwarded = await target.ReceiveAsync(allowedTimeout.Token);
            Assert.Equal(payload, forwarded.Buffer);
        }

        bridge.Dispose();
        await allowed.SendAsync(payload, destination);
        using var revokedTimeout = new CancellationTokenSource(TimeSpan.FromMilliseconds(250));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await target.ReceiveAsync(revokedTimeout.Token));
    }

    private static async Task<TcpClient> ConnectFromAsync(string sourceIp, int targetPort)
    {
        var client = new TcpClient(AddressFamily.InterNetwork);
        try
        {
            client.Client.Bind(new IPEndPoint(IPAddress.Parse(sourceIp), 0));
            await client.ConnectAsync(IPAddress.Loopback, targetPort);
            return client;
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }

    private static async Task<bool> ReadClosedAsync(TcpClient client)
    {
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(1));
            return await client.GetStream().ReadAsync(new byte[1], timeout.Token) == 0;
        }
        catch (Exception exception) when (exception is IOException or SocketException)
        {
            return true;
        }
    }

    private static PeerMeshConfig Config(bool sharing, int targetPort, bool enabled) => new()
    {
        Enabled = true,
        VirtualIp = "127.0.0.1",
        ServiceSharing = ServiceSharingStatus.Of(true, sharing, true),
        LocalServices =
        [
            new LocalPeerService
            {
                ServiceId = "svc-http01",
                Name = "web",
                Transport = "tcp",
                Application = "http",
                TargetHost = "127.0.0.1",
                TargetPort = targetPort,
                PublishedPort = 18080,
                Path = "/app",
                Enabled = enabled,
            },
        ],
    };

    private static int FreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private static TcpListener Listen(int port)
    {
        var listener = new TcpListener(IPAddress.Loopback, port);
        listener.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        listener.Start();
        return listener;
    }

    private static void WaitUntil(Func<bool> condition)
    {
        for (var i = 0; i < 50; i++)
        {
            if (condition())
            {
                return;
            }
            Thread.Sleep(20);
        }
        throw new InvalidOperationException("condition not met");
    }

    private sealed class PeerServiceWireVectors
    {
        public int ProtocolVersion { get; set; }
        public string[] Applications { get; set; } = [];
        public Dictionary<string, JsonElement> ServiceReports { get; set; } = [];
        public LegacyCompatibilityVector LegacyCompatibility { get; set; } = new();
    }

    private sealed class LegacyCompatibilityVector
    {
        public JsonElement UnknownMessage { get; set; }
    }

    private sealed class CatalogFaultVectors
    {
        public CatalogFaultCase[] Cases { get; set; } = [];
    }

    private sealed class CatalogFaultCase
    {
        public string Name { get; set; } = "";
        public CatalogFaultEvent[] Events { get; set; } = [];
        public int ExpectedServiceCount { get; set; }
    }

    private sealed class CatalogFaultEvent
    {
        public long Revision { get; set; }
        public bool ServicePresent { get; set; }
    }
}
