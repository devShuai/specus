using System.Net;
using System.Net.Sockets;
using Specus.Client.Configuration;
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
        runtime.ApplyConfig(Config(sharing: true, port, enabled: true));
        WaitUntil(() => sent.Count > 0);
        Assert.Contains("service-report", sent[0]);
        Assert.Contains("svc-http01", sent[0]);
        Assert.DoesNotContain("targetHost", sent[0]);

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
    public void CatalogRevisionTombstoneRejectsRollbackAndLateRevival()
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
        runtime.ApplyCatalog(2, "client-b", 9, 2, DateTimeOffset.UtcNow.AddMinutes(1).ToString("O"), [service]);
        runtime.ApplyCatalog(2, "client-b", 9, 1, DateTimeOffset.UtcNow.AddMinutes(1).ToString("O"), []);
        Assert.Single(runtime.RemoteServices());

        runtime.ApplyCatalog(2, "client-b", 9, 3, DateTimeOffset.UtcNow.ToString("O"), []);
        runtime.ApplyCatalog(2, "client-b", 9, 2, DateTimeOffset.UtcNow.AddMinutes(1).ToString("O"), [service]);
        Assert.Empty(runtime.RemoteServices());
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
    public void CollectedEnvironmentAdvertisesPeerServiceCapabilities()
    {
        var environment = ClientEnvironmentInfo.Collect(Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance);
        Assert.Equal(2, environment.ClientPeerServiceCapabilities.Version);
        Assert.Equal(new[] { "http", "https", "ssh", "tcp", "udp" }, environment.ClientPeerServiceCapabilities.Applications);
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
}
