using System.Net;
using ShuaiTunnel.Client.DirectHttp;
using ShuaiTunnel.Protocol.Packets;

namespace ShuaiTunnel.Client.Tests;

public class DirectHttpForwarderTests
{
    [Fact]
    public void BuildTarget_AcceptsRelativePathUnderBase()
    {
        var ok = DirectHttpForwarder.TryBuildTarget(
            "http://upstream.local:8080/base", "/v1/items", "limit=10", out var target, out var error);
        Assert.True(ok, error);
        Assert.Equal("http://upstream.local:8080/base/v1/items?limit=10", target.ToString());
    }

    [Fact]
    public void BuildTarget_RejectsCrossOrigin()
    {
        var ok = DirectHttpForwarder.TryBuildTarget(
            "http://upstream.local/base", "//attacker.example.com/x", null, out _, out var error);
        Assert.False(ok);
        Assert.Contains("跨主机", error);
    }

    [Fact]
    public void BuildTarget_RejectsNetworkPathReference()
    {
        // RFC 3986 §4.2 — "//foo" is a network-path reference, which would change authority
        // when resolved against an http base. Forwarder must refuse.
        var ok = DirectHttpForwarder.TryBuildTarget(
            "http://upstream.local/base", "//attacker.example.com/x", null, out _, out var error);
        Assert.False(ok);
        Assert.Contains("跨主机", error);
    }

    [Fact]
    public void BuildTarget_RejectsParentSegment()
    {
        var ok = DirectHttpForwarder.TryBuildTarget(
            "http://upstream.local/base", "/v1/../../etc/passwd", null, out _, out var error);
        Assert.False(ok);
        Assert.True(error.Contains("非法段") || error.Contains("越出"), error);
    }

    [Fact]
    public void BuildTarget_RejectsUnsupportedScheme()
    {
        var ok = DirectHttpForwarder.TryBuildTarget(
            "ftp://upstream.local/base", "/x", null, out _, out var error);
        Assert.False(ok);
        Assert.Contains("scheme", error);
    }

    [Fact]
    public void BuildTarget_RejectsBaseWithQuery()
    {
        var ok = DirectHttpForwarder.TryBuildTarget(
            "http://upstream.local/base?secret=1", "/x", null, out _, out var error);
        Assert.False(ok);
        Assert.Contains("query", error);
    }

    [Fact]
    public async Task ForwardAsync_ReturnsFailureWhenRouteUnknown()
    {
        using var http = new HttpClient();
        var forwarder = new DirectHttpForwarder(http);
        var packet = new DirectHttpRequestPacket
        {
            RequestId = "abc",
            RequestMethod = "GET",
            Route = "missing",
            RelativePath = "/",
        };
        var response = await forwarder.ForwardAsync(packet, new Dictionary<string, string>(), CancellationToken.None);
        Assert.Equal(DirectHttpForwarder.FailureStatus, response.StatusCode);
        Assert.Contains("未配置", response.Error);
    }

    [Fact]
    public async Task ForwardAsync_RejectsOversizedRequestBody()
    {
        using var http = new HttpClient();
        var forwarder = new DirectHttpForwarder(http);
        var packet = new DirectHttpRequestPacket
        {
            RequestId = "abc",
            RequestMethod = "POST",
            Route = "web",
            RelativePath = "/",
            Body = new byte[DirectHttpForwarder.MaxBodySize + 1],
        };
        var routes = new Dictionary<string, string> { ["web"] = "http://127.0.0.1:1/" };
        var response = await forwarder.ForwardAsync(packet, routes, CancellationToken.None);
        Assert.Equal(DirectHttpForwarder.FailureStatus, response.StatusCode);
        Assert.Contains("16MB", response.Error);
    }

    [Fact]
    public async Task ForwardAsync_RoundTripsThroughLoopbackServer()
    {
        using var listener = new HttpListener();
        var port = GetFreePort();
        listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        listener.Start();
        var serverTask = Task.Run(async () =>
        {
            var ctx = await listener.GetContextAsync();
            Assert.Equal("/api/echo", ctx.Request.Url!.AbsolutePath);
            Assert.Equal("foo=bar", ctx.Request.Url.Query.TrimStart('?'));
            ctx.Response.StatusCode = 201;
            ctx.Response.ContentType = "application/json";
            var payload = "{\"ok\":true}"u8.ToArray();
            ctx.Response.OutputStream.Write(payload, 0, payload.Length);
            ctx.Response.OutputStream.Close();
        });

        using var http = DirectHttpForwarder.BuildDefaultClient();
        var forwarder = new DirectHttpForwarder(http);
        var packet = new DirectHttpRequestPacket
        {
            RequestId = "round",
            RequestMethod = "GET",
            Route = "api",
            RelativePath = "/api/echo",
            RawQuery = "foo=bar",
            Headers = new List<string> { "X-Test:1" },
            Body = Array.Empty<byte>(),
        };
        var routes = new Dictionary<string, string> { ["api"] = $"http://127.0.0.1:{port}/" };

        var response = await forwarder.ForwardAsync(packet, routes, CancellationToken.None);
        await serverTask;
        listener.Stop();

        Assert.Equal(201, response.StatusCode);
        Assert.Equal("{\"ok\":true}", System.Text.Encoding.UTF8.GetString(response.Body!));
        Assert.Null(response.Error);
    }

    private static int GetFreePort()
    {
        var probe = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        probe.Start();
        var port = ((System.Net.IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();
        return port;
    }
}
