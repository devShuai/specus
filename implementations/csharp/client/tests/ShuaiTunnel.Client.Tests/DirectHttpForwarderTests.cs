using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using ShuaiTunnel.Client.Configuration;
using ShuaiTunnel.Client.Control;
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
    public void BuildTarget_AcceptsDoubleSlashPathLikeJava()
    {
        var ok = DirectHttpForwarder.TryBuildTarget(
            "http://upstream.local/base", "//assets/app.js", null, out var target, out var error);
        Assert.True(ok, error);
        Assert.Equal("http://upstream.local/base//assets/app.js", target.ToString());
    }

    [Fact]
    public void BuildTarget_RejectsParentSegment()
    {
        var ok = DirectHttpForwarder.TryBuildTarget(
            "http://upstream.local/base", "/v1/../../etc/passwd", null, out _, out var error);
        Assert.False(ok);
        Assert.Equal("HTTP 转发路径越界", error);
    }

    [Fact]
    public void BuildTarget_RejectsEncodedParentSegmentLikeJava()
    {
        var ok = DirectHttpForwarder.TryBuildTarget(
            "http://upstream.local/base", "/v1/%2e%2e/secret", null, out _, out var error);
        Assert.False(ok);
        Assert.Equal("HTTP 转发路径越界", error);
    }

    [Fact]
    public void BuildTarget_RejectsUnsupportedScheme()
    {
        var ok = DirectHttpForwarder.TryBuildTarget(
            "ftp://upstream.local/base", "/x", null, out _, out var error);
        Assert.False(ok);
        Assert.Equal("HTTP route 仅支持 http 和 https", error);
    }

    [Fact]
    public void BuildTarget_RejectsBaseWithQuery()
    {
        var ok = DirectHttpForwarder.TryBuildTarget(
            "http://upstream.local/base?secret=1", "/x", null, out _, out var error);
        Assert.False(ok);
        Assert.Equal("HTTP route 地址无效", error);
    }

    [Fact]
    public void BuildTarget_UsesJavaErrorMessages()
    {
        var missing = DirectHttpForwarder.TryBuildTarget(
            "", "/", null, out _, out var missingError);
        Assert.False(missing);
        Assert.Equal("未配置 HTTP route", missingError);

        var invalidPath = DirectHttpForwarder.TryBuildTarget(
            "http://upstream.local/base", "x", null, out _, out var invalidPathError);
        Assert.False(invalidPath);
        Assert.Equal("HTTP 转发路径无效", invalidPathError);
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
            Body = new byte[DirectHttpForwarder.MaxRequestBodySize + 1],
        };
        var routes = new Dictionary<string, string> { ["web"] = "http://127.0.0.1:1/" };
        var response = await forwarder.ForwardAsync(packet, routes, CancellationToken.None);
        Assert.Equal(DirectHttpForwarder.FailureStatus, response.StatusCode);
        Assert.Equal("HTTP 请求体超过限制", response.Error);
    }

    [Fact]
    public async Task ForwardAsync_UsesJavaMessageForOversizedResponseBody()
    {
        using var http = new HttpClient(new OversizedResponseHandler());
        var forwarder = new DirectHttpForwarder(http);
        var packet = new DirectHttpRequestPacket
        {
            RequestId = "abc",
            RequestMethod = "GET",
            Route = "web",
            RelativePath = "/",
        };
        var routes = new Dictionary<string, string> { ["web"] = "http://127.0.0.1:8080/" };

        var response = await forwarder.ForwardAsync(packet, routes, CancellationToken.None);

        Assert.Equal(DirectHttpForwarder.FailureStatus, response.StatusCode);
        Assert.Equal("HTTP 响应体超过限制", response.Error);
    }

    [Fact]
    public async Task ForwardAsync_RoundTripsThroughLoopbackServer()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = Task.Run(async () =>
        {
            using var socket = await listener.AcceptTcpClientAsync();
            await using var stream = socket.GetStream();
            using var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
            var requestLine = await reader.ReadLineAsync();
            Assert.Equal("GET /api/echo?foo=bar HTTP/1.1", requestLine);
            string? rangeHeader = null;
            string? line;
            do
            {
                line = await reader.ReadLineAsync();
                if (line?.StartsWith("Range:", StringComparison.OrdinalIgnoreCase) == true)
                {
                    rangeHeader = line;
                }
            } while (!string.IsNullOrEmpty(line));
            Assert.Equal("Range: bytes=0-8388607", rangeHeader);

            var payload = Encoding.UTF8.GetBytes("{\"ok\":true}");
            var header = Encoding.ASCII.GetBytes(
                "HTTP/1.1 201 Created\r\n" +
                "Content-Type: application/json\r\n" +
                $"Content-Length: {payload.Length}\r\n" +
                "Connection: close\r\n\r\n");
            await stream.WriteAsync(header);
            await stream.WriteAsync(payload);
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
            Headers = new List<string> { "X-Test:1", "Range:bytes=0-" },
            Body = Array.Empty<byte>(),
        };
        var routes = new Dictionary<string, string> { ["api"] = $"http://127.0.0.1:{port}/" };

        var response = await forwarder.ForwardAsync(packet, routes, CancellationToken.None);
        await serverTask;

        Assert.Equal(201, response.StatusCode);
        Assert.Equal("{\"ok\":true}", Encoding.UTF8.GetString(response.Body!));
        Assert.Null(response.Error);
    }

    [Fact]
    public void BuildDefaultHandler_MatchesJavaDirectHttpTlsPolicy()
    {
        using var handler = DirectHttpForwarder.BuildDefaultHandler();
        Assert.False(handler.UseProxy);
        Assert.False(handler.AllowAutoRedirect);
        Assert.Equal(DecompressionMethods.None, handler.AutomaticDecompression);
        Assert.NotNull(handler.SslOptions.RemoteCertificateValidationCallback);
        Assert.True(handler.SslOptions.RemoteCertificateValidationCallback!(
            sender: new object(),
            certificate: null,
            chain: null,
            sslPolicyErrors: SslPolicyErrors.RemoteCertificateChainErrors));
    }

    [Theory]
    [InlineData("bytes=0-", "bytes=0-8388607")]
    [InlineData("bytes=10-20", "bytes=10-20")]
    [InlineData("bytes=10-99999999", "bytes=10-8388617")]
    [InlineData("bytes=-99999999", "bytes=-8388608")]
    [InlineData("bytes=20-10", null)]
    [InlineData("bytes=0-1,2-3", null)]
    [InlineData("items=0-10", null)]
    public void BoundedRange_MatchesJavaForwarder(string input, string? expected)
    {
        Assert.Equal(expected, DirectHttpForwarder.BoundedRange(input));
    }

    [Fact]
    public async Task ApplyRoutes_PreservesMissingSnapshotAndClearsEmptySnapshotLikeJava()
    {
        await using var stream = new MemoryStream();
        await using var writer = new FrameWriter(stream);
        using var http = new HttpClient();
        var handler = new DirectHttpHandler(
            new[] { new HttpTunnelConfigEntry { Route = "web", TargetBaseUrl = "http://127.0.0.1:8080" } },
            writer,
            new DirectHttpForwarder(http),
            NullLogger<DirectHttpHandler>.Instance);

        handler.ApplyRoutes(null);

        Assert.True(handler.SnapshotRoutes().ContainsKey("web"));

        handler.ApplyRoutes(Array.Empty<HttpTunnelConfigEntry>());

        Assert.Empty(handler.SnapshotRoutes());
    }

    private sealed class OversizedResponseHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(Array.Empty<byte>()),
            };
            response.Content.Headers.ContentLength = DirectHttpForwarder.MaxResponseBodySize + 1L;
            return Task.FromResult(response);
        }
    }

}
