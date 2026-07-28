using System.Net;
using System.Net.Security;
using Microsoft.Extensions.Logging.Abstractions;
using Specus.Client.Configuration;
using Specus.Client.Control;
using Specus.Client.DirectHttp;

namespace Specus.Client.Tests;

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
            new[] { new HttpSpecusConfigEntry { Route = "web", TargetBaseUrl = "http://127.0.0.1:8080" } },
            writer,
            new DirectHttpForwarder(http),
            NullLogger<DirectHttpHandler>.Instance);

        handler.ApplyRoutes(null);

        Assert.True(handler.SnapshotRoutes().ContainsKey("web"));

        handler.ApplyRoutes(Array.Empty<HttpSpecusConfigEntry>());

        Assert.Empty(handler.SnapshotRoutes());
    }

}
