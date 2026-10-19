using System.Net;

namespace Specus.IntegrationTests;

public sealed class PublicPageRoutingTests : IAsyncLifetime
{
    private static readonly string[] Entries = ["/nat-detect", "/transfer", "/diagram", "/diagram-embed", "/download"];
    private TestServerFixture? _server;

    public async Task InitializeAsync() => _server = await TestServerFixture.StartAsync();
    public async Task DisposeAsync()
    {
        if (_server is not null) await _server.DisposeAsync();
    }

    [Fact]
    public async Task PublicEntriesServeActualIndexWithoutRedirectingOrLosingQueryState()
    {
        using var client = _server!.CreateClient();
        var index = await client.GetStringAsync("/index.html");
        Assert.Contains("<html", index);
        foreach (var entry in Entries)
        foreach (var suffix in new[] { "", "/", "?roomId=fixture&view=file", "/?roomId=fixture&view=file" })
        foreach (var method in new[] { HttpMethod.Get, HttpMethod.Head })
        {
            var path = entry + suffix;
            using var request = new HttpRequestMessage(method, path);
            using var response = await client.SendAsync(request);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(path, response.RequestMessage!.RequestUri!.PathAndQuery);
            Assert.Null(response.Headers.Location);
            Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);
            Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
            Assert.Contains("frame-ancestors 'none'", response.Headers.GetValues("Content-Security-Policy").Single());
            Assert.DoesNotContain("immutable", response.Headers.CacheControl?.ToString() ?? "");
            var body = await response.Content.ReadAsStringAsync();
            Assert.Equal(method == HttpMethod.Head ? "" : index, body);
        }
    }

    [Fact]
    public async Task UnknownResourcesAndApplicationProxyPathsNeverBecomePortalHtml()
    {
        using var client = _server!.CreateClient();
        foreach (var path in new[] { "/transfer/unknown", "/transfer.js", "/transfer-other", "/assets/missing.js", "/api/public/missing", "/api/admin/missing", "/http/missing-client/missing-route/", "/http-share/missing/" })
        {
            using var response = await client.GetAsync(path);
            Assert.True((int)response.StatusCode >= 400, path);
            Assert.DoesNotContain("<html", await response.Content.ReadAsStringAsync());
        }
    }

    [Fact]
    public async Task PublicEntriesDoNotAcceptWriteMethods()
    {
        using var client = _server!.CreateClient();
        foreach (var entry in Entries)
        foreach (var method in new[] { HttpMethod.Post, HttpMethod.Put, HttpMethod.Delete })
        {
            using var request = new HttpRequestMessage(method, entry);
            using var response = await client.SendAsync(request);
            Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
        }
    }
}
