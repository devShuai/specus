using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

namespace ShuaiTunnel.IntegrationTests;

public sealed class ManagementPageTests : IAsyncLifetime
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private TestServerFixture? _server;

    public async Task InitializeAsync()
    {
        _server = await TestServerFixture.StartAsync();
    }

    public async Task DisposeAsync()
    {
        if (_server is not null)
        {
            await _server.DisposeAsync();
        }
    }

    [Fact]
    public async Task ManagementPageStaticAssetsAreServedWithSecurityHeaders()
    {
        using var client = _server!.CreateClient();

        var index = await client.GetAsync("/");
        index.EnsureSuccessStatusCode();
        var html = await index.Content.ReadAsStringAsync();
        Assert.Contains("shuai-tunnel 管理后台", html);
        Assert.Equal("nosniff", index.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Contains("script-src 'self'", index.Headers.GetValues("Content-Security-Policy").Single());

        // The React build references hashed bundles under /assets/; fetch the JS bundle.
        var match = System.Text.RegularExpressions.Regex.Match(html, "/assets/[^\"']+\\.js");
        Assert.True(match.Success, "index.html should reference a /assets/*.js bundle");
        var js = await client.GetAsync(match.Value);
        js.EnsureSuccessStatusCode();
    }

    [Fact]
    public async Task DatabaseInitializeEndpointIsProtectedAndIdempotent()
    {
        using var anonymous = _server!.CreateClient();
        var rejected = await anonymous.PostAsync("/api/admin/database/initialize", content: null);
        Assert.Equal(HttpStatusCode.Unauthorized, rejected.StatusCode);

        using var client = _server.CreateClient();
        var token = await LoginAsync(client);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token.AccessToken);

        var response = await client.PostAsync("/api/admin/database/initialize", content: null);

        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadFromJsonAsync<DatabaseInitializeBody>(JsonOptions);
        Assert.NotNull(body);
        Assert.True(body!.Initialized);
        Assert.Equal("entity-framework-core", body.Orm);
        Assert.Equal("sqlite", body.Dialect);
        Assert.True(body.Clients >= 1);
    }

    private static async Task<TokenBody> LoginAsync(HttpClient client)
    {
        var response = await client.PostAsJsonAsync("/auth/login", new
        {
            username = "admin",
            password = "admin",
        });
        response.EnsureSuccessStatusCode();
        var token = await response.Content.ReadFromJsonAsync<TokenBody>(JsonOptions);
        Assert.NotNull(token);
        return token!;
    }

    private sealed record TokenBody(string AccessToken, string TokenType, long ExpiresIn);

    private sealed record DatabaseInitializeBody(bool Initialized, string Orm, string Dialect, long Clients);
}
