using System.Net;
using System.Net.Http.Json;

namespace Specus.IntegrationTests;

public sealed class LoginRateLimiterEndpointTests
{
    [Fact]
    public async Task TrustedProxySeparatesLoginBudgetsByResolvedForwardedAddress()
    {
        await using var server = await TestServerFixture.StartAsync(new Dictionary<string, string?>
        {
            ["Specus:TrustedProxies"] = "127.0.0.1/32",
            ["Specus:Auth:LoginRateLimitPerIp"] = "1",
            ["Specus:Auth:LoginRateLimitPerAccount"] = "100",
            ["Specus:Auth:LoginRateLimitWindowSeconds"] = "300",
        });
        using var client = server.CreateClient();

        using var firstAddress = await LoginWithForwardedAddressAsync(client, "203.0.113.10");
        using var secondAddress = await LoginWithForwardedAddressAsync(client, "203.0.113.11");
        using var repeatedFirstAddress = await LoginWithForwardedAddressAsync(client, "203.0.113.10");

        Assert.Equal(HttpStatusCode.Unauthorized, firstAddress.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, secondAddress.StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, repeatedFirstAddress.StatusCode);
        Assert.True(repeatedFirstAddress.Headers.Contains("Retry-After"));
    }

    [Fact]
    public async Task UntrustedPeerCannotRotateItsBudgetWithForwardedHeaders()
    {
        await using var server = await TestServerFixture.StartAsync(new Dictionary<string, string?>
        {
            ["Specus:TrustedProxies"] = string.Empty,
            ["Specus:Auth:LoginRateLimitPerIp"] = "1",
            ["Specus:Auth:LoginRateLimitPerAccount"] = "100",
            ["Specus:Auth:LoginRateLimitWindowSeconds"] = "300",
        });
        using var client = server.CreateClient();

        using var firstSpoofedAddress = await LoginWithForwardedAddressAsync(client, "203.0.113.20");
        using var secondSpoofedAddress = await LoginWithForwardedAddressAsync(client, "203.0.113.21");

        Assert.Equal(HttpStatusCode.Unauthorized, firstSpoofedAddress.StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, secondSpoofedAddress.StatusCode);
    }

    private static Task<HttpResponseMessage> LoginWithForwardedAddressAsync(HttpClient client, string address)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/auth/login")
        {
            Content = JsonContent.Create(new { username = "admin", password = "wrong" }),
        };
        request.Headers.Add("X-Forwarded-For", address);
        return client.SendAsync(request);
    }
}
