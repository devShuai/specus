using System.Text;
using Specus.Server.Authentication;
using Specus.Server.Http;

namespace Specus.IntegrationTests;

public sealed class HttpRouteBasicAuthenticatorTests
{
    private const string Username = "访客";
    private static readonly string PasswordHash = PasswordHasher.HashToken("route secret");

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("Bearer token")]
    [InlineData("Basic not-base64")]
    [InlineData("Basic dXNlcm5hbWU=")]
    public void RejectsMissingOrMalformedCredentials(string? authorization)
    {
        Assert.False(HttpRouteBasicAuthenticator.IsAuthorized(authorization, Username, PasswordHash));
    }

    [Fact]
    public void AcceptsUtf8UsernameAndPassword()
    {
        var authorization = Basic(Username, "route secret");

        Assert.True(HttpRouteBasicAuthenticator.IsAuthorized(authorization, Username, PasswordHash));
    }

    [Theory]
    [InlineData("other", "route secret")]
    [InlineData("访客", "wrong")]
    public void RejectsWrongUsernameOrPassword(string username, string password)
    {
        Assert.False(HttpRouteBasicAuthenticator.IsAuthorized(Basic(username, password),
            Username, PasswordHash));
    }

    [Fact]
    public void RejectsMalformedStoredPolicyBeforeCredentialComparison()
    {
        Assert.False(HttpRouteBasicAuthenticator.IsConfigured(null, PasswordHash));
        Assert.False(HttpRouteBasicAuthenticator.IsConfigured("   ", PasswordHash));
        Assert.False(HttpRouteBasicAuthenticator.IsConfigured(Username, null));
        Assert.False(HttpRouteBasicAuthenticator.IsConfigured(Username, "abc"));
        Assert.False(HttpRouteBasicAuthenticator.IsConfigured(Username,
            new string('g', 64)));
        Assert.True(HttpRouteBasicAuthenticator.IsConfigured(Username, PasswordHash));
    }

    private static string Basic(string username, string password) =>
        "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}"));
}
