using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ShuaiTunnel.Server.Configuration;
using ShuaiTunnel.Server.Data;
using ShuaiTunnel.Server.Management;
using ShuaiTunnel.Server.Security;

namespace ShuaiTunnel.IntegrationTests;

public sealed class RegistrationAuthenticationTests
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    [Fact]
    public async Task VerifiedEmailRegistrationCreatesUserAndSupportsPasswordLogin()
    {
        var emailSender = new CapturingEmailSender();
        var turnstile = new FakeTurnstileVerifier();
        await using var server = await TestServerFixture.StartAsync(new Dictionary<string, string?>
        {
            ["Tunnel:Auth:RegistrationEnabled"] = "true",
            ["Tunnel:Auth:EmailVerificationEnabled"] = "true",
            ["Tunnel:Auth:EmailResendCooldownSeconds"] = "60",
        }, services =>
        {
            services.RemoveAll<IRegistrationEmailSender>();
            services.AddSingleton<IRegistrationEmailSender>(emailSender);
            services.RemoveAll<ITurnstileVerifier>();
            services.AddSingleton<ITurnstileVerifier>(turnstile);
        });
        using var client = server.CreateClient();

        var config = await client.GetFromJsonAsync<OidcRegistrationConfig>("/oidc-config", JsonOptions);
        Assert.NotNull(config);
        Assert.True(config!.RegistrationEnabled);
        Assert.True(config.EmailVerificationRequired);
        Assert.True(config.TurnstileEnabled);
        Assert.Equal(turnstile.SiteKey, config.TurnstileSiteKey);

        var missingTurnstile = await client.PostAsJsonAsync("/auth/register", new
        {
            username = "registered-user",
            email = "tester@example.com",
            password = "Strong-pass-123",
            turnstileToken = "",
        });
        Assert.Equal(HttpStatusCode.BadRequest, missingTurnstile.StatusCode);

        var requested = await client.PostAsJsonAsync("/auth/register", new
        {
            username = "registered-user",
            email = "tester@example.com",
            password = "Strong-pass-123",
            turnstileToken = FakeTurnstileVerifier.ValidToken,
        });
        Assert.Equal(HttpStatusCode.Accepted, requested.StatusCode);
        var challenge = await requested.Content.ReadFromJsonAsync<RegistrationChallengeResponse>(JsonOptions);
        Assert.NotNull(challenge);
        Assert.Equal("te***@example.com", challenge!.EmailMasked);
        Assert.False(string.IsNullOrWhiteSpace(challenge.RegistrationId));
        Assert.Equal("tester@example.com", emailSender.LastEmail);
        Assert.Equal(6, emailSender.LastCode?.Length);

        var rateLimited = await client.PostAsJsonAsync("/auth/register", new
        {
            username = "registered-user",
            email = "tester@example.com",
            password = "Strong-pass-123",
            turnstileToken = FakeTurnstileVerifier.ValidToken,
        });
        Assert.Equal(HttpStatusCode.TooManyRequests, rateLimited.StatusCode);

        var wrongCode = emailSender.LastCode == "000000" ? "000001" : "000000";
        var rejected = await client.PostAsJsonAsync("/auth/register/verify", new
        {
            registrationId = challenge.RegistrationId,
            code = wrongCode,
        });
        Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);

        var verified = await client.PostAsJsonAsync("/auth/register/verify", new
        {
            registrationId = challenge.RegistrationId,
            code = emailSender.LastCode,
        });
        verified.EnsureSuccessStatusCode();
        var token = await verified.Content.ReadFromJsonAsync<TokenResponse>(JsonOptions);
        Assert.NotNull(token);
        Assert.False(string.IsNullOrWhiteSpace(token!.AccessToken));

        await using (var scope = server.HostServices.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TunnelDbContext>();
            Assert.True(await db.ManagementUsers.AnyAsync(user => user.Username == "registered-user"));
            Assert.True(await db.ManagementUserEmails.AnyAsync(item =>
                item.Username == "registered-user" && item.Email == "tester@example.com"));
            Assert.False(await db.ManagementRegistrationChallenges.AnyAsync(item =>
                item.RegistrationId == challenge.RegistrationId));
        }

        var login = await client.PostAsJsonAsync("/auth/login", new
        {
            username = "registered-user",
            password = "Strong-pass-123",
            turnstileToken = FakeTurnstileVerifier.ValidToken,
        });
        login.EnsureSuccessStatusCode();
        Assert.Contains(TurnstileVerifier.RegisterAction, turnstile.Actions);
        Assert.Contains(TurnstileVerifier.LoginAction, turnstile.Actions);

        var duplicateEmail = await client.PostAsJsonAsync("/auth/register", new
        {
            username = "second-user",
            email = "TESTER@example.com",
            password = "Strong-pass-456",
            turnstileToken = FakeTurnstileVerifier.ValidToken,
        });
        Assert.Equal(HttpStatusCode.Conflict, duplicateEmail.StatusCode);
    }

    [Fact]
    public async Task TurnstileVerifierRequiresMatchingActionAndHostname()
    {
        var handler = new StaticResponseHandler("""
            {
              "success": true,
              "action": "login",
              "hostname": "TUNNEL.EXAMPLE.COM.",
              "error-codes": []
            }
            """);
        var options = Options.Create(new AuthOptions
        {
            TurnstileEnabled = true,
            TurnstileSiteKey = "site-key",
            TurnstileSecretKey = "secret-key",
            TurnstileVerifyUrl = "https://verify.example/siteverify",
            TurnstileAllowedHostnames = "tunnel.example.com",
        });
        var verifier = new TurnstileVerifier(options, new StaticHttpClientFactory(handler),
            NullLogger<TurnstileVerifier>.Instance);

        await verifier.VerifyAsync("valid-token", TurnstileVerifier.LoginAction);

        Assert.Contains("secret=secret-key", handler.LastRequestBody, StringComparison.Ordinal);
        Assert.Contains("response=valid-token", handler.LastRequestBody, StringComparison.Ordinal);
        await Assert.ThrowsAsync<ArgumentException>(() =>
            verifier.VerifyAsync("valid-token", TurnstileVerifier.RegisterAction));

        var wrongHostnameOptions = Options.Create(new AuthOptions
        {
            TurnstileEnabled = true,
            TurnstileSiteKey = "site-key",
            TurnstileSecretKey = "secret-key",
            TurnstileVerifyUrl = "https://verify.example/siteverify",
            TurnstileAllowedHostnames = "other.example.com",
        });
        var wrongHostnameVerifier = new TurnstileVerifier(wrongHostnameOptions,
            new StaticHttpClientFactory(handler), NullLogger<TurnstileVerifier>.Instance);
        await Assert.ThrowsAsync<ArgumentException>(() =>
            wrongHostnameVerifier.VerifyAsync("valid-token", TurnstileVerifier.LoginAction));
    }

    private sealed class CapturingEmailSender : IRegistrationEmailSender
    {
        public bool Configured => true;
        public string? LastEmail { get; private set; }
        public string? LastCode { get; private set; }

        public Task SendVerificationCodeAsync(string email, string username, string code,
            long ttlSeconds, CancellationToken cancellationToken = default)
        {
            LastEmail = email;
            LastCode = code;
            return Task.CompletedTask;
        }
    }

    private sealed class FakeTurnstileVerifier : ITurnstileVerifier
    {
        public const string ValidToken = "valid-turnstile-token";

        public bool Enabled => true;
        public bool Configured => true;
        public string SiteKey => "test-site-key";
        public List<string> Actions { get; } = [];

        public Task VerifyAsync(string? responseToken, string expectedAction,
            CancellationToken cancellationToken = default)
        {
            if (!string.Equals(responseToken, ValidToken, StringComparison.Ordinal))
            {
                throw new ArgumentException("人机验证失败，请重试");
            }
            Actions.Add(expectedAction);
            return Task.CompletedTask;
        }
    }

    private sealed class StaticHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private sealed class StaticResponseHandler(string responseJson) : HttpMessageHandler
    {
        public string LastRequestBody { get; private set; } = string.Empty;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            LastRequestBody = request.Content is null
                ? string.Empty
                : await request.Content.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(responseJson, System.Text.Encoding.UTF8, "application/json"),
            };
        }
    }

    private sealed record OidcRegistrationConfig(
        bool RegistrationEnabled,
        bool EmailVerificationRequired,
        bool TurnstileEnabled,
        string TurnstileSiteKey);
}
