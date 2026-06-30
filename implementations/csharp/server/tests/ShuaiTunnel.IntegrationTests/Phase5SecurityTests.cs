using System.ComponentModel;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using ShuaiTunnel.Server.Security;

namespace ShuaiTunnel.IntegrationTests;

public sealed class Phase5SecurityTests
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    [Fact]
    public async Task OidcConfigReflectsConfiguredClientAndPasswordLoginFlag()
    {
        await using var server = await TestServerFixture.StartAsync(new Dictionary<string, string?>
        {
            ["Tunnel:Oidc:ClientId"] = "admin-spa",
            ["Tunnel:Oidc:AuthorizationEndpoint"] = "https://issuer.example/authorize",
            ["Tunnel:Oidc:EndSessionEndpoint"] = "https://issuer.example/logout",
            ["Tunnel:Oidc:RedirectUri"] = "http://127.0.0.1:8088/callback",
            ["Tunnel:Oidc:Scope"] = "openid profile",
            ["Tunnel:Auth:PasswordLoginEnabled"] = "false",
        });
        using var client = server.CreateClient();

        var body = await client.GetFromJsonAsync<OidcConfigBody>("/oidc-config", JsonOptions);

        Assert.NotNull(body);
        Assert.True(body!.Configured);
        Assert.Equal("https://issuer.example/authorize", body.AuthorizationEndpoint);
        Assert.Equal("https://issuer.example/logout", body.EndSessionEndpoint);
        Assert.Equal("admin-spa", body.ClientId);
        Assert.Equal("http://127.0.0.1:8088/callback", body.RedirectUri);
        Assert.Equal("openid profile", body.Scope);
        Assert.False(body.PasswordLoginEnabled);
    }

    [Fact]
    public async Task OidcTokenExchangeUsesBasicAuthForConfidentialClient()
    {
        var fake = new CapturingOidcTokenEndpointClient(new OidcTokenEndpointResponse(
            HttpStatusCode.OK,
            """
            {"access_token":"access-1","id_token":"id-1","token_type":"Bearer","expires_in":90}
            """));
        await using var server = await TestServerFixture.StartAsync(
            OidcTokenExchangeConfiguration(clientSecret: "secret-1"),
            services =>
            {
                services.RemoveAll<IOidcTokenEndpointClient>();
                services.AddSingleton<IOidcTokenEndpointClient>(fake);
            });
        using var client = server.CreateClient();

        var response = await client.PostAsJsonAsync("/oidc/token", new
        {
            code = "code-1",
            codeVerifier = "verifier-1",
        });

        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadFromJsonAsync<OidcTokenBody>(JsonOptions);
        Assert.NotNull(body);
        Assert.Equal("access-1", body!.AccessToken);
        Assert.Equal("id-1", body.IdToken);
        Assert.Equal("Bearer", body.TokenType);
        Assert.Equal(90, body.ExpiresIn);

        Assert.NotNull(fake.LastRequest);
        Assert.Equal("https://issuer.example/token", fake.LastRequest!.TokenEndpoint.ToString());
        Assert.Equal("authorization_code", fake.LastRequest.Form["grant_type"]);
        Assert.Equal("code-1", fake.LastRequest.Form["code"]);
        Assert.Equal("http://127.0.0.1:8088/callback", fake.LastRequest.Form["redirect_uri"]);
        Assert.Equal("verifier-1", fake.LastRequest.Form["code_verifier"]);
        Assert.False(fake.LastRequest.Form.ContainsKey("client_id"));
        Assert.Equal("Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("admin-spa:secret-1")),
            fake.LastRequest.BasicAuthorization);
    }

    [Fact]
    public async Task OidcTokenExchangeSendsClientIdForPublicClient()
    {
        var fake = new CapturingOidcTokenEndpointClient(new OidcTokenEndpointResponse(
            HttpStatusCode.OK,
            """{"access_token":"access-2","token_type":"Bearer","expires_in":120}"""));
        await using var server = await TestServerFixture.StartAsync(
            OidcTokenExchangeConfiguration(clientSecret: string.Empty),
            services =>
            {
                services.RemoveAll<IOidcTokenEndpointClient>();
                services.AddSingleton<IOidcTokenEndpointClient>(fake);
            });
        using var client = server.CreateClient();

        var response = await client.PostAsJsonAsync("/oidc/token", new
        {
            code = "code-2",
            codeVerifier = "verifier-2",
        });

        response.EnsureSuccessStatusCode();
        Assert.NotNull(fake.LastRequest);
        Assert.Equal("admin-spa", fake.LastRequest!.Form["client_id"]);
        Assert.Null(fake.LastRequest.BasicAuthorization);
    }

    [Fact]
    public async Task OidcRs256BearerCanReadAdminApiButCannotUseLocalRefresh()
    {
        using var rsa = RSA.Create(2048);
        var token = CreateOidcToken(rsa, "test-key");
        var jwks = CreateJwks(rsa, "test-key");
        await using var server = await TestServerFixture.StartAsync(new Dictionary<string, string?>
        {
            ["Tunnel:Oidc:Issuer"] = "https://issuer.example",
            ["Tunnel:Oidc:Audience"] = "admin-api",
            ["Tunnel:Oidc:JwkSetUri"] = "https://issuer.example/jwks",
        }, services =>
        {
            services.RemoveAll<IOidcJwkProvider>();
            services.AddSingleton<IOidcJwkProvider>(new StaticOidcJwkProvider(jwks));
        });
        using var client = server.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var overview = await client.GetAsync("/api/admin/overview");
        Assert.Equal(HttpStatusCode.OK, overview.StatusCode);

        var refresh = await client.PostAsync("/auth/refresh", content: null);
        Assert.Equal(HttpStatusCode.BadRequest, refresh.StatusCode);
    }

    [Fact]
    public async Task OidcRs256BearerUsesConfiguredTenantClaim()
    {
        using var rsa = RSA.Create(2048);
        var token = CreateOidcToken(rsa, "tenant-key", tenantClaimName: "org_id", tenantId: "tenant-oidc");
        var jwks = CreateJwks(rsa, "tenant-key");
        await using var server = await TestServerFixture.StartAsync(new Dictionary<string, string?>
        {
            ["Tunnel:Auth:TenantId"] = "default",
            ["Tunnel:Oidc:Issuer"] = "https://issuer.example",
            ["Tunnel:Oidc:Audience"] = "admin-api",
            ["Tunnel:Oidc:JwkSetUri"] = "https://issuer.example/jwks",
            ["Tunnel:Oidc:TenantClaim"] = "org_id",
        }, services =>
        {
            services.RemoveAll<IOidcJwkProvider>();
            services.AddSingleton<IOidcJwkProvider>(new StaticOidcJwkProvider(jwks));
        });
        using var client = server.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var me = await client.GetFromJsonAsync<CurrentUserBody>("/api/admin/me", JsonOptions);

        Assert.NotNull(me);
        Assert.Equal("oidc-user@example.com", me!.Username);
        Assert.Equal("tenant-oidc", me.TenantId);
    }

    [Fact]
    public async Task SelfSignedTlsModeAcceptsControlChannelSslHandshake()
    {
        await using var server = await TestServerFixture.StartAsync(new Dictionary<string, string?>
        {
            ["Tunnel:Tls:Mode"] = "self-signed",
        });

        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, server.ControlPort);
        using var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false);

        try
        {
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = "localhost",
                EnabledSslProtocols = SslProtocols.None,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                RemoteCertificateValidationCallback = (_, _, _, _) => true,
            });
        }
        catch (AuthenticationException ex) when (OperatingSystem.IsWindows()
            && ex.InnerException is Win32Exception win32
            && win32.NativeErrorCode == unchecked((int)0x8009030E))
        {
            return;
        }

        Assert.True(ssl.IsAuthenticated);
        Assert.True(ssl.IsEncrypted);
    }

    private static Dictionary<string, string?> OidcTokenExchangeConfiguration(string clientSecret) => new()
    {
        ["Tunnel:Oidc:ClientId"] = "admin-spa",
        ["Tunnel:Oidc:ClientSecret"] = clientSecret,
        ["Tunnel:Oidc:TokenEndpoint"] = "https://issuer.example/token",
        ["Tunnel:Oidc:RedirectUri"] = "http://127.0.0.1:8088/callback",
    };

    private static string CreateOidcToken(RSA rsa, string keyId,
        string? tenantClaimName = null, string? tenantId = null)
    {
        var now = DateTimeOffset.UtcNow;
        var header = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(new
        {
            alg = "RS256",
            typ = "JWT",
            kid = keyId,
        }, JsonOptions));
        var payloadValues = new Dictionary<string, object?>
        {
            ["iss"] = "https://issuer.example",
            ["sub"] = "oidc-user",
            ["preferred_username"] = "oidc-user@example.com",
            ["aud"] = new[] { "admin-api" },
            ["iat"] = now.ToUnixTimeSeconds(),
            ["exp"] = now.AddMinutes(10).ToUnixTimeSeconds(),
        };
        if (!string.IsNullOrWhiteSpace(tenantClaimName))
        {
            payloadValues[tenantClaimName] = tenantId;
        }
        var payload = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(payloadValues, JsonOptions));
        var signingInput = $"{header}.{payload}";
        var signature = rsa.SignData(Encoding.ASCII.GetBytes(signingInput),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        return $"{signingInput}.{Base64UrlEncode(signature)}";
    }

    private static string CreateJwks(RSA rsa, string keyId)
    {
        var parameters = rsa.ExportParameters(includePrivateParameters: false);
        return JsonSerializer.Serialize(new
        {
            keys = new[]
            {
                new
                {
                    kty = "RSA",
                    kid = keyId,
                    alg = "RS256",
                    n = Base64UrlEncode(parameters.Modulus!),
                    e = Base64UrlEncode(parameters.Exponent!),
                },
            },
        }, JsonOptions);
    }

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private sealed class CapturingOidcTokenEndpointClient : IOidcTokenEndpointClient
    {
        private readonly OidcTokenEndpointResponse _response;

        public CapturingOidcTokenEndpointClient(OidcTokenEndpointResponse response)
        {
            _response = response;
        }

        public OidcTokenEndpointRequest? LastRequest { get; private set; }

        public Task<OidcTokenEndpointResponse> ExchangeAsync(OidcTokenEndpointRequest request,
            CancellationToken cancellationToken = default)
        {
            LastRequest = request;
            return Task.FromResult(_response);
        }
    }

    private sealed class StaticOidcJwkProvider : IOidcJwkProvider
    {
        private readonly string _jwks;

        public StaticOidcJwkProvider(string jwks)
        {
            _jwks = jwks;
        }

        public Task<string> GetJwksAsync(Uri jwksUri, CancellationToken cancellationToken = default) =>
            Task.FromResult(_jwks);
    }

    private sealed record OidcConfigBody(
        bool Configured,
        string AuthorizationEndpoint,
        string EndSessionEndpoint,
        string ClientId,
        string RedirectUri,
        string Scope,
        bool PasswordLoginEnabled);

    private sealed record CurrentUserBody(
        string Username,
        string TenantId,
        string Role,
        bool Admin,
        bool BuiltIn,
        bool Enabled);

    private sealed record OidcTokenBody(
        string? AccessToken,
        string? IdToken,
        string TokenType,
        long ExpiresIn);
}
