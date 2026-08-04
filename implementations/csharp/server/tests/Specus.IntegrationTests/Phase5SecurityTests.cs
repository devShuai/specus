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
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Specus.Server.ControlChannel;
using Specus.Server.Configuration;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using Specus.Server.Security;

namespace Specus.IntegrationTests;

public sealed class Phase5SecurityTests
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    [Fact]
    public async Task OidcConfigReflectsConfiguredClientAndPasswordLoginFlag()
    {
        await using var server = await TestServerFixture.StartAsync(new Dictionary<string, string?>
        {
            ["Specus:Oidc:ClientId"] = "admin-spa",
            ["Specus:Oidc:AuthorizationEndpoint"] = "https://issuer.example/authorize",
            ["Specus:Oidc:RegistrationEndpoint"] = "https://issuer.example/register",
            ["Specus:Oidc:EndSessionEndpoint"] = "https://issuer.example/logout",
            ["Specus:Oidc:RedirectUri"] = "http://127.0.0.1:8088/callback",
            ["Specus:Oidc:Scope"] = "openid profile",
            ["Specus:Auth:PasswordLoginEnabled"] = "false",
        });
        using var client = server.CreateClient();

        var body = await client.GetFromJsonAsync<OidcConfigBody>("/oidc-config", JsonOptions);

        Assert.NotNull(body);
        Assert.True(body!.Configured);
        Assert.Equal("https://issuer.example/authorize", body.AuthorizationEndpoint);
        Assert.Equal("https://issuer.example/register", body.RegistrationEndpoint);
        Assert.Equal("https://issuer.example/logout", body.EndSessionEndpoint);
        Assert.Equal("admin-spa", body.ClientId);
        Assert.Equal("http://127.0.0.1:8088/callback", body.RedirectUri);
        Assert.Equal("openid profile", body.Scope);
        Assert.False(body.PasswordLoginEnabled);
    }

    [Fact]
    public async Task OidcTokenExchangeUsesBasicAuthForConfidentialClient()
    {
        using var rsa = RSA.Create(2048);
        const string nonce = "nonce-1";
        var idToken = CreateOidcToken(rsa, "exchange-key", nonce: nonce,
            audiences: ["admin-spa"]);
        var jwks = CreateJwks(rsa, "exchange-key");
        var fake = new CapturingOidcTokenEndpointClient(new OidcTokenEndpointResponse(
            HttpStatusCode.OK,
            $$"""
            {"access_token":"upstream-access-1","id_token":"{{idToken}}","token_type":"Bearer","expires_in":90}
            """));
        await using var server = await TestServerFixture.StartAsync(
            OidcTokenExchangeConfiguration(clientSecret: "secret-1"),
            services =>
            {
                services.RemoveAll<IOidcTokenEndpointClient>();
                services.AddSingleton<IOidcTokenEndpointClient>(fake);
                services.RemoveAll<IOidcJwkProvider>();
                services.AddSingleton<IOidcJwkProvider>(new StaticOidcJwkProvider(jwks));
            });
        using var client = server.CreateClient();

        var response = await client.PostAsJsonAsync("/oidc/token", new
        {
            code = "code-1",
            codeVerifier = "verifier-1",
            nonce,
        });

        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadFromJsonAsync<OidcTokenBody>(JsonOptions);
        Assert.NotNull(body);
        Assert.NotEqual("upstream-access-1", body!.AccessToken);
        Assert.Equal(idToken, body.IdToken);
        Assert.Equal("Bearer", body.TokenType);
        var localTokens = server.HostServices.GetRequiredService<LocalTokenService>();
        Assert.Equal(localTokens.TtlSeconds, body.ExpiresIn);
        var principal = localTokens.Validate(body.AccessToken);
        Assert.NotNull(principal);
        Assert.Equal("oidc-user@example.com", principal!.Identity!.Name);

        await using (var scope = server.HostServices.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            var user = await db.ManagementUsers.SingleAsync(row => row.Username == "oidc-user@example.com");
            Assert.Equal("https://issuer.example", user.OidcIssuer);
            Assert.Equal("oidc-user", user.OidcSubject);
            Assert.False(string.IsNullOrWhiteSpace(user.OidcIdentityKey));
            Assert.Equal("USER", user.Role.ToString().ToUpperInvariant());
        }

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
        using var rsa = RSA.Create(2048);
        const string nonce = "nonce-2";
        var idToken = CreateOidcToken(rsa, "public-key", nonce: nonce,
            audiences: ["admin-spa"]);
        var jwks = CreateJwks(rsa, "public-key");
        var fake = new CapturingOidcTokenEndpointClient(new OidcTokenEndpointResponse(
            HttpStatusCode.OK,
            $$"""{"access_token":"upstream-access-2","id_token":"{{idToken}}","token_type":"Bearer","expires_in":120}"""));
        await using var server = await TestServerFixture.StartAsync(
            OidcTokenExchangeConfiguration(clientSecret: string.Empty),
            services =>
            {
                services.RemoveAll<IOidcTokenEndpointClient>();
                services.AddSingleton<IOidcTokenEndpointClient>(fake);
                services.RemoveAll<IOidcJwkProvider>();
                services.AddSingleton<IOidcJwkProvider>(new StaticOidcJwkProvider(jwks));
            });
        using var client = server.CreateClient();

        var response = await client.PostAsJsonAsync("/oidc/token", new
        {
            code = "code-2",
            codeVerifier = "verifier-2",
            nonce,
        });

        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadFromJsonAsync<OidcTokenBody>(JsonOptions);
        Assert.NotNull(body);
        Assert.NotEqual("upstream-access-2", body!.AccessToken);
        Assert.Equal(idToken, body.IdToken);
        Assert.NotNull(fake.LastRequest);
        Assert.Equal("admin-spa", fake.LastRequest!.Form["client_id"]);
        Assert.Null(fake.LastRequest.BasicAuthorization);
    }

    [Fact]
    public async Task OidcTokenExchangeRequiresNonceBeforeCallingProvider()
    {
        var fake = new CapturingOidcTokenEndpointClient(new OidcTokenEndpointResponse(
            HttpStatusCode.OK, "{}"));
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
            code = "code-without-nonce",
            codeVerifier = "verifier-without-nonce",
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(fake.LastRequest);
    }

    [Fact]
    public async Task OidcTokenExchangeRejectsNonceMismatch()
    {
        using var rsa = RSA.Create(2048);
        var idToken = CreateOidcToken(rsa, "nonce-key", nonce: "issued-nonce",
            audiences: ["admin-spa"]);
        var jwks = CreateJwks(rsa, "nonce-key");
        var fake = new CapturingOidcTokenEndpointClient(new OidcTokenEndpointResponse(
            HttpStatusCode.OK, $$"""{"id_token":"{{idToken}}","token_type":"Bearer"}"""));
        await using var server = await TestServerFixture.StartAsync(
            OidcTokenExchangeConfiguration(clientSecret: string.Empty),
            services =>
            {
                services.RemoveAll<IOidcTokenEndpointClient>();
                services.AddSingleton<IOidcTokenEndpointClient>(fake);
                services.RemoveAll<IOidcJwkProvider>();
                services.AddSingleton<IOidcJwkProvider>(new StaticOidcJwkProvider(jwks));
            });
        using var client = server.CreateClient();

        var response = await client.PostAsJsonAsync("/oidc/token", new
        {
            code = "code-nonce-mismatch",
            codeVerifier = "verifier-nonce-mismatch",
            nonce = "different-nonce",
        });

        Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
    }

    [Fact]
    public async Task OidcTokenExchangeRejectsInvalidSignature()
    {
        using var signingRsa = RSA.Create(2048);
        using var trustedRsa = RSA.Create(2048);
        var idToken = CreateOidcToken(signingRsa, "shared-key-id",
            nonce: "nonce-invalid-signature", audiences: ["admin-spa"]);
        var jwks = CreateJwks(trustedRsa, "shared-key-id");
        var fake = new CapturingOidcTokenEndpointClient(new OidcTokenEndpointResponse(
            HttpStatusCode.OK, $$"""{"id_token":"{{idToken}}","token_type":"Bearer"}"""));
        await using var server = await TestServerFixture.StartAsync(
            OidcTokenExchangeConfiguration(clientSecret: string.Empty),
            services =>
            {
                services.RemoveAll<IOidcTokenEndpointClient>();
                services.AddSingleton<IOidcTokenEndpointClient>(fake);
                services.RemoveAll<IOidcJwkProvider>();
                services.AddSingleton<IOidcJwkProvider>(new StaticOidcJwkProvider(jwks));
            });
        using var client = server.CreateClient();

        var response = await client.PostAsJsonAsync("/oidc/token", new
        {
            code = "code-invalid-signature",
            codeVerifier = "verifier-invalid-signature",
            nonce = "nonce-invalid-signature",
        });

        Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
    }

    [Fact]
    public async Task OidcRs256BearerCanReadAdminApiButCannotUseLocalRefresh()
    {
        using var rsa = RSA.Create(2048);
        var token = CreateOidcToken(rsa, "test-key");
        var jwks = CreateJwks(rsa, "test-key");
        await using var server = await TestServerFixture.StartAsync(new Dictionary<string, string?>
        {
            ["Specus:Oidc:Issuer"] = "https://issuer.example",
            ["Specus:Oidc:Audience"] = "admin-api",
            ["Specus:Oidc:JwkSetUri"] = "https://issuer.example/jwks",
        }, services =>
        {
            services.RemoveAll<IOidcJwkProvider>();
            services.AddSingleton<IOidcJwkProvider>(new StaticOidcJwkProvider(jwks));
        });
        await BindOidcUserAsync(server, tenantId: "default", role: ManagementRole.User);
        using var client = server.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var overview = await client.GetAsync("/api/admin/overview");
        Assert.Equal(HttpStatusCode.OK, overview.StatusCode);

        var refresh = await client.PostAsync("/auth/refresh", content: null);
        Assert.Equal(HttpStatusCode.BadRequest, refresh.StatusCode);
    }

    [Fact]
    public async Task OidcRs256BearerUsesCurrentLocalTenantInsteadOfExternalClaim()
    {
        using var rsa = RSA.Create(2048);
        var token = CreateOidcToken(rsa, "tenant-key", tenantClaimName: "org_id", tenantId: "tenant-oidc");
        var jwks = CreateJwks(rsa, "tenant-key");
        await using var server = await TestServerFixture.StartAsync(new Dictionary<string, string?>
        {
            ["Specus:Auth:TenantId"] = "default",
            ["Specus:Oidc:Issuer"] = "https://issuer.example",
            ["Specus:Oidc:Audience"] = "admin-api",
            ["Specus:Oidc:JwkSetUri"] = "https://issuer.example/jwks",
            ["Specus:Oidc:TenantClaim"] = "org_id",
        }, services =>
        {
            services.RemoveAll<IOidcJwkProvider>();
            services.AddSingleton<IOidcJwkProvider>(new StaticOidcJwkProvider(jwks));
        });
        await BindOidcUserAsync(server, tenantId: "tenant-local", role: ManagementRole.User);
        using var client = server.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var me = await client.GetFromJsonAsync<CurrentUserBody>("/api/admin/me", JsonOptions);

        Assert.NotNull(me);
        Assert.Equal("oidc-user@example.com", me!.Username);
        Assert.Equal("tenant-local", me.TenantId);
    }

    [Fact]
    public async Task OidcDirectBearerRequiresAudienceBindingAndEnabledLocalAccount()
    {
        using var rsa = RSA.Create(2048);
        var jwks = CreateJwks(rsa, "direct-key");
        await using var server = await TestServerFixture.StartAsync(new Dictionary<string, string?>
        {
            ["Specus:Oidc:Issuer"] = "https://issuer.example",
            ["Specus:Oidc:Audience"] = "admin-api",
            ["Specus:Oidc:JwkSetUri"] = "https://issuer.example/jwks",
        }, services =>
        {
            services.RemoveAll<IOidcJwkProvider>();
            services.AddSingleton<IOidcJwkProvider>(new StaticOidcJwkProvider(jwks));
        });
        using var client = server.CreateClient();

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer",
            CreateOidcToken(rsa, "direct-key", subject: "unbound"));
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await client.GetAsync("/api/admin/me")).StatusCode);

        await BindOidcUserAsync(server, "tenant-current", ManagementRole.Admin);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer",
            CreateOidcToken(rsa, "direct-key", audiences: ["wrong-api"]));
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await client.GetAsync("/api/admin/me")).StatusCode);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer",
            CreateOidcToken(rsa, "direct-key"));
        var me = await client.GetFromJsonAsync<CurrentUserBody>("/api/admin/me", JsonOptions);
        Assert.NotNull(me);
        Assert.Equal("tenant-current", me!.TenantId);
        Assert.Equal("ADMIN", me.Role);

        await SetUserEnabledAsync(server, "oidc-user@example.com", enabled: false);
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await client.GetAsync("/api/admin/me")).StatusCode);
    }

    [Fact]
    public async Task OidcDirectBearerRejectsServerWithoutConfiguredAudience()
    {
        using var rsa = RSA.Create(2048);
        var jwks = CreateJwks(rsa, "no-audience-key");
        await using var server = await TestServerFixture.StartAsync(new Dictionary<string, string?>
        {
            ["Specus:Oidc:Issuer"] = "https://issuer.example",
            ["Specus:Oidc:Audience"] = string.Empty,
            ["Specus:Oidc:JwkSetUri"] = "https://issuer.example/jwks",
        }, services =>
        {
            services.RemoveAll<IOidcJwkProvider>();
            services.AddSingleton<IOidcJwkProvider>(new StaticOidcJwkProvider(jwks));
        });
        await BindOidcUserAsync(server, "default", ManagementRole.User);
        using var client = server.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer",
            CreateOidcToken(rsa, "no-audience-key"));

        Assert.Equal(HttpStatusCode.Unauthorized,
            (await client.GetAsync("/api/admin/me")).StatusCode);
    }

    [Fact]
    public async Task OidcBearerAndIdTokenFailClosedWithoutConfiguredIssuer()
    {
        using var rsa = RSA.Create(2048);
        var validator = CreateOidcValidator(
            new StaticOidcJwkProvider(CreateJwks(rsa, "missing-issuer-key")),
            issuer: string.Empty);
        const string nonce = "configured-issuer-required";

        Assert.Null(await validator.ValidateBearerAsync(
            CreateOidcToken(rsa, "missing-issuer-key")));
        Assert.Null(await validator.ValidateIdTokenAsync(
            CreateOidcToken(rsa, "missing-issuer-key", nonce: nonce,
                audiences: ["admin-spa"]), nonce));
    }

    [Fact]
    public async Task OidcIdTokenRequiresClientAudienceAndAuthorizedParty()
    {
        using var rsa = RSA.Create(2048);
        var jwks = CreateJwks(rsa, "id-key");
        await using var server = await TestServerFixture.StartAsync(
            OidcTokenExchangeConfiguration(string.Empty), services =>
            {
                services.RemoveAll<IOidcJwkProvider>();
                services.AddSingleton<IOidcJwkProvider>(new StaticOidcJwkProvider(jwks));
            });
        var validator = server.HostServices.GetRequiredService<OidcTokenValidator>();
        const string nonce = "id-token-nonce";

        Assert.Null(await validator.ValidateIdTokenAsync(
            CreateOidcToken(rsa, "id-key", nonce: nonce, audiences: ["admin-api"]), nonce));
        Assert.Null(await validator.ValidateIdTokenAsync(
            CreateOidcToken(rsa, "id-key", nonce: nonce,
                audiences: ["admin-spa", "another" ]), nonce));
        Assert.Null(await validator.ValidateIdTokenAsync(
            CreateOidcToken(rsa, "id-key", nonce: nonce, audiences: ["admin-spa"],
                authorizedParty: "other-client"), nonce));
        Assert.NotNull(await validator.ValidateIdTokenAsync(
            CreateOidcToken(rsa, "id-key", nonce: nonce,
                audiences: ["admin-spa"]), nonce));
        Assert.NotNull(await validator.ValidateIdTokenAsync(
            CreateOidcToken(rsa, "id-key", nonce: nonce,
                audiences: ["admin-spa"], authorizedParty: string.Empty), nonce));
        Assert.NotNull(await validator.ValidateIdTokenAsync(
            CreateOidcToken(rsa, "id-key", nonce: nonce,
                audiences: ["admin-spa"], authorizedParty: "   "), nonce));
        Assert.Null(await validator.ValidateIdTokenAsync(
            CreateOidcToken(rsa, "id-key", nonce: nonce,
                audiences: ["admin-spa", "another"], authorizedParty: "   "), nonce));
        Assert.Null(await validator.ValidateIdTokenAsync(
            CreateOidcToken(rsa, "id-key", nonce: nonce,
                audiences: ["admin-spa", "admin-spa"]), nonce));
        Assert.NotNull(await validator.ValidateIdTokenAsync(
            CreateOidcToken(rsa, "id-key", nonce: nonce,
                audiences: ["admin-spa", "another"], authorizedParty: "admin-spa"), nonce));
    }

    [Fact]
    public async Task OidcIdTokenRejectsWhitespaceAlteredNonceAzpAndIssuer()
    {
        using var rsa = RSA.Create(2048);
        var validator = CreateOidcValidator(
            new StaticOidcJwkProvider(CreateJwks(rsa, "exact-claims-key")));
        const string nonce = "exact-nonce";

        Assert.Null(await validator.ValidateIdTokenAsync(
            CreateOidcToken(rsa, "exact-claims-key", nonce: $" {nonce} ",
                audiences: ["admin-spa"]), nonce));
        Assert.Null(await validator.ValidateIdTokenAsync(
            CreateOidcToken(rsa, "exact-claims-key", nonce: nonce,
                audiences: ["admin-spa"], authorizedParty: " admin-spa "), nonce));
        Assert.Null(await validator.ValidateIdTokenAsync(
            CreateOidcToken(rsa, "exact-claims-key", nonce: nonce,
                audiences: ["admin-spa"], issuer: " https://issuer.example "), nonce));
    }

    [Fact]
    public async Task OidcExchangeCannotClaimBuiltInAdminUsername()
    {
        using var rsa = RSA.Create(2048);
        const string nonce = "admin-claim-nonce";
        var idToken = CreateOidcToken(rsa, "admin-claim-key", nonce: nonce,
            audiences: ["admin-spa"], preferredUsername: "admin");
        var fake = new CapturingOidcTokenEndpointClient(new OidcTokenEndpointResponse(
            HttpStatusCode.OK, $$"""{"id_token":"{{idToken}}","token_type":"Bearer"}"""));
        await using var server = await TestServerFixture.StartAsync(
            OidcTokenExchangeConfiguration(string.Empty), services =>
            {
                services.RemoveAll<IOidcTokenEndpointClient>();
                services.AddSingleton<IOidcTokenEndpointClient>(fake);
                services.RemoveAll<IOidcJwkProvider>();
                services.AddSingleton<IOidcJwkProvider>(new StaticOidcJwkProvider(
                    CreateJwks(rsa, "admin-claim-key")));
            });
        using var client = server.CreateClient();

        var response = await client.PostAsJsonAsync("/oidc/token", new
        {
            code = "admin-code",
            codeVerifier = "admin-verifier",
            nonce,
        });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        Assert.False(await db.ManagementUsers.AnyAsync(item => item.Username == "admin"));
    }

    [Fact]
    public async Task LocalBearerReloadsCurrentTenantRoleAndEnabledStateForRequestAndRefresh()
    {
        await using var server = await TestServerFixture.StartAsync();
        await CreateLocalUserAsync(server, "dynamic-user", "tenant-current", ManagementRole.User);
        var tokens = server.HostServices.GetRequiredService<LocalTokenService>();
        var stale = tokens.IssueToken("dynamic-user", "tenant-stale", ManagementRole.Admin);
        using var client = server.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", stale);

        var me = await client.GetFromJsonAsync<CurrentUserBody>("/api/admin/me", JsonOptions);
        Assert.NotNull(me);
        Assert.Equal("tenant-current", me!.TenantId);
        Assert.Equal("USER", me.Role);

        var refresh = await client.PostAsync("/auth/refresh", content: null);
        refresh.EnsureSuccessStatusCode();
        var body = await refresh.Content.ReadFromJsonAsync<OidcTokenBody>(JsonOptions);
        var refreshed = tokens.Validate(body!.AccessToken);
        Assert.Equal("tenant-current", refreshed!.FindFirst("tenant_id")!.Value);
        Assert.Equal("USER", refreshed.FindFirst("role")!.Value);

        await SetUserEnabledAsync(server, "dynamic-user", enabled: false);
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await client.GetAsync("/api/admin/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await client.PostAsync("/auth/refresh", content: null)).StatusCode);
    }

    [Fact]
    public async Task DisabledPasswordLoginInvalidatesExistingBuiltInAdminToken()
    {
        await using var server = await TestServerFixture.StartAsync(new Dictionary<string, string?>
        {
            ["Specus:Auth:PasswordLoginEnabled"] = "false",
            ["Specus:Auth:Password"] = "still-configured",
        });
        var tokens = server.HostServices.GetRequiredService<LocalTokenService>();
        using var client = server.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer",
            tokens.IssueToken("admin", "default", ManagementRole.Admin));

        Assert.Equal(HttpStatusCode.Unauthorized,
            (await client.GetAsync("/api/admin/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await client.PostAsync("/auth/refresh", content: null)).StatusCode);
    }

    [Fact]
    public async Task ConcurrentFirstOidcBindingHasExactlyOneWinner()
    {
        await using var server = await TestServerFixture.StartAsync();
        await CreateLocalUserAsync(server, "shared-user", "default", ManagementRole.User);

        async Task<LoginUser?> BindAsync(string subject)
        {
            await using var scope = server.HostServices.CreateAsyncScope();
            var users = scope.ServiceProvider.GetRequiredService<ManagementUserService>();
            return await users.ResolveOrProvisionOidcUserAsync("https://issuer.example", subject,
                "shared-user", CancellationToken.None);
        }

        var results = await Task.WhenAll(BindAsync("subject-a"), BindAsync("subject-b"));

        Assert.Single(results, result => result is not null);
        await using var verifyScope = server.HostServices.CreateAsyncScope();
        var db = verifyScope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var row = await db.ManagementUsers.SingleAsync(item => item.Username == "shared-user");
        Assert.Contains(row.OidcSubject, new[] { "subject-a", "subject-b" });
    }

    [Fact]
    public async Task JwksUnknownKidRefreshesOnceAndAcceptsRotatedKey()
    {
        using var oldRsa = RSA.Create(2048);
        using var newRsa = RSA.Create(2048);
        var provider = new SequencedOidcJwkProvider(
            () => CreateJwks(oldRsa, "old-key"),
            () => CreateJwks(newRsa, "new-key"));
        var validator = CreateOidcValidator(provider);

        Assert.NotNull(await validator.ValidateBearerAsync(
            CreateOidcToken(oldRsa, "old-key")));
        Assert.NotNull(await validator.ValidateBearerAsync(
            CreateOidcToken(newRsa, "new-key")));
        Assert.NotNull(await validator.ValidateBearerAsync(
            CreateOidcToken(oldRsa, "old-key")));
        Assert.Equal(2, provider.CallCount);
    }

    [Fact]
    public async Task JwksTokenWithoutKidTriesEveryCompatibleSigningKey()
    {
        using var firstRsa = RSA.Create(2048);
        using var secondRsa = RSA.Create(2048);
        var validator = CreateOidcValidator(new StaticOidcJwkProvider(
            CreateJwks((firstRsa, "first-key"), (secondRsa, "second-key"))));

        Assert.NotNull(await validator.ValidateBearerAsync(
            CreateOidcToken(secondRsa, keyId: null)));
        // Nimbus distinguishes an absent kid from an explicitly empty kid. The latter only
        // matches a JWK whose own kid is empty, so the regular named keys above must not match.
        Assert.Null(await validator.ValidateBearerAsync(
            CreateOidcToken(secondRsa, keyId: string.Empty)));
    }

    [Fact]
    public async Task JwksRefreshContinuesWhenFirstCallerCancels()
    {
        using var rsa = RSA.Create(2048);
        var provider = new BlockingOidcJwkProvider(CreateJwks(rsa, "shared-key"));
        var validator = CreateOidcValidator(provider);
        var token = CreateOidcToken(rsa, "shared-key");
        using var firstCancellation = new CancellationTokenSource();

        var first = validator.ValidateBearerAsync(token, firstCancellation.Token).AsTask();
        await provider.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var second = validator.ValidateBearerAsync(token).AsTask();
        firstCancellation.Cancel();
        provider.Release.TrySetResult();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first);
        Assert.NotNull(await second);
        Assert.Equal(1, provider.CallCount);
    }

    [Fact]
    public async Task JwksBadSignaturesShareRefreshCooldownAndRefreshFailureKeepsHealthyKeys()
    {
        using var rsa = RSA.Create(2048);
        var healthy = CreateJwks(rsa, "stable-key");
        var provider = new SequencedOidcJwkProvider(
            () => healthy,
            () => throw new HttpRequestException("temporary JWKS outage"));
        var validator = CreateOidcValidator(provider);
        var good = CreateOidcToken(rsa, "stable-key");

        Assert.NotNull(await validator.ValidateBearerAsync(good));
        var bad = CorruptSignature(good);
        var results = await Task.WhenAll(Enumerable.Range(0, 32)
            .Select(_ => validator.ValidateBearerAsync(bad).AsTask()));
        Assert.All(results, result => Assert.Null(result));
        Assert.Equal(2, provider.CallCount);
        Assert.NotNull(await validator.ValidateBearerAsync(good));
        Assert.Equal(2, provider.CallCount);
    }

    [Fact]
    public async Task JwksUnknownKidNegativeCacheIsBounded()
    {
        using var rsa = RSA.Create(2048);
        var provider = new SequencedOidcJwkProvider(() => CreateJwks(rsa, "known-key"));
        var validator = CreateOidcValidator(provider);
        var known = CreateOidcToken(rsa, "known-key");
        Assert.NotNull(await validator.ValidateBearerAsync(known));

        for (var index = 0; index < OidcTokenValidator.MaximumUnknownKeyEntries + 128; index++)
        {
            Assert.Null(await validator.ValidateBearerAsync(
                ReplaceTokenKeyId(known, $"unknown-{index}")));
        }

        Assert.Equal(OidcTokenValidator.MaximumUnknownKeyEntries,
            validator.UnknownKeyCacheCountForTests);
        Assert.Equal(2, provider.CallCount);
    }

    [Fact]
    public async Task JwksRejectsOversizeWeakAndNonSigningKeys()
    {
        using var strongRsa = RSA.Create(2048);
        using var weakRsa = RSA.Create(1024);
        var token = CreateOidcToken(strongRsa, "filtered-key");

        var oversized = CreateOidcValidator(new StaticOidcJwkProvider(
            new string('x', OidcTokenValidator.MaximumJwksResponseBytes + 1)));
        Assert.Null(await oversized.ValidateBearerAsync(token));

        var weak = CreateOidcValidator(new StaticOidcJwkProvider(
            CreateJwks(weakRsa, "filtered-key")));
        Assert.Null(await weak.ValidateBearerAsync(
            CreateOidcToken(weakRsa, "filtered-key")));

        var encryptionOnly = CreateOidcValidator(new StaticOidcJwkProvider(
            CreateJwks(strongRsa, "filtered-key", use: "enc")));
        Assert.Null(await encryptionOnly.ValidateBearerAsync(token));

        var wrongAlgorithm = CreateOidcValidator(new StaticOidcJwkProvider(
            CreateJwks(strongRsa, "filtered-key", algorithm: "RS512")));
        Assert.Null(await wrongAlgorithm.ValidateBearerAsync(token));

        var invalidExponent = CreateOidcValidator(new StaticOidcJwkProvider(
            CreateJwks(strongRsa, "filtered-key", exponentOverride: "Ag")));
        Assert.Null(await invalidExponent.ValidateBearerAsync(token));
    }

    [Fact]
    public async Task SelfSignedTlsModeAcceptsControlChannelSslHandshake()
    {
        await using var server = await TestServerFixture.StartAsync(new Dictionary<string, string?>
        {
            ["Specus:Tls:Mode"] = "self-signed",
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

    [Theory]
    [InlineData("0.0.0.0", false)]
    [InlineData("::", false)]
    [InlineData("127.0.0.1", true)]
    [InlineData("10.1.2.3", true)]
    [InlineData("172.16.0.1", true)]
    [InlineData("172.31.255.254", true)]
    [InlineData("172.32.0.1", false)]
    [InlineData("192.168.1.2", true)]
    [InlineData("203.0.113.1", false)]
    [InlineData("fd00::1", true)]
    public void ControlChannelClassifiesPrivateBindAddresses(string address, bool expected)
    {
        Assert.Equal(expected,
            ControlChannelListener.IsPrivateBindAddress(IPAddress.Parse(address)));
    }

    [Fact]
    public async Task RequiredEncryptionRejectsPlaintextPublicControlBinding()
    {
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            await using var _ = await TestServerFixture.StartAsync(new Dictionary<string, string?>
            {
                ["Specus:Tls:Mode"] = "disabled",
                ["Specus:Tls:RequireEncryption"] = "true",
                ["Specus:Tls:TerminatedUpstream"] = "true",
                ["Specus:Netty:BindAddress"] = "0.0.0.0",
            });
        });
    }

    [Fact]
    public async Task RequiredEncryptionRejectsSelfSignedControlCertificate()
    {
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            await using var _ = await TestServerFixture.StartAsync(new Dictionary<string, string?>
            {
                ["Specus:Tls:Mode"] = "self-signed",
                ["Specus:Tls:RequireEncryption"] = "true",
                ["Specus:Netty:BindAddress"] = "127.0.0.1",
            });
        });
    }

    private static Dictionary<string, string?> OidcTokenExchangeConfiguration(string clientSecret) => new()
    {
        ["Specus:Oidc:Issuer"] = "https://issuer.example",
        ["Specus:Oidc:Audience"] = "admin-api",
        ["Specus:Oidc:JwkSetUri"] = "https://issuer.example/jwks",
        ["Specus:Oidc:ClientId"] = "admin-spa",
        ["Specus:Oidc:ClientSecret"] = clientSecret,
        ["Specus:Oidc:TokenEndpoint"] = "https://issuer.example/token",
        ["Specus:Oidc:RedirectUri"] = "http://127.0.0.1:8088/callback",
    };

    private static string CreateOidcToken(RSA rsa, string? keyId,
        string? tenantClaimName = null, string? tenantId = null, string? nonce = null,
        IReadOnlyList<string>? audiences = null, string subject = "oidc-user",
        string preferredUsername = "oidc-user@example.com", string? authorizedParty = null,
        string issuer = "https://issuer.example")
    {
        var now = DateTimeOffset.UtcNow;
        var headerValues = new Dictionary<string, object?>
        {
            ["alg"] = "RS256",
            ["typ"] = "JWT",
        };
        if (keyId is not null)
        {
            headerValues["kid"] = keyId;
        }
        var header = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(
            headerValues, JsonOptions));
        var payloadValues = new Dictionary<string, object?>
        {
            ["iss"] = issuer,
            ["sub"] = subject,
            ["preferred_username"] = preferredUsername,
            ["aud"] = audiences ?? ["admin-api"],
            ["iat"] = now.ToUnixTimeSeconds(),
            ["exp"] = now.AddMinutes(10).ToUnixTimeSeconds(),
        };
        if (!string.IsNullOrWhiteSpace(nonce))
        {
            payloadValues["nonce"] = nonce;
        }
        if (!string.IsNullOrWhiteSpace(tenantClaimName))
        {
            payloadValues[tenantClaimName] = tenantId;
        }
        if (authorizedParty is not null)
        {
            payloadValues["azp"] = authorizedParty;
        }
        var payload = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(payloadValues, JsonOptions));
        var signingInput = $"{header}.{payload}";
        var signature = rsa.SignData(Encoding.ASCII.GetBytes(signingInput),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        return $"{signingInput}.{Base64UrlEncode(signature)}";
    }

    private static string CreateJwks(RSA rsa, string keyId, string algorithm = "RS256",
        string? use = null, string? exponentOverride = null)
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
                    alg = algorithm,
                    use,
                    n = Base64UrlEncode(parameters.Modulus!),
                    e = exponentOverride ?? Base64UrlEncode(parameters.Exponent!),
                },
            },
        }, JsonOptions);
    }

    private static string CreateJwks(params (RSA Rsa, string KeyId)[] signingKeys)
    {
        var keys = signingKeys.Select(entry =>
        {
            var parameters = entry.Rsa.ExportParameters(includePrivateParameters: false);
            return new
            {
                kty = "RSA",
                kid = entry.KeyId,
                alg = "RS256",
                use = (string?)null,
                n = Base64UrlEncode(parameters.Modulus!),
                e = Base64UrlEncode(parameters.Exponent!),
            };
        }).ToArray();
        return JsonSerializer.Serialize(new { keys }, JsonOptions);
    }

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static OidcTokenValidator CreateOidcValidator(IOidcJwkProvider provider,
        string issuer = "https://issuer.example") => new(
        Options.Create(new OidcOptions
        {
            Issuer = issuer,
            Audience = "admin-api",
            ClientId = "admin-spa",
            JwkSetUri = "https://issuer.example/jwks",
        }), provider, NullLogger<OidcTokenValidator>.Instance);

    private static string CorruptSignature(string token)
    {
        var parts = token.Split('.');
        var signature = JwtTokenUtility.Base64UrlDecode(parts[2]);
        signature[0] ^= 0x80;
        return $"{parts[0]}.{parts[1]}.{Base64UrlEncode(signature)}";
    }

    private static string ReplaceTokenKeyId(string token, string keyId)
    {
        var parts = token.Split('.');
        var header = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(new
        {
            alg = "RS256",
            typ = "JWT",
            kid = keyId,
        }, JsonOptions));
        return $"{header}.{parts[1]}.{parts[2]}";
    }

    private static async Task BindOidcUserAsync(TestServerFixture server,
        string tenantId, ManagementRole role, bool enabled = true,
        string subject = "oidc-user", string preferredUsername = "oidc-user@example.com")
    {
        await using var scope = server.HostServices.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<ManagementUserService>();
        var login = await users.ResolveOrProvisionOidcUserAsync("https://issuer.example", subject,
            preferredUsername, CancellationToken.None);
        Assert.NotNull(login);
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var entity = await db.ManagementUsers.SingleAsync(item => item.Username == preferredUsername);
        entity.TenantId = tenantId;
        entity.Role = role;
        entity.Enabled = enabled;
        entity.UpdatedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync();
    }

    private static async Task CreateLocalUserAsync(TestServerFixture server, string username,
        string tenantId, ManagementRole role)
    {
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var now = DateTimeOffset.UtcNow;
        db.ManagementUsers.Add(new ManagementUser
        {
            Username = username,
            TenantId = tenantId,
            PasswordHash = "not-used-in-this-test",
            Role = role,
            Enabled = true,
            CreatedAt = now,
            UpdatedAt = now,
        });
        await db.SaveChangesAsync();
    }

    private static async Task SetUserEnabledAsync(TestServerFixture server, string username,
        bool enabled)
    {
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var user = await db.ManagementUsers.SingleAsync(item => item.Username == username);
        user.Enabled = enabled;
        user.UpdatedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync();
    }

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

    private sealed class SequencedOidcJwkProvider(params Func<string>[] responses)
        : IOidcJwkProvider
    {
        private readonly object _lock = new();
        private int _callCount;

        public int CallCount => Volatile.Read(ref _callCount);

        public Task<string> GetJwksAsync(Uri jwksUri,
            CancellationToken cancellationToken = default)
        {
            Func<string> response;
            lock (_lock)
            {
                var index = _callCount++;
                response = responses[Math.Min(index, responses.Length - 1)];
            }
            return Task.FromResult(response());
        }
    }

    private sealed class BlockingOidcJwkProvider(string response) : IOidcJwkProvider
    {
        private int _callCount;

        public TaskCompletionSource Started { get; } = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        public int CallCount => Volatile.Read(ref _callCount);

        public async Task<string> GetJwksAsync(Uri jwksUri,
            CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref _callCount);
            Started.TrySetResult();
            await Release.Task.WaitAsync(cancellationToken);
            return response;
        }
    }

    private sealed record OidcConfigBody(
        bool Configured,
        string AuthorizationEndpoint,
        string RegistrationEndpoint,
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
