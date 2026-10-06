using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Protocol;
using Specus.Protocol.Packets;
using Specus.Server.Data.Entities;
using Specus.Server.Http;
using Specus.Server.Management;

namespace Specus.IntegrationTests;

/// <summary>One server for the whole replay; each case reseeds the world it needs.</summary>
public sealed class HttpShareVectorFixture : IAsyncLifetime
{
    internal HttpShareTestHost Host { get; private set; } = null!;

    public async Task InitializeAsync() => Host = await HttpShareTestHost.StartAsync();

    public async Task DisposeAsync() => await Host.DisposeAsync();
}

/// <summary>
/// Replays protocol/test-vectors/temporary-http-share-v1.json through the real server: the SQLite
/// store, the share service, the management, exchange and share-path endpoints and the route,
/// client and user management that carries the hooks. The share clock and random source are
/// injected, a fake device captures the NAT OPEN a share forwards, and every case compares the
/// audit entries and revoke columns it writes as well as the answer.
/// </summary>
public sealed class HttpShareVectorTests : IClassFixture<HttpShareVectorFixture>
{
    private static readonly Lazy<JsonDocument> Vector = new(() =>
        JsonDocument.Parse(File.ReadAllText(FindVector())));

    private readonly HttpShareTestHost _host;

    public HttpShareVectorTests(HttpShareVectorFixture fixture)
    {
        _host = fixture.Host;
    }

    private static JsonElement Root => Vector.Value.RootElement;

    /// <summary>The shared fixture world, also used by the HTTP-level share tests.</summary>
    internal static JsonElement World => Root.GetProperty("world");

    public static TheoryData<string> CreateCases() => Names("create");

    public static TheoryData<string> ExchangeCases() => Names("exchange");

    public static TheoryData<string> AccessCases() => Names("access");

    public static TheoryData<string> LifecycleCases() => Names("lifecycle");

    // ----------------------------------------------------------------------------------------------
    // constants, codes, token, pathPrefix

    [Fact]
    public void ConstantsMatchTheImplementation()
    {
        var constants = Root.GetProperty("constants");
        Assert.Equal(HttpShareProtocol.TokenVersion, constants.GetProperty("tokenVersion").GetString());
        Assert.Equal(HttpShareProtocol.ShareIdBytes, constants.GetProperty("shareIdBytes").GetInt32());
        Assert.Equal(HttpShareProtocol.SecretBytes, constants.GetProperty("secretBytes").GetInt32());
        Assert.Equal(HttpShareProtocol.TokenPattern, constants.GetProperty("tokenPattern").GetString());
        Assert.Equal(HttpShareProtocol.CookieName, constants.GetProperty("cookieName").GetString());
        Assert.Equal(HttpShareProtocol.MaxCookieCandidates, constants.GetProperty("maxCookieCandidates").GetInt32());
        Assert.Equal(HttpShareProtocol.SharePathRoot, constants.GetProperty("sharePathRoot").GetString());
        Assert.Equal(HttpShareProtocol.LinkRoot, constants.GetProperty("linkRoot").GetString());
        Assert.Equal(HttpShareProtocol.MinExpiresInSeconds, constants.GetProperty("minExpiresInSeconds").GetInt32());
        Assert.Equal(HttpShareProtocol.MaxExpiresInSeconds, constants.GetProperty("maxExpiresInSeconds").GetInt32());
        Assert.Equal(HttpShareProtocol.MaxActiveSharesPerRoute,
            constants.GetProperty("maxActiveSharesPerRoute").GetInt32());
        Assert.Equal(HttpShareProtocol.LabelMaxCodePoints, constants.GetProperty("labelMaxCodePoints").GetInt32());
        Assert.Equal(HttpShareProtocol.PathPrefixMaxBytes, constants.GetProperty("pathPrefixMaxBytes").GetInt32());
        Assert.Equal(HttpShareProtocol.ReadMethods, Strings(constants.GetProperty("readMethods")));
        Assert.Equal(HttpShareProtocol.MaxConcurrentPerShare, constants.GetProperty("maxConcurrentPerShare").GetInt32());
        Assert.Equal(HttpShareProtocol.SweepIntervalMaxSeconds,
            constants.GetProperty("sweepIntervalMaxSeconds").GetInt32());
        Assert.True(HttpShareProtocol.SweepIntervalSeconds <= HttpShareProtocol.SweepIntervalMaxSeconds);
        Assert.Equal(HttpShareProtocol.StreamRecheckMaxSeconds,
            constants.GetProperty("streamRecheckMaxSeconds").GetInt32());
        Assert.True(HttpShareProtocol.StreamRecheckSeconds + HttpShareProtocol.StreamExpiryTickSeconds
                    <= HttpShareProtocol.StreamRecheckMaxSeconds);
        Assert.Equal(HttpShareProtocol.ShareRetentionDays, constants.GetProperty("shareRetentionDays").GetInt32());
        Assert.Equal(HttpShareProtocol.AuditRetentionDays, constants.GetProperty("auditRetentionDays").GetInt32());
        Assert.Equal(HttpShareProtocol.RevokeReasons, Strings(constants.GetProperty("revokeReasons")));
        Assert.Equal(HttpShareProtocol.AuditActions, Strings(constants.GetProperty("auditActions")));

        var rate = Root.GetProperty("rate");
        Assert.Equal("gcra", rate.GetProperty("algorithm").GetString());
        Assert.Equal(HttpShareProtocol.ExchangeIntervalMs, rate.GetProperty("exchange").GetProperty("intervalMs").GetInt64());
        Assert.Equal(HttpShareProtocol.ExchangeBurst, rate.GetProperty("exchange").GetProperty("burst").GetInt32());
        Assert.Equal(HttpShareProtocol.ShareIntervalMs, rate.GetProperty("share").GetProperty("intervalMs").GetInt64());
        Assert.Equal(HttpShareProtocol.ShareBurst, rate.GetProperty("share").GetProperty("burst").GetInt32());

        var known = typeof(HttpShareCodes).GetFields()
            .Select(field => (string)field.GetValue(null)!).ToHashSet(StringComparer.Ordinal);
        foreach (var section in Root.GetProperty("codes").EnumerateObject())
        {
            foreach (var code in section.Value.EnumerateArray())
            {
                Assert.Contains(code.GetString()!, known);
            }
        }
    }

    [Fact]
    public void TokenExamplesAndParsing()
    {
        var token = Root.GetProperty("token");
        var examples = 0;
        foreach (var example in token.GetProperty("examples").EnumerateArray())
        {
            var (shareId, made) = HttpShareProtocol.MakeToken(
                Convert.FromHexString(example.GetProperty("shareIdBytesHex").GetString()!),
                Convert.FromHexString(example.GetProperty("secretBytesHex").GetString()!));
            Assert.Equal(example.GetProperty("shareId").GetString(), shareId);
            Assert.Equal(example.GetProperty("token").GetString(), made);
            Assert.Equal(example.GetProperty("tokenSha256").GetString(), HttpShareProtocol.TokenHash(made));
            Assert.Equal(example.GetProperty("sharePath").GetString(), HttpShareProtocol.SharePath(shareId));
            Assert.Equal(example.GetProperty("linkPath").GetString(), HttpShareProtocol.LinkPath(made));
            examples++;
        }
        var parsed = 0;
        foreach (var testCase in token.GetProperty("parse").EnumerateArray())
        {
            var input = testCase.GetProperty("input");
            var text = input.ValueKind == JsonValueKind.Null ? null : input.GetString();
            Assert.Equal(testCase.GetProperty("shareId").GetString(), HttpShareProtocol.ParseToken(text));
            parsed++;
        }
        Assert.Equal(3, examples);
        Assert.Equal(17, parsed);
    }

    [Fact]
    public void PathPrefixCanonicalisation()
    {
        var cases = 0;
        foreach (var testCase in Root.GetProperty("pathPrefix").EnumerateArray())
        {
            var input = testCase.GetProperty("input");
            var expected = testCase.GetProperty("canonical");
            if (input.ValueKind == JsonValueKind.String)
            {
                Assert.Equal(expected.ValueKind == JsonValueKind.Null ? null : expected.GetString(),
                    HttpShareProtocol.CanonicalPrefix(input.GetString()));
            }
            else
            {
                // A pathPrefix that is not a string is refused by the create body validation.
                Assert.Equal(JsonValueKind.Null, expected.ValueKind);
                var body = "{\"expiresInSeconds\":3600,\"pathPrefix\":" + input.GetRawText() + "}";
                Assert.Null(HttpShareService.ValidateCreateBody(Encoding.UTF8.GetBytes(body)));
            }
            cases++;
        }
        Assert.Equal(28, cases);
    }

    // ----------------------------------------------------------------------------------------------
    // create

    [Theory]
    [MemberData(nameof(CreateCases))]
    public async Task Create(string name)
    {
        var testCase = Case("create", name);
        var input = testCase.GetProperty("input");
        var expect = testCase.GetProperty("expect");
        await _host.SeedWorldAsync(Root.GetProperty("world"), Optional(input, "worldChanges"),
            Optional(input, "shares"));
        var newShare = Root.GetProperty("newShare");
        _host.Random.Enqueue(Convert.FromHexString(newShare.GetProperty("shareIdBytesHex").GetString()!),
            Convert.FromHexString(newShare.GetProperty("secretBytesHex").GetString()!));
        _host.Clock.Now = Now(input);
        _host.Store.Fail = input.TryGetProperty("readable", out var readable) && !readable.GetBoolean();

        var authenticated = !input.TryGetProperty("authenticated", out var auth) || auth.GetBoolean();
        using var client = _host.CreateClient(authenticated ? input.GetProperty("caller").GetString() : null);
        using var content = new StringContent(input.GetProperty("body").GetRawText(), Encoding.UTF8,
            "application/json");
        using var response = await client.PostAsync(
            $"/api/admin/http-routes/{input.GetProperty("routeId").GetInt64()}/shares", content);
        _host.Store.Fail = false;

        Assert.Equal(expect.GetProperty("httpStatus").GetInt32(), (int)response.StatusCode);
        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            Assert.Empty(await _host.AuditAsync());
            return;
        }
        Assert.Equal("private, no-store", RawHeader(response, "Cache-Control"));
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync())!;
        if (expect.TryGetProperty("code", out var code))
        {
            Assert.Equal(code.GetString(), body["code"]!.GetValue<string>());
        }
        else
        {
            AssertJsonEqual(expect.GetProperty("body"), body);
            var token = expect.GetProperty("body").GetProperty("token").GetString()!;
            var row = await _host.ShareAsync(newShare.GetProperty("shareId").GetString()!);
            Assert.NotNull(row);
            Assert.Equal(HttpShareProtocol.TokenHash(token), row!.TokenSha256);
            Assert.Equal("t1", row.TenantId);
        }
        await AssertAuditAsync(Optional(expect, "audit"), new Dictionary<long, long>());
    }

    // ----------------------------------------------------------------------------------------------
    // exchange

    [Theory]
    [MemberData(nameof(ExchangeCases))]
    public async Task Exchange(string name)
    {
        var testCase = Case("exchange", name);
        var input = testCase.GetProperty("input");
        var expect = testCase.GetProperty("expect");
        await _host.SeedWorldAsync(Root.GetProperty("world"), Optional(input, "worldChanges"),
            Optional(input, "shares"));
        var now = Now(input);
        _host.Clock.Now = now;
        var source = "198.51.100." + (CaseIndex("exchange", name) + 1).ToString(CultureInfo.InvariantCulture);
        if (input.TryGetProperty("rateLimitedMs", out var limitedMs))
        {
            // Ten requests at the moment that leaves exactly rateLimitedMs to wait now.
            var limiter = _host.Service<HttpShareExchangeRateLimiter>();
            var at = now.ToUnixTimeMilliseconds() + limitedMs.GetInt64() - HttpShareProtocol.ExchangeIntervalMs;
            for (var i = 0; i < HttpShareProtocol.ExchangeBurst; i++)
            {
                Assert.True(limiter.TryAcquire(source, at, out _));
            }
        }
        _host.Store.Fail = input.TryGetProperty("readable", out var readable) && !readable.GetBoolean();

        using var client = _host.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/public/http-shares/exchange");
        request.Content = new ByteArrayContent(Encoding.UTF8.GetBytes(input.GetProperty("body").GetRawText()));
        request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(
            input.TryGetProperty("contentType", out var contentType) ? contentType.GetString()! : "application/json");
        request.Headers.TryAddWithoutValidation("X-Real-IP", source);
        using var response = await client.SendAsync(request);
        _host.Store.Fail = false;

        Assert.Equal(expect.GetProperty("httpStatus").GetInt32(), (int)response.StatusCode);
        Assert.Equal("no-store", RawHeader(response, "Cache-Control"));
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync())!;
        response.Headers.TryGetValues("Set-Cookie", out var setCookies);
        if (expect.TryGetProperty("code", out var code))
        {
            Assert.Equal(code.GetString(), body["code"]!.GetValue<string>());
            Assert.Null(setCookies);
        }
        else
        {
            AssertJsonEqual(expect.GetProperty("body"), body);
            Assert.Equal(CookieHeader(expect.GetProperty("setCookie")), Assert.Single(setCookies!));
            Assert.Equal("no-referrer", Assert.Single(response.Headers.GetValues("Referrer-Policy")));
        }
        if (expect.TryGetProperty("retryAfterSeconds", out var retryAfter))
        {
            Assert.Equal(retryAfter.GetInt64().ToString(CultureInfo.InvariantCulture),
                Assert.Single(response.Headers.GetValues("Retry-After")));
        }
        await AssertRevokeAsync(input, expect, now);
        await AssertAuditAsync(Optional(expect, "audit"), new Dictionary<long, long>());
    }

    // ----------------------------------------------------------------------------------------------
    // access

    [Theory]
    [MemberData(nameof(AccessCases))]
    public async Task Access(string name)
    {
        var testCase = Case("access", name);
        var input = testCase.GetProperty("input");
        var expect = testCase.GetProperty("expect");
        await _host.SeedWorldAsync(Root.GetProperty("world"), Optional(input, "worldChanges"),
            Optional(input, "shares"));
        var now = Now(input);
        _host.Clock.Now = now;
        var request = input.GetProperty("request");
        var path = request.GetProperty("path").GetString()!;
        var query = request.TryGetProperty("rawQuery", out var rawQuery) ? rawQuery.GetString()! : string.Empty;
        var cookies = Strings(request.GetProperty("cookies"));
        var method = request.GetProperty("method").GetString()!;
        var upgrade = request.TryGetProperty("upgrade", out var upgradeValue) && upgradeValue.GetBoolean();
        var authorization = request.TryGetProperty("authorization", out var authValue) ? authValue.GetString() : null;
        var shareId = path["/http-share/".Length..].Split('/')[0];

        var leases = new List<HttpShareStreamRegistry.Lease>();
        var admission = input.TryGetProperty("admission", out var admissionValue) ? admissionValue.GetString() : null;
        var share = HttpShareProtocol.IsShareId(shareId) ? await _host.ShareAsync(shareId) : null;
        if (admission == "share-busy")
        {
            var registry = _host.Service<HttpShareStreamRegistry>();
            for (var i = 0; i < HttpShareProtocol.MaxConcurrentPerShare; i++)
            {
                leases.Add(registry.TryAcquire(shareId, share!.ExpiresAt)!);
            }
        }
        else if (admission == "rate-limited")
        {
            var limiter = _host.Service<HttpShareRequestRateLimiter>();
            for (var i = 0; i < HttpShareProtocol.ShareBurst; i++)
            {
                Assert.True(limiter.TryAcquire(shareId, now.ToUnixTimeMilliseconds(), out _));
            }
        }
        _host.Store.Fail = input.TryGetProperty("readable", out var readable) && !readable.GetBoolean();

        await using var device = ShareFakeDevice.Bind(_host.Server, HttpShareTestHost.ClientName(7));
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        try
        {
            var forwarded = expect.GetProperty("httpStatus").ValueKind == JsonValueKind.String;
            if (forwarded && upgrade)
            {
                var webSockets = _host.Server.Server.CreateWebSocketClient();
                webSockets.ConfigureRequest = upgradeRequest =>
                {
                    foreach (var cookie in cookies)
                    {
                        upgradeRequest.Headers.Append("Cookie", cookie);
                    }
                };
                using var socket = await webSockets.ConnectAsync(
                    new Uri("ws://localhost" + path + (query.Length > 0 ? "?" + query : string.Empty)),
                    cancellation.Token);
                var opened = await device.OpenedAsync(cancellation.Token);
                Assert.Equal("ws", opened.MetaData!["source"]);
                AssertForward(expect.GetProperty("forward"), opened, webSocket: true);
                socket.Abort();
                Assert.Equal(1, device.OpenCount);
                return;
            }

            var responseTask = _host.Server.Server.SendAsync(context =>
            {
                context.Request.Method = method;
                context.Request.Path = PathString.FromUriComponent(path);
                if (query.Length > 0)
                {
                    context.Request.QueryString = new QueryString("?" + query);
                }
                context.Features.Get<IHttpRequestFeature>()!.RawTarget =
                    path + (query.Length > 0 ? "?" + query : string.Empty);
                foreach (var cookie in cookies)
                {
                    context.Request.Headers.Append("Cookie", cookie);
                }
                if (authorization is not null)
                {
                    context.Request.Headers.Authorization = authorization;
                }
                if (upgrade)
                {
                    context.Request.Headers.Upgrade = "websocket";
                    context.Request.Headers.Connection = "Upgrade";
                    context.Request.Headers["Sec-WebSocket-Key"] = "dGhlIHNhbXBsZSBub25jZQ==";
                    context.Request.Headers["Sec-WebSocket-Version"] = "13";
                }
            }, cancellation.Token);

            if (forwarded)
            {
                var opened = await device.OpenedAsync(cancellation.Token);
                Assert.Equal("http", opened.MetaData!["source"]);
                AssertForward(expect.GetProperty("forward"), opened, webSocket: false);
                await device.RespondAsync(opened.StreamId, 200, ["Content-Type:text/plain"], "ok");
                var forwardedContext = await responseTask;
                Assert.Equal(200, forwardedContext.Response.StatusCode);
                Assert.Equal(1, device.OpenCount);
                return;
            }

            var context = await responseTask;
            _host.Store.Fail = false;
            var response = context.Response;
            Assert.Equal(expect.GetProperty("httpStatus").GetInt32(), response.StatusCode);
            Assert.Equal(0, device.OpenCount);
            if (response.StatusCode == StatusCodes.Status308PermanentRedirect)
            {
                Assert.Equal(expect.GetProperty("location").GetString(), response.Headers.Location.ToString());
                return;
            }
            Assert.Equal("no-store", response.Headers.CacheControl.ToString());
            using var reader = new StreamReader(response.Body);
            var body = JsonNode.Parse(await reader.ReadToEndAsync(cancellation.Token))!;
            Assert.Equal(expect.GetProperty("code").GetString(), body["code"]!.GetValue<string>());
            if (expect.TryGetProperty("setCookie", out var setCookie))
            {
                Assert.Equal(CookieHeader(setCookie), Assert.Single(response.Headers.SetCookie.ToArray()));
            }
            else
            {
                Assert.Equal(0, response.Headers.SetCookie.Count);
            }
            if (expect.TryGetProperty("allow", out var allow))
            {
                Assert.Equal(allow.GetString(), response.Headers.Allow.ToString());
            }
            if (expect.TryGetProperty("retryAfterSeconds", out var retryAfter))
            {
                Assert.Equal(retryAfter.GetInt64().ToString(CultureInfo.InvariantCulture),
                    response.Headers.RetryAfter.ToString());
            }
            // The share path never carries the portal's security headers.
            Assert.False(response.Headers.ContainsKey("Content-Security-Policy"));
            await AssertRevokeAsync(input, expect, now);
            await AssertAuditAsync(Optional(expect, "audit"), new Dictionary<long, long>());
        }
        finally
        {
            _host.Store.Fail = false;
            foreach (var lease in leases)
            {
                lease.Dispose();
            }
        }
    }

    private static void AssertForward(JsonElement forward, NatMessagePacket opened, bool webSocket)
    {
        var metadata = opened.MetaData!;
        Assert.Equal(forward.GetProperty("route").GetString(), metadata["route"]);
        if (!webSocket)
        {
            Assert.Equal(forward.GetProperty("method").GetString(), metadata["method"]);
        }
        Assert.Equal(forward.GetProperty("relativePath").GetString(), metadata["relativePath"]);
        Assert.Equal(forward.GetProperty("rawQuery").GetString(), (string?)metadata["rawQuery"] ?? string.Empty);
        var cookieLines = ShareFakeDevice.Headers(opened)
            .Where(line => line.Split(':', 2)[0].Trim().Equals("Cookie", StringComparison.OrdinalIgnoreCase))
            .ToList();
        var expectedCookie = forward.GetProperty("cookie");
        if (expectedCookie.ValueKind == JsonValueKind.Null)
        {
            Assert.Empty(cookieLines);
        }
        else
        {
            Assert.Equal("Cookie:" + expectedCookie.GetString(), Assert.Single(cookieLines));
        }
        // The token never reaches the device: not in the path, the query or any header.
        var everything = string.Join("\n", metadata.Values.Select(value => value switch
        {
            IEnumerable<string> lines => string.Join("\n", lines),
            _ => value?.ToString() ?? string.Empty,
        }));
        Assert.DoesNotContain("hs1.", everything, StringComparison.Ordinal);
    }

    // ----------------------------------------------------------------------------------------------
    // headers

    [Fact]
    public void RequestCookieStripping()
    {
        var cases = 0;
        foreach (var testCase in Root.GetProperty("headers").GetProperty("requestCookie").EnumerateArray())
        {
            var expected = testCase.GetProperty("forwardedCookie");
            Assert.Equal(expected.ValueKind == JsonValueKind.Null ? null : expected.GetString(),
                HttpShareProtocol.ForwardedCookie(Strings(testCase.GetProperty("cookieHeaders"))));
            cases++;
        }
        Assert.Equal(7, cases);
    }

    [Fact]
    public void ResponseHeaderRewriting()
    {
        var cases = 0;
        foreach (var testCase in Root.GetProperty("headers").GetProperty("response").EnumerateArray())
        {
            var relayed = HttpShareProtocol.ResponseHeaders(testCase.GetProperty("status").GetInt32(),
                Strings(testCase.GetProperty("upstream")), testCase.GetProperty("shareId").GetString()!);
            Assert.Equal(Strings(testCase.GetProperty("relayed")), relayed);
            cases++;
        }
        Assert.Equal(7, cases);
    }

    // ----------------------------------------------------------------------------------------------
    // lifecycle

    [Theory]
    [MemberData(nameof(LifecycleCases))]
    public async Task Lifecycle(string name)
    {
        var testCase = Case("lifecycle", name);
        var input = testCase.GetProperty("input");
        var expect = testCase.GetProperty("expect");
        await _host.SeedWorldAsync(Root.GetProperty("world"), null, input.GetProperty("shares"));
        var routeIds = new Dictionary<long, long>();
        var responses = new List<(int Status, string? StatusOrCode)>();
        var lastAt = HttpShareTestHost.VectorNow;

        foreach (var item in input.GetProperty("events").EnumerateArray())
        {
            lastAt = DateTimeOffset.Parse(item.GetProperty("at").GetString()!, CultureInfo.InvariantCulture);
            _host.Clock.Now = lastAt;
            var kind = item.GetProperty("kind").GetString();
            var actor = item.TryGetProperty("actor", out var actorValue) ? actorValue.GetString() : null;
            using var client = _host.CreateClient(actor);
            switch (kind)
            {
                case "revoke":
                {
                    using var response = await client.PostAsync(
                        $"/api/admin/http-routes/{MapRoute(routeIds, item.GetProperty("routeId").GetInt64())}"
                        + $"/shares/{item.GetProperty("shareId").GetString()}/revoke", null);
                    var body = JsonNode.Parse(await response.Content.ReadAsStringAsync())!;
                    responses.Add(((int)response.StatusCode, response.IsSuccessStatusCode
                        ? body["share"]!["status"]!.GetValue<string>()
                        : body["code"]!.GetValue<string>()));
                    break;
                }
                case "route-created":
                {
                    var route = item.GetProperty("route");
                    var authEnabled = route.GetProperty("authEnabled").GetBoolean();
                    using var response = await client.PostAsJsonAsync(
                        $"/api/admin/clients/{route.GetProperty("clientId").GetInt64()}/http-routes",
                        new HttpRouteMutation(route.GetProperty("name").GetString(), "http://127.0.0.1:9",
                            route.GetProperty("enabled").GetBoolean(), false, false, authEnabled,
                            authEnabled ? "basic" : null, authEnabled ? "basic-password" : null));
                    Assert.Equal(HttpStatusCode.Created, response.StatusCode);
                    var created = JsonNode.Parse(await response.Content.ReadAsStringAsync())!;
                    routeIds[route.GetProperty("routeId").GetInt64()] = created["id"]!.GetValue<long>();
                    break;
                }
                case "route-updated":
                {
                    var routeId = MapRoute(routeIds, item.GetProperty("routeId").GetInt64());
                    var current = await _host.WithDbAsync(db =>
                        db.HttpRouteMappings.AsNoTracking().SingleAsync(r => r.Id == routeId));
                    var credentialsChanged = item.TryGetProperty("credentialsChanged", out var changed)
                                             && changed.GetBoolean();
                    using var response = await client.PutAsJsonAsync($"/api/admin/http-routes/{routeId}",
                        new HttpRouteMutation(current.Route, current.TargetBaseUrl,
                            item.TryGetProperty("enabled", out var enabled) ? enabled.GetBoolean() : current.Enabled,
                            null, null,
                            item.TryGetProperty("authEnabled", out var authEnabled)
                                ? authEnabled.GetBoolean()
                                : current.AuthEnabled,
                            credentialsChanged ? "basic" : null,
                            credentialsChanged ? "rotated-password" : null));
                    Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                    break;
                }
                case "route-deleted":
                {
                    using var response = await client.DeleteAsync(
                        $"/api/admin/http-routes/{MapRoute(routeIds, item.GetProperty("routeId").GetInt64())}");
                    Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
                    break;
                }
                case "client-disabled":
                {
                    using var response = await client.PutAsJsonAsync(
                        $"/api/admin/clients/{item.GetProperty("clientId").GetInt64()}",
                        new ClientMutation(null, false, null));
                    Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                    break;
                }
                case "client-deleted":
                {
                    var clientId = item.GetProperty("clientId").GetInt64();
                    using var response = await client.DeleteAsync($"/api/admin/clients/{clientId}");
                    Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
                    // Deleting a client deletes its routes: no orphan route rows remain.
                    Assert.Equal(0, await _host.WithDbAsync(db =>
                        db.HttpRouteMappings.CountAsync(r => r.ClientId == clientId)));
                    break;
                }
                case "user-updated":
                {
                    using var response = await client.PutAsJsonAsync(
                        $"/api/admin/users/{item.GetProperty("username").GetString()}",
                        new UserMutation(null, null,
                            item.TryGetProperty("role", out var role) ? role.GetString() : null,
                            item.TryGetProperty("enabled", out var enabled) ? enabled.GetBoolean() : null));
                    Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                    break;
                }
                case "user-deleted":
                {
                    using var response = await client.DeleteAsync(
                        $"/api/admin/users/{item.GetProperty("username").GetString()}");
                    Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
                    break;
                }
                case "sweep":
                    await using (var scope = _host.Server.HostServices.CreateAsyncScope())
                    {
                        await scope.ServiceProvider.GetRequiredService<HttpShareService>()
                            .SweepAsync(CancellationToken.None);
                    }
                    break;
                case "silent-change":
                    await _host.WithDbAsync(db => HttpShareTestHost.ApplyChangeAsync(db,
                        item.GetProperty("table").GetString()!, item.GetProperty("key"), false,
                        item.GetProperty("set")));
                    break;
                default:
                    throw new InvalidOperationException("unknown lifecycle event " + kind);
            }
        }

        await AssertAuditAsync(expect.GetProperty("audit"), routeIds);
        var expectedShares = expect.GetProperty("shares").EnumerateObject().ToList();
        var rows = await _host.WithDbAsync(db => db.HttpShares.AsNoTracking().ToListAsync());
        Assert.Equal(expectedShares.Count, rows.Count);
        foreach (var expected in expectedShares)
        {
            var row = Assert.Single(rows, r => r.ShareId == expected.Name);
            Assert.Equal(expected.Value.GetProperty("status").GetString(),
                HttpShareService.Status(row, lastAt.ToUnixTimeMilliseconds()));
            Assert.Equal(expected.Value.GetProperty("revokeReason").GetString(), row.RevokeReason);
            Assert.Equal(expected.Value.GetProperty("revokedBy").GetString(), row.RevokedBy);
        }
        var expectedResponses = expect.TryGetProperty("responses", out var responseList)
            ? responseList.EnumerateArray().Select(r => (r.GetProperty("httpStatus").GetInt32(),
                r.TryGetProperty("status", out var status) ? status.GetString() : r.GetProperty("code").GetString()))
                .ToList()
            : [];
        Assert.Equal(expectedResponses, responses);
    }

    private static long MapRoute(Dictionary<long, long> routeIds, long vectorId) =>
        routeIds.TryGetValue(vectorId, out var actual) ? actual : vectorId;

    // ----------------------------------------------------------------------------------------------
    // rate

    [Fact]
    public void RateLimitersReplayTheGcraEvents()
    {
        var rate = Root.GetProperty("rate");
        foreach (var section in new[] { "exchange", "share" })
        {
            var spec = rate.GetProperty(section);
            var limiter = new GcraRateLimiter(spec.GetProperty("intervalMs").GetInt64(), spec.GetProperty("burst").GetInt32());
            var events = 0;
            foreach (var item in spec.GetProperty("events").EnumerateArray())
            {
                var admitted = 0;
                long? retryAfter = null;
                for (var i = 0; i < item.GetProperty("requests").GetInt32(); i++)
                {
                    if (limiter.TryAcquire(item.GetProperty("key").GetString()!, item.GetProperty("atMs").GetInt64(),
                            out var waitMs))
                    {
                        admitted++;
                    }
                    else
                    {
                        retryAfter ??= GcraRateLimiter.RetryAfterSeconds(waitMs);
                    }
                }
                Assert.Equal(item.GetProperty("admitted").GetInt32(), admitted);
                Assert.Equal(item.TryGetProperty("retryAfterSeconds", out var expected) ? expected.GetInt64() : null,
                    retryAfter);
                events++;
            }
            Assert.Equal(6, events);
        }
    }

    // ----------------------------------------------------------------------------------------------
    // helpers

    private async Task AssertRevokeAsync(JsonElement input, JsonElement expect, DateTimeOffset now)
    {
        if (!expect.TryGetProperty("revoke", out var revoke))
        {
            return;
        }
        var shareId = input.GetProperty("shares")[0].GetProperty("shareId").GetString()!;
        var row = await _host.ShareAsync(shareId);
        Assert.Equal(now.ToUnixTimeSeconds(), row!.RevokedAt);
        Assert.Equal(revoke.GetProperty("revokedBy").GetString(), row.RevokedBy);
        Assert.Equal(revoke.GetProperty("reason").GetString(), row.RevokeReason);
    }

    private async Task AssertAuditAsync(JsonElement? expected, Dictionary<long, long> routeIds)
    {
        var rows = await _host.AuditAsync();
        var entries = expected?.EnumerateArray().ToList() ?? [];
        Assert.Equal(entries.Count, rows.Count);
        for (var i = 0; i < entries.Count; i++)
        {
            var entry = entries[i];
            var row = rows[i];
            Assert.Equal(entry.GetProperty("action").GetString(), row.Action);
            Assert.Equal(entry.GetProperty("at").GetString(), HttpShareProtocol.Stamp(row.OccurredAt));
            Assert.Equal(entry.GetProperty("actor").GetString(), row.Actor);
            Assert.Equal(MapRoute(routeIds, entry.GetProperty("routeId").GetInt64()), row.RouteId);
            Assert.Equal(entry.GetProperty("shareId").GetString(), row.ShareId);
            AssertJsonEqual(entry.GetProperty("detail"), JsonNode.Parse(row.DetailJson));
            Assert.Equal("t1", row.TenantId);
            // The audit never holds a token, its hash or a label.
            Assert.DoesNotContain("hs1.", row.DetailJson, StringComparison.Ordinal);
        }
    }

    private static void AssertJsonEqual(JsonElement expected, JsonNode? actual)
    {
        var expectedNode = JsonNode.Parse(expected.GetRawText());
        Assert.True(JsonNode.DeepEquals(expectedNode, actual),
            $"expected {expectedNode?.ToJsonString()} but got {actual?.ToJsonString()}");
    }

    private static string CookieHeader(JsonElement cookie)
    {
        Assert.Equal(JsonValueKind.Null, cookie.GetProperty("domain").ValueKind);
        Assert.True(cookie.GetProperty("httpOnly").GetBoolean());
        Assert.True(cookie.GetProperty("secure").GetBoolean());
        Assert.Equal("Strict", cookie.GetProperty("sameSite").GetString());
        return $"{cookie.GetProperty("name").GetString()}={cookie.GetProperty("value").GetString()}; "
               + $"Path={cookie.GetProperty("path").GetString()}; "
               + $"Max-Age={cookie.GetProperty("maxAge").GetInt64().ToString(CultureInfo.InvariantCulture)}; "
               + "HttpOnly; Secure; SameSite=Strict";
    }

    private static string? RawHeader(HttpResponseMessage response, string name) =>
        response.Headers.NonValidated.TryGetValues(name, out var values) ? values.ToString() : null;

    private static DateTimeOffset Now(JsonElement input) =>
        input.TryGetProperty("now", out var now)
            ? DateTimeOffset.Parse(now.GetString()!, CultureInfo.InvariantCulture)
            : HttpShareTestHost.VectorNow;

    private static JsonElement? Optional(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) ? value : null;

    private static List<string> Strings(JsonElement array) =>
        array.EnumerateArray().Select(item => item.GetString()!).ToList();

    private static JsonElement Case(string section, string name) =>
        Root.GetProperty(section).EnumerateArray().Single(c => c.GetProperty("name").GetString() == name);

    private static int CaseIndex(string section, string name) =>
        Root.GetProperty(section).EnumerateArray().TakeWhile(c => c.GetProperty("name").GetString() != name).Count();

    private static TheoryData<string> Names(string section)
    {
        var names = new TheoryData<string>();
        foreach (var testCase in Root.GetProperty(section).EnumerateArray())
        {
            names.Add(testCase.GetProperty("name").GetString()!);
        }
        return names;
    }

    private static string FindVector()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        for (var depth = 0; directory is not null && depth < 12; depth++, directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, "protocol", "test-vectors",
                "temporary-http-share-v1.json");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }
        throw new FileNotFoundException("cannot locate temporary-http-share-v1.json");
    }
}
