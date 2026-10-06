using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Specus.Protocol;
using Specus.Server.Http;
using Specus.Server.Management;

namespace Specus.IntegrationTests;

/// <summary>
/// Temporary HTTP shares end to end over HTTP: the exchange cookie, what reaches the device, the
/// response rewriting, revocation (also from "another instance" through the database) cutting
/// in-flight streams, and the cascades from the real route, client and user endpoints.
/// </summary>
public sealed class HttpShareHttpTests : IAsyncLifetime
{
    private const string CookieName = HttpShareProtocol.CookieName;

    private HttpShareTestHost _host = null!;

    public async Task InitializeAsync()
    {
        _host = await HttpShareTestHost.StartAsync();
        await _host.SeedWorldAsync(HttpShareVectorTests.World, null, null);
    }

    public async Task DisposeAsync() => await _host.DisposeAsync();

    [Fact]
    public async Task ExchangeSetsTheShareCookieWithExactlyTheContractAttributes()
    {
        var (shareId, token) = await CreateShareAsync("alice", 42,
            """{"expiresInSeconds": 3600, "pathPrefix": "/docs"}""");
        // Half a second into the share's life: Max-Age is the whole seconds left, rounded up.
        _host.Clock.Now = HttpShareTestHost.VectorNow.AddMilliseconds(500);

        using var client = _host.CreateClient();
        using var response = await client.PostAsync("/api/public/http-shares/exchange",
            JsonContent(new JsonObject { ["token"] = token }));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(
            $"{CookieName}={token}; Path=/http-share/{shareId}/; Max-Age=3600; HttpOnly; Secure; SameSite=Strict",
            Assert.Single(RawHeaders(response, "Set-Cookie")));
        Assert.Equal("no-store", Assert.Single(RawHeaders(response, "Cache-Control")));
        Assert.Equal("no-referrer", Assert.Single(RawHeaders(response, "Referrer-Policy")));
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync())!.AsObject();
        Assert.Equal($"/http-share/{shareId}/docs/", body["location"]!.GetValue<string>());
        Assert.Equal("2026-10-06T09:00:00Z", body["expiresAt"]!.GetValue<string>());
        Assert.False(body.ContainsKey("token"));
        Assert.DoesNotContain(token, body.ToJsonString(), StringComparison.Ordinal);

        // A plain form cannot submit the exchange.
        using var form = await client.PostAsync("/api/public/http-shares/exchange",
            new StringContent("token=" + token, Encoding.UTF8, "application/x-www-form-urlencoded"));
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, form.StatusCode);
        Assert.False(form.Headers.Contains("Set-Cookie"));
    }

    [Fact]
    public async Task TheShareCookieIsStrippedWhileOtherCookiesAndAuthorizationReachTheDevice()
    {
        var (shareId, token) = await CreateShareAsync("alice", 42,
            """{"expiresInSeconds": 3600, "access": "full"}""");
        await using var device = ShareFakeDevice.Bind(_host.Server, HttpShareTestHost.ClientName(7));
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var client = _host.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, $"/http-share/{shareId}/app/items?x=%2F1");
        request.Headers.TryAddWithoutValidation("Cookie", $"theme=dark; {CookieName}={token}; sid=abc");
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer upstream-token");

        var responseTask = client.SendAsync(request, cancellation.Token);
        var opened = await device.OpenedAsync(cancellation.Token);
        var headers = ShareFakeDevice.Headers(opened);
        await device.RespondAsync(opened.StreamId, 200, ["Content-Type:text/plain"], "hello");
        using var response = await responseTask;

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("hello", await response.Content.ReadAsStringAsync(cancellation.Token));
        Assert.Equal("api", opened.MetaData!["route"]);
        Assert.Equal("/app/items", opened.MetaData["relativePath"]);
        Assert.Equal("x=%2F1", opened.MetaData["rawQuery"]);
        Assert.Contains("Cookie:theme=dark; sid=abc", headers);
        Assert.Contains("Authorization:Bearer upstream-token", headers);
        Assert.DoesNotContain(headers, line => line.Contains(token, StringComparison.Ordinal));
        Assert.DoesNotContain(headers, line => line.Contains(CookieName, StringComparison.Ordinal));
    }

    [Fact]
    public async Task UpstreamCookiesCacheHeadersAndClearSiteDataAreRewritten()
    {
        var (shareId, token) = await CreateShareAsync("alice", 42, """{"expiresInSeconds": 3600}""");
        await using var device = ShareFakeDevice.Bind(_host.Server, HttpShareTestHost.ClientName(7));
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var client = _host.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, $"/http-share/{shareId}/");
        request.Headers.TryAddWithoutValidation("Cookie", $"{CookieName}={token}");

        var responseTask = client.SendAsync(request, cancellation.Token);
        var opened = await device.OpenedAsync(cancellation.Token);
        await device.RespondAsync(opened.StreamId, 200,
        [
            "Content-Type:text/plain",
            $"Set-Cookie:{CookieName}=evil; Path=/",
            "Set-Cookie:sid=abc; path=/; Domain=example.com; HttpOnly",
            "Set-Cookie:pref=1; Path=/app/; Max-Age=60",
            "Set-Cookie:rel=1; Path=app",
            "Set-Cookie:__Host-csrf=x; Path=/; Secure",
            "Cache-Control:public, max-age=3600",
            "CDN-Cache-Control:max-age=600",
            "Expires:Wed, 21 Oct 2026 07:28:00 GMT",
            "Clear-Site-Data:\"cookies\", \"storage\"",
        ], "body");
        using var response = await responseTask;

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(
        [
            $"sid=abc; Path=/http-share/{shareId}/; HttpOnly",
            $"pref=1; Path=/http-share/{shareId}/app/; Max-Age=60",
            "rel=1; Path=app",
        ], RawHeaders(response, "Set-Cookie"));
        Assert.Equal("private, no-cache", Assert.Single(RawHeaders(response, "Cache-Control")));
        Assert.Empty(RawHeaders(response, "Clear-Site-Data"));
        Assert.Empty(RawHeaders(response, "CDN-Cache-Control"));
        Assert.Null(response.Content.Headers.Expires);
        // Like /http/, the share path never carries the portal's security headers.
        Assert.Empty(RawHeaders(response, "Content-Security-Policy"));
        Assert.Empty(RawHeaders(response, "X-Frame-Options"));
    }

    [Fact]
    public async Task RevokeAnswers410WithAClearingCookieAndWritesTheAudit()
    {
        var (shareId, token) = await CreateShareAsync("alice", 42, """{"expiresInSeconds": 3600}""");
        await using var device = ShareFakeDevice.Bind(_host.Server, HttpShareTestHost.ClientName(7));
        using var owner = _host.CreateClient("alice");
        using var revoke = await owner.PostAsync($"/api/admin/http-routes/42/shares/{shareId}/revoke",
            JsonContent(new JsonObject()));
        Assert.Equal(HttpStatusCode.OK, revoke.StatusCode);
        var share = JsonNode.Parse(await revoke.Content.ReadAsStringAsync())!["share"]!;
        Assert.Equal("revoked", share["status"]!.GetValue<string>());
        Assert.Equal("alice", share["revokedBy"]!.GetValue<string>());

        using var visitor = _host.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, $"/http-share/{shareId}/page");
        request.Headers.TryAddWithoutValidation("Cookie", $"{CookieName}={token}");
        using var response = await visitor.SendAsync(request);

        Assert.Equal(HttpStatusCode.Gone, response.StatusCode);
        Assert.Equal("SHARE_REVOKED",
            JsonNode.Parse(await response.Content.ReadAsStringAsync())!["code"]!.GetValue<string>());
        Assert.Equal($"{CookieName}=; Path=/http-share/{shareId}/; Max-Age=0; HttpOnly; Secure; SameSite=Strict",
            Assert.Single(RawHeaders(response, "Set-Cookie")));
        Assert.Equal("no-store", Assert.Single(RawHeaders(response, "Cache-Control")));
        Assert.Equal(0, device.OpenCount);

        using var audit = await owner.GetAsync("/api/admin/http-routes/42/access-audit");
        var entries = JsonNode.Parse(await audit.Content.ReadAsStringAsync())!["entries"]!.AsArray();
        Assert.Equal(["share.revoked", "share.created"],
            entries.Select(entry => entry!["action"]!.GetValue<string>()).ToArray());
        Assert.Equal("revoked-by-user", entries[0]!["detail"]!["reason"]!.GetValue<string>());
    }

    [Fact]
    public async Task ARevokeOnAnotherInstanceCutsAnInFlightResponseWithinFiveSeconds()
    {
        var (shareId, token) = await CreateShareAsync("alice", 42, """{"expiresInSeconds": 3600}""");
        await using var device = ShareFakeDevice.Bind(_host.Server, HttpShareTestHost.ClientName(7));
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var client = _host.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, $"/http-share/{shareId}/events");
        request.Headers.TryAddWithoutValidation("Cookie", $"{CookieName}={token}");

        var responseTask = client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellation.Token);
        var opened = await device.OpenedAsync(cancellation.Token);
        await device.RespondAsync(opened.StreamId, 200, ["Content-Type:text/event-stream"], "event: one\n\n",
            finish: false);
        using var response = await responseTask;
        await using var body = await response.Content.ReadAsStreamAsync(cancellation.Token);
        var buffer = new byte[256];
        Assert.True(await body.ReadAsync(buffer, cancellation.Token) > 0);

        // Another instance revokes: only the database changes, nothing is cut locally.
        var stopwatch = Stopwatch.StartNew();
        await _host.WithDbAsync(db => db.HttpShares.Where(s => s.ShareId == shareId)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(s => s.RevokedAt, HttpShareTestHost.VectorNow.ToUnixTimeSeconds())
                .SetProperty(s => s.RevokedBy, "alice")
                .SetProperty(s => s.RevokeReason, HttpShareProtocol.ReasonRevokedByUser)));

        var ended = false;
        try
        {
            ended = await body.ReadAsync(buffer, cancellation.Token) == 0;
        }
        catch (Exception error) when (error is IOException or HttpRequestException)
        {
            ended = true;
        }
        Assert.True(ended);
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(5), $"cut after {stopwatch.Elapsed}");
        var reset = await device.ReadAsync(packet => packet.NatMessageType == NatMessageType.Rst
                                                     && packet.StreamId == opened.StreamId, cancellation.Token);
        Assert.Equal(8u, reset.Value);
    }

    [Fact]
    public async Task AWebSocketThroughAFullShareIsClosedWith1008WhenTheShareIsRevoked()
    {
        var (shareId, token) = await CreateShareAsync("alice", 42,
            """{"expiresInSeconds": 3600, "access": "full"}""");
        await using var device = ShareFakeDevice.Bind(_host.Server, HttpShareTestHost.ClientName(7));
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var webSockets = _host.Server.Server.CreateWebSocketClient();
        webSockets.ConfigureRequest = request => request.Headers.Append("Cookie", $"{CookieName}={token}");
        using var socket = await webSockets.ConnectAsync(new Uri($"ws://localhost/http-share/{shareId}/live"),
            cancellation.Token);
        var opened = await device.OpenedAsync(cancellation.Token);
        Assert.Equal("ws", opened.MetaData!["source"]);
        Assert.DoesNotContain(ShareFakeDevice.Headers(opened),
            line => line.Contains(token, StringComparison.Ordinal));

        using var owner = _host.CreateClient("alice");
        using var revoke = await owner.PostAsync($"/api/admin/http-routes/42/shares/{shareId}/revoke", null);
        Assert.Equal(HttpStatusCode.OK, revoke.StatusCode);

        var received = await socket.ReceiveAsync(new byte[64], cancellation.Token);
        Assert.Equal(WebSocketMessageType.Close, received.MessageType);
        Assert.Equal(WebSocketCloseStatus.PolicyViolation, received.CloseStatus);
        await device.ReadAsync(packet => packet.NatMessageType == NatMessageType.Rst
                                         && packet.StreamId == opened.StreamId, cancellation.Token);
    }

    [Fact]
    public async Task RouteClientAndUserEndpointsCascadeToSharesAndTheAudit()
    {
        var (a, _) = await CreateShareAsync("alice", 42, """{"expiresInSeconds": 3600}""");
        var (b, _) = await CreateShareAsync("alice", 42, """{"expiresInSeconds": 7200, "label": "b"}""");
        var (c, _) = await CreateShareAsync("bob", 50, """{"expiresInSeconds": 3600}""");
        var (d, _) = await CreateShareAsync("admin", 50, """{"expiresInSeconds": 3600}""");
        using var alice = _host.CreateClient("alice");
        using var admin = _host.CreateClient("admin");

        // Disabling the route ends both of its shares, attributed to the owner who did it.
        using (var update = await alice.PutAsJsonAsync("/api/admin/http-routes/42",
                   new HttpRouteMutation("api", "http://127.0.0.1:9", false, null, null, null, null, null)))
        {
            Assert.Equal(HttpStatusCode.OK, update.StatusCode);
        }
        await AssertShareAsync(a, "route-disabled", "alice");
        await AssertShareAsync(b, "route-disabled", "alice");

        // Disabling bob ends his share on his own route; the admin's share of that route stays.
        using (var update = await admin.PutAsJsonAsync("/api/admin/users/bob",
                   new UserMutation(null, null, null, false)))
        {
            Assert.Equal(HttpStatusCode.OK, update.StatusCode);
        }
        await AssertShareAsync(c, "creator-lost-access", "admin");
        await AssertShareAsync(d, null, null);

        // Disabling client 8 ends the admin's share too.
        using (var update = await admin.PutAsJsonAsync("/api/admin/clients/8", new ClientMutation(null, false, null)))
        {
            Assert.Equal(HttpStatusCode.OK, update.StatusCode);
        }
        await AssertShareAsync(d, "client-disabled", "admin");

        // Deleting client 7 deletes its route rows and audits each of them.
        using (var delete = await admin.DeleteAsync("/api/admin/clients/7"))
        {
            Assert.Equal(HttpStatusCode.NoContent, delete.StatusCode);
        }
        Assert.Equal(0, await _host.WithDbAsync(db => db.HttpRouteMappings.CountAsync(r => r.ClientId == 7)));

        // The tenant-wide audit (admins only), newest first, paged by auditId.
        var actions = new List<string>();
        string? before = null;
        do
        {
            using var page = await admin.GetAsync("/api/admin/http-access-audit?limit=3"
                                                  + (before is null ? string.Empty : "&before=" + before));
            Assert.Equal(HttpStatusCode.OK, page.StatusCode);
            Assert.Equal("private, no-store", Assert.Single(RawHeaders(page, "Cache-Control")));
            var json = JsonNode.Parse(await page.Content.ReadAsStringAsync())!;
            actions.AddRange(json["entries"]!.AsArray().Select(entry => entry!["action"]!.GetValue<string>()));
            before = json["nextBefore"]?.ToJsonString();
        }
        while (before is not null);
        Assert.Equal(
        [
            "route.deleted", "route.deleted", "route.deleted",
            "share.revoked",
            "share.revoked",
            "share.revoked", "share.revoked", "route.exposure-changed",
            "share.created", "share.created", "share.created", "share.created",
        ], actions);

        // A deleted route's audit stays readable to tenant admins; others get 403.
        using (var deletedRoute = await admin.GetAsync("/api/admin/http-access-audit?routeId=42&limit=200"))
        {
            var entries = JsonNode.Parse(await deletedRoute.Content.ReadAsStringAsync())!["entries"]!.AsArray();
            Assert.Equal("route.deleted", entries[0]!["action"]!.GetValue<string>());
            Assert.Equal("disabled", entries[0]!["detail"]!["exposure"]!.GetValue<string>());
        }
        using (var forbidden = await alice.GetAsync("/api/admin/http-access-audit"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);
            Assert.Equal("SHARE_FORBIDDEN",
                JsonNode.Parse(await forbidden.Content.ReadAsStringAsync())!["code"]!.GetValue<string>());
        }
    }

    [Fact]
    public async Task ListingRevokesASilentlyLapsedShareBeforeAnsweringAndSeparatesRoutes()
    {
        var (shareId, _) = await CreateShareAsync("alice", 42, """{"expiresInSeconds": 3600, "label": "周报"}""");
        // A change that bypassed the hooks: only a read (or the sweep) can notice it.
        await _host.WithDbAsync(db => db.HttpRouteMappings.Where(r => r.Id == 42)
            .ExecuteUpdateAsync(setters => setters.SetProperty(r => r.AuthEnabled, false)));

        using var alice = _host.CreateClient("alice");
        using var list = await alice.GetAsync("/api/admin/http-routes/42/shares");
        Assert.Equal(HttpStatusCode.OK, list.StatusCode);
        var share = Assert.Single(JsonNode.Parse(await list.Content.ReadAsStringAsync())!["shares"]!.AsArray())!;
        Assert.Equal(shareId, share["shareId"]!.GetValue<string>());
        Assert.Equal("周报", share["label"]!.GetValue<string>());
        Assert.Equal("revoked", share["status"]!.GetValue<string>());
        Assert.Equal("route-made-public", share["revokeReason"]!.GetValue<string>());
        Assert.Null(share["revokedBy"]);
        var audit = await _host.AuditAsync();
        Assert.Equal(HttpShareProtocol.ActionShareRevoked, audit[^1].Action);
        Assert.Null(audit[^1].Actor);
        Assert.DoesNotContain(audit, row => row.DetailJson.Contains("周报", StringComparison.Ordinal));

        using var other = await alice.GetAsync($"/api/admin/http-routes/43/shares/{shareId}");
        Assert.Equal(HttpStatusCode.NotFound, other.StatusCode);
        Assert.Equal("SHARE_NOT_FOUND",
            JsonNode.Parse(await other.Content.ReadAsStringAsync())!["code"]!.GetValue<string>());
        using var bob = _host.CreateClient("bob");
        using var hidden = await bob.GetAsync("/api/admin/http-routes/42/shares");
        Assert.Equal(HttpStatusCode.NotFound, hidden.StatusCode);
        Assert.Equal("SHARE_ROUTE_NOT_FOUND",
            JsonNode.Parse(await hidden.Content.ReadAsStringAsync())!["code"]!.GetValue<string>());
    }

    private async Task<(string ShareId, string Token)> CreateShareAsync(string caller, long routeId, string body)
    {
        using var client = _host.CreateClient(caller);
        using var response = await client.PostAsync($"/api/admin/http-routes/{routeId}/shares",
            new StringContent(body, Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var json = JsonNode.Parse(await response.Content.ReadAsStringAsync())!;
        return (json["share"]!["shareId"]!.GetValue<string>(), json["token"]!.GetValue<string>());
    }

    private async Task AssertShareAsync(string shareId, string? reason, string? revokedBy)
    {
        var row = await _host.ShareAsync(shareId);
        Assert.NotNull(row);
        Assert.Equal(reason, row!.RevokeReason);
        Assert.Equal(revokedBy, row.RevokedBy);
        Assert.Equal(reason is null, row.RevokedAt is null);
    }

    private static StringContent JsonContent(JsonNode body) =>
        new(body.ToJsonString(), Encoding.UTF8, "application/json");

    private static string[] RawHeaders(HttpResponseMessage response, string name)
    {
        if (response.Headers.NonValidated.TryGetValues(name, out var values)
            || response.Content.Headers.NonValidated.TryGetValues(name, out values))
        {
            return values.ToArray();
        }
        return [];
    }
}
