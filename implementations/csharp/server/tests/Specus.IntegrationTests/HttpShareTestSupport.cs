using System.Collections.Concurrent;
using System.Data.Common;
using System.Globalization;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Specus.Protocol;
using Specus.Protocol.Packets;
using Specus.Server.Authentication;
using Specus.Server.ControlChannel;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Http;
using Specus.Server.Management;
using Specus.Server.Nat;
using Specus.Server.Networking;
using Specus.Server.Security;
using Specus.Server.Sessions;

namespace Specus.IntegrationTests;

/// <summary>A share clock the tests set; everything else in the host keeps the real time.</summary>
internal sealed class ManualShareClock() : HttpShareClock(TimeProvider.System)
{
    private long _nowMs;

    public DateTimeOffset Now
    {
        get => DateTimeOffset.FromUnixTimeMilliseconds(Interlocked.Read(ref _nowMs));
        set => Interlocked.Exchange(ref _nowMs, value.ToUnixTimeMilliseconds());
    }

    public override DateTimeOffset UtcNow => Now;
}

/// <summary>Hands out queued bytes first (the vector's <c>newShare</c>), then CSPRNG output.</summary>
internal sealed class ScriptedShareRandom : IHttpShareRandom
{
    private readonly ConcurrentQueue<byte[]> _next = new();

    public void Enqueue(params byte[][] chunks)
    {
        foreach (var chunk in chunks)
        {
            _next.Enqueue(chunk);
        }
    }

    public void Clear() => _next.Clear();

    public void Fill(Span<byte> destination)
    {
        if (_next.TryDequeue(out var bytes))
        {
            if (bytes.Length != destination.Length)
            {
                throw new InvalidOperationException(
                    $"scripted random has {bytes.Length} bytes, {destination.Length} requested");
            }
            bytes.CopyTo(destination);
            return;
        }
        RandomNumberGenerator.Fill(destination);
    }
}

/// <summary>Makes every command on the share, route tables fail while <see cref="Fail"/> is set.</summary>
internal sealed class FailingShareStoreInterceptor : DbCommandInterceptor
{
    private int _fail;

    public bool Fail
    {
        get => Volatile.Read(ref _fail) != 0;
        set => Volatile.Write(ref _fail, value ? 1 : 0);
    }

    private void Check(DbCommand command)
    {
        if (Fail && (command.CommandText.Contains("http_share", StringComparison.Ordinal)
                     || command.CommandText.Contains("http_route_mapping", StringComparison.Ordinal)))
        {
            throw new InvalidOperationException("share store unavailable (test)");
        }
    }

    public override InterceptionResult<DbDataReader> ReaderExecuting(DbCommand command,
        CommandEventData eventData, InterceptionResult<DbDataReader> result)
    {
        Check(command);
        return result;
    }

    public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command,
        CommandEventData eventData, InterceptionResult<DbDataReader> result,
        CancellationToken cancellationToken = default)
    {
        Check(command);
        return ValueTask.FromResult(result);
    }

    public override InterceptionResult<object> ScalarExecuting(DbCommand command,
        CommandEventData eventData, InterceptionResult<object> result)
    {
        Check(command);
        return result;
    }

    public override ValueTask<InterceptionResult<object>> ScalarExecutingAsync(DbCommand command,
        CommandEventData eventData, InterceptionResult<object> result,
        CancellationToken cancellationToken = default)
    {
        Check(command);
        return ValueTask.FromResult(result);
    }

    public override InterceptionResult<int> NonQueryExecuting(DbCommand command,
        CommandEventData eventData, InterceptionResult<int> result)
    {
        Check(command);
        return result;
    }

    public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(DbCommand command,
        CommandEventData eventData, InterceptionResult<int> result,
        CancellationToken cancellationToken = default)
    {
        Check(command);
        return ValueTask.FromResult(result);
    }
}

/// <summary>
/// The in-process server with an injected share clock and random source, a switchable store
/// failure, and helpers to seed the vector world (users, clients 7 and 8, routes 42/43/44/50).
/// The built-in admin is renamed so the vector's <c>admin</c> is an ordinary user row.
/// </summary>
internal sealed class HttpShareTestHost : IAsyncDisposable
{
    public const string BuiltInAdmin = "root";
    public static readonly DateTimeOffset VectorNow = DateTimeOffset.Parse("2026-10-06T08:00:00Z",
        CultureInfo.InvariantCulture);

    private HttpShareTestHost(TestServerFixture server, ManualShareClock clock, ScriptedShareRandom random,
        FailingShareStoreInterceptor store)
    {
        Server = server;
        Clock = clock;
        Random = random;
        Store = store;
    }

    public TestServerFixture Server { get; }

    public ManualShareClock Clock { get; }

    public ScriptedShareRandom Random { get; }

    public FailingShareStoreInterceptor Store { get; }

    public static async Task<HttpShareTestHost> StartAsync(bool keepSweeper = false)
    {
        var clock = new ManualShareClock { Now = VectorNow };
        var random = new ScriptedShareRandom();
        var store = new FailingShareStoreInterceptor();
        var server = await TestServerFixture.StartAsync(
            new Dictionary<string, string?> { ["Specus:Auth:Username"] = BuiltInAdmin },
            services =>
            {
                services.AddSingleton<HttpShareClock>(clock);
                services.AddSingleton<IHttpShareRandom>(random);
                services.ConfigureDbContext<SpecusDbContext>((_, options) => options.AddInterceptors(store));
                if (!keepSweeper)
                {
                    // Sweeps are replayed explicitly; a background one would write expiry entries
                    // in the middle of a case.
                    var sweeper = services.Single(descriptor => descriptor.ServiceType == typeof(IHostedService)
                                                                && descriptor.ImplementationType == typeof(HttpShareSweeper));
                    services.Remove(sweeper);
                }
            });
        return new HttpShareTestHost(server, clock, random, store);
    }

    public T Service<T>() where T : notnull => Server.HostServices.GetRequiredService<T>();

    public async Task<T> WithDbAsync<T>(Func<SpecusDbContext, Task<T>> work)
    {
        await using var scope = Server.HostServices.CreateAsyncScope();
        return await work(scope.ServiceProvider.GetRequiredService<SpecusDbContext>());
    }

    public Task WithDbAsync(Func<SpecusDbContext, Task> work) => WithDbAsync(async db =>
    {
        await work(db);
        return true;
    });

    public HttpClient CreateClient(string? bearerFor = null)
    {
        var client = Server.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = false,
        });
        if (bearerFor is not null)
        {
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", TokenFor(bearerFor));
        }
        return client;
    }

    /// <summary>
    /// A local bearer token for the user in its own tenant, as login would mint it: the token's tenant
    /// selects whose login name <c>sub</c> is. The server re-reads the user on every request anyway.
    /// </summary>
    public string TokenFor(string username)
    {
        var tokens = Service<LocalTokenService>();
        string? tenant;
        using (var scope = Server.HostServices.CreateScope())
        {
            tenant = scope.ServiceProvider.GetRequiredService<SpecusDbContext>().ManagementUsers.AsNoTracking()
                .Where(u => u.Username == username)
                .Select(u => u.TenantId)
                .FirstOrDefault();
        }
        // The built-in administrator has no row and belongs to the default tenant.
        tenant ??= string.Equals(username, BuiltInAdmin, StringComparison.OrdinalIgnoreCase) ? "default" : "t1";
        return tokens.IssueTokenBody(username, tenant, ManagementRole.User).AccessToken;
    }

    public static string ClientName(long clientId) => "vector-client-" + clientId.ToString(CultureInfo.InvariantCulture);

    /// <summary>Resets the share tables and seeds the vector world, its changes and shares.</summary>
    public async Task SeedWorldAsync(JsonElement world, JsonElement? worldChanges, JsonElement? shares)
    {
        Store.Fail = false;
        Random.Clear();
        Service<HttpShareRequestRateLimiter>().Reset();
        await WithDbAsync(async db =>
        {
            var clientIds = world.GetProperty("clients").EnumerateObject()
                .Select(c => c.Value.GetProperty("clientId").GetInt64()).ToList();
            var usernames = world.GetProperty("users").EnumerateObject().Select(u => u.Name).ToList();
            await db.HttpShares.ExecuteDeleteAsync();
            await db.HttpAccessAudits.ExecuteDeleteAsync();
            await db.HttpRouteMappings.Where(r => clientIds.Contains(r.ClientId)).ExecuteDeleteAsync();
            await db.ClientAccounts.Where(c => clientIds.Contains(c.Id)).ExecuteDeleteAsync();
            await db.ManagementUsers.Where(u => usernames.Contains(u.Username)).ExecuteDeleteAsync();

            var now = DateTimeOffset.UtcNow;
            foreach (var user in world.GetProperty("users").EnumerateObject().Select(u => u.Value))
            {
                db.ManagementUsers.Add(new ManagementUser
                {
                    Username = user.GetProperty("username").GetString()!,
                    TenantId = user.GetProperty("tenantId").GetString()!,
                    PasswordHash = PasswordHasher.HashToken("unused-" + Guid.NewGuid()),
                    Role = user.GetProperty("role").GetString() == "ADMIN" ? ManagementRole.Admin : ManagementRole.User,
                    Enabled = user.GetProperty("enabled").GetBoolean(),
                    CreatedAt = now,
                    UpdatedAt = now,
                });
            }
            foreach (var client in world.GetProperty("clients").EnumerateObject().Select(c => c.Value))
            {
                var id = client.GetProperty("clientId").GetInt64();
                db.ClientAccounts.Add(new ClientAccount
                {
                    Id = id,
                    TenantId = client.GetProperty("tenantId").GetString()!,
                    OwnerUsername = client.GetProperty("owner").GetString(),
                    ClientName = ClientName(id),
                    PasswordHash = PasswordHasher.HashToken("unused"),
                    Enabled = client.GetProperty("enabled").GetBoolean(),
                    CreatedAt = now,
                    UpdatedAt = now,
                });
            }
            foreach (var route in world.GetProperty("routes").EnumerateObject().Select(r => r.Value))
            {
                var clientId = route.GetProperty("clientId").GetInt64();
                var authEnabled = route.GetProperty("authEnabled").GetBoolean();
                db.HttpRouteMappings.Add(new HttpRouteMapping
                {
                    Id = route.GetProperty("routeId").GetInt64(),
                    TenantId = route.GetProperty("tenantId").GetString(),
                    ClientId = clientId,
                    ClientName = ClientName(clientId),
                    Route = route.GetProperty("name").GetString()!,
                    TargetBaseUrl = "http://127.0.0.1:9",
                    Enabled = route.GetProperty("enabled").GetBoolean(),
                    AuthEnabled = authEnabled,
                    AuthUsername = authEnabled ? "basic" : null,
                    AuthPasswordHash = authEnabled ? PasswordHasher.HashToken("basic-password") : null,
                    CreatedAt = now,
                    UpdatedAt = now,
                });
            }
            await db.SaveChangesAsync();

            if (worldChanges is { ValueKind: JsonValueKind.Array } changes)
            {
                foreach (var change in changes.EnumerateArray())
                {
                    await ApplyChangeAsync(db, change.GetProperty("table").GetString()!, change.GetProperty("key"),
                        change.TryGetProperty("deleted", out var deleted) && deleted.GetBoolean(),
                        change.TryGetProperty("set", out var set) ? set : null);
                }
            }
            if (shares is { ValueKind: JsonValueKind.Array } rows)
            {
                foreach (var row in rows.EnumerateArray())
                {
                    db.HttpShares.Add(ShareRow(row));
                }
                await db.SaveChangesAsync();
            }
        });
    }

    /// <summary>A change made to the world without any hook: the vector's worldChanges and silent-change.</summary>
    public static async Task ApplyChangeAsync(SpecusDbContext db, string table, JsonElement key, bool deleted,
        JsonElement? set)
    {
        switch (table)
        {
            case "users":
            {
                var username = key.GetString()!;
                var user = await db.ManagementUsers.SingleAsync(u => u.Username == username);
                if (deleted)
                {
                    db.ManagementUsers.Remove(user);
                }
                else
                {
                    if (set!.Value.TryGetProperty("enabled", out var enabled))
                    {
                        user.Enabled = enabled.GetBoolean();
                    }
                    if (set.Value.TryGetProperty("role", out var role))
                    {
                        user.Role = role.GetString() == "ADMIN" ? ManagementRole.Admin : ManagementRole.User;
                    }
                }
                break;
            }
            case "clients":
            {
                var id = key.GetInt64();
                var client = await db.ClientAccounts.SingleAsync(c => c.Id == id);
                if (deleted)
                {
                    db.ClientAccounts.Remove(client);
                }
                else if (set!.Value.TryGetProperty("enabled", out var enabled))
                {
                    client.Enabled = enabled.GetBoolean();
                }
                break;
            }
            case "routes":
            {
                var id = key.GetInt64();
                var route = await db.HttpRouteMappings.SingleAsync(r => r.Id == id);
                if (deleted)
                {
                    db.HttpRouteMappings.Remove(route);
                }
                else
                {
                    if (set!.Value.TryGetProperty("enabled", out var enabled))
                    {
                        route.Enabled = enabled.GetBoolean();
                    }
                    if (set.Value.TryGetProperty("authEnabled", out var authEnabled))
                    {
                        route.AuthEnabled = authEnabled.GetBoolean();
                    }
                }
                break;
            }
            default:
                throw new InvalidOperationException("unknown table " + table);
        }
        await db.SaveChangesAsync();
    }

    public static HttpShare ShareRow(JsonElement row) => new()
    {
        ShareId = row.GetProperty("shareId").GetString()!,
        TenantId = row.GetProperty("tenantId").GetString()!,
        RouteId = row.GetProperty("routeId").GetInt64(),
        TokenSha256 = row.GetProperty("tokenSha256").GetString()!,
        Access = row.GetProperty("access").GetString()!,
        PathPrefix = row.GetProperty("pathPrefix").GetString()!,
        Label = row.GetProperty("label").GetString(),
        CreatedBy = row.GetProperty("createdBy").GetString()!,
        CreatedAt = HttpShareProtocol.ParseStamp(row.GetProperty("createdAt").GetString()!),
        ExpiresAt = HttpShareProtocol.ParseStamp(row.GetProperty("expiresAt").GetString()!),
        RevokedAt = row.GetProperty("revokedAt").ValueKind == JsonValueKind.Null
            ? null
            : HttpShareProtocol.ParseStamp(row.GetProperty("revokedAt").GetString()!),
        RevokedBy = row.GetProperty("revokedBy").GetString(),
        RevokeReason = row.GetProperty("revokeReason").GetString(),
    };

    public Task<List<HttpAccessAudit>> AuditAsync() =>
        WithDbAsync(db => db.HttpAccessAudits.AsNoTracking().OrderBy(a => a.Id).ToListAsync());

    public Task<HttpShare?> ShareAsync(string shareId) =>
        WithDbAsync(db => db.HttpShares.AsNoTracking().FirstOrDefaultAsync(s => s.ShareId == shareId));

    public ValueTask DisposeAsync() => Server.DisposeAsync();
}

/// <summary>
/// Plays a connected device's data connection: captures every NAT packet the server sends (the
/// OPEN metadata is what a share forwards) and injects the device's answers.
/// </summary>
internal sealed class ShareFakeDevice : IAsyncDisposable
{
    private readonly NatServerHandler _nat;
    private readonly SessionRegistry _registry;
    private readonly CancellationTokenSource _lifetime;
    private readonly CapturingWriter _writer;
    private readonly string _clientName;

    private ShareFakeDevice(NatServerHandler nat, SessionRegistry registry, CancellationTokenSource lifetime,
        CapturingWriter writer, SpecusConnectionContext context, string clientName)
    {
        _nat = nat;
        _registry = registry;
        _lifetime = lifetime;
        _writer = writer;
        Context = context;
        _clientName = clientName;
    }

    public SpecusConnectionContext Context { get; }

    public int OpenCount => _writer.OpenCount;

    public static ShareFakeDevice Bind(TestServerFixture server, string clientName)
    {
        var nat = server.HostServices.GetRequiredService<NatServerHandler>();
        var registry = server.HostServices.GetRequiredService<SessionRegistry>();
        var lifetime = new CancellationTokenSource();
        var writer = new CapturingWriter();
        var context = new SpecusConnectionContext("http-share-test-" + Guid.NewGuid().ToString("N"),
            "127.0.0.1:23456", writer, lifetime.Token, lifetime.Cancel, new ReadGate(lifetime.Token),
            new WriteBackpressureGate(64 * 1024, 1024 * 1024));
        context.OnLoginSuccess(clientName, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            clientSessionId: 1, connectionRole: ConnectionRole.Data);
        registry.ReplaceData(clientName, context);
        nat.Attach(context);
        return new ShareFakeDevice(nat, registry, lifetime, writer, context, clientName);
    }

    public Task<NatMessagePacket> ReadAsync(Func<NatMessagePacket, bool> predicate,
        CancellationToken cancellationToken) => _writer.ReadAsync(predicate, cancellationToken);

    public Task<NatMessagePacket> OpenedAsync(CancellationToken cancellationToken) =>
        ReadAsync(packet => packet.NatMessageType == NatMessageType.Open, cancellationToken);

    public IReadOnlyList<NatMessagePacket> Snapshot() => _writer.Snapshot();

    /// <summary>Answers an HTTP stream: response head, optional body, optional end.</summary>
    public async Task RespondAsync(uint streamId, int statusCode, IEnumerable<string>? headers = null,
        string? body = null, bool finish = true)
    {
        await _nat.HandleAsync(Context, new NatMessagePacket
        {
            NatMessageType = NatMessageType.Open,
            StreamId = streamId,
            MetaData = new Dictionary<string, object?>
            {
                ["source"] = "http",
                ["phase"] = "response",
                ["statusCode"] = statusCode,
                ["headers"] = (headers ?? []).ToList(),
            },
        });
        if (body is not null)
        {
            await _nat.HandleAsync(Context, new NatMessagePacket
            {
                NatMessageType = NatMessageType.Data,
                StreamId = streamId,
                Data = Encoding.UTF8.GetBytes(body),
            });
        }
        if (finish)
        {
            await _nat.HandleAsync(Context, new NatMessagePacket
            {
                NatMessageType = NatMessageType.Fin,
                StreamId = streamId,
            });
        }
    }

    public async ValueTask DisposeAsync()
    {
        _registry.Unbind(_clientName, Context);
        _lifetime.Cancel();
        await _nat.OnConnectionClosedAsync(Context);
        _lifetime.Dispose();
    }

    public static List<string> Headers(NatMessagePacket packet) =>
        packet.MetaData?.TryGetValue("headers", out var value) == true && value is IEnumerable<string> lines
            ? lines.ToList()
            : [];

    private sealed class CapturingWriter : IFrameWriter
    {
        private readonly Channel<NatMessagePacket> _packets = Channel.CreateUnbounded<NatMessagePacket>();
        private readonly ConcurrentQueue<NatMessagePacket> _snapshot = new();
        private int _openCount;

        public int OpenCount => Volatile.Read(ref _openCount);

        public ValueTask WriteAsync(Packet packet, CancellationToken cancellationToken = default)
        {
            if (packet is not NatMessagePacket nat)
            {
                return ValueTask.CompletedTask;
            }
            var captured = new NatMessagePacket
            {
                NatMessageType = nat.NatMessageType,
                Flags = nat.Flags,
                StreamId = nat.StreamId,
                Value = nat.Value,
                MetaData = nat.MetaData is null ? null : new Dictionary<string, object?>(nat.MetaData),
                Data = nat.Data?.ToArray(),
            };
            if (captured.NatMessageType == NatMessageType.Open)
            {
                Interlocked.Increment(ref _openCount);
            }
            _snapshot.Enqueue(captured);
            _packets.Writer.TryWrite(captured);
            return ValueTask.CompletedTask;
        }

        public async Task<NatMessagePacket> ReadAsync(Func<NatMessagePacket, bool> predicate,
            CancellationToken cancellationToken)
        {
            await foreach (var packet in _packets.Reader.ReadAllAsync(cancellationToken))
            {
                if (predicate(packet))
                {
                    return packet;
                }
            }
            throw new EndOfStreamException("NAT capture completed");
        }

        public IReadOnlyList<NatMessagePacket> Snapshot() => _snapshot.ToArray();
    }
}
