using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Authentication;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Hosting;

namespace Specus.IntegrationTests;

internal sealed class ClientAuthStub : IAsyncDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly TestServerFixture _server;
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _shutdown = new();
    private readonly Task _acceptLoop;

    private ClientAuthStub(TestServerFixture server)
    {
        _server = server;
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _acceptLoop = Task.Run(AcceptLoopAsync);
    }

    public int Port { get; }

    public string ServerBaseUrl => $"http://127.0.0.1:{Port}";

    public static ClientAuthStub Start(TestServerFixture server) => new(server);

    public async ValueTask DisposeAsync()
    {
        _shutdown.Cancel();
        try { _listener.Stop(); } catch { }
        try { await _acceptLoop; } catch { }
        _shutdown.Dispose();
    }

    private async Task AcceptLoopAsync()
    {
        while (!_shutdown.IsCancellationRequested)
        {
            TcpClient tcp;
            try
            {
                tcp = await _listener.AcceptTcpClientAsync(_shutdown.Token);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            _ = Task.Run(() => ServeAsync(tcp, _shutdown.Token), _shutdown.Token);
        }
    }

    private async Task ServeAsync(TcpClient tcp, CancellationToken cancellationToken)
    {
        try
        {
            using (tcp)
            {
                var stream = tcp.GetStream();
                await DrainRequestHeadersAsync(stream, cancellationToken);
                var response = await BuildResponseAsync(cancellationToken);
                var payload = JsonSerializer.SerializeToUtf8Bytes(response, JsonOptions);
                var header = Encoding.ASCII.GetBytes(
                    "HTTP/1.1 200 OK\r\n" +
                    "Content-Type: application/json\r\n" +
                    $"Content-Length: {payload.Length}\r\n" +
                    "Connection: close\r\n\r\n");
                await stream.WriteAsync(header, cancellationToken);
                await stream.WriteAsync(payload, cancellationToken);
                await stream.FlushAsync(cancellationToken);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Console.WriteLine("[auth-stub] " + ex);
        }
    }

    private async Task<ClientAuthLoginResponse> BuildResponseAsync(CancellationToken cancellationToken)
    {
        await using var scope = _server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var sessionStore = scope.ServiceProvider.GetRequiredService<ClientAuthSessionStore>();
        var account = await db.ClientAccounts.AsNoTracking()
            .SingleAsync(c => c.ClientName == DatabaseInitializer.DemoClientName, cancellationToken);
        var credential = await db.ClientCredentials.AsNoTracking()
            .SingleAsync(c => c.ApiKey == DatabaseInitializer.DemoCredentialApiKey, cancellationToken);
        var identity = new ClientIdentity
        {
            Id = Specus.Server.Authentication.ClientIdGenerator.NewId(),
            TenantId = credential.TenantId,
            CredentialId = credential.Id,
            ClientId = account.Id,
            ClientName = account.ClientName,
            MachineFingerprint = "it-machine",
            OsUser = Environment.UserName,
            Hostname = "integration-test",
            FirstSeenAt = DateTimeOffset.UtcNow,
            LastSeenAt = DateTimeOffset.UtcNow,
        };
        var session = sessionStore.Create(credential, identity, account, TimeSpan.FromHours(1), new ClientEnvironmentInfo
        {
            MachineFingerprint = "it-machine",
            Hostname = "integration-test",
            OsUser = Environment.UserName,
        });
        var specusMappings = await db.SpecusMappings.AsNoTracking()
            .Where(m => m.ClientId == account.Id && m.Enabled)
            .OrderBy(m => m.Id)
            .Select(m => new SpecusEndpoint
            {
                Port = m.ListenPort,
                SpecusAddress = m.TargetAddress,
                SpecusPort = m.TargetPort,
            })
            .ToListAsync(cancellationToken);
        return new ClientAuthLoginResponse
        {
            TenantId = "default",
            ClientId = account.Id,
            ClientName = account.ClientName,
            ClientSessionId = session.Id,
            AccessToken = session.AccessToken,
            TokenTtlSeconds = 3600,
            NettyHost = "127.0.0.1",
            NettyPort = _server.ControlPort,
            MaxOnlineInstances = 2,
            Policy = new ClientPolicy { Enabled = true, BillingStatus = "ACTIVE" },
            SpecusConfigList = specusMappings,
            HttpSpecusConfigList = new List<HttpRouteEndpoint>(),
        };
    }

    private static async Task DrainRequestHeadersAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        var buffer = new byte[1024];
        using var request = new MemoryStream();
        var headerEnd = -1;
        while (headerEnd < 0)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken);
            if (read <= 0)
            {
                return;
            }
            request.Write(buffer, 0, read);
            var text = Encoding.ASCII.GetString(request.GetBuffer(), 0, (int)request.Length);
            headerEnd = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            if (request.Length > 64 * 1024)
            {
                return;
            }
        }
        var headers = Encoding.ASCII.GetString(request.GetBuffer(), 0, headerEnd);
        var contentLength = headers.Split("\r\n", StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.Split(':', 2))
            .Where(parts => parts.Length == 2 && parts[0].Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
            .Select(parts => int.TryParse(parts[1].Trim(), out var value) ? value : 0)
            .FirstOrDefault();
        var bodyAlreadyRead = (int)request.Length - headerEnd - 4;
        var remaining = Math.Max(0, contentLength - bodyAlreadyRead);
        while (remaining > 0)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, remaining)), cancellationToken);
            if (read <= 0)
            {
                return;
            }
            remaining -= read;
        }
    }
}
