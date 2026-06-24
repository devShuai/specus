using System.IO.Pipelines;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using ShuaiTunnel.Client.Configuration;
using ShuaiTunnel.Client.Control;
using ShuaiTunnel.Client.DirectHttp;
using ShuaiTunnel.Protocol;
using ShuaiTunnel.Protocol.Codec;
using ShuaiTunnel.Protocol.Packets;

namespace ShuaiTunnel.Client.Tests;

/// <summary>
/// Spins up a minimal in-process tunnel "server" that speaks just enough of the wire
/// protocol to validate the C# client: accepts login, drives a REGISTER + CONNECTED + DATA
/// echo, then forces a reconnect and verifies the client comes back.
/// </summary>
public class TunnelControlClientReconnectTests
{
    [Fact]
    public async Task ClientLogsIn_Registers_RoundtripsData_AndReconnects()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var controlPort = ((IPEndPoint)listener.LocalEndpoint).Port;

        using var authListener = new TcpListener(IPAddress.Loopback, 0);
        authListener.Start();
        var authPort = ((IPEndPoint)authListener.LocalEndpoint).Port;

        using var upstream = new TcpListener(IPAddress.Loopback, 0);
        upstream.Start();
        var upstreamPort = ((IPEndPoint)upstream.LocalEndpoint).Port;
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var upstreamTask = AcceptAndEchoAsync(upstream);
        var authTask = RunAuthServerAsync(authListener, controlPort, upstreamPort, cts.Token);

        var config = new TunnelClientConfig
        {
            ServerBaseUrl = $"http://127.0.0.1:{authPort}",
            ApiKey = "ak_test",
            Secret = "sk_test",
        };

        using var http = new HttpClient();
        var auth = new ClientAuthService(config, http, NullLogger<ClientAuthService>.Instance);
        var client = new TunnelControlClient(auth, new DirectHttpForwarder(http), NullLoggerFactory.Instance);
        var clientTask = Task.Run(() => client.RunAsync(cts.Token), cts.Token);

        try
        {
            // --- First session ----------------------------------------------------
            using (var session = await ServerSession.AcceptAsync(listener, cts.Token))
            {
                var login = (LoginRequestPacket)await session.ReadAsync(cts.Token);
                Assert.Equal("csharp-tester", login.ClientName);
                Assert.True(login.ClientSessionId > 0);
                Assert.Equal("cs-test-token", login.AccessToken);
                await session.WriteAsync(new LoginResponsePacket
                {
                    ClientName = login.ClientName, Success = true, Reason = null,
                }, cts.Token);

                var register = (NatMessagePacket)await session.ReadAsync(cts.Token);
                Assert.Equal(NatMessageType.Register, register.NatMessageType);
                Assert.Equal(9999, Convert.ToInt32(register.MetaData!["port"]));

                await session.WriteAsync(new NatMessagePacket
                {
                    NatMessageType = NatMessageType.RegisterResult,
                    MetaData = new Dictionary<string, object?> { ["port"] = 9999, ["success"] = true },
                }, cts.Token);

                // HTTP_ROUTES_REPORT is sent once per session.
                var routes = (NatMessagePacket)await session.ReadAsync(cts.Token);
                Assert.Equal(NatMessageType.HttpRoutesReport, routes.NatMessageType);

                const string channelId = "abc123";
                await session.WriteAsync(new NatMessagePacket
                {
                    NatMessageType = NatMessageType.Connected,
                    MetaData = new Dictionary<string, object?>
                    {
                        ["channelId"] = channelId, ["port"] = 9999,
                    },
                }, cts.Token);

                var greeting = new byte[] { 0x01, 0x02, 0x03 };
                await session.WriteAsync(new NatMessagePacket
                {
                    NatMessageType = NatMessageType.Data,
                    MetaData = new Dictionary<string, object?> { ["channelId"] = channelId },
                    Data = greeting,
                }, cts.Token);

                var echoed = (NatMessagePacket)await session.ReadAsync(cts.Token);
                Assert.Equal(NatMessageType.Data, echoed.NatMessageType);
                Assert.Equal(channelId, (string)echoed.MetaData!["channelId"]!);
                Assert.Equal(greeting, echoed.Data);

                // Drop the connection -- the client should reconnect.
            }

            // --- Second session ---------------------------------------------------
            using (var session = await ServerSession.AcceptAsync(listener, cts.Token))
            {
                var login = (LoginRequestPacket)await session.ReadAsync(cts.Token);
                Assert.Equal("csharp-tester", login.ClientName);
                Assert.True(login.ClientSessionId > 0);
                Assert.Equal("cs-test-token", login.AccessToken);
                await session.WriteAsync(new LoginResponsePacket
                {
                    ClientName = login.ClientName, Success = true,
                }, cts.Token);

                var register = (NatMessagePacket)await session.ReadAsync(cts.Token);
                Assert.Equal(NatMessageType.Register, register.NatMessageType);
            }
        }
        finally
        {
            cts.Cancel();
            try { await clientTask.WaitAsync(TimeSpan.FromSeconds(5)); }
            catch (OperationCanceledException) { }
            catch (TimeoutException) { }
            listener.Stop();
            authListener.Stop();
            upstream.Stop();
            try { await upstreamTask.WaitAsync(TimeSpan.FromSeconds(2)); } catch { }
            try { await authTask.WaitAsync(TimeSpan.FromSeconds(2)); } catch { }
        }
    }

    private static async Task RunAuthServerAsync(
        TcpListener listener, int controlPort, int upstreamPort, CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var tcp = await listener.AcceptTcpClientAsync(ct);
                _ = Task.Run(async () =>
                {
                    using (tcp)
                    using (var stream = tcp.GetStream())
                    {
                        var buffer = new byte[8192];
                        var read = await stream.ReadAsync(buffer, ct);
                        Assert.True(read > 0);
                        var body = $$"""
                        {"tenantId":"default","clientId":1,"clientName":"csharp-tester","clientSessionId":1001,"accessToken":"cs-test-token","tokenTtlSeconds":3600,"nettyHost":"127.0.0.1","nettyPort":{{controlPort}},"maxOnlineInstances":2,"policy":{"enabled":true,"billingStatus":"ACTIVE","retryAfterSeconds":0},"tunnelConfigList":[{"port":9999,"tunnelAddress":"127.0.0.1","tunnelPort":{{upstreamPort}}}],"httpTunnelConfigList":[]}
                        """;
                        var payload = Encoding.UTF8.GetBytes(body);
                        var header = Encoding.ASCII.GetBytes(
                            $"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {payload.Length}\r\nConnection: close\r\n\r\n");
                        await stream.WriteAsync(header, ct);
                        await stream.WriteAsync(payload, ct);
                        await stream.FlushAsync(ct);
                    }
                }, ct);
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch
        {
            // listener stopped
        }
    }

    private static async Task AcceptAndEchoAsync(TcpListener listener)
    {
        try
        {
            while (true)
            {
                var tcp = await listener.AcceptTcpClientAsync();
                _ = Task.Run(async () =>
                {
                    using (tcp)
                    using (var stream = tcp.GetStream())
                    {
                        var buffer = new byte[4096];
                        int read;
                        while ((read = await stream.ReadAsync(buffer)) > 0)
                        {
                            await stream.WriteAsync(buffer.AsMemory(0, read));
                        }
                    }
                });
            }
        }
        catch
        {
            // listener stopped
        }
    }

    private sealed class ServerSession : IDisposable
    {
        private readonly TcpClient _tcp;
        private readonly NetworkStream _stream;
        private readonly PipeReader _reader;

        private ServerSession(TcpClient tcp)
        {
            _tcp = tcp;
            _stream = tcp.GetStream();
            _reader = PipeReader.Create(_stream);
        }

        public static async Task<ServerSession> AcceptAsync(TcpListener listener, CancellationToken ct)
        {
            var tcp = await listener.AcceptTcpClientAsync(ct);
            return new ServerSession(tcp);
        }

        public async Task<Packet> ReadAsync(CancellationToken ct)
        {
            var packet = await FrameReaderProxy.ReadFrameAsync(_reader, 32 * 1024 * 1024, ct);
            Assert.NotNull(packet);
            return packet!;
        }

        public async Task WriteAsync(Packet packet, CancellationToken ct)
        {
            var bytes = PacketCodec.Encode(packet);
            await _stream.WriteAsync(bytes, ct);
            await _stream.FlushAsync(ct);
        }

        public void Dispose()
        {
            _reader.Complete();
            _stream.Dispose();
            _tcp.Dispose();
        }
    }
}

/// <summary>Trampoline because the client's FrameReader is internal — exposed to tests via InternalsVisibleTo.</summary>
internal static class FrameReaderProxy
{
    public static ValueTask<Packet?> ReadFrameAsync(PipeReader reader, int maxFrameSize, CancellationToken token)
        => FrameReader.ReadFrameAsync(reader, maxFrameSize, token);
}
