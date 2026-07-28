using System.IO.Pipelines;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Specus.Client.Configuration;
using Specus.Client.Control;
using Specus.Client.DirectHttp;
using Specus.Client.Nat;
using Specus.Protocol;
using Specus.Protocol.Packets;

namespace Specus.Client.Tests;

public class NatClientHandlerWebSocketTests
{
    [Fact]
    public async Task RegisterFailure_ClearsPortSoConfigRefreshCanRetry()
    {
        var mapping = new SpecusConfigEntry
        {
            Port = 19090,
            SpecusAddress = "127.0.0.1",
            SpecusPort = 8080,
        };
        await using var stream = new MemoryStream();
        await using var writer = new FrameWriter(stream);
        var directHttp = new DirectHttpHandler(
            Enumerable.Empty<HttpSpecusConfigEntry>(),
            writer,
            new DirectHttpForwarder(new HttpClient()),
            NullLogger<DirectHttpHandler>.Instance);
        await using var nat = new NatClientHandler(
            new[] { mapping },
            "csharp-tester",
            writer,
            directHttp,
            NullLogger<NatClientHandler>.Instance);
        nat.Bind(CancellationToken.None);

        await nat.RegisterAllAsync();
        var firstRegisterLength = stream.Length;
        await nat.HandleAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.RegisterResult,
            MetaData = new Dictionary<string, object?>
            {
                ["port"] = mapping.Port,
                ["success"] = false,
                ["reason"] = "address already in use",
            },
        });
        await nat.ApplyConfigAsync(new[] { mapping });

        Assert.True(stream.Length > firstRegisterLength);
    }

    [Theory]
    [MemberData(nameof(InvalidTcpOpenMetadata))]
    public async Task HandleOpenAsync_ForInvalidTcpMapping_IgnoresLikeJava(Dictionary<string, object?> metadata)
    {
        await using var stream = new MemoryStream();
        await using var writer = new FrameWriter(stream);
        var directHttp = new DirectHttpHandler(
            Enumerable.Empty<HttpSpecusConfigEntry>(),
            writer,
            new DirectHttpForwarder(new HttpClient()),
            NullLogger<DirectHttpHandler>.Instance);
        await using var nat = new NatClientHandler(
            Enumerable.Empty<SpecusConfigEntry>(),
            "csharp-tester",
            writer,
            directHttp,
            NullLogger<NatClientHandler>.Instance);
        nat.Bind(CancellationToken.None);

        await nat.HandleAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.Open,
            StreamId = 1,
            MetaData = metadata,
        });

        Assert.Equal(0, stream.Length);
    }

    public static IEnumerable<object[]> InvalidTcpOpenMetadata()
    {
        yield return new object[] { new Dictionary<string, object?> { ["channelId"] = "channel-1" } };
        yield return new object[] { new Dictionary<string, object?> { ["port"] = 10022 } };
        yield return new object[] { new Dictionary<string, object?> { ["channelId"] = "channel-1", ["port"] = 10022 } };
    }

    [Fact]
    public void TryBuildWebSocketTarget_MapsHttpRouteToWebSocketTarget()
    {
        var ok = NatClientHandler.TryBuildWebSocketTarget(
            "http://127.0.0.1:8080/api",
            "/socket",
            "transport=websocket",
            out var target,
            out var error);

        Assert.True(ok, error);
        Assert.Equal("ws://127.0.0.1:8080/api/socket?transport=websocket", target.ToString());
    }

    [Fact]
    public void TryBuildWebSocketTarget_MapsHttpsRouteToSecureWebSocketTarget()
    {
        var ok = NatClientHandler.TryBuildWebSocketTarget(
            "https://example.test/base/",
            "/events",
            null,
            out var target,
            out var error);

        Assert.True(ok, error);
        Assert.Equal("wss://example.test/base/events", target.ToString());
    }

    [Fact]
    public void TryBuildWebSocketTarget_PreservesDoubleSlashPathLikeJava()
    {
        var ok = NatClientHandler.TryBuildWebSocketTarget(
            "http://example.test/base",
            "//assets/socket",
            null,
            out var target,
            out var error);

        Assert.True(ok, error);
        Assert.Equal("ws://example.test/base//assets/socket", target.ToString());
    }

    [Theory]
    [InlineData("", "/", "未配置 HTTP route")]
    [InlineData("ftp://example.test/base", "/", "HTTP route 仅支持 http/https/ws/wss")]
    [InlineData("http://example.test/base?x=1", "/", "HTTP route 地址无效")]
    [InlineData("http://example.test/base#x", "/", "HTTP route 地址无效")]
    [InlineData("http://example.test/base", "/socket\r\nBad: value", "relativePath 含有非法控制字符")]
    public void TryBuildWebSocketTarget_UsesJavaErrorMessages(
        string targetBaseUrl,
        string relativePath,
        string expected)
    {
        var ok = NatClientHandler.TryBuildWebSocketTarget(
            targetBaseUrl,
            relativePath,
            null,
            out _,
            out var error);

        Assert.False(ok);
        Assert.Equal(expected, error);
    }

    [Fact]
    public void BuildLocalWebSocket_TrustsOperatorConfiguredLanCertificates()
    {
        using var socket = NatClientHandler.BuildLocalWebSocket();

        Assert.NotNull(socket.Options.RemoteCertificateValidationCallback);
        Assert.True(socket.Options.RemoteCertificateValidationCallback!(
            sender: new object(),
            certificate: null,
            chain: null,
            sslPolicyErrors: SslPolicyErrors.RemoteCertificateChainErrors));
    }

    [Fact]
    public void WebSocketHandshakeHeaders_FiltersHopByHopAndWebSocketHeaders()
    {
        var headers = NatClientHandler.WebSocketHandshakeHeaders(new Dictionary<string, object?>
        {
            ["headers"] = new object?[]
            {
                "Origin:http://127.0.0.1:8088",
                "Connection:Upgrade",
                "Sec-WebSocket-Key:bad",
                "X-Trace:abc",
            },
        });

        Assert.Equal(
            new[]
            {
                new KeyValuePair<string, string>("Origin", "http://127.0.0.1:8088"),
                new KeyValuePair<string, string>("X-Trace", "abc"),
            },
            headers);
    }

    [Fact]
    public async Task HandleOpenAsync_ForWebSocketRoute_ForwardsLocalTextFrameToNatData()
    {
        using var wsListener = new TcpListener(IPAddress.Loopback, 0);
        wsListener.Start();
        var wsPort = ((IPEndPoint)wsListener.LocalEndpoint).Port;
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var wsTask = RunMinimalWebSocketServerAsync(wsListener, cts.Token);

        using var controlListener = new TcpListener(IPAddress.Loopback, 0);
        controlListener.Start();
        var controlPort = ((IPEndPoint)controlListener.LocalEndpoint).Port;
        using var controlClient = new TcpClient();
        var acceptControlTask = controlListener.AcceptTcpClientAsync(cts.Token);
        await controlClient.ConnectAsync(IPAddress.Loopback, controlPort, cts.Token);
        using var controlServer = await acceptControlTask;
        await using var writer = new FrameWriter(controlClient.GetStream());

        var directHttp = new DirectHttpHandler(
            new[]
            {
                new HttpSpecusConfigEntry
                {
                    Route = "app",
                    TargetBaseUrl = $"http://127.0.0.1:{wsPort}/base",
                },
            },
            writer,
            new DirectHttpForwarder(new HttpClient()),
            NullLogger<DirectHttpHandler>.Instance);
        await using var nat = new NatClientHandler(
            Enumerable.Empty<SpecusConfigEntry>(),
            "csharp-tester",
            writer,
            directHttp,
            NullLogger<NatClientHandler>.Instance);
        nat.Bind(cts.Token);

        await nat.HandleAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.Open,
            StreamId = 1,
            MetaData = new Dictionary<string, object?>
            {
                ["channelId"] = "ws1",
                ["source"] = "ws",
                ["route"] = "app",
                ["relativePath"] = "/socket",
                ["rawQuery"] = "transport=websocket",
                ["headers"] = new object?[] { "X-Trace:abc", "Connection:Upgrade" },
            },
        });

        var packet = await FrameReaderProxy.ReadFrameAsync(
            PipeReader.Create(controlServer.GetStream()), 32 * 1024 * 1024, cts.Token);
        var natData = Assert.IsType<NatMessagePacket>(packet);
        Assert.Equal(NatMessageType.Data, natData.NatMessageType);
        Assert.Equal(1U, natData.StreamId);
        Assert.Empty(natData.MetaData!);
        var frame = WebSocketSpecusFrame.Decode(natData.Data!);
        Assert.Equal(WebSocketSpecusFrame.OpcodeText, frame.Opcode);
        Assert.True(frame.FinalFragment);
        Assert.Equal("hello", Encoding.UTF8.GetString(frame.Payload));

        cts.Cancel();
        wsListener.Stop();
        controlListener.Stop();
        try { await wsTask; } catch (OperationCanceledException) { }
    }

    [Fact]
    public void WebSocketSpecusFrame_RejectsLegacyPrefix()
    {
        Assert.Throws<InvalidDataException>(() =>
            WebSocketSpecusFrame.Decode(new byte[] { 0x01, (byte)'o', (byte)'l', (byte)'d' }));
    }

    [Fact]
    public void WebSocketSpecusFrame_RoundTripsClose()
    {
        var encoded = new WebSocketSpecusFrame(
            WebSocketSpecusFrame.OpcodeClose, true, 0, 1001, Encoding.UTF8.GetBytes("going away")).Encode();
        var decoded = WebSocketSpecusFrame.Decode(encoded);

        Assert.Equal(WebSocketSpecusFrame.OpcodeClose, decoded.Opcode);
        Assert.Equal((ushort)1001, decoded.CloseCode);
        Assert.Equal("going away", Encoding.UTF8.GetString(decoded.Payload));
    }

    private static async Task RunMinimalWebSocketServerAsync(TcpListener listener, CancellationToken ct)
    {
        using var tcp = await listener.AcceptTcpClientAsync(ct);
        await using var stream = tcp.GetStream();
        var header = await ReadHttpHeaderAsync(stream, ct);
        Assert.StartsWith("GET /base/socket?transport=websocket HTTP/1.1", header, StringComparison.Ordinal);
        Assert.Contains("X-Trace: abc", header, StringComparison.OrdinalIgnoreCase);
        var key = ExtractHeader(header, "Sec-WebSocket-Key");
        Assert.False(string.IsNullOrWhiteSpace(key));
        var accept = Convert.ToBase64String(
            SHA1.HashData(Encoding.ASCII.GetBytes(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")));
        var response = Encoding.ASCII.GetBytes(
            "HTTP/1.1 101 Switching Protocols\r\n" +
            "Upgrade: websocket\r\n" +
            "Connection: Upgrade\r\n" +
            $"Sec-WebSocket-Accept: {accept}\r\n\r\n");
        await stream.WriteAsync(response, ct);
        await WriteServerWebSocketFrameAsync(stream, 0x1, Encoding.UTF8.GetBytes("hello"), ct);
        await stream.FlushAsync(ct);
    }

    private static async Task<string> ReadHttpHeaderAsync(NetworkStream stream, CancellationToken ct)
    {
        var buffer = new List<byte>();
        var one = new byte[1];
        while (true)
        {
            var read = await stream.ReadAsync(one, ct);
            if (read <= 0)
            {
                break;
            }
            buffer.Add(one[0]);
            if (buffer.Count >= 4
                && buffer[^4] == '\r'
                && buffer[^3] == '\n'
                && buffer[^2] == '\r'
                && buffer[^1] == '\n')
            {
                break;
            }
        }
        return Encoding.ASCII.GetString(buffer.ToArray());
    }

    private static string ExtractHeader(string headerBlock, string name)
    {
        foreach (var line in headerBlock.Split("\r\n", StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = line.IndexOf(':');
            if (separator > 0 && string.Equals(line[..separator], name, StringComparison.OrdinalIgnoreCase))
            {
                return line[(separator + 1)..].Trim();
            }
        }
        return "";
    }

    private static async Task WriteServerWebSocketFrameAsync(
        NetworkStream stream, byte opcode, byte[] payload, CancellationToken ct)
    {
        var header = new List<byte> { (byte)(0x80 | opcode) };
        if (payload.Length < 126)
        {
            header.Add((byte)payload.Length);
        }
        else if (payload.Length <= ushort.MaxValue)
        {
            header.Add(126);
            header.Add((byte)(payload.Length >> 8));
            header.Add((byte)payload.Length);
        }
        else
        {
            throw new InvalidOperationException("test websocket payload is too large");
        }
        await stream.WriteAsync(header.ToArray(), ct);
        await stream.WriteAsync(payload, ct);
    }
}
