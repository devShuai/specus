using System.IO.Pipelines;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Cryptography;
using System.Text;
using System.Net.WebSockets;
using Microsoft.Extensions.Logging.Abstractions;
using Specus.Client.Configuration;
using Specus.Client.Control;
using Specus.Client.DirectHttp;
using Specus.Client.Nat;
using Specus.Protocol;
using Specus.Protocol.Codec;
using Specus.Protocol.Flow;
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
    public async Task HandleOpenAsync_ForInvalidTcpMapping_SendsStreamReset(Dictionary<string, object?> metadata)
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

        var reset = Assert.IsType<NatMessagePacket>(PacketCodec.DecodeExact(stream.ToArray()));
        Assert.Equal(NatMessageType.Rst, reset.NatMessageType);
        Assert.Equal(1U, reset.StreamId);
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

    [Fact]
    public void TryBuildWebSocketTarget_PreservesEncodedPathAndRawQuery()
    {
        var ok = NatClientHandler.TryBuildWebSocketTarget(
            "http://example.test/base%2Froot",
            "/%E4%BD%A0%2F%252F",
            "next=%2Fraw",
            out var target,
            out var error);

        Assert.True(ok, error);
        Assert.Equal("ws://example.test/base%2Froot/%E4%BD%A0%2F%252F?next=%2Fraw", target.OriginalString);
    }

    [Theory]
    [InlineData("/../admin")]
    [InlineData("/%2e%2e/admin")]
    public void TryBuildWebSocketTarget_RejectsDotSegments(string relativePath)
    {
        var ok = NatClientHandler.TryBuildWebSocketTarget(
            "http://example.test/base", relativePath, null, out _, out var error);

        Assert.False(ok);
        Assert.Equal("HTTP 转发路径越界", error);
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
    public void RawWebSocketTransportTrustsOperatorConfiguredLanCertificates()
    {
        Assert.True(RawWebSocketConnection.AcceptLocalCertificate(
            sender: new object(),
            certificate: null,
            chain: null,
            sslPolicyErrors: SslPolicyErrors.RemoteCertificateChainErrors));
    }

    [Fact]
    public async Task RawWebSocketTransportRejectsInvalidHandshakeAccept()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var serverTask = RunInvalidAcceptWebSocketServerAsync(listener, cts.Token);

        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await RawWebSocketConnection.ConnectAsync(
                new Uri($"ws://127.0.0.1:{port}/invalid"), [], cts.Token));
        await serverTask;
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
    public async Task WebSocketCloseStopsWaitingForSendCreditAndReleasesChannel()
    {
        using var wsListener = new TcpListener(IPAddress.Loopback, 0);
        wsListener.Start();
        var wsPort = ((IPEndPoint)wsListener.LocalEndpoint).Port;
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var wsTask = RunClosingWebSocketServerAsync(wsListener, cts.Token);

        await using var socket = await NatClientHandler.ConnectLocalWebSocketAsync(
            new Uri($"ws://127.0.0.1:{wsPort}/close"), [], cts.Token);

        var sendWindow = new StreamSendWindow();
        Assert.True(await sendWindow.ConsumeAsync(
            checked((int)StreamSendWindow.InitialBytes), cts.Token));
        await using var control = new MemoryStream();
        await using var writer = new FrameWriter(control);
        var closed = 0;
        var channel = new WebSocketSpecusChannel(
            17,
            "close-timeout",
            socket,
            writer,
            NullLogger<WebSocketSpecusChannel>.Instance,
            _ => Interlocked.Increment(ref closed),
            sendWindow,
            TimeSpan.FromMilliseconds(50));

        var completion = await channel.PumpAsync(cts.Token);

        Assert.Equal(WebSocketPumpResult.CloseCreditTimedOut, completion);
        Assert.Equal(1, Volatile.Read(ref closed));
        Assert.Equal(0, control.Length);
        await wsTask;
    }

    [Fact]
    public async Task TunnelFramesKeepFinContinuationPingPongAndCloseOnLocalWire()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var serverTask = RunCapturingWebSocketServerAsync(listener, frameCount: 5, cts.Token);

        await using var socket = await NatClientHandler.ConnectLocalWebSocketAsync(
            new Uri($"ws://127.0.0.1:{port}/hold"), [], cts.Token);
        await using var control = new MemoryStream();
        await using var writer = new FrameWriter(control);
        await using var channel = new WebSocketSpecusChannel(
            18, "control-frame", socket, writer,
            NullLogger<WebSocketSpecusChannel>.Instance, static _ => { });
        await channel.WriteAsync(new WebSocketSpecusFrame(
            WebSocketSpecusFrame.OpcodeText, false, 0, 0, "hel"u8.ToArray()).Encode(), cts.Token);
        await channel.WriteAsync(new WebSocketSpecusFrame(
            WebSocketSpecusFrame.OpcodePing, true, 0, 0, "ping"u8.ToArray()).Encode(), cts.Token);
        await channel.WriteAsync(new WebSocketSpecusFrame(
            WebSocketSpecusFrame.OpcodeContinuation, true, 0, 0, "lo"u8.ToArray()).Encode(), cts.Token);
        await channel.WriteAsync(new WebSocketSpecusFrame(
            WebSocketSpecusFrame.OpcodePong, true, 0, 0, "pong"u8.ToArray()).Encode(), cts.Token);
        await channel.WriteAsync(new WebSocketSpecusFrame(
            WebSocketSpecusFrame.OpcodeClose, true, 0, 1000, "done"u8.ToArray()).Encode(), cts.Token);

        var frames = await serverTask;
        Assert.Collection(frames,
            frame =>
            {
                Assert.Equal(WebSocketSpecusFrame.OpcodeText, frame.Opcode);
                Assert.False(frame.FinalFragment);
                Assert.Equal(0, frame.Rsv);
                Assert.Equal("hel", Encoding.UTF8.GetString(frame.Payload));
            },
            frame =>
            {
                Assert.Equal(WebSocketSpecusFrame.OpcodePing, frame.Opcode);
                Assert.Equal("ping", Encoding.UTF8.GetString(frame.Payload));
            },
            frame =>
            {
                Assert.Equal(WebSocketSpecusFrame.OpcodeContinuation, frame.Opcode);
                Assert.True(frame.FinalFragment);
                Assert.Equal("lo", Encoding.UTF8.GetString(frame.Payload));
            },
            frame =>
            {
                Assert.Equal(WebSocketSpecusFrame.OpcodePong, frame.Opcode);
                Assert.Equal("pong", Encoding.UTF8.GetString(frame.Payload));
            },
            frame =>
            {
                Assert.Equal(WebSocketSpecusFrame.OpcodeClose, frame.Opcode);
                Assert.Equal(new byte[] { 0x03, 0xE8, (byte)'d', (byte)'o', (byte)'n', (byte)'e' },
                    frame.Payload);
            });
        Assert.Equal(0, control.Length);
    }

    [Fact]
    public async Task LocalRawFramesKeepFinContinuationPingPongAndCloseInSws2()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var serverTask = RunRawFrameSequenceServerAsync(listener, cts.Token);

        await using var socket = await NatClientHandler.ConnectLocalWebSocketAsync(
            new Uri($"ws://127.0.0.1:{port}/frames"), [], cts.Token);
        await using var control = new MemoryStream();
        await using var writer = new FrameWriter(control);
        var closed = 0;
        var channel = new WebSocketSpecusChannel(
            19, "raw-frames", socket, writer,
            NullLogger<WebSocketSpecusChannel>.Instance, _ => Interlocked.Increment(ref closed));

        var completion = await channel.PumpAsync(cts.Token);
        Assert.Equal(WebSocketPumpResult.Completed, completion);
        Assert.Equal(1, Volatile.Read(ref closed));
        await serverTask;

        control.Position = 0;
        var reader = PipeReader.Create(control, new StreamPipeReaderOptions(leaveOpen: true));
        var frames = new List<WebSocketSpecusFrame>();
        for (var index = 0; index < 5; index++)
        {
            var packet = Assert.IsType<NatMessagePacket>(await FrameReaderProxy.ReadFrameAsync(
                reader, 32 * 1024 * 1024, cts.Token));
            frames.Add(WebSocketSpecusFrame.Decode(packet.Data!));
        }
        await reader.CompleteAsync();

        Assert.Collection(frames,
            frame =>
            {
                Assert.Equal(WebSocketSpecusFrame.OpcodeText, frame.Opcode);
                Assert.False(frame.FinalFragment);
                Assert.Equal(0, frame.Rsv);
                Assert.Equal("hel", Encoding.UTF8.GetString(frame.Payload));
            },
            frame =>
            {
                Assert.Equal(WebSocketSpecusFrame.OpcodePing, frame.Opcode);
                Assert.Equal("ping", Encoding.UTF8.GetString(frame.Payload));
            },
            frame =>
            {
                Assert.Equal(WebSocketSpecusFrame.OpcodeContinuation, frame.Opcode);
                Assert.True(frame.FinalFragment);
                Assert.Equal("lo", Encoding.UTF8.GetString(frame.Payload));
            },
            frame =>
            {
                Assert.Equal(WebSocketSpecusFrame.OpcodePong, frame.Opcode);
                Assert.Equal("pong", Encoding.UTF8.GetString(frame.Payload));
            },
            frame =>
            {
                Assert.Equal(WebSocketSpecusFrame.OpcodeClose, frame.Opcode);
                Assert.Equal((ushort)1000, frame.CloseCode);
                Assert.Equal("done", Encoding.UTF8.GetString(frame.Payload));
            });
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

    private static async Task RunInvalidAcceptWebSocketServerAsync(
        TcpListener listener, CancellationToken ct)
    {
        using var tcp = await listener.AcceptTcpClientAsync(ct);
        await using var stream = tcp.GetStream();
        await ReadHttpHeaderAsync(stream, ct);
        await stream.WriteAsync(Encoding.ASCII.GetBytes(
            "HTTP/1.1 101 Switching Protocols\r\n" +
            "Upgrade: websocket\r\n" +
            "Connection: Upgrade\r\n" +
            "Sec-WebSocket-Accept: invalid\r\n\r\n"), ct);
        await stream.FlushAsync(ct);
    }

    private static async Task RunClosingWebSocketServerAsync(TcpListener listener, CancellationToken ct)
    {
        using var tcp = await listener.AcceptTcpClientAsync(ct);
        await using var stream = tcp.GetStream();
        var header = await ReadHttpHeaderAsync(stream, ct);
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
        var closeCode = (int)WebSocketCloseStatus.NormalClosure;
        await WriteServerWebSocketFrameAsync(stream, 0x8,
            [(byte)(closeCode >> 8), (byte)(closeCode & 0xff), .. Encoding.UTF8.GetBytes("done")], ct);
        await stream.FlushAsync(ct);
    }

    private static async Task<IReadOnlyList<CapturedWebSocketFrame>> RunCapturingWebSocketServerAsync(
        TcpListener listener, int frameCount, CancellationToken ct)
    {
        using var tcp = await listener.AcceptTcpClientAsync(ct);
        await using var stream = tcp.GetStream();
        var header = await ReadHttpHeaderAsync(stream, ct);
        var key = ExtractHeader(header, "Sec-WebSocket-Key");
        Assert.False(string.IsNullOrWhiteSpace(key));
        var accept = Convert.ToBase64String(
            SHA1.HashData(Encoding.ASCII.GetBytes(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")));
        await stream.WriteAsync(Encoding.ASCII.GetBytes(
            "HTTP/1.1 101 Switching Protocols\r\n" +
            "Upgrade: websocket\r\n" +
            "Connection: Upgrade\r\n" +
            $"Sec-WebSocket-Accept: {accept}\r\n\r\n"), ct);
        await stream.FlushAsync(ct);

        var frames = new List<CapturedWebSocketFrame>(frameCount);
        for (var index = 0; index < frameCount; index++)
        {
            frames.Add(await ReadClientWebSocketFrameAsync(stream, ct));
        }
        return frames;
    }

    private static async Task RunRawFrameSequenceServerAsync(TcpListener listener, CancellationToken ct)
    {
        using var tcp = await listener.AcceptTcpClientAsync(ct);
        await using var stream = tcp.GetStream();
        var header = await ReadHttpHeaderAsync(stream, ct);
        var key = ExtractHeader(header, "Sec-WebSocket-Key");
        Assert.False(string.IsNullOrWhiteSpace(key));
        var accept = Convert.ToBase64String(
            SHA1.HashData(Encoding.ASCII.GetBytes(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")));
        await stream.WriteAsync(Encoding.ASCII.GetBytes(
            "HTTP/1.1 101 Switching Protocols\r\n" +
            "Upgrade: websocket\r\n" +
            "Connection: Upgrade\r\n" +
            $"Sec-WebSocket-Accept: {accept}\r\n\r\n"), ct);
        await WriteServerWebSocketFrameAsync(stream, WebSocketSpecusFrame.OpcodeText,
            "hel"u8.ToArray(), ct, finalFragment: false, rsv: 0);
        await WriteServerWebSocketFrameAsync(stream, WebSocketSpecusFrame.OpcodePing,
            "ping"u8.ToArray(), ct);
        await WriteServerWebSocketFrameAsync(stream, WebSocketSpecusFrame.OpcodeContinuation,
            "lo"u8.ToArray(), ct);
        await WriteServerWebSocketFrameAsync(stream, WebSocketSpecusFrame.OpcodePong,
            "pong"u8.ToArray(), ct);
        await WriteServerWebSocketFrameAsync(stream, WebSocketSpecusFrame.OpcodeClose,
            [0x03, 0xE8, (byte)'d', (byte)'o', (byte)'n', (byte)'e'], ct);
        await stream.FlushAsync(ct);

        var closeReply = await ReadClientWebSocketFrameAsync(stream, ct);
        Assert.Equal(WebSocketSpecusFrame.OpcodeClose, closeReply.Opcode);
        Assert.True(closeReply.FinalFragment);
        Assert.Equal(0, closeReply.Rsv);
        Assert.Equal(new byte[] { 0x03, 0xE8, (byte)'d', (byte)'o', (byte)'n', (byte)'e' },
            closeReply.Payload);
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
        NetworkStream stream, byte opcode, byte[] payload, CancellationToken ct,
        bool finalFragment = true, byte rsv = 0)
    {
        var header = new List<byte>
        {
            (byte)((finalFragment ? 0x80 : 0) | ((rsv & 7) << 4) | opcode),
        };
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

    private static async Task<CapturedWebSocketFrame> ReadClientWebSocketFrameAsync(
        NetworkStream stream, CancellationToken ct)
    {
        var header = new byte[2];
        await ReadExactlyAsync(stream, header, ct);
        var masked = (header[1] & 0x80) != 0;
        Assert.True(masked);

        ulong payloadLength = (uint)(header[1] & 0x7f);
        if (payloadLength == 126)
        {
            var extended = new byte[2];
            await ReadExactlyAsync(stream, extended, ct);
            payloadLength = ((ulong)extended[0] << 8) | extended[1];
        }
        else if (payloadLength == 127)
        {
            var extended = new byte[8];
            await ReadExactlyAsync(stream, extended, ct);
            payloadLength = 0;
            foreach (var current in extended)
            {
                payloadLength = (payloadLength << 8) | current;
            }
        }
        Assert.True(payloadLength <= int.MaxValue);

        var mask = new byte[4];
        await ReadExactlyAsync(stream, mask, ct);
        var payload = new byte[(int)payloadLength];
        await ReadExactlyAsync(stream, payload, ct);
        for (var index = 0; index < payload.Length; index++)
        {
            payload[index] ^= mask[index & 3];
        }
        return new CapturedWebSocketFrame(
            (byte)(header[0] & 0x0f),
            (header[0] & 0x80) != 0,
            (byte)((header[0] >> 4) & 7),
            payload);
    }

    private static async Task ReadExactlyAsync(
        NetworkStream stream, Memory<byte> destination, CancellationToken ct)
    {
        var offset = 0;
        while (offset < destination.Length)
        {
            var read = await stream.ReadAsync(destination[offset..], ct);
            if (read == 0)
            {
                throw new EndOfStreamException("truncated test WebSocket frame");
            }
            offset += read;
        }
    }

    private sealed record CapturedWebSocketFrame(
        byte Opcode,
        bool FinalFragment,
        byte Rsv,
        byte[] Payload);
}
