using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging.Abstractions;
using Specus.Client.Control;
using Specus.Client.Nat;
using Specus.Protocol;
using Specus.Protocol.Codec;
using Specus.Protocol.Packets;

namespace Specus.Client.Tests;

public sealed class LocalSpecusChannelTests
{
    [Fact]
    public async Task LocalEofKeepsRemoteToLocalDirectionUntilRemoteFin()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var (local, peer) = await ConnectedPairAsync(timeout.Token);
        using (peer)
        using (local)
        await using (var transport = new MemoryStream())
        await using (var writer = new FrameWriter(transport))
        {
            var closed = 0;
            await using var channel = new LocalSpecusChannel(
                17, "local-first", 7017, local, writer,
                NullLogger.Instance, _ => Interlocked.Increment(ref closed));
            var pump = channel.PumpAsync(timeout.Token);
            var peerStream = peer.GetStream();

            peer.Client.Shutdown(SocketShutdown.Send);

            Assert.Equal(LocalSpecusPumpResult.LocalFin, await pump);
            Assert.True(channel.LocalFinished);
            Assert.False(channel.RemoteFinished);
            Assert.False(channel.IsClosed);
            Assert.Equal(0, Volatile.Read(ref closed));

            var response = "still-open"u8.ToArray();
            Assert.Equal(LocalSpecusWriteResult.Written,
                await channel.WriteAsync(response, timeout.Token));
            var received = new byte[response.Length];
            await peerStream.ReadExactlyAsync(received, timeout.Token);
            Assert.Equal(response, received);

            Assert.Equal(LocalSpecusRemoteFinResult.Completed, channel.FinishRemoteDirection());
            Assert.True(channel.RemoteFinished);
            Assert.True(channel.IsClosed);
            Assert.Equal(1, Volatile.Read(ref closed));
        }
    }

    [Fact]
    public async Task RemoteFinKeepsLocalToRemoteDirectionUntilLocalEof()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var (local, peer) = await ConnectedPairAsync(timeout.Token);
        using (peer)
        using (local)
        await using (var transport = new MemoryStream())
        await using (var writer = new FrameWriter(transport))
        {
            var closed = 0;
            await using var channel = new LocalSpecusChannel(
                18, "remote-first", 7018, local, writer,
                NullLogger.Instance, _ => Interlocked.Increment(ref closed));
            var pump = channel.PumpAsync(timeout.Token);
            var peerStream = peer.GetStream();

            Assert.Equal(LocalSpecusRemoteFinResult.Accepted, channel.FinishRemoteDirection());
            var eofProbe = new byte[1];
            Assert.Equal(0, await peerStream.ReadAsync(eofProbe, timeout.Token));
            Assert.False(pump.IsCompleted);

            var request = "after-fin"u8.ToArray();
            await peerStream.WriteAsync(request, timeout.Token);
            peer.Client.Shutdown(SocketShutdown.Send);

            Assert.Equal(LocalSpecusPumpResult.LocalFin, await pump);
            Assert.True(channel.LocalFinished);
            Assert.True(channel.RemoteFinished);
            Assert.True(channel.IsClosed);
            Assert.Equal(1, Volatile.Read(ref closed));

            var packet = Assert.IsType<NatMessagePacket>(PacketCodec.DecodeExact(transport.ToArray()));
            Assert.Equal(NatMessageType.Data, packet.NatMessageType);
            Assert.Equal(18U, packet.StreamId);
            Assert.Equal(request, packet.Data);
        }
    }

    [Fact]
    public async Task ResetImmediatelyClosesBothDirectionsAndIsIdempotent()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var (local, peer) = await ConnectedPairAsync(timeout.Token);
        using (peer)
        using (local)
        await using (var transport = new MemoryStream())
        await using (var writer = new FrameWriter(transport))
        {
            var closed = 0;
            await using var channel = new LocalSpecusChannel(
                19, "reset", 7019, local, writer,
                NullLogger.Instance, _ => Interlocked.Increment(ref closed));
            var pump = channel.PumpAsync(timeout.Token);

            channel.Reset();
            channel.Reset();

            Assert.Equal(LocalSpecusPumpResult.Canceled, await pump);
            Assert.True(channel.IsClosed);
            Assert.Equal(1, Volatile.Read(ref closed));
            Assert.Equal(LocalSpecusWriteResult.Reset,
                await channel.WriteAsync([1], timeout.Token));
        }
    }

    private static async Task<(TcpClient Local, TcpClient Peer)> ConnectedPairAsync(
        CancellationToken cancellationToken)
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var endpoint = (IPEndPoint)listener.LocalEndpoint;
        var local = new TcpClient { NoDelay = true };
        var accepted = listener.AcceptTcpClientAsync(cancellationToken);
        await local.ConnectAsync(endpoint.Address, endpoint.Port, cancellationToken);
        var peer = await accepted;
        peer.NoDelay = true;
        return (local, peer);
    }
}
