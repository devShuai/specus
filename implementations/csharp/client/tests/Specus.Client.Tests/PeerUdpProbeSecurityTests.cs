using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Specus.Client.Configuration;
using Specus.Client.PeerMesh;

namespace Specus.Client.Tests;

public sealed class PeerUdpProbeSecurityTests
{
    [Fact]
    public void CodecDecodesValidProbeAndRejectsMalformedWrongMagicAndOversizedPackets()
    {
        var valid = JsonSerializer.SerializeToUtf8Bytes(new PeerMeshClient.PeerUdpProbe(
            PeerUdpProbeCodec.Magic,
            "check",
            7,
            11,
            22,
            "abc",
            "token",
            123));
        var malformed = Encoding.UTF8.GetBytes(
            "{\"magic\":\"specus-peer-mesh\",\"toClientId\":oops}");
        var wrongMagic = Encoding.UTF8.GetBytes("{\"magic\":\"not-peer-mesh\"}");
        var oversized = new byte[PeerUdpProbeCodec.MaxPacketBytes + 1];
        oversized[0] = (byte)'{';
        oversized[^1] = (byte)'}';

        var decoded = PeerUdpProbeCodec.Decode(valid);

        Assert.NotNull(decoded);
        Assert.Equal("check", decoded!.Type);
        Assert.Equal(7, decoded.SessionId);
        Assert.Null(PeerUdpProbeCodec.Decode(malformed));
        Assert.Null(PeerUdpProbeCodec.Decode(wrongMagic));
        Assert.Null(PeerUdpProbeCodec.Decode(oversized));
    }

    [Fact]
    public void RateLimiterLimitsEachSourceAndResetsAfterWindow()
    {
        var limiter = new PeerUdpProbeRateLimiter();
        var source = IPAddress.Parse("192.0.2.10");

        for (var index = 0; index < PeerUdpProbeRateLimiter.SourcePacketsPerWindow; index++)
        {
            Assert.True(limiter.TryAcquire(source, 10_000));
        }
        Assert.False(limiter.TryAcquire(source, 10_000));
        Assert.True(limiter.TryAcquire(source, 11_000));
    }

    [Fact]
    public void RateLimiterLimitsAggregateProbeRate()
    {
        var limiter = new PeerUdpProbeRateLimiter();
        for (var sourceIndex = 0; sourceIndex < 20; sourceIndex++)
        {
            var source = SourceAddress(sourceIndex);
            for (var packetIndex = 0; packetIndex < 100; packetIndex++)
            {
                Assert.True(limiter.TryAcquire(source, 20_000));
            }
        }

        Assert.False(limiter.TryAcquire(SourceAddress(21), 20_000));
    }

    [Fact]
    public void RateLimiterBoundsAndExpiresSourceTable()
    {
        var limiter = new PeerUdpProbeRateLimiter();
        for (var index = 0; index <= PeerUdpProbeRateLimiter.MaxSources; index++)
        {
            var now = (index / PeerUdpProbeRateLimiter.GlobalPacketsPerWindow) * 1_000L;
            Assert.True(limiter.TryAcquire(SourceAddress(index), now));
        }
        Assert.Equal(PeerUdpProbeRateLimiter.MaxSources, limiter.SourceCount);

        limiter.Cleanup(PeerUdpProbeRateLimiter.SourceTtlMilliseconds + 3_000);

        Assert.Equal(0, limiter.SourceCount);
    }

    [Fact]
    public async Task ReceiveLoopDropsOneFaultingDatagramAndProcessesTheNext()
    {
        await using var client = new PeerMeshClient(
            new SpecusClientConfig(),
            NullLogger<PeerMeshClient>.Instance);
        using var receiver = PeerMeshClient.CreatePeerUdpClient();
        using var sender = new UdpClient(receiver.Client.AddressFamily);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var firstPacket = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var secondPacket = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var handled = 0;

        Task HandlePacketAsync(byte[] payload, IPEndPoint _)
        {
            if (Interlocked.Increment(ref handled) == 1)
            {
                firstPacket.TrySetResult(true);
                throw new JsonException("malformed probe");
            }
            Assert.Equal("second"u8.ToArray(), payload);
            secondPacket.TrySetResult(true);
            return Task.CompletedTask;
        }

        var receiveTask = client.ReceiveLoopAsync(receiver, cancellation.Token, HandlePacketAsync);
        var local = Assert.IsType<IPEndPoint>(receiver.Client.LocalEndPoint);
        var destination = new IPEndPoint(
            local.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Loopback : IPAddress.Loopback,
            local.Port);

        await sender.SendAsync("{malformed-json"u8.ToArray(), destination);
        await firstPacket.Task.WaitAsync(TimeSpan.FromSeconds(3));
        await sender.SendAsync("second"u8.ToArray(), destination);
        await secondPacket.Task.WaitAsync(TimeSpan.FromSeconds(3));

        Assert.False(receiveTask.IsCompleted);
        await cancellation.CancelAsync();
        await receiveTask.WaitAsync(TimeSpan.FromSeconds(3));
    }

    [Fact]
    public async Task ReceiveSupervisorTerminatesSessionOnUnexpectedFaultOrCleanExit()
    {
        var fault = new SocketException((int)SocketError.NetworkDown);
        Exception? observedFault = null;
        var faultCallbacks = 0;
        await PeerMeshClient.SuperviseReceiveTaskAsync(
            Task.FromException(fault),
            CancellationToken.None,
            failure =>
            {
                observedFault = failure;
                Interlocked.Increment(ref faultCallbacks);
                return Task.CompletedTask;
            });

        Exception? observedCleanExit = fault;
        var cleanCallbacks = 0;
        await PeerMeshClient.SuperviseReceiveTaskAsync(
            Task.CompletedTask,
            CancellationToken.None,
            failure =>
            {
                observedCleanExit = failure;
                Interlocked.Increment(ref cleanCallbacks);
                return Task.CompletedTask;
            });

        Assert.Same(fault, observedFault);
        Assert.Equal(1, faultCallbacks);
        Assert.Null(observedCleanExit);
        Assert.Equal(1, cleanCallbacks);
    }

    [Fact]
    public async Task ReceiveSupervisorDoesNotTerminateAnExpectedCanceledSession()
    {
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();
        var callbacks = 0;

        await PeerMeshClient.SuperviseReceiveTaskAsync(
            Task.FromCanceled(cancellation.Token),
            cancellation.Token,
            _ =>
            {
                Interlocked.Increment(ref callbacks);
                return Task.CompletedTask;
            });

        Assert.Equal(0, callbacks);
    }

    [Fact]
    public async Task UnexpectedReceiveFailureSafelyStopsItsOwnPeerMeshSession()
    {
        await using var client = new PeerMeshClient(
            new SpecusClientConfig(),
            NullLogger<PeerMeshClient>.Instance);
        using var cancellation = new CancellationTokenSource();
        using var udp = PeerMeshClient.CreatePeerUdpClient();
        var loop = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var maintenance = Task.Delay(Timeout.InfiniteTimeSpan, cancellation.Token);
        var supervisor = PeerMeshClient.SuperviseReceiveTaskAsync(
            loop.Task,
            cancellation.Token,
            client.HandleUnexpectedReceiveExitAsync);
        SetField(client, "_cts", cancellation);
        SetField(client, "_udp", udp);
        SetField(client, "_receiveTask", supervisor);
        SetField(client, "_maintenanceTask", maintenance);

        loop.TrySetException(new SocketException((int)SocketError.NetworkDown));
        await supervisor.WaitAsync(TimeSpan.FromSeconds(3));

        Assert.True(cancellation.IsCancellationRequested);
        Assert.True(maintenance.IsCompleted);
        Assert.Null(client.ReceiveTask);
        Assert.Null(client.MaintenanceTask);
    }

    [Fact]
    public async Task DisposeWaitsForStoredReceiveAndMaintenanceTasks()
    {
        var client = new PeerMeshClient(
            new SpecusClientConfig(),
            NullLogger<PeerMeshClient>.Instance);
        using var cancellation = new CancellationTokenSource();
        var receive = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var maintenance = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        SetField(client, "_cts", cancellation);
        SetField(client, "_receiveTask", receive.Task);
        SetField(client, "_maintenanceTask", maintenance.Task);

        var dispose = client.DisposeAsync().AsTask();
        Assert.True(cancellation.IsCancellationRequested);
        Assert.False(dispose.IsCompleted);

        receive.TrySetResult(true);
        await Task.Yield();
        Assert.False(dispose.IsCompleted);
        maintenance.TrySetResult(true);
        await dispose.WaitAsync(TimeSpan.FromSeconds(3));
    }

    private static IPAddress SourceAddress(int value)
        => new([10, (byte)(value >> 16), (byte)(value >> 8), (byte)value]);

    private static void SetField(object target, string name, object value)
        => target.GetType()
            .GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!
            .SetValue(target, value);
}
