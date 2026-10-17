using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Text;
using Specus.Server.WebSockets;

namespace Specus.IntegrationTests;

public sealed class ConnectionEventDeliveryTests
{
    [Fact]
    public async Task OnePhysicalWriterPreservesFifoWhileTheFirstFrameIsBlocked()
    {
        using var socket = new ControlledSocket(block: true);
        var errors = new ConcurrentQueue<Exception>();
        await using var delivery = Create(socket, errors);
        var first = Send(delivery, "first"); await socket.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        var second = Send(delivery, "second");
        Assert.False(second.IsCompleted); Assert.Equal(1, socket.MaximumConcurrentWrites);
        socket.Release(); await Task.WhenAll(first, second).WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(new[] { "first", "second" }, socket.Frames.ToArray());
        Assert.Equal(1, socket.MaximumConcurrentWrites); Assert.Empty(errors);
    }

    [Fact]
    public async Task QueueOverflowAbortsOnlyThisWriterAndJoinsEveryPendingDelivery()
    {
        using var socket = new ControlledSocket(block: true);
        var errors = new ConcurrentQueue<Exception>(); var removed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var delivery = Create(socket, errors, removed);
        var pending = new List<Task> { Send(delivery, "blocked") };
        await socket.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        for (var i = 0; i < ConnectionEventDelivery.Capacity; i++) pending.Add(Send(delivery, "queued-" + i));
        pending.Add(Send(delivery, "overflow"));
        await Task.WhenAll(pending).WaitAsync(TimeSpan.FromSeconds(10));
        await removed.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(WebSocketState.Aborted, socket.State); Assert.Empty(socket.Frames); Assert.Empty(errors);
        Assert.Equal(0, socket.ActiveWrites);
        // A separate healthy subscriber is not poisoned by this one's overflow.
        using var healthy = new ControlledSocket();
        await using var other = Create(healthy, errors);
        await Send(other, "healthy"); Assert.Equal("healthy", Assert.Single(healthy.Frames));
    }

    [Fact]
    public async Task RealSendBudgetCancelsTheStalledFrameAndJoinsTheOriginalWriter()
    {
        using var socket = new ControlledSocket(block: true);
        var errors = new ConcurrentQueue<Exception>(); var removed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var delivery = Create(socket, errors, removed);
        await Send(delivery, "stalled").WaitAsync(TimeSpan.FromSeconds(10));
        await removed.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(WebSocketState.Aborted, socket.State); Assert.Equal(0, socket.ActiveWrites);
        Assert.Empty(socket.Frames); Assert.Empty(errors);
    }

    [Fact]
    public async Task PendingEventRechecksAuthorityAfterActivationWithoutSendingRevokedData()
    {
        using var socket = new ControlledSocket();
        var state = (int)ConnectionEventAccess.Allowed;
        var removed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var errors = new ConcurrentQueue<Exception>();
        await using var delivery = new ConnectionEventDelivery((_, _) => Task.FromResult((ConnectionEventAccess)Volatile.Read(ref state)),
            () => removed.TrySetResult(), errors.Enqueue);
        delivery.Bind(socket);
        var pending = Send(delivery, "must-not-leak");
        Assert.Empty(socket.Frames);
        Volatile.Write(ref state, (int)ConnectionEventAccess.Revoked);
        Assert.True(delivery.Activate());
        await pending.WaitAsync(TimeSpan.FromSeconds(10)); await removed.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Empty(socket.Frames); Assert.Equal(WebSocketCloseStatus.PolicyViolation, socket.CloseStatus);
        Assert.Equal(ManagementWebSocketIdentity.Revoked, socket.CloseStatusDescription); Assert.Empty(errors);
    }

    [Fact]
    public async Task FilteredEventDoesNotCloseTheConnectionOrBlockTheNextAuthorizedEvent()
    {
        using var socket = new ControlledSocket(); var errors = new ConcurrentQueue<Exception>();
        await using var delivery = new ConnectionEventDelivery((item, _) => Task.FromResult(item.Connection.ClientName == "filtered"
            ? ConnectionEventAccess.Filtered : ConnectionEventAccess.Allowed), () => { }, errors.Enqueue);
        delivery.Bind(socket); Assert.True(delivery.Activate());
        await Send(delivery, "filtered"); await Send(delivery, "allowed");
        Assert.Equal("allowed", Assert.Single(socket.Frames)); Assert.Equal(WebSocketState.Open, socket.State); Assert.Empty(errors);
    }

    [Fact]
    public async Task TimedOutPendingUpgradeCannotActivateAndRequestsResyncInsteadOfLogout()
    {
        var errors = new ConcurrentQueue<Exception>(); var removed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var delivery = new ConnectionEventDelivery((_, _) => Task.FromResult(ConnectionEventAccess.Allowed),
            () => removed.TrySetResult(), errors.Enqueue);
        await Send(delivery, "never-activated").WaitAsync(TimeSpan.FromSeconds(10));
        await removed.Task.WaitAsync(TimeSpan.FromSeconds(10));
        using var socket = new ControlledSocket(); delivery.Bind(socket);
        Assert.False(delivery.Activate());
        await delivery.CloseAsync(WebSocketCloseStatus.NormalClosure, "bye");
        Assert.Equal(WebSocketCloseStatus.EndpointUnavailable, socket.CloseStatus);
        Assert.Contains("resync", socket.CloseStatusDescription!, StringComparison.Ordinal);
        Assert.Empty(socket.Frames); Assert.Empty(errors);
    }

    [Fact]
    public async Task PendingUpgradeTimeoutAlsoAbortsItsUnderlyingHttpRequest()
    {
        var aborted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var errors = new ConcurrentQueue<Exception>();
        await using var delivery = new ConnectionEventDelivery((_, _) => Task.FromResult(ConnectionEventAccess.Allowed),
            () => { }, errors.Enqueue, () => aborted.TrySetResult());
        await Send(delivery, "pending-request").WaitAsync(TimeSpan.FromSeconds(10));
        await aborted.Task.WaitAsync(TimeSpan.FromSeconds(10)); Assert.Empty(errors);
    }

    [Fact]
    public async Task OversizedEventCannotConsumeAnUnboundedQueueAllocation()
    {
        using var socket = new ControlledSocket(); var errors = new ConcurrentQueue<Exception>();
        await using var delivery = Create(socket, errors);
        await delivery.SendAsync(ConnectionEventSubscriptionTests.Event("oversized"), new byte[ConnectionEventDelivery.MaximumPayloadBytes + 1]);
        Assert.Equal(WebSocketState.Aborted, socket.State); Assert.Empty(socket.Frames); Assert.Empty(errors);
    }

    private static ConnectionEventDelivery Create(ControlledSocket socket, ConcurrentQueue<Exception> errors, TaskCompletionSource? removed = null)
    {
        var delivery = new ConnectionEventDelivery((_, _) => Task.FromResult(ConnectionEventAccess.Allowed),
            () => removed?.TrySetResult(), errors.Enqueue);
        delivery.Bind(socket); Assert.True(delivery.Activate()); return delivery;
    }
    private static Task Send(ConnectionEventDelivery delivery, string marker) =>
        delivery.SendAsync(ConnectionEventSubscriptionTests.Event(marker), Encoding.UTF8.GetBytes(marker));

    private sealed class ControlledSocket : WebSocket
    {
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _state = (int)WebSocketState.Open;
        private int _active;
        private int _maximum;
        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal ConcurrentQueue<string> Frames { get; } = new();
        internal int ActiveWrites => Volatile.Read(ref _active);
        internal int MaximumConcurrentWrites => Volatile.Read(ref _maximum);
        internal ControlledSocket(bool block = false) { if (!block) Release(); }
        internal void Release() => _release.TrySetResult();
        public override WebSocketState State => (WebSocketState)Volatile.Read(ref _state);
        public override WebSocketCloseStatus? CloseStatus => _close;
        private WebSocketCloseStatus? _close;
        private string? _description;
        public override string? CloseStatusDescription => _description;
        public override string? SubProtocol => null;
        public override void Abort() { Volatile.Write(ref _state, (int)WebSocketState.Aborted); Release(); }
        public override void Dispose() => Volatile.Write(ref _state, (int)WebSocketState.Closed);
        public override Task CloseAsync(WebSocketCloseStatus status, string? description, CancellationToken ct) => CloseOutputAsync(status, description, ct);
        public override Task CloseOutputAsync(WebSocketCloseStatus status, string? description, CancellationToken ct)
        {
            Assert.Equal(0, ActiveWrites); _close = status; _description = description;
            Volatile.Write(ref _state, (int)WebSocketState.CloseSent); return Task.CompletedTask;
        }
        public override async Task SendAsync(ArraySegment<byte> buffer, WebSocketMessageType type, bool end, CancellationToken ct)
        {
            var active = Interlocked.Increment(ref _active);
            var maximum = Volatile.Read(ref _maximum);
            while (active > maximum)
            {
                var observed = Interlocked.CompareExchange(ref _maximum, active, maximum);
                if (observed == maximum) break;
                maximum = observed;
            }
            Entered.TrySetResult();
            try
            {
                await _release.Task.WaitAsync(ct); ct.ThrowIfCancellationRequested();
                Frames.Enqueue(Encoding.UTF8.GetString(buffer));
            }
            finally { Interlocked.Decrement(ref _active); }
        }
        public override Task<WebSocketReceiveResult> ReceiveAsync(ArraySegment<byte> buffer, CancellationToken ct) => throw new NotSupportedException();
    }
}
