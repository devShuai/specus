using System.Net.WebSockets;
using System.Threading.Channels;
using Specus.Server.Management;

namespace Specus.Server.WebSockets;

internal enum ConnectionEventAccess { Allowed, Filtered, Revoked }

// Reserve before HTTP upgrade, activate only after the second identity check. Each
// subscriber has one writer and bounded memory/waiting; slow peers cannot block others.
internal sealed class ConnectionEventDelivery : IAsyncDisposable
{
    internal const int Capacity = 128;
    internal const int MaximumPayloadBytes = 64 * 1024;
    internal static readonly TimeSpan SendBudget = TimeSpan.FromSeconds(2);
    private sealed record Delivery(ConnectionEvent Event, byte[] Payload)
    {
        internal TaskCompletionSource Finished { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }
    private sealed record CloseCause(WebSocketCloseStatus Status, string Reason);

    private readonly Channel<Delivery> _queue = Channel.CreateBounded<Delivery>(new BoundedChannelOptions(Capacity)
        { SingleReader = true, FullMode = BoundedChannelFullMode.Wait, AllowSynchronousContinuations = false });
    private readonly TaskCompletionSource<WebSocket> _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly CancellationTokenSource _stop = new();
    private readonly CancellationTokenSource _receiveStop = new();
    private readonly CancellationToken _token;
    private readonly CancellationToken _receiveToken;
    private readonly SemaphoreSlim _closeGate = new(1, 1);
    private readonly Func<ConnectionEvent, CancellationToken, Task<ConnectionEventAccess>> _authorize;
    private readonly Action _removed;
    private readonly Action<Exception> _failed;
    private readonly Action? _abortPending;
    private readonly Task _pump;
    private WebSocket? _socket;
    private CloseCause? _cause;
    internal CancellationToken Lifetime => _token;
    internal CancellationToken ReceiveLifetime => _receiveToken;

    internal ConnectionEventDelivery(Func<ConnectionEvent, CancellationToken, Task<ConnectionEventAccess>> authorize,
        Action removed, Action<Exception> failed, Action? abortPending = null)
    {
        _authorize = authorize; _removed = removed; _failed = failed;
        _abortPending = abortPending;
        _token = _stop.Token;
        _receiveToken = _receiveStop.Token;
        _pump = PumpAsync();
    }

    internal void Bind(WebSocket socket) => Volatile.Write(ref _socket, socket);
    internal bool Activate() => Volatile.Read(ref _cause) is null && _ready.TrySetResult(_socket
        ?? throw new InvalidOperationException("event socket is not bound"));

    internal async Task SendAsync(ConnectionEvent connectionEvent, byte[] payload)
    {
        if (Volatile.Read(ref _cause) is not null) return;
        if (payload.Length > MaximumPayloadBytes)
        {
            Stop(new CloseCause(WebSocketCloseStatus.EndpointUnavailable, "connection event exceeds delivery limit; resync required"), abort: true);
            return;
        }
        var delivery = new Delivery(connectionEvent, payload);
        if (!_queue.Writer.TryWrite(delivery))
        {
            Stop(new CloseCause(WebSocketCloseStatus.EndpointUnavailable, "connection events require resync"), abort: true);
            return;
        }
        try { await delivery.Finished.Task.WaitAsync(SendBudget, _token).ConfigureAwait(false); }
        catch (TimeoutException)
        { Stop(new CloseCause(WebSocketCloseStatus.EndpointUnavailable, "connection event delivery timed out; resync required"), abort: true); }
        catch (OperationCanceledException) when (_token.IsCancellationRequested) { }
    }

    private async Task PumpAsync()
    {
        try
        {
            await foreach (var delivery in _queue.Reader.ReadAllAsync(_token).ConfigureAwait(false))
            {
                try
                {
                    var socket = await _ready.Task.WaitAsync(_token).ConfigureAwait(false);
                    var access = await _authorize(delivery.Event, _token).ConfigureAwait(false);
                    if (access == ConnectionEventAccess.Revoked)
                    {
                        Stop(new CloseCause(WebSocketCloseStatus.PolicyViolation, ManagementWebSocketIdentity.Revoked), abort: false);
                        await CloseSocketAsync().ConfigureAwait(false);
                        break;
                    }
                    if (access == ConnectionEventAccess.Filtered) continue;
                    _token.ThrowIfCancellationRequested();
                    await socket.SendAsync(delivery.Payload.AsMemory(), WebSocketMessageType.Text, true, _token).ConfigureAwait(false);
                }
                finally { delivery.Finished.TrySetResult(); }
            }
        }
        catch (OperationCanceledException) when (_token.IsCancellationRequested) { }
        catch (Exception exception)
        {
            if (!_token.IsCancellationRequested) _failed(exception);
            Stop(new CloseCause(WebSocketCloseStatus.EndpointUnavailable, "connection events require resync"), abort: true);
        }
        finally
        {
            while (_queue.Reader.TryRead(out var pending)) pending.Finished.TrySetResult();
            _removed();
        }
    }

    private void Stop(CloseCause cause, bool abort)
    {
        var first = Interlocked.CompareExchange(ref _cause, cause, null) is null;
        // A policy close must not be replaced by normal request cleanup.
        if (cause.Status == WebSocketCloseStatus.PolicyViolation) Interlocked.Exchange(ref _cause, cause);
        if (first)
        {
            _queue.Writer.TryComplete();
            _stop.Cancel();
        }
        if (abort)
        {
            if (Volatile.Read(ref _socket) is { } socket) socket.Abort();
            else _abortPending?.Invoke();
        }
    }

    internal async Task CloseAsync(WebSocketCloseStatus status, string reason)
    {
        Stop(new CloseCause(status, reason), abort: false);
        try { await _pump.WaitAsync(SendBudget).ConfigureAwait(false); }
        catch (TimeoutException)
        {
            Volatile.Read(ref _socket)?.Abort();
            // Abort terminates pending WebSocket I/O; always join the original writer.
            await _pump.ConfigureAwait(false);
        }
        await CloseSocketAsync().ConfigureAwait(false);
    }

    private async Task CloseSocketAsync()
    {
        using var timeout = new CancellationTokenSource(SendBudget);
        var acquired = false;
        try
        {
            await _closeGate.WaitAsync(timeout.Token).ConfigureAwait(false); acquired = true;
            var socket = Volatile.Read(ref _socket);
            if (socket?.State is WebSocketState.Open or WebSocketState.CloseReceived)
            {
                var cause = Volatile.Read(ref _cause)!;
                await socket.CloseOutputAsync(cause.Status, cause.Reason, timeout.Token).ConfigureAwait(false);
                // ManagedWebSocket cancels ReceiveAsync by aborting its transport. Allow
                // the policy close frame onto the wire before starting the bounded ACK wait.
                if (socket.State == WebSocketState.CloseSent) _receiveStop.CancelAfter(SendBudget);
            }
        }
        catch (Exception exception) when (exception is WebSocketException or ObjectDisposedException
            or OperationCanceledException or InvalidOperationException)
        { Volatile.Read(ref _socket)?.Abort(); }
        finally { if (acquired) _closeGate.Release(); }
    }

    public async ValueTask DisposeAsync()
    {
        await CloseAsync(WebSocketCloseStatus.NormalClosure, "bye").ConfigureAwait(false);
        _stop.Dispose();
        _receiveStop.Dispose();
    }
}
