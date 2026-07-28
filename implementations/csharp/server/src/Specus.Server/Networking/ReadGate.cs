namespace Specus.Server.Networking;

/// <summary>
/// A single-connection "is the kernel-side read armed" gate. The Java port's equivalent is
/// <c>ChannelBackpressure.setAutoRead</c> — when you flip <c>autoRead</c> off, Netty stops
/// arming the next <c>read</c>, the TCP receive buffer fills up, and the peer observes a
/// clogged socket without dropping any bytes.
///
/// <para>On .NET there is no built-in <c>autoRead</c>, so this class manages the same state
/// explicitly. The contract:
/// <list type="bullet">
/// <item><see cref="Pause"/> flips the gate off; the reader MUST stop arming <c>ReceiveAsync</c>
/// until <see cref="Resume"/> is called.</item>
/// <item><see cref="WaitIfPausedAsync"/> waits on the current pause token. <see cref="Resume"/>
/// flips the gate on and releases every waiter. If resume wins the race before the reader
/// reaches the gate, the reader simply observes the unpaused state and keeps moving.</item>
/// </list></para>
///
/// <para>The gate is intentionally tiny — we want it observable from many call sites (the
/// reader, the dispatcher, the NAT session) without having to thread the state through a
/// channel context.</para>
/// </summary>
public sealed class ReadGate
{
    private readonly CancellationToken _lifetime;
    private readonly object _sync = new();
    private TaskCompletionSource? _resumeSignal;

    /// <summary>
    /// Snapshot of the read state. <c>true</c> means reads are PAUSED — do not arm another
    /// receive until someone resumes. <c>false</c> means armed (default).
    /// </summary>
    private bool _isPaused;

    public ReadGate(CancellationToken lifetime)
    {
        _lifetime = lifetime;
    }

    public bool IsPaused
    {
        get
        {
            lock (_sync)
            {
                return _isPaused;
            }
        }
    }

    /// <summary>Pause reads. Idempotent — calling when already paused is a no-op.</summary>
    public void Pause()
    {
        if (_lifetime.IsCancellationRequested)
        {
            return;
        }

        lock (_sync)
        {
            if (_isPaused)
            {
                return;
            }

            _isPaused = true;
            _resumeSignal = CreateResumeSignal();
        }
    }

    /// <summary>Waits while reads are paused. Returns immediately when the gate is open.</summary>
    public async ValueTask WaitIfPausedAsync(CancellationToken cancellationToken)
    {
        Task? waitTask;
        lock (_sync)
        {
            waitTask = _isPaused ? _resumeSignal?.Task : null;
        }

        if (waitTask is not null)
        {
            await waitTask.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Resume reads. Returns true if this call un-paused the gate; false if it was already
    /// running or the connection has gone down.
    /// </summary>
    public bool Resume()
    {
        TaskCompletionSource? signal;
        lock (_sync)
        {
            if (!_isPaused)
            {
                return false;
            }

            _isPaused = false;
            signal = _resumeSignal;
            _resumeSignal = null;
        }

        signal?.TrySetResult();

        if (_lifetime.IsCancellationRequested)
        {
            return false;
        }

        return true;
    }

    private static TaskCompletionSource CreateResumeSignal() =>
        new(TaskCreationOptions.RunContinuationsAsynchronously);
}
