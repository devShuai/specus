using System.Threading.Channels;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ShuaiTunnel.Server.Configuration;

namespace ShuaiTunnel.Server.Authentication;

/// <summary>
/// Mirrors <c>ServerExecutorConfig.loginExecutor</c>: a bounded queue + N workers running login
/// work off the I/O thread. The queue's <see cref="BoundedChannelFullMode.DropWrite"/> behavior
/// is the .NET equivalent of Java's <c>AbortPolicy</c> — when the queue is full
/// <see cref="TryEnqueue"/> returns false and the caller answers with a
/// <c>SERVER_BUSY</c> close.
///
/// <para>Why a custom queue instead of <see cref="Task.Run"/>? We need (a) bounded depth so a
/// login storm can't OOM the process, (b) a clean shutdown handshake. The .NET ThreadPool has
/// neither.</para>
/// </summary>
public sealed class LoginExecutor : BackgroundService
{
    private readonly Channel<Func<Task>> _queue;
    private readonly LoginExecutorOptions _options;
    private readonly ILogger<LoginExecutor> _logger;

    public LoginExecutor(IOptions<LoginExecutorOptions> options, ILogger<LoginExecutor> logger)
    {
        _options = options.Value;
        _logger = logger;
        _queue = Channel.CreateBounded<Func<Task>>(new BoundedChannelOptions(_options.ExecutorQueueCapacity)
        {
            // TryEnqueue relies on TryWrite returning false when the queue is full so the
            // caller can send SERVER_BUSY. DropWrite would silently discard the login task.
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = false,
            SingleWriter = false,
        });
    }

    /// <summary>
    /// Returns false when the queue is full — caller must respond with the busy answer
    /// (<c>SERVER_BUSY</c>) and close the connection.
    /// </summary>
    public bool TryEnqueue(Func<Task> work)
    {
        return _queue.Writer.TryWrite(work);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var workers = Enumerable.Range(0, _options.ExecutorMaxSize)
            .Select(i => Task.Run(() => WorkerAsync(i, stoppingToken), stoppingToken))
            .ToArray();
        try
        {
            await Task.WhenAll(workers).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown — ignore.
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _queue.Writer.TryComplete();
        await base.StopAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task WorkerAsync(int workerIndex, CancellationToken stoppingToken)
    {
        await foreach (var work in _queue.Reader.ReadAllAsync(stoppingToken).ConfigureAwait(false))
        {
            try
            {
                await work().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "login-worker-{Idx} task threw", workerIndex);
            }
        }
    }
}
