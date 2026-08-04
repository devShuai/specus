using System.IO.Compression;
using System.Text;

namespace Specus.Server.Management;

internal static class HttpMediaBodyCodec
{
    public static string ToText(byte[] bytes, string? contentEncoding)
    {
        var decoded = Decode(bytes, contentEncoding);
        var text = Encoding.UTF8.GetString(decoded);
        var result = new StringBuilder(text.Length);
        foreach (var ch in text)
        {
            result.Append(char.IsControl(ch) && ch is not ('\r' or '\n' or '\t') || char.IsSurrogate(ch)
                ? '.' : ch);
        }
        return result.ToString();
    }

    private static byte[] Decode(byte[] bytes, string? contentEncoding)
    {
        if (string.IsNullOrWhiteSpace(contentEncoding))
        {
            return bytes;
        }
        var current = bytes;
        foreach (var token in contentEncoding.Split(',', StringSplitOptions.TrimEntries)
                     .Reverse())
        {
            if (token.Length == 0 || token.Equals("identity", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            using var source = new MemoryStream(current, writable: false);
            using Stream decoder = token.ToLowerInvariant() switch
            {
                "gzip" or "x-gzip" => new GZipStream(source, CompressionMode.Decompress),
                "deflate" or "x-deflate" => new DeflateStream(source, CompressionMode.Decompress),
                "br" => new BrotliStream(source, CompressionMode.Decompress),
                _ => throw new InvalidOperationException($"unsupported media content encoding: {token}"),
            };
            using var output = new MemoryStream();
            decoder.CopyTo(output);
            current = output.ToArray();
        }
        return current;
    }
}

public sealed class HttpMediaUploadScheduler : IHostedService
{
    private readonly SemaphoreSlim _workers;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<long, Task> _pending = new();
    private long _sequence;

    public HttpMediaUploadScheduler(Microsoft.Extensions.Options.IOptions<
        Configuration.MediaCaptureOptions> options)
    {
        _workers = new SemaphoreSlim(options.Value.NormalizedUploadThreads);
    }

    public async Task<T> RunAsync<T>(Func<Task<T>> work)
    {
        await _workers.WaitAsync().ConfigureAwait(false);
        try
        {
            return await work().ConfigureAwait(false);
        }
        finally
        {
            _workers.Release();
        }
    }

    public void Track(Task task)
    {
        var id = Interlocked.Increment(ref _sequence);
        _pending[id] = task;
        _ = task.ContinueWith((completedTask, state) =>
        {
            var (pending, key) = ((System.Collections.Concurrent.ConcurrentDictionary<long, Task>, long))state!;
            if (completedTask.IsFaulted)
            {
                _ = completedTask.Exception;
            }
            pending.TryRemove(key, out _);
        }, (_pending, id), CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }

    public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        var pending = _pending.Values.ToArray();
        if (pending.Length == 0)
        {
            return;
        }
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        try
        {
            await Task.WhenAll(pending).WaitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested)
        {
            // Match Java's bounded executor shutdown: unfinished best-effort finalizers are abandoned.
        }
    }
}
