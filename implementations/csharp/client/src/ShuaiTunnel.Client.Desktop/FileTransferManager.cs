using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ShuaiTunnel.Client.Desktop;

/// <summary>
/// STXFER1 chunked file transfer on top of the client message channel
/// (peer mesh first, server fallback). Wire-compatible with the Android client:
/// every frame is a text message prefixed with "STXFER1\n" carrying a JSON body.
/// </summary>
internal sealed class FileTransferManager
{
    internal const string Prefix = "STXFER1\n";
    internal const int ChunkBytes = 600;
    internal const long MaxFileBytes = 8L * 1024 * 1024;
    private static readonly TimeSpan SessionTtl = TimeSpan.FromSeconds(120);
    private const int ProgressEveryChunks = 32;

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly object _gate = new();
    private readonly Dictionary<string, IncomingSession> _incoming = new(StringComparer.Ordinal);

    public static FileTransferManager Instance { get; } = new();

    /// <summary>direction ("IN"/"OUT"), peer, user-facing text.</summary>
    public event Action<string, string, string>? TransferEvent;

    private FileTransferManager()
    {
    }

    public static bool IsTransferMessage(string? body)
        => body is not null && body.StartsWith(Prefix, StringComparison.Ordinal);

    public bool OnIncomingMessage(string from, string body)
    {
        if (!IsTransferMessage(body))
        {
            SweepExpired();
            return false;
        }
        TransferFrame? frame;
        try
        {
            frame = JsonSerializer.Deserialize<TransferFrame>(body.AsSpan(Prefix.Length), JsonOptions);
        }
        catch (JsonException)
        {
            return true;
        }
        if (frame is null || string.IsNullOrWhiteSpace(frame.Id))
        {
            return true;
        }

        try
        {
            switch (frame.Type)
            {
                case "offer":
                    HandleOffer(from, frame);
                    break;
                case "chunk":
                    HandleChunk(from, frame);
                    break;
                case "done":
                    HandleDone(from, frame);
                    break;
                case "abort":
                    HandleAbort(from, frame);
                    break;
            }
        }
        catch (Exception ex)
        {
            DropSession(frame.Id);
            Emit("IN", from, $"文件接收失败 · {ex.Message}");
        }
        return true;
    }

    public async Task SendFileAsync(
        string target,
        string filePath,
        Func<string, string, CancellationToken, Task> sendAsync,
        CancellationToken cancellationToken)
    {
        var fileInfo = new FileInfo(filePath);
        if (!fileInfo.Exists)
        {
            Emit("OUT", target, $"文件不存在 · {Path.GetFileName(filePath)}");
            return;
        }
        if (fileInfo.Length > MaxFileBytes)
        {
            Emit("OUT", target, $"文件过大 · 上限 {FormatBytes(MaxFileBytes)}");
            return;
        }

        var id = Guid.NewGuid().ToString("N");
        var name = fileInfo.Name;
        var total = fileInfo.Length;
        var chunks = (int)Math.Max(1, (total + ChunkBytes - 1) / ChunkBytes);
        try
        {
            await sendAsync(target, BuildOffer(id, name, total, chunks), cancellationToken).ConfigureAwait(false);
            Emit("OUT", target, $"发送中 {name} · {FormatBytes(total)}");

            var buffer = new byte[ChunkBytes];
            await using var stream = new FileStream(
                filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, useAsync: true);
            for (var seq = 0; seq < chunks; seq++)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(0, ChunkBytes), cancellationToken).ConfigureAwait(false);
                if (read <= 0)
                {
                    throw new IOException("文件读取提前结束");
                }
                await sendAsync(target, BuildChunk(id, seq, buffer, read), cancellationToken).ConfigureAwait(false);
                if ((seq + 1) % ProgressEveryChunks == 0 || seq + 1 == chunks)
                {
                    var percent = (int)((long)(seq + 1) * 100 / chunks);
                    Emit("OUT", target, $"发送中 {name} · {percent}%");
                }
            }

            await sendAsync(target, BuildDone(id), cancellationToken).ConfigureAwait(false);
            Emit("OUT", target, $"已发送 {name} · {FormatBytes(total)}");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            try
            {
                await sendAsync(target, BuildAbort(id, ex.Message), CancellationToken.None).ConfigureAwait(false);
            }
            catch
            {
                // Best effort abort notice.
            }
            Emit("OUT", target, $"文件发送失败 · {ex.Message}");
        }
    }

    internal static string BuildOffer(string id, string name, long size, int chunks)
        => Prefix + JsonSerializer.Serialize(new TransferFrame
        {
            Type = "offer",
            Id = id,
            Name = name,
            Size = size,
            Mime = "application/octet-stream",
            Chunks = chunks,
        }, JsonOptions);

    internal static string BuildChunk(string id, int seq, byte[] data, int length)
        => Prefix + JsonSerializer.Serialize(new TransferFrame
        {
            Type = "chunk",
            Id = id,
            Seq = seq,
            Data = Convert.ToBase64String(data, 0, length),
        }, JsonOptions);

    internal static string BuildDone(string id)
        => Prefix + JsonSerializer.Serialize(new TransferFrame { Type = "done", Id = id }, JsonOptions);

    internal static string BuildAbort(string id, string reason)
        => Prefix + JsonSerializer.Serialize(new TransferFrame { Type = "abort", Id = id, Reason = reason }, JsonOptions);

    private void HandleOffer(string from, TransferFrame frame)
    {
        if (frame.Size < 0 || frame.Size > MaxFileBytes || frame.Chunks <= 0 || frame.Chunks > MaxFileBytes / ChunkBytes + 1)
        {
            throw new ArgumentException("invalid offer");
        }
        DropSession(frame.Id!);

        var dir = Path.Combine(Path.GetTempPath(), "shuai-tunnel-transfers");
        Directory.CreateDirectory(dir);
        var temp = Path.Combine(dir, frame.Id + ".part");
        var stream = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None, 64 * 1024, useAsync: false);
        stream.SetLength(frame.Size);

        var session = new IncomingSession
        {
            Id = frame.Id!,
            Name = SanitizeName(frame.Name),
            From = from,
            Size = frame.Size,
            Chunks = frame.Chunks,
            TempPath = temp,
            Stream = stream,
            LastTouchedAt = DateTime.UtcNow,
        };
        lock (_gate)
        {
            _incoming[session.Id] = session;
        }
        Emit("IN", from, $"接收中 {session.Name} · {FormatBytes(session.Size)}");
    }

    private void HandleChunk(string from, TransferFrame frame)
    {
        var session = GetSession(frame.Id!);
        if (session is null)
        {
            return;
        }
        if (frame.Seq < 0 || frame.Seq >= session.Chunks)
        {
            throw new ArgumentException("invalid chunk seq");
        }
        var data = Convert.FromBase64String(frame.Data ?? "");
        var offset = (long)frame.Seq * ChunkBytes;
        if (offset + data.Length > session.Size)
        {
            throw new ArgumentException("chunk out of range");
        }
        lock (session)
        {
            session.Stream.Position = offset;
            session.Stream.Write(data, 0, data.Length);
            session.Received++;
            session.LastTouchedAt = DateTime.UtcNow;
            if (session.Received % ProgressEveryChunks == 0)
            {
                var percent = (int)(session.Received * 100L / session.Chunks);
                Emit("IN", from, $"接收中 {session.Name} · {percent}%");
            }
        }
    }

    private void HandleDone(string from, TransferFrame frame)
    {
        IncomingSession? session;
        lock (_gate)
        {
            _incoming.Remove(frame.Id!, out session);
        }
        if (session is null)
        {
            return;
        }
        session.Stream.Dispose();
        if (session.Received != session.Chunks)
        {
            TryDelete(session.TempPath);
            Emit("IN", from, $"文件不完整 · {session.Name} ({session.Received}/{session.Chunks})");
            return;
        }

        var target = UniqueTargetPath(session.Name);
        File.Move(session.TempPath, target);
        Emit("IN", from, $"已接收 {session.Name} · {FormatBytes(session.Size)}\n保存到 {target}");
    }

    private void HandleAbort(string from, TransferFrame frame)
    {
        var session = DropSession(frame.Id!);
        if (session is not null)
        {
            Emit("IN", from, $"对方取消发送 · {session.Name}");
        }
    }

    private IncomingSession? GetSession(string id)
    {
        lock (_gate)
        {
            return _incoming.TryGetValue(id, out var session) ? session : null;
        }
    }

    private IncomingSession? DropSession(string id)
    {
        IncomingSession? session;
        lock (_gate)
        {
            _incoming.Remove(id, out session);
        }
        if (session is not null)
        {
            session.Stream.Dispose();
            TryDelete(session.TempPath);
        }
        return session;
    }

    private void SweepExpired()
    {
        var now = DateTime.UtcNow;
        List<string> expired;
        lock (_gate)
        {
            expired = _incoming
                .Where(pair => now - pair.Value.LastTouchedAt > SessionTtl)
                .Select(pair => pair.Key)
                .ToList();
        }
        foreach (var id in expired)
        {
            var session = DropSession(id);
            if (session is not null)
            {
                Emit("IN", session.From, $"接收超时 · {session.Name}");
            }
        }
    }

    private static string UniqueTargetPath(string name)
    {
        var downloads = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            "Downloads",
            "shuai-tunnel");
        Directory.CreateDirectory(downloads);

        var candidate = Path.Combine(downloads, name);
        if (!File.Exists(candidate))
        {
            return candidate;
        }
        var baseName = Path.GetFileNameWithoutExtension(name);
        var extension = Path.GetExtension(name);
        for (var i = 1; i < 1000; i++)
        {
            candidate = Path.Combine(downloads, $"{baseName} ({i}){extension}");
            if (!File.Exists(candidate))
            {
                return candidate;
            }
        }
        return Path.Combine(downloads, $"{DateTimeOffset.Now.ToUnixTimeMilliseconds()}-{name}");
    }

    private static string SanitizeName(string? name)
    {
        var value = string.IsNullOrWhiteSpace(name) ? "file" : name.Trim();
        foreach (var invalid in Path.GetInvalidFileNameChars())
        {
            value = value.Replace(invalid, '_');
        }
        return value;
    }

    internal static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB"];
        var value = (double)Math.Max(0L, bytes);
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }
        return unit == 0 ? $"{value:0} {units[unit]}" : $"{value:0.0} {units[unit]}";
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
            // Best effort cleanup.
        }
    }

    private void Emit(string direction, string peer, string text)
    {
        TransferEvent?.Invoke(direction, peer, text);
    }

    private sealed class IncomingSession
    {
        public string Id { get; init; } = "";
        public string Name { get; init; } = "";
        public string From { get; init; } = "";
        public long Size { get; init; }
        public int Chunks { get; init; }
        public int Received { get; set; }
        public string TempPath { get; init; } = "";
        public FileStream Stream { get; init; } = null!;
        public DateTime LastTouchedAt { get; set; }
    }

    internal sealed class TransferFrame
    {
        [JsonPropertyName("t")]
        public string? Type { get; set; }

        [JsonPropertyName("id")]
        public string? Id { get; set; }

        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [JsonPropertyName("size")]
        public long Size { get; set; }

        [JsonPropertyName("mime")]
        public string? Mime { get; set; }

        [JsonPropertyName("chunks")]
        public int Chunks { get; set; }

        [JsonPropertyName("seq")]
        public int Seq { get; set; }

        [JsonPropertyName("data")]
        public string? Data { get; set; }

        [JsonPropertyName("reason")]
        public string? Reason { get; set; }
    }
}
