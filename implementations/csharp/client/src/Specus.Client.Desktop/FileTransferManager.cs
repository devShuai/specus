using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Specus.Client.Desktop;

/// <summary>
/// STXFER1 chunked file transfer on top of the client message channel
/// (peer mesh first, server fallback). Wire-compatible with the Android client:
/// every frame is a text message prefixed with "STXFER1\n" carrying a JSON body.
///
/// <para>The receive path treats the peer as untrusted: sessions are keyed by the authenticated
/// sender plus the transfer id, the remote id never reaches the filesystem, chunks are tracked in a
/// bitmap so retries are idempotent, and completion requires every chunk plus a matching digest.
/// Because the transport falls back to the server when a peer ACK is lost, duplicate deliveries are
/// expected and must not corrupt or prematurely complete a file.</para>
/// </summary>
internal sealed class FileTransferManager
{
    internal const string Prefix = "STXFER1\n";
    internal const int ChunkBytes = 600;
    internal const long MaxFileBytes = 8L * 1024 * 1024;
    /// <summary>Concurrent inbound sessions across all peers.</summary>
    internal const int MaxConcurrentSessions = 16;
    /// <summary>Total bytes reserved on disk by in-flight inbound sessions.</summary>
    internal const long MaxPendingBytes = 64L * 1024 * 1024;
    private static readonly TimeSpan SessionTtl = TimeSpan.FromSeconds(120);
    private static readonly TimeSpan SweepInterval = TimeSpan.FromSeconds(15);
    private const int ProgressEveryChunks = 32;

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly object _gate = new();
    private readonly Dictionary<string, IncomingSession> _incoming = new(StringComparer.Ordinal);
    /// <summary>Sessions finished recently, so a replayed "done" is ignored instead of re-delivered.</summary>
    private readonly Dictionary<string, DateTime> _completed = new(StringComparer.Ordinal);
    private readonly Timer _sweepTimer;
    private long _pendingBytes;

    public static FileTransferManager Instance { get; } = new();

    /// <summary>direction ("IN"/"OUT"), peer, user-facing text.</summary>
    public event Action<string, string, string>? TransferEvent;

    private FileTransferManager()
    {
        // Expiry must not depend on the next inbound message: a stalled sender would otherwise pin
        // the temp file and its reserved bytes indefinitely.
        _sweepTimer = new Timer(_ => SweepExpired(), null, SweepInterval, SweepInterval);
    }

    /// <summary>Test seam: builds an instance whose downloads land under <paramref name="rootDirectory"/>.</summary>
    internal FileTransferManager(string rootDirectory)
    {
        RootDirectoryOverride = rootDirectory;
        _sweepTimer = new Timer(_ => SweepExpired(), null, SweepInterval, SweepInterval);
    }

    internal string? RootDirectoryOverride { get; }

    public static bool IsTransferMessage(string? body)
        => body is not null && body.StartsWith(Prefix, StringComparison.Ordinal);

    public bool OnIncomingMessage(string from, string body)
    {
        if (!IsTransferMessage(body))
        {
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
        // The envelope's own sender field is peer-controlled and must never override the
        // authenticated sender the transport gives us.
        var sessionKey = SessionKey(from, frame.Id!);

        try
        {
            switch (frame.Type)
            {
                case "offer":
                    HandleOffer(sessionKey, from, frame);
                    break;
                case "chunk":
                    HandleChunk(sessionKey, from, frame);
                    break;
                case "done":
                    HandleDone(sessionKey, from, frame);
                    break;
                case "abort":
                    HandleAbort(sessionKey, from, frame);
                    break;
            }
        }
        catch (Exception ex)
        {
            DropSession(sessionKey);
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
        // A zero-byte file carries no chunks at all; the digest still proves the transfer.
        var chunks = (int)((total + ChunkBytes - 1) / ChunkBytes);
        try
        {
            var digest = await ComputeFileDigestAsync(filePath, cancellationToken).ConfigureAwait(false);
            await sendAsync(target, BuildOffer(id, name, total, chunks, digest), cancellationToken)
                .ConfigureAwait(false);
            Emit("OUT", target, $"发送中 {name} · {FormatBytes(total)}");

            var buffer = new byte[ChunkBytes];
            await using var stream = new FileStream(
                filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, useAsync: true);
            for (var seq = 0; seq < chunks; seq++)
            {
                var read = await ReadChunkAsync(stream, buffer, cancellationToken).ConfigureAwait(false);
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

    internal static string BuildOffer(string id, string name, long size, int chunks, string? sha256 = null)
        => Prefix + JsonSerializer.Serialize(new TransferFrame
        {
            Type = "offer",
            Id = id,
            Name = name,
            Size = size,
            Mime = "application/octet-stream",
            Chunks = chunks,
            Sha256 = sha256,
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

    private void HandleOffer(string sessionKey, string from, TransferFrame frame)
    {
        var expectedChunks = (int)((frame.Size + ChunkBytes - 1) / ChunkBytes);
        if (frame.Size < 0 || frame.Size > MaxFileBytes || frame.Chunks < 0 || frame.Chunks != expectedChunks)
        {
            throw new ArgumentException("invalid offer");
        }
        if (frame.Sha256 is not null && !IsHexDigest(frame.Sha256))
        {
            throw new ArgumentException("invalid digest");
        }
        // A repeated offer for the same sender+id restarts the transfer; it must not leak the
        // previous temp file or its reserved bytes.
        DropSession(sessionKey);

        var directory = TempDirectory();
        Directory.CreateDirectory(directory);
        // The remote id never reaches the filesystem: the temp name is locally generated and the
        // resolved path is verified to stay inside our own directory.
        var temp = Path.Combine(directory, Guid.NewGuid().ToString("N") + ".part");
        EnsureContained(directory, temp);

        lock (_gate)
        {
            if (_incoming.Count >= MaxConcurrentSessions)
            {
                throw new InvalidOperationException("接收会话过多");
            }
            if (_pendingBytes + frame.Size > MaxPendingBytes)
            {
                throw new InvalidOperationException("接收缓冲已满");
            }
            var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                64 * 1024, useAsync: false);
            stream.SetLength(frame.Size);
            _incoming[sessionKey] = new IncomingSession
            {
                Name = SanitizeName(frame.Name),
                From = from,
                Size = frame.Size,
                Chunks = frame.Chunks,
                Sha256 = frame.Sha256,
                TempPath = temp,
                Stream = stream,
                ReceivedChunks = new bool[frame.Chunks],
                LastTouchedAt = DateTime.UtcNow,
            };
            _pendingBytes += frame.Size;
        }
        Emit("IN", from, $"接收中 {SanitizeName(frame.Name)} · {FormatBytes(frame.Size)}");
    }

    private void HandleChunk(string sessionKey, string from, TransferFrame frame)
    {
        var session = GetSession(sessionKey);
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
        // Every chunk but the last must be exactly ChunkBytes, so a short chunk cannot silently
        // leave a hole that the bitmap would still count as received.
        var expected = (int)Math.Min(ChunkBytes, session.Size - offset);
        if (data.Length != expected)
        {
            throw new ArgumentException("chunk length mismatch");
        }

        var progress = 0;
        lock (session)
        {
            session.LastTouchedAt = DateTime.UtcNow;
            if (session.ReceivedChunks[frame.Seq])
            {
                // Duplicate delivery (peer retry or server fallback): writing again is harmless but
                // the completion count must stay unchanged.
                return;
            }
            session.Stream.Position = offset;
            session.Stream.Write(data, 0, data.Length);
            session.ReceivedChunks[frame.Seq] = true;
            session.ReceivedCount++;
            session.ReceivedBytes += data.Length;
            progress = session.ReceivedCount;
        }
        if (progress > 0 && progress % ProgressEveryChunks == 0)
        {
            var percent = (int)(progress * 100L / Math.Max(1, session.Chunks));
            Emit("IN", from, $"接收中 {session.Name} · {percent}%");
        }
    }

    private void HandleDone(string sessionKey, string from, TransferFrame frame)
    {
        IncomingSession? session;
        lock (_gate)
        {
            if (_completed.ContainsKey(sessionKey))
            {
                // The sender retried "done" after its ACK was lost; the file is already delivered.
                return;
            }
            if (_incoming.Remove(sessionKey, out session) && session is not null)
            {
                _pendingBytes = Math.Max(0, _pendingBytes - session.Size);
            }
        }
        if (session is null)
        {
            return;
        }
        session.Stream.Dispose();
        if (session.ReceivedCount != session.Chunks || session.ReceivedBytes != session.Size)
        {
            TryDelete(session.TempPath);
            Emit("IN", from, $"文件不完整 · {session.Name} ({session.ReceivedCount}/{session.Chunks})");
            return;
        }
        if (session.Sha256 is not null)
        {
            var actual = ComputeFileDigest(session.TempPath);
            if (!string.Equals(actual, session.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                TryDelete(session.TempPath);
                Emit("IN", from, $"文件校验失败 · {session.Name}");
                return;
            }
        }

        var target = UniqueTargetPath(session.Name);
        File.Move(session.TempPath, target);
        lock (_gate)
        {
            _completed[sessionKey] = DateTime.UtcNow;
        }
        Emit("IN", from, $"已接收 {session.Name} · {FormatBytes(session.Size)}\n保存到 {target}");
    }

    private void HandleAbort(string sessionKey, string from, TransferFrame frame)
    {
        var session = DropSession(sessionKey);
        if (session is not null)
        {
            Emit("IN", from, $"对方取消发送 · {session.Name}");
        }
    }

    private IncomingSession? GetSession(string sessionKey)
    {
        lock (_gate)
        {
            return _incoming.TryGetValue(sessionKey, out var session) ? session : null;
        }
    }

    private IncomingSession? DropSession(string sessionKey)
    {
        IncomingSession? session;
        lock (_gate)
        {
            if (_incoming.Remove(sessionKey, out session) && session is not null)
            {
                _pendingBytes = Math.Max(0, _pendingBytes - session.Size);
            }
        }
        if (session is not null)
        {
            session.Stream.Dispose();
            TryDelete(session.TempPath);
        }
        return session;
    }

    internal void SweepExpired()
    {
        var now = DateTime.UtcNow;
        List<string> expired;
        lock (_gate)
        {
            expired = _incoming
                .Where(pair => now - pair.Value.LastTouchedAt > SessionTtl)
                .Select(pair => pair.Key)
                .ToList();
            foreach (var key in _completed
                         .Where(pair => now - pair.Value > SessionTtl)
                         .Select(pair => pair.Key)
                         .ToList())
            {
                _completed.Remove(key);
            }
        }
        foreach (var key in expired)
        {
            var session = DropSession(key);
            if (session is not null)
            {
                Emit("IN", session.From, $"接收超时 · {session.Name}");
            }
        }
    }

    /// <summary>Sessions are per authenticated sender, so peers cannot collide on transfer ids.</summary>
    private static string SessionKey(string from, string id) => from + " " + id;

    private string TempDirectory()
        => Path.Combine(RootDirectoryOverride ?? Path.GetTempPath(), "specus-transfers");

    /// <summary>Rejects any candidate that resolves outside the directory we own.</summary>
    private static void EnsureContained(string directory, string candidate)
    {
        var root = Path.GetFullPath(directory);
        if (!root.EndsWith(Path.DirectorySeparatorChar))
        {
            root += Path.DirectorySeparatorChar;
        }
        var resolved = Path.GetFullPath(candidate);
        if (!resolved.StartsWith(root, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("resolved path escapes the transfer directory");
        }
    }

    private static async Task<int> ReadChunkAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            var current = await stream.ReadAsync(buffer.AsMemory(read, buffer.Length - read), cancellationToken)
                .ConfigureAwait(false);
            if (current <= 0)
            {
                break;
            }
            read += current;
        }
        return read;
    }

    private static async Task<string> ComputeFileDigestAsync(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            64 * 1024, useAsync: true);
        var digest = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
        return Convert.ToHexString(digest).ToLowerInvariant();
    }

    private static string ComputeFileDigest(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    private static bool IsHexDigest(string value) =>
        value.Length == 64 && value.All(Uri.IsHexDigit);

    private string UniqueTargetPath(string name)
    {
        var downloads = RootDirectoryOverride is null
            ? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                "Downloads",
                "specus")
            : Path.Combine(RootDirectoryOverride, "downloads");
        Directory.CreateDirectory(downloads);

        var candidate = Path.Combine(downloads, name);
        EnsureContained(downloads, candidate);
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

    /// <summary>
    /// Reduces a peer-supplied name to a bare file name. Separators, traversal segments, reserved
    /// device names and invalid characters are all removed before the name reaches the filesystem.
    /// </summary>
    internal static string SanitizeName(string? name)
    {
        var value = string.IsNullOrWhiteSpace(name) ? "" : name.Trim();
        // Strip any directory component the peer tried to smuggle in, using both separators so a
        // POSIX-style path is handled on Windows too.
        var lastSeparator = value.LastIndexOfAny(['/', '\\']);
        if (lastSeparator >= 0)
        {
            value = value[(lastSeparator + 1)..];
        }
        foreach (var invalid in Path.GetInvalidFileNameChars())
        {
            value = value.Replace(invalid, '_');
        }
        value = value.Trim().TrimEnd('.', ' ');
        if (value.Length == 0 || value == "." || value == "..")
        {
            return "file";
        }
        var stem = Path.GetFileNameWithoutExtension(value);
        string[] reserved =
        [
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        ];
        if (reserved.Contains(stem, StringComparer.OrdinalIgnoreCase))
        {
            value = "_" + value;
        }
        return value.Length > 180 ? value[^180..] : value;
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
        public string Name { get; init; } = "";
        public string From { get; init; } = "";
        public long Size { get; init; }
        public int Chunks { get; init; }
        public string? Sha256 { get; init; }
        public bool[] ReceivedChunks { get; init; } = [];
        public int ReceivedCount { get; set; }
        public long ReceivedBytes { get; set; }
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

        /// <summary>Whole-file digest; absent for peers that predate the check.</summary>
        [JsonPropertyName("sha256")]
        public string? Sha256 { get; set; }
    }
}
