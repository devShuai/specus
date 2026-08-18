using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Specus.Client.Configuration;

namespace Specus.Client.Desktop;

/// <summary>
/// STXFER1 chunked file transfer on top of the client message channel
/// (peer mesh first, server fallback). Wire-compatible with the Android client:
/// every frame is a text message prefixed with "STXFER1\n" carrying a JSON body.
///
/// <para>The receive path treats the peer as untrusted. Sessions are keyed by the authenticated
/// transport sender plus the transfer id, remote identifiers never reach the filesystem, and a
/// file is published only after every exact-length chunk and the mandatory whole-file digest have
/// been verified. Direct and server-fallback copies may be duplicated or reordered.</para>
/// </summary>
internal sealed class FileTransferManager : IDisposable
{
    internal const string Prefix = "STXFER1\n";
    internal const int ChunkBytes = 600;
    internal const long MaxFileBytes = ClientMessageCapabilities.DesktopMaxAttachmentBytes;
    internal const int MaxConcurrentSessions = 16;
    internal const long MaxPendingBytes = 64L * 1024 * 1024;
    /// <summary>Maximum JSON payload length in UTF-16 characters before deserialization.</summary>
    internal const int MaxFrameCharacters = 8 * 1024;

    private const int MaxTransferIdLength = 128;
    private const int MaxCompletedTombstones = 512;
    private const int MaxTerminalEntriesPerSender = 64;
    private const int ProgressEveryChunks = 32;
    private static readonly TimeSpan SessionTtl = TimeSpan.FromSeconds(120);
    private static readonly TimeSpan SweepInterval = TimeSpan.FromSeconds(15);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly object _gate = new();
    private readonly Dictionary<TransferKey, IncomingSession> _incoming = [];
    /// <summary>Terminal (completed or aborted) transfers whose delayed fallback frames are ignored.</summary>
    private readonly Dictionary<TransferKey, DateTime> _completed = [];
    /// <summary>Done frames that raced ahead of their offer on the other transport path.</summary>
    private readonly Dictionary<TransferKey, DateTime> _earlyDone = [];
    private readonly IFileTransferStorage _storage;
    private readonly FileTransferTestHooks _testHooks;
    private readonly Timer _sweepTimer;
    private long _pendingBytes;
    private int _disposed;

    public static FileTransferManager Instance { get; } = new();

    /// <summary>direction ("IN"/"OUT"), peer, user-facing text.</summary>
    public event Action<string, string, string>? TransferEvent;

    private FileTransferManager()
    {
        _storage = PhysicalFileTransferStorage.Instance;
        _testHooks = new FileTransferTestHooks();
        _sweepTimer = new Timer(_ => SweepExpired(), null, SweepInterval, SweepInterval);
    }

    /// <summary>Test seam: downloads land under <paramref name="rootDirectory"/>.</summary>
    internal FileTransferManager(
        string rootDirectory,
        IFileTransferStorage? storage = null,
        FileTransferTestHooks? testHooks = null)
    {
        RootDirectoryOverride = rootDirectory;
        _storage = storage ?? PhysicalFileTransferStorage.Instance;
        _testHooks = testHooks ?? new FileTransferTestHooks();
        _sweepTimer = new Timer(_ => SweepExpired(), null, SweepInterval, SweepInterval);
    }

    internal string? RootDirectoryOverride { get; }

    internal int IncomingSessionCount
    {
        get
        {
            lock (_gate)
            {
                return _incoming.Count;
            }
        }
    }

    internal long PendingBytes
    {
        get
        {
            lock (_gate)
            {
                return _pendingBytes;
            }
        }
    }

    public static bool IsTransferMessage(string? body)
        => body is not null && body.StartsWith(Prefix, StringComparison.Ordinal);

    public bool OnIncomingMessage(string from, string body)
    {
        if (!IsTransferMessage(body))
        {
            return false;
        }
        if (body.Length - Prefix.Length > MaxFrameCharacters)
        {
            // Legal STXFER1 frames are roughly 1 KiB. Bound the untrusted JSON before the parser
            // materializes its strings; the outer transport's much larger message limit is not a
            // suitable per-chunk allocation limit.
            return true;
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

        var authenticatedSender = from?.Trim() ?? "";
        var transferId = frame?.Id?.Trim() ?? "";
        if (frame is null
            || authenticatedSender.Length == 0
            || transferId.Length == 0
            || transferId.Length > MaxTransferIdLength)
        {
            return true;
        }

        var sessionKey = TransferKey.Create(authenticatedSender, transferId);
        TransferNotice? notice = null;
        try
        {
            lock (_gate)
            {
                if (_disposed != 0 || _completed.ContainsKey(sessionKey))
                {
                    // A successful transfer leaves a tombstone that consumes every delayed frame,
                    // including an old offer arriving after the server fallback.
                    return true;
                }

                notice = frame.Type switch
                {
                    "offer" => HandleOfferLocked(sessionKey, authenticatedSender, frame),
                    "chunk" => HandleChunkLocked(sessionKey, frame),
                    "done" => HandleDoneLocked(sessionKey),
                    "abort" => HandleAbortLocked(sessionKey),
                    _ => null,
                };
            }
        }
        catch (TransferProtocolException ex)
        {
            lock (_gate)
            {
                if (ex.DropSession)
                {
                    DropSessionLocked(sessionKey);
                }
            }
            notice = new TransferNotice(
                "IN",
                authenticatedSender,
                ex.UserFacingText ?? $"文件接收失败 · {ex.Message}");
        }
        catch (Exception ex)
        {
            lock (_gate)
            {
                DropSessionLocked(sessionKey);
            }
            notice = new TransferNotice("IN", authenticatedSender, $"文件接收失败 · {ex.Message}");
        }

        notice?.Publish(this);
        return true;
    }

    public async Task SendFileAsync(
        string target,
        string filePath,
        Action<string, long> ensureTargetCanReceive,
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
        // Validate the same size snapshot used to construct the offer immediately before any
        // digest work or STXFER1 frame is emitted.
        ensureTargetCanReceive(target, fileInfo.Length);

        var id = Guid.NewGuid().ToString("N");
        var name = fileInfo.Name;
        var total = fileInfo.Length;
        var chunks = (int)((total + ChunkBytes - 1) / ChunkBytes);
        string digest;
        try
        {
            digest = await ComputeFileDigestAsync(filePath, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Emit("OUT", target, $"文件发送失败 · {ex.Message}");
            return;
        }

        // Capability and online state may change while hashing. Re-read the authoritative roster
        // immediately before the first frame, with no await between the gate and send.
        ensureTargetCanReceive(target, total);
        var offerSent = false;
        try
        {
            await sendAsync(target, BuildOffer(id, name, total, chunks, digest), cancellationToken)
                .ConfigureAwait(false);
            offerSent = true;
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
            if (offerSent)
            {
                try
                {
                    await sendAsync(target, BuildAbort(id, ex.Message), CancellationToken.None).ConfigureAwait(false);
                }
                catch
                {
                    // Best effort abort notice after the target accepted the offer.
                }
            }
            Emit("OUT", target, $"文件发送失败 · {ex.Message}");
        }
    }

    internal static string BuildOffer(string id, string name, long size, int chunks, string? sha256)
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

    private TransferNotice? HandleOfferLocked(TransferKey sessionKey, string from, TransferFrame frame)
    {
        _incoming.TryGetValue(sessionKey, out var existing);
        ValidateOffer(frame, dropSession: existing is null);

        var name = SanitizeName(frame.Name);
        var digest = frame.Sha256!.ToLowerInvariant();
        if (existing is not null)
        {
            if (!existing.MatchesOffer(name, frame.Size, frame.Chunks, digest))
            {
                // A conflicting replay must not erase bytes already received for the authenticated
                // sender's original transfer.
                throw new TransferProtocolException("conflicting offer", dropSession: false);
            }
            existing.LastTouchedAt = DateTime.UtcNow;
            return null;
        }

        if (_incoming.Count >= MaxConcurrentSessions)
        {
            throw new TransferProtocolException("接收会话过多", dropSession: false);
        }
        if (!HasTerminalCapacityForLocked(sessionKey))
        {
            // Every admitted session reserves one terminal slot. Never evict another authenticated
            // sender's tombstone: that would let delayed fallback frames publish a second file.
            throw new TransferProtocolException("接收终止记录已满", dropSession: false);
        }
        if (_pendingBytes > MaxPendingBytes - frame.Size)
        {
            throw new TransferProtocolException("接收缓冲已满", dropSession: false);
        }

        var directory = TempDirectory();
        _storage.CreateDirectory(directory);
        var temp = Path.Combine(directory, Guid.NewGuid().ToString("N") + ".part");
        EnsureContained(directory, temp);

        Stream? stream = null;
        var registered = false;
        try
        {
            stream = _storage.CreateTemporaryFile(temp);
            _storage.SetLength(stream, frame.Size);
            _testHooks.BeforeSessionRegistration?.Invoke();

            var doneSeen = _earlyDone.ContainsKey(sessionKey);
            var session = new IncomingSession
            {
                Name = name,
                From = from,
                Size = frame.Size,
                Chunks = frame.Chunks,
                Sha256 = digest,
                TempPath = temp,
                Stream = stream,
                ReceivedChunks = new bool[frame.Chunks],
                DoneSeen = doneSeen,
                LastTouchedAt = DateTime.UtcNow,
            };
            _incoming.Add(sessionKey, session);
            _pendingBytes += frame.Size;
            registered = true;
            stream = null;
            if (doneSeen)
            {
                _earlyDone.Remove(sessionKey);
            }
            _testHooks.AfterSessionRegistration?.Invoke();

            if (session.DoneSeen && session.IsComplete)
            {
                return FinalizeLocked(sessionKey, session);
            }
        }
        finally
        {
            if (!registered)
            {
                TryDispose(stream);
                TryDelete(temp);
            }
        }

        return new TransferNotice("IN", from, $"接收中 {name} · {FormatBytes(frame.Size)}");
    }

    private TransferNotice? HandleChunkLocked(TransferKey sessionKey, TransferFrame frame)
    {
        if (!_incoming.TryGetValue(sessionKey, out var session))
        {
            return null;
        }
        if (frame.Seq < 0 || frame.Seq >= session.Chunks)
        {
            throw new TransferProtocolException("invalid chunk seq", dropSession: true);
        }
        if (frame.Data is null || frame.Data.Length > 4 * ((ChunkBytes + 2) / 3))
        {
            throw new TransferProtocolException("invalid chunk data", dropSession: true);
        }

        byte[] data;
        try
        {
            data = Convert.FromBase64String(frame.Data);
        }
        catch (FormatException ex)
        {
            throw new TransferProtocolException("invalid chunk data", dropSession: true, innerException: ex);
        }

        var offset = (long)frame.Seq * ChunkBytes;
        var expected = (int)Math.Min(ChunkBytes, session.Size - offset);
        if (data.Length != expected)
        {
            throw new TransferProtocolException("chunk length mismatch", dropSession: true);
        }

        session.LastTouchedAt = DateTime.UtcNow;
        if (session.ReceivedChunks[frame.Seq])
        {
            return null;
        }

        var stream = session.Stream
            ?? throw new TransferProtocolException("receive stream unavailable", dropSession: true);
        stream.Position = offset;
        stream.Write(data, 0, data.Length);
        session.ReceivedChunks[frame.Seq] = true;
        session.ReceivedCount++;
        session.ReceivedBytes += data.Length;

        if (session.DoneSeen && session.IsComplete)
        {
            return FinalizeLocked(sessionKey, session);
        }
        if (session.ReceivedCount > 0 && session.ReceivedCount % ProgressEveryChunks == 0)
        {
            var percent = (int)(session.ReceivedCount * 100L / Math.Max(1, session.Chunks));
            return new TransferNotice("IN", session.From, $"接收中 {session.Name} · {percent}%");
        }
        return null;
    }

    private TransferNotice? HandleDoneLocked(TransferKey sessionKey)
    {
        if (!_incoming.TryGetValue(sessionKey, out var session))
        {
            AddEarlyDoneLocked(sessionKey);
            return null;
        }
        session.DoneSeen = true;
        session.LastTouchedAt = DateTime.UtcNow;
        // A direct-path done may race ahead of server-fallback chunks. Keep the session alive and
        // let the last missing chunk trigger finalization.
        return session.IsComplete ? FinalizeLocked(sessionKey, session) : null;
    }

    private TransferNotice? HandleAbortLocked(TransferKey sessionKey)
    {
        var session = DropSessionLocked(sessionKey);
        _earlyDone.Remove(sessionKey);
        if (session is not null || HasTerminalCapacityForLocked(sessionKey))
        {
            AddCompletedTombstoneLocked(sessionKey);
        }
        return session is null
            ? null
            : new TransferNotice("IN", session.From, $"对方取消发送 · {session.Name}");
    }

    private TransferNotice FinalizeLocked(TransferKey sessionKey, IncomingSession session)
    {
        string? ownedTarget = null;
        try
        {
            var stream = session.Stream
                ?? throw new TransferProtocolException("receive stream unavailable", dropSession: true);
            stream.Flush();
            stream.Dispose();
            // Keep the session reference until Dispose succeeds. If it throws, DropSessionLocked
            // retries disposal before deleting the temporary file and releasing accounting.
            session.Stream = null;

            var actual = _storage.ComputeSha256(session.TempPath);
            if (!string.Equals(actual, session.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new TransferProtocolException(
                    "digest mismatch",
                    dropSession: true,
                    userFacingText: $"文件校验失败 · {session.Name}");
            }

            var target = PublishTempFile(session.TempPath, session.Name);
            ownedTarget = target;
            RemoveRegisteredSessionLocked(sessionKey, session);
            AddCompletedTombstoneLocked(sessionKey);
            return new TransferNotice(
                "IN",
                session.From,
                $"已接收 {session.Name} · {FormatBytes(session.Size)}\n保存到 {target}");
        }
        catch
        {
            if (ownedTarget is not null)
            {
                TryDelete(ownedTarget);
            }
            DropSessionLocked(sessionKey);
            throw;
        }
    }

    private static void ValidateOffer(TransferFrame frame, bool dropSession)
    {
        if (frame.Size < 0 || frame.Size > MaxFileBytes)
        {
            throw new TransferProtocolException("invalid offer", dropSession);
        }
        var expectedChunks = (int)((frame.Size + ChunkBytes - 1) / ChunkBytes);
        if (frame.Chunks < 0 || frame.Chunks != expectedChunks)
        {
            throw new TransferProtocolException("invalid offer", dropSession);
        }
        if (string.IsNullOrWhiteSpace(frame.Sha256) || !IsHexDigest(frame.Sha256))
        {
            throw new TransferProtocolException("invalid digest", dropSession);
        }
    }

    private IncomingSession? DropSessionLocked(TransferKey sessionKey)
    {
        if (!_incoming.Remove(sessionKey, out var session) || session is null)
        {
            return null;
        }
        _pendingBytes = Math.Max(0, _pendingBytes - session.Size);
        TryDispose(session.Stream);
        session.Stream = null;
        TryDelete(session.TempPath);
        return session;
    }

    private void RemoveRegisteredSessionLocked(TransferKey sessionKey, IncomingSession expected)
    {
        if (_incoming.Remove(sessionKey, out var removed) && removed is not null)
        {
            _pendingBytes = Math.Max(0, _pendingBytes - removed.Size);
            if (!ReferenceEquals(removed, expected))
            {
                TryDispose(removed.Stream);
                TryDelete(removed.TempPath);
            }
        }
    }

    private void AddCompletedTombstoneLocked(TransferKey sessionKey)
    {
        if (_completed.ContainsKey(sessionKey))
        {
            _completed[sessionKey] = DateTime.UtcNow;
            return;
        }
        if (!HasTerminalCapacityForLocked(sessionKey))
        {
            // Capacity is fail-closed. New offers are rejected until TTL cleanup makes room, while
            // existing senders retain replay protection for the full window.
            return;
        }
        _completed[sessionKey] = DateTime.UtcNow;
    }

    private bool HasTerminalCapacityForLocked(TransferKey sessionKey)
    {
        if (_completed.Count + _incoming.Count >= MaxCompletedTombstones)
        {
            return false;
        }
        var senderEntries = _completed.Keys.Count(key => key.Sender == sessionKey.Sender)
            + _incoming.Keys.Count(key => key.Sender == sessionKey.Sender);
        return senderEntries < MaxTerminalEntriesPerSender;
    }

    private void AddEarlyDoneLocked(TransferKey sessionKey)
    {
        if (_earlyDone.ContainsKey(sessionKey))
        {
            _earlyDone[sessionKey] = DateTime.UtcNow;
            return;
        }
        if (_earlyDone.Count >= MaxCompletedTombstones
            || _earlyDone.Keys.Count(key => key.Sender == sessionKey.Sender) >= MaxTerminalEntriesPerSender)
        {
            return;
        }
        _earlyDone[sessionKey] = DateTime.UtcNow;
    }

    internal void SweepExpired()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            return;
        }

        var now = DateTime.UtcNow;
        List<TransferNotice> notices = [];
        lock (_gate)
        {
            if (_disposed != 0)
            {
                return;
            }
            foreach (var key in _incoming
                         .Where(pair => now - pair.Value.LastTouchedAt > SessionTtl)
                         .Select(pair => pair.Key)
                         .ToList())
            {
                var session = DropSessionLocked(key);
                if (session is not null)
                {
                    notices.Add(new TransferNotice("IN", session.From, $"接收超时 · {session.Name}"));
                }
            }
            foreach (var key in _completed
                         .Where(pair => now - pair.Value > SessionTtl)
                         .Select(pair => pair.Key)
                         .ToList())
            {
                _completed.Remove(key);
            }
            foreach (var key in _earlyDone
                         .Where(pair => now - pair.Value > SessionTtl)
                         .Select(pair => pair.Key)
                         .ToList())
            {
                _earlyDone.Remove(key);
            }
        }
        foreach (var notice in notices)
        {
            notice.Publish(this);
        }
    }

    private string TempDirectory()
        => Path.Combine(RootDirectoryOverride ?? Path.GetTempPath(), "specus-transfers");

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

    private static async Task<int> ReadChunkAsync(
        Stream stream,
        byte[] buffer,
        CancellationToken cancellationToken)
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

    private static bool IsHexDigest(string value)
        => value.Length == 64 && value.All(Uri.IsHexDigit);

    private string PublishTempFile(string source, string name)
    {
        var downloads = RootDirectoryOverride is null
            ? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                "Downloads",
                "specus")
            : Path.Combine(RootDirectoryOverride, "downloads");
        _storage.CreateDirectory(downloads);

        for (var attempt = 0; attempt < 1016; attempt++)
        {
            var candidateName = PublishCandidateName(name, attempt);
            var candidate = Path.Combine(downloads, candidateName);
            EnsureContained(downloads, candidate);
            var result = _storage.PublishFile(source, candidate);
            if (result.OwnedPartialPath is not null)
            {
                EnsureContained(downloads, result.OwnedPartialPath);
                TryDelete(result.OwnedPartialPath);
            }
            if (result.Status == FileTransferPublishStatus.Published)
            {
                return candidate;
            }
            if (result.Status == FileTransferPublishStatus.Conflict)
            {
                continue;
            }
            // Delete only a destination the storage implementation explicitly says this transfer
            // created. A generic publish failure may instead belong to a racing external writer.
            if (result.TargetOwned)
            {
                TryDelete(candidate);
            }
            throw result.Error ?? new IOException("文件发布失败");
        }
        throw new IOException("无法分配下载文件名");
    }

    private static string PublishCandidateName(string name, int attempt)
    {
        if (attempt == 0)
        {
            return name;
        }
        var baseName = Path.GetFileNameWithoutExtension(name);
        var extension = Path.GetExtension(name);
        return attempt < 1000
            ? $"{baseName} ({attempt}){extension}"
            : $"{Guid.NewGuid():N}-{name}";
    }

    internal static string SanitizeName(string? name)
    {
        var value = string.IsNullOrWhiteSpace(name) ? "" : name.Trim();
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

    private static void TryDispose(Stream? stream)
    {
        try
        {
            stream?.Dispose();
        }
        catch
        {
            // Cleanup must continue to the temporary file and accounting release.
        }
    }

    private void TryDelete(string path)
    {
        try
        {
            _storage.DeleteFile(path);
        }
        catch
        {
            // Best effort cleanup.
        }
    }

    private void Emit(string direction, string peer, string text)
        => TransferEvent?.Invoke(direction, peer, text);

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }
        _sweepTimer.Dispose();
        lock (_gate)
        {
            foreach (var key in _incoming.Keys.ToList())
            {
                DropSessionLocked(key);
            }
            _completed.Clear();
            _earlyDone.Clear();
        }
    }

    private readonly record struct TransferKey(string Sender, string TransferId)
    {
        public static TransferKey Create(string sender, string transferId)
            => new(sender.Trim(), transferId);
    }

    private sealed class IncomingSession
    {
        public string Name { get; init; } = "";
        public string From { get; init; } = "";
        public long Size { get; init; }
        public int Chunks { get; init; }
        public string Sha256 { get; init; } = "";
        public bool[] ReceivedChunks { get; init; } = [];
        public int ReceivedCount { get; set; }
        public long ReceivedBytes { get; set; }
        public string TempPath { get; init; } = "";
        public Stream? Stream { get; set; }
        public bool DoneSeen { get; set; }
        public DateTime LastTouchedAt { get; set; }

        public bool IsComplete => ReceivedCount == Chunks && ReceivedBytes == Size;

        public bool MatchesOffer(string name, long size, int chunks, string sha256)
            => string.Equals(Name, name, StringComparison.Ordinal)
               && Size == size
               && Chunks == chunks
               && string.Equals(Sha256, sha256, StringComparison.OrdinalIgnoreCase);
    }

    private sealed class TransferProtocolException : Exception
    {
        public TransferProtocolException(
            string message,
            bool dropSession,
            string? userFacingText = null,
            Exception? innerException = null)
            : base(message, innerException)
        {
            DropSession = dropSession;
            UserFacingText = userFacingText;
        }

        public bool DropSession { get; }

        public string? UserFacingText { get; }
    }

    private sealed record TransferNotice(string Direction, string Peer, string Text)
    {
        public void Publish(FileTransferManager manager) => manager.Emit(Direction, Peer, Text);
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

        /// <summary>Mandatory SHA-256 digest for the complete file.</summary>
        [JsonPropertyName("sha256")]
        public string? Sha256 { get; set; }
    }
}

internal sealed class FileTransferTestHooks
{
    public Action? BeforeSessionRegistration { get; init; }

    public Action? AfterSessionRegistration { get; init; }
}

internal interface IFileTransferStorage
{
    void CreateDirectory(string path);

    Stream CreateTemporaryFile(string path);

    void SetLength(Stream stream, long length);

    string ComputeSha256(string path);

    FileTransferPublishResult PublishFile(string source, string target);

    void DeleteFile(string path);
}

internal sealed class PhysicalFileTransferStorage : IFileTransferStorage
{
    public static PhysicalFileTransferStorage Instance { get; } = new();

    private PhysicalFileTransferStorage()
    {
    }

    public void CreateDirectory(string path) => Directory.CreateDirectory(path);

    public Stream CreateTemporaryFile(string path)
        => new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None,
            64 * 1024, useAsync: false);

    public void SetLength(Stream stream, long length) => stream.SetLength(length);

    public string ComputeSha256(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    public FileTransferPublishResult PublishFile(string source, string target)
    {
        var directory = Path.GetDirectoryName(target)
            ?? throw new InvalidOperationException("publish target has no directory");
        var partial = Path.Combine(directory, $".specus-{Guid.NewGuid():N}.partial");
        var targetOwned = false;
        FileTransferPublishResult result;
        try
        {
            using (var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var output = new FileStream(
                       partial, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024))
            {
                input.CopyTo(output);
                output.Flush(flushToDisk: true);
            }

            // File.Move without overwrite is the atomic no-replace publication point. A racing
            // target never becomes ours and is handled as a naming conflict below.
            File.Move(partial, target);
            targetOwned = true;
            File.Delete(source);
            result = FileTransferPublishResult.Published();
        }
        catch (IOException) when (!targetOwned && File.Exists(source) && File.Exists(target))
        {
            result = FileTransferPublishResult.Conflict();
        }
        catch (Exception ex)
        {
            result = FileTransferPublishResult.Failed(ex, targetOwned);
        }

        if (File.Exists(partial))
        {
            try
            {
                File.Delete(partial);
            }
            catch
            {
                result = result with { OwnedPartialPath = partial };
            }
        }
        return result;
    }

    public void DeleteFile(string path)
    {
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }
}

internal enum FileTransferPublishStatus
{
    Published,
    Conflict,
    Failed,
}

internal readonly record struct FileTransferPublishResult(
    FileTransferPublishStatus Status,
    bool TargetOwned,
    Exception? Error,
    string? OwnedPartialPath)
{
    public static FileTransferPublishResult Published()
        => new(FileTransferPublishStatus.Published, TargetOwned: true, Error: null, OwnedPartialPath: null);

    public static FileTransferPublishResult Conflict()
        => new(FileTransferPublishStatus.Conflict, TargetOwned: false, Error: null, OwnedPartialPath: null);

    public static FileTransferPublishResult Failed(
        Exception error,
        bool targetOwned,
        string? ownedPartialPath = null)
        => new(FileTransferPublishStatus.Failed, targetOwned, error, ownedPartialPath);
}
