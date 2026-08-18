using System.Security.Cryptography;
using System.Text;
using Specus.Client.Desktop;

namespace Specus.Client.Tests;

/// <summary>
/// The STXFER1 receive path treats the peer as untrusted. These cases pin the properties an
/// attacker or a lossy transport would otherwise break: path containment, sender isolation,
/// idempotent retries, and completion only on a verified whole file.
/// </summary>
public sealed class FileTransferReceiveTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(),
        "specus-transfer-tests-" + Guid.NewGuid().ToString("N"));
    private readonly FileTransferManager _manager;
    private readonly List<(string Direction, string Peer, string Text)> _events = [];

    public FileTransferReceiveTests()
    {
        Directory.CreateDirectory(_root);
        _manager = new FileTransferManager(_root);
        _manager.TransferEvent += (direction, peer, text) => _events.Add((direction, peer, text));
    }

    public void Dispose()
    {
        _manager.Dispose();
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (IOException)
        {
            // Best effort cleanup.
        }
    }

    private string DownloadsDirectory => Path.Combine(_root, "downloads");

    private static string Digest(byte[] payload) =>
        Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();

    private void SendOffer(string from, string id, string name, byte[] payload, string? digest = null)
    {
        var chunks = (payload.Length + FileTransferManager.ChunkBytes - 1) / FileTransferManager.ChunkBytes;
        _manager.OnIncomingMessage(from,
            FileTransferManager.BuildOffer(id, name, payload.Length, chunks, digest ?? Digest(payload)));
    }

    private void SendChunks(string from, string id, byte[] payload)
    {
        for (var offset = 0; offset < payload.Length; offset += FileTransferManager.ChunkBytes)
        {
            var length = Math.Min(FileTransferManager.ChunkBytes, payload.Length - offset);
            var slice = payload.AsSpan(offset, length).ToArray();
            _manager.OnIncomingMessage(from,
                FileTransferManager.BuildChunk(id, offset / FileTransferManager.ChunkBytes, slice, length));
        }
    }

    private void SendChunk(string from, string id, byte[] payload, int sequence)
    {
        var offset = sequence * FileTransferManager.ChunkBytes;
        var length = Math.Min(FileTransferManager.ChunkBytes, payload.Length - offset);
        var slice = payload.AsSpan(offset, length).ToArray();
        _manager.OnIncomingMessage(from,
            FileTransferManager.BuildChunk(id, sequence, slice, length));
    }

    private static byte[] Payload(int size)
    {
        var payload = new byte[size];
        for (var index = 0; index < size; index++)
        {
            payload[index] = (byte)(index % 251);
        }
        return payload;
    }

    [Fact]
    public void DeliversFileAndVerifiesDigest()
    {
        var payload = Payload(1500);
        SendOffer("alice", "t1", "report.bin", payload);
        SendChunks("alice", "t1", payload);
        _manager.OnIncomingMessage("alice", FileTransferManager.BuildDone("t1"));

        var saved = Directory.GetFiles(DownloadsDirectory);
        Assert.Single(saved);
        Assert.Equal(payload, File.ReadAllBytes(saved[0]));
        Assert.Contains(_events, item => item.Text.StartsWith("已接收", StringComparison.Ordinal));
    }

    [Fact]
    public void AcceptsZeroByteFile()
    {
        var payload = Array.Empty<byte>();
        SendOffer("alice", "empty", "empty.txt", payload);
        _manager.OnIncomingMessage("alice", FileTransferManager.BuildDone("empty"));

        var saved = Directory.GetFiles(DownloadsDirectory);
        Assert.Single(saved);
        Assert.Empty(File.ReadAllBytes(saved[0]));
    }

    [Fact]
    public void DuplicateChunksAndRepeatedDoneDoNotCorruptOrDoubleDeliver()
    {
        var payload = Payload(1500);
        SendOffer("alice", "dup", "dup.bin", payload);
        SendChunks("alice", "dup", payload);
        // The transport falls back to the server when a peer ACK is lost, so the same chunks and
        // the same "done" arrive twice.
        SendChunks("alice", "dup", payload);
        _manager.OnIncomingMessage("alice", FileTransferManager.BuildDone("dup"));
        _manager.OnIncomingMessage("alice", FileTransferManager.BuildDone("dup"));

        var saved = Directory.GetFiles(DownloadsDirectory);
        Assert.Single(saved);
        Assert.Equal(payload, File.ReadAllBytes(saved[0]));
    }

    [Fact]
    public void DoneWithHolesWaitsForMissingChunksInsteadOfPublishingOrDroppingTheSession()
    {
        var payload = Payload(1800);
        SendOffer("alice", "holes", "holes.bin", payload);
        // Deliver chunk 0 three times and never send chunks 1 and 2: a naive counter would reach
        // the expected chunk count and publish a file full of zeroes.
        var first = payload.AsSpan(0, FileTransferManager.ChunkBytes).ToArray();
        for (var attempt = 0; attempt < 3; attempt++)
        {
            _manager.OnIncomingMessage("alice",
                FileTransferManager.BuildChunk("holes", 0, first, first.Length));
        }
        _manager.OnIncomingMessage("alice", FileTransferManager.BuildDone("holes"));

        Assert.False(Directory.Exists(DownloadsDirectory) && Directory.GetFiles(DownloadsDirectory).Length > 0);
        Assert.Equal(1, _manager.IncomingSessionCount);
        Assert.DoesNotContain(_events, item => item.Text.StartsWith("已接收", StringComparison.Ordinal));

        // A missing fallback chunk may arrive after done and must be allowed to complete normally.
        SendChunk("alice", "holes", payload, 1);
        SendChunk("alice", "holes", payload, 2);
        var saved = Directory.GetFiles(DownloadsDirectory);
        Assert.Single(saved);
        Assert.Equal(payload, File.ReadAllBytes(saved[0]));
    }

    [Fact]
    public void SessionsAreIsolatedPerAuthenticatedSender()
    {
        var alicePayload = Payload(900);
        var mallory = Encoding.UTF8.GetBytes(new string('x', 900));
        SendOffer("alice", "shared-id", "alice.bin", alicePayload);
        // Mallory reuses Alice's transfer id; it must open a separate session rather than write
        // into Alice's file.
        SendOffer("mallory", "shared-id", "mallory.bin", mallory);
        SendChunks("mallory", "shared-id", mallory);
        SendChunks("alice", "shared-id", alicePayload);
        _manager.OnIncomingMessage("alice", FileTransferManager.BuildDone("shared-id"));
        _manager.OnIncomingMessage("mallory", FileTransferManager.BuildDone("shared-id"));

        var saved = Directory.GetFiles(DownloadsDirectory).OrderBy(path => path).ToList();
        Assert.Equal(2, saved.Count);
        var aliceFile = saved.Single(path => Path.GetFileName(path).StartsWith("alice", StringComparison.Ordinal));
        Assert.Equal(alicePayload, File.ReadAllBytes(aliceFile));
    }

    [Fact]
    public void RejectsChunkWhoseLengthDoesNotMatchTheOffer()
    {
        var payload = Payload(1500);
        SendOffer("alice", "short", "short.bin", payload);
        var truncated = payload.AsSpan(0, 10).ToArray();
        _manager.OnIncomingMessage("alice",
            FileTransferManager.BuildChunk("short", 0, truncated, truncated.Length));

        Assert.Contains(_events, item => item.Text.StartsWith("文件接收失败", StringComparison.Ordinal));
        _manager.OnIncomingMessage("alice", FileTransferManager.BuildDone("short"));
        Assert.False(Directory.Exists(DownloadsDirectory) && Directory.GetFiles(DownloadsDirectory).Length > 0);
    }

    [Fact]
    public void RejectsFileWhoseDigestDoesNotMatch()
    {
        var payload = Payload(1200);
        var tampered = Payload(1200);
        tampered[0] ^= 0xFF;
        SendOffer("alice", "tamper", "tamper.bin", payload, Digest(payload));
        SendChunks("alice", "tamper", tampered);
        _manager.OnIncomingMessage("alice", FileTransferManager.BuildDone("tamper"));

        Assert.Contains(_events, item => item.Text.StartsWith("文件校验失败", StringComparison.Ordinal));
        Assert.False(Directory.Exists(DownloadsDirectory) && Directory.GetFiles(DownloadsDirectory).Length > 0);
    }

    [Fact]
    public void RejectsOfferWithoutMandatoryDigest()
    {
        var payload = Payload(600);
        _manager.OnIncomingMessage("alice",
            FileTransferManager.BuildOffer("no-digest", "unsafe.bin", payload.Length, 1, null));

        Assert.Equal(0, _manager.IncomingSessionCount);
        Assert.Equal(0, _manager.PendingBytes);
        Assert.Contains(_events, item => item.Text.Contains("invalid digest", StringComparison.Ordinal));
    }

    [Fact]
    public void RejectsOversizedRawFrameBeforeJsonDeserializationOrSessionCreation()
    {
        var oversized = FileTransferManager.Prefix
            + "{\"t\":\"offer\",\"id\":\"large\",\"name\":\""
            + new string('x', FileTransferManager.MaxFrameCharacters)
            + "\"}";

        Assert.True(_manager.OnIncomingMessage("alice", oversized));
        Assert.Equal(0, _manager.IncomingSessionCount);
        Assert.Equal(0, _manager.PendingBytes);
        Assert.Empty(_events);
    }

    [Theory]
    [InlineData("")]
    [InlineData("abc")]
    [InlineData("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")]
    public void RejectsMalformedDigest(string digest)
    {
        var payload = Payload(600);
        _manager.OnIncomingMessage("alice",
            FileTransferManager.BuildOffer("bad-digest", "unsafe.bin", payload.Length, 1, digest));

        Assert.Equal(0, _manager.IncomingSessionCount);
        Assert.Equal(0, _manager.PendingBytes);
    }

    [Fact]
    public void IdenticalFallbackOfferIsIdempotentAndEarlyDoneCompletesAfterRemainingChunks()
    {
        var payload = Payload(1500);
        SendOffer("alice", "fallback", "fallback.bin", payload);
        SendChunk("alice", "fallback", payload, 0);

        // The direct copy made progress, then the server fallback delivered the same offer and a
        // done frame before its remaining chunks. Neither frame may reset or discard the session.
        SendOffer("alice", "fallback", "fallback.bin", payload);
        _manager.OnIncomingMessage("alice", FileTransferManager.BuildDone("fallback"));
        SendChunk("alice", "fallback", payload, 1);
        SendChunk("alice", "fallback", payload, 2);

        var saved = Directory.GetFiles(DownloadsDirectory);
        Assert.Single(saved);
        Assert.Equal(payload, File.ReadAllBytes(saved[0]));
        Assert.Equal(0, _manager.IncomingSessionCount);
        Assert.Equal(0, _manager.PendingBytes);
    }

    [Fact]
    public void DoneBeforeOfferIsRememberedAndFinalizesWhenChunksArrive()
    {
        var payload = Payload(900);
        _manager.OnIncomingMessage("alice", FileTransferManager.BuildDone("done-first"));
        SendOffer("alice", "done-first", "done-first.bin", payload);
        SendChunks("alice", "done-first", payload);

        var saved = Directory.GetFiles(DownloadsDirectory);
        Assert.Single(saved);
        Assert.Equal(payload, File.ReadAllBytes(saved[0]));
    }

    [Fact]
    public void ConflictingOfferDoesNotResetOriginalSession()
    {
        var payload = Payload(1200);
        SendOffer("alice", "conflict", "original.bin", payload);
        SendChunk("alice", "conflict", payload, 0);

        _manager.OnIncomingMessage("alice",
            FileTransferManager.BuildOffer(
                "conflict",
                "replacement.bin",
                payload.Length,
                2,
                Digest(payload)));

        Assert.Equal(1, _manager.IncomingSessionCount);
        SendChunk("alice", "conflict", payload, 1);
        _manager.OnIncomingMessage("alice", FileTransferManager.BuildDone("conflict"));

        var saved = Directory.GetFiles(DownloadsDirectory);
        Assert.Single(saved);
        Assert.Equal("original.bin", Path.GetFileName(saved[0]));
        Assert.Equal(payload, File.ReadAllBytes(saved[0]));
    }

    [Fact]
    public void CompletedTombstoneConsumesEveryDelayedFrame()
    {
        var payload = Payload(600);
        SendOffer("alice", "complete", "only-once.bin", payload);
        SendChunks("alice", "complete", payload);
        _manager.OnIncomingMessage("alice", FileTransferManager.BuildDone("complete"));

        SendOffer("alice", "complete", "duplicate.bin", payload);
        SendChunks("alice", "complete", payload);
        _manager.OnIncomingMessage("alice", FileTransferManager.BuildDone("complete"));
        _manager.OnIncomingMessage("alice", FileTransferManager.BuildAbort("complete", "late"));

        var saved = Directory.GetFiles(DownloadsDirectory);
        Assert.Single(saved);
        Assert.Equal("only-once.bin", Path.GetFileName(saved[0]));
        Assert.Equal(0, _manager.IncomingSessionCount);
    }

    [Fact]
    public void AnotherSenderCannotFloodOutACompletedTransferTombstone()
    {
        var payload = Payload(600);
        SendOffer("alice", "protected", "protected.bin", payload);
        SendChunks("alice", "protected", payload);
        _manager.OnIncomingMessage("alice", FileTransferManager.BuildDone("protected"));

        for (var index = 0; index < 600; index++)
        {
            _manager.OnIncomingMessage("bob",
                FileTransferManager.BuildAbort("flood-" + index, "noise"));
        }

        SendOffer("alice", "protected", "duplicate.bin", payload);
        SendChunks("alice", "protected", payload);
        _manager.OnIncomingMessage("alice", FileTransferManager.BuildDone("protected"));

        var saved = Directory.GetFiles(DownloadsDirectory);
        Assert.Single(saved);
        Assert.Equal("protected.bin", Path.GetFileName(saved[0]));
        Assert.Equal(payload, File.ReadAllBytes(saved[0]));
    }

    [Fact]
    public void GlobalTerminalFloodCannotConsumeAnActiveSessionsReservedTombstone()
    {
        var payload = Payload(600);
        SendOffer("alice", "reserved", "reserved.bin", payload);
        SendChunks("alice", "reserved", payload);

        for (var index = 0; index < 600; index++)
        {
            _manager.OnIncomingMessage("flooder-" + index,
                FileTransferManager.BuildAbort("noise", "noise"));
        }

        _manager.OnIncomingMessage("alice", FileTransferManager.BuildDone("reserved"));
        SendOffer("alice", "reserved", "duplicate.bin", payload);
        SendChunks("alice", "reserved", payload);
        _manager.OnIncomingMessage("alice", FileTransferManager.BuildDone("reserved"));

        var saved = Directory.GetFiles(DownloadsDirectory);
        Assert.Single(saved);
        Assert.Equal("reserved.bin", Path.GetFileName(saved[0]));
        Assert.Equal(payload, File.ReadAllBytes(saved[0]));
    }

    [Fact]
    public void AbortLeavesTombstoneThatConsumesDelayedFallbackOffer()
    {
        var payload = Payload(600);
        SendOffer("alice", "aborted", "aborted.bin", payload);
        _manager.OnIncomingMessage("alice", FileTransferManager.BuildAbort("aborted", "cancel"));

        SendOffer("alice", "aborted", "late.bin", payload);
        SendChunks("alice", "aborted", payload);
        _manager.OnIncomingMessage("alice", FileTransferManager.BuildDone("aborted"));

        Assert.Equal(0, _manager.IncomingSessionCount);
        Assert.Equal(0, _manager.PendingBytes);
        Assert.False(Directory.Exists(DownloadsDirectory) && Directory.GetFiles(DownloadsDirectory).Length > 0);
    }

    [Fact]
    public void StructuredSessionKeyCannotCollideOnEmbeddedDelimiters()
    {
        var first = Payload(600);
        var second = Encoding.UTF8.GetBytes(new string('z', 600));
        SendOffer("a", "b\0c", "first.bin", first);
        SendOffer("a\0b", "c", "second.bin", second);
        SendChunks("a", "b\0c", first);
        SendChunks("a\0b", "c", second);
        _manager.OnIncomingMessage("a", FileTransferManager.BuildDone("b\0c"));
        _manager.OnIncomingMessage("a\0b", FileTransferManager.BuildDone("c"));

        var saved = Directory.GetFiles(DownloadsDirectory);
        Assert.Equal(2, saved.Length);
        Assert.Equal(first, File.ReadAllBytes(saved.Single(path => Path.GetFileName(path) == "first.bin")));
        Assert.Equal(second, File.ReadAllBytes(saved.Single(path => Path.GetFileName(path) == "second.bin")));
    }

    [Fact]
    public void CaseDistinctAuthenticatedSendersRemainIsolated()
    {
        var lowerPayload = Payload(600);
        var upperPayload = Encoding.UTF8.GetBytes(new string('U', 600));
        SendOffer("alice", "same-id", "lower.bin", lowerPayload);
        SendOffer("ALICE", "same-id", "upper.bin", upperPayload);
        SendChunks("alice", "same-id", lowerPayload);
        SendChunks("ALICE", "same-id", upperPayload);
        _manager.OnIncomingMessage("alice", FileTransferManager.BuildDone("same-id"));
        _manager.OnIncomingMessage("ALICE", FileTransferManager.BuildDone("same-id"));

        var saved = Directory.GetFiles(DownloadsDirectory);
        Assert.Equal(2, saved.Length);
        Assert.Equal(lowerPayload, File.ReadAllBytes(saved.Single(path => Path.GetFileName(path) == "lower.bin")));
        Assert.Equal(upperPayload, File.ReadAllBytes(saved.Single(path => Path.GetFileName(path) == "upper.bin")));
    }

    [Fact]
    public void RejectsOfferWhoseChunkCountDisagreesWithTheSize()
    {
        var payload = Payload(1500);
        _manager.OnIncomingMessage("alice",
            FileTransferManager.BuildOffer("bad", "bad.bin", payload.Length, 1, Digest(payload)));

        Assert.Contains(_events, item => item.Text.StartsWith("文件接收失败", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("../../escape.txt", "escape.txt")]
    [InlineData("..\\..\\escape.txt", "escape.txt")]
    [InlineData("/etc/passwd", "passwd")]
    [InlineData("C:\\Windows\\System32\\evil.dll", "evil.dll")]
    [InlineData("..", "file")]
    [InlineData("", "file")]
    [InlineData("   ", "file")]
    public void SanitizeNameReducesPeerInputToABareFileName(string input, string expected)
    {
        Assert.Equal(expected, FileTransferManager.SanitizeName(input));
    }

    [Fact]
    public void RemoteIdAndNameNeverEscapeTheDownloadDirectory()
    {
        var payload = Payload(600);
        // Both the transfer id and the file name attempt traversal.
        SendOffer("alice", "../../../evil", "../../../evil.bin", payload);
        SendChunks("alice", "../../../evil", payload);
        _manager.OnIncomingMessage("alice", FileTransferManager.BuildDone("../../../evil"));

        var saved = Directory.GetFiles(DownloadsDirectory);
        Assert.Single(saved);
        Assert.Equal("evil.bin", Path.GetFileName(saved[0]));
        Assert.StartsWith(Path.GetFullPath(DownloadsDirectory), Path.GetFullPath(saved[0]), StringComparison.Ordinal);
    }

    [Fact]
    public void BoundsConcurrentSessions()
    {
        var payload = Payload(600);
        for (var index = 0; index < FileTransferManager.MaxConcurrentSessions; index++)
        {
            SendOffer("alice", "session-" + index, "file-" + index + ".bin", payload);
        }
        _events.Clear();
        SendOffer("alice", "one-too-many", "overflow.bin", payload);

        Assert.Contains(_events, item => item.Text.Contains("接收会话过多", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(FailurePoint.Open)]
    [InlineData(FailurePoint.SetLength)]
    [InlineData(FailurePoint.BeforeRegistration)]
    [InlineData(FailurePoint.AfterRegistration)]
    public void OfferSetupFailureReleasesHandleTempFileSessionAndPendingBytes(FailurePoint point)
    {
        var root = Path.Combine(_root, "fault-" + point);
        var storage = new FaultInjectingStorage(point);
        var hooks = new FileTransferTestHooks
        {
            BeforeSessionRegistration = point == FailurePoint.BeforeRegistration
                ? () => throw new IOException("before registration")
                : null,
            AfterSessionRegistration = point == FailurePoint.AfterRegistration
                ? () => throw new IOException("after registration")
                : null,
        };
        using var manager = new FileTransferManager(root, storage, hooks);
        var payload = Payload(600);

        manager.OnIncomingMessage("alice",
            FileTransferManager.BuildOffer("fault", "fault.bin", payload.Length, 1, Digest(payload)));

        Assert.Equal(0, manager.IncomingSessionCount);
        Assert.Equal(0, manager.PendingBytes);
        Assert.Empty(Directory.Exists(root)
            ? Directory.GetFiles(root, "*.part", SearchOption.AllDirectories)
            : []);
    }

    [Fact]
    public void FinalMoveFailureDeletesDestinationTempFileAndReleasesRegistration()
    {
        var root = Path.Combine(_root, "fault-finalize");
        var storage = new FaultInjectingStorage(FailurePoint.MoveAfterTargetCreated);
        using var manager = new FileTransferManager(root, storage);
        var payload = Payload(600);
        manager.OnIncomingMessage("alice",
            FileTransferManager.BuildOffer("move", "move.bin", payload.Length, 1, Digest(payload)));
        manager.OnIncomingMessage("alice",
            FileTransferManager.BuildChunk("move", 0, payload, payload.Length));
        manager.OnIncomingMessage("alice", FileTransferManager.BuildDone("move"));

        Assert.Equal(0, manager.IncomingSessionCount);
        Assert.Equal(0, manager.PendingBytes);
        Assert.Empty(Directory.Exists(root)
            ? Directory.GetFiles(root, "*", SearchOption.AllDirectories)
            : []);
    }

    [Fact]
    public void PublishRacePreservesExternalTargetAndRetriesWithAnotherName()
    {
        var root = Path.Combine(_root, "publish-race");
        var storage = new FaultInjectingStorage(FailurePoint.ExternalPublishConflict);
        using var manager = new FileTransferManager(root, storage);
        var payload = Payload(600);
        manager.OnIncomingMessage("alice",
            FileTransferManager.BuildOffer("race", "race.bin", payload.Length, 1, Digest(payload)));
        manager.OnIncomingMessage("alice",
            FileTransferManager.BuildChunk("race", 0, payload, payload.Length));
        manager.OnIncomingMessage("alice", FileTransferManager.BuildDone("race"));

        var downloads = Path.Combine(root, "downloads");
        var external = Path.Combine(downloads, "race.bin");
        var delivered = Path.Combine(downloads, "race (1).bin");
        Assert.Equal(FaultInjectingStorage.ExternalContent, File.ReadAllBytes(external));
        Assert.Equal(payload, File.ReadAllBytes(delivered));
        Assert.Equal(0, manager.IncomingSessionCount);
        Assert.Equal(0, manager.PendingBytes);
    }

    [Fact]
    public void OwnedPublishPartialFailureCleansOnlyOwnedPartialAndSourceTemp()
    {
        var root = Path.Combine(_root, "owned-publish-partial");
        var storage = new FaultInjectingStorage(FailurePoint.OwnedPublishPartial);
        using var manager = new FileTransferManager(root, storage);
        var payload = Payload(600);
        manager.OnIncomingMessage("alice",
            FileTransferManager.BuildOffer("partial", "partial.bin", payload.Length, 1, Digest(payload)));
        manager.OnIncomingMessage("alice",
            FileTransferManager.BuildChunk("partial", 0, payload, payload.Length));
        manager.OnIncomingMessage("alice", FileTransferManager.BuildDone("partial"));

        Assert.Equal(0, manager.IncomingSessionCount);
        Assert.Equal(0, manager.PendingBytes);
        Assert.Empty(Directory.Exists(root)
            ? Directory.GetFiles(root, "*", SearchOption.AllDirectories)
            : []);
    }

    [Fact]
    public void FinalDisposeFailureIsRetriedBeforeTempFileAndAccountingAreReleased()
    {
        var root = Path.Combine(_root, "fault-dispose");
        var storage = new FaultInjectingStorage(FailurePoint.DisposeOnce);
        using var manager = new FileTransferManager(root, storage);
        var payload = Payload(600);
        manager.OnIncomingMessage("alice",
            FileTransferManager.BuildOffer("dispose", "dispose.bin", payload.Length, 1, Digest(payload)));
        manager.OnIncomingMessage("alice",
            FileTransferManager.BuildChunk("dispose", 0, payload, payload.Length));
        manager.OnIncomingMessage("alice", FileTransferManager.BuildDone("dispose"));

        Assert.True(storage.DisposeAttempts >= 2);
        Assert.Equal(0, manager.IncomingSessionCount);
        Assert.Equal(0, manager.PendingBytes);
        Assert.Empty(Directory.Exists(root)
            ? Directory.GetFiles(root, "*", SearchOption.AllDirectories)
            : []);
    }

    [Theory]
    [InlineData(FailurePoint.Write)]
    [InlineData(FailurePoint.Digest)]
    public void WriteOrDigestFailureDropsSessionAndReleasesAllResources(FailurePoint point)
    {
        var root = Path.Combine(_root, "fault-" + point);
        var storage = new FaultInjectingStorage(point);
        using var manager = new FileTransferManager(root, storage);
        var payload = Payload(600);
        manager.OnIncomingMessage("alice",
            FileTransferManager.BuildOffer("io", "io.bin", payload.Length, 1, Digest(payload)));
        manager.OnIncomingMessage("alice",
            FileTransferManager.BuildChunk("io", 0, payload, payload.Length));
        manager.OnIncomingMessage("alice", FileTransferManager.BuildDone("io"));

        Assert.Equal(0, manager.IncomingSessionCount);
        Assert.Equal(0, manager.PendingBytes);
        Assert.Empty(Directory.Exists(root)
            ? Directory.GetFiles(root, "*", SearchOption.AllDirectories)
            : []);
    }

    [Fact]
    public void ConcurrentDoneAndChunksPublishExactlyOneVerifiedFile()
    {
        var payload = Payload(1800);
        SendOffer("alice", "parallel", "parallel.bin", payload);
        var frames = Enumerable.Range(0, 3)
            .Select(sequence =>
            {
                var offset = sequence * FileTransferManager.ChunkBytes;
                var slice = payload.AsSpan(offset, FileTransferManager.ChunkBytes).ToArray();
                return FileTransferManager.BuildChunk("parallel", sequence, slice, slice.Length);
            })
            .Append(FileTransferManager.BuildDone("parallel"))
            .ToArray();

        Parallel.ForEach(frames, frame => _manager.OnIncomingMessage("alice", frame));

        var saved = Directory.GetFiles(DownloadsDirectory);
        Assert.Single(saved);
        Assert.Equal(payload, File.ReadAllBytes(saved[0]));
        Assert.Equal(0, _manager.IncomingSessionCount);
    }

    public enum FailurePoint
    {
        None,
        Open,
        SetLength,
        BeforeRegistration,
        AfterRegistration,
        MoveAfterTargetCreated,
        DisposeOnce,
        Write,
        Digest,
        ExternalPublishConflict,
        OwnedPublishPartial,
    }

    private sealed class FaultInjectingStorage(FailurePoint point) : IFileTransferStorage
    {
        private readonly IFileTransferStorage _inner = PhysicalFileTransferStorage.Instance;
        private bool _publishConflictInjected;

        public static byte[] ExternalContent { get; } = Encoding.UTF8.GetBytes("external owner");

        public int DisposeAttempts { get; private set; }

        public void CreateDirectory(string path) => _inner.CreateDirectory(path);

        public Stream CreateTemporaryFile(string path)
        {
            if (point == FailurePoint.Open)
            {
                throw new IOException("open failure");
            }
            var stream = _inner.CreateTemporaryFile(path);
            return point is FailurePoint.DisposeOnce or FailurePoint.Write
                ? new FaultingStream(stream, point, () => DisposeAttempts++)
                : stream;
        }

        public void SetLength(Stream stream, long length)
        {
            if (point == FailurePoint.SetLength)
            {
                throw new IOException("set length failure");
            }
            _inner.SetLength(stream, length);
        }

        public string ComputeSha256(string path)
        {
            if (point == FailurePoint.Digest)
            {
                throw new IOException("digest failure");
            }
            return _inner.ComputeSha256(path);
        }

        public FileTransferPublishResult PublishFile(string source, string target)
        {
            if (point == FailurePoint.OwnedPublishPartial)
            {
                var partial = Path.Combine(
                    Path.GetDirectoryName(target)!,
                    ".owned-by-transfer.partial");
                File.WriteAllBytes(partial, [1, 2, 3]);
                return FileTransferPublishResult.Failed(
                    new IOException("owned partial failure"),
                    targetOwned: false,
                    ownedPartialPath: partial);
            }
            if (point == FailurePoint.ExternalPublishConflict && !_publishConflictInjected)
            {
                _publishConflictInjected = true;
                File.WriteAllBytes(target, ExternalContent);
                return _inner.PublishFile(source, target);
            }

            var result = _inner.PublishFile(source, target);
            if (point == FailurePoint.MoveAfterTargetCreated
                && result.Status == FileTransferPublishStatus.Published)
            {
                return FileTransferPublishResult.Failed(
                    new IOException("move reported failure after creating target"),
                    targetOwned: true);
            }
            return result;
        }

        public void DeleteFile(string path) => _inner.DeleteFile(path);
    }

    private sealed class FaultingStream(Stream inner, FailurePoint point, Action onDispose) : Stream
    {
        private bool _thrown;

        public override bool CanRead => inner.CanRead;

        public override bool CanSeek => inner.CanSeek;

        public override bool CanWrite => inner.CanWrite;

        public override long Length => inner.Length;

        public override long Position
        {
            get => inner.Position;
            set => inner.Position = value;
        }

        public override void Flush() => inner.Flush();

        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);

        public override long Seek(long offset, SeekOrigin origin) => inner.Seek(offset, origin);

        public override void SetLength(long value) => inner.SetLength(value);

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (point == FailurePoint.Write)
            {
                throw new IOException("write failure");
            }
            inner.Write(buffer, offset, count);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                onDispose();
                if (point == FailurePoint.DisposeOnce && !_thrown)
                {
                    _thrown = true;
                    throw new IOException("first dispose failure");
                }
                inner.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
