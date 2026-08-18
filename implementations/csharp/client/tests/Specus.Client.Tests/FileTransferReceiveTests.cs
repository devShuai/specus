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
    public void DuplicateChunkCannotCompleteAFileWithHoles()
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
        Assert.Contains(_events, item => item.Text.StartsWith("文件不完整", StringComparison.Ordinal));
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
}
