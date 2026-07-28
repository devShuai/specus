using System.Buffers.Binary;
using System.Text.Json;
using Specus.Server.PeerMesh;

namespace Specus.IntegrationTests;

public sealed class PeerDataFrameHeaderTests
{
    [Fact]
    public void ParseSupportsOnlySpm2AndRejectsZeroSequence()
    {
        using var vector = JsonDocument.Parse(File.ReadAllText(FindVector()));
        var root = vector.RootElement;
        var frame = Convert.FromHexString(root.GetProperty("frameHex").GetString()!);
        var sessionId = root.GetProperty("sessionId").GetInt64();
        var sequence = root.GetProperty("sequence").GetInt64();

        Assert.Equal(new PeerDataFrameHeader(sessionId, sequence), PeerDataFrameHeader.Parse(frame));
        Assert.True(PeerDataFrameHeader.LooksLikeDataFrame(frame));

        frame.AsSpan(12, 8).Clear();
        Assert.Null(PeerDataFrameHeader.Parse(frame));
    }

    private static string FindVector()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        for (var depth = 0; directory is not null && depth < 12; depth++, directory = directory.Parent)
        {
            var candidate = Path.Combine(
                directory.FullName, "protocol", "test-vectors", "peer-mesh-spm2.json");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }
        throw new FileNotFoundException("cannot locate peer-mesh-spm2.json");
    }

    [Fact]
    public void ParseRejectsRemovedSpm1Frame()
    {
        var frame = new byte[70];
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(0, 4), 0x53504d31);

        Assert.False(PeerDataFrameHeader.LooksLikeDataFrame(frame));
        Assert.Null(PeerDataFrameHeader.Parse(frame));
    }
}
