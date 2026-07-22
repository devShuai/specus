using System.Text;
using System.Text.Json;
using ShuaiTunnel.Server.WebSockets;

namespace ShuaiTunnel.IntegrationTests;

public sealed class PublicTransferClusterFrameTests
{
    [Fact]
    public void TextEventMatchesCanonicalVectorAndRoundTrips()
    {
        using var document = JsonDocument.Parse(File.ReadAllText(FindVector()));
        var root = document.RootElement;
        var vector = root.GetProperty("canonicalText");
        var clusterEvent = new PublicTransferClusterEvent(
            vector.GetProperty("kind").GetByte(),
            vector.GetProperty("excludeSource").GetBoolean(),
            vector.GetProperty("revision").GetUInt64(),
            vector.GetProperty("groupId").GetString()!,
            vector.GetProperty("targetPeerId").GetString()!,
            vector.GetProperty("sourceLeaseId").GetString()!,
            Encoding.UTF8.GetBytes(vector.GetProperty("payloadUtf8").GetString()!));

        var encoded = PublicTransferClusterFrame.Encode(clusterEvent);
        Assert.Equal(Convert.FromHexString(vector.GetProperty("frameHex").GetString()!), encoded);

        var decoded = PublicTransferClusterFrame.Decode(encoded);
        Assert.Equal(clusterEvent.Kind, decoded.Kind);
        Assert.Equal(clusterEvent.ExcludeSource, decoded.ExcludeSource);
        Assert.Equal(clusterEvent.Revision, decoded.Revision);
        Assert.Equal(clusterEvent.GroupId, decoded.GroupId);
        Assert.Equal(clusterEvent.TargetPeerId, decoded.TargetPeerId);
        Assert.Equal(clusterEvent.SourceLeaseId, decoded.SourceLeaseId);
        Assert.Equal(clusterEvent.Payload, decoded.Payload);
        Assert.Throws<ArgumentException>(() =>
            PublicTransferClusterFrame.Decode([.. encoded, 0]));

        var derivation = root.GetProperty("groupIdDerivation");
        Assert.Equal(derivation.GetProperty("groupId").GetString(),
            PublicTransferCoordinationService.GroupId(
                derivation.GetProperty("roomId").GetString()!,
                derivation.GetProperty("roomKey").GetString()!));
    }

    [Fact]
    public void BinaryWithoutTargetAndRosterPayloadAreRejected()
    {
        Assert.Throws<ArgumentException>(() => PublicTransferClusterFrame.Encode(
            new PublicTransferClusterEvent(PublicTransferClusterFrame.KindBinary, false, 0,
                "group", string.Empty, string.Empty, [1])));
        Assert.Throws<ArgumentException>(() => PublicTransferClusterFrame.Encode(
            new PublicTransferClusterEvent(PublicTransferClusterFrame.KindRoster, false, 1,
                "group", string.Empty, string.Empty, [1])));
    }

    [Fact]
    public void ManagementEventMatchesCanonicalVectorAndTenantBinding()
    {
        using var document = JsonDocument.Parse(File.ReadAllText(FindVector()));
        var vector = document.RootElement.GetProperty("canonicalManagement");
        var clusterEvent = new PublicTransferClusterEvent(
            vector.GetProperty("kind").GetByte(),
            vector.GetProperty("excludeSource").GetBoolean(),
            vector.GetProperty("revision").GetUInt64(),
            vector.GetProperty("groupId").GetString()!,
            vector.GetProperty("targetPeerId").GetString()!,
            vector.GetProperty("sourceLeaseId").GetString()!,
            Encoding.UTF8.GetBytes(vector.GetProperty("payloadUtf8").GetString()!));

        var encoded = PublicTransferClusterFrame.Encode(clusterEvent);

        Assert.Equal(Convert.FromHexString(vector.GetProperty("frameHex").GetString()!), encoded);
        var decoded = PublicTransferClusterFrame.Decode(encoded);
        Assert.Equal(clusterEvent.Kind, decoded.Kind);
        Assert.Equal(clusterEvent.GroupId, decoded.GroupId);
        Assert.Equal(clusterEvent.Payload, decoded.Payload);
        Assert.Equal(vector.GetProperty("groupId").GetString(),
            PublicTransferCoordinationService.ManagementGroupId(
                vector.GetProperty("tenantId").GetString()));
        Assert.Throws<ArgumentException>(() => PublicTransferClusterFrame.Encode(
            clusterEvent with { TargetPeerId = "unexpected-target" }));
    }

    private static string FindVector()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        for (var depth = 0; directory is not null && depth < 12; depth++, directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, "protocol", "test-vectors",
                "public-transfer-cluster-v2.json");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }
        throw new FileNotFoundException("cannot locate public-transfer-cluster-v2.json");
    }
}
