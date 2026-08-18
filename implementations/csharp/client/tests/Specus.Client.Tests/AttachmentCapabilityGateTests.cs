using Specus.Client.Configuration;
using Specus.Client.Desktop;
using Specus.Client.PeerMesh;

namespace Specus.Client.Tests;

public sealed class AttachmentCapabilityGateTests
{
    [Fact]
    public void AllowsFileWithinAuthoritativeTargetLimit()
    {
        var rejection = PeerMeshClient.AttachmentTransferRejectionReason(
            targetKnown: true,
            online: true,
            receiveMessages: true,
            attachments: true,
            maxAttachmentBytes: ClientMessageCapabilities.DesktopMaxAttachmentBytes,
            sizeBytes: 1024);

        Assert.Null(rejection);
    }

    [Fact]
    public void RejectsJavaOrLegacyTargetWithoutAttachmentCapability()
    {
        var rejection = PeerMeshClient.AttachmentTransferRejectionReason(
            targetKnown: true,
            online: true,
            receiveMessages: true,
            attachments: false,
            maxAttachmentBytes: 0,
            sizeBytes: 0);

        Assert.Contains("不支持文件互传", rejection, StringComparison.Ordinal);
    }

    [Fact]
    public void RejectsFileAboveTargetAdvertisedLimit()
    {
        var rejection = PeerMeshClient.AttachmentTransferRejectionReason(
            targetKnown: true,
            online: true,
            receiveMessages: true,
            attachments: true,
            maxAttachmentBytes: 600,
            sizeBytes: 601);

        Assert.Contains("接收上限", rejection, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    public void RejectsUnknownOrOfflineTarget(bool known, bool online)
    {
        var rejection = PeerMeshClient.AttachmentTransferRejectionReason(
            targetKnown: known,
            online: online,
            receiveMessages: true,
            attachments: true,
            maxAttachmentBytes: 1024,
            sizeBytes: 1);

        Assert.Contains("不在线或能力信息不可用", rejection, StringComparison.Ordinal);
    }

    [Fact]
    public async Task FileSenderRunsCapabilityGateBeforeEmittingFirstFrame()
    {
        var root = Path.Combine(Path.GetTempPath(), "specus-capability-gate-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var file = Path.Combine(root, "payload.bin");
        await File.WriteAllBytesAsync(file, new byte[32]);
        using var manager = new FileTransferManager(root);
        var sentFrames = 0;

        await Assert.ThrowsAsync<InvalidOperationException>(() => manager.SendFileAsync(
            "java-client",
            file,
            (_, _) => throw new InvalidOperationException("attachments unsupported"),
            (_, _, _) =>
            {
                Interlocked.Increment(ref sentFrames);
                return Task.CompletedTask;
            },
            CancellationToken.None));

        Assert.Equal(0, sentFrames);
        Directory.Delete(root, recursive: true);
    }

    [Fact]
    public async Task FileSenderRechecksCapabilityAfterHashAndSendsNeitherOfferNorAbortWhenRevoked()
    {
        var root = Path.Combine(Path.GetTempPath(), "specus-capability-recheck-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var file = Path.Combine(root, "payload.bin");
        await File.WriteAllBytesAsync(file, new byte[32]);
        using var manager = new FileTransferManager(root);
        var gateCalls = 0;
        var sentFrames = 0;

        await Assert.ThrowsAsync<InvalidOperationException>(() => manager.SendFileAsync(
            "desktop-client",
            file,
            (_, _) =>
            {
                if (Interlocked.Increment(ref gateCalls) == 2)
                {
                    throw new InvalidOperationException("capability revoked");
                }
            },
            (_, _, _) =>
            {
                Interlocked.Increment(ref sentFrames);
                return Task.CompletedTask;
            },
            CancellationToken.None));

        Assert.Equal(2, gateCalls);
        Assert.Equal(0, sentFrames);
        Directory.Delete(root, recursive: true);
    }

    [Fact]
    public void ExactTargetSelectionDoesNotMergeCaseDistinctAuthenticatedClients()
    {
        string[] authenticatedNames = ["alice", "ALICE"];

        var selected = authenticatedNames.Single(name =>
            PeerMeshClient.ExactAuthenticatedClientName(name, "ALICE"));

        Assert.Equal("ALICE", selected);
        Assert.False(PeerMeshClient.ExactAuthenticatedClientName("alice", "ALICE"));
    }
}
