using System.Text;
using Specus.Client.PeerMesh;

namespace Specus.Client.Tests;

public sealed class PeerAppMessageCodecTests
{
    [Fact]
    public void OrdinaryTextUsesMandatoryStmsg2WireFormat()
    {
        var message = new PeerAppMessage
        {
            Type = PeerAppMessageCodec.TypeMessage,
            Id = "message-1",
            FromClientId = 1,
            FromClientName = "csharp-a",
            ToClientId = 2,
            ToClientName = "java-or-go",
            Message = "hello",
            CreatedAtMillis = 1234,
        };

        var payload = PeerAppMessageCodec.Encode(message);

        Assert.Equal("STMSG2\n", Encoding.ASCII.GetString(payload, 0, 7));
        Assert.True(PeerAppMessageCodec.TryDecode(payload, out var decoded));
        Assert.Equal("message-1", decoded.Id);
        Assert.Equal("hello", decoded.Message);
        Assert.Null(decoded.Attachment);
    }

    [Fact]
    public void Stmsg2AttachmentExtensionRoundTrips()
    {
        var message = new PeerAppMessage
        {
            Type = PeerAppMessageCodec.TypeMessage,
            Id = "message-2",
            Message = "report",
            Attachment = new PeerAppAttachment
            {
                ObjectId = "object-1",
                AttachmentId = 22,
                FileName = "report.pdf",
                MimeType = "application/pdf",
                SizeBytes = 4096,
                Sha256 = "abc123",
            },
        };

        var payload = PeerAppMessageCodec.Encode(message);

        Assert.Equal("STMSG2\n", Encoding.ASCII.GetString(payload, 0, 7));
        Assert.True(PeerAppMessageCodec.TryDecode(payload, out var decoded));
        Assert.NotNull(decoded.Attachment);
        Assert.Equal("object-1", decoded.Attachment.ObjectId);
        Assert.Equal(22, decoded.Attachment.AttachmentId);
        Assert.Equal("report.pdf", decoded.Attachment.FileName);
        Assert.Equal("application/pdf", decoded.Attachment.MimeType);
        Assert.Equal(4096, decoded.Attachment.SizeBytes);
        Assert.Equal("abc123", decoded.Attachment.Sha256);
    }

    [Fact]
    public void RemovedStmsg1PayloadIsRejected()
    {
        var payload = Encoding.UTF8.GetBytes(
            "STMSG1\n{\"type\":\"message\",\"id\":\"old\",\"fromClientId\":7," +
            "\"fromClientName\":\"java-or-go\",\"toClientId\":8,\"toClientName\":\"csharp\"," +
            "\"message\":\"legacy\",\"createdAtMillis\":4567}");

        Assert.False(PeerAppMessageCodec.TryDecode(payload, out _));
    }

    [Fact]
    public void AckUsesStmsg2AndOmitsAttachmentExtension()
    {
        var ack = new PeerAppMessage
        {
            Type = PeerAppMessageCodec.TypeAck,
            Id = "message-2",
            FromClientId = 2,
            ToClientId = 1,
            Attachment = new PeerAppAttachment { ObjectId = "must-not-leak" },
        };

        var payload = PeerAppMessageCodec.Encode(ack);

        Assert.Equal("STMSG2\n", Encoding.ASCII.GetString(payload, 0, 7));
        Assert.True(PeerAppMessageCodec.TryDecode(payload, out var decoded));
        Assert.Equal(PeerAppMessageCodec.TypeAck, decoded.Type);
        Assert.Equal("message-2", decoded.Id);
        Assert.Null(decoded.Attachment);
        Assert.DoesNotContain("attachment", Encoding.UTF8.GetString(payload), StringComparison.Ordinal);
    }
}
