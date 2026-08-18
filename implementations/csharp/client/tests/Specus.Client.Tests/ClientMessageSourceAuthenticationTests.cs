using System.Text;
using Specus.Client.Control;
using Specus.Client.PeerMesh;
using Specus.Protocol;
using Specus.Protocol.Packets;

namespace Specus.Client.Tests;

public sealed class ClientMessageSourceAuthenticationTests
{
    [Fact]
    public void ServerFallbackKeepsPacketSourceWhenEnvelopeClaimsAnotherClient()
    {
        var envelope = new PeerAppMessage
        {
            Type = PeerAppMessageCodec.TypeMessage,
            Id = "spoof",
            FromClientId = 999,
            FromClientName = "mallory",
            Message = "STXFER1\n{\"t\":\"done\",\"id\":\"x\"}",
        };
        var packet = new MessageResponsePacket
        {
            ClientName = "alice",
            MessageType = MessageType.ClientToClient,
            Message = Encoding.UTF8.GetString(PeerAppMessageCodec.Encode(envelope)),
        };

        var decoded = SpecusControlClient.DecodeAuthenticatedServerMessage(packet);

        Assert.Equal("alice", decoded.Sender);
        Assert.Equal(envelope.Message, decoded.RawBody);
    }

    [Fact]
    public void DirectMessageUsesAuthenticatedRosterNameInsteadOfEnvelopeName()
    {
        var envelope = new PeerAppMessage
        {
            Type = PeerAppMessageCodec.TypeMessage,
            FromClientId = 42,
            FromClientName = "mallory",
        };

        var sender = PeerMeshClient.ResolveAuthenticatedPeerSender(
            envelope,
            rosterPeerName: "alice",
            sessionPeerName: "stale-alias",
            authenticatedPeerId: 42);

        Assert.Equal("alice", sender);
    }

    [Fact]
    public void DirectMessageRejectsEnvelopeWithDifferentAuthenticatedPeerId()
    {
        var envelope = new PeerAppMessage
        {
            Type = PeerAppMessageCodec.TypeMessage,
            FromClientId = 99,
            FromClientName = "alice",
        };

        Assert.Null(PeerMeshClient.ResolveAuthenticatedPeerSender(
            envelope,
            rosterPeerName: "alice",
            sessionPeerName: "alice",
            authenticatedPeerId: 42));
    }
}
