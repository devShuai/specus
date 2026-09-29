using Specus.Protocol;
using Specus.Protocol.Packets;
using Specus.Server.Services;

namespace Specus.IntegrationTests;

public sealed class ControlChannelRoleTests
{
    [Fact]
    public void ControlRoleUsesClientFrameWhitelist()
    {
        Packet[] allowed =
        [
            new MessageRequestPacket(),
            new HeartbeatRequestPacket(),
            new HeartbeatResponsePacket(),
            new LogoutRequestPacket(),
        ];
        Packet[] rejected =
        [
            new LoginResponsePacket(),
            new MessageResponsePacket(),
            new LogoutResponsePacket(),
            new NatMessagePacket(),
        ];

        Assert.All(allowed, packet =>
            Assert.True(ControlChannelDispatcher.PacketAllowedForRole(ConnectionRole.Control, packet)));
        Assert.All(rejected, packet =>
            Assert.False(ControlChannelDispatcher.PacketAllowedForRole(ConnectionRole.Control, packet)));
    }

    [Fact]
    public void DataRoleUsesNatHeartbeatAndLogoutWhitelist()
    {
        Packet[] allowed =
        [
            new NatMessagePacket(),
            new HeartbeatRequestPacket(),
            new HeartbeatResponsePacket(),
            new LogoutRequestPacket(),
        ];
        Packet[] rejected =
        [
            new MessageRequestPacket(),
            new LoginResponsePacket(),
            new MessageResponsePacket(),
            new LogoutResponsePacket(),
        ];

        Assert.All(allowed, packet =>
            Assert.True(ControlChannelDispatcher.PacketAllowedForRole(ConnectionRole.Data, packet)));
        Assert.All(rejected, packet =>
            Assert.False(ControlChannelDispatcher.PacketAllowedForRole(ConnectionRole.Data, packet)));
    }

    // The read loop closes a connection on any exception the dispatcher lets through. A signal to a
    // peer that has just gone must not be one: every client still signalling it was disconnected.
    [Fact]
    public async Task UndeliverablePeerSignalDoesNotCloseTheSender()
    {
        var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance;

        await ControlChannelDispatcher.RoutePeerSignalAsync(
            () => throw new Specus.Server.PeerMesh.PeerSignalUndeliverableException("target peer is offline: gone"),
            logger, "channel-1", "gone");

        var violation = new ArgumentException("toClientName is required");
        var thrown = await Assert.ThrowsAsync<ArgumentException>(() => ControlChannelDispatcher.RoutePeerSignalAsync(
            () => throw violation, logger, "channel-1", null));
        Assert.Same(violation, thrown);
    }
}
