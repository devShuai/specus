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
}
