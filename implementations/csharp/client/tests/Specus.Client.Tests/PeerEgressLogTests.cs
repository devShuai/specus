using System.Net.Sockets;
using Specus.Client.PeerMesh;
using Xunit;

namespace Specus.Client.Tests;

/// <summary>The egress logs why a dial failed and never where it went: exception messages carry the address.</summary>
public sealed class PeerEgressLogTests
{
    [Fact]
    public void ConnectReasonNamesTheCauseWithoutTheAddress()
    {
        Assert.Equal("refused", PeerEgressRuntime.ConnectReason(new SocketException((int)SocketError.ConnectionRefused)));
        Assert.Equal("refused", PeerEgressRuntime.ConnectReason(
            new IOException("connect 203.0.113.10:80", new SocketException((int)SocketError.ConnectionRefused))));
        Assert.Equal("timed out", PeerEgressRuntime.ConnectReason(new SocketException((int)SocketError.TimedOut)));
        Assert.Equal("timed out", PeerEgressRuntime.ConnectReason(new TimeoutException("203.0.113.10:80")));
        Assert.Equal("unreachable", PeerEgressRuntime.ConnectReason(new SocketException((int)SocketError.HostUnreachable)));
        Assert.Equal("no route outside the tunnel", PeerEgressRuntime.ConnectReason(new PeerEgressNoPhysicalRouteException("203.0.113.10")));
        Assert.Equal("error", PeerEgressRuntime.ConnectReason(new IOException("203.0.113.10:80 went wrong")));
        Assert.Equal("no socket", PeerEgressRuntime.ConnectReason(null));
    }
}
