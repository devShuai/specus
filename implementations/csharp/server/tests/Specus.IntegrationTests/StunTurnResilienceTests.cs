using Specus.Server.PeerMesh;

namespace Specus.IntegrationTests;

/// <summary>
/// The embedded STUN/TURN surface is exposed to the internet, so a hostile datagram must not be
/// able to take the receive loop down, and the RFC 5780 capability it advertises must match what it
/// actually does.
/// </summary>
public sealed class StunTurnResilienceTests
{
    [Fact]
    public void MalformedDatagramsParseToNullInsteadOfThrowing()
    {
        // Truncated header, bogus magic cookie, impossible attribute length and pure noise: each one
        // must be rejected as "not a STUN message" rather than by throwing out of the parser.
        Assert.Null(StunMessage.Parse([]));
        Assert.Null(StunMessage.Parse([0x00, 0x01]));
        Assert.Null(StunMessage.Parse([0x00, 0x01, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef]));
        Assert.Null(StunMessage.Parse(new byte[20]));

        var attributeOverflow = new byte[]
        {
            0x00, 0x01, 0x00, 0x08, 0x21, 0x12, 0xa4, 0x42,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            // attribute type 0x0020 claiming 0xffff bytes of value
            0x00, 0x20, 0xff, 0xff,
        };
        Assert.Null(StunMessage.Parse(attributeOverflow));

        var random = new Random(20260818);
        for (var attempt = 0; attempt < 200; attempt++)
        {
            var noise = new byte[random.Next(1, 512)];
            random.NextBytes(noise);
            // Whatever comes back, parsing must not throw.
            _ = StunMessage.Parse(noise);
        }
    }

    [Fact]
    public void ChangeRequestRoundTripsAndDefaultsToNoChange()
    {
        var transactionId = StunMessage.NewTransactionId();

        var changePort = StunMessage.Parse(new StunMessage(StunMessage.BindingRequest, transactionId,
            [StunMessage.ChangeRequest(changeIp: false, changePort: true)]).ToBytes());
        Assert.NotNull(changePort);
        Assert.Equal((false, true), changePort!.ChangeRequest());

        var changeIp = StunMessage.Parse(new StunMessage(StunMessage.BindingRequest, transactionId,
            [StunMessage.ChangeRequest(changeIp: true, changePort: false)]).ToBytes());
        Assert.NotNull(changeIp);
        Assert.Equal((true, false), changeIp!.ChangeRequest());

        // A binding request without the attribute asks for no change at all.
        var plain = StunMessage.Parse(new StunMessage(StunMessage.BindingRequest, transactionId, []).ToBytes());
        Assert.NotNull(plain);
        Assert.Equal((false, false), plain!.ChangeRequest());
    }
}
